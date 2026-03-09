package main

import (
	"database/sql"
	"fmt"
	"log"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// TenantMetrics holds aggregated metrics for a single tenant
type TenantMetrics struct {
	TenantID    string  `json:"tenant_id"`
	Queries     int64   `json:"queries"`
	AvgTimeMs   float64 `json:"avg_time_ms"`
	P50Ms       float64 `json:"p50_ms"`
	P95Ms       float64 `json:"p95_ms"`
	P99Ms       float64 `json:"p99_ms"`
	RowsRead    int64   `json:"rows_read"`
	RowsWritten int64   `json:"rows_written"`
	Connections int     `json:"connections"`
	IOBytes     int64   `json:"io_bytes"`
	CacheHit    float64 `json:"cache_hit_ratio"`
}

// QueryStat holds stats for a single query
type QueryStat struct {
	Query     string  `json:"query"`
	TenantID  string  `json:"tenant_id"`
	Calls     int64   `json:"calls"`
	AvgTimeMs float64 `json:"avg_time_ms"`
	TotalMs   float64 `json:"total_ms"`
	Rows      int64   `json:"rows"`
}

// Overview holds global resource stats
type Overview struct {
	TotalConnections int     `json:"total_connections"`
	MaxConnections   int     `json:"max_connections"`
	QueriesPerSec    float64 `json:"queries_per_sec"`
	CacheHitRatio    float64 `json:"cache_hit_ratio"`
	CollectedAt      string  `json:"collected_at"`
}

// CollectorData is the full snapshot returned by Collect
type CollectorData struct {
	Tenants  []TenantMetrics `json:"tenants"`
	Queries  []QueryStat     `json:"queries"`
	Overview Overview        `json:"overview"`
}

// Collector manages metric collection from PostgreSQL
type Collector struct {
	db   *sql.DB
	mu   sync.RWMutex
	data CollectorData

	// track previous call counts for QPS calculation
	prevCalls    int64
	prevCallTime time.Time
}

func NewCollector(db *sql.DB) *Collector {
	return &Collector{
		db:           db,
		prevCallTime: time.Now(),
	}
}

func (c *Collector) GetData() CollectorData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *Collector) Collect(d *Detector) error {
	tenants, err := c.collectTenantMetrics(d)
	if err != nil {
		log.Printf("tenant metrics error: %v", err)
	}

	queries, err := c.collectTopQueries(d)
	if err != nil {
		log.Printf("query stats error: %v", err)
	}

	overview, err := c.collectOverview()
	if err != nil {
		log.Printf("overview error: %v", err)
	}

	c.mu.Lock()
	c.data = CollectorData{
		Tenants:  tenants,
		Queries:  queries,
		Overview: overview,
	}
	c.mu.Unlock()
	return nil
}

func (c *Collector) collectOverview() (Overview, error) {
	ov := Overview{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Active connections
	err := c.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE state IS NOT NULL`).Scan(&ov.TotalConnections)
	if err != nil {
		return ov, fmt.Errorf("connection count: %w", err)
	}

	// Max connections
	err = c.db.QueryRow(`SHOW max_connections`).Scan(&ov.MaxConnections)
	if err != nil {
		// Not critical
		ov.MaxConnections = 100
	}

	// Cache hit ratio
	var blksHit, blksRead int64
	err = c.db.QueryRow(`
		SELECT sum(blks_hit), sum(blks_read) FROM pg_stat_database
	`).Scan(&blksHit, &blksRead)
	if err == nil && (blksHit+blksRead) > 0 {
		ov.CacheHitRatio = float64(blksHit) / float64(blksHit+blksRead) * 100
	}

	// QPS from pg_stat_statements
	var totalCalls int64
	err = c.db.QueryRow(`SELECT COALESCE(sum(calls), 0) FROM pg_stat_statements`).Scan(&totalCalls)
	if err == nil {
		now := time.Now()
		elapsed := now.Sub(c.prevCallTime).Seconds()
		if elapsed > 0 && c.prevCalls > 0 {
			ov.QueriesPerSec = math.Max(0, float64(totalCalls-c.prevCalls)/elapsed)
		}
		c.prevCalls = totalCalls
		c.prevCallTime = now
	}

	return ov, nil
}

func (c *Collector) collectTopQueries(d *Detector) ([]QueryStat, error) {
	rows, err := c.db.Query(`
		SELECT 
			query,
			calls,
			ROUND((total_exec_time / calls)::numeric, 2) AS avg_time_ms,
			ROUND(total_exec_time::numeric, 2) AS total_ms,
			rows
		FROM pg_stat_statements
		WHERE calls > 0
		  AND query NOT LIKE '%pg_stat%'
		  AND query NOT LIKE '%information_schema%'
		ORDER BY avg_time_ms DESC
		LIMIT 50
	`)
	if err != nil {
		if strings.Contains(err.Error(), "pg_stat_statements") {
			return []QueryStat{}, nil // extension not available
		}
		return nil, err
	}
	defer rows.Close()

	var stats []QueryStat
	for rows.Next() {
		var qs QueryStat
		if err := rows.Scan(&qs.Query, &qs.Calls, &qs.AvgTimeMs, &qs.TotalMs, &qs.Rows); err != nil {
			continue
		}
		// Truncate long queries
		if len(qs.Query) > 200 {
			qs.Query = qs.Query[:200] + "…"
		}
		// Try to attribute to tenant
		qs.TenantID = extractTenantFromQuery(qs.Query, d)
		stats = append(stats, qs)
	}

	// Sort by avg time descending, keep top 10
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].AvgTimeMs > stats[j].AvgTimeMs
	})
	if len(stats) > 10 {
		stats = stats[:10]
	}
	return stats, nil
}

func (c *Collector) collectTenantMetrics(d *Detector) ([]TenantMetrics, error) {
	switch d.Pattern {
	case PatternSchema:
		return c.collectSchemaMetrics(d)
	case PatternRowLevel:
		return c.collectRowLevelMetrics(d)
	default:
		return c.collectDefaultMetrics()
	}
}

func (c *Collector) collectSchemaMetrics(d *Detector) ([]TenantMetrics, error) {
	var metrics []TenantMetrics

	for _, schema := range d.TenantSchemas {
		m := TenantMetrics{TenantID: schema}

		// Table I/O for this schema
		err := c.db.QueryRow(`
			SELECT 
				COALESCE(sum(seq_tup_read + idx_tup_fetch), 0),
				COALESCE(sum(n_tup_ins + n_tup_upd + n_tup_del), 0),
				COALESCE(sum((heap_blks_read + idx_blks_read) * 8192), 0)
			FROM pg_stat_user_tables
			WHERE schemaname = $1
		`, schema).Scan(&m.RowsRead, &m.RowsWritten, &m.IOBytes)
		if err != nil {
			log.Printf("schema metrics for %s: %v", schema, err)
		}

		// Connections for this schema (via search_path in query or application_name)
		err = c.db.QueryRow(`
			SELECT count(*)
			FROM pg_stat_activity
			WHERE query ~ $1 OR application_name ~ $1
		`, schema).Scan(&m.Connections)
		if err != nil {
			m.Connections = 0
		}

		// Query stats from pg_stat_statements — look for schema in query
		rows, err := c.db.Query(`
			SELECT calls, total_exec_time, rows
			FROM pg_stat_statements
			WHERE query ILIKE $1
			  AND calls > 0
		`, "%"+schema+"%")
		if err == nil {
			var totalCalls int64
			var totalTime float64
			var totalRows int64
			var times []float64
			for rows.Next() {
				var calls int64
				var execTime float64
				var r int64
				if scanErr := rows.Scan(&calls, &execTime, &r); scanErr != nil {
					continue
				}
				totalCalls += calls
				totalTime += execTime
				totalRows += r
				if calls > 0 {
					times = append(times, execTime/float64(calls))
				}
			}
			rows.Close()
			m.Queries = totalCalls
			if totalCalls > 0 {
				m.AvgTimeMs = totalTime / float64(totalCalls)
			}
			m.RowsRead += totalRows
			percentiles := calcPercentiles(times)
			m.P50Ms = percentiles[0]
			m.P95Ms = percentiles[1]
			m.P99Ms = percentiles[2]
		}

		metrics = append(metrics, m)
	}

	return metrics, nil
}

func (c *Collector) collectRowLevelMetrics(d *Detector) ([]TenantMetrics, error) {
	if d.TenantColumn == "" {
		return c.collectDefaultMetrics()
	}

	// Get query stats attributed by tenant from pg_stat_statements
	rows, err := c.db.Query(`
		SELECT query, calls, total_exec_time, rows
		FROM pg_stat_statements
		WHERE calls > 0
		  AND query NOT LIKE '%pg_stat%'
		ORDER BY total_exec_time DESC
		LIMIT 500
	`)
	if err != nil {
		return c.collectDefaultMetrics()
	}
	defer rows.Close()

	type aggStats struct {
		calls     int64
		totalTime float64
		rows      int64
		times     []float64
	}
	tenantAgg := make(map[string]*aggStats)

	for rows.Next() {
		var query string
		var calls int64
		var execTime float64
		var r int64
		if err := rows.Scan(&query, &calls, &execTime, &r); err != nil {
			continue
		}
		tenantID := extractTenantIDFromSQL(query, d.TenantColumn)
		agg, ok := tenantAgg[tenantID]
		if !ok {
			agg = &aggStats{}
			tenantAgg[tenantID] = agg
		}
		agg.calls += calls
		agg.totalTime += execTime
		agg.rows += r
		if calls > 0 {
			agg.times = append(agg.times, execTime/float64(calls))
		}
	}

	// Get connection counts
	connRows, err := c.db.Query(`
		SELECT application_name, count(*)
		FROM pg_stat_activity
		WHERE state IS NOT NULL
		GROUP BY application_name
	`)
	connCounts := make(map[string]int)
	if err == nil {
		defer connRows.Close()
		for connRows.Next() {
			var appName string
			var cnt int
			if scanErr := connRows.Scan(&appName, &cnt); scanErr != nil {
				continue
			}
			connCounts[appName] = cnt
		}
	}

	var metrics []TenantMetrics
	for tid, agg := range tenantAgg {
		m := TenantMetrics{
			TenantID: tid,
			Queries:  agg.calls,
			RowsRead: agg.rows,
		}
		if agg.calls > 0 {
			m.AvgTimeMs = agg.totalTime / float64(agg.calls)
		}
		percentiles := calcPercentiles(agg.times)
		m.P50Ms = percentiles[0]
		m.P95Ms = percentiles[1]
		m.P99Ms = percentiles[2]
		metrics = append(metrics, m)
	}

	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Queries > metrics[j].Queries
	})

	if len(metrics) > 50 {
		metrics = metrics[:50]
	}
	return metrics, nil
}

func (c *Collector) collectDefaultMetrics() ([]TenantMetrics, error) {
	m := TenantMetrics{TenantID: "default"}

	err := c.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE state IS NOT NULL`).Scan(&m.Connections)
	if err != nil {
		return nil, err
	}

	err = c.db.QueryRow(`
		SELECT 
			COALESCE(sum(calls), 0),
			COALESCE(sum(total_exec_time) / NULLIF(sum(calls), 0), 0),
			COALESCE(sum(rows), 0)
		FROM pg_stat_statements
		WHERE calls > 0
	`).Scan(&m.Queries, &m.AvgTimeMs, &m.RowsRead)
	if err != nil {
		m.Queries = 0
	}

	err = c.db.QueryRow(`
		SELECT COALESCE(sum((heap_blks_read + idx_blks_read) * 8192), 0)
		FROM pg_stat_user_tables
	`).Scan(&m.IOBytes)
	if err != nil {
		m.IOBytes = 0
	}

	return []TenantMetrics{m}, nil
}

// extractTenantFromQuery tries to extract a tenant identifier from a SQL query
func extractTenantFromQuery(query string, d *Detector) string {
	if d.Pattern == PatternSchema {
		for _, schema := range d.TenantSchemas {
			if strings.Contains(strings.ToLower(query), strings.ToLower(schema)) {
				return schema
			}
		}
	}
	if d.TenantColumn != "" {
		return extractTenantIDFromSQL(query, d.TenantColumn)
	}
	return "unknown"
}

// extractTenantIDFromSQL parses SQL to find tenant_id = 'value' patterns
var tenantValRe = regexp.MustCompile(`(?i)(tenant_id|org_id|organization_id|account_id|workspace_id|team_id|company_id|customer_id|client_id)\s*=\s*'?([^'\s,)]+)'?`)
var searchPathRe = regexp.MustCompile(`(?i)SET\s+search_path\s*=\s*([a-zA-Z0-9_,\s]+)`)

func extractTenantIDFromSQL(query, column string) string {
	// Check for column = value pattern
	m := tenantValRe.FindStringSubmatch(query)
	if len(m) >= 3 {
		return m[2]
	}

	// Check for search_path
	m2 := searchPathRe.FindStringSubmatch(query)
	if len(m2) >= 2 {
		parts := strings.Split(m2[1], ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	return "unknown"
}

// calcPercentiles returns [p50, p95, p99] from a sorted slice of latencies
func calcPercentiles(times []float64) [3]float64 {
	if len(times) == 0 {
		return [3]float64{0, 0, 0}
	}
	sort.Float64s(times)
	n := len(times)
	p50 := times[int(math.Floor(float64(n)*0.50))]
	p95Idx := int(math.Floor(float64(n) * 0.95))
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p99Idx := int(math.Floor(float64(n) * 0.99))
	if p99Idx >= n {
		p99Idx = n - 1
	}
	return [3]float64{p50, times[p95Idx], times[p99Idx]}
}
