package main

import (
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OverviewSnapshot is the overview fields we track over time
type OverviewSnapshot struct {
	Timestamp   time.Time `json:"timestamp"`
	Connections int       `json:"connections"`
	QPS         float64   `json:"qps"`
	CacheHit    float64   `json:"cache_hit"`
}

// Snapshot is a point-in-time recording of all metrics
type Snapshot struct {
	Timestamp time.Time       `json:"timestamp"`
	Tenants   []TenantMetrics `json:"tenants"`
	Overview  Overview        `json:"overview"`
}

// HistoryStore maintains time-series snapshots in memory
type HistoryStore struct {
	mu        sync.RWMutex
	snapshots []Snapshot
	retention time.Duration
}

// NewHistoryStore creates a new HistoryStore with configured retention
func NewHistoryStore() *HistoryStore {
	retention := 24 * time.Hour
	if v := os.Getenv("HISTORY_RETENTION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			retention = d
		}
	}
	return &HistoryStore{
		retention: retention,
	}
}

// Record stores a new snapshot and prunes old data
func (h *HistoryStore) Record(data CollectorData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	snap := Snapshot{
		Timestamp: time.Now(),
		Tenants:   data.Tenants,
		Overview:  data.Overview,
	}
	h.snapshots = append(h.snapshots, snap)

	// Prune old snapshots
	cutoff := time.Now().Add(-h.retention)
	start := 0
	for start < len(h.snapshots) && h.snapshots[start].Timestamp.Before(cutoff) {
		start++
	}
	if start > 0 {
		h.snapshots = h.snapshots[start:]
	}
}

// parsePeriod converts a period string like "1h", "6h", "24h" to a duration
func parsePeriod(s string) time.Duration {
	if s == "" {
		return 1 * time.Hour
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 1 * time.Hour
	}
	return d
}

// TenantMetricPoint is a timestamped metric value for a tenant
type TenantMetricPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// GetTenantHistory returns a time-series for a specific tenant metric
func (h *HistoryStore) GetTenantHistory(tenantID, metric string, period time.Duration) []TenantMetricPoint {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cutoff := time.Now().Add(-period)
	var points []TenantMetricPoint

	for _, snap := range h.snapshots {
		if snap.Timestamp.Before(cutoff) {
			continue
		}
		for _, t := range snap.Tenants {
			if t.TenantID != tenantID {
				continue
			}
			var val float64
			switch metric {
			case "queries":
				val = float64(t.Queries)
			case "p99_ms":
				val = t.P99Ms
			case "p95_ms":
				val = t.P95Ms
			case "avg_time_ms":
				val = t.AvgTimeMs
			case "connections":
				val = float64(t.Connections)
			case "cache_hit":
				val = t.CacheHit
			case "io_bytes":
				val = float64(t.IOBytes)
			default:
				val = float64(t.Queries)
			}
			points = append(points, TenantMetricPoint{
				Timestamp: snap.Timestamp,
				Value:     val,
			})
		}
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})
	return points
}

// GetOverviewHistory returns time-series of overview metrics
func (h *HistoryStore) GetOverviewHistory(period time.Duration) []OverviewSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cutoff := time.Now().Add(-period)
	var points []OverviewSnapshot

	for _, snap := range h.snapshots {
		if snap.Timestamp.Before(cutoff) {
			continue
		}
		points = append(points, OverviewSnapshot{
			Timestamp:   snap.Timestamp,
			Connections: snap.Overview.TotalConnections,
			QPS:         snap.Overview.QueriesPerSec,
			CacheHit:    snap.Overview.CacheHitRatio,
		})
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})
	return points
}

// ── HTTP Handlers ──────────────────────────────────────────────────────

// handleHistory returns time-series data for a tenant metric
// GET /api/history?tenant=X&metric=queries&period=1h
func handleHistory(w http.ResponseWriter, r *http.Request) {
	if historyStore == nil {
		writeJSON(w, []interface{}{})
		return
	}
	q := r.URL.Query()
	tenantID := q.Get("tenant")
	metric := q.Get("metric")
	periodStr := q.Get("period")

	if tenantID == "" {
		http.Error(w, "tenant query param required", http.StatusBadRequest)
		return
	}
	if metric == "" {
		metric = "queries"
	}

	period := parsePeriod(periodStr)
	points := historyStore.GetTenantHistory(tenantID, metric, period)
	writeJSON(w, points)
}

// handleHistoryOverview returns time-series of global overview metrics
// GET /api/history/overview?period=1h
func handleHistoryOverview(w http.ResponseWriter, r *http.Request) {
	if historyStore == nil {
		writeJSON(w, []interface{}{})
		return
	}
	periodStr := r.URL.Query().Get("period")
	period := parsePeriod(periodStr)
	points := historyStore.GetOverviewHistory(period)
	writeJSON(w, points)
}

// handleExportCSV exports all tenant metrics as CSV
// GET /api/export/csv
func handleExportCSV(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"faultwall-export-"+
		time.Now().Format("20060102-150405")+".csv\"")

	var sb strings.Builder
	sb.WriteString("tenant_id,queries,avg_time_ms,p50_ms,p95_ms,p99_ms,rows_read,rows_written,connections,io_bytes,cache_hit_ratio\n")

	for _, t := range data.Tenants {
		sb.WriteString(csvEscape(t.TenantID) + ",")
		sb.WriteString(strconv.FormatInt(t.Queries, 10) + ",")
		sb.WriteString(strconv.FormatFloat(t.AvgTimeMs, 'f', 2, 64) + ",")
		sb.WriteString(strconv.FormatFloat(t.P50Ms, 'f', 2, 64) + ",")
		sb.WriteString(strconv.FormatFloat(t.P95Ms, 'f', 2, 64) + ",")
		sb.WriteString(strconv.FormatFloat(t.P99Ms, 'f', 2, 64) + ",")
		sb.WriteString(strconv.FormatInt(t.RowsRead, 10) + ",")
		sb.WriteString(strconv.FormatInt(t.RowsWritten, 10) + ",")
		sb.WriteString(strconv.Itoa(t.Connections) + ",")
		sb.WriteString(strconv.FormatInt(t.IOBytes, 10) + ",")
		sb.WriteString(strconv.FormatFloat(t.CacheHit, 'f', 2, 64) + "\n")
	}

	w.Write([]byte(sb.String()))
}

// handleExportJSON exports full CollectorData as JSON download
// GET /api/export/json
func handleExportJSON(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"faultwall-export-"+
		time.Now().Format("20060102-150405")+".json\"")
	writeJSON(w, data)
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
