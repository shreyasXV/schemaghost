package main

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// IsolationPattern represents how tenants are isolated
type IsolationPattern string

const (
	PatternUnknown  IsolationPattern = "unknown"
	PatternSchema   IsolationPattern = "schema-per-tenant"
	PatternRowLevel IsolationPattern = "row-level-isolation"
	PatternDatabase IsolationPattern = "database-per-tenant"
)

// TenantColumn common column names used for row-level tenant isolation
var TenantColumns = []string{
	"tenant_id", "org_id", "organization_id", "account_id",
	"workspace_id", "team_id", "company_id", "customer_id", "client_id",
}

// SystemSchemas schemas to skip during detection
var SystemSchemas = map[string]bool{
	"pg_catalog":         true,
	"information_schema": true,
	"pg_toast":           true,
	"pg_temp_1":          true,
	"public":             false, // public is special — we check it but don't treat it as a tenant
}

// Detector handles tenant isolation pattern detection
type Detector struct {
	db      *sql.DB
	Pattern IsolationPattern
	Tenants []string

	// For row-level isolation
	TenantColumn string
	TenantTables []string

	// For schema-per-tenant
	TenantSchemas []string

	// Summary info
	DetectionNotes []string
}

func NewDetector(db *sql.DB) *Detector {
	return &Detector{
		db:      db,
		Pattern: PatternUnknown,
	}
}

func (d *Detector) Detect() error {
	d.DetectionNotes = []string{}

	// Try each detection method in order of specificity
	if detected, err := d.detectSchemaPerTenant(); err != nil {
		d.DetectionNotes = append(d.DetectionNotes, fmt.Sprintf("schema detection error: %v", err))
	} else if detected {
		return nil
	}

	if detected, err := d.detectRowLevel(); err != nil {
		d.DetectionNotes = append(d.DetectionNotes, fmt.Sprintf("row-level detection error: %v", err))
	} else if detected {
		return nil
	}

	if detected, err := d.detectDatabasePerTenant(); err != nil {
		d.DetectionNotes = append(d.DetectionNotes, fmt.Sprintf("database-per-tenant detection error: %v", err))
	} else if detected {
		return nil
	}

	d.DetectionNotes = append(d.DetectionNotes, "no multi-tenant pattern detected; treating as single-tenant")
	d.Pattern = PatternUnknown
	d.Tenants = []string{"default"}
	return nil
}

func (d *Detector) detectSchemaPerTenant() (bool, error) {
	rows, err := d.db.Query(`
		SELECT schema_name 
		FROM information_schema.schemata 
		WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'public')
		  AND schema_name NOT LIKE 'pg_temp_%'
		  AND schema_name NOT LIKE 'pg_toast_%'
		ORDER BY schema_name
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	var schemas []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			continue
		}
		schemas = append(schemas, schema)
	}

	if len(schemas) < 2 {
		return false, nil
	}

	// Get table counts per schema to verify they have similar structures
	schemaTableCounts := make(map[string]int)
	for _, schema := range schemas {
		var count int
		err := d.db.QueryRow(`
			SELECT COUNT(*) FROM information_schema.tables 
			WHERE table_schema = $1 AND table_type = 'BASE TABLE'
		`, schema).Scan(&count)
		if err != nil {
			continue
		}
		schemaTableCounts[schema] = count
	}

	// Find schemas with tables — if most have similar counts, it's schema-per-tenant
	var schemasWithTables []string
	tableCounts := []int{}
	for _, schema := range schemas {
		if count, ok := schemaTableCounts[schema]; ok && count > 0 {
			schemasWithTables = append(schemasWithTables, schema)
			tableCounts = append(tableCounts, count)
		}
	}

	if len(schemasWithTables) < 2 {
		return false, nil
	}

	// Check if table counts are similar (within 50% of each other)
	if len(tableCounts) >= 2 {
		maxCount := tableCounts[0]
		minCount := tableCounts[0]
		for _, c := range tableCounts {
			if c > maxCount {
				maxCount = c
			}
			if c < minCount {
				minCount = c
			}
		}
		// If max count is at most 2x the min (and min > 0), they're likely similar
		if minCount > 0 && maxCount <= 2*minCount {
			d.Pattern = PatternSchema
			d.TenantSchemas = schemasWithTables
			d.Tenants = schemasWithTables
			d.DetectionNotes = append(d.DetectionNotes,
				fmt.Sprintf("found %d schemas with similar table structures (%d-%d tables each)",
					len(schemasWithTables), minCount, maxCount))
			return true, nil
		}
	}

	return false, nil
}

func (d *Detector) detectRowLevel() (bool, error) {
	// Check for common tenant columns in user tables
	rows, err := d.db.Query(`
		SELECT DISTINCT c.table_schema, c.table_name, c.column_name
		FROM information_schema.columns c
		JOIN information_schema.tables t 
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
		  AND t.table_type = 'BASE TABLE'
		  AND LOWER(c.column_name) = ANY($1)
		ORDER BY c.table_schema, c.table_name
	`, pqStringArray(TenantColumns))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	columnHits := make(map[string]int) // column_name -> count of tables using it
	tables := []string{}
	for rows.Next() {
		var schema, table, column string
		if err := rows.Scan(&schema, &table, &column); err != nil {
			continue
		}
		colLower := strings.ToLower(column)
		columnHits[colLower]++
		tables = append(tables, schema+"."+table)
	}

	if len(columnHits) == 0 {
		return false, nil
	}

	// Find the most common tenant column
	bestColumn := ""
	bestCount := 0
	for col, count := range columnHits {
		if count > bestCount {
			bestCount = count
			bestColumn = col
		}
	}

	if bestCount == 0 {
		return false, nil
	}

	// Get distinct tenant values from the most common column's table
	d.Pattern = PatternRowLevel
	d.TenantColumn = bestColumn
	d.TenantTables = tables
	d.DetectionNotes = append(d.DetectionNotes,
		fmt.Sprintf("found tenant column '%s' in %d tables", bestColumn, bestCount))

	// Try to get sample tenant IDs (limit to 100 for performance)
	tenants, err := d.sampleTenantValues(bestColumn)
	if err != nil {
		d.DetectionNotes = append(d.DetectionNotes, fmt.Sprintf("could not sample tenant values: %v", err))
		d.Tenants = []string{}
	} else {
		d.Tenants = tenants
	}

	return true, nil
}

// TenantNameMap maps tenant IDs to human-readable names
var TenantNameMap map[string]string

func (d *Detector) sampleTenantValues(column string) ([]string, error) {
	// Find the table with the most rows that has this column
	rows, err := d.db.Query(`
		SELECT c.table_schema, c.table_name
		FROM information_schema.columns c
		JOIN pg_stat_user_tables s 
		  ON s.schemaname = c.table_schema AND s.relname = c.table_name
		WHERE LOWER(c.column_name) = $1
		ORDER BY s.n_live_tup DESC
		LIMIT 1
	`, column)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, fmt.Errorf("no table found with column %s", column)
	}

	var schema, table string
	if err := rows.Scan(&schema, &table); err != nil {
		return nil, err
	}

	// Safe quoting
	safeSchema := sanitizeIdentifier(schema)
	safeTable := sanitizeIdentifier(table)
	safeColumn := sanitizeIdentifier(column)

	query := fmt.Sprintf(`SELECT DISTINCT %s FROM %s.%s WHERE %s IS NOT NULL LIMIT 100`,
		safeColumn, safeSchema, safeTable, safeColumn)

	tenantRows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer tenantRows.Close()

	var tenants []string
	for tenantRows.Next() {
		var val interface{}
		if err := tenantRows.Scan(&val); err != nil {
			continue
		}
		tenants = append(tenants, fmt.Sprintf("%v", val))
	}

	// Try to resolve tenant IDs to names
	d.resolveTenantNames(column, tenants)

	return tenants, nil
}

// resolveTenantNames attempts to find a lookup table that maps tenant IDs to names
// Common patterns: organizations(id, name), tenants(id, name), companies(id, name), etc.
func (d *Detector) resolveTenantNames(tenantColumn string, tenantIDs []string) {
	TenantNameMap = make(map[string]string)

	// Figure out the reference table from foreign key constraints
	refRows, err := d.db.Query(`
		SELECT DISTINCT
			ccu.table_schema, ccu.table_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
			ON tc.constraint_name = kcu.constraint_name
			AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage ccu
			ON ccu.constraint_name = tc.constraint_name
			AND ccu.table_schema = tc.table_schema
		WHERE tc.constraint_type = 'FOREIGN KEY'
			AND LOWER(kcu.column_name) = $1
		LIMIT 1
	`, tenantColumn)
	if err != nil {
		return
	}
	defer refRows.Close()

	if !refRows.Next() {
		// No FK found, try common table names
		d.tryCommonTenantTables(tenantIDs)
		return
	}

	var refSchema, refTable string
	if err := refRows.Scan(&refSchema, &refTable); err != nil {
		return
	}

	// Check if the referenced table has a 'name', 'title', or 'slug' column
	d.loadNamesFromTable(refSchema, refTable, tenantIDs)
}

func (d *Detector) tryCommonTenantTables(tenantIDs []string) {
	commonTables := []string{
		"organizations", "tenants", "companies", "accounts",
		"workspaces", "teams", "clients", "customers",
	}
	for _, tbl := range commonTables {
		var exists bool
		err := d.db.QueryRow(`
			SELECT EXISTS(
				SELECT 1 FROM information_schema.tables 
				WHERE table_schema = 'public' AND table_name = $1
			)
		`, tbl).Scan(&exists)
		if err == nil && exists {
			d.loadNamesFromTable("public", tbl, tenantIDs)
			if len(TenantNameMap) > 0 {
				return
			}
		}
	}
}

func (d *Detector) loadNamesFromTable(schema, table string, tenantIDs []string) {
	// Find the name column
	nameColumns := []string{"name", "title", "slug", "label", "display_name"}
	var nameCol string
	for _, nc := range nameColumns {
		var exists bool
		err := d.db.QueryRow(`
			SELECT EXISTS(
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = $1 AND table_name = $2 AND LOWER(column_name) = $3
			)
		`, schema, table, nc).Scan(&exists)
		if err == nil && exists {
			nameCol = nc
			break
		}
	}
	if nameCol == "" {
		return
	}

	safeSchema := sanitizeIdentifier(schema)
	safeTable := sanitizeIdentifier(table)
	safeNameCol := sanitizeIdentifier(nameCol)

	query := fmt.Sprintf(`SELECT id::text, %s FROM %s.%s`, safeNameCol, safeSchema, safeTable)
	rows, err := d.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		TenantNameMap[id] = name
	}

	if len(TenantNameMap) > 0 {
		d.DetectionNotes = append(d.DetectionNotes,
			fmt.Sprintf("resolved tenant names from %s.%s.%s (%d mappings)", schema, table, nameCol, len(TenantNameMap)))
	}
}

// ResolveTenantName returns the human name for a tenant ID, or the ID itself
func ResolveTenantName(id string) string {
	if TenantNameMap == nil {
		return id
	}
	if name, ok := TenantNameMap[id]; ok {
		return name
	}
	return id
}

// sanitizeIdentifier removes anything that's not alphanumeric or underscore/dollar
var identRe = regexp.MustCompile(`[^a-zA-Z0-9_$]`)

func sanitizeIdentifier(s string) string {
	clean := identRe.ReplaceAllString(s, "")
	if clean == "" {
		return "unknown"
	}
	return `"` + clean + `"`
}

func (d *Detector) detectDatabasePerTenant() (bool, error) {
	rows, err := d.db.Query(`
		SELECT datname FROM pg_database
		WHERE datistemplate = false
		  AND datname NOT IN ('postgres', 'template0', 'template1')
		ORDER BY datname
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	var databases []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		databases = append(databases, name)
	}

	if len(databases) < 2 {
		return false, nil
	}

	// Only flag database-per-tenant if we didn't already detect schema or row-level
	if d.Pattern == PatternSchema || d.Pattern == PatternRowLevel {
		return false, nil
	}

	d.Pattern = PatternDatabase
	d.Tenants = databases
	d.DetectionNotes = append(d.DetectionNotes,
		fmt.Sprintf("found %d user databases suggesting database-per-tenant pattern", len(databases)),
		"note: cross-database per-tenant collection is planned; currently monitoring connected database only",
	)
	return true, nil
}

// pqStringArray converts a []string to a format suitable for $1 = ANY($1) queries
func pqStringArray(ss []string) interface{} {
	return "{" + strings.Join(ss, ",") + "}"
}
