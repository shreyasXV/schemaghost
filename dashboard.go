package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// handleDashboard serves the HTML dashboard
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmplPath := findTemplatePath()
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	data := struct {
		Pattern string
		Tenants int
	}{
		Pattern: string(detector.Pattern),
		Tenants: len(detector.Tenants),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template render error: %v", err)
	}
}

// handleTenants returns JSON tenant leaderboard
func handleTenants(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	writeJSON(w, data.Tenants)
}

// handleQueries returns JSON top queries
func handleQueries(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	writeJSON(w, data.Queries)
}

// handleHealth returns health status
func handleHealth(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	status := map[string]interface{}{
		"status":       "ok",
		"pattern":      string(detector.Pattern),
		"tenants":      len(detector.Tenants),
		"overview":     data.Overview,
		"collected_at": data.Overview.CollectedAt,
	}
	writeJSON(w, status)
}

// handleConfig returns detected pattern configuration
func handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := map[string]interface{}{
		"pattern":        string(detector.Pattern),
		"tenants":        detector.Tenants,
		"tenant_column":  detector.TenantColumn,
		"tenant_schemas": detector.TenantSchemas,
		"notes":          detector.DetectionNotes,
	}
	writeJSON(w, cfg)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("JSON encode error: %v", err)
	}
}

func findTemplatePath() string {
	// Try relative to binary location first
	candidates := []string{
		"templates/dashboard.html",
		"/app/templates/dashboard.html",
	}

	// Try relative to source file (dev mode)
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(filename)
		candidates = append(candidates, filepath.Join(dir, "templates/dashboard.html"))
	}

	// Try relative to working directory
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "templates/dashboard.html"))
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Fallback — return first candidate and let it fail with a useful error
	return candidates[0]
}
