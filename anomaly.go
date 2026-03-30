package main

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// MetricSample is a single point-in-time sample of tenant metrics
type MetricSample struct {
	Timestamp      time.Time `json:"timestamp"`
	AvgQueryTimeMs float64   `json:"avg_query_time_ms"`
	QueryCount     int64     `json:"query_count"`
	Connections    int       `json:"connections"`
	RowsRead       int64     `json:"rows_read"`
}

// TenantBaseline tracks rolling statistics for one tenant
type TenantBaseline struct {
	TenantID string         `json:"tenant_id"`
	Samples  []MetricSample `json:"samples"`
	maxSize  int
}

// addSample appends a sample to the ring buffer
func (tb *TenantBaseline) addSample(s MetricSample) {
	tb.Samples = append(tb.Samples, s)
	if len(tb.Samples) > tb.maxSize {
		tb.Samples = tb.Samples[len(tb.Samples)-tb.maxSize:]
	}
}

// meanStdDev calculates mean and standard deviation for a metric extractor
func (tb *TenantBaseline) meanStdDev(extract func(MetricSample) float64) (float64, float64) {
	n := len(tb.Samples)
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, s := range tb.Samples {
		sum += extract(s)
	}
	mean := sum / float64(n)

	var variance float64
	for _, s := range tb.Samples {
		diff := extract(s) - mean
		variance += diff * diff
	}
	variance /= float64(n)
	return mean, math.Sqrt(variance)
}

// Anomaly represents a detected anomaly for a tenant metric
type Anomaly struct {
	Timestamp      time.Time `json:"timestamp"`
	TenantID       string    `json:"tenant_id"`
	Metric         string    `json:"metric"`
	CurrentValue   float64   `json:"current_value"`
	BaselineMean   float64   `json:"baseline_mean"`
	BaselineStdDev float64   `json:"baseline_std_dev"`
	ZScore         float64   `json:"z_score"`
	Severity       string    `json:"severity"`
	Message        string    `json:"message"`
}

// AnomalyDetector maintains per-tenant baselines and detects anomalies
type AnomalyDetector struct {
	mu          sync.RWMutex
	baselines   map[string]*TenantBaseline
	active      []Anomaly
	recent      []Anomaly
	windowSize  int
	sensitivity float64
	slack       *SlackNotifier

	// Track last alert time per tenant+metric to avoid re-alerting within 5 min
	lastAlerted map[string]time.Time
	// Track consecutive below-threshold cycles per tenant+metric for resolution
	belowCount map[string]int
}

// NewAnomalyDetector creates an AnomalyDetector with config from env vars
func NewAnomalyDetector(slack *SlackNotifier) *AnomalyDetector {
	windowSize := 30
	if v := os.Getenv("ANOMALY_WINDOW_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			windowSize = n
		}
	}

	sensitivity := 2.0
	if v := os.Getenv("ANOMALY_SENSITIVITY"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			sensitivity = f
		}
	}

	return &AnomalyDetector{
		baselines:   make(map[string]*TenantBaseline),
		windowSize:  windowSize,
		sensitivity: sensitivity,
		slack:       slack,
		lastAlerted: make(map[string]time.Time),
		belowCount:  make(map[string]int),
	}
}

// metricDef defines a metric to check for anomalies
type metricDef struct {
	name    string
	extract func(MetricSample) float64
	format  func(float64) string
}

var anomalyMetrics = []metricDef{
	{
		name:    "avg_query_time",
		extract: func(s MetricSample) float64 { return s.AvgQueryTimeMs },
		format:  func(v float64) string { return fmt.Sprintf("%.0fms", v) },
	},
	{
		name:    "query_count",
		extract: func(s MetricSample) float64 { return float64(s.QueryCount) },
		format:  func(v float64) string { return fmt.Sprintf("%.0f", v) },
	},
	{
		name:    "connections",
		extract: func(s MetricSample) float64 { return float64(s.Connections) },
		format:  func(v float64) string { return fmt.Sprintf("%.0f", v) },
	},
	{
		name:    "rows_read",
		extract: func(s MetricSample) float64 { return float64(s.RowsRead) },
		format:  func(v float64) string { return fmt.Sprintf("%.0f", v) },
	},
}

// Evaluate checks current data against baselines for anomalies
func (ad *AnomalyDetector) Evaluate(data CollectorData) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()

	// Track which anomaly keys are still active
	stillActive := make(map[string]bool)

	for _, t := range data.Tenants {
		// Ensure baseline exists
		bl, ok := ad.baselines[t.TenantID]
		if !ok {
			bl = &TenantBaseline{
				TenantID: t.TenantID,
				maxSize:  ad.windowSize,
			}
			ad.baselines[t.TenantID] = bl
		}

		sample := MetricSample{
			Timestamp:      now,
			AvgQueryTimeMs: t.AvgTimeMs,
			QueryCount:     t.Queries,
			Connections:    t.Connections,
			RowsRead:       t.RowsRead,
		}
		bl.addSample(sample)

		// Need at least 10 samples for baseline
		if len(bl.Samples) < 10 {
			continue
		}

		for _, m := range anomalyMetrics {
			currentVal := m.extract(sample)
			mean, stddev := bl.meanStdDev(m.extract)
			anomalyKey := t.TenantID + ":" + m.name

			if stddev == 0 {
				// No variance — can't detect anomaly
				ad.belowCount[anomalyKey] = 0
				continue
			}

			zScore := (currentVal - mean) / stddev

			if zScore > ad.sensitivity {
				stillActive[anomalyKey] = true
				ad.belowCount[anomalyKey] = 0

				severity := "warning"
				if zScore > 3.0 {
					severity = "critical"
				}

				multiplier := 0.0
				if mean > 0 {
					multiplier = currentVal / mean
				}

				message := fmt.Sprintf("%s %s is %s, %.1fx above baseline of %s",
					t.TenantID, m.name, m.format(currentVal), multiplier, m.format(mean))

				anomaly := Anomaly{
					Timestamp:      now,
					TenantID:       t.TenantID,
					Metric:         m.name,
					CurrentValue:   currentVal,
					BaselineMean:   mean,
					BaselineStdDev: stddev,
					ZScore:         math.Round(zScore*100) / 100,
					Severity:       severity,
					Message:        message,
				}

				// Check if already in active list — update it
				found := false
				for i, a := range ad.active {
					if a.TenantID == t.TenantID && a.Metric == m.name {
						ad.active[i] = anomaly
						found = true
						break
					}
				}
				if !found {
					ad.active = append(ad.active, anomaly)
				}

				// Slack notification with 5-min cooldown
				if lastTime, ok := ad.lastAlerted[anomalyKey]; !ok || now.Sub(lastTime) >= 5*time.Minute {
					ad.lastAlerted[anomalyKey] = now
					ad.notifySlack(anomaly)
				}
			} else {
				// Below threshold — track consecutive cycles
				ad.belowCount[anomalyKey]++
			}
		}
	}

	// Resolve anomalies that have been below threshold for 3 consecutive cycles
	var remaining []Anomaly
	for _, a := range ad.active {
		key := a.TenantID + ":" + a.Metric
		if stillActive[key] {
			remaining = append(remaining, a)
		} else if ad.belowCount[key] >= 3 {
			// Resolved — add to recent history
			ad.addRecent(a)
		} else {
			// Not yet resolved, keep active
			remaining = append(remaining, a)
		}
	}
	ad.active = remaining
}

// addRecent adds an anomaly to the recent history, keeping at most 100
func (ad *AnomalyDetector) addRecent(a Anomaly) {
	ad.recent = append(ad.recent, a)
	if len(ad.recent) > 100 {
		ad.recent = ad.recent[len(ad.recent)-100:]
	}
}

// notifySlack sends an anomaly notification to Slack
func (ad *AnomalyDetector) notifySlack(a Anomaly) {
	if ad.slack == nil {
		return
	}
	title := fmt.Sprintf("[FaultWall] Anomaly %s: %s", a.Severity, a.TenantID)
	text := fmt.Sprintf("Metric: `%s` | Value: `%s` | Baseline: `%.2f` | Z-Score: `%.1f`\n%s",
		a.Metric, fmt.Sprintf("%.2f", a.CurrentValue), a.BaselineMean, a.ZScore, a.Message)
	color := "#f5c542" // yellow for warning
	if a.Severity == "critical" {
		color = "#e53e3e" // red
	}
	payload := slackPayload(title, text, color)
	go ad.slack.send(payload)
}

// GetActive returns a copy of active anomalies
func (ad *AnomalyDetector) GetActive() []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	result := make([]Anomaly, len(ad.active))
	copy(result, ad.active)
	return result
}

// GetRecent returns a copy of recently resolved anomalies
func (ad *AnomalyDetector) GetRecent() []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	result := make([]Anomaly, len(ad.recent))
	copy(result, ad.recent)
	return result
}

// BaselineSummary is a summary of a tenant's baseline for API responses
type BaselineSummary struct {
	TenantID       string  `json:"tenant_id"`
	SampleCount    int     `json:"sample_count"`
	AvgQueryMean   float64 `json:"avg_query_time_mean"`
	AvgQueryStdDev float64 `json:"avg_query_time_std_dev"`
	QueryCountMean float64 `json:"query_count_mean"`
	ConnMean       float64 `json:"connections_mean"`
	RowsReadMean   float64 `json:"rows_read_mean"`
}

// GetBaselines returns baseline summaries for all tenants
func (ad *AnomalyDetector) GetBaselines() map[string]BaselineSummary {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	result := make(map[string]BaselineSummary, len(ad.baselines))
	for tid, bl := range ad.baselines {
		aqMean, aqStd := bl.meanStdDev(func(s MetricSample) float64 { return s.AvgQueryTimeMs })
		qcMean, _ := bl.meanStdDev(func(s MetricSample) float64 { return float64(s.QueryCount) })
		cMean, _ := bl.meanStdDev(func(s MetricSample) float64 { return float64(s.Connections) })
		rrMean, _ := bl.meanStdDev(func(s MetricSample) float64 { return float64(s.RowsRead) })
		result[tid] = BaselineSummary{
			TenantID:       tid,
			SampleCount:    len(bl.Samples),
			AvgQueryMean:   math.Round(aqMean*100) / 100,
			AvgQueryStdDev: math.Round(aqStd*100) / 100,
			QueryCountMean: math.Round(qcMean*100) / 100,
			ConnMean:       math.Round(cMean*100) / 100,
			RowsReadMean:   math.Round(rrMean*100) / 100,
		}
	}
	return result
}

// GetTenantBaseline returns the full baseline for a single tenant
func (ad *AnomalyDetector) GetTenantBaseline(tenantID string) *TenantBaseline {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	bl, ok := ad.baselines[tenantID]
	if !ok {
		return nil
	}
	// Return a copy
	cp := &TenantBaseline{
		TenantID: bl.TenantID,
		maxSize:  bl.maxSize,
		Samples:  make([]MetricSample, len(bl.Samples)),
	}
	copy(cp.Samples, bl.Samples)
	return cp
}

// ── HTTP Handlers ──────────────────────────────────────────────────────

func handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if anomalyDetector == nil {
		writeJSON(w, map[string]interface{}{"active": []interface{}{}, "recent": []interface{}{}, "baselines": map[string]interface{}{}})
		return
	}
	writeJSON(w, map[string]interface{}{
		"active":    anomalyDetector.GetActive(),
		"recent":    anomalyDetector.GetRecent(),
		"baselines": anomalyDetector.GetBaselines(),
	})
}

func handleTenantBaseline(w http.ResponseWriter, r *http.Request) {
	if anomalyDetector == nil {
		http.Error(w, "anomaly detector not initialized", http.StatusServiceUnavailable)
		return
	}
	tenantID := r.URL.Query().Get("tenant")
	if tenantID == "" {
		http.Error(w, "tenant query param required", http.StatusBadRequest)
		return
	}
	bl := anomalyDetector.GetTenantBaseline(tenantID)
	if bl == nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}

	aqMean, aqStd := bl.meanStdDev(func(s MetricSample) float64 { return s.AvgQueryTimeMs })
	qcMean, qcStd := bl.meanStdDev(func(s MetricSample) float64 { return float64(s.QueryCount) })
	cMean, cStd := bl.meanStdDev(func(s MetricSample) float64 { return float64(s.Connections) })
	rrMean, rrStd := bl.meanStdDev(func(s MetricSample) float64 { return float64(s.RowsRead) })

	writeJSON(w, map[string]interface{}{
		"tenant_id":    tenantID,
		"sample_count": len(bl.Samples),
		"samples":      bl.Samples,
		"stats": map[string]interface{}{
			"avg_query_time": map[string]float64{"mean": math.Round(aqMean*100) / 100, "std_dev": math.Round(aqStd*100) / 100},
			"query_count":    map[string]float64{"mean": math.Round(qcMean*100) / 100, "std_dev": math.Round(qcStd*100) / 100},
			"connections":    map[string]float64{"mean": math.Round(cMean*100) / 100, "std_dev": math.Round(cStd*100) / 100},
			"rows_read":      map[string]float64{"mean": math.Round(rrMean*100) / 100, "std_dev": math.Round(rrStd*100) / 100},
		},
	})
}
