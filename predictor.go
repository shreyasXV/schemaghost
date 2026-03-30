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

// Prediction represents a projected threshold breach
type Prediction struct {
	Timestamp          time.Time `json:"timestamp"`
	TenantID           string    `json:"tenant_id"`
	Metric             string    `json:"metric"`
	CurrentValue       float64   `json:"current_value"`
	ProjectedValue     float64   `json:"projected_value"`
	ThresholdValue     float64   `json:"threshold_value"`
	TimeToThresholdMin float64   `json:"time_to_threshold_min"`
	Trend              string    `json:"trend"`
	Confidence         float64   `json:"confidence"`
	Message            string    `json:"message"`
	expiresAt          time.Time
}

// Predictor uses rate-of-change analysis to predict threshold breaches
type Predictor struct {
	mu            sync.RWMutex
	predictions   []Prediction
	thresholdMs   float64
	connThreshold float64
}

// NewPredictor creates a Predictor with config from env vars
func NewPredictor() *Predictor {
	thresholdMs := 30000.0
	if v := os.Getenv("PREDICT_THRESHOLD_MS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			thresholdMs = f
		}
	} else if v := os.Getenv("THROTTLE_MAX_QUERY_TIME_MS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			thresholdMs = f
		}
	}

	connThreshold := 50.0
	if v := os.Getenv("THROTTLE_MAX_CONNECTIONS_PER_TENANT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			connThreshold = float64(n)
		}
	}

	return &Predictor{
		thresholdMs:   thresholdMs,
		connThreshold: connThreshold,
	}
}

// linearRegression calculates slope, intercept, and R-squared for (x, y) pairs
// x values are seconds since the first sample
func linearRegression(xs, ys []float64) (slope, intercept, rSquared float64) {
	n := float64(len(xs))
	if n < 2 {
		return 0, 0, 0
	}

	var sumX, sumY, sumXY, sumX2 float64
	for i := range xs {
		sumX += xs[i]
		sumY += ys[i]
		sumXY += xs[i] * ys[i]
		sumX2 += xs[i] * xs[i]
	}

	denom := n*sumX2 - sumX*sumX
	if denom == 0 {
		return 0, sumY / n, 0
	}

	slope = (n*sumXY - sumX*sumY) / denom
	intercept = (sumY - slope*sumX) / n

	// R-squared
	meanY := sumY / n
	var ssTot, ssRes float64
	for i := range xs {
		predicted := slope*xs[i] + intercept
		ssRes += (ys[i] - predicted) * (ys[i] - predicted)
		ssTot += (ys[i] - meanY) * (ys[i] - meanY)
	}
	if ssTot == 0 {
		rSquared = 0
	} else {
		rSquared = 1 - ssRes/ssTot
	}

	return slope, intercept, rSquared
}

// classifyTrend determines if the trend is accelerating, decelerating, or linear
// by checking the second derivative (change in slope between halves)
func classifyTrend(xs, ys []float64) string {
	n := len(xs)
	if n < 6 {
		return "linear"
	}

	mid := n / 2
	slope1, _, _ := linearRegression(xs[:mid], ys[:mid])
	slope2, _, _ := linearRegression(xs[mid:], ys[mid:])

	diff := slope2 - slope1
	threshold := math.Abs(slope1) * 0.2 // 20% change is significant

	if diff > threshold {
		return "accelerating"
	} else if diff < -threshold {
		return "decelerating"
	}
	return "linear"
}

// Evaluate analyzes trends and creates predictions
func (p *Predictor) Evaluate(data CollectorData) {
	if anomalyDetector == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// Expire old predictions
	var remaining []Prediction
	for _, pred := range p.predictions {
		if now.Before(pred.expiresAt) {
			remaining = append(remaining, pred)
		}
	}
	p.predictions = remaining

	anomalyDetector.mu.RLock()
	baselines := anomalyDetector.baselines
	anomalyDetector.mu.RUnlock()

	for _, t := range data.Tenants {
		bl, ok := baselines[t.TenantID]
		if !ok {
			continue
		}

		anomalyDetector.mu.RLock()
		samples := make([]MetricSample, len(bl.Samples))
		copy(samples, bl.Samples)
		anomalyDetector.mu.RUnlock()

		if len(samples) < 6 {
			continue
		}

		// Analyze avg_query_time trend
		p.analyzeTrend(t.TenantID, "avg_query_time", samples,
			func(s MetricSample) float64 { return s.AvgQueryTimeMs },
			p.thresholdMs, "ms", now)

		// Analyze connections trend
		p.analyzeTrend(t.TenantID, "connections", samples,
			func(s MetricSample) float64 { return float64(s.Connections) },
			p.connThreshold, "", now)
	}
}

// analyzeTrend checks one metric for threshold breach prediction
func (p *Predictor) analyzeTrend(tenantID, metric string, samples []MetricSample,
	extract func(MetricSample) float64, threshold float64, unit string, now time.Time) {

	n := len(samples)
	xs := make([]float64, n)
	ys := make([]float64, n)
	baseTime := samples[0].Timestamp

	for i, s := range samples {
		xs[i] = s.Timestamp.Sub(baseTime).Seconds()
		ys[i] = extract(s)
	}

	slope, _, rSquared := linearRegression(xs, ys)

	// Only predict if slope is positive, R-squared > 0.6, and current < threshold
	currentVal := ys[n-1]
	if slope <= 0 || rSquared <= 0.6 || currentVal >= threshold {
		// Remove any existing prediction for this tenant+metric if trend reversed
		p.removePrediction(tenantID, metric)
		return
	}

	// Project time to threshold (in seconds from now)
	timeToThresholdSec := (threshold - currentVal) / slope
	timeToThresholdMin := timeToThresholdSec / 60.0

	if timeToThresholdMin > 60 || timeToThresholdMin <= 0 {
		p.removePrediction(tenantID, metric)
		return
	}

	// Project value at threshold time
	currentX := xs[n-1]
	projectedValue := slope*(currentX+timeToThresholdSec) + (currentVal - slope*currentX)

	trend := classifyTrend(xs, ys)

	slopePerMin := slope * 60.0
	var message string
	if unit == "ms" {
		message = fmt.Sprintf("Tenant %s %s increasing at %.1f%s/min. Projected to exceed %.0f%s threshold in ~%.0f minutes.",
			tenantID, metric, slopePerMin, unit, threshold, unit, timeToThresholdMin)
	} else {
		message = fmt.Sprintf("Tenant %s %s increasing at %.1f/min. Projected to exceed %.0f threshold in ~%.0f minutes.",
			tenantID, metric, slopePerMin, threshold, timeToThresholdMin)
	}

	pred := Prediction{
		Timestamp:          now,
		TenantID:           tenantID,
		Metric:             metric,
		CurrentValue:       math.Round(currentVal*100) / 100,
		ProjectedValue:     math.Round(projectedValue*100) / 100,
		ThresholdValue:     threshold,
		TimeToThresholdMin: math.Round(timeToThresholdMin*10) / 10,
		Trend:              trend,
		Confidence:         math.Round(rSquared*100) / 100,
		Message:            message,
		expiresAt:          now.Add(10 * time.Minute),
	}

	// Update or add prediction
	found := false
	for i, existing := range p.predictions {
		if existing.TenantID == tenantID && existing.Metric == metric {
			p.predictions[i] = pred
			found = true
			break
		}
	}
	if !found {
		p.predictions = append(p.predictions, pred)
	}
}

// removePrediction removes a prediction for a tenant+metric
func (p *Predictor) removePrediction(tenantID, metric string) {
	for i, pred := range p.predictions {
		if pred.TenantID == tenantID && pred.Metric == metric {
			p.predictions = append(p.predictions[:i], p.predictions[i+1:]...)
			return
		}
	}
}

// GetPredictions returns a copy of active predictions
func (p *Predictor) GetPredictions() []Prediction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]Prediction, len(p.predictions))
	copy(result, p.predictions)
	return result
}

// GetTenantPredictions returns predictions for a specific tenant
func (p *Predictor) GetTenantPredictions(tenantID string) []Prediction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result []Prediction
	for _, pred := range p.predictions {
		if pred.TenantID == tenantID {
			result = append(result, pred)
		}
	}
	return result
}

// ── HTTP Handlers ──────────────────────────────────────────────────────

func handlePredictions(w http.ResponseWriter, r *http.Request) {
	if predictor == nil {
		writeJSON(w, []interface{}{})
		return
	}
	tenantID := r.URL.Query().Get("tenant")
	if tenantID != "" {
		writeJSON(w, predictor.GetTenantPredictions(tenantID))
		return
	}
	writeJSON(w, predictor.GetPredictions())
}
