package main

import (
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
)

// TenantCost holds cost attribution for a single tenant
type TenantCost struct {
	TenantID          string  `json:"tenant_id"`
	QueryTimeProportion float64 `json:"query_time_proportion"`
	HourlyCost        float64 `json:"hourly_cost"`
	DailyCost         float64 `json:"daily_cost"`
	MonthlyCost       float64 `json:"monthly_cost"`
	TotalQueryTimeMs  float64 `json:"total_query_time_ms"`
}

// CostEstimator calculates per-tenant cost attribution
type CostEstimator struct {
	mu             sync.RWMutex
	rdsHourlyCost  float64
	latestCosts    []TenantCost
}

// NewCostEstimator creates a CostEstimator with config from env vars
func NewCostEstimator() *CostEstimator {
	hourlyCost := 0.50
	if v := os.Getenv("RDS_HOURLY_COST"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			hourlyCost = f
		}
	}
	return &CostEstimator{
		rdsHourlyCost: hourlyCost,
	}
}

// Estimate calculates cost attribution from the latest collector data
func (ce *CostEstimator) Estimate(data CollectorData) []TenantCost {
	// Calculate total query time across all tenants
	var totalQueryTimeMs float64
	for _, t := range data.Tenants {
		totalQueryTimeMs += t.AvgTimeMs * float64(t.Queries)
	}

	costs := make([]TenantCost, 0, len(data.Tenants))
	for _, t := range data.Tenants {
		tenantQueryTime := t.AvgTimeMs * float64(t.Queries)
		var proportion float64
		if totalQueryTimeMs > 0 {
			proportion = tenantQueryTime / totalQueryTimeMs
		}

		hourly := ce.rdsHourlyCost * proportion
		tc := TenantCost{
			TenantID:          t.TenantID,
			QueryTimeProportion: math.Round(proportion*10000) / 10000,
			HourlyCost:        math.Round(hourly*100) / 100,
			DailyCost:         math.Round(hourly*24*100) / 100,
			MonthlyCost:       math.Round(hourly*24*30*100) / 100,
			TotalQueryTimeMs:  math.Round(tenantQueryTime*100) / 100,
		}
		costs = append(costs, tc)
	}

	ce.mu.Lock()
	ce.latestCosts = costs
	ce.mu.Unlock()

	return costs
}

// GetCosts returns the latest cost estimates
func (ce *CostEstimator) GetCosts() []TenantCost {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	result := make([]TenantCost, len(ce.latestCosts))
	copy(result, ce.latestCosts)
	return result
}

// GetTenantCost returns cost for a specific tenant
func (ce *CostEstimator) GetTenantCost(tenantID string) *TenantCost {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	for _, tc := range ce.latestCosts {
		if tc.TenantID == tenantID {
			cp := tc
			return &cp
		}
	}
	return nil
}

// ── HTTP Handlers ──────────────────────────────────────────────────────

func handleCosts(w http.ResponseWriter, r *http.Request) {
	if costEstimator == nil {
		writeJSON(w, []interface{}{})
		return
	}

	// Check for single tenant query param
	tenantID := r.URL.Query().Get("tenant")
	if tenantID != "" {
		tc := costEstimator.GetTenantCost(tenantID)
		if tc == nil {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		writeJSON(w, tc)
		return
	}

	writeJSON(w, costEstimator.GetCosts())
}
