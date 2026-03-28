package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var (
	db              *sql.DB
	collector       *Collector
	detector        *Detector
	alertManager    *AlertManager
	historyStore    *HistoryStore
	slackBot        *SlackNotifier
	throttler       *Throttler
	costEstimator   *CostEstimator
	anomalyDetector *AnomalyDetector
	predictor       *Predictor
	agentTracker    *AgentTracker
	policyEngine    *PolicyEngine
)

func main() {
	// Check for --mcp flag
	mcpMode := false
	tunerMode := false
	for _, arg := range os.Args[1:] {
		if arg == "--mcp" {
			mcpMode = true
		}
		if arg == "--tune" {
			tunerMode = true
		}
	}

	// Tuner mode — run autoresearch optimization, no DB needed
	if tunerMode {
		result := RunTuner(100, 50, 0.3)
		outPath := "tuner_results/latest.json"
		os.MkdirAll("tuner_results", 0755)
		if err := SaveTunerResult(result, outPath); err != nil {
			log.Fatalf("Error saving: %v", err)
		}
		fmt.Printf("  Results saved to: %s\n", outPath)
		return
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Optional env vars
	slackWebhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	alertWebhookURL := os.Getenv("ALERT_WEBHOOK_URL")

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("✅ Connected to PostgreSQL")

	// Check pg_stat_statements
	var extExists bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&extExists)
	if err != nil || !extExists {
		fmt.Println(`
⚠️  pg_stat_statements extension is NOT enabled.

To enable it, run as a superuser:
  CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

And add to postgresql.conf:
  shared_preload_libraries = 'pg_stat_statements'

Then restart PostgreSQL. FaultWall will run in degraded mode without query-level metrics.`)
	} else {
		log.Println("✅ pg_stat_statements extension detected")
	}

	// Initialize subsystems
	slackBot = NewSlackNotifier(slackWebhookURL)
	alertManager = NewAlertManager(alertWebhookURL, slackBot)
	historyStore = NewHistoryStore()
	throttler = NewThrottler(slackBot)
	costEstimator = NewCostEstimator()
	anomalyDetector = NewAnomalyDetector(slackBot)
	predictor = NewPredictor()

	if slackWebhookURL != "" {
		log.Println("✅ Slack notifications enabled")
	}
	if alertWebhookURL != "" {
		log.Printf("✅ Alert webhook configured: %s", alertWebhookURL)
	}
	log.Printf("✅ History store initialized (retention: %s)", os.Getenv("HISTORY_RETENTION"))
	log.Printf("✅ Throttler initialized (enabled: %v)", throttler.GetConfig().Enabled)
	log.Printf("✅ Cost estimator initialized (RDS hourly: $%.2f)", costEstimator.rdsHourlyCost)
	log.Printf("✅ Anomaly detector initialized (window: %d, sensitivity: %.1f)", anomalyDetector.windowSize, anomalyDetector.sensitivity)
	log.Printf("✅ Predictor initialized (threshold: %.0fms)", predictor.thresholdMs)

	agentTracker = NewAgentTracker()
	policyEngine = NewPolicyEngine()
	log.Printf("Policy engine initialized (enforcement: %s, file: %s)", policyEngine.enforcement, policyEngine.filePath)

	detector = NewDetector(db)
	collector = NewCollector(db)

	// Run initial detection
	if err := detector.Detect(); err != nil {
		log.Printf("⚠️  Tenant detection warning: %v", err)
	} else {
		log.Printf("🔍 Detected isolation pattern: %s", detector.Pattern)
		if len(detector.Tenants) > 0 {
			log.Printf("👥 Found %d tenants", len(detector.Tenants))
		}
	}

	// Get max connections for alert evaluation
	var maxConns int
	if err := db.QueryRow(`SHOW max_connections`).Scan(&maxConns); err != nil {
		maxConns = 100
	}

	// Start background collection
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			if err := collector.Collect(detector); err != nil {
				log.Printf("Collection error: %v", err)
			} else {
				data := collector.GetData()
				historyStore.Record(data)
				alertManager.Evaluate(data, maxConns)
				throttler.Evaluate(db, detector)
				costEstimator.Estimate(data)
				anomalyDetector.Evaluate(data)
				predictor.Evaluate(data)
			}
			// Poll agent connections and enforce policies
			if err := agentTracker.Poll(db); err != nil {
				log.Printf("Agent tracker poll error: %v", err)
			} else {
				conns := agentTracker.GetConnections()
				if len(conns) > 0 {
					log.Printf("🔍 Agent poll: found %d agent connections", len(conns))
					for _, conn := range conns {
						log.Printf("  → pid=%d agent=%s state=%s query=%s", conn.PID, conn.ApplicationName, conn.State, conn.Query)
						policyEngine.EnforceOnConnection(db, conn)
					}
				}
			}
			<-ticker.C
		}
	}()

	// Run first collection immediately
	if err := collector.Collect(detector); err != nil {
		log.Printf("Initial collection warning: %v", err)
	} else {
		data := collector.GetData()
		historyStore.Record(data)
		costEstimator.Estimate(data)
	}

	// MCP mode: run JSON-RPC server over stdin/stdout
	if mcpMode {
		runMCP()
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/api/tenants", handleTenants)
	mux.HandleFunc("/api/queries", handleQueries)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/config", handleConfig)

	// Alerts
	mux.HandleFunc("/api/alerts", handleAlerts)
	mux.HandleFunc("/api/alerts/history", handleAlertsHistory)
	mux.HandleFunc("/api/alerts/rules", handleAlertsRules)

	// History / time-series
	mux.HandleFunc("/api/history", handleHistory)
	mux.HandleFunc("/api/history/overview", handleHistoryOverview)

	// Throttle
	mux.HandleFunc("/api/throttle/status", handleThrottleStatus)
	mux.HandleFunc("/api/throttle/config", handleThrottleConfig)

	// Cost attribution
	mux.HandleFunc("/api/costs", handleCosts)

	// Anomaly detection
	mux.HandleFunc("/api/anomalies", handleAnomalies)
	mux.HandleFunc("/api/anomalies/baseline", handleTenantBaseline)

	// Predictions
	mux.HandleFunc("/api/predictions", handlePredictions)

	// Agent-native API
	mux.HandleFunc("/api/agents/status", handleAgentStatus)
	mux.HandleFunc("/api/agents/noisy", handleAgentNoisy)
	mux.HandleFunc("/api/agents/tenant/", handleAgentTenant)
	mux.HandleFunc("/api/agents/costs", handleAgentCosts)
	mux.HandleFunc("/api/agents/recommendation", handleAgentRecommendation)
	mux.HandleFunc("/api/agents/anomalies", handleAgentAnomalies)
	mux.HandleFunc("/api/agents/predictions", handleAgentPredictions)

	// Firewall: agent identity + policy enforcement
	mux.HandleFunc("/api/firewall/agents", handleFirewallAgents)
	mux.HandleFunc("/api/firewall/agents/", handleFirewallAgentQueries)
	mux.HandleFunc("/api/policies", handlePolicies)
	mux.HandleFunc("/api/policies/reload", handlePoliciesReload)
	mux.HandleFunc("/api/violations", handleViolations)

	// Export
	mux.HandleFunc("/api/export/csv", handleExportCSV)
	mux.HandleFunc("/api/export/json", handleExportJSON)

	log.Printf("🚀 FaultWall running on http://0.0.0.0:%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
