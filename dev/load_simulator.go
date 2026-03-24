package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Tenant behavior profiles
type TenantProfile struct {
	Name        string
	Schema      string
	QPS         int           // queries per second
	QueryDelay  time.Duration // simulated query complexity
	BurstChance float64       // chance of sudden burst (0-1)
	BurstMulti  int           // burst multiplier
	HeavyQuery  bool          // runs expensive full-table scans
}

var profiles = []TenantProfile{
	// Normal tenants - well-behaved
	{Name: "Hooli (normal)", Schema: "hooli", QPS: 2, QueryDelay: 5 * time.Millisecond, BurstChance: 0.01, BurstMulti: 3},
	{Name: "Pied Piper (normal)", Schema: "pied_piper", QPS: 1, QueryDelay: 3 * time.Millisecond, BurstChance: 0.01, BurstMulti: 2},
	{Name: "Globex (light)", Schema: "globex_inc", QPS: 1, QueryDelay: 2 * time.Millisecond, BurstChance: 0.0, BurstMulti: 1},
	{Name: "Initech (light)", Schema: "initech", QPS: 1, QueryDelay: 1 * time.Millisecond, BurstChance: 0.0, BurstMulti: 1},

	// The noisy neighbor - acme_corp goes crazy
	{Name: "ACME Corp (NOISY)", Schema: "acme_corp", QPS: 10, QueryDelay: 50 * time.Millisecond, BurstChance: 0.15, BurstMulti: 5, HeavyQuery: true},

	// Medium usage
	{Name: "Wayne Enterprises (medium)", Schema: "wayne_enterprises", QPS: 3, QueryDelay: 10 * time.Millisecond, BurstChance: 0.05, BurstMulti: 3},
	{Name: "Stark Industries (medium)", Schema: "stark_industries", QPS: 2, QueryDelay: 8 * time.Millisecond, BurstChance: 0.03, BurstMulti: 2},
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://ec2-user@localhost:5432/sg_test_schema?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(20)

	if err := db.Ping(); err != nil {
		log.Fatal("Cannot connect:", err)
	}

	// Ensure tables exist in each schema
	for _, p := range profiles {
		ensureSchema(db, p.Schema)
	}

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║         FaultWall Load Simulator v1.0           ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Tenants: %-39d║\n", len(profiles))
	fmt.Println("║  Noisy neighbor: acme_corp (10 QPS + bursts)    ║")
	fmt.Println("║  Normal tenants: 1-3 QPS                        ║")
	fmt.Println("║                                                  ║")
	fmt.Println("║  Run FaultWall in another terminal:              ║")
	fmt.Println("║  DATABASE_URL=... go run .                       ║")
	fmt.Println("║                                                  ║")
	fmt.Println("║  Watch: http://localhost:8080/api/agents/status  ║")
	fmt.Println("║  Costs: http://localhost:8080/api/costs          ║")
	fmt.Println("║  Anomalies: http://localhost:8080/api/anomalies  ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()

	var wg sync.WaitGroup

	for _, profile := range profiles {
		wg.Add(1)
		go func(p TenantProfile) {
			defer wg.Done()
			runTenant(db, p)
		}(profile)
	}

	// Phase announcer
	go func() {
		phases := []struct {
			delay   time.Duration
			message string
		}{
			{30 * time.Second, "📊 Phase 1: Baselines building... (anomaly detector needs ~10 samples)"},
			{60 * time.Second, "📊 Phase 2: Baselines established. Watch for anomalies on acme_corp."},
			{90 * time.Second, "🔥 Phase 3: ACME CORP BURST MODE — doubling their load!"},
			{150 * time.Second, "📊 Phase 4: ACME calming down. Watch anomalies resolve."},
			{210 * time.Second, "🔥 Phase 5: ACME GOING NUCLEAR — 5x load spike!"},
			{270 * time.Second, "📊 Phase 6: Back to normal. Check /api/anomalies for history."},
		}

		start := time.Now()
		for _, phase := range phases {
			time.Sleep(phase.delay - time.Since(start))
			start = time.Now()
			fmt.Printf("\n⏱  %s\n\n", phase.message)

			// Actually modify acme's behavior
			switch phase.message {
			case "🔥 Phase 3: ACME CORP BURST MODE — doubling their load!":
				acmeBurstMode = 2
			case "📊 Phase 4: ACME calming down. Watch anomalies resolve.":
				acmeBurstMode = 1
			case "🔥 Phase 5: ACME GOING NUCLEAR — 5x load spike!":
				acmeBurstMode = 5
			case "📊 Phase 6: Back to normal. Check /api/anomalies for history.":
				acmeBurstMode = 1
			}
		}
	}()

	wg.Wait()
}

var acmeBurstMode = 1

func runTenant(db *sql.DB, p TenantProfile) {
	ticker := time.NewTicker(time.Second / time.Duration(p.QPS))
	defer ticker.Stop()

	queryCount := 0
	for range ticker.C {
		// Calculate effective QPS with burst
		effectiveQPS := 1
		if p.Schema == "acme_corp" {
			effectiveQPS = acmeBurstMode
		} else if rand.Float64() < p.BurstChance {
			effectiveQPS = p.BurstMulti
		}

		for i := 0; i < effectiveQPS; i++ {
			go func() {
				runQuery(db, p)
				queryCount++
				if queryCount%100 == 0 {
					fmt.Printf("  [%s] %d queries executed\n", p.Name, queryCount)
				}
			}()
		}
	}
}

func runQuery(db *sql.DB, p TenantProfile) {
	queries := []string{
		fmt.Sprintf("SELECT count(*) FROM %s.users", p.Schema),
		fmt.Sprintf("SELECT * FROM %s.users ORDER BY id LIMIT 10", p.Schema),
		fmt.Sprintf("SELECT * FROM %s.orders WHERE id > $1 LIMIT 5", p.Schema),
	}

	if p.HeavyQuery {
		// Expensive queries that the noisy neighbor runs
		queries = append(queries,
			fmt.Sprintf("SELECT u.*, o.* FROM %s.users u LEFT JOIN %s.orders o ON u.id = o.user_id", p.Schema, p.Schema),
			fmt.Sprintf("SELECT count(*), avg(id) FROM %s.orders GROUP BY user_id", p.Schema),
			fmt.Sprintf("SELECT * FROM %s.orders ORDER BY random() LIMIT 100", p.Schema),
		)
	}

	query := queries[rand.Intn(len(queries))]

	// Add artificial delay for complex queries
	if p.QueryDelay > 0 {
		// Use pg_sleep for realistic pg_stat_statements timing
		sleepMs := float64(p.QueryDelay.Milliseconds()) / 1000.0
		if p.HeavyQuery && rand.Float64() < 0.3 {
			sleepMs *= 3 // Some queries are extra slow
		}
		query = fmt.Sprintf("SELECT pg_sleep(%f), (%s) as result", sleepMs, query)
	}

	ctx := db.QueryRow(query, rand.Intn(1000))
	var result interface{}
	ctx.Scan(&result) // We don't care about errors, just generating load
}

func ensureSchema(db *sql.DB, schema string) {
	// Create schema if not exists
	db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema))

	// Create tables if not exist
	db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.users (
		id SERIAL PRIMARY KEY,
		name TEXT,
		email TEXT,
		created_at TIMESTAMP DEFAULT now()
	)`, schema))

	db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.orders (
		id SERIAL PRIMARY KEY,
		user_id INTEGER,
		amount DECIMAL,
		status TEXT DEFAULT 'pending',
		created_at TIMESTAMP DEFAULT now()
	)`, schema))

	// Seed some data if empty
	var count int
	db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s.users", schema)).Scan(&count)
	if count == 0 {
		for i := 0; i < 100; i++ {
			db.Exec(fmt.Sprintf("INSERT INTO %s.users (name, email) VALUES ($1, $2)", schema),
				fmt.Sprintf("user_%d", i), fmt.Sprintf("user_%d@%s.com", i, schema))
		}
		for i := 0; i < 500; i++ {
			db.Exec(fmt.Sprintf("INSERT INTO %s.orders (user_id, amount, status) VALUES ($1, $2, $3)", schema),
				rand.Intn(100)+1, rand.Float64()*1000, []string{"pending", "completed", "cancelled"}[rand.Intn(3)])
		}
		fmt.Printf("  ✅ Seeded %s: 100 users, 500 orders\n", schema)
	}
}
