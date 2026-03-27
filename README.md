<p align="center">
  <img src="logo-v3.svg.png" alt="FaultWall" width="80">
  <h1 align="center">FaultWall</h1>
  <p align="center"><strong>Autonomous Database SRE — detects anomalies, kills runaway queries, attributes costs.</strong></p>
  <p align="center">eBPF-powered query detection and auto-throttling for PostgreSQL. One binary. Open source.</p>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/shreyasXV/faultwall"><img src="https://goreportcard.com/badge/github.com/shreyasXV/faultwall" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/go-1.21+-00ADD8.svg" alt="Go 1.21+">
  <img src="https://img.shields.io/badge/postgres-14+-336791.svg" alt="PostgreSQL 14+">
</p>

---

**Your database is running a query that's about to take everyone down.** A bad JOIN, a missing index, an AI agent that just fired a full table scan. By the time you get paged, P99 is at 12 seconds and customers are churning. FaultWall detects it, kills the query, and tells you exactly which tenant caused it — autonomously, in real time.

```bash
# One binary. One env var. Done.
DATABASE_URL=postgres://user:pass@host:5432/db ./faultwall
# → http://localhost:8080
```

---

## What it does

🔍 **Detects** — Auto-identifies your tenant isolation pattern (schema-per-tenant, row-level, database-per-tenant) and starts tracking per-tenant metrics immediately.

📊 **Monitors** — Real-time dashboard showing tenant leaderboard, top slow queries, cost attribution, anomaly alerts, and breach predictions. Auto-refreshes every 5 seconds.

🧠 **Learns** — Statistical anomaly detection builds per-tenant baselines. No LLM needed — z-score analysis flags when a tenant deviates from their normal behavior.

🔮 **Predicts** — Linear regression on metric trends: "acme_corp will breach the query time threshold in ~4 minutes." Gives you time to act before the outage.

⚡ **Throttles** — Auto-kills runaway queries, enforces per-tenant connection limits. Configurable grace periods and escalation (cancel → terminate).

💰 **Attributes cost** — "Tenant acme_corp is responsible for 74% of your database work and costs $338/mo of your $360 RDS bill." Finance teams love this.

🤖 **AI-native** — MCP server (10 tools) + agent REST API. AI agents can query tenant health, detect noisy neighbors, and throttle them — no human in the loop.

---

## Quick Start

### Option 1: Binary

```bash
git clone https://github.com/shreyasXV/faultwall && cd faultwall
go build -o faultwall .
DATABASE_URL="postgres://user:pass@localhost:5432/mydb?sslmode=disable" ./faultwall
```

### Option 2: Docker

```bash
docker run -e DATABASE_URL=postgres://user:pass@host:5432/dbname -p 8080:8080 ghcr.io/shreyasxv/faultwall:latest
```

### Option 3: Docker Compose (with demo data)

```bash
git clone https://github.com/shreyasXV/faultwall && cd faultwall
docker compose up
```

Starts PostgreSQL with demo tenant schemas + FaultWall on [localhost:8080](http://localhost:8080).

> **Requires `pg_stat_statements`** — see [setup](#enabling-pg_stat_statements) below.

---

## Dashboard

The dashboard shows 6 panels, all auto-refreshing:

| Panel | What you see |
|-------|-------------|
| **Resource Overview** | Connections, QPS, cache hit ratio, DB size |
| **Tenant Leaderboard** | Ranked by queries, latency, rows, connections — click to expand |
| **Top Slow Queries** | Worst queries with tenant attribution |
| **💰 Cost per Tenant** | Monthly cost estimate with proportion bars |
| **🔥 Active Anomalies** | Severity badges, z-scores, timestamps |
| **🔮 Predictions** | Trend arrows, breach forecasts, R² confidence |
| **🛡️ Throttle Status** | Per-tenant throttle indicators |

---

## For AI Agents (MCP)

FaultWall is **AI-native**. It exposes an [MCP server](https://modelcontextprotocol.io) so AI agents can monitor and control your database autonomously.

### Setup

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "faultwall": {
      "command": "./faultwall",
      "args": ["--mcp"],
      "env": {
        "DATABASE_URL": "postgres://user:pass@localhost:5432/mydb"
      }
    }
  }
}
```

### 10 MCP Tools

| Tool | Description |
|------|-------------|
| `list_tenants` | All tenants with metrics and cost |
| `get_tenant` | Deep-dive on one tenant |
| `get_noisy_tenants` | Tenants above latency threshold |
| `get_costs` | Cost attribution breakdown |
| `get_tenant_cost` | Cost for a specific tenant |
| `throttle_tenant` | Cancel or terminate a tenant's queries |
| `get_health` | Overall DB health |
| `get_throttle_events` | Recent throttle actions |
| `get_anomalies` | Active anomalies (z-score) |
| `get_predictions` | Trend predictions + breach forecasts |

### Example

> **You:** "Which tenants are noisy right now?"  
> **Claude** calls `get_noisy_tenants` →  
> **Claude:** "acme_corp has avg query time 234ms and is using 74% of resources ($338/mo). Recommend throttling."

---

## Agent REST API

Higher-level endpoints with `summary` fields — designed for LLMs, not just JSON parsers.

| Endpoint | Description |
|----------|-------------|
| `GET /api/agents/status` | One-call overview: health, noisy tenants, alerts |
| `GET /api/agents/noisy` | Noisy tenants with context |
| `GET /api/agents/tenant/{id}` | Tenant detail with plain-English summary |
| `POST /api/agents/tenant/{id}` | Throttle a tenant |
| `GET /api/agents/recommendation` | AI-generated suggested actions |
| `GET /api/agents/anomalies` | Active anomalies with summaries |
| `GET /api/agents/predictions` | Predicted breaches with summaries |

---

## How it works

```
┌─────────────────┐         ┌──────────────┐
│ Your Application │────────▶│  PostgreSQL   │
└─────────────────┘         └──────┬───────┘
                                   │
                            ┌──────┴───────┐
                            │  FaultWall    │  ← polls pg_stat_statements
                            │  (sidecar)    │     every 10 seconds
                            └──┬──┬──┬──┬──┘
                               │  │  │  │
              ┌────────────────┘  │  │  └────────────────┐
              ▼                   ▼  ▼                   ▼
        ┌──────────┐     ┌──────────┐  ┌──────────┐  ┌──────────┐
        │Dashboard │     │ Anomaly  │  │Throttler │  │MCP Server│
        │ :8080    │     │ Detector │  │          │  │ (AI)     │
        └──────────┘     └──────────┘  └──────────┘  └──────────┘
```

FaultWall is a **sidecar** — it connects to your database as a read-only client, polls `pg_stat_statements` and `pg_stat_activity`, and builds a tenant-aware view. It never modifies your data. Throttling uses `pg_cancel_backend()` / `pg_terminate_backend()` on runaway queries only.

### Tenant detection

FaultWall automatically detects how your app isolates tenants:

| Pattern | How it detects | Accuracy |
|---------|---------------|----------|
| **Schema-per-tenant** | Queries contain `schema.table` | ⭐⭐⭐ Best |
| **Row-level isolation** | `WHERE tenant_id = X` in queries | ⭐⭐ Good |
| **Database-per-tenant** | Separate databases per tenant | ⭐⭐ Good |

No config needed. Point it at your database and it figures it out.

---

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `DATABASE_URL` | **(required)** | PostgreSQL connection string |
| `PORT` | `8080` | HTTP server port |
| `SLACK_WEBHOOK_URL` | — | Slack webhook for alerts |
| `THROTTLE_ENABLED` | `false` | Enable auto-throttling |
| `THROTTLE_MAX_QUERY_TIME_MS` | `30000` | Kill queries longer than this |
| `THROTTLE_MAX_CONNECTIONS_PER_TENANT` | `50` | Max connections per tenant |
| `THROTTLE_ACTION` | `cancel` | `cancel` or `terminate` |
| `THROTTLE_GRACE_PERIOD_MS` | `5000` | Grace period before escalation |
| `RDS_HOURLY_COST` | `0.50` | Hourly DB cost for attribution |
| `ANOMALY_SENSITIVITY` | `2.0` | Z-score threshold (std deviations) |
| `PREDICT_THRESHOLD_MS` | `30000` | Prediction breach threshold |
| `HISTORY_RETENTION` | `24h` | Time-series retention |

---

## Full API Reference

<details>
<summary><strong>Core APIs</strong></summary>

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard |
| `GET /api/tenants` | Tenant leaderboard |
| `GET /api/queries` | Top slow queries |
| `GET /api/health` | Health check + overview |
| `GET /api/config` | Detected isolation pattern |

</details>

<details>
<summary><strong>Alerts</strong></summary>

| Endpoint | Description |
|----------|-------------|
| `GET /api/alerts` | Active alerts |
| `GET /api/alerts/history` | Alert history |
| `GET /api/alerts/rules` | List rules |
| `POST /api/alerts/rules` | Add rule |
| `DELETE /api/alerts/rules?id=X` | Remove rule |

</details>

<details>
<summary><strong>Throttle</strong></summary>

| Endpoint | Description |
|----------|-------------|
| `GET /api/throttle/status` | Status + config + events |
| `GET /api/throttle/config` | Current config |
| `POST /api/throttle/config` | Update config |

</details>

<details>
<summary><strong>Cost Attribution</strong></summary>

| Endpoint | Description |
|----------|-------------|
| `GET /api/costs` | All tenants |
| `GET /api/costs?tenant=X` | Specific tenant |

</details>

<details>
<summary><strong>Anomaly Detection & Predictions</strong></summary>

| Endpoint | Description |
|----------|-------------|
| `GET /api/anomalies` | Active anomalies + baselines |
| `GET /api/anomalies/baseline?tenant=X` | Full baseline for tenant |
| `GET /api/predictions` | Breach predictions |
| `GET /api/predictions?tenant=X` | Predictions for tenant |

</details>

<details>
<summary><strong>History & Export</strong></summary>

| Endpoint | Description |
|----------|-------------|
| `GET /api/history?tenant=X&metric=p99_ms&period=1h` | Time-series |
| `GET /api/history/overview?period=1h` | Overview time-series |
| `GET /api/export/csv` | CSV export |
| `GET /api/export/json` | JSON snapshot |

</details>

---

## Enabling pg_stat_statements

```sql
-- Add to postgresql.conf:
-- shared_preload_libraries = 'pg_stat_statements'
-- Restart PostgreSQL, then:
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

**AWS RDS/Aurora:** Enable via parameter group → reboot.  
**Supabase/Neon:** Usually pre-enabled — just `CREATE EXTENSION`.

Without it, FaultWall still works (connection + I/O metrics) but per-query data won't be available.

---

## Self-Tuning (AutoResearch)

FaultWall can optimize its own detection parameters using a genetic algorithm:

```bash
DATABASE_URL=... ./faultwall --tune
```

This runs 100 generations of parameter optimization against your workload, finding the sensitivity and window settings that maximize detection rate while minimizing false positives. No LLM needed — pure statistics.

---

## Architecture

```
faultwall/
├── main.go          # Server, startup, --mcp flag, --tune flag
├── mcp.go           # MCP server (JSON-RPC 2.0 stdio)
├── agent_api.go     # Agent REST API with summaries
├── collector.go     # pg_stat_* metrics collection
├── detector.go      # Tenant pattern auto-detection
├── anomaly.go       # Statistical anomaly detection
├── predictor.go     # Linear regression predictions
├── throttle.go      # Auto-throttling engine
├── cost.go          # Cost-per-tenant attribution
├── alerting.go      # Threshold alerting
├── slack.go         # Slack notifications
├── history.go       # Time-series + export
├── dashboard.go     # HTTP handlers
├── tuner.go         # AutoResearch genetic optimizer
└── templates/
    └── dashboard.html
```

Single binary. Zero external dependencies beyond `lib/pq`. ~5,000 lines of Go.

---

## Roadmap

- [ ] eBPF kernel-level per-query CPU/IO attribution
- [ ] SQL proxy mode (intercept queries in-flight)
- [ ] Query plan regression detection
- [ ] MySQL support
- [ ] Kubernetes operator
- [ ] Grafana plugin

---

## Contributing

Contributions welcome! Open an issue or submit a PR.

```bash
git clone https://github.com/shreyasXV/faultwall
cd faultwall
go build -o faultwall .
DATABASE_URL=... ./faultwall
```

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Built by <a href="https://github.com/shreyasXV">Shreyas Shubham</a></strong><br>
  <a href="https://twitter.com/FaultWall">@FaultWall</a>
</p>
