<p align="center">
  <h1 align="center">SchemaGhost</h1>
  <p align="center"><strong>Tenant-aware intelligence layer for multi-tenant PostgreSQL</strong></p>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/shreyasXV/schemaghost"><img src="https://goreportcard.com/badge/github.com/shreyasXV/schemaghost" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://ghcr.io/shreyasxv/schemaghost"><img src="https://img.shields.io/badge/docker-ghcr.io-blue.svg" alt="Docker"></a>
</p>

---

## The Problem

- **Databases don't know tenants.** PostgreSQL sees connections and queries — not which customer is behind them. When your database is on fire, you're blind to *who* caused it.
- **Datadog can't answer WHO.** APM tools show you slow queries and high CPU, but they can't tell you which tenant is consuming 80% of your resources while paying 5% of the bill.
- **AI agents are tenant-blind.** As AI-driven workloads hit your database, you need per-tenant observability to understand, attribute, and control resource consumption in real time.

SchemaGhost fixes all three. One binary, zero config, instant tenant-level visibility.

---

## Quick Start

```bash
docker run -e DATABASE_URL=postgres://user:pass@host:5432/dbname -p 8080:8080 ghcr.io/shreyasxv/schemaghost:latest
```

Open [http://localhost:8080](http://localhost:8080) — that's it.

---

## Features

- **Auto-Detection** — Automatically identifies schema-per-tenant, row-level isolation, or single-tenant patterns
- **Tenant Leaderboard** — Real-time rankings by queries, latency (P50/P95/P99), connections, I/O, and cache hit ratio
- **Auto-Throttling** — Kill or cancel runaway queries per tenant, enforce per-tenant connection limits
- **Cost Attribution** — Proportionally attribute RDS/database costs to each tenant based on query time
- **Threshold Alerts** — Configurable rules for latency, connections, cache hit, and I/O with Slack notifications
- **Slack Integration** — Color-coded alert notifications with rate limiting (5min cooldown)
- **Historical Trends** — In-memory time-series with sparklines and CSV/JSON export
- **AI Anomaly Detection** — Statistical learning builds per-tenant baselines and detects deviations using z-score analysis (no LLM required)
- **Predictive Throttling** — Linear regression on metric trends predicts when tenants will breach thresholds, with minutes-ahead warnings
- **Slow Query Explorer** — Top queries with tenant attribution and fingerprinting
- **Zero Dependencies** — Single Go binary, no frameworks, no build steps. Just `lib/pq`.
- **Dark Dashboard** — Mobile-responsive, auto-refreshing UI with no external JS dependencies

---

## For AI Agents

> **SchemaGhost is AI-native.** It exposes an MCP server and agent-optimized REST API so that AI agents (Claude, GPT, Cursor, custom copilots) can query tenant health, identify noisy neighbors, attribute costs, and throttle runaway tenants — all programmatically, in real time.

---

## MCP Integration (Model Context Protocol)

AI agents connect via MCP to query tenant health over JSON-RPC 2.0 (stdio transport).

### Setup

Add to your `claude_desktop_config.json` (or equivalent MCP client config):

```json
{
  "mcpServers": {
    "cordon": {
      "command": "./schemaghost",
      "args": ["--mcp"],
      "env": {
        "DATABASE_URL": "postgres://user:pass@localhost:5432/mydb"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|---|---|
| `list_tenants` | All tenants with current metrics and cost |
| `get_tenant` | Detailed metrics for one tenant |
| `get_noisy_tenants` | Tenants above avg query time threshold |
| `get_costs` | Cost attribution for all tenants |
| `get_tenant_cost` | Cost for a specific tenant |
| `throttle_tenant` | Cancel or terminate a tenant's active queries |
| `get_health` | Overall DB health (connections, cache hit, QPS, alerts) |
| `get_throttle_events` | Recent throttle events |
| `get_anomalies` | Active anomalies detected by statistical learning |
| `get_predictions` | Active predictions of threshold breaches |

### Example (Claude Desktop)

> "Which tenants are noisy right now?"

Claude calls `get_noisy_tenants` and returns a summary like:
> "acme_corp has avg query time 234ms (45% of resources). Recommend throttling."

---

## Agent-Native REST API

Higher-level endpoints designed for AI agents. Every response includes a `summary` field with plain-English descriptions.

| Endpoint | Method | Description |
|---|---|---|
| `/api/agents/status` | GET | One-call overview: healthy, noisy tenants, alerts, throttle events |
| `/api/agents/noisy` | GET | Noisy tenants with actionable context |
| `/api/agents/tenant/{id}` | GET | Tenant detail with plain-english summary |
| `/api/agents/tenant/{id}` | POST | Throttle a tenant (`{"action": "cancel"}`) |
| `/api/agents/costs` | GET | Simplified cost view |
| `/api/agents/recommendation` | GET | Suggested actions based on current state |
| `/api/agents/anomalies` | GET | Active anomalies with plain-english summaries |
| `/api/agents/predictions` | GET | Predicted threshold breaches with summaries |

---

## Architecture

```mermaid
graph LR
    App["Your Application"] --> PG["PostgreSQL"]
    SG["SchemaGhost"] --> PG
    SG --> Dashboard["Dashboard :8080"]
    SG --> Alerts["Slack / Webhooks"]
    SG --> API["REST API"]
    SG --> Throttle["Auto-Throttler"]
    SG --> Cost["Cost Attribution"]
```

```
schemaghost/
├── main.go          # HTTP server, startup, background loop, --mcp flag
├── mcp.go           # MCP server (JSON-RPC 2.0 over stdio)
├── agent_api.go     # Agent-native REST API with plain-english summaries
├── collector.go     # Metrics collection from pg_stat_* views
├── detector.go      # Tenant isolation pattern auto-detection
├── dashboard.go     # HTTP handlers + HTML dashboard
├── alerting.go      # Threshold alerting engine
├── throttle.go      # Auto-throttling (cancel/terminate runaway queries)
├── anomaly.go       # AI anomaly detection (statistical learning)
├── predictor.go     # Predictive throttling (trend analysis)
├── cost.go          # Per-tenant cost attribution
├── slack.go         # Slack webhook notifications
├── history.go       # In-memory time-series + export
├── mcp_config.json  # Example MCP client configuration
└── templates/
    └── dashboard.html
```

---

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `DATABASE_URL` | **(required)** | PostgreSQL connection string |
| `PORT` | `8080` | HTTP server port |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook for notifications |
| `ALERT_WEBHOOK_URL` | — | Generic webhook URL for alert JSON payloads |
| `HISTORY_RETENTION` | `24h` | In-memory time-series retention (Go duration) |
| `THROTTLE_ENABLED` | `false` | Enable auto-throttling of runaway queries |
| `THROTTLE_MAX_QUERY_TIME_MS` | `30000` | Kill queries running longer than this (ms) |
| `THROTTLE_MAX_CONNECTIONS_PER_TENANT` | `50` | Max active connections per tenant |
| `THROTTLE_ACTION` | `cancel` | `cancel` (pg_cancel_backend) or `terminate` (pg_terminate_backend) |
| `THROTTLE_GRACE_PERIOD_MS` | `5000` | Wait time before escalating cancel to terminate |
| `RDS_HOURLY_COST` | `0.50` | Hourly database cost in USD for cost attribution |
| `ANOMALY_WINDOW_SIZE` | `30` | Rolling window size for anomaly baselines (number of collection cycles) |
| `ANOMALY_SENSITIVITY` | `2.0` | Z-score threshold for anomaly detection (standard deviations) |
| `PREDICT_THRESHOLD_MS` | `30000` | Query time threshold for predictive alerts (ms) |

---

## API Reference

### Core

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | GET | Dashboard HTML |
| `GET /api/tenants` | GET | Tenant leaderboard (JSON) |
| `GET /api/queries` | GET | Top slow queries (JSON) |
| `GET /api/health` | GET | Health check + overview stats |
| `GET /api/config` | GET | Detected isolation pattern |

### Alerts

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/alerts` | GET | Active alerts |
| `GET /api/alerts/history` | GET | Alert history (last 100) |
| `GET /api/alerts/rules` | GET | List alert rules |
| `POST /api/alerts/rules` | POST | Add alert rule |
| `DELETE /api/alerts/rules?id=X` | DELETE | Remove alert rule |

### Throttle

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/throttle/status` | GET | Throttle status, config, recent events |
| `GET /api/throttle/config` | GET | Current throttle config |
| `POST /api/throttle/config` | POST | Update throttle config at runtime |

### Cost Attribution

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/costs` | GET | Cost breakdown for all tenants |
| `GET /api/costs?tenant=X` | GET | Cost for a specific tenant |

### History & Export

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/history?tenant=X&metric=p99_ms&period=1h` | GET | Tenant metric time-series |
| `GET /api/history/overview?period=1h` | GET | Overview time-series |
| `GET /api/export/csv` | GET | Export metrics as CSV |
| `GET /api/export/json` | GET | Export full snapshot as JSON |

### Anomaly Detection & Predictions

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/anomalies` | GET | Active anomalies, recent history, and baseline summaries |
| `GET /api/anomalies/baseline?tenant=X` | GET | Full baseline data for one tenant |
| `GET /api/predictions` | GET | Active threshold breach predictions |
| `GET /api/predictions?tenant=X` | GET | Predictions for a specific tenant |

---

## Enabling pg_stat_statements

SchemaGhost uses `pg_stat_statements` for per-query metrics. Without it, you still get connection and I/O metrics.

```sql
-- Add to postgresql.conf:
-- shared_preload_libraries = 'pg_stat_statements'
-- Then restart PostgreSQL and run:
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

**AWS RDS / Aurora:** Enable via parameter group, then reboot.
**Supabase, Neon, etc.:** Usually already enabled — just run `CREATE EXTENSION`.

---

## Dev Setup

```bash
git clone https://github.com/shreyasXV/schemaghost
cd schemaghost
docker compose up
```

This starts PostgreSQL with demo tenant schemas pre-seeded, plus SchemaGhost on port 8080.

---

## AI-Powered Observability

SchemaGhost uses **statistical learning** (not LLMs) for genuine AI-powered analysis:

- **Anomaly Detection** — Maintains per-tenant rolling baselines for avg query time, query count, connections, and rows read. Uses z-score analysis to detect deviations beyond configurable sensitivity (default: 2 standard deviations). Automatically resolves anomalies when metrics return to normal for 3 consecutive cycles.

- **Predictive Throttling** — Applies linear regression to metric trends to project when a tenant will breach thresholds. Reports trend direction (accelerating/linear/decelerating), confidence (R-squared), and estimated minutes until breach. Predictions auto-expire after 10 minutes or when trends reverse.

Both systems feed into the agent recommendation engine and send Slack notifications for critical events.

## Roadmap

- **eBPF Integration** — Kernel-level query tracing for zero-overhead observability

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

Built by [Shreyas Shubham](https://github.com/shreyasXV).
