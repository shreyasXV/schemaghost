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
- **Slow Query Explorer** — Top queries with tenant attribution and fingerprinting
- **Zero Dependencies** — Single Go binary, no frameworks, no build steps. Just `lib/pq`.
- **Dark Dashboard** — Mobile-responsive, auto-refreshing UI with no external JS dependencies

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
├── main.go          # HTTP server, startup, background loop
├── collector.go     # Metrics collection from pg_stat_* views
├── detector.go      # Tenant isolation pattern auto-detection
├── dashboard.go     # HTTP handlers + HTML dashboard
├── alerting.go      # Threshold alerting engine
├── throttle.go      # Auto-throttling (cancel/terminate runaway queries)
├── cost.go          # Per-tenant cost attribution
├── slack.go         # Slack webhook notifications
├── history.go       # In-memory time-series + export
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

## Roadmap

- **MCP Server** — Model Context Protocol integration for AI agents to query tenant health
- **AI Anomaly Detection** — ML-based anomaly detection for tenant behavior
- **Predictive Throttling** — Anticipate resource spikes before they happen
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
