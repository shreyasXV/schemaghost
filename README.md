<p align="center">
  <img src="assets/logos/icon.png" alt="FaultWall" width="80">
  <h1 align="center">FaultWall</h1>
  <p align="center"><strong>The Agentic Data Firewall for PostgreSQL</strong></p>
  <p align="center">Identity-aware policy enforcement for AI agents. Block rogue queries, protect PII, attribute costs — at the kernel level.</p>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/shreyasXV/faultwall"><img src="https://goreportcard.com/badge/github.com/shreyasXV/faultwall" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/go-1.21+-00ADD8.svg" alt="Go 1.21+">
  <img src="https://img.shields.io/badge/postgres-14+-336791.svg" alt="PostgreSQL 14+">
</p>

---

**Your AI agent has database credentials. What could go wrong?**

A prompt injection hides a `DROP TABLE` in a customer feedback comment. Your agent blindly executes it. The WAF sees nothing — it's a legitimate connection with valid credentials. The database sees a normal query from an authorized user.

FaultWall sees the intent. It knows which agent is running, what mission it's on, and what it's allowed to do. When the agent tries to access a table outside its mission scope — FaultWall kills the connection before the query completes.

```
Agent: agent:cursor-ai:mission:summarize-feedback
Query: SELECT * FROM public.users        ← blocked table  
Action: 🚨 pg_terminate_backend(pid)     ← connection killed
Reason: blocked_table (not in mission scope)
```

```bash
# One binary. One policy file. Done.
DATABASE_URL=postgres://user:pass@host:5432/db POLICY_FILE=./policies.yaml ./faultwall
```

---

## How it works

**1. Agents identify themselves** via PostgreSQL's `application_name`:
```sql
SET application_name = 'agent:cursor-ai:mission:summarize-feedback';
```

**2. Policies define what each agent can do** (`policies.yaml`):
```yaml
agents:
  cursor-ai:
    missions:
      summarize-feedback:
        tables: [public.feedback, public.products]
    blocked_operations: [DROP, TRUNCATE, DELETE, ALTER, CREATE, GRANT]
    blocked_tables: [public.users, public.payments]
```

**3. FaultWall enforces in real-time** — polls `pg_stat_activity`, parses the query, checks against the policy, terminates violating connections instantly.

---

## Features

🛡️ **Agent Firewall** — Mission-scoped policies. Agent X can only `SELECT` on tables Y, Z during this mission. Everything else is blocked.

🔍 **Anomaly Detection** — Genetic algorithm-tuned baselines per tenant. Learns what "normal" looks like, flags deviations automatically.

⚡ **Auto-Throttling** — Kills runaway queries, enforces per-tenant connection limits before they cascade.

💰 **Cost Attribution** — "Tenant acme_corp costs $338/mo of your $360 RDS bill." Per-tenant cost breakdowns in real-time.

📊 **Real-Time Dashboard** — Violations, agent connections, tenant leaderboard, anomalies, predictions. Auto-refreshes.

🤖 **MCP Server** — 10 tools for AI agent control. Agents can check policies and manage themselves autonomously.

🔬 **eBPF Tracing** — Kernel-level verification that agents didn't bypass the proxy. *(Enterprise tier)*

---

## Quick Start (5 minutes)

### Step 1: Install

```bash
git clone https://github.com/shreyasXV/faultwall && cd faultwall
go build -o faultwall .
```

Or use Docker:
```bash
docker pull ghcr.io/shreyasxv/faultwall:latest
```

### Step 2: Write your policy

Create `policies.yaml` — this is where you define what each agent is allowed to do:

```yaml
# Default: block any agent not explicitly listed
default_policy: deny

agents:
  cursor-ai:
    description: "Cursor IDE agent"
    # Never allow these operations from this agent
    blocked_operations: [DROP, TRUNCATE, DELETE, ALTER, GRANT]
    # Never allow access to these tables
    blocked_tables: [public.users, public.payments]
    # Per-mission permissions
    missions:
      summarize-feedback:
        tables: [public.feedback, public.products]
        max_rows: 1000
        max_query_time_ms: 5000
      update-shipping:
        tables: [public.orders]
        conditions: ["UPDATE must include WHERE clause"]

  langchain-agent:
    description: "LangChain research agent"
    blocked_operations: [DROP, TRUNCATE, ALTER, GRANT]
    missions:
      analyze-trends:
        tables: [public.orders, public.products]
        max_rows: 5000

# What to do with connections that don't identify as an agent
unidentified:
  policy: monitor    # monitor | deny | allow
```

### Step 3: Run FaultWall

```bash
DATABASE_URL="postgres://user:pass@localhost:5432/mydb?sslmode=disable" \
POLICY_FILE=./policies.yaml \
POLICY_ENFORCEMENT=enforce \
./faultwall
```

FaultWall starts on [http://localhost:8080](http://localhost:8080) with the dashboard, API, and policy enforcement.

### Step 4: Configure your agents

In your agent code, set the identity before running queries:

```sql
SET application_name = 'agent:cursor-ai:mission:summarize-feedback';
```

For Python (psycopg2):
```python
conn = psycopg2.connect(dsn, application_name="agent:cursor-ai:mission:summarize-feedback")
```

For Node.js (pg):
```javascript
const client = new Client({ connectionString: dsn, application_name: "agent:cursor-ai:mission:summarize-feedback" });
```

That's it. FaultWall now enforces your policies in real-time. Any agent that tries to access a table or run an operation outside its mission scope gets its connection terminated.

### Step 5: Verify it works

```bash
# Check loaded policies
curl http://localhost:8080/api/policies

# See connected agents
curl http://localhost:8080/api/firewall/agents

# View violations (blocked queries)
curl http://localhost:8080/api/violations
```

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

FaultWall is a **sidecar** — it connects to your database, polls `pg_stat_activity`, and enforces agent policies in real-time. In **monitor mode**, it's read-only and logs violations. In **enforce mode**, it actively terminates connections that violate policies using `pg_cancel_backend()` / `pg_terminate_backend()`. It never modifies your schema or data.

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
