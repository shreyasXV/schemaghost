# SchemaGhost 👻

> **Multi-tenant PostgreSQL observability in a single Docker container.**

SchemaGhost automatically detects how your application isolates tenants, then gives you a real-time dashboard showing exactly who's consuming your database resources.

---

## Quick Start

```bash
docker run -e DATABASE_URL=postgres://user:pass@host:5432/dbname -p 8080:8080 ghcr.io/shreyasxv/schemaghost:latest
```

Open [http://localhost:8080](http://localhost:8080) — that's it.

---

## Screenshot

![SchemaGhost Dashboard](docs/screenshot.png)

*(Dark theme, real-time tenant leaderboard, latency percentiles, slow query explorer)*

---

## What It Detects

SchemaGhost auto-detects your tenant isolation pattern on startup:

| Pattern | How it's detected | Example |
|---|---|---|
| **Schema-per-tenant** | Multiple non-system schemas with similar table structures | `tenant_acme.orders`, `tenant_globex.orders` |
| **Row-level isolation** | Tables with columns like `tenant_id`, `org_id`, `account_id` | `orders WHERE tenant_id = 'acme'` |
| **Single-tenant** | Fallback when no multi-tenant pattern found | Traditional single-database app |

---

## Dashboard Features

- 🏆 **Tenant Leaderboard** — sortable table with queries, avg latency, P50/P95/P99, rows read, connections, I/O
- 🐌 **Top Slow Queries** — top 10 slowest queries with tenant attribution
- 📊 **Resource Overview** — total connections, queries/sec, cache hit ratio
- ⚡ **Auto-refresh** every 5 seconds, no page reload
- 📱 **Mobile responsive**, dark theme, no external dependencies

---

## Enabling pg_stat_statements

SchemaGhost uses `pg_stat_statements` for per-query metrics. Without it, you still get connection and I/O metrics.

**Step 1:** Add to `postgresql.conf`:
```
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track = all
```

**Step 2:** Restart PostgreSQL, then run:
```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

**AWS RDS / Aurora:** Enable via parameter group (`shared_preload_libraries = pg_stat_statements`), then reboot the instance.

**Managed databases (Supabase, Neon, etc.):** Usually already enabled. Just run the `CREATE EXTENSION` command.

---

## Dev Setup (with sample data)

```bash
git clone https://github.com/shreyasXV/schemaghost
cd schemaghost
docker compose up
```

This starts a PostgreSQL instance with three demo tenant schemas pre-seeded, plus SchemaGhost on port 8080.

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard HTML |
| `GET /api/tenants` | JSON tenant leaderboard |
| `GET /api/queries` | JSON top slow queries |
| `GET /api/health` | Health check + overview stats |
| `GET /api/config` | Detected isolation pattern + config |

---

## Configuration

| Env Var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | — | PostgreSQL connection string |
| `PORT` | ❌ | `8080` | HTTP port to listen on |

---

## Architecture

```
schemaghost/
├── main.go          # HTTP server, startup checks
├── collector.go     # Metrics collection from pg_stat_*
├── detector.go      # Tenant isolation pattern detection
├── dashboard.go     # HTTP handlers
└── templates/
    └── dashboard.html  # Single-file dashboard (vanilla JS)
```

Built with Go stdlib + [lib/pq](https://github.com/lib/pq). No frameworks, no build steps, single binary.

---

## License

MIT
