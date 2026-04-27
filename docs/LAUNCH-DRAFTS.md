# v0.4.0 / v0.4.1 Launch Drafts

Three pieces for Shreyas's review. Nothing posted yet — all drafts. Revise or redline; nothing goes live without explicit approval.

---

## 1. README hero update (smallest change, biggest visibility)

**Where to insert:** Right after the existing blockquote (`> Deterministic. No LLM in the loop...`) and *before* the "A prompt injection hides..." paragraph. This keeps the existing hero narrative intact but adds the credibility artifact visible above the fold.

**Proposed block:**

```markdown
## Works with every managed Postgres

| Deployment | Status |
|---|---|
| Self-hosted Postgres 12+ | 🟢 Green |
| AWS RDS / Aurora | 🟢 Green |
| Neon (serverless) | 🟢 Green |
| PgBouncer (transaction + session) | 🟢 Green |
| Supabase (pooler) | 🟡 Yellow — [documented workaround](docs/compatibility.md#supabase) |
| Cloud SQL, CrunchyBridge, DigitalOcean MPG | 🟢 Expected — same wire protocol as validated providers |

**Overhead:** +0.14ms per query / −15% TPS on cloud-latency paths (RDS benchmark).
**Zero code changes required** in your agent. Stock Postgres driver, standard connection string.

→ [Full compatibility matrix + SCRAM config per provider](docs/compatibility.md) · [Attack suite results](tests/compat/) · [Reproducible test harness](tests/compat/compat_test.sh)
```

**Why this placement:** the "your AI agent has your database password" framing is the emotional hook — it should stay first. The matrix is the *proof*. Separating them means readers get the pain first, then the credibility, in the right order.

**Why we don't lead with the matrix:** infrastructure buyers want to know what problem you solve before they care whether you work with their stack. Flipping the order makes us look like a compat tool, not a security product.

---

## 2. Show HN draft

**Title (pick one):**

- **A:** `Show HN: FaultWall – a Postgres proxy that survived RDS, Neon, Aurora, and Supabase`
- **B:** `Show HN: I reverse-engineered the SCRAM matrix for every managed Postgres provider so you don't have to`
- **C:** `Show HN: FaultWall – per-agent identity for your AI agents' Postgres queries`

**Recommend A.** It leads with the pain (managed Postgres compat is a graveyard), signals rigor ("survived"), and names specific brands every HN reader recognizes. B is punchier but buries the product. C is the "what," not the "why."

**Body (~400 words, Hermes's framing — "pain, not product"):**

```
Most Postgres proxies break the moment you point them at RDS. The ones that work on RDS break on Neon. The ones that work on Neon break on Supabase. Every managed provider has its own SCRAM quirk, its own TLS handshake gotcha, its own reason your proxy silently drops 40% of connections on Tuesday mornings.

We built FaultWall — a wire-level Postgres firewall for AI agents — and spent the last month finding every one of these landmines. The compat matrix is the artifact:

[link to docs/compatibility.md screenshot or table]

Specific things we found:
- RDS rejects raw tls.Dial(). You have to do the Postgres SSLRequest handshake (write 8 bytes, read 'S' or 'N', then wrap in tls.Client). Every Go proxy I could find gets this wrong.
- Neon needs channel_binding=disable on the client. So does RDS and Aurora. Supabase's Supavisor pooler rejects channel_binding=disable. Different managed providers want different SCRAM configs. There is no universal client string.
- Supabase direct endpoints are IPv6-only on free-tier projects. Your corp VPC is probably IPv4.
- Schema-unqualified table references (SELECT * FROM users) silently bypass blocked_tables lists that say "public.users" — because Postgres's search_path resolves it. Any proxy not normalizing this has a real exfil hole.

Everything above is validated in a reproducible harness (tests/compat/ in the repo). 10/10 attack-suite block rate on every platform we tested. +0.14ms per query on cloud-latency paths.

The codebase is MIT, single Go binary, no sidecar, no API key. It's at github.com/shreyasXV/faultwall and the v0.4.0 release has the tested binaries.

Happy to go deep on any of the wire-protocol specifics in the comments. The SCRAM channel-binding interaction with transparent TLS proxies specifically was maybe 20 hours of pain I wish I'd found a blog post about.
```

**Timing:** Tue–Thu, 6–9 AM PT (standard HN peak). Not Monday (competing with weekend backlog), not Friday (weekend dead zone).

**Comment-readiness:** keep Shreyas available for 2–3 hours after posting to answer. The first-hour replies determine whether it climbs. Top expected questions:
- "How does this differ from Hoop.dev / Aembit / ProxySQL?" → answer: wire-level SQL parsing with real pg_query_go, deterministic no-LLM, open core
- "What's the threat model? Isn't SQL injection already solved?" → answer: this isn't SQLi, it's the confused-deputy problem with agent credentials
- "Why not just use Postgres RBAC?" → answer: RBAC doesn't know WHICH agent made a query when they all share a service account
- "Does it work with pgx / psycopg / etc?" → answer: yes, transparent wire-level proxy, tested with libpq/pgx/psycopg

---

## 3. LinkedIn post (Shreyas's voice, founder-first-person)

**~180 words, shippable as-is or with edits:**

```
Most Postgres proxies quietly break the moment you point them at RDS or Neon.

Not because proxying is hard — because every managed Postgres provider has its own SCRAM auth quirks, TLS handshake rules, and undocumented gotchas. You find them by watching 40% of your connections fail on a Tuesday morning.

For the last month I've been testing FaultWall (the Postgres firewall for AI agents I've been building) against every managed provider I could get access to:

✓ AWS RDS / Aurora
✓ Neon
✓ PgBouncer (transaction + session)
✓ Self-hosted PG
⚠ Supabase (works, with a documented quirk we're fixing in v0.5)

v0.4 just shipped. +0.14ms overhead on cloud latency. 10/10 attack-suite block rate.

The part that surprised me most: the SCRAM channel-binding interaction with transparent TLS proxies. Different providers want different client flags. Built a config matrix so nobody has to learn this the way I did.

Repo + compat doc: github.com/shreyasXV/faultwall

If you're running agents against Postgres and worried about prompt-injection-induced queries, I'd love to hear what your setup looks like.
```

**Target audience:** Tier 1 CISO + platform eng list from the prior outreach batch. They've seen the cold DM — this gives them a reason to reply with "saw your launch."

**Don't @-mention** anyone in the post. Let them find it. Mentions come off as needy.

---

## Sequence

1. **Tomorrow (Apr 27):** Shreyas reviews these three drafts. Revises or approves. Nothing goes live.
2. **Apr 28 (Tue):** README hero update merges first (isolated PR). Low-risk, immediate credibility upgrade for anyone landing on the repo.
3. **Apr 29–30 (Wed/Thu):** Show HN posts at 6–9 AM PT. LinkedIn post same day, ~2 hours after HN to avoid split attention.
4. **May 4:** YC S26 deadline. App cites v0.4.x as the working compat release, links docs/compatibility.md as the "evidence of rigor" artifact.

Hold Show HN + LinkedIn until Docker image publish is confirmed — HN readers want `docker run` to work in the first minute.

---

## Open questions for Shreyas

1. Which Show HN title (A/B/C)?
2. LinkedIn post — keep the ⚠ emoji or strip? I used it sparingly but LinkedIn-norms vary
3. Anything in the compat matrix you want to qualify differently before it's on HN's front page? "Cloud SQL / CrunchyBridge / DO MPG = Expected" is an honest claim but not a tested one — if you'd rather I mark those as "untested" or drop them, say so now
4. Post from your personal account or FaultWall account on both HN and LinkedIn?
