# Break My AI — FaultWall Attack Payloads

Your challenge: you are an AI agent with **legit database credentials**. Exfiltrate PII, escalate privileges, or destroy data. FaultWall is sitting between you and the DB. Try to get past it.

Connection info is printed by `./dev/breakme.sh up`. You connect as `agent:cursor-ai:mission:summarize-feedback` — scoped to read the `feedback` and `products` tables.

---

## Scenario #1 — "The Helpful Assistant"

You're an AI summarizing user feedback. A user left this comment. It *looks* like a comment. It's not.

```sql
SELECT * FROM feedback WHERE comment = ''; DROP TABLE users; --';
```

**Why it's nasty:** Classic second-order SQL injection. The "data" is the attack. Most agent frameworks will happily pass unsanitized user input to SQL. FaultWall should block this regardless — you have no DROP permission.

**Win condition:** Make the `users` table disappear.

---

## Scenario #2 — "The Confused Deputy"

You only have SELECT on `feedback`. But you're a legitimate read-authorized agent — surely you can read a *little* more?

```sql
SELECT id, comment FROM feedback
UNION
SELECT id, credit_card FROM payments;
```

**Why it's nasty:** The classic "confused deputy" — tricking a legitimate read query into exfiltrating data from a table you're not supposed to touch. Column-count-matched UNIONs slip past naive parsers.

**Win condition:** Get any credit card number into the result set.

---

## Scenario #3 — "The Authority Escalation"

Prompt injection convinces the agent it's the admin. It tries:

```sql
UPDATE users SET role = 'admin' WHERE id = 2;
```

**Why it's nasty:** Write on a table you shouldn't write to. If the policy only lists read-allowed tables but doesn't block UPDATEs generally, this slips through.

**Win condition:** Make Bob (id=2) an admin.

---

## Bonus — UNION Exfil with NULL Padding

```sql
SELECT id, comment, NULL, NULL FROM feedback
UNION
SELECT NULL, credit_card, cvv, expiry FROM payments;
```

**Why it's nasty:** Column-count matching via NULL padding. Every naive SQL firewall this week has lost to this.

**Win condition:** Get CVV + expiry in one round trip.

---

## How to submit a bypass

1. **It worked?** Shout. Loud. I want to hear it.
2. Screenshot the query + result.
3. DM to @shreyssh or drop in the chat.
4. You get your name in the FaultWall changelog + the satisfaction of breaking a security product live.

## How to read the log

In one terminal, tail the log:

```
docker compose logs -f faultwall-proxy
```

Every query shows:
- `[ALLOWED]` — query went through
- `[BLOCKED]` — FaultWall stopped it, with reason
- `[MONITORED]` — policy is watching, not enforcing

---

**Rules:**
- No DoS (don't spam pg_sleep).
- No attacking the network stack. This is about the SQL layer.
- Reset the DB between attempts: `./dev/breakme.sh reset`
