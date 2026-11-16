# Alaka

A spend-reservation kernel between AI agents and payment rails. An agent gets an Ed25519-signed
mandate (budget, per-transaction cap, merchant allowlist, validity window). Alaka executes its
payments through a PostgreSQL 16 double-entry ledger and a two-step rail protocol, so that:

- a mandate is never overspent, in the ledger or on the rail;
- each idempotency key is charged at most once;
- the ledger and the rail never disagree silently;

and this holds under concurrency, retries, timeouts, crashes and network faults.

Each of those claims is checked by a TLA+ model, an adversarial SQL suite, property-based tests and
a fault-injection suite. One command re-runs all of it. The design, the measurements and the known
limitations are in [docs/DESIGN.md](docs/DESIGN.md).

## What is verified

| Check | Result at the time of writing |
|-------|-------------------------------|
| TLC, safe protocol | No error. 6,642 distinct states (940,994 in the wide config) |
| TLC, the two known bugs (blind void; void after a rejected `/cancel`) | Rejected: `I6`, then `I1` overspend (12 charged on a budget of 10) |
| Adversarial SQL suite as `alaka_app` | 137/137 cases; owner-guard suite 20/20; 4 holes found in the baseline schema and fixed |
| 20-session SQL concurrency probe | Exactly 5 of 20 commit under READ COMMITTED, with and without an upfront lock, and under SERIALIZABLE with retry |
| 50-thread storm, `naive` | The rail charged 34,996–39,995 on a budget of 10,000 |
| 50-thread storm, `hardened-pessimistic` / `hardened-ssi` | 10,000 / 9,999–10,000 charged; 0 invariant violations |
| Toxiproxy chaos: cut after `/confirm`, cut after `/create`, latency + resets + cuts | 0 invariant violations; the sweeper recovers every intent |

## Layout

```
spec/                 TLA+ model (AlakaInFlight.tla) and TLC configs, incl. unsafe and probe configs
migrations/           000 roles, 001 Nidhi ledger kernel, 002 deliberately unsafe naive baseline
tests/sql/            adversarial attack suite, owner-guard suite, 20-session concurrency probe
src/main/java/dev/alaka/
  core/               engine (naive, hardened-pessimistic, hardened-ssi), gateway, HTTP layer
  nidhi/              ledger SQL, transaction runner with 40001 retry, SQLSTATE translation
  mudra/              Ed25519 capability tokens, quote-to-settlement drift check
  yaksha/             rail port, Stripe v1 HTTP adapter, webhook verifier, recovery sweeper
src/test/java/dev/alaka/
  core/ yaksha/ mudra/   integration and unit tests (Testcontainers Postgres 16, mock Stripe)
  property/           jqwik stateful property suite + the shared InvariantChecker
  nidhi/              50-virtual-thread storm benchmark
  chaos/              Toxiproxy network fault suite
scripts/verify-all.sh  one command for everything
```

## Running it

Requirements: bash, Java 21+, and Docker with the compose plugin.

```bash
bash scripts/verify-all.sh          # TLC + SQL suites + concurrency probe + ./mvnw clean verify
./mvnw -B clean verify              # Java tests only
```

To run the service:

```bash
docker compose up -d --wait
docker exec -i alaka-postgres psql -U postgres -d alaka --single-transaction < migrations/000_roles.sql
for f in migrations/001_*.sql migrations/002_*.sql; do
  docker exec -i alaka-postgres psql -U alaka_migrator -d alaka --single-transaction < "$f"
done
./mvnw -B -DskipTests package
java -jar target/alaka-0.1.0-SNAPSHOT.jar \
  --alaka.db.url=jdbc:postgresql://localhost:54329/alaka --alaka.db.password=alaka_app_dev_only \
  --alaka.stripe.secret-key=sk_test_... --alaka.stripe.webhook-secret=whsec_... \
  --alaka.stripe.confirm-payment-method=pm_card_visa \
  --alaka.mudra.trusted-keys.<kid>=<base64 X.509 Ed25519 public key>
```

The service connects only as `alaka_app` and refuses to start as any other database user.
Credentials in `docker-compose.yml` and the migrations are for local development and CI only.

## HTTP API

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/mandates` | Register the mandate a signed token grants |
| `POST /v1/mandates/{id}/revoke` | Revoke it, irreversibly |
| `POST /v1/spends` | Spend: header `X-Mudra-Token`, body = spend request + approved quote |
| `POST /v1/webhooks/stripe` | Stripe deliveries, verified by `Stripe-Signature` |

Status codes and error bodies are listed in [docs/DESIGN.md §9](docs/DESIGN.md#9-http-surface).

## Known limitations

These are summarised here; [docs/DESIGN.md §10](docs/DESIGN.md#10-scope-and-limitations) has the
full list.

- **Finite model.** TLC results hold for the finite instances checked: two or three keys and a
  budget of 10.
- **Unsigned quote.** The approved quote is sent unsigned by the agent, so the drift check does not
  defend against a compromised agent fabricating its quote.
- **Mock rail.** Every automated test runs against a mock Stripe server. A test against the real
  Stripe test mode exists, but runs only with `STRIPE_TEST_KEY`.
- **Rail-only faults.** Faults are injected on the rail path only, and the latencies are from a
  laptop, not a load test.
