#!/usr/bin/env bash
# =============================================================================
# Alaka / nidhi -- tests/sql/verify_nidhi_concurrency.sh
# Multi-session concurrency probe of the Nidhi ledger, as alaka_app.
#
# Every wave: one fresh mandate with total_budget_minor = 3000, then N = 20
# concurrent sessions each reserving 600 in ONE Phase 1 transaction (intent +
# RESERVE ledger tx + DEBIT AVAILABLE / CREDIT HELD). At most 5 can fit.
# Sessions are released together by an advisory-lock barrier and meet again at
# a second barrier INSIDE their transactions, so all 20 transactions are open
# at the same instant; pg_sleep at a chosen step widens the race window.
#
#   rc_lock             READ COMMITTED, canonical upfront
#                       SELECT ... FROM mandate_balances FOR UPDATE
#   rc_nolock_postings  READ COMMITTED, NO upfront lock, sleep between postings
#   rc_nolock_commit    READ COMMITTED, NO upfront lock, sleep before COMMIT
#   ssi_noretry         SERIALIZABLE, no lock, no retry: counts 40001
#   ssi_retry           SERIALIZABLE, no lock, retry 40001 with exponential
#                       backoff + full jitter: must converge to exhaustion
#
# Asserted per wave: the exact set of final per-session outcomes (COMMITTED or
# an exact SQLSTATE; nothing else may appear), the count of each, and the end
# state of the mandate: available/held/settled, balance == SUM(postings), the
# number of intents and RESERVE transactions, and no unbalanced transaction.
#
# Environment: ALAKA_PG_CONTAINER (default alaka-postgres), ALAKA_PG_DATABASE
# (default alaka), ALAKA_CONC_REPEAT (default 1: waves per scenario).
# Assumes all migrations are applied. Re-runnable: every wave uses fresh ids.
# Exit status 0 only if every assertion held.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

C="${ALAKA_PG_CONTAINER:-alaka-postgres}"
DB="${ALAKA_PG_DATABASE:-alaka}"
REPEAT="${ALAKA_CONC_REPEAT:-1}"
N=20
BUDGET=3000
AMOUNT=600
REMOTE="/tmp/alaka-conc-$$-$RANDOM"
PASSES=0
FAILURES=0

dk() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker "$@"; }
app() { dk exec -i "$C" psql -X -q -At -v ON_ERROR_STOP=1 -U alaka_app -d "$DB" "$@"; }

pass() { printf 'PASS  %s\n' "$*"; PASSES=$((PASSES + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

check() { # check LABEL EXPECTED ACTUAL
    if [ "$2" = "$3" ]; then pass "$1 [$3]"; else fail "$1: expected [$2], got [$3]"; fi
}

cleanup() { dk exec "$C" rm -rf "$REMOTE" > /dev/null 2>&1 || true; }
trap cleanup EXIT

# Ship the helpers into the container, normalising line endings on the way
# (a Windows checkout may have converted them to CRLF).
dk exec "$C" mkdir -p "$REMOTE"
for f in tests/sql/concurrency/*.sql tests/sql/concurrency/*.sh; do
    tr -d '\r' < "$f" | dk exec -i "$C" sh -c "cat > '$REMOTE/$(basename "$f")'"
done

# fact KEY ANALYSIS  -> value of "KEY=..." from analyze.awk output
fact() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

# run_wave NAME ISO LOCKMODE GATE2_AT SLEEP_AT SLEEP_S RETRY ALLOWED
run_wave() {
    local name="$1" iso="$2" lockmode="$3" gate2_at="$4" sleep_at="$5" sleep_s="$6" retry="$7" allowed="$8"
    local tag agent mandate accounts av he out analysis coord rc state
    tag="$(date +%s)$RANDOM"
    agent="conc-$name-$tag"
    mandate="$(app -c "INSERT INTO spend_mandates (agent_id, currency, total_budget_minor, max_per_tx_minor,
                           allowed_merchants, not_before, expires_at, token_kid)
                       VALUES ('$agent', 'USD', $BUDGET, $AMOUNT, ARRAY['merchant-a'], NOW() - INTERVAL '5 seconds', NOW() + INTERVAL '1 hour', 'kid-conc')
                       RETURNING mandate_id" | tr -d '\r' | head -n 1)"
    accounts="$(app -c "SELECT string_agg(account_id::text, ' ' ORDER BY bucket) FROM ledger_accounts
                        WHERE mandate_id = '$mandate' AND bucket IN ('MANDATE_AVAILABLE', 'MANDATE_HELD')" | tr -d '\r')"
    av="${accounts%% *}"
    he="${accounts##* }"

    out="$(dk exec \
        -e DB="$DB" -e N="$N" -e PREFIX="nc-$tag" -e K="$(( (RANDOM << 15 | RANDOM) % 2000000000 + 1 ))" \
        -e USE_G2="$( [ "$gate2_at" = none ] && echo false || echo true )" \
        -e M="$mandate" -e AGENT="$agent" -e AV="$av" -e HE="$he" \
        -e RH="$(printf '%064d' 0 | tr 0 a)" -e TAG="$tag" -e AMOUNT="$AMOUNT" -e ISO="$iso" \
        -e LOCKMODE="$lockmode" -e GATE2_AT="$gate2_at" -e SLEEP_AT="$sleep_at" -e SLEEP_S="$sleep_s" \
        -e RETRY="$retry" -e MAX_ATTEMPTS=60 -e BACKOFF_BASE_MS=2 -e BACKOFF_CAP_MS=100 \
        "$C" sh "$REMOTE/wave.sh" | tr -d '\r')" || true

    analysis="$(printf '%s\n' "$out" | grep '^ATT|' | awk -v allowed="$allowed" -f tests/sql/concurrency/analyze.awk)"
    coord="$(printf '%s\n' "$out" | grep '^COORD|' || true)"
    rc="$(printf '%s\n' "$out" | sed -n 's/^WAVE_EXIT|//p')"
    state="$(app -c "SELECT b.available_minor || '/' || b.held_minor || '/' || b.settled_minor,
                            (SELECT count(*) FROM payment_intents WHERE mandate_id = b.mandate_id),
                            (SELECT count(*) FROM ledger_transactions WHERE mandate_id = b.mandate_id AND transition_type = 'RESERVE'),
                            (SELECT COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_HELD' THEN CASE p.direction WHEN 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END ELSE 0 END), 0)
                               FROM ledger_postings p JOIN ledger_accounts a USING (account_id) WHERE p.mandate_id = b.mandate_id) = b.held_minor
                        AND (SELECT COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_AVAILABLE' THEN CASE p.direction WHEN 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END ELSE 0 END), 0)
                               FROM ledger_postings p JOIN ledger_accounts a USING (account_id) WHERE p.mandate_id = b.mandate_id) + b.total_budget_minor = b.available_minor,
                            (SELECT count(*) FROM (SELECT tx_id FROM ledger_postings WHERE mandate_id = b.mandate_id GROUP BY tx_id
                                                    HAVING SUM(CASE direction WHEN 'DEBIT' THEN amount_minor ELSE -amount_minor END) <> 0) u)
                       FROM mandate_balances b WHERE b.mandate_id = '$mandate'" -F ' ' | tr -d '\r')"

    printf '\n--- %s (%s, lock=%s, barrier=%s, sleep %ss at %s, retry=%s)\n' \
        "$name" "$iso" "$lockmode" "$gate2_at" "$sleep_s" "$sleep_at" "$retry"
    printf '%s\n' "$analysis" | sed 's/^/      /'
    printf '      %s\n' "${coord:-COORD line missing}"
    printf '      end state: avail/held/settled intents reserve_txs balance==sum(postings) unbalanced_txs = %s\n' "$state"

    LAST_COMMITTED="$(fact outcomes "$analysis" | tr ' ' '\n' | sed -n 's/^COMMITTED=//p')"
    LAST_SER="$(fact ser_total "$analysis")"
    check "$name: coordinator finished cleanly" "0" "${rc:-missing}"
    check "$name: all $N sessions reported" "$N" "$(fact sessions "$analysis")"
    check "$name: no session ended in an unexpected SQLSTATE (allowed: $allowed)" "0" "$(fact unexpected "$analysis")"
    if [ "$gate2_at" != none ]; then
        check "$name: all $N transactions were open at the in-transaction barrier" \
            "$N" "$(printf '%s\n' "$coord" | sed -n 's/.*|gate2_waiters=\([0-9-]*\)|.*/\1/p')"
    fi
    WAVE_STATE="$state"
}

expect_exhaustion() { # NAME : exactly 5 committed, 15 SG003, ledger exhausted and consistent
    local name="$1"
    check "$name: exactly 5 of $N reservations committed" "5" "${LAST_COMMITTED:-0}"
    check "$name: end state" "0/3000/0 5 5 t 0" "$WAVE_STATE"
}

i=1
while [ "$i" -le "$REPEAT" ]; do
    run_wave rc_lock "READ COMMITTED" update begin before_commit 0.02 0 "COMMITTED SG003"
    expect_exhaustion rc_lock
    run_wave rc_nolock_postings "READ COMMITTED" none pre_posting between_postings 0.02 0 "COMMITTED SG003"
    expect_exhaustion rc_nolock_postings
    run_wave rc_nolock_commit "READ COMMITTED" none pre_posting before_commit 0.02 0 "COMMITTED SG003"
    expect_exhaustion rc_nolock_commit

    run_wave ssi_noretry SERIALIZABLE none begin none 0 0 "COMMITTED 40001 SG003"
    if [ "${LAST_COMMITTED:-0}" -ge 1 ] && [ "${LAST_COMMITTED:-0}" -le 5 ]; then
        pass "ssi_noretry: between 1 and 5 committed, the rest rejected [committed=$LAST_COMMITTED, 40001=$LAST_SER]"
    else
        fail "ssi_noretry: expected 1..5 committed, got ${LAST_COMMITTED:-0} (40001=$LAST_SER)"
    fi
    if [ "${LAST_SER:-0}" -ge 1 ]; then
        pass "ssi_noretry: SERIALIZABLE reported serialization failures [40001=$LAST_SER]"
    else
        fail "ssi_noretry: expected at least one 40001 with 20 overlapping writers, got ${LAST_SER:-0}"
    fi
    check "ssi_noretry: ledger consistent (balance == sum(postings), no unbalanced tx)" "t 0" \
        "$(printf '%s\n' "$WAVE_STATE" | awk '{ print $4, $5 }')"

    run_wave ssi_retry SERIALIZABLE none begin none 0 1 "COMMITTED SG003"
    expect_exhaustion ssi_retry
    i=$((i + 1))
done

printf '\nNIDHI CONCURRENCY PROBE: %d checks passed, %d failed (db=%s, waves per scenario=%s)\n' \
    "$PASSES" "$FAILURES" "$DB" "$REPEAT"
[ "$FAILURES" -eq 0 ]
