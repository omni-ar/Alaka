#!/usr/bin/env bash
# =============================================================================
# Alaka -- scripts/verify-all.sh
# One command that re-proves everything:
#
#   tla          TLC on spec/AlakaInFlight.tla: the safe config must pass AND
#                every unsafe config must be rejected with its named invariant.
#   sql          all migrations applied to a fresh scratch database, then the
#                nidhi attack suite (as alaka_app) and the owner-guard suite
#                (as alaka_migrator).
#   concurrency  tests/sql/verify_nidhi_concurrency.sh against its own fresh
#                scratch database.
#   java         ./mvnw -B clean verify (Testcontainers; needs Docker).
#
# Runs in Git Bash on Windows and on Linux. Needs only: bash, java, docker
# (with the compose plugin) and coreutils/grep/sed/awk. No psql, mvn, make or
# timeout on the host.
#
# The developer database "alaka" and the compose volume are never dropped,
# recreated or written to: the SQL steps create, use and drop databases whose
# names start with "alaka_verify_". (000_roles.sql is cluster-wide by nature:
# it re-pins the attributes of the roles alaka_migrator / alaka_app, to the
# same values, every time it is applied.)
#
# Full tool output goes to target-verify/<step>/ (gitignored via "target-*/").
# It is deliberately NOT under target/: the java step runs "mvn clean", which
# would delete the logs of the steps that ran before it.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Everything below uses paths relative to the repo root on purpose: relative
# paths mean the same thing to Git Bash, to native Windows programs (java,
# docker) and on Linux, so nothing depends on MSYS path translation.
LOG_REL="target-verify"
ALL_STEPS="tla sql concurrency java"
DEFAULT_PG_CONTAINER="alaka-postgres"
PG_CONTAINER="${ALAKA_PG_CONTAINER:-$DEFAULT_PG_CONTAINER}"
SCRATCH_PREFIX="alaka_verify"
CONCURRENCY_SCRIPT="tests/sql/verify_nidhi_concurrency.sh"
TLA_SPEC="AlakaInFlight.tla"
WIDE="${ALAKA_VERIFY_WIDE:-0}"
KEEP_DB="${ALAKA_VERIFY_KEEP_DB:-0}"

usage() {
    cat <<'EOF'
Usage: scripts/verify-all.sh [--wide] [STEP ...]

Steps (run in this order; no STEP means all of them):
  tla          TLC: safe config passes, every unsafe config is rejected
  sql          migrations + attack suite + owner-guard suite on a scratch DB
  concurrency  tests/sql/verify_nidhi_concurrency.sh on a scratch DB
  java         ./mvnw -B clean verify

A failed step does not stop the run; the summary lists every step and the
exit status is 0 only if all selected steps passed (1 otherwise, 2 on usage).

Options:
  --wide       also model-check spec/AlakaInFlightWide.cfg (slower)
  -h, --help   this text

Environment:
  ALAKA_VERIFY_WIDE=1     same as --wide
  ALAKA_VERIFY_KEEP_DB=1  keep the scratch databases even when a step passes
                          (they are always kept when the step fails)
  ALAKA_PG_CONTAINER      Postgres container name (default: alaka-postgres)

Logs: target-verify/<step>/   Summary: target-verify/summary.txt
EOF
}

# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
FAILS=0
STEP_DIR=""

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

# One-line evidence for the summary table (last call wins).
evidence() { printf '%s\n' "$*" > "$STEP_DIR/evidence"; }

# run_logged LOG CMD [ARG ...]
# Runs CMD with stdout+stderr captured in LOG (CRs stripped, so Windows tool
# output greps the same as on Linux) and returns CMD's exit status. stdin is
# passed through. Always call it as:  rc=0; run_logged ... || rc=$?
run_logged() {
    local log="$1" rc=0
    shift
    "$@" > "$log.raw" 2>&1 || rc=$?
    tr -d '\r' < "$log.raw" > "$log"
    rm -f "$log.raw"
    return "$rc"
}

# Indented excerpt of a log: show_lines FILE MAX [GREP_ERE]
show_lines() {
    local file="$1" max="$2" pattern="${3:-}"
    # awk (not head) so the producer is always read to the end: no SIGPIPE
    # that pipefail would turn into a spurious failure.
    if [ -n "$pattern" ]; then
        { grep -E "$pattern" "$file" || true; } | awk -v max="$max" 'NR <= max { print "        | " $0 }'
    else
        tail -n "$max" "$file" | awk '{ print "        | " $0 }'
    fi
}

# docker, with MSYS (Git Bash) argument/path mangling switched off so that
# container-side paths and '/'-leading arguments arrive untouched.
dk() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker "$@"; }

# pg ROLE DB [PSQL_ARG ...]   SQL comes from stdin (or -c). Local-socket auth
# inside the container is trust, so no password is involved.
pg() {
    local role="$1" db="$2"
    shift 2
    dk exec -i "$PG_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$role" -d "$db" "$@"
}

# ----------------------------------------------------------------------------
# Postgres plumbing shared by the sql and concurrency steps
# ----------------------------------------------------------------------------
pg_container_running() {
    local state
    state="$(dk inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null | tr -d '\r' || true)"
    [ "$state" = "true" ]
}

ensure_stack() {
    local log="$STEP_DIR/00-compose-up.log" rc=0 tries=0
    if ! command -v docker >/dev/null 2>&1; then
        bad "docker not found on PATH"
        return 1
    fi
    if pg_container_running; then
        info "container $PG_CONTAINER is running"
    elif [ "$PG_CONTAINER" != "$DEFAULT_PG_CONTAINER" ]; then
        bad "container $PG_CONTAINER (from ALAKA_PG_CONTAINER) is not running; docker-compose.yml only defines $DEFAULT_PG_CONTAINER"
        return 1
    else
        info "container $PG_CONTAINER is not running: docker compose up -d --wait"
        run_logged "$log" dk compose up -d --wait < /dev/null || rc=$?
        if [ "$rc" -ne 0 ]; then
            bad "docker compose up -d --wait failed, exit $rc (log: $log)"
            show_lines "$log" 10
            return 1
        fi
    fi
    while ! dk exec "$PG_CONTAINER" pg_isready -q -h 127.0.0.1 -U postgres > /dev/null 2>&1 < /dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            bad "Postgres in $PG_CONTAINER did not accept connections within 60s"
            return 1
        fi
        sleep 1
    done
    return 0
}

# prepare_scratch_db DB : drop-if-exists + create DB, then apply every
# migrations/NNN_*.sql in name order (000_* as the superuser, the rest as
# alaka_migrator, each in a single transaction). Sets MIGRATION_COUNT.
MIGRATION_COUNT=0
prepare_scratch_db() {
    local db="$1" rc=0 log list name role
    case "$db" in
        "${SCRATCH_PREFIX}"_*) ;;
        *)
            bad "refusing to (re)create database '$db': scratch names must start with ${SCRATCH_PREFIX}_"
            return 1
            ;;
    esac

    log="$STEP_DIR/01-create-db.log"
    run_logged "$log" pg postgres postgres \
        -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" \
        -c "CREATE DATABASE $db" < /dev/null || rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "could not create scratch database $db, exit $rc (log: $log)"
        show_lines "$log" 10
        return 1
    fi
    ok "fresh scratch database $db created in $PG_CONTAINER"

    list="$(ls migrations 2>/dev/null | { grep -E '^[0-9]+_[A-Za-z0-9_.-]+\.sql$' || true; } | LC_ALL=C sort)"
    if [ -z "$list" ]; then
        bad "no migrations/NNN_*.sql files found"
        return 1
    fi
    MIGRATION_COUNT=0
    for name in $list; do
        case "$name" in
            000_*) role="postgres" ;;
            *)     role="alaka_migrator" ;;
        esac
        log="$STEP_DIR/02-migrate-${name%.sql}.log"
        rc=0
        run_logged "$log" pg "$role" "$db" --single-transaction < "migrations/$name" || rc=$?
        if [ "$rc" -ne 0 ]; then
            bad "migration $name (as $role) failed on $db, exit $rc (log: $log)"
            show_lines "$log" 10 '^(ERROR|FATAL|psql:)'
            return 1
        fi
        MIGRATION_COUNT=$((MIGRATION_COUNT + 1))
        ok "migration $name applied as $role"
    done
    return 0
}

# Drop the scratch database after a clean step; keep it for post-mortem when
# the step failed (or when asked to).
finish_scratch_db() {
    local db="$1"
    if [ "$FAILS" -ne 0 ]; then
        info "scratch database $db kept for inspection:"
        info "  docker exec -it $PG_CONTAINER psql -U postgres -d $db"
    elif [ "$KEEP_DB" = "1" ]; then
        info "scratch database $db kept (ALAKA_VERIFY_KEEP_DB=1)"
    elif run_logged "$STEP_DIR/99-drop-db.log" pg postgres postgres \
            -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" < /dev/null; then
        info "scratch database $db dropped"
    else
        info "warning: could not drop scratch database $db (log: $STEP_DIR/99-drop-db.log)"
    fi
}

# ----------------------------------------------------------------------------
# Step: tla
# ----------------------------------------------------------------------------
TLC_RC=0
TLC_LOG=""
TLC_STATES=""
TLC_VIOLATED=""

# Runs from inside spec/ with bare file names: the one invocation form that
# makes TLC find the module on Windows and on Linux alike.
tlc_exec() {
    (
        cd spec
        exec java -XX:+UseParallelGC -cp ../tools/tla2tools.jar tlc2.TLC \
            -workers auto -metadir "$2" -config "$1" "$TLA_SPEC"
    )
}

# tlc_run CFG : sets TLC_RC, TLC_LOG, TLC_STATES ("N states generated, M
# distinct states found, K states left on queue.") and TLC_VIOLATED (names of
# violated invariants, space separated).
tlc_run() {
    local cfg="$1" name="${1%.cfg}"
    local meta="$LOG_REL/tla/meta-$name"
    TLC_LOG="$LOG_REL/tla/$name.log"
    TLC_RC=0
    if [ ! -f "spec/$cfg" ]; then
        printf 'missing config spec/%s\n' "$cfg" > "$TLC_LOG"
        TLC_RC=127
    else
        run_logged "$TLC_LOG" tlc_exec "$cfg" "../$meta" < /dev/null || TLC_RC=$?
    fi
    rm -rf "$meta"
    TLC_STATES="$(grep -E '^[0-9]+ states generated, [0-9]+ distinct states found, [0-9]+ states left on queue\.$' "$TLC_LOG" | tail -n 1 || true)"
    TLC_VIOLATED="$(sed -n 's/^Error: Invariant \([A-Za-z0-9_]*\) is violated\.$/\1/p' "$TLC_LOG" | tr '\n' ' ' | sed 's/ *$//')"
}

tlc_distinct() { printf '%s\n' "$TLC_STATES" | sed -n 's/^[0-9]* states generated, \([0-9]*\) distinct states found.*/\1/p'; }

# The config must model-check cleanly and exhaustively.
tlc_expect_pass() {
    local cfg="$1" why=""
    tlc_run "$cfg"
    if [ "$TLC_RC" -ne 0 ]; then
        why="exit $TLC_RC (expected 0)"
    elif ! grep -q '^Model checking completed\. No error has been found\.$' "$TLC_LOG"; then
        why="exit 0 but no 'No error has been found' line"
    elif grep -q '^Error:' "$TLC_LOG"; then
        why="exit 0 but the log contains an Error: line"
    elif [ -z "$TLC_STATES" ]; then
        why="no state-count line in the log"
    elif ! printf '%s\n' "$TLC_STATES" | grep -q ', 0 states left on queue\.$'; then
        why="state queue not exhausted"
    fi
    if [ -n "$why" ]; then
        bad "$cfg: must pass, but $why${TLC_VIOLATED:+; violated: $TLC_VIOLATED} (log: $TLC_LOG)"
        show_lines "$TLC_LOG" 6 '^Error:'
        return 1
    fi
    ok "$cfg: no error found; $TLC_STATES"
    return 0
}

# The config enables a protocol bug: TLC must reject it, with exactly this
# invariant. A clean pass here means the checker has lost its teeth.
tlc_expect_violation() {
    local cfg="$1" want="$2"
    tlc_run "$cfg"
    if [ "$TLC_RC" -eq 12 ] && [ "$TLC_VIOLATED" = "$want" ]; then
        ok "$cfg: rejected as required (exit 12, invariant $want violated)"
        return 0
    fi
    if [ "$TLC_RC" -eq 0 ]; then
        bad "$cfg: an UNSAFE config PASSED model checking; expected exit 12 violating $want (log: $TLC_LOG)"
    else
        bad "$cfg: expected exit 12 violating $want, got exit $TLC_RC violating '${TLC_VIOLATED:-nothing}' (log: $TLC_LOG)"
        show_lines "$TLC_LOG" 6 '^Error:'
    fi
    return 1
}

tla_litter() {
    ls -a spec 2>/dev/null | { grep -E '_TTrace_|^states$|\.tla\.out$' || true; } | LC_ALL=C sort | tr '\n' ' '
}

step_tla() {
    local safe_distinct="" wide_distinct="" rejected=0 unsafe_total=0 litter_before litter_after line cfg want

    if ! command -v java >/dev/null 2>&1; then
        bad "java not found on PATH"
        evidence "java not found on PATH"
        return 1
    fi
    if [ ! -f tools/tla2tools.jar ]; then
        bad "tools/tla2tools.jar is missing"
        evidence "tools/tla2tools.jar is missing"
        return 1
    fi
    litter_before="$(tla_litter)"

    if tlc_expect_pass AlakaInFlight.cfg; then
        safe_distinct="$(tlc_distinct)"
    fi

    # config | invariant TLC must report as violated
    while IFS='|' read -r cfg want; do
        [ -n "$cfg" ] || continue
        unsafe_total=$((unsafe_total + 1))
        if tlc_expect_violation "$cfg" "$want"; then
            rejected=$((rejected + 1))
        fi
    done <<'EOF'
AlakaInFlightUnsafeBlindVoid.cfg|I6_NoSilentRailDrift
AlakaInFlightUnsafeCancelFailure.cfg|I6_NoSilentRailDrift
AlakaInFlightUnsafeBlindVoidNoI6.cfg|I1_NoMandateOverspent
AlakaInFlightUnsafeCancelFailureNoI6.cfg|I1_NoMandateOverspent
EOF

    if [ "$WIDE" = "1" ]; then
        if tlc_expect_pass AlakaInFlightWide.cfg; then
            wide_distinct="$(tlc_distinct)"
        fi
    else
        info "AlakaInFlightWide.cfg skipped (opt in with --wide or ALAKA_VERIFY_WIDE=1)"
    fi

    litter_after="$(tla_litter)"
    if [ "$litter_before" != "$litter_after" ]; then
        bad "TLC left files behind in spec/: now [ $litter_after] was [ $litter_before]"
    fi

    line="safe: ${safe_distinct:-?} distinct states, "
    if [ -n "$safe_distinct" ]; then line="${line}no error"; else line="${line}NOT PROVEN"; fi
    line="$line; unsafe configs rejected: $rejected/$unsafe_total"
    if [ "$WIDE" = "1" ]; then
        if [ -n "$wide_distinct" ]; then
            line="$line; wide: $wide_distinct distinct states, no error"
        else
            line="$line; wide: NOT PROVEN"
        fi
    fi
    evidence "$line"
    [ "$FAILS" -eq 0 ]
}

# ----------------------------------------------------------------------------
# Step: sql
# ----------------------------------------------------------------------------
SUITE_RESULT=""

# run_suite LABEL ROLE DB FILE : a suite passes only if psql exits 0 AND its
# summary line reports N/N cases passed with 0 failed (N > 0).
run_suite() {
    local label="$1" role="$2" db="$3" file="$4"
    local log="$STEP_DIR/10-$label.log" rc=0 line passed total failed
    SUITE_RESULT="$label: NOT RUN"
    if [ ! -f "$file" ]; then
        bad "$label: missing $file"
        SUITE_RESULT="$label: missing"
        return 1
    fi
    run_logged "$log" pg "$role" "$db" < "$file" || rc=$?
    line="$(grep -E 'SUITE: [0-9]+/[0-9]+ cases PASSED, [0-9]+ failed' "$log" | tail -n 1 || true)"
    passed="$(printf '%s\n' "$line" | sed -n 's/.*SUITE: \([0-9]*\)\/[0-9]* cases PASSED, [0-9]* failed.*/\1/p')"
    total="$(printf '%s\n' "$line" | sed -n 's/.*SUITE: [0-9]*\/\([0-9]*\) cases PASSED, [0-9]* failed.*/\1/p')"
    failed="$(printf '%s\n' "$line" | sed -n 's/.*SUITE: [0-9]*\/[0-9]* cases PASSED, \([0-9]*\) failed.*/\1/p')"
    if [ "$rc" -eq 0 ] && [ -n "$line" ] && [ "$total" -gt 0 ] && [ "$passed" -eq "$total" ] && [ "$failed" -eq 0 ]; then
        ok "$line"
        SUITE_RESULT="$label $passed/$total"
        return 0
    fi
    bad "$label (as $role on $db): psql exit $rc, summary line: ${line:-<none>} (log: $log)"
    show_lines "$log" 5 'ASSERTION FAILED'
    show_lines "$log" 4
    SUITE_RESULT="$label FAILED (exit $rc)"
    return 1
}

step_sql() {
    local db="${SCRATCH_PREFIX}_sql" summary=""

    if ! ensure_stack; then
        evidence "Postgres container not available"
        return 1
    fi
    if ! prepare_scratch_db "$db"; then
        evidence "scratch database / migrations failed on $db"
        finish_scratch_db "$db"
        return 1
    fi

    run_suite "attacks" alaka_app "$db" tests/sql/verify_nidhi_attacks.sql || true
    summary="$SUITE_RESULT"
    run_suite "owner-guards" alaka_migrator "$db" tests/sql/verify_nidhi_owner_guards.sql || true
    summary="$summary, $SUITE_RESULT"

    evidence "$summary ($MIGRATION_COUNT migrations, db $db)"
    finish_scratch_db "$db"
    [ "$FAILS" -eq 0 ]
}

# ----------------------------------------------------------------------------
# Step: concurrency
# ----------------------------------------------------------------------------
step_concurrency() {
    local db="${SCRATCH_PREFIX}_concurrency" log="$STEP_DIR/10-concurrency.log" rc=0 last

    if [ ! -f "$CONCURRENCY_SCRIPT" ]; then
        bad "missing: $CONCURRENCY_SCRIPT (the concurrency probe does not exist in this tree)"
        evidence "missing $CONCURRENCY_SCRIPT"
        return 1
    fi
    if ! ensure_stack; then
        evidence "Postgres container not available"
        return 1
    fi
    if ! prepare_scratch_db "$db"; then
        evidence "scratch database / migrations failed on $db"
        finish_scratch_db "$db"
        return 1
    fi

    run_logged "$log" env ALAKA_PG_CONTAINER="$PG_CONTAINER" ALAKA_PG_DATABASE="$db" \
        bash "$CONCURRENCY_SCRIPT" < /dev/null || rc=$?
    last="$({ grep -v '^[[:space:]]*$' "$log" || true; } | tail -n 1 | cut -c 1-110)"
    if [ "$rc" -eq 0 ]; then
        ok "$CONCURRENCY_SCRIPT: exit 0; ${last:-<no output>}"
        evidence "${last:-exit 0, no output} (db $db)"
    else
        bad "$CONCURRENCY_SCRIPT: exit $rc (log: $log)"
        show_lines "$log" 12
        evidence "exit $rc: ${last:-<no output>}"
    fi
    finish_scratch_db "$db"
    [ "$FAILS" -eq 0 ]
}

# ----------------------------------------------------------------------------
# Step: java
# ----------------------------------------------------------------------------
step_java() {
    local log="$STEP_DIR/mvnw.log" rc=0 totals build sums run failed

    if [ ! -f mvnw ]; then
        bad "mvnw (Maven Wrapper) is missing"
        evidence "mvnw is missing"
        return 1
    fi
    info "running ./mvnw -B clean verify (takes a while; follow it with: tail -f $log.raw)"
    run_logged "$log" sh ./mvnw -B clean verify < /dev/null || rc=$?

    # Reactor-level result lines only (the per-class lines carry a "Time elapsed" tail).
    totals="$(grep -E 'Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+$' "$log" || true)"
    build="$({ grep -E 'BUILD (SUCCESS|FAILURE)' "$log" || true; } | tail -n 1 | sed 's/^\[[A-Z]*\] *//')"
    sums="$(printf '%s\n' "$totals" | awk '
        { for (i = 1; i < NF; i++) {
              if ($i == "run:")      r += $(i + 1)
              if ($i == "Failures:") f += $(i + 1)
              if ($i == "Errors:")   e += $(i + 1)
              if ($i == "Skipped:")  s += $(i + 1)
          } }
        END { printf "%d %d %d %d", r, f, e, s }')"
    run="${sums%% *}"
    failed="$(printf '%s\n' "$sums" | awk '{ print $2 + $3 }')"

    if [ -n "$totals" ]; then
        printf '%s\n' "$totals" | sed 's/^/        | /'
    fi
    [ -z "$build" ] || info "$build"

    if [ "$rc" -ne 0 ]; then
        bad "./mvnw -B clean verify failed, exit $rc (log: $log)"
        show_lines "$log" 25 '^\[ERROR\]'
    elif [ "$build" != "BUILD SUCCESS" ]; then
        bad "mvnw exited 0 but the log has no BUILD SUCCESS line (log: $log)"
    elif [ "$failed" -ne 0 ]; then
        bad "mvnw exited 0 but the test totals report failures/errors (log: $log)"
    elif [ "$run" -eq 0 ]; then
        bad "the build succeeded but executed 0 tests: that proves nothing (log: $log)"
    else
        ok "./mvnw -B clean verify: exit 0 (log: $log)"
    fi
    evidence "$(printf '%s\n' "$sums" | awk '{ printf "Tests run: %d, Failures: %d, Errors: %d, Skipped: %d", $1, $2, $3, $4 }'); ${build:-no BUILD line} (exit $rc)"
    [ "$FAILS" -eq 0 ]
}

# ----------------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------------
SELECTED=""
for arg; do
    case "$arg" in
        -h|--help|help) usage; exit 0 ;;
        --wide)         WIDE=1 ;;
        all)            SELECTED="$ALL_STEPS" ;;
        tla|sql|concurrency|java) SELECTED="$SELECTED $arg" ;;
        *)
            printf 'verify-all: unknown argument: %s\n\n' "$arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done
[ -n "$SELECTED" ] || SELECTED="$ALL_STEPS"

mkdir -p "$LOG_REL"

R_STEP=()
R_STATUS=()
R_TIME=()
R_EVIDENCE=()
FAILED_STEPS=""
N=0

for step in $ALL_STEPS; do
    case " $SELECTED " in
        *" $step "*) ;;
        *) continue ;;
    esac

    STEP_DIR="$LOG_REL/$step"
    rm -rf "$STEP_DIR"
    mkdir -p "$STEP_DIR"
    say ""
    say "=== [$step] ================================================================"
    started=$SECONDS

    # Each step runs in a subshell with errexit ON and outside any '||' / 'if'
    # context, so a bug in the runner itself (unset variable, unexpected
    # command failure) aborts the step and is reported as FAIL, never as PASS.
    set +e
    ( set -e; FAILS=0; "step_$step" )
    rc=$?
    set -e

    elapsed=$((SECONDS - started))
    if [ -s "$STEP_DIR/evidence" ]; then
        ev="$(head -n 1 "$STEP_DIR/evidence")"
    else
        ev="step aborted without evidence (exit $rc); see $STEP_DIR/"
    fi
    if [ "$rc" -eq 0 ]; then
        status="PASS"
    else
        status="FAIL"
        FAILED_STEPS="$FAILED_STEPS $step"
    fi
    say "--- [$step] $status in ${elapsed}s (logs: $STEP_DIR/)"

    R_STEP[N]="$step"
    R_STATUS[N]="$status"
    R_TIME[N]="${elapsed}s"
    R_EVIDENCE[N]="$ev"
    N=$((N + 1))
done

{
    say ""
    say "==================== ALAKA VERIFY-ALL SUMMARY ===================="
    printf '%-12s %-6s %6s  %s\n' "STEP" "RESULT" "TIME" "EVIDENCE"
    i=0
    while [ "$i" -lt "$N" ]; do
        printf '%-12s %-6s %6s  %s\n' "${R_STEP[i]}" "${R_STATUS[i]}" "${R_TIME[i]}" "${R_EVIDENCE[i]}"
        i=$((i + 1))
    done
    say "Logs: $ROOT/$LOG_REL/"
    if [ -z "$FAILED_STEPS" ]; then
        say "RESULT: PASS ($N of $N steps passed)"
    else
        say "RESULT: FAIL (failed:$FAILED_STEPS)"
    fi
} | tee "$LOG_REL/summary.txt"

[ -z "$FAILED_STEPS" ]
