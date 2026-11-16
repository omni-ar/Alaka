#!/bin/sh
# =============================================================================
# Alaka / nidhi -- tests/sql/concurrency/wave.sh
# Runs ONE wave of N concurrent reservation sessions. Executes INSIDE the
# Postgres container (busybox sh), copied there by verify_nidhi_concurrency.sh,
# so all N psql processes start from one shell with no docker-exec skew; the
# advisory-lock barrier in coordinator.sql then releases them together.
#
# Input: environment variables (see verify_nidhi_concurrency.sh, run_wave).
# Output on stdout: every worker's ATT lines, then the COORD line, then
#   WAVE_EXIT|<coordinator exit status>
# =============================================================================
set -eu
cd "$(dirname "$0")"
out="$(mktemp -d)"
common="-X -q -U alaka_app -d $DB"

PGAPPNAME="${PREFIX}-coord" psql $common \
    -v k="$K" -v g1=1 -v g2=2 -v use_g2="$USE_G2" -v n="$N" -v prefix="${PREFIX}-w" \
    -f coordinator.sql > "$out/coord" 2>&1 &
coord=$!

tries=0
while ! grep -q COORD_READY "$out/coord" 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 600 ] || ! kill -0 "$coord" 2>/dev/null; then
        echo "WAVE_ERROR|coordinator did not become ready"
        cat "$out/coord"
        exit 3
    fi
    sleep 0.05
done

s=1
while [ "$s" -le "$N" ]; do
    sid="$(printf '%02d' "$s")"
    PGAPPNAME="${PREFIX}-w${sid}" psql $common \
        -v sid="$sid" -v m="$M" -v agent="$AGENT" -v av="$AV" -v he="$HE" -v rh="$RH" -v tag="$TAG" \
        -v amount="$AMOUNT" -v iso="$ISO" -v lockmode="$LOCKMODE" -v gate2_at="$GATE2_AT" \
        -v sleep_at="$SLEEP_AT" -v sleep_s="$SLEEP_S" -v k="$K" -v g1=1 -v g2=2 \
        -v retry="$RETRY" -v max_attempts="$MAX_ATTEMPTS" \
        -v backoff_base_ms="$BACKOFF_BASE_MS" -v backoff_cap_ms="$BACKOFF_CAP_MS" \
        -f worker.sql > "$out/w${sid}" 2>&1 &
    s=$((s + 1))
done

rc=0
wait "$coord" || rc=$?
wait || true

cat "$out"/w*
grep '^COORD|' "$out/coord" || { echo "WAVE_ERROR|coordinator output:"; cat "$out/coord"; }
echo "WAVE_EXIT|$rc"
rm -rf "$out"
