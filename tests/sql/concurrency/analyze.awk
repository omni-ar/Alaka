# =============================================================================
# Alaka / nidhi -- tests/sql/concurrency/analyze.awk
# Reduces the ATT lines of one wave to key=value facts for driver.sh.
# POSIX awk only (busybox awk in postgres:16-alpine, mawk/gawk elsewhere).
#
# Input line:  ATT|sid|attempt|sqlstate|failed_at|t0|t1|w_lock|w_p1|w_commit|w_fail
# Variable:    allowed = space-separated list of acceptable FINAL outcomes
#              (COMMITTED or an exact SQLSTATE)
# =============================================================================
BEGIN { FS = "|" }

$1 == "ATT" && NF >= 11 {
    sid = $2; n = $3 + 0; st = $4; at = $5
    if (!(sid in last_n)) { sids[++nsid] = sid; last_n[sid] = 0 }
    if (n > last_n[sid]) { last_n[sid] = n; last_st[sid] = st; last_at[sid] = at }
    att_total++
    if (st == "40001") { ser_total++; ser_at[at]++ }
    if (st == "40P01") { dl_total++ }
    ev_t[++nev] = $6 + 0; ev_d[nev] = 1
    ev_t[++nev] = $7 + 0; ev_d[nev] = -1
    if ($8 + 0 >= 0)  wl[++nwl] = $8 + 0
    if ($9 + 0 >= 0)  wp[++nwp] = $9 + 0
    if ($10 + 0 >= 0) wc[++nwc] = $10 + 0
    if ($11 + 0 >= 0) { wf[++nwf] = $11 + 0; wf_at[at] = (wf_at[at] > $11 + 0 ? wf_at[at] : $11 + 0) }
}

function isort(a, n,    i, j, v) {
    for (i = 2; i <= n; i++) { v = a[i]; for (j = i - 1; j >= 1 && a[j] > v; j--) a[j + 1] = a[j]; a[j + 1] = v }
}
function ssort(a, n,    i, j, v) {
    for (i = 2; i <= n; i++) { v = a[i]; for (j = i - 1; j >= 1 && a[j] "" > v ""; j--) a[j + 1] = a[j]; a[j + 1] = v }
}
function stats(a, n) {
    if (n == 0) return "n/a"
    isort(a, n)
    return sprintf("min=%d med=%d max=%d (n=%d)", a[1], a[int((n + 1) / 2)], a[n], n)
}
function join_counts(cnt,    k, keys, nk, i, out) {
    nk = 0
    for (k in cnt) keys[++nk] = k
    ssort(keys, nk)
    out = ""
    for (i = 1; i <= nk; i++) out = out (i > 1 ? " " : "") keys[i] "=" cnt[keys[i]]
    return (out == "" ? "none" : out)
}

END {
    nallowed = split(allowed, al, " ")
    for (i = 1; i <= nallowed; i++) ok[al[i]] = 1

    unexpected = 0; amax = 0
    for (i = 1; i <= nsid; i++) {
        s = sids[i]
        o = (last_st[s] == "00000") ? "COMMITTED" : last_st[s]
        outc[o]++
        if (o != "COMMITTED") fat[o "@" last_at[s]]++
        if (!(o in ok)) unexpected++
        adist[last_n[s]]++
        if (last_n[s] > amax) amax = last_n[s]
    }

    # attempts distribution, numerically ordered: "attempts:sessions"
    ad = ""
    for (a = 1; a <= amax; a++) if (a in adist) ad = ad (ad == "" ? "" : " ") a ":" adist[a]

    # peak number of simultaneously open transactions: sweep over [t0,t1]
    for (i = 2; i <= nev; i++) {
        t = ev_t[i]; d = ev_d[i]
        for (j = i - 1; j >= 1 && (ev_t[j] > t || (ev_t[j] == t && ev_d[j] > d)); j--) { ev_t[j + 1] = ev_t[j]; ev_d[j + 1] = ev_d[j] }
        ev_t[j + 1] = t; ev_d[j + 1] = d
    }
    cur = 0; peak = 0
    for (i = 1; i <= nev; i++) { cur += ev_d[i]; if (cur > peak) peak = cur }

    for (k in ser_at) ser_at2["40001@" k] = ser_at[k]

    print "sessions=" nsid + 0
    print "attempts_total=" att_total + 0
    print "outcomes=" join_counts(outc)
    print "final_at=" join_counts(fat)
    print "unexpected=" unexpected
    print "ser_total=" ser_total + 0
    print "ser_at=" join_counts(ser_at2)
    print "dl_total=" dl_total + 0
    print "attempts_dist=" (ad == "" ? "none" : ad)
    print "attempts_max=" amax
    print "peak_overlap=" peak
    print "wait_lock_ms=" stats(wl, nwl)
    print "wait_posting1_ms=" stats(wp, nwp)
    print "wait_commit_ms=" stats(wc, nwc)
    print "wait_failed_step_ms=" stats(wf, nwf)
}
