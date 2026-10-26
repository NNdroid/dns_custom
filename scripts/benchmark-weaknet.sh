#!/bin/bash
# Runs the weak-network benchmark sweep and writes machine-readable results.
#
# The merge gate in .github/workflows/test.yml smoke-runs these benchmarks once
# per profile only to prove they execute; this script is where real numbers come
# from, so it runs them long enough to be meaningful and turns the output into a
# CSV that survives across commits.
#
#   BENCHTIME=3x ./scripts/benchmark-weaknet.sh
#
# Outputs into $OUT_DIR (default: bench):
#   weaknet-raw.txt  the unmodified `go test` output, for provenance
#   weaknet.csv      one row per profile, for trend comparison

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

BENCHTIME="${BENCHTIME:-3x}"
OUT_DIR="${OUT_DIR:-bench}"
BENCH_PATTERN="${BENCH_PATTERN:-BenchmarkWeakLink}"

mkdir -p "${OUT_DIR}"
RAW="${OUT_DIR}/weaknet-raw.txt"
CSV="${OUT_DIR}/weaknet.csv"

echo "=== Weak-network benchmark sweep (benchtime ${BENCHTIME}) ==="
echo

go test -run '^$' -bench "${BENCH_PATTERN}" -benchtime "${BENCHTIME}" -timeout 30m . | tee "${RAW}"

# `go test` tab-separates the fields but pads every one with spaces, so the
# whitespace is stripped before any anchor is applied. Custom benchmark metrics
# are printed in alphabetical order, so "retries" always precedes "window".
awk -F'\t' -v OFS=',' '
    BEGIN { print "profile,iterations,ns_per_op,mb_per_s,retries,window" }
    $1 ~ /^BenchmarkWeakLink\// && $3 ~ /ns\/op/ {
        name = $1; n = $2; ns = $3; mbs = $4; ret = $5; win = $6
        gsub(/[[:space:]]+/, "", name); gsub(/[[:space:]]+/, "", n)
        gsub(/[[:space:]]+/, "", ns);   gsub(/[[:space:]]+/, "", mbs)
        gsub(/[[:space:]]+/, "", ret);  gsub(/[[:space:]]+/, "", win)
        sub(/-[0-9]+$/, "", name)            # trailing GOMAXPROCS suffix
        sub(/^BenchmarkWeakLink\//, "", name)
        sub(/ns\/op$/, "", ns)
        sub(/MB\/s$/, "", mbs)
        sub(/retries$/, "", ret)
        sub(/window$/, "", win)
        print name, n, ns, mbs, ret, win
    }
' "${RAW}" > "${CSV}"

echo
echo "=== Results: ${CSV} ==="
cat "${CSV}"

# A sweep that produced no rows means the benchmark list drifted; fail loudly
# rather than uploading an empty artifact.
if [ "$(tail -n +2 "${CSV}" | wc -l)" -lt 1 ]; then
  echo "no benchmark results parsed from ${RAW}" >&2
  exit 1
fi
