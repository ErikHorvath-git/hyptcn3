#!/bin/bash
# Supplementary evidence of the second G0 record: check_claims.sh again, on the commit that fixes the handbook's date
# (d1fac50, documents only), because the run of g0_dokazy2.sh on 3372df0 found docs/PRIRUCKA.md stale by its date
# line alone. check_claims.sh runs the whole suite itself (check_prirucka.sh regenerates the handbook and compares).
# The log carries the full header (S2). Runs alone in the main repository.
set -u
cd /home/eh/projects/hyptcn3 || exit 2
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
D=data/results/g0_doplnok_$STAMP
mkdir -p $D
cp "$0" $D/g0_doplnok.sh
HEAD=$(git rev-parse HEAD)
{ echo "# commit $HEAD"; echo "# date $(date -u +%FT%TZ)"; echo "# host $(hostname)"
  echo "# git status --porcelain (only the evidence directories, when clean):"; git status --porcelain | sed 's/^/#   /'
  echo "# command nice -n 19 bash scripts/check_claims.sh"
  nice -n 19 bash scripts/check_claims.sh 2>&1; echo "exit $?"; } > $D/check_claims.log
for d in /tmp/pytest-of-eh/pytest-*; do [ -d "$d" ] && [ ! -L "$d" ] && rm -rf "$d"; done
echo "# $(date -u +%FT%TZ) evidence in $D"; tail -3 $D/check_claims.log
