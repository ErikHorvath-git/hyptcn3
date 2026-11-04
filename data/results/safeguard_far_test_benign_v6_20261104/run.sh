#!/usr/bin/env bash
# Final (one-time) evaluation of benign-v6: replay of the test_benign role with the trained bundle, then tcn.eval far --final.
# Run on the collection PC 2026-11-04 at 113e7c5 (setsid nohup, log /tmp/run_far_test.log); its --out was
# copied unchanged to data/results/safeguard_far_test_benign_v6_20261104.json. The ledger
# data/campaigns/benign-v6-20261026/corpus.json.test_benign-final.json records this single run.
set -euo pipefail
cd "$HOME/projects/hyptcn3"
CORPUS=data/campaigns/benign-v6-20261026/corpus.json
BUNDLE=data/models/server-v2-benign-v6
OUT=data/safeguard/far-test-benign-v6
mkdir -p "$OUT"
.venv/bin/python - "$CORPUS" > "$OUT/test_sessions.tsv" <<'P'
import json, sys
for s in json.load(open(sys.argv[1]))["sessions"]:
    if s["role"] == "test_benign":
        print(s["id"] + "\t" + s["features"])
P
while IFS=$'\t' read -r sid archive; do
  echo "replay $sid"
  .venv/bin/python -m safeguard replay --bundle "$BUNDLE" --archive "$archive" --out "$OUT/$sid" > "$OUT/$sid.replay.json"
done < "$OUT/test_sessions.tsv"
.venv/bin/python -m tcn.eval far --corpus "$CORPUS" --role test_benign --final --replay $(cut -f1 "$OUT/test_sessions.tsv" | sed "s#^#$OUT/#") \
  --campaign data/results/collection_campaign_benign_v6_20261026.json --out /tmp/safeguard_far_test_benign_v6_20261104.json
echo DONE
