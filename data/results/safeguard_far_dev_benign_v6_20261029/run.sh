#!/usr/bin/env bash
# Replay of the dev role of benign-v6 with the trained bundle, then FAR (tcn.eval far).
# Run on the collection PC 2026-10-29 at 591a061 (setsid nohup, log /tmp/run_far_dev.log). Its --out
# /tmp/safeguard_far_dev_benign_v6_20261030.json was copied unchanged to
# data/results/safeguard_far_dev_benign_v6_20261029.json (date of the run in UTC). The _b record reran
# only the last command over the same replays at a1a4b9b, with --out /tmp/..._20261029_b.json.
set -euo pipefail
cd "$HOME/projects/hyptcn3"
CORPUS=data/campaigns/benign-v6-20261026/corpus.json
BUNDLE=data/models/server-v2-benign-v6
OUT=data/safeguard/far-dev-benign-v6
mkdir -p "$OUT"
.venv/bin/python - "$CORPUS" > "$OUT/dev_sessions.tsv" <<'P'
import json, sys
for s in json.load(open(sys.argv[1]))["sessions"]:
    if s["role"] == "dev":
        print(s["id"] + "\t" + s["features"])
P
while IFS=$'\t' read -r sid archive; do
  echo "replay $sid"
  .venv/bin/python -m safeguard replay --bundle "$BUNDLE" --archive "$archive" --out "$OUT/$sid" > "$OUT/$sid.replay.json"
done < "$OUT/dev_sessions.tsv"
.venv/bin/python -m tcn.eval far --corpus "$CORPUS" --role dev --replay $(cut -f1 "$OUT/dev_sessions.tsv" | sed "s#^#$OUT/#") \
  --campaign data/results/collection_campaign_benign_v6_20261026.json --out /tmp/safeguard_far_dev_benign_v6_20261030.json
echo DONE
