#!/usr/bin/env bash
# E2, protocol v3 step A: replay of the 45 accepted sessions of the closed campaign events-v3-20261108 with the
# current bundle server-v2-benign-v6 (seed 0), then tcn.eval udalosti over the campaign's explicitly incomplete event
# index (groups 1-7 complete, group 8 has 3 of 6 sessions; see values.alokacia). Run on the collection PC
# (setsid nohup, log in the operator scratchpad); its --out was copied unchanged to
# data/results/safeguard_far_events_v3_20261114.json.
set -euo pipefail
cd "$HOME/projects/hyptcn3"
INDEX=data/campaigns/events-v3-20261108/events_index.json
BUNDLE=data/models/server-v2-benign-v6
OUT=data/safeguard/far-events-v3-20261108
RESULT=${1:?usage: run.sh RESULT_JSON}
mkdir -p "$OUT"
.venv/bin/python - "$INDEX" > "$OUT/sessions.tsv" <<'P'
import json, sys
for s in json.load(open(sys.argv[1]))["sessions"]:
    print(s["id"] + "\t" + s["features"])
P
while IFS=$'\t' read -r sid archive; do
  echo "replay $sid"
  .venv/bin/python -m safeguard replay --bundle "$BUNDLE" --archive "$archive" --out "$OUT/$sid" > "$OUT/$sid.replay.json"
done < "$OUT/sessions.tsv"
.venv/bin/python -m tcn.eval udalosti --index "$INDEX" --replay $(cut -f1 "$OUT/sessions.tsv" | sed "s#^#$OUT/#") \
  --out "$RESULT"
echo DONE
