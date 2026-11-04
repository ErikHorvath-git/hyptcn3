#!/usr/bin/env bash
# Extractor equivalence on corpus v6 raw data: old (d6c1ed4) vs new (625fe0f) features/+guestparse/.
# Run on the collection PC 2026-11-04 (setsid nohup, log /tmp/eqv.log) with /tmp/old.tar = git archive d6c1ed4
# features guestparse and /tmp/new.tar = git archive 625fe0f features guestparse; printed output is in the record.
set -euo pipefail
W=/tmp/eqv; rm -rf $W; mkdir -p $W/old $W/new $W/ses/raw
tar -xf /tmp/old.tar -C $W/old; tar -xf /tmp/new.tar -C $W/new
SES=benign-v6-20261026_01_train_write_heavy
RAW=$HOME/hyptcn3-archive/campaigns/benign-v6-20261026/collections/$SES/raw
PROF=$HOME/projects/hyptcn3/data/collections/$SES/profile
for i in $(seq 0 59); do
  n=$(printf "%06d" $i)
  for f in "$RAW"/hyptcn-lab_${n}_*; do
    case "$f" in *.zst) zstd -q -d "$f" -o "$W/ses/raw/$(basename "${f%.zst}")" ;; *) cp "$f" "$W/ses/raw/" ;; esac
  done
done
cp "$RAW"/capture.json "$W/ses/raw/" 2>/dev/null || true
cp "$HOME/projects/hyptcn3/data/collections/$SES/session.json" "$W/ses/"
for v in old new; do
  (cd $W/$v && $HOME/projects/hyptcn3/.venv/bin/python -m features session --snapshot $W/ses/raw --profile "$PROF" --quality-policy behavioral-inputs-v1 --out $W/$v.npz > $W/$v.log 2>&1) || { echo "FAIL $v"; tail -n 3 $W/$v.log; }
done
$HOME/projects/hyptcn3/.venv/bin/python - <<'P'
import numpy as np
a, b = np.load("/tmp/eqv/old.npz", allow_pickle=False), np.load("/tmp/eqv/new.npz", allow_pickle=False)
print("keys equal:", sorted(a.files) == sorted(b.files), sorted(a.files))
diff = []
for k in a.files:
    x, y = a[k], b[k]
    same = x.shape == y.shape and (np.array_equal(x, y, equal_nan=True) if x.dtype.kind in "fc" else np.array_equal(x, y))
    if not same: diff.append(k)
print("rows:", a["matica"].shape, "differing arrays:", diff)
P
echo DONE
