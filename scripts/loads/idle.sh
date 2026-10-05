#!/usr/bin/env bash
# idle - nečinná VM. Referenčná záťaž (BENIGNA trieda v tcn/train.py).
set -uo pipefail
echo "idle: seed=${SEED:-0} dur=${DUR:-60}"
sleep "${DUR:-60}"
echo "idle: koniec"
