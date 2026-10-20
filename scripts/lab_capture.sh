#!/usr/bin/env bash
# Bounded, non-destructive capture of the persistent benign lab.
# Does not revert, pause, inject into or shut down the VM.
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
CYCLES=${1:-24}
INTERVAL=${VMIC_INTERVAL:-5}
DOMAIN=${VMIC_DOMAIN:-hyptcn-lab}
FULL_EVERY=${VMIC_FULL_EVERY:-20}
FSYNC=${VMIC_FSYNC:-true}
HASH_ASYNC=${VMIC_HASH_ASYNC:-false}
# Set by scripts/collection.py, which performs the status/build preflight
# before warmup and records its own session traffic; nothing here may touch
# the HTTP endpoint inside the measured interval.
MANAGED=${VMIC_MANAGED_SESSION:-0}
[[ "$CYCLES" =~ ^[1-9][0-9]*$ ]] || { echo 'cycles must be a positive integer' >&2; exit 2; }
[[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || { echo 'VMIC_INTERVAL must be a positive integer (seconds)' >&2; exit 2; }
[[ "$FULL_EVERY" =~ ^[1-9][0-9]*$ ]] || { echo 'VMIC_FULL_EVERY must be a positive integer' >&2; exit 2; }
[[ "$FSYNC" =~ ^(true|false)$ ]] || { echo 'VMIC_FSYNC must be true or false' >&2; exit 2; }
[[ "$HASH_ASYNC" =~ ^(true|false)$ ]] || { echo 'VMIC_HASH_ASYNC must be true or false' >&2; exit 2; }
[[ "$MANAGED" =~ ^[01]$ ]] || { echo 'VMIC_MANAGED_SESSION must be 0 or 1' >&2; exit 2; }
if [ "$(id -u)" -ne 0 ]; then
    echo "eBPF requires root: sudo $0 $CYCLES" >&2
    exit 2
fi
as_user() {
    if [ -n "${SUDO_USER:-}" ]; then
        runuser -u "$SUDO_USER" -- env "XDG_RUNTIME_DIR=/run/user/$(id -u "$SUDO_USER")" "$@"
    else
        "$@"
    fi
}
if [ "$MANAGED" = 0 ]; then
    as_user python3 scripts/labctl.py --domain "$DOMAIN" status
    as_user make -C vmicollect
fi
STAMP=$(date -u +%Y%m%dT%H%M%SZ)_$$
OUT=${VMIC_OUT:-"$REPO/data/raw/${STAMP}_lab"}
mkdir -p "$(dirname "$OUT")"
mkdir "$OUT"
# Standalone captures only: status of the persistent generator, named as such.
# It is not evidence for a managed session, which keeps its own request log.
if [ "$MANAGED" = 0 ]; then
    cp data/lab/traffic.json "$OUT/persistent_traffic_status_before.json" 2>/dev/null || true
fi
COLLECT_PID=''
cleanup() {
    if [ -n "$COLLECT_PID" ] && kill -0 "$COLLECT_PID" 2>/dev/null; then
        kill -TERM "$COLLECT_PID" 2>/dev/null || true
        wait "$COLLECT_PID" || true
    fi
    if [ -n "${SUDO_UID:-}" ]; then
        chown -R "$SUDO_UID:${SUDO_GID:-$(id -g "$SUDO_USER")}" "$OUT"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "Collecting $CYCLES snapshots every ${INTERVAL}s from $DOMAIN -> $OUT"
vmicollect/build/vmicollect run \
    -o vm.domain="$DOMAIN" -o vm.backend=ebpf \
    -o output.dir="$OUT" -o output.writer=delta -o output.hash=sha256 \
    -o output.delta_full_every="$FULL_EVERY" -o output.fsync="$FSYNC" -o output.hash_async="$HASH_ASYNC" \
    -o features.enable=true -o features.entropy=true -o features.bin_bytes=16777216 \
    -o retention.max_snapshots=0 -o retention.max_bytes=0 -o retention.max_age_s=0 \
    -o schedule.interval_s="$INTERVAL" -o schedule.max_cycles="$CYCLES" \
    > "$OUT/collect.log" 2>&1 &
COLLECT_PID=$!
RC=0
wait "$COLLECT_PID" || RC=$?
COLLECT_PID=''
if [ "$MANAGED" = 0 ]; then
    cp data/lab/traffic.json "$OUT/persistent_traffic_status_after.json" 2>/dev/null || true
fi
python3 - "$OUT" "$DOMAIN" "$CYCLES" "$INTERVAL" "$RC" "$FULL_EVERY" "$FSYNC" "$MANAGED" "$HASH_ASYNC" <<'PY'
import datetime, hashlib, json, pathlib, platform, subprocess, sys
out, domain, cycles, interval, rc, full_every, fsync, managed, hash_async = sys.argv[1:]
p = pathlib.Path(out)
sidecars = []
for path in p.glob('*.json'):
    doc = json.loads(path.read_text())
    if doc.get('schema') == 'vmicollect/1':
        sidecars.append(doc)
result = {'schema': 'hyptcn3/lab-capture/1',
          'commit': subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
          'commit_dirty': bool(subprocess.check_output(['git','status','--porcelain'],text=True).strip()),
          'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'host': platform.platform(), 'guest': {'domain': domain},
          'command': f'sudo scripts/lab_capture.sh {cycles}', 'n': len(sidecars),
          'values': {'requested_cycles': int(cycles), 'interval_s': int(interval),
                     'collector_exit_code': int(rc), 'snapshots': len(sidecars),
                     'full_every': int(full_every), 'output_hash': 'sha256',
                     'fsync': fsync == 'true', 'hash_async': hash_async == 'true', 'managed_session': managed == '1',
                     'collector_sha256': hashlib.sha256(pathlib.Path('vmicollect/build/vmicollect').read_bytes()).hexdigest(),
                     'raw_dir': out, 'label': 'server_lab', 'typ': 'benign'}}
(p/'capture.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
if int(rc) or len(sidecars) != int(cycles):
    raise SystemExit('Capture failed or incomplete; inspect collect.log')
PY
tail -n 4 "$OUT/collect.log"
echo "Capture complete: $OUT"
