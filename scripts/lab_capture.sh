#!/usr/bin/env bash
# Bounded, non-destructive capture of the persistent benign lab.
# Does not revert, pause, inject into or shut down the VM.
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
CYCLES=${1:-24}
INTERVAL=${VMIC_INTERVAL:-5}
DOMAIN=${VMIC_DOMAIN:-hyptcn-lab}
[[ "$CYCLES" =~ ^[1-9][0-9]*$ ]] || { echo 'cycles must be a positive integer' >&2; exit 2; }
[[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || { echo 'VMIC_INTERVAL must be a positive integer (seconds)' >&2; exit 2; }
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
as_user python3 scripts/labctl.py --domain "$DOMAIN" status
as_user make -C vmicollect
STAMP=$(date -u +%Y%m%dT%H%M%SZ)_$$
OUT="$REPO/data/raw/${STAMP}_lab"
mkdir -p "$OUT"
cp data/lab/traffic.json "$OUT/traffic_before.json" 2>/dev/null || true
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
    -o output.dir="$OUT" -o output.writer=delta -o output.hash=none \
    -o output.delta_full_every=20 \
    -o schedule.interval_s="$INTERVAL" -o schedule.max_cycles="$CYCLES" \
    > "$OUT/collect.log" 2>&1 &
COLLECT_PID=$!
RC=0
wait "$COLLECT_PID" || RC=$?
COLLECT_PID=''
cp data/lab/traffic.json "$OUT/traffic_after.json" 2>/dev/null || true
python3 - "$OUT" "$DOMAIN" "$CYCLES" "$INTERVAL" "$RC" <<'PY'
import datetime, hashlib, json, pathlib, platform, subprocess, sys
out, domain, cycles, interval, rc = sys.argv[1:]
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
                     'collector_sha256': hashlib.sha256(pathlib.Path('vmicollect/build/vmicollect').read_bytes()).hexdigest(),
                     'raw_dir': out, 'label': 'server_lab', 'typ': 'benign'}}
(p/'capture.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
if int(rc) or len(sidecars) != int(cycles):
    raise SystemExit('Capture failed or incomplete; inspect collect.log')
PY
tail -n 4 "$OUT/collect.log"
echo "Capture complete: $OUT"
