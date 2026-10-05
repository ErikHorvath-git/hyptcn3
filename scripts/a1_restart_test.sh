#!/usr/bin/env bash
#
# a1_restart_test.sh - A1: znovupripojenie zberaca po reštarte hosťa.
#
# Priebeh: vmicollect run (delta, perioda z prepinacov) bezi na pozadi, po
# 3. snimke sa domena ZNICI a hned NASKARtuje (virsh destroy + start pod
# uctom pouzivatela), beh dobehne do konca a overi sa:
#   - beh skoncil kodom 0 a napisal aspon jednu snimku po reštarte,
#   - v sidecaroch su DVE rozne vm.vmid (stary a novy QEMU pid),
#   - posledna snimka patri NOVEMU pidu (zber pokracoval po reštarte).
#
# Vysledok: data/results/a1_restart_<stamp>.json (schema hyptcn3/a1-restart/1).
#
# Spustenie:  sudo scripts/a1_restart_test.sh [-d DOMENA] [-i S] [-N N]
#             sudo scripts/a1_restart_test.sh --dry-run
#
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || exit 1
BIN="$REPO/vmicollect/build/vmicollect"
DOMAIN="${VMIC_DOMAIN:-hyptcn-guest}"
URI="${VMIC_LIBVIRT_URI:-qemu:///session}"
INTERVAL="${VMIC_INTERVAL:-5.0}"
CYCLES=8
DRY=0

usage()
{
    cat <<'EOF'
POUZITIE
  a1_restart_test.sh [-d DOMENA] [-i SEKUNDY] [-N CYKLOV] [-n|--dry-run]

  -d, --domain NAZOV   libvirt domena (vychodzie: hyptcn-guest)
  -i, --interval S     perioda zberu v sekundach (vychodzie: 5)
  -N, --cycles N       pocet cyklov (vychodzie: 8)
  -n, --dry-run        vypis plan a skonci (root netreba)

  PRECO sudo: samotny zber (eBPF nad KVM) potrebuje CAP_BPF. Restart domeny
  robi skript pod uctom pouzivatela (SUDO_USER), lebo libvirt bezi
  v session rezime.
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--domain)   [ $# -ge 2 ] || usage; DOMAIN="$2"; shift 2 ;;
        -i|--interval) [ $# -ge 2 ] || usage; INTERVAL="$2"; shift 2 ;;
        -N|--cycles)   [ $# -ge 2 ] || usage; CYCLES="$2"; shift 2 ;;
        -n|--dry-run)  DRY=1; shift ;;
        *) usage ;;
    esac
done

as_user()
{
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        local uid home
        uid=$(id -u "$SUDO_USER") || return 1
        home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        runuser -u "$SUDO_USER" -- env "XDG_RUNTIME_DIR=/run/user/$uid" \
                "HOME=$home" "$@"
    else
        "$@"
    fi
}

if [ "$DRY" -eq 1 ]; then
    echo "plan: vmicollect run (delta, $INTERVAL s, $CYCLES cyklov) na domene '$DOMAIN'"
    echo "      po 3. sidecari: virsh destroy + virsh start '$DOMAIN'"
    echo "      overenie: dve rozne vm.vmid v sidecaroch, posledna snimka z noveho pidu"
    echo "      vystup: data/results/a1_restart_<stamp>.json"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || {
    echo "a1_restart_test.sh: potrebuje root - spusti cez sudo" >&2
    exit 1
}

state=$(as_user virsh --connect "$URI" domstate "$DOMAIN" 2>&1 | head -1)
[ "$state" = "running" ] || {
    echo "a1_restart_test.sh: domena $DOMAIN nebezi (domstate: $state)" >&2
    echo "                    spusti ju: virsh --connect $URI start $DOMAIN" >&2
    exit 1
}

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
COMMIT=$(git -C "$REPO" rev-parse HEAD)
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/a1_restart.XXXXXX") || exit 1
OUT="$REPO/data/results/a1_restart_${STAMP}.json"

"$BIN" run -o vm.domain="$DOMAIN" -o output.dir="$TMPD" \
    -o output.writer=delta -o schedule.interval_s="$INTERVAL" \
    -o schedule.max_cycles="$CYCLES" -o output.hash=none \
    >"$TMPD/run.log" 2>&1 &
RUNPID=$!

# cakaj na 3. sidecar (najviac 60 s)
sidecars=0
for _ in $(seq 1 60); do
    sidecars=$(ls "$TMPD"/*.json 2>/dev/null | wc -l)
    [ "$sidecars" -ge 3 ] && break
    sleep 1
done

restart_ok="nie"
restart_note="sidecary nevznikli vcas (menej nez 3)"
if [ "$sidecars" -ge 3 ]; then
    as_user virsh --connect "$URI" destroy "$DOMAIN" >/dev/null 2>&1
    sleep 1
    as_user virsh --connect "$URI" start "$DOMAIN" >/dev/null 2>&1
    restart_ok="ano"
    restart_note="po ${sidecars}. sidecari"
fi

wait "$RUNPID"
RC=$?
state2=$(as_user virsh --connect "$URI" domstate "$DOMAIN" 2>&1 | head -1)

python3 - "$TMPD" "$DOMAIN" "$STAMP" "$COMMIT" "$RC" "$state2" \
        "$restart_ok" "$restart_note" "$INTERVAL" "$CYCLES" "$OUT" <<'PYEOF'
import json, os, sys
tmpd, domain, stamp, commit, rc, state2, restart_ok, restart_note, interval, cycles, out = sys.argv[1:]
vmids = []
seqs = []
chains = set()
for name in sorted(os.listdir(tmpd)):
    if not name.endswith(".json"):
        continue
    try:
        doc = json.load(open(os.path.join(tmpd, name), encoding="utf-8"))
    except (OSError, ValueError):
        continue
    vmid = (doc.get("vm") or {}).get("vmid")
    if vmid is not None:
        vmids.append((name, vmid))
    seqs.append(doc.get("seq"))
    chain = doc.get("output", {}).get("chain_id")
    if chain:
        chains.add(chain)

unique = {}
for name, vmid in vmids:
    unique.setdefault(vmid, []).append(name)

log_tail = ""
log_path = os.path.join(tmpd, "run.log")
if os.path.exists(log_path):
    log_tail = "\n".join(open(log_path, encoding="utf-8", errors="replace")
                         .read().splitlines()[-4:])

# posledna snimka = najvyssi seq
last_doc = None
last_name = ""
for name in sorted(os.listdir(tmpd)):
    if not name.endswith(".json"):
        continue
    try:
        d = json.load(open(os.path.join(tmpd, name), encoding="utf-8"))
    except (OSError, ValueError):
        continue
    if last_doc is None or d.get("seq", -1) >= last_doc.get("seq", -1):
        last_doc, last_name = d, name
last_vmid = (last_doc or {}).get("vm", {}).get("vmid")
newest_vmid = sorted(unique)[-1] if unique else None

doc = {
    "schema": "hyptcn3/a1-restart/1",
    "date": "%s-%s-%sT%s:%s:%sZ" % (stamp[:4], stamp[4:6], stamp[6:8],
                                    stamp[9:11], stamp[11:13], stamp[13:15]),
    "commit": commit,
    "command": ("vmicollect run (delta, interval %ss, %s cyklov) na domene "
                "'%s'; po 3. sidecari virsh destroy+start" %
                (interval, cycles, domain)),
    "domain": domain,
    "run_rc": int(rc),
    "domain_state_po": state2,
    "restart": {"vykonany": restart_ok == "ano", "poznamka": restart_note},
    "n_sidecars": len(seqs),
    "n_vmid": len(unique),
    "vmids": {str(k): v for k, v in unique.items()},
    "posledna_snimka": {"subor": last_name,
                        "vmid": last_vmid,
                        "novy_pid": last_vmid == newest_vmid},
    "chains": len(chains),
    "log_tail": log_tail,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=1, ensure_ascii=False)
    fh.write("\n")

print("a1_restart_test: rc=%s, sidecarov=%d, vmid=%d, posledna_snimka_novy_pid=%s"
      % (rc, len(seqs), len(unique), doc["posledna_snimka"]["novy_pid"]))
ok = (int(rc) == 0 and len(unique) >= 2 and doc["posledna_snimka"]["novy_pid"])
print("VYSLEDOK:", "OK - zberac sa po reštarte pripojil na novy pid" if ok
      else "NEUSPECH - pozri %s" % out)
sys.exit(0 if ok else 1)
PYEOF
RC2=$?

# vysledok aj adresar so snimkami vratime pouzivatelovi
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    chown -R "$SUDO_USER" "$TMPD" "$OUT" 2>/dev/null
fi
echo "snimky:  $TMPD"
echo "vysledok: $OUT"

exit $RC2
