#!/usr/bin/env bash
#
# session.sh - B4: jedno cele sedenie podľa manifestu.
#
#   sudo scripts/session.sh <manifest.json> [--dry-run]
#
# PRIEBEH (B5 - KRITICKÉ): benígne aj škodlivé sedenie má IDENTICKÝ tok:
#
#   snapshot-revert hyptcn-clean  →  štart VM  →  zahriatie (warmup_s)
#   → apt_packages (do overlayu, po sedení zahodené)
#   → tcpdump na moste (voliteľný)
#   → pozemná pravda PRED (ps/lsmod/ss/boot_id cez guest_exec)
#   → štart zberu (vmicollect run, root)
#   → INJEKCIA binárky cez qemu-guest-agent (guest-file-open/write/close +
#     guest-exec) - benígna binárka pri benígnom sedení, PoC/malvér pri
#     škodlivom; mechanizmus je ten istý
#   → záťaž C (benígny) / beh injikovanej binárky (pevný čas runtime_s)
#   → pozemná pravda PO  →  stop zberu  →  stop tcpdump
#   → virsh destroy + snapshot-revert (zahodenie overlayu)
#   → manifest sedenia (typ, štítok, SHA-256, commit, časy, priebeh)
#
# Jediný rozdiel benígne/škodlivé = obsah injikovanej binárky. Preto sa
# model nemôže naučiť harness namiesto správania (B5). Priebeh sa zapisuje
# do manifestu na dôkaz.
#
# Výstupy:
#   data/raw/<stamp>_session/            snímky .vmicd (mimo gitu)
#   data/sessions/<stamp>_<label>_<typ>/ pozemná pravda + manifest + tcpdump
#
# Root treba iba na zber (eBPF) a tcpdump; virsh a guest_exec bežia pod
# SUDO_USER (libvirt qemu:///session), rovnako ako v root_run.sh.
#
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || exit 1
BIN="$REPO/vmicollect/build/vmicollect"
GUEST_EXEC="$REPO/scripts/guest_exec.sh"
URI="${VMIC_LIBVIRT_URI:-qemu:///session}"
DOMAIN="${VMIC_DOMAIN:-hyptcn-guest}"
SNAPSHOT="${VMIC_SNAPSHOT:-hyptcn-clean}"
BRIDGE="${VMIC_BRIDGE:-virbr0}"
# profil hosta (kallsyms+BTF); A2 preukotvenie ho pri inych bootoch opravi
PROFILE="${VMIC_PROFILE:-$REPO/profiles/debian12-6.1.0-42-cloud-amd64}"
DRY=0

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

give_back()
{
    local target="$1"
    [ -e "$target" ] || return 0
    [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] || return 0
    chown -R "${SUDO_UID:-$(id -u "$SUDO_USER")}:${SUDO_GID:-$(id -g "$SUDO_USER")}" \
        "$target" 2>/dev/null || return 1
}

die() { echo "session.sh: $*" >&2; exit 1; }

MANIFEST_IN=""
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        *) MANIFEST_IN="$a" ;;
    esac
done
[ -n "$MANIFEST_IN" ] || die "pouzitie: session.sh <manifest.json> [--dry-run]"
[ -f "$MANIFEST_IN" ] || die "manifest $MANIFEST_IN neexistuje"

for tool in jq virsh sha256sum base64; do
    command -v "$tool" >/dev/null || die "chyba nastroj $tool"
done

TYP=$(jq -r '.typ // "benign"' "$MANIFEST_IN")
LABEL=$(jq -r '.label // empty' "$MANIFEST_IN")
NET=$(jq -r '.net // "default"' "$MANIFEST_IN")
[ -n "$LABEL" ] || die "manifest nema label"
SEED=$(jq -r '.seed // 0' "$MANIFEST_IN")
WARMUP=$(jq -r '.warmup_s // 30' "$MANIFEST_IN")
RUNTIME=$(jq -r '.runtime_s // 300' "$MANIFEST_IN")
INTERVAL=$(jq -r '.interval_s // 5' "$MANIFEST_IN")
LOAD=$(jq -r '.load // empty' "$MANIFEST_IN")
TCPDUMP=$(jq -r '.tcpdump // true' "$MANIFEST_IN")
INJ_FILE=$(jq -r '.injekcia.subor // empty' "$MANIFEST_IN")
INJ_ARGS=$(jq -r '.injekcia.args // [] | join(" ")' "$MANIFEST_IN")
COLLECT_WRITER=$(jq -r '.collect.writer // "delta"' "$MANIFEST_IN")
COLLECT_HASH=$(jq -r '.collect.hash // "none"' "$MANIFEST_IN")

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# Diagnostika: kazdy riadok aj stderr idu do /tmp/session_debug_<stamp>.log -
# ked sedenie umrie, subor ukaze presne kde (zostava aj po ukonceni).
exec 2> >(tee -a "/tmp/session_debug_${STAMP}.log" >&2)
PS4='+${LINENO}: '
if [ "${SESSION_TRACE:-0}" = "1" ]; then set -x; fi
SESS="$REPO/data/sessions/${STAMP}_${LABEL}_${TYP}"
RAWDIR="$REPO/data/raw/${STAMP}_session"

if [ "$DRY" -eq 1 ]; then
    echo "plan sedenia: $TYP/$LABEL seed=$SEED warmup=${WARMUP}s runtime=${RUNTIME}s interval=${INTERVAL}s"
    echo "  revert:  virsh snapshot-revert $DOMAIN $SNAPSHOT --running"
    echo "  zber:    vmicollect run (writer=$COLLECT_WRITER) -> $RAWDIR"
    echo "  injekcia: guest-agent -> $INJ_FILE ($INJ_ARGS)"
    [ -n "$LOAD" ] && echo "  zataz:   scripts/loads/run.sh $LOAD --seed $SEED --dur $RUNTIME"
    echo "  ground truth PRED/PO + tcpdump=$TCPDUMP -> $SESS"
    exit 0
fi

mkdir -p "$SESS" "$RAWDIR"

[ "$(id -u)" -eq 0 ] || die "potrebuje root (eBPF zber) - spusti cez sudo"

# ---------------------------------------------------------------- revert
as_user virsh --connect "$URI" destroy "$DOMAIN" >/dev/null 2>&1 || true
as_user virsh --connect "$URI" snapshot-revert "$DOMAIN" "$SNAPSHOT" --running \
    || die "revert $SNAPSHOT zlyhal - vytvor ho: virsh snapshot-create-as $DOMAIN $SNAPSHOT 'cisty stav'"

# ------------------------------------------------------------------ priebeh
priebeh=()
zaznam() { priebeh+=("$(date -u +%H:%M:%S)Z $1"); echo "session: $1"; }

zaznam "revert $SNAPSHOT ok, VM startuje"
zaznam "zahriatie ${WARMUP}s"
sleep "$WARMUP"

# apt_packages (iba v overlayi - po reverte zmiznu)
APT_PKGS=$(jq -r '.apt_packages // [] | join(" ")' "$MANIFEST_IN")
if [ -n "$APT_PKGS" ]; then
    zaznam "apt install: $APT_PKGS"
    as_user "$GUEST_EXEC" -- "DEBIAN_FRONTEND=noninteractive apt-get install -y $APT_PKGS" \
        >"$SESS/apt.log" 2>&1 || zaznam "POZOR: apt install vratil chybu (pozri apt.log)"
fi

# tcpdump na moste
TCPDUMP_PID=""
ISO_ATTACHED=0
if [ "$NET" = "isolated" ]; then
    zaznam "izolovana siet: net-start hyptcn-iso + attach-interface"
    as_user virsh --connect "$URI" net-start hyptcn-iso >/dev/null 2>&1 || true
    as_user virsh --connect "$URI" attach-interface "$DOMAIN" network hyptcn-iso --model virtio --config --live >/dev/null 2>&1 \
        || zaznam "POZOR: attach hyptcn-iso zlyhal"
    ISO_ATTACHED=1
fi
if [ "$TCPDUMP" = "true" ]; then
    zaznam "tcpdump na $BRIDGE"
    tcpdump -i "$BRIDGE" -w "$SESS/tcpdump.pcap" -s 96 >/dev/null 2>&1 &
    TCPDUMP_PID=$!
fi

# pozemná pravda PRED
zaznam "ground truth PRED"
as_user "$GUEST_EXEC" -- 'ps -eo pid,comm --no-headers' > "$SESS/ps_before.txt"
as_user "$GUEST_EXEC" -- 'lsmod' > "$SESS/lsmod_before.txt"
as_user "$GUEST_EXEC" -- 'ss -tulpn' > "$SESS/ss_before.txt" 2>/dev/null || true
as_user "$GUEST_EXEC" -- 'find /tmp /root /var/tmp -xdev -type f -printf "%p %s\n" 2>/dev/null | sort' > "$SESS/files_before.txt"
as_user "$GUEST_EXEC" -- 'cat /proc/sys/kernel/random/boot_id' > "$SESS/boot_id_before.txt"

# zber na pozadí
zaznam "zber: vmicollect run writer=$COLLECT_WRITER interval=${INTERVAL}s"
"$BIN" run -o vm.domain="$DOMAIN" -o output.dir="$RAWDIR" \
    -o output.writer="$COLLECT_WRITER" -o schedule.interval_s="$INTERVAL" \
    -o output.hash="$COLLECT_HASH" > "$SESS/collect.log" 2>&1 &
COLLECT_PID=$!

# A3: baseline textu z CISTEJ snimky TOHOTO bootu (LIMITACIE L18 -
# medzi bootmi sa text legitímne líši, takže baseline pre validaciu
# sedenia musi vzniknut z prvej (plnej) snimky rovnakeho bootu; profil
# sa preukotvi sam)
sleep 10
if ls "$RAWDIR"/*.json >/dev/null 2>&1; then
    python3 -m guestparse textbaseline --snapshot "$RAWDIR" \
        --profile "$PROFILE" --force >> "$SESS/collect.log" 2>&1 \
        || zaznam "POZOR: baseline textu tohto bootu sa nepodarila"
else
    zaznam "POZOR: prva snimka sa neobjavila - baseline textu sa nevytvorila"
fi

# injekcia binárky cez guest-agent (identický mechanizmus pre oba typy)
zaznam "injekcia: $INJ_FILE"
if [ ! -f "$INJ_FILE" ]; then
    die "subor na injekciu $INJ_FILE neexistuje (benign payload: harness/payloads/)"
fi
INJ_SHA=$(sha256sum "$INJ_FILE" | cut -d' ' -f1)
INJ_REMOTE="/tmp/hyptcn_payload"
# virsh qemu-agent-command musi bezat pod SUDO_USER (libvirt session rezim) -
# preto cely pythonovy prenos ide cez as_user, ktore nastavi HOME/XDG.
as_user python3 - "$INJ_FILE" "$INJ_REMOTE" "$URI" "$DOMAIN" <<'PYEOF'
import base64, json, subprocess, sys
local, remote, uri, domain = sys.argv[1:]
def ga(cmd):
    r = subprocess.run(["virsh", "--connect", uri, "qemu-agent-command", domain, cmd],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("guest-agent zlyhal: %s" % r.stderr.strip())
    return json.loads(r.stdout)
data = open(local, "rb").read()
fd = ga(json.dumps({"execute": "guest-file-open",
                    "arguments": {"path": remote, "mode": "w+"}}))["return"]
try:
    CH = 512 * 1024
    for i in range(0, len(data), CH):
        chunk = base64.b64encode(data[i:i+CH]).decode()
        ga(json.dumps({"execute": "guest-file-write",
                       "arguments": {"handle": fd, "buf-b64": chunk}}))
finally:
    ga(json.dumps({"execute": "guest-file-close", "arguments": {"handle": fd}}))
print("injekcia: %d bajtov cez guest-agent -> %s" % (len(data), remote))
PYEOF
as_user "$GUEST_EXEC" -- "chmod +x $INJ_REMOTE"

# beh injikovanej binárky - JEDINÁ cesta pre oba typy (B5): benígne sedenie
# injikuje benígnu binárku (napr. záťažový skript z C s SEED/DUR), škodlivé
# injikuje PoC/malvér. Mechanizmus, načasovanie aj ukončenie sú rovnaké.
zaznam "beh injikovanej binárky ${RUNTIME}s (seed=$SEED)"
as_user "$GUEST_EXEC" -- "SEED=$SEED DUR=$RUNTIME $INJ_REMOTE $INJ_ARGS" \
    > "$SESS/payload.log" 2>&1 &
PAYLOAD_PID=$!

# HOST-SIDE traffic: skutocna externa premavka (host -> virbr0 -> sluzby
# v hostovi), paralelne s payloadom - tcpdump na moste ju zachyti
HT_PID=""
HOST_TRAFFIC=$(jq -r '.host_traffic // false' "$MANIFEST_IN")
if [ "$HOST_TRAFFIC" != "false" ]; then
    HT_TARGET=$(jq -r '.host_traffic_target // "http://192.168.122.100"' "$MANIFEST_IN")
    zaznam "host-side traffic: host_traffic.py -> $HT_TARGET (${RUNTIME}s, seed=$SEED)"
    python3 "$REPO/scripts/host_traffic.py" --target "$HT_TARGET" \
        --dur "$RUNTIME" --seed "$SEED" > "$SESS/host_traffic.log" 2>&1 &
    HT_PID=$!
fi

sleep "$RUNTIME"
kill "$PAYLOAD_PID" 2>/dev/null || true
# ssh/agent zabije len prenos, nie vzdialeny proces - dobeh sa pripadne
# dorazi v hostovi (best effort; skripty sa koncia same po DUR)
as_user "$GUEST_EXEC" -- "pkill -f $INJ_REMOTE" >/dev/null 2>&1 || true

# pozemná pravda PO
zaznam "ground truth PO"
as_user "$GUEST_EXEC" -- 'ps -eo pid,comm --no-headers' > "$SESS/ps_after.txt"
as_user "$GUEST_EXEC" -- 'lsmod' > "$SESS/lsmod_after.txt"
as_user "$GUEST_EXEC" -- 'ss -tulpn' > "$SESS/ss_after.txt" 2>/dev/null || true
as_user "$GUEST_EXEC" -- 'find /tmp /root /var/tmp -xdev -type f -printf "%p %s\n" 2>/dev/null | sort' > "$SESS/files_after.txt"

[ -n "$HT_PID" ] && kill "$HT_PID" 2>/dev/null || true
[ -n "$HT_PID" ] && wait "$HT_PID" 2>/dev/null || true

# stop zberu a tcpdump
kill -INT "$COLLECT_PID" 2>/dev/null || true
wait "$COLLECT_PID" 2>/dev/null || true
if [ -n "$TCPDUMP_PID" ]; then
    sleep 1
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
fi

if [ "$ISO_ATTACHED" = "1" ]; then
    as_user virsh --connect "$URI" detach-interface "$DOMAIN" network --live >/dev/null 2>&1 || true
    zaznam "izolovana siet odpojena"
fi

# zahodenie overlayu
zaznam "stop VM + revert (zahodenie overlayu)"
as_user virsh --connect "$URI" destroy "$DOMAIN" >/dev/null 2>&1 || true
as_user virsh --connect "$URI" snapshot-revert "$DOMAIN" "$SNAPSHOT" >/dev/null \
    || zaznam "POZOR: zaverecny revert zlyhal"

# ---------------------------------------------------------------- manifest
COLLECT_TAIL=$(grep -E "koniec:" "$SESS/collect.log" | tail -1 || true)
N_SIDECARS=$(ls "$RAWDIR"/*.json 2>/dev/null | wc -l)
python3 - "$SESS" "$MANIFEST_IN" "$STAMP" "$INJ_SHA" "$N_SIDECARS" \
        "$COLLECT_TAIL" "$TYP" "$LABEL" "$SEED" "$REPO" <<'PYEOF'
import json, os, subprocess, sys
sess, manifest_in, stamp, inj_sha, n_sidecars, collect_tail, typ, label, seed, repo = sys.argv[1:]
# POZOR: skript bezi cez 'python3 -' (stdin), preto __file__ je '<stdin>' a
# cestu k repu NESMIE odvodzovat - podava ju session.sh ako posledny argv
# (2026-10-05: prave toto ticho zabilo manifest prveho sedenia).
commit = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"],
                                 text=True).strip()
inp = json.load(open(manifest_in, encoding="utf-8"))
def sha(p):
    if not os.path.exists(p):
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()

out = {
    "schema": "hyptcn3/session/1",
    "stamp": stamp,
    "date": "%s-%s-%sT%s:%s:%sZ" % (stamp[:4], stamp[4:6], stamp[6:8],
                                    stamp[9:11], stamp[11:13], stamp[13:15]),
    "commit": commit,
    "typ": typ,
    "label": label,
    "seed": int(seed),
    "manifest": inp,
    "injekcia": {"subor": inp.get("injekcia", {}).get("subor"),
                 "sha256_merane": inj_sha,
                 "args": inp.get("injekcia", {}).get("args", [])},
    "vystupy": {
        "snimky_adresar": os.path.join("data", "raw", stamp + "_session"),
        "snimok": int(n_sidecars),
        "collect_tail": collect_tail,
        "tcpdump": os.path.exists(os.path.join(sess, "tcpdump.pcap")),
        "ground_truth": {n: sha(os.path.join(sess, n)) for n in
                         ("ps_before.txt", "ps_after.txt", "lsmod_before.txt",
                          "lsmod_after.txt", "ss_before.txt", "ss_after.txt",
                          "boot_id_before.txt", "payload.log",
                          "collect.log", "apt.log")},
    },
    "priebeh": ["(zaznamy priebehu generuje session.sh - zhodny pre oba typy)"],
}
with open(os.path.join(sess, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
    f.write("\n")
print("manifest zapisany: %s/manifest.json" % sess)
PYEOF

# priebeh do manifestu (python hore pise samostatne; tu ho doplnime)
python3 - "$SESS" "$(printf '%s\n' "${priebeh[@]}" | jq -R -s -c 'split("\n")[:-1]')" <<'PYEOF'
import json, os, sys
sess, priebeh_json = sys.argv[1], sys.argv[2]
p = os.path.join(sess, "manifest.json")
d = json.load(open(p, encoding="utf-8"))
d["priebeh"] = json.loads(priebeh_json)
json.dump(d, open(p, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
open(p, "a", encoding="utf-8").write("\n")
PYEOF

# G3: oznacenie behu aktivny/neaktivny z pozemnej pravdy (payloadovy
# subor sa z dokazov vylucuje - vytvara ho injekcia, nie beh)
"$REPO/scripts/aktivita.sh" "$SESS" "$INJ_REMOTE" || true

give_back "$SESS" "$RAWDIR"

echo "session.sh: hotovo"
echo "  sedenie: $SESS"
echo "  snimky:  $RAWDIR ($N_SIDECARS sidecarov)"
echo "  zber:    $COLLECT_TAIL"
