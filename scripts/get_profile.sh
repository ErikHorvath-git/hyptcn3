#!/usr/bin/env bash
#
# get_profile.sh - ziska profil jadra hosta (kallsyms + BTF) do profiles/<distro>-<uname -r>/
#
# Profil je jednorazova vstupna zavislost parsera: adresy symbolov a offsety
# poli struktur toho jadra, ktore v hostovi naozaj bezi. Ziskava sa Z HOSTA
# (ssh alebo qemu-guest-agent), rovnako ako profil pri LibVMI alebo Volatility.
# Nie je to sucast zberu - zber sam ziadny pristup do hosta nepotrebuje.
#
# BTF sa z hosta berie binarne (/sys/kernel/btf/vmlinux) a do citatelneho vypisu
# sa preklada az na hostitelovi: host (Debian 12 cloud image) bpftool nema,
# hostitel ano. Do hosta sa teda nic neinstaluje.
#
# Skript nepotrebuje root na hostitelovi. V hostovi potrebuje ucet, ktory vidi
# nezamaskovane adresy v /proc/kallsyms (root alebo kernel.kptr_restrict=0) -
# inak su vsetky adresy nulove a profil je na nic; skript to kontroluje.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SELF_DIR/.." && pwd)"

OUT_ROOT="$REPO_DIR/profiles"
LIBVIRT_URI="qemu:///session"
TRANSPORT=""
FORCE=0

# Symboly, bez ktorych parser (guestparse) neurobi ani prvy krok. Zoznam je
# zaroven kontrolou, ze kallsyms nie je zamaskovany alebo z ineho jadra.
KEY_SYMS=(
    linux_banner        # kotva pre urcenie posunu obrazu jadra (KASLR)
    init_task           # zaciatok zoznamu procesov a kontrola posunu (comm == swapper/0)
    modules             # hlavicka zoznamu nacitanych modulov
    page_offset_base    # zaciatok priameho mapovania (cita sa z pamate, adresa je odtialto)
    init_top_pgt        # koren tabuliek stranok jadra pre oblasti mimo linearnych vetiev
    socket_file_ops     # rozpoznanie deskriptora, ktory je socket
    tcp_prot            # protokol socketu podla skc_prot, nie podla hadania
    udp_prot
    tcpv6_prot          # to iste pre IPv6, inak sa protokol reportuje ako "?"
    udpv6_prot
    _stext              # hranice textu jadra pre kontrolu sys_call_table
    _etext
    sys_call_table      # tabulka, ktorej integrita sa kontroluje
)

usage()
{
    cat <<'EOF'
Pouzitie: scripts/get_profile.sh [prepinace] <ssh-ciel | libvirt-domena>

  <ssh-ciel>        napr. root@192.168.122.100  (prenos ssh)
  <libvirt-domena>  napr. hyptcn-guest          (prenos qemu-guest-agent)

Prepinace:
  -t ssh|agent   vynuti prenos (inak sa urci z tvaru argumentu)
  -o ADRESAR     korenovy adresar profilov (vychodzi: <repo>/profiles)
  -c URI         libvirt URI pre prenos agent (vychodzie: qemu:///session)
  -f             prepise uz existujuci profil
  -h             tento vypis

Vystup: <ADRESAR>/<distro><verzia>-<uname -r>/{kallsyms.txt,btf.raw,btf.txt,README.md}
EOF
}

die() { echo "get_profile: $*" >&2; exit 1; }

# ------------------------------------------------------------------ prepinace

while getopts "t:o:c:fh" opt; do
    case "$opt" in
    t) TRANSPORT="$OPTARG" ;;
    o) OUT_ROOT="$OPTARG" ;;
    c) LIBVIRT_URI="$OPTARG" ;;
    f) FORCE=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || { usage >&2; exit 2; }
TARGET="$1"

command -v bpftool >/dev/null || die "na hostitelovi chyba bpftool (vypis BTF sa robi tu, nie v hostovi)"

# ------------------------------------------------------------------ prenos

# Urcenie prenosu: 'user@host' je jednoznacne ssh, meno existujucej domeny je
# jednoznacne agent. Ked to nie je ani jedno, skusi sa ssh - ssh si meno vie
# rozlozit cez ~/.ssh/config, co skript nedokaze.
detect_transport()
{
    if [ -n "$TRANSPORT" ]; then echo "$TRANSPORT"; return; fi
    case "$TARGET" in
    *@*) echo ssh; return ;;
    esac
    if command -v virsh >/dev/null && virsh --connect "$LIBVIRT_URI" domid "$TARGET" >/dev/null 2>&1; then
        echo agent
    else
        echo ssh
    fi
}

# Pomocnik pre qemu-guest-agent. virsh sam subory neprenasa, takze sa skladaju
# z volani guest-file-read; 1 MiB na davku, aby base64 odpoved presla cez QMP.
GA_PY='
import base64, json, subprocess, sys, time

uri, dom, mode = sys.argv[1], sys.argv[2], sys.argv[3]

def qmp(req):
    p = subprocess.run(["virsh", "--connect", uri, "qemu-agent-command", dom,
                        json.dumps(req)], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("qemu-agent-command zlyhal: " + p.stderr.strip())
    return json.loads(p.stdout)["return"]

def run(cmd):
    pid = qmp({"execute": "guest-exec",
               "arguments": {"path": "/bin/sh", "arg": ["-c", cmd],
                             "capture-output": True}})["pid"]
    for _ in range(120):
        st = qmp({"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if st.get("exited"):
            if st.get("exitcode", 0) != 0:
                sys.stderr.write(base64.b64decode(st.get("err-data", "")).decode("utf8", "replace"))
                sys.exit("guest-exec: rc=%s" % st.get("exitcode"))
            return base64.b64decode(st.get("out-data", "")).decode("utf8", "replace")
        time.sleep(0.5)
    sys.exit("guest-exec: timeout")

if mode == "exec":
    sys.stdout.write(run(sys.argv[4]))
elif mode == "get":
    remote, local = sys.argv[4], sys.argv[5]
    h = qmp({"execute": "guest-file-open", "arguments": {"path": remote, "mode": "rb"}})
    try:
        with open(local, "wb") as out:
            while True:
                r = qmp({"execute": "guest-file-read",
                         "arguments": {"handle": h, "count": 1048576}})
                buf = base64.b64decode(r.get("buf-b64", ""))
                out.write(buf)
                if r.get("eof") or not buf:
                    break
    finally:
        qmp({"execute": "guest-file-close", "arguments": {"handle": h}})
else:
    sys.exit("neznamy rezim: " + mode)
'

ga() { python3 -c "$GA_PY" "$LIBVIRT_URI" "$TARGET" "$@"; }

guest_exec()
{
    case "$MODE" in
    ssh)   ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" "$1" ;;
    agent) ga exec "$1" ;;
    esac
}

# Subor sa berie tak, ako je - /proc/kallsyms aj /sys/kernel/btf/vmlinux hlasia
# nulovu velkost, takze 'scp' na ne nesadne a cita sa prudom.
guest_get()
{
    case "$MODE" in
    ssh)   ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" "cat $1" > "$2" ;;
    agent) ga get "$1" "$2" ;;
    esac
}

MODE="$(detect_transport)"
case "$MODE" in ssh|agent) ;; *) die "neznamy prenos '$MODE'" ;; esac

# ------------------------------------------------------------------ identifikacia hosta

echo "get_profile: ciel '$TARGET', prenos $MODE"

IDENT="$(guest_exec '. /etc/os-release; echo "$ID"; echo "$VERSION_ID"; uname -r; uname -m')" \
    || die "host neodpovedal"
GUEST_ID="$(echo "$IDENT"    | sed -n 1p | tr -d '\r')"
GUEST_VER="$(echo "$IDENT"   | sed -n 2p | tr -d '\r')"
GUEST_REL="$(echo "$IDENT"   | sed -n 3p | tr -d '\r')"
GUEST_ARCH="$(echo "$IDENT"  | sed -n 4p | tr -d '\r')"
[ -n "$GUEST_REL" ] || die "nepodarilo sa zistit verziu jadra hosta"

NAME="${GUEST_ID}${GUEST_VER}-${GUEST_REL}"
OUT="$OUT_ROOT/$NAME"
if [ -e "$OUT" ] && [ "$FORCE" -eq 0 ]; then
    die "profil '$OUT' uz existuje (prepis prepinacom -f)"
fi
mkdir -p "$OUT"

DATE_ISO="$(date -Iseconds)"
HOST_KERNEL="$(uname -r)"
BPFTOOL_VER="$(bpftool version 2>&1 | head -1)"

# ------------------------------------------------------------------ zber

echo "get_profile: /proc/kallsyms -> $OUT/kallsyms.txt"
guest_get /proc/kallsyms "$OUT/kallsyms.txt"

echo "get_profile: /sys/kernel/btf/vmlinux -> $OUT/btf.raw"
guest_get /sys/kernel/btf/vmlinux "$OUT/btf.raw"

echo "get_profile: bpftool btf dump -> $OUT/btf.txt"
bpftool btf dump file "$OUT/btf.raw" format raw > "$OUT/btf.txt"

# ------------------------------------------------------------------ kontroly

# Bez tychto kontrol by vznikol profil, ktory vyzera spravne a parser s nim
# ticho vrati prazdny zoznam procesov.
STEXT_ADDR="$(awk '$3 == "_stext" { print $1; exit }' "$OUT/kallsyms.txt" || true)"
[ -n "$STEXT_ADDR" ] || die "v kallsyms nie je _stext - je to vobec /proc/kallsyms?"
if [ "$STEXT_ADDR" = "0000000000000000" ]; then
    die "adresy v kallsyms su nulove: ucet v hostovi nema pravo ich vidiet (kptr_restrict)"
fi

MISSING=""
for s in "${KEY_SYMS[@]}"; do
    awk -v s="$s" '$3 == s { found = 1; exit } END { exit !found }' "$OUT/kallsyms.txt" \
        || MISSING="$MISSING $s"
done
[ -z "$MISSING" ] || die "v kallsyms chybaju symboly:$MISSING"

for t in task_struct module socket sock_common file files_struct fdtable; do
    grep -q "STRUCT '$t'" "$OUT/btf.txt" || die "v BTF chyba struktura $t"
done

BANNER_VER="$(guest_exec 'cat /proc/version' | tr -d '\r')"
KALLSYMS_LINES="$(wc -l < "$OUT/kallsyms.txt")"
BTF_LINES="$(wc -l < "$OUT/btf.txt")"
BTF_BYTES="$(stat -c %s "$OUT/btf.raw")"

# ------------------------------------------------------------------ README

sym_addr() { awk -v s="$1" '$3 == s { print "0x" $1; exit }' "$OUT/kallsyms.txt"; }

{
    cat <<EOF
# Profil jadra hosťa: $GUEST_ID $GUEST_VER, $GUEST_REL ($GUEST_ARCH)

Tento adresár vygeneroval \`scripts/get_profile.sh\` dňa $DATE_ISO.

## Pôvod

| položka | hodnota |
|---|---|
| cieľ | \`$TARGET\` |
| prenos | $MODE |
| jadro hosťa | \`$GUEST_REL\` |
| \`/proc/version\` hosťa | \`$BANNER_VER\` |
| jadro hostiteľa | \`$HOST_KERNEL\` |
| bpftool na hostiteľovi | $BPFTOOL_VER |

Príkazy, ktorými súbory vznikli:

\`\`\`
EOF
    if [ "$MODE" = ssh ]; then
        cat <<EOF
ssh -o BatchMode=yes $TARGET cat /proc/kallsyms            > kallsyms.txt
ssh -o BatchMode=yes $TARGET cat /sys/kernel/btf/vmlinux   > btf.raw
EOF
    else
        cat <<EOF
virsh --connect $LIBVIRT_URI qemu-agent-command $TARGET \\
      '{"execute":"guest-file-open","arguments":{"path":"/proc/kallsyms","mode":"rb"}}'
# ... guest-file-read po 1 MiB dávkach, base64 dekódované do kallsyms.txt
# to isté pre /sys/kernel/btf/vmlinux -> btf.raw
EOF
    fi
    cat <<EOF
bpftool btf dump file btf.raw format raw                  > btf.txt
\`\`\`

## Súbory

| súbor | riadkov / bajtov | obsah |
|---|---|---|
| \`kallsyms.txt\` | $KALLSYMS_LINES riadkov | adresy symbolov bežiaceho jadra hosťa |
| \`btf.raw\` | $BTF_BYTES B | binárne BTF z \`/sys/kernel/btf/vmlinux\` |
| \`btf.txt\` | $BTF_LINES riadkov | výpis BTF, z neho parser číta offsety polí |

## Kľúčové symboly, ktoré parser číta

| symbol | adresa | na čo |
|---|---|---|
EOF
    cat <<EOF
| \`linux_banner\` | $(sym_addr linux_banner) | kotva pre určenie posunu obrazu jadra (KASLR) |
| \`init_task\` | $(sym_addr init_task) | začiatok zoznamu procesov, kontrola posunu (\`comm == swapper/0\`) |
| \`modules\` | $(sym_addr modules) | hlavička zoznamu načítaných modulov |
| \`page_offset_base\` | $(sym_addr page_offset_base) | odtiaľ sa číta začiatok priameho mapovania |
| \`init_top_pgt\` | $(sym_addr init_top_pgt) | koreň tabuliek stránok pre oblasti mimo lineárnych vetiev |
| \`socket_file_ops\` | $(sym_addr socket_file_ops) | rozpoznanie deskriptora, ktorý je socket |
| \`tcp_prot\` | $(sym_addr tcp_prot) | určenie protokolu podľa \`skc_prot\` |
| \`udp_prot\` | $(sym_addr udp_prot) | to isté pre UDP |
| \`tcpv6_prot\` | $(sym_addr tcpv6_prot) | to isté pre TCP nad IPv6 |
| \`udpv6_prot\` | $(sym_addr udpv6_prot) | to isté pre UDP nad IPv6 |
| \`_stext\` | $(sym_addr _stext) | dolná hranica textu jadra |
| \`_etext\` | $(sym_addr _etext) | horná hranica textu jadra |
| \`sys_call_table\` | $(sym_addr sys_call_table) | tabuľka, ktorej integrita sa kontroluje |

Adresy sú z jedného konkrétneho štartu jadra (KASLR ich pri každom štarte posunie).
Parser z nich používa iba rozdiely voči \`linux_banner\`, ktorý nájde v snímke.

## Poctivo o tom, čo to znamená

Profil je **jednorazová vstupná závislosť získaná z hosťa** – rovnako ako profil
pri LibVMI alebo Volatility. Nejde teda o rekonštrukciu „bez akejkoľvek znalosti
hosťa“: adresy symbolov a offsety polí pochádzajú z bežiaceho hosťa a boli
odobraté raz, mimo behu zberu. Samotný zber snímok ani parsovanie už do hosťa
nesiahajú.

## Čo sa stane po reštarte hosťa

- Reštart **toho istého jadra**: KASLR zvolí iný posun, absolútne adresy v
  \`kallsyms.txt\` prestanú sedieť s pamäťou. Parser posun dopočíta z polohy
  \`linux_banner\` v snímke, takže rozdiely medzi symbolmi zostávajú platné.
  Toto je vlastnosť kódu, nie zmeraný výsledok – po reštarte treba validáciu
  zopakovať.
- Reštart do **iného jadra** (napr. po \`unattended-upgrades\`): profil prestane
  sedieť úplne – iné adresy aj iné offsety polí. Treba spustiť
  \`scripts/get_profile.sh\` znova, vznikne nový adresár podľa novej verzie
  jadra a validácia sa musí zopakovať.
EOF
} > "$OUT/README.md"

echo "get_profile: hotovo -> $OUT"
ls -l "$OUT"
