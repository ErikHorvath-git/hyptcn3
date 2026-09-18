#!/usr/bin/env bash
#
# guest_exec.sh - spusti prikaz vnutri hosta (guest) a vrati stdout, stderr aj
# navratovy kod. Root nepotrebuje.
#
# Preco dve cesty a preco sa ta pomalsia nezahadzuje:
#   ssh    je rychlejsia, ale predpoklada siet v hostovi a beziaci sshd. Ked
#          sa v experimente hostovi vypne siet (alebo ju zhodi merany scenar),
#          pozemna prava sa uz neda odobrat.
#   agent  ide cez qemu-guest-agent po virtio-serial, teda cez hypervizor.
#          Je pomalsia (polling), ale funguje aj bez siete - a to je pre pracu
#          podstatne: host sa da ovladat z hostitela aj vtedy, ked je zo siete
#          nedosiahnutelny.
# Vychodzi rezim 'auto' skusi ssh a pri zlyhani spojenia prepne na agenta.
#
# Kontrakt (na tento sa spoliehaju volajuce skripty):
#   - stdout hosta ide na stdout, stderr hosta na stderr,
#   - navratovy kod skriptu = navratovy kod prikazu v hostovi,
#   - zlyhanie samotneho prenosu ma vyhradeny kod 125, aby sa nedalo zamenit
#     za neuspech prikazu v hostovi,
#   - stdin sa do hosta NEPREPOSIELA. Je to zamerne: bez toho by ssh precitalo
#     stdin volajuceho (napr. telo cyklu 'while read' alebo ruru, z ktorej ma
#     citat dalsi prikaz) a ticho by ho zhltlo.
#
# S --json sa vsetko vypise ako jeden JSON objekt na stdout (mode, command,
# exit_code, stdout, stderr) a navratovy kod skriptu je 0, ak prenos presiel.

set -uo pipefail

DOMAIN="${VMIC_DOMAIN:-hyptcn-guest}"
URI="${VMIC_LIBVIRT_URI:-qemu:///session}"
SSH_TARGET="${VMIC_SSH_TARGET:-root@192.168.122.100}"
MODE="auto"
TIMEOUT=60
JSON=0
SELFTEST=0

TRANSPORT_FAIL=125

usage()
{
    cat <<'EOF'
POUZITIE
  guest_exec.sh [prepinace] <prikaz...>
  guest_exec.sh --self-test

PREPINACE
  -m, --mode ssh|agent|auto   cesta do hosta (vychodzie: auto)
  -d, --domain NAZOV          libvirt domena (vychodzie: hyptcn-guest)
  -H, --ssh-target U@HOST     ciel pre ssh (vychodzie: root@192.168.122.100)
  -c, --connect URI           libvirt URI (vychodzie: qemu:///session)
  -t, --timeout S             limit na dokoncenie prikazu (vychodzie: 60)
  -j, --json                  vypis JSON namiesto surovych vystupov
  -s, --self-test             over obe cesty a vypis tabulku
  -h, --help                  tato napoveda

PREMENNE PROSTREDIA
  VMIC_DOMAIN, VMIC_LIBVIRT_URI, VMIC_SSH_TARGET

NAVRATOVE KODY
  0..124, 126..255   navratovy kod prikazu v hostovi
  125                prenos zlyhal (agent nereaguje, ssh nespoji, timeout)
  2                  chyba v pouziti skriptu

PRIKLADY
  guest_exec.sh uname -r
  guest_exec.sh -m agent 'ps -eo pid,comm --no-headers | wc -l'
  guest_exec.sh --json -- 'lsmod'
EOF
}

die_usage()
{
    printf 'guest_exec.sh: %s\n' "$1" >&2
    usage >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -m|--mode)        [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; MODE="$2";       shift 2 ;;
        -d|--domain)      [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; DOMAIN="$2";     shift 2 ;;
        -H|--ssh-target)  [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; SSH_TARGET="$2"; shift 2 ;;
        -c|--connect)     [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; URI="$2";        shift 2 ;;
        -t|--timeout)     [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; TIMEOUT="$2";    shift 2 ;;
        -j|--json)        JSON=1;     shift ;;
        -s|--self-test)   SELFTEST=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        --)               shift; break ;;
        -*)               die_usage "neznamy prepinac $1" ;;
        *)                break ;;
    esac
done

case "$MODE" in
    ssh|agent|auto) ;;
    *) die_usage "rezim musi byt ssh, agent alebo auto (dostal som '$MODE')" ;;
esac

for tool in jq base64 virsh; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'guest_exec.sh: chyba nastroj %s\n' "$tool" >&2
        exit "$TRANSPORT_FAIL"
    }
done

# Ked skript bezi pod sudo, libvirt session beziaca pod uctom pouzivatela ani
# jeho ssh kluc rootovi nepatria - obe cesty preto spustame spat pod povodnym
# pouzivatelom. Bez XDG_RUNTIME_DIR by virsh nenasiel socket session demona.
as_user()
{
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        local uid home
        uid=$(id -u "$SUDO_USER") || return "$TRANSPORT_FAIL"
        home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        runuser -u "$SUDO_USER" -- env "XDG_RUNTIME_DIR=/run/user/$uid" \
                "HOME=$home" "$@"
    else
        "$@"
    fi
}

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/guest_exec.XXXXXX") || exit "$TRANSPORT_FAIL"
trap 'rm -rf "$TMPD"' EXIT

OUTF="$TMPD/out"
ERRF="$TMPD/err"
TRANSPORT_ERR=""   # neprazdne = prenos zlyhal, obsah je dovod

virsh_agent()
{
    # jeden QMP prikaz agentovi; JSON je na stdin, aby sa nic necitovalo rucne
    as_user virsh --connect "$URI" qemu-agent-command "$DOMAIN" "$1" </dev/null
}

run_agent()
{
    local cmd="$1" req gpid status deadline exited rc sig
    : >"$OUTF"; : >"$ERRF"
    TRANSPORT_ERR=""

    req=$(jq -cn --arg cmd "$cmd" \
        '{execute:"guest-exec",arguments:{path:"/bin/sh",arg:["-c",$cmd],"capture-output":true}}')

    local start
    start=$(virsh_agent "$req" 2>"$TMPD/vfail")
    if [ $? -ne 0 ] || [ -z "$start" ]; then
        TRANSPORT_ERR="qemu-guest-agent neodpoveda: $(tr -d '\n' <"$TMPD/vfail")"
        return "$TRANSPORT_FAIL"
    fi
    gpid=$(printf '%s' "$start" | jq -r '.return.pid // empty')
    if [ -z "$gpid" ]; then
        TRANSPORT_ERR="agent nevratil pid: $start"
        return "$TRANSPORT_FAIL"
    fi

    # guest-exec je asynchronny - treba cakat na "exited":true, inak by sme
    # precitali prazdny vystup a vyhlasili ho za vysledok
    deadline=$(( $(date +%s) + TIMEOUT ))
    while :; do
        status=$(virsh_agent \
            "$(jq -cn --argjson p "$gpid" \
                '{execute:"guest-exec-status",arguments:{pid:$p}}')" 2>"$TMPD/vfail")
        if [ $? -ne 0 ] || [ -z "$status" ]; then
            TRANSPORT_ERR="guest-exec-status zlyhal: $(tr -d '\n' <"$TMPD/vfail")"
            return "$TRANSPORT_FAIL"
        fi
        exited=$(printf '%s' "$status" | jq -r '.return.exited // false')
        [ "$exited" = "true" ] && break
        if [ "$(date +%s)" -ge "$deadline" ]; then
            TRANSPORT_ERR="prikaz v hostovi neskoncil do ${TIMEOUT} s"
            return "$TRANSPORT_FAIL"
        fi
        sleep 0.2
    done

    printf '%s' "$status" | jq -r '.return."out-data" // ""' | base64 -d >"$OUTF" 2>/dev/null
    printf '%s' "$status" | jq -r '.return."err-data" // ""' | base64 -d >"$ERRF" 2>/dev/null

    rc=$(printf '%s' "$status" | jq -r '.return.exitcode // empty')
    if [ -z "$rc" ]; then
        # ked prikaz zabil signal, exitcode chyba - prelozime ho ako shell
        sig=$(printf '%s' "$status" | jq -r '.return.signal // empty')
        if [ -n "$sig" ]; then rc=$(( 128 + sig )); else rc=0; fi
    fi
    return "$rc"
}

run_ssh()
{
    local cmd="$1" rc
    : >"$OUTF"; : >"$ERRF"
    TRANSPORT_ERR=""

    # -n: ssh nesmie siahnut na stdin volajuceho (viz hlavicka)
    as_user ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
            -o StrictHostKeyChecking=accept-new \
            "$SSH_TARGET" "$cmd" >"$OUTF" 2>"$ERRF" </dev/null
    rc=$?
    # 255 je vyhradene pre chybu samotneho ssh, nie pre prikaz v hostovi
    if [ "$rc" -eq 255 ]; then
        TRANSPORT_ERR="ssh na $SSH_TARGET zlyhal: $(tr -d '\n' <"$ERRF")"
        return "$TRANSPORT_FAIL"
    fi
    return "$rc"
}

# Spusti prikaz podla rezimu. Nastavi USED_MODE a vrati navratovy kod prikazu.
USED_MODE=""
dispatch()
{
    local cmd="$1" rc
    case "$MODE" in
        ssh)
            USED_MODE="ssh"
            run_ssh "$cmd"; return $?
            ;;
        agent)
            USED_MODE="agent"
            run_agent "$cmd"; return $?
            ;;
        auto)
            USED_MODE="ssh"
            run_ssh "$cmd"; rc=$?
            if [ "$rc" -eq "$TRANSPORT_FAIL" ] && [ -n "$TRANSPORT_ERR" ]; then
                USED_MODE="agent"
                run_agent "$cmd"; rc=$?
            fi
            return "$rc"
            ;;
    esac
}

self_test()
{
    local ok=0 fail=0 m c rc
    printf '%-6s  %-40s  %-4s  %s\n' "cesta" "prikaz" "rc" "vystup"
    printf -- '---------------------------------------------------------------------------\n'
    for m in ssh agent; do
        for c in 'uname -r' 'ps -eo pid,comm --no-headers | wc -l'; do
            MODE="$m"
            dispatch "$c"; rc=$?
            printf '%-6s  %-40s  %-4s  %s\n' "$m" "$c" "$rc" \
                   "$(head -c 200 "$OUTF" | tr '\n' ' ')"
            if [ "$rc" -eq 0 ]; then
                ok=$(( ok + 1 ))
            else
                fail=$(( fail + 1 ))
                [ -n "$TRANSPORT_ERR" ] && printf '        dovod: %s\n' "$TRANSPORT_ERR"
            fi
        done
    done
    printf -- '---------------------------------------------------------------------------\n'
    printf 'domena %s, uri %s, ssh %s: %d ok, %d chyba\n' \
           "$DOMAIN" "$URI" "$SSH_TARGET" "$ok" "$fail"
    [ "$fail" -eq 0 ]
}

if [ "$SELFTEST" -eq 1 ]; then
    self_test
    exit $?
fi

[ $# -ge 1 ] || die_usage "chyba prikaz"
CMD="$*"

dispatch "$CMD"
RC=$?

if [ "$JSON" -eq 1 ]; then
    jq -n --arg mode "$USED_MODE" \
          --arg domain "$DOMAIN" \
          --arg command "$CMD" \
          --argjson exit_code "$RC" \
          --arg transport_error "$TRANSPORT_ERR" \
          --rawfile stdout "$OUTF" \
          --rawfile stderr "$ERRF" \
          '{mode:$mode,domain:$domain,command:$command,exit_code:$exit_code,
            transport_error:(if $transport_error=="" then null else $transport_error end),
            stdout:$stdout,stderr:$stderr}'
    [ -n "$TRANSPORT_ERR" ] && exit "$TRANSPORT_FAIL"
    exit 0
fi

cat "$OUTF"
cat "$ERRF" >&2
[ -n "$TRANSPORT_ERR" ] && printf 'guest_exec.sh: %s\n' "$TRANSPORT_ERR" >&2
exit "$RC"
