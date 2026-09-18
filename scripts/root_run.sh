#!/usr/bin/env bash
#
# root_run.sh - jediny skript, ktory sa v tomto projekte spusta pod rootom.
#
# Preco jeden skript a nie sada prikazov: kazdy root beh je v praci udalost,
# ktoru treba vediet zopakovat a dolozit. Zabalenim do podprikazov sa dosiahne,
# ze sa merania nespustaju rucne poskladanymi prikazmi, a ze kazdy vystup nesie
# commit repozitara, datum, presny prikaz a verziu binarky.
#
# Root treba iba na samotny zber (eBPF nad KVM vyzaduje CAP_BPF a CAP_PERFMON).
# Vsetko ostatne - libvirt session, guest agent, ssh - patri pouzivatelovi,
# preto sa tieto kroky spustaju spat pod $SUDO_USER.
#
#   root_run.sh probe       pripojenie k domene -> data/results/probe_<stamp>.json
#   root_run.sh validate    pozemna prava PRED -> plna snimka -> pozemna prava PO
#   root_run.sh once        jedna snimka
#   root_run.sh run         periodicky zber
#
# --dry-run vypise, co by sa spustilo, a skonci. Root pritom netreba.

set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || exit 1
BIN="$REPO/vmicollect/build/vmicollect"
GUEST_EXEC="$REPO/scripts/guest_exec.sh"

DOMAIN="${VMIC_DOMAIN:-hyptcn-guest}"
URI="${VMIC_LIBVIRT_URI:-qemu:///session}"
DRY=0
SUB=""

# parametre podprikazov
INTERVAL="5.0"
CYCLES="6"
WRITER="delta"
HASH="sha256"
OUTDIR=""
GMODE="auto"
FULL_EVERY=""

TMPD=""
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS="$REPO/data/results"
SESSIONS="$REPO/data/sessions"
RAWDIR="$REPO/data/raw"

usage()
{
    cat <<'EOF'
POUZITIE
  root_run.sh [globalne] <podprikaz> [prepinace podprikazu]

PODPRIKAZY
  probe      pripoj sa k domene a zapis, co vidno (memsloty, RAM, vCPU)
             -> data/results/probe_<stamp>.json
  validate   pozemna prava PRED (ps, lsmod, ss) -> jedna plna delta snimka ->
             pozemna prava PO
             -> data/sessions/<stamp>_validate/
  once       jedna snimka
             -> data/raw/<stamp>_once/ + data/results/once_<stamp>.json
  run        periodicky zber
             -> data/raw/<stamp>_run/ + data/results/run_<stamp>.json

GLOBALNE
  -d, --domain NAZOV     libvirt domena (vychodzie: hyptcn-guest)
  -c, --connect URI      libvirt URI (vychodzie: qemu:///session)
  -n, --dry-run          vypis plan a skonci (root netreba)
  -h, --help             tato napoveda

PREPINACE PODPRIKAZOV
  once, run:
    -w, --writer raw|delta     vychodzie: delta
    -i, --interval S           perioda v sekundach (run, vychodzie: 5.0)
    -N, --cycles N             pocet cyklov (run, vychodzie: 6)
    -H, --hash sha256|none     vychodzie: sha256
    -F, --full-every N         delta: kazda N-ta snimka je plna
    -o, --out DIR              vlastny adresar na snimky
  validate:
    -m, --mode ssh|agent|auto  cesta do hosta pre pozemnu pravdu (vychodzie: auto)
    -H, --hash sha256|none     vychodzie: sha256

PRIKLADY
  sudo -A scripts/root_run.sh probe
  sudo -A scripts/root_run.sh validate
  sudo -A scripts/root_run.sh run -i 2 -N 60 -w delta
  scripts/root_run.sh --dry-run run -i 2 -N 60
EOF
}

die()
{
    printf 'root_run.sh: %s\n' "$1" >&2
    exit "${2:-1}"
}

die_usage()
{
    printf 'root_run.sh: %s\n' "$1" >&2
    usage >&2
    exit 2
}

# ---------------------------------------------------------------- argumenty

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--domain)  [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; DOMAIN="$2"; shift 2 ;;
        -c|--connect) [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; URI="$2";    shift 2 ;;
        -n|--dry-run) DRY=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; break ;;
        -*)           die_usage "neznamy globalny prepinac $1" ;;
        *)            break ;;
    esac
done

[ $# -ge 1 ] || die_usage "chyba podprikaz"
SUB="$1"; shift

case "$SUB" in
    probe|validate|once|run) ;;
    *) die_usage "neznamy podprikaz '$SUB'" ;;
esac

while [ $# -gt 0 ]; do
    case "$1" in
        -w|--writer)     [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; WRITER="$2";     shift 2 ;;
        -i|--interval)   [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; INTERVAL="$2";   shift 2 ;;
        -N|--cycles)     [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; CYCLES="$2";     shift 2 ;;
        -H|--hash)       [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; HASH="$2";       shift 2 ;;
        -F|--full-every) [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; FULL_EVERY="$2"; shift 2 ;;
        -o|--out)        [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; OUTDIR="$2";     shift 2 ;;
        -m|--mode)       [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; GMODE="$2";      shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        *)               die_usage "neznamy prepinac podprikazu $SUB: $1" ;;
    esac
done

case "$WRITER" in raw|delta) ;; *) die_usage "writer musi byt raw alebo delta" ;; esac
case "$HASH"   in sha256|none) ;; *) die_usage "hash musi byt sha256 alebo none" ;; esac

# ---------------------------------------------------------------- pomocnicky

# Docasne subory drzia stdout/stderr zberaca, kym sa z nich neposklada JSON.
# Jeden adresar a jeden EXIT trap preto, aby sa upratali aj vtedy, ked skript
# skonci cez die().
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/root_run.XXXXXX") || { echo "root_run.sh: mktemp zlyhal" >&2; exit 1; }
trap 'rm -rf "$TMPD"' EXIT

# Libvirt bezi v session rezime pod uctom pouzivatela, takze pod rootom by
# virsh hladal domenu na qemu:///system a nenasiel by ju. Preto sa vracia spat.
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

# Vystupy vytvorene rootom by boli pre dalsie kroky (parser, trening, git)
# necitatelne na zapis - kazdy vytvoreny adresar preto vratime pouzivatelovi.
give_back()
{
    local target="$1" owner
    [ -e "$target" ] || return 0
    [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] || return 0
    owner="${SUDO_UID:-$(id -u "$SUDO_USER")}:${SUDO_GID:-$(id -g "$SUDO_USER")}"
    chown -R "$owner" "$target" || return 1
    return 0
}

# Rodicovske adresare (data/, data/results/, ...) mohol vyrobit tento beh, ale
# mozu v nich lezat vystupy inych krokov - preto sa menia nerekurzivne.
give_back_parents()
{
    local d owner
    [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] || return 0
    owner="${SUDO_UID:-$(id -u "$SUDO_USER")}:${SUDO_GID:-$(id -g "$SUDO_USER")}"
    for d in "$@"; do
        [ -d "$d" ] && chown "$owner" "$d"
    done
    return 0
}

repo_commit()
{
    git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD 2>/dev/null || printf 'unknown'
}

repo_dirty()
{
    local out
    out=$(git -c safe.directory="$REPO" -C "$REPO" status --porcelain 2>/dev/null)
    [ -n "$out" ] && printf 'true' || printf 'false'
}

bin_version()
{
    "$BIN" --version 2>/dev/null | head -1 || printf 'unknown'
}

bin_sha()
{
    sha256sum "$BIN" 2>/dev/null | cut -d' ' -f1 || printf 'unknown'
}

domain_state()
{
    as_user virsh --connect "$URI" domstate "$DOMAIN" 2>&1 | head -1
}

# Preflight sa robi aj pri --dry-run: zmysel dry-runu je zistit, ci by beh
# presiel, nie iba vypisat text.
preflight()
{
    local st
    if [ ! -x "$BIN" ]; then
        die "binarka $BIN neexistuje - spusti 'make -C $REPO/vmicollect'"
    fi
    for tool in jq virsh git sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || die "chyba nastroj $tool"
    done
    [ -x "$GUEST_EXEC" ] || die "chyba $GUEST_EXEC"

    st=$(domain_state)
    if [ "$st" != "running" ]; then
        printf 'root_run.sh: domena %s nebezi (virsh domstate na %s hlasi: %s)\n' \
               "$DOMAIN" "$URI" "$st" >&2
        printf '            zber pamate sa bez beziacej domeny spustit neda.\n' >&2
        printf "            spusti ju:  virsh --connect %s start %s\n" "$URI" "$DOMAIN" >&2
        exit 1
    fi
}

require_root()
{
    [ "$(id -u)" -eq 0 ] || die "podprikaz '$SUB' potrebuje root - spusti ho cez sudo (alebo pouzi --dry-run)"
}

host_json()
{
    jq -n --arg hostname "$(hostname)" \
          --arg kernel "$(uname -r)" \
          --arg cpus "$(nproc)" \
          '{hostname:$hostname,kernel:$kernel,cpus:($cpus|tonumber)}'
}

# Spolocna hlavicka kazdeho vystupneho JSONu. Bez nej sa cislo v texte prace
# neda spatne priradit k behu, ktory ho vyrobil.
meta_json()
{
    local command="$1"
    jq -n --arg schema "hyptcn3/$SUB/1" \
          --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          --argjson date_unix "$(date +%s)" \
          --arg commit "$(repo_commit)" \
          --argjson commit_dirty "$(repo_dirty)" \
          --arg domain "$DOMAIN" \
          --arg uri "$URI" \
          --arg command "$command" \
          --arg bin_path "$BIN" \
          --arg bin_version "$(bin_version)" \
          --arg bin_sha256 "$(bin_sha)" \
          --argjson host "$(host_json)" \
          '{schema:$schema,date:$date,date_unix:$date_unix,
            commit:$commit,commit_dirty:$commit_dirty,
            domain:$domain,libvirt_uri:$uri,
            command:$command,
            binary:{path:$bin_path,version:$bin_version,sha256:$bin_sha256},
            host:$host}'
}

guest_env_json()
{
    local kern uptime
    kern=$("$GUEST_EXEC" -m "$GMODE" -d "$DOMAIN" -c "$URI" 'uname -r' </dev/null 2>/dev/null)
    uptime=$("$GUEST_EXEC" -m "$GMODE" -d "$DOMAIN" -c "$URI" 'cat /proc/uptime' </dev/null 2>/dev/null)
    jq -n --arg kernel "${kern:-unknown}" --arg uptime "${uptime:-unknown}" \
          '{kernel:$kernel,proc_uptime:$uptime}'
}

# ---------------------------------------------------------------- probe

# Riadok so slotmi vypisuje backend az na urovni DEBUG (probe -v). Sucet
# velkosti slotov je jediny presny udaj o velkosti RAM, ktory probe dava -
# riadok "velkost RAM" je zaokruhleny na dve desatinne miesta.
slots_json()
{
    local f="$1" id base end hva flags first=1
    printf '['
    while read -r id base end hva flags; do
        [ "$first" -eq 1 ] || printf ','
        first=0
        printf '{"id":%d,"gpa_start":%d,"gpa_end":%d,"size_bytes":%d,"hva":%d,"flags":%d}' \
            "$id" "$((16#$base))" "$((16#$end))" "$(( 16#$end - 16#$base + 1 ))" \
            "$((16#$hva))" "$((16#$flags))"
    done < <(sed -nE 's/.*slot +([0-9]+): GPA 0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+) +HVA 0x([0-9a-fA-F]+) +flags 0x([0-9a-fA-F]+).*/\1 \2 \3 \4 \5/p' "$f")
    printf ']'
}

field_after_colon()
{
    sed -nE "s/^$1 *: *//p" "$2" | head -1
}

do_probe()
{
    local cmd outf errf rc slots memslots ram_human maxp_hex vcpus vmid backend
    local rt_bytes rt_ms rt_mibs values

    mkdir -p "$RESULTS" || die "neviem vytvorit $RESULTS"
    outf="$TMPD/probe.out"; errf="$TMPD/probe.err"

    cmd="$BIN probe -v -o vm.domain=$DOMAIN"
    printf '>> %s\n' "$cmd" >&2
    "$BIN" probe -v -o "vm.domain=$DOMAIN" >"$outf" 2>"$errf"
    rc=$?
    cat "$errf" >&2
    cat "$outf"

    slots=$(slots_json "$errf")
    memslots=$(sed -nE 's/.*: ([0-9]+) memslotov.*/\1/p' "$errf" | head -1)
    ram_human=$(field_after_colon "velkost RAM" "$outf")
    maxp_hex=$(sed -nE 's/.*max\. fyz\. adresa *: .*\(0x([0-9a-fA-F]+)\).*/\1/p' "$outf" | head -1)
    vcpus=$(field_after_colon "pocet vCPU" "$outf")
    vmid=$(field_after_colon "id domeny" "$outf")
    backend=$(field_after_colon "backend" "$outf")
    rt_bytes=$(sed -nE 's/.*test citania *: ([0-9]+) B za .*/\1/p' "$outf" | head -1)
    rt_ms=$(sed -nE 's/.*test citania *: [0-9]+ B za ([0-9.]+) ms.*/\1/p' "$outf" | head -1)
    rt_mibs=$(sed -nE 's/.*test citania *: .*= ([0-9.]+) MiB\/s.*/\1/p' "$outf" | head -1)

    values=$(jq -n \
        --argjson slots "${slots:-[]}" \
        --arg memslots "${memslots:-}" \
        --arg ram_human "${ram_human:-}" \
        --arg maxp_hex "${maxp_hex:-}" \
        --arg vcpus "${vcpus:-}" \
        --arg vmid "${vmid:-}" \
        --arg backend "${backend:-}" \
        --arg rt_bytes "${rt_bytes:-}" \
        --arg rt_ms "${rt_ms:-}" \
        --arg rt_mibs "${rt_mibs:-}" \
        'def num($s): if $s=="" then null else ($s|tonumber) end;
         {memslots: num($memslots),
          ram_bytes: (if ($slots|length)>0 then ([$slots[].size_bytes]|add) else null end),
          ram_human: (if $ram_human=="" then null else $ram_human end),
          max_paddr: (if $maxp_hex=="" then null
                      else ($maxp_hex|ascii_downcase|explode
                            |reduce .[] as $c (0; .*16 + (if $c>=97 then $c-87 else $c-48 end))) end),
          vcpus: num($vcpus),
          vmid: num($vmid),
          backend: (if $backend=="" then null else $backend end),
          read_test:{bytes:num($rt_bytes),ms:num($rt_ms),mib_s:num($rt_mibs)},
          memslot_ranges:$slots}')

    local out="$RESULTS/probe_$STAMP.json"
    meta_json "$cmd" \
        | jq --argjson exit_code "$rc" \
             --argjson values "$values" \
             --rawfile stdout "$outf" \
             --rawfile stderr "$errf" \
             '. + {exit_code:$exit_code, values:$values,
                   stdout:$stdout, stderr:$stderr}' >"$out" || die "zapis $out zlyhal"
    [ -s "$out" ] || die "$out vysiel prazdny - JSON sa neposkladal"

    give_back "$out"
    give_back_parents "$REPO/data" "$RESULTS"
    printf '\nzapisane: %s\n' "$out" >&2
    return "$rc"
}

# ---------------------------------------------------------------- once / run

# Zo zaverecneho riadku 'koniec: ...' sa daju vytiahnut cisla, ktore sa inak
# nikde neuklada: pocet zmeskanych slotov a najvacsie meskanie.
summary_json()
{
    local errf="$1" line
    line=$(grep -oE 'koniec: [0-9]+ snimok, [0-9]+ chyb, [0-9]+ zmeskanych slotov, najvacsie meskanie [0-9.]+ s' "$errf" | tail -1)
    if [ -z "$line" ]; then printf 'null'; return; fi
    printf '%s' "$line" | sed -nE 's/koniec: ([0-9]+) snimok, ([0-9]+) chyb, ([0-9]+) zmeskanych slotov, najvacsie meskanie ([0-9.]+) s/{"cycles_done":\1,"cycles_failed":\2,"cycles_skipped":\3,"worst_lateness_s":\4}/p'
}

# Zoznam prepinacov zberaca sa stavia na JEDNOM mieste. Vypis do JSONu ("presny
# prikaz") aj samotne spustenie potom nemozu rozist - a prave rozidenie by
# znamenalo, ze v dokladoch je iny prikaz, nez sa naozaj spustil.
OPTS=()
build_opts()
{
    local mode="$1" dir="$2"
    OPTS=(-o "vm.domain=$DOMAIN" -o "output.writer=$WRITER"
          -o "output.hash=$HASH" -o "output.dir=$dir")
    [ -n "$FULL_EVERY" ] && OPTS+=(-o "output.delta_full_every=$FULL_EVERY")
    if [ "$mode" = "run" ]; then
        OPTS+=(-o "schedule.interval_s=$INTERVAL" -o "schedule.max_cycles=$CYCLES")
    fi
    return 0
}

run_collect()
{
    local mode="$1" dir="$2" outf="$3" errf="$4"
    build_opts "$mode" "$dir"
    "$BIN" "$mode" "${OPTS[@]}" >"$outf" 2>"$errf"
}

describe_collect()
{
    local mode="$1" dir="$2"
    build_opts "$mode" "$dir"
    printf '%s %s %s' "$BIN" "$mode" "${OPTS[*]}"
}

do_collect()
{
    local mode="$1" dir cmd outf errf rc out
    dir="${OUTDIR:-$RAWDIR/${STAMP}_$mode}"
    mkdir -p "$dir" "$RESULTS" || die "neviem vytvorit $dir"
    outf="$TMPD/$mode.out"; errf="$TMPD/$mode.err"

    cmd=$(describe_collect "$mode" "$dir")
    printf '>> %s\n' "$cmd" >&2
    run_collect "$mode" "$dir" "$outf" "$errf"
    rc=$?
    cat "$errf" >&2
    cat "$outf"

    out="$RESULTS/${mode}_$STAMP.json"
    meta_json "$cmd" \
        | jq --argjson exit_code "$rc" \
             --arg dir "$dir" \
             --argjson summary "$(summary_json "$errf")" \
             --argjson params "$(jq -n --arg w "$WRITER" --arg h "$HASH" \
                                       --arg i "$INTERVAL" --arg n "$CYCLES" \
                                       --arg f "${FULL_EVERY:-}" \
                                 '{writer:$w,hash:$h,
                                   interval_s:($i|tonumber),max_cycles:($n|tonumber),
                                   delta_full_every:(if $f=="" then null else ($f|tonumber) end)}')" \
             --rawfile stdout "$outf" \
             --rawfile stderr "$errf" \
             '. + {exit_code:$exit_code, snapshot_dir:$dir, params:$params,
                   summary:$summary, stdout:$stdout, stderr:$stderr}' >"$out" \
        || die "zapis $out zlyhal"
    [ -s "$out" ] || die "$out vysiel prazdny - JSON sa neposkladal"

    give_back "$dir"
    give_back "$out"
    give_back_parents "$REPO/data" "$RESULTS" "$RAWDIR"
    printf '\nsnimky: %s\nzapisane: %s\n' "$dir" "$out" >&2
    return "$rc"
}

# ---------------------------------------------------------------- validate

# Pozemna prava sa berie PRED aj PO snimke. Snimka je ziva (VM sa nezastavuje),
# takze porovnavat sa smie iba to, co bolo v hostovi pritomne v oboch behoch -
# prienik urobi az parser, tu sa iba poctivo ulozia obe strany.
GT_FAILED=0
grab_gt()
{
    local when="$1" dir="$2" name cmd rc
    while IFS='|' read -r name cmd; do
        [ -z "$name" ] && continue
        "$GUEST_EXEC" -m "$GMODE" -d "$DOMAIN" -c "$URI" "$cmd" </dev/null \
            >"$dir/${name}_${when}.txt" 2>"$dir/${name}_${when}.err"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            printf 'root_run.sh: pozemna prava %s (%s) skoncila s kodom %d\n' \
                   "$name" "$when" "$rc" >&2
            GT_FAILED=$(( GT_FAILED + 1 ))
        fi
        [ -s "$dir/${name}_${when}.err" ] || rm -f "$dir/${name}_${when}.err"
    done <<'EOF'
ps|ps -eo pid,comm --no-headers
ps_full|ps -eo pid,ppid,user,comm,args --no-headers
lsmod|lsmod
ss|ss -tuanp
ss_listen|ss -tulpn
EOF
}

do_validate()
{
    local dir snapdir cmd outf errf rc out t0 t1 t2 t3 t4
    dir="${OUTDIR:-$SESSIONS/${STAMP}_validate}"
    snapdir="$dir/snap"
    mkdir -p "$snapdir" || die "neviem vytvorit $snapdir"
    outf="$TMPD/validate.out"; errf="$TMPD/validate.err"

    t0=$(date +%s.%N)
    printf '>> pozemna prava PRED (cesta %s)\n' "$GMODE" >&2
    grab_gt before "$dir"
    t1=$(date +%s.%N)

    local save_writer="$WRITER"
    WRITER="delta"
    cmd=$(describe_collect once "$snapdir")
    printf '>> %s\n' "$cmd" >&2
    t2=$(date +%s.%N)
    run_collect once "$snapdir" "$outf" "$errf"
    rc=$?
    t3=$(date +%s.%N)
    cat "$errf" >&2
    cat "$outf"
    WRITER="$save_writer"

    printf '>> pozemna prava PO\n' >&2
    grab_gt after "$dir"
    t4=$(date +%s.%N)

    out="$dir/validate.json"
    meta_json "$cmd" \
        | jq --argjson exit_code "$rc" \
             --arg dir "$dir" \
             --arg snapdir "$snapdir" \
             --argjson gt_failed "$GT_FAILED" \
             --arg guest_mode "$GMODE" \
             --argjson guest "$(guest_env_json)" \
             --argjson timing "$(jq -n --arg a "$t0" --arg b "$t1" --arg c "$t2" \
                                       --arg d "$t3" --arg e "$t4" \
                                 '{gt_before_start:($a|tonumber),gt_before_end:($b|tonumber),
                                   snapshot_start:($c|tonumber),snapshot_end:($d|tonumber),
                                   gt_after_end:($e|tonumber),
                                   gt_before_s:(($b|tonumber)-($a|tonumber)),
                                   snapshot_s:(($d|tonumber)-($c|tonumber)),
                                   gt_after_s:(($e|tonumber)-($d|tonumber)),
                                   total_s:(($e|tonumber)-($a|tonumber))}')" \
             --rawfile stdout "$outf" \
             --rawfile stderr "$errf" \
             '. + {exit_code:$exit_code, session_dir:$dir, snapshot_dir:$snapdir,
                   guest_exec_mode:$guest_mode, guest:$guest,
                   ground_truth:{before:["ps_before.txt","ps_full_before.txt","lsmod_before.txt","ss_before.txt","ss_listen_before.txt"],
                                 after:["ps_after.txt","ps_full_after.txt","lsmod_after.txt","ss_after.txt","ss_listen_after.txt"],
                                 failed_commands:$gt_failed},
                   timing:$timing, stdout:$stdout, stderr:$stderr}' >"$out" \
        || die "zapis $out zlyhal"
    [ -s "$out" ] || die "$out vysiel prazdny - JSON sa neposkladal"

    ( cd "$dir" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
        | xargs -0 sha256sum >SHA256SUMS ) 2>/dev/null

    give_back "$dir"
    give_back_parents "$REPO/data" "$SESSIONS"
    printf '\nsession: %s\nzapisane: %s\n' "$dir" "$out" >&2
    [ "$GT_FAILED" -eq 0 ] || printf 'POZOR: %d prikazov pozemnej pravdy zlyhalo\n' "$GT_FAILED" >&2
    return "$rc"
}

# ---------------------------------------------------------------- dry-run

do_dry()
{
    local dir save_writer
    printf 'PLAN (--dry-run, nic sa nespusta)\n\n'
    printf '  repozitar    : %s\n' "$REPO"
    printf '  commit       : %s (dirty: %s)\n' "$(repo_commit)" "$(repo_dirty)"
    printf '  binarka      : %s (%s)\n' "$BIN" "$(bin_version)"
    printf '  domena       : %s na %s, stav: %s\n' "$DOMAIN" "$URI" "$(domain_state)"
    printf '  podprikaz    : %s\n' "$SUB"
    printf '  stamp        : %s\n\n' "$STAMP"
    case "$SUB" in
        probe)
            printf '  spustilo by sa:\n    %s probe -v -o vm.domain=%s\n' "$BIN" "$DOMAIN"
            printf '  vystup:\n    %s/probe_%s.json\n' "$RESULTS" "$STAMP"
            ;;
        once|run)
            dir="${OUTDIR:-$RAWDIR/${STAMP}_$SUB}"
            printf '  spustilo by sa:\n    %s\n' "$(describe_collect "$SUB" "$dir")"
            printf '  vystup:\n    %s/  (snimky + sidecary)\n    %s/%s_%s.json\n' \
                   "$dir" "$RESULTS" "$SUB" "$STAMP"
            ;;
        validate)
            dir="${OUTDIR:-$SESSIONS/${STAMP}_validate}"
            printf '  spustilo by sa (cesta do hosta: %s):\n' "$GMODE"
            printf '    1) v hostovi: ps -eo pid,comm | ps -eo pid,ppid,user,comm,args | lsmod | ss -tuanp | ss -tulpn   -> *_before.txt\n'
            # validate zbiera vzdy delta writerom, nech je -w akekolvek
            save_writer="$WRITER"; WRITER="delta"
            printf '    2) %s\n' "$(describe_collect once "$dir/snap")"
            WRITER="$save_writer"
            printf '    3) to iste co 1) -> *_after.txt\n'
            printf '  vystup:\n    %s/  (pozemna prava, snap/, validate.json, SHA256SUMS)\n' "$dir"
            ;;
    esac
    printf '\n  vystupy by sa nakoniec prepisali na vlastnika %s\n' "${SUDO_USER:-$(id -un)}"
}

# ---------------------------------------------------------------- hlavne telo

preflight

if [ "$DRY" -eq 1 ]; then
    do_dry
    exit 0
fi

require_root

case "$SUB" in
    probe)    do_probe ;;
    validate) do_validate ;;
    once)     do_collect once ;;
    run)      do_collect run ;;
esac
exit $?
