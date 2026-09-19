#!/usr/bin/env bash
#
# collect_corpus.sh - nazbiera korpus sedeni: v hostovi bezi scenar spravania,
# na hostitelovi sa pritom zbieraju snimky pamate.
#
# Jedno SEDENIE = jeden scenar zo scenarios/ + retazec snimok, ktore vznikli
# pocas jeho behu + labels.json s tym, co sa naozaj spustilo.
#
# PRECO SA PORADIE TRIED STRIEDA: keby sa najprv nazbierali vsetky sedenia
# triedy 'idle' a az potom 'cpu_burn', do dat by sa dostal cas ako confound -
# model by mohol rozlisovat "prve sedenia" od "neskorsich" (zahriata cache,
# obsadenost pamate hosta, rast uptime) namiesto spravania. Preto sa v kazdom
# kole prejdu vsetky triedy a poradie tried sa v kazdom kole pootoci.
#
# PRECO JE PLNA SNIMKA RAZ ZA SEDENIE: plna snimka je stovky MiB, delta jednotky
# MiB (namerane hodnoty su v docs/MERANIA.md). Retazec potrebuje plnu snimku ako
# referenciu, ale staci jedna na zaciatku sedenia - preto sa output.delta_full_every
# nastavi na viac, nez je poctu cyklov, a plna vyjde iba prva.
#
# Scenar sa do hosta prenasa ako base64 v prikaze, nie cez scp: host nema siet
# do vonkajsieho sveta a cesta cez qemu-guest-agent (guest_exec.sh -m agent)
# funguje aj bez siete uplne. Prenasa sa vzdy jeden samostatny subor.
#
# Root treba iba na zber (viz root_run.sh). --dry-run vypise plan a skonci,
# root pritom netreba.
#
#   sudo -A scripts/collect_corpus.sh -s 3 -t 60
#   scripts/collect_corpus.sh --dry-run

set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || exit 1
SCEN="$REPO/scenarios"
GUEST_EXEC="$REPO/scripts/guest_exec.sh"
ROOT_RUN="$REPO/scripts/root_run.sh"
BIN="$REPO/vmicollect/build/vmicollect"

DOMAIN="${VMIC_DOMAIN:-hyptcn-guest}"
URI="${VMIC_LIBVIRT_URI:-qemu:///session}"
GMODE="auto"

SESSIONS=3
DURATION=60
INTERVAL="5.0"
OUT="$REPO/data/raw"
DRY=0
TRIEDY=(idle cpu_burn mass_file_rewrite proc_scan anon_exec fork_storm)

usage()
{
    cat <<'EOF'
POUZITIE
  collect_corpus.sh [prepinace]

PREPINACE
  -s, --sessions N       sedeni na jednu triedu (vychodzie: 3)
  -t, --duration S       trvanie jedneho sedenia v sekundach (vychodzie: 60)
  -i, --interval S       perioda zberu snimok (vychodzie: 5.0)
  -C, --classes a,b,c    zoznam tried (vychodzie: vsetky zo scenarios/)
  -o, --out DIR          kam sa ukladaju sedenia (vychodzie: data/raw)
  -d, --domain NAZOV     libvirt domena (vychodzie: hyptcn-guest)
  -c, --connect URI      libvirt URI (vychodzie: qemu:///session)
  -m, --mode ssh|agent|auto  cesta do hosta (vychodzie: auto)
  -n, --dry-run          vypis plan a skonci (root netreba)
  -h, --help             tato napoveda

VYSTUP
  <out>/<stamp>_<trieda>/snap/       snimky a sidecary
  <out>/<stamp>_<trieda>/labels.json trieda, presne prikazy, casy, prostredie
  <out>/<stamp>_<trieda>/scenar.out  suhrn scenara (jeden riadok JSON)
EOF
}

die()
{
    printf 'collect_corpus.sh: %s\n' "$1" >&2
    exit "${2:-1}"
}

die_usage()
{
    printf 'collect_corpus.sh: %s\n' "$1" >&2
    usage >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--sessions) [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; SESSIONS="$2"; shift 2 ;;
        -t|--duration) [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; DURATION="$2"; shift 2 ;;
        -i|--interval) [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; INTERVAL="$2"; shift 2 ;;
        -C|--classes)  [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"
                       IFS=',' read -r -a TRIEDY <<<"$2"; shift 2 ;;
        -o|--out)      [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; OUT="$2";      shift 2 ;;
        -d|--domain)   [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; DOMAIN="$2";   shift 2 ;;
        -c|--connect)  [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; URI="$2";      shift 2 ;;
        -m|--mode)     [ $# -ge 2 ] || die_usage "$1 potrebuje hodnotu"; GMODE="$2";    shift 2 ;;
        -n|--dry-run)  DRY=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             die_usage "neznamy prepinac $1" ;;
    esac
done

case "$SESSIONS" in ''|*[!0-9]*) die_usage "--sessions musi byt cele cislo" ;; esac
case "$DURATION" in ''|*[!0-9]*) die_usage "--duration musi byt cele cislo sekund" ;; esac
[ "$SESSIONS" -ge 1 ] || die_usage "--sessions musi byt aspon 1"
[ ${#TRIEDY[@]} -ge 1 ] || die_usage "zoznam tried je prazdny"

for t in "${TRIEDY[@]}"; do
    [ -f "$SCEN/$t.py" ] || die "trieda '$t' nema scenar $SCEN/$t.py"
done

# Pocet cyklov sa odvodi z trvania a periody. Zber tak skonci skor nez scenar,
# takze kazda snimka sedenia vznikla v case, ked scenar naozaj bezal.
CYCLES=$(awk -v d="$DURATION" -v i="$INTERVAL" 'BEGIN{printf "%d", int(d/i)}')
[ "$CYCLES" -ge 1 ] || die "--duration $DURATION s pri perioda $INTERVAL s nedava ani jeden cyklus"
FULL_EVERY=$(( CYCLES + 1 ))

# ---------------------------------------------------------------- pomocnicky

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

guest()
{
    "$GUEST_EXEC" -m "$GMODE" -d "$DOMAIN" -c "$URI" "$@" </dev/null
}

# Poradie tried v kole r je zoznam pootoceny o r. Rovnaka sada, iny start -
# kazda trieda sa tak v korpuse vyskytne rovnomerne rozlozena v case.
poradie_kola()
{
    local r="$1" n=${#TRIEDY[@]} k
    for (( k = 0; k < n; k++ )); do
        printf '%s\n' "${TRIEDY[$(( (k + r) % n ))]}"
    done
}

# ---------------------------------------------------------------- jedno sedenie

sedenie()
{
    local trieda="$1" kolo="$2" stamp dir snapdir gpy b64 cmd_host cmd_zber
    local spid t0 t1 t2 t3 rc_zber rc_scen zvysne runjson

    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    dir="$OUT/${stamp}_${trieda}"
    snapdir="$dir/snap"
    gpy="/tmp/hyptcn_scen_${trieda}.py"
    mkdir -p "$snapdir" || die "neviem vytvorit $snapdir"

    b64=$(base64 -w0 "$SCEN/$trieda.py") || die "base64 nad $SCEN/$trieda.py zlyhal"
    guest "printf %s '$b64' | base64 -d > $gpy" >/dev/null 2>"$dir/prenos.err"
    [ $? -eq 0 ] || die "prenos scenara $trieda do hosta zlyhal (viz $dir/prenos.err)"
    rm -f "$dir/prenos.err"

    cmd_host="python3 $gpy $DURATION"
    cmd_zber="$ROOT_RUN -d $DOMAIN -c $URI run -w delta -i $INTERVAL -N $CYCLES -F $FULL_EVERY -o $snapdir"

    printf '\n== sedenie %s (kolo %d) ==\n' "$trieda" "$kolo" >&2
    printf '   v hostovi : %s\n' "$cmd_host" >&2
    printf '   zber      : %s\n' "$cmd_zber" >&2

    t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    # Scenar sa spusta na pozadi, aby zber bezal SUCASNE s nim. Na jeho koniec
    # sa caka az po zbere - inak by sa cast snimok odobrala po jeho skonceni.
    ( guest "$cmd_host" >"$dir/scenar.out" 2>"$dir/scenar.err"; printf '%s' $? >"$dir/scenar.rc" ) &
    spid=$!

    t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    $ROOT_RUN -d "$DOMAIN" -c "$URI" run -w delta -i "$INTERVAL" -N "$CYCLES" \
              -F "$FULL_EVERY" -o "$snapdir" >"$dir/zber.out" 2>"$dir/zber.err"
    rc_zber=$?
    t2=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    tail -5 "$dir/zber.err" >&2

    wait "$spid"
    t3=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    rc_scen=$(cat "$dir/scenar.rc" 2>/dev/null || printf '125')
    rm -f "$dir/scenar.rc"

    # Kontrola upratania po scenari sa robi po KAZDOM sedeni, nie raz na konci:
    # proces, ktory zostal bezat, by kontaminoval vsetky nasledujuce sedenia
    # a bez tohto zaznamu by sa spatne nedalo zistit, od ktoreho sedenia.
    # Vzor je v hranatych zatvorkach zamerne: prikaz sa v hostovi spusta cez
    # 'sh -c', takze jeho vlastny prikazovy riadok obsahuje hladany retazec a
    # bez tohto triku by pgrep nasiel sam seba a hlasil zvysok po kazdom sedeni.
    zvysne=$(guest "pgrep -c -f '[h]yptcn_scen_' 2>/dev/null || true" 2>/dev/null)
    guest "rm -f $gpy" >/dev/null 2>&1

    runjson=$(sed -nE 's/^zapisane: (.*)$/\1/p' "$dir/zber.err" | tail -1)

    jq -n --arg schema "hyptcn3/session/1" \
          --arg trieda "$trieda" \
          --argjson kolo "$kolo" \
          --arg session_dir "$dir" \
          --arg snapshot_dir "$snapdir" \
          --arg scenar_subor "scenarios/$trieda.py" \
          --arg scenar_sha256 "$(sha256sum "$SCEN/$trieda.py" | cut -d' ' -f1)" \
          --arg prikaz_v_hostovi "$cmd_host" \
          --arg prikaz_zberu "$cmd_zber" \
          --argjson rc "$(jq -n --argjson z "$rc_zber" --argjson s "${rc_scen:-125}" \
                                '{zber:$z,scenar:$s}')" \
          --argjson cas "$(jq -n --arg a "$t0" --arg b "$t1" --arg c "$t2" --arg d "$t3" \
                                 --argjson dur "$DURATION" \
                           '{scenar_start:$a,zber_start:$b,zber_koniec:$c,scenar_koniec:$d,
                             trvanie_zadane_s:$dur}')" \
          --argjson zber "$(jq -n --arg i "$INTERVAL" --argjson n "$CYCLES" \
                                  --argjson f "$FULL_EVERY" --arg r "${runjson:-}" \
                            '{interval_s:($i|tonumber),cykly:$n,delta_full_every:$f,
                              vysledok_json:(if $r=="" then null else $r end)}')" \
          --arg guest_kernel "$(guest 'uname -r' 2>/dev/null)" \
          --arg domain "$DOMAIN" \
          --arg commit "$(repo_commit)" \
          --argjson commit_dirty "$(repo_dirty)" \
          --arg bin_sha256 "$(sha256sum "$BIN" 2>/dev/null | cut -d' ' -f1)" \
          --arg scenar_suhrn "$(cat "$dir/scenar.out" 2>/dev/null)" \
          --arg zvysne_procesy "${zvysne:-unknown}" \
          '{schema:$schema,trieda:$trieda,kolo:$kolo,
            session_dir:$session_dir,snapshot_dir:$snapshot_dir,
            scenar:{subor:$scenar_subor,sha256:$scenar_sha256,
                    prikaz:$prikaz_v_hostovi,suhrn:$scenar_suhrn},
            prikaz_zberu:$prikaz_zberu,zber:$zber,cas:$cas,exit_codes:$rc,
            prostredie:{domain:$domain,guest_kernel:$guest_kernel,
                        commit:$commit,commit_dirty:$commit_dirty,
                        vmicollect_sha256:$bin_sha256},
            zvysne_procesy_v_hostovi:$zvysne_procesy}' >"$dir/labels.json" \
        || die "zapis $dir/labels.json zlyhal"

    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$dir"
    fi

    printf '   hotovo    : %s (zber rc=%d, scenar rc=%s, zvysne procesy v hostovi: %s)\n' \
           "$dir" "$rc_zber" "${rc_scen:-?}" "${zvysne:-unknown}" >&2
    [ "$rc_zber" -eq 0 ] && [ "${rc_scen:-1}" -eq 0 ]
}

# ---------------------------------------------------------------- dry-run

do_dry()
{
    local r t i=0
    printf 'PLAN (--dry-run, nic sa nespusta)\n\n'
    printf '  repozitar  : %s (commit %s, dirty %s)\n' "$REPO" "$(repo_commit)" "$(repo_dirty)"
    printf '  domena     : %s na %s\n' "$DOMAIN" "$URI"
    printf '  triedy     : %s\n' "${TRIEDY[*]}"
    printf '  sedeni     : %d na triedu, spolu %d\n' "$SESSIONS" "$(( SESSIONS * ${#TRIEDY[@]} ))"
    printf '  jedno      : %s s, perioda %s s -> %d snimok (z toho 1 plna, delta_full_every=%d)\n' \
           "$DURATION" "$INTERVAL" "$CYCLES" "$FULL_EVERY"
    printf '  snimok     : %d spolu, z toho %d plnych\n' \
           "$(( SESSIONS * ${#TRIEDY[@]} * CYCLES ))" "$(( SESSIONS * ${#TRIEDY[@]} ))"
    printf '  cisty cas  : %d s zberu (bez rezie medzi sedeniami)\n' \
           "$(( SESSIONS * ${#TRIEDY[@]} * DURATION ))"
    printf '  vystup     : %s\n' "$OUT"
    printf '  volne miesto na tom zvazku:\n'
    df -h "$(dirname "$OUT")" | sed 's/^/    /'
    printf '\n  poradie sedeni (poradie tried sa v kazdom kole otoci):\n'
    for (( r = 0; r < SESSIONS; r++ )); do
        while read -r t; do
            i=$(( i + 1 ))
            printf '    %2d. kolo %d  trieda %-18s python3 /tmp/hyptcn_scen_%s.py %s\n' \
                   "$i" "$(( r + 1 ))" "$t" "$t" "$DURATION"
        done < <(poradie_kola "$r")
    done
    printf '\n  kazde sedenie spusti:\n    %s\n' \
        "$ROOT_RUN -d $DOMAIN -c $URI run -w delta -i $INTERVAL -N $CYCLES -F $FULL_EVERY -o $OUT/<stamp>_<trieda>/snap"
    printf '  a ulozi <stamp>_<trieda>/labels.json (trieda, prikazy, casy, jadro hosta, commit, sha256 binarky)\n'
    printf '\n  ostry beh potrebuje root: sudo -A %s\n' "$0"
}

# ---------------------------------------------------------------- hlavne telo

for tool in jq base64 sha256sum awk; do
    command -v "$tool" >/dev/null 2>&1 || die "chyba nastroj $tool"
done
[ -x "$GUEST_EXEC" ] || die "chyba $GUEST_EXEC"
[ -x "$ROOT_RUN" ] || die "chyba $ROOT_RUN"
[ -x "$BIN" ] || die "binarka $BIN neexistuje - spusti 'make -C $REPO/vmicollect'"

if [ "$DRY" -eq 1 ]; then
    do_dry
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "zber potrebuje root - spusti cez sudo (alebo pouzi --dry-run)"

mkdir -p "$OUT" || die "neviem vytvorit $OUT"
ZLYHALO=0
CELKOM=0
for (( kolo = 0; kolo < SESSIONS; kolo++ )); do
    while read -r trieda; do
        CELKOM=$(( CELKOM + 1 ))
        sedenie "$trieda" "$(( kolo + 1 ))" || ZLYHALO=$(( ZLYHALO + 1 ))
    done < <(poradie_kola "$kolo")
done

printf '\nkorpus: %d sedeni, %d zlyhalo, vystup v %s\n' "$CELKOM" "$ZLYHALO" "$OUT" >&2
[ "$ZLYHALO" -eq 0 ]
