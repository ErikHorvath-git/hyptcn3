#!/usr/bin/env bash
#
# check_claims.sh - textova kontrola tvrdeni v texte prace (pravidla z HONESTY.md).
#
# PRECO: predchadzajuca iteracia projektu vyprodukovala cisla, ktore sa do textu
# dostali bez zdroja a prezili niekolko revizii. Cierna listina sama nestaci -
# zachyti len cisla, ktore uz poznam. Preto skript popri nej vynucuje, aby kazde
# cislo v thesis/ ukazovalo znackou na konkretny JSON v data/results/, a tu znacku
# aj rozvinie a porovna s textom. Cislo, ktore sa v JSON nenachadza, je nalez.
#
# Sest kontrol:
#   A  zakazane cisla z hypTcn002 (riadok so slovom RETRAKCIA sa preskakuje)
#   B  cislo bez znacky zdroja (iba .md pod thesis/)
#   C  znacka {{res:subor.json:kluc}} - existencia suboru, kluca a zhoda hodnoty
#   D  zakazane slova
#   E  hlavicka {commit, date, host, guest, command, n, values} v data/results/*.json
#   F  aktualnost docs/PRIRUCKA.md (volanie scripts/check_prirucka.sh)
#
# Pouzitie:
#   scripts/check_claims.sh                  # vychodzi rozsah (nizsie) + kontroly E a F
#   scripts/check_claims.sh thesis/09.md ... # konkretne subory alebo adresare (bez E a F)
#   scripts/check_claims.sh --json-hlavicky  # iba kontrola E
#
# Navratovy kod: 0 = ciste, 1 = nalezy, 2 = chyba pouzitia.
#
# VYCHODZI ROZSAH zodpovedá prvej vete HONESTY.md ("thesis/, docs/, README.md,
# komentare v zdrojakoch"): thesis/, docs/, README.md v koreni, vmicollect/README.md
# a komentare v zdrojakoch (cely vmicollect/ okrem build/, guestparse/, scripts/,
# features/, tcn/).
# Predtym to bolo iba thesis/ a docs/, takze korenovy README.md - subor
# s hlavnymi namerannymi cislami - sa nekontroloval nikdy.
#
# PRECO AJ features/ A tcn/: prave v nich stoji upozornenie "model nie je
# natrenovany" (tcn/score.py, tcn/__init__.py, features/PERBIN.md). Su to
# komentare o tom, co cislo znamena - teda presne ten druh textu, ktory tato
# kontrola strazi. Do 2026-09-19 boli oba adresare mimo rozsahu, takze zakazane
# cislo ani zakazane slovo v nich nikto nehladal.
#
# Co sa v zdrojaku kontroluje: iba text komentarov (// /* */ #), nie kod. Cislo
# v kode je konstanta, nie tvrdenie; hodnota 0.86 v algoritme nie je metrika
# z hypTcn002. Komentare vyberá python3 (funkcia extract_comments nizsie).
#
# Vynimky v texte:
#   <!-- noclaim: dovod -->      riadok sa preskoci vo vsetkych kontrolach
#   <!-- prevzate:start -->      zaciatok prevzatej tabulky (kontrola B sa nerobi)
#   <!-- prevzate:end -->        koniec prevzatej tabulky
#   RETRAKCIA                    riadok smie obsahovat zakazane cislo aj cislo
#                                bez znacky (stare cislo ziadny JSON v data/results nema)
#   thesis/.claims-allow         regexy (jeden na riadok), tokeny ktore su v poriadku
#
# Vynimky mimo textu: pole EXEMPT nizsie (subor + vzor + dovod). Su urcene pre
# prevzate subory, do ktorych sa poznamka dopisat neda alebo sa zatial nedopisala.
# Skript ich na konci behu vypise, aby nebolo ticho o tom, co sa vynalo.
#
# Premenna prostredia VMIC_RESULTS_DIR prebije cestu k data/results (pouziva ju test).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${VMIC_RESULTS_DIR:-$REPO_DIR/data/results}"
ALLOW_FILE="${VMIC_ALLOW_FILE:-$REPO_DIR/thesis/.claims-allow}"

# --------------------------------------------------------------------------
# A: zakazane cisla. Prvy stlpec je PCRE, druhy popis do hlasky.
# Ohranicenie (?<![0-9]) / (?![0-9]) brani tomu, aby 0,86 chytilo 0,8633.
# Desatinny oddelovac je [.,] - text je po slovensky, JSON po anglicky.
# --------------------------------------------------------------------------
FORBIDDEN_NUM=(
  '99[.,]70|F1 z hypTcn002'
  '99[.,]98|AUC z hypTcn002'
  '0[.,]9997|metrika na okno z hypTcn002'
  '0[.,]9995|metrika na okno z hypTcn002'
  '0[.,]9998|metrika na okno z hypTcn002'
  '0[.,]9984|metrika na okno z hypTcn002'
  '0[.,]9869|metrika na okno z hypTcn002'
  '0[.,]9861|metrika na okno z hypTcn002'
  '0[.,]9956|metrika na okno z hypTcn002'
  '95[.,]5|presnost 5 tried z hypTcn002'
  '0[.,]8583|metrika z hypTcn002'
  '0[.,]8633|metrika z hypTcn002'
  '0[.,]86|metrika z hypTcn002'
  '0[.,]999|AUC z hypTcn002'
  '0[.,]852|LogReg baseline z hypTcn002'
  '26/33|pocet detegovanych vzoriek z hypTcn002'
  '78[.,]8|pomer detegovanych vzoriek z hypTcn002'
  '1[.,]75e-12|SPRT p-hodnota z hypTcn002'
  '1[.,]76|overhead z hypTcn002 (iny senzor)'
  '4[.,]08|priepustnost z hypTcn002 (iny senzor)'
  '3[.,]4 ?ms|latencia z hypTcn002 (iny senzor)'
  '0[.,]741|per-PID AUC z hypTcn002 - iba v kapitole o retrakciach'
  '1043[.,]2|ilustracne cislo z vmicollect/README.md, nie meranie'
  '2[.,]8 ?TB|ilustracny odhad z vmicollect/README.md, nie meranie'
)

# --------------------------------------------------------------------------
# D: zakazane slova. Kmen slova, aby sadli ohnute tvary; s diakritikou aj bez.
# Poslednych dvoch (vyrazne, revolucny) niet v HONESTY P11 ako povinnych,
# su tam na ziadost zadavatela prace - preto su na konci a hlasia to iste.
# --------------------------------------------------------------------------
FORBIDDEN_WORD=(
  'state-of-the-art'
  'production-ready'
  'robustn'
  'komplexn'
  'inovat[ií]vn'
  'unik[áa]tn'
  'v[ýy]razn'
  'revolu[čc]n'
)

# --------------------------------------------------------------------------
# Vynimky pre prevzate subory: <cesta od korena repa>|<PCRE>|<dovod>
#
# PRECO zoznam a nie poznamka priamo v subore: vmicollect/ je prevzaty strom
# (commit 6b9053d "prevzaty stav k 2026-08-26, bez zmien"). Poznamka "ilustracne"
# priamo v jeho README.md a v hlavickach .c je spravnejsia - je vidiet na mieste,
# kde clovek cislo cita - ale meni prevzaty subor. Kym sa to nestane, drzi vynimku
# tento zoznam: je verzionovany, kazda polozka ma dovod a skript ich na konci
# vypise, takze vynatie nie je tiche. Polozka plati len pre uvedeny subor,
# nie globalne; v thesis/ a docs/ tie iste cisla nalezom zostavaju.
#
# DOROBIT: az sa vmicollect/README.md, src/writer_delta.c a src/retention.c budu
# menit, dopisat k cislam "(ilustracne, nie meranie)" a polozky odtialto zmazat.
# --------------------------------------------------------------------------
EXEMPT=(
  'vmicollect/README.md|2[.,]8 ?TB|ilustracny radovy odhad v prevzatej dokumentacii (HONESTY kap. 3), nie meranie; nahradit nameranym objemom'
  'vmicollect/README.md|1043[.,]2|vymysleny priklad JSON sidecaru v prevzatej dokumentacii (HONESTY kap. 3), nie meranie'
  'vmicollect/src/writer_delta.c|2[.,]8 ?TB|ten isty radovy odhad v hlavicke prevzateho zdrojaku (HONESTY kap. 3)'
  'vmicollect/src/retention.c|2[.,]8 ?TB|ten isty radovy odhad v hlavicke prevzateho zdrojaku (HONESTY kap. 3)'
)

# Zlucene vzory na rychle predsito: jeden grep na riadok namiesto dvadsiatich styroch.
# Sama kontrola potom uz bezi len nad riadkami, ktore nieco obsahuju.
COMBINED_NUM="$(printf '%s\n' "${FORBIDDEN_NUM[@]}" | sed 's/|.*//' | paste -sd '|' -)"
COMBINED_WORD="$(printf '%s\n' "${FORBIDDEN_WORD[@]}" | paste -sd '|' -)"

# Kontexty, po ktorych cislo nie je tvrdenie, ale odkaz alebo verzia.
# Vyhadzuju sa z riadku este pred kontrolou B.
CTX_REF='(kapitol[aeuy]|kap\.|sekci[aeiu]|cast[iou]?|časť|§|tabu[ľl]k[aeuy]|obr[áa]zok|obr\.|rovnic[aeiu]|krok|commit)[[:space:]]+v?[0-9][0-9A-Za-z._,-]*'
CTX_VER='(jadr[oau]|kernel|verzi[aeiu]|Debian|Fedora|Ubuntu|QEMU|KVM|clang|libbpf|LLVM|GCC|[Pp]ython3?|torch|numpy|pytest|IPv4|IPv6|SHA-?256|ABI)[[:space:]]*v?[0-9][0-9A-Za-z._,-]*'

# Tokeny, ktore cislom tvrdenia nie su nikdy. Cislo verzie (dva a viac bodiek,
# napr. 6.1.0-42 alebo 7.1.13-100.fc43) sa v texte objavi pri kazdej zmienke
# o jadre hosta alebo hostitela a znacku zdroja nepotrebuje.
DEFAULT_ALLOW=(
  '^[0-9]+\.[0-9]+\.[0-9]+'
)

# Adresare, ktorych JSON subory kontrola E nekontroluje. Kazdy s dovodom -
# vypise sa pri behu.
JSON_SKIP=(
  'sidecars|doslovny vystup vmicollect (schema vmicollect/1); hlavicka by bola zasah do nameraneho suboru'
  'ground_truth|doslovny vystup prikazov v hostovi (pozemna pravda), nie odvodeny vysledok'
)

FINDINGS="$(mktemp)"
EXEMPT_LOG="$(mktemp)"
trap 'rm -f "$FINDINGS" "$EXEMPT_LOG"' EXIT

note() { printf '%s:%s: [%s] %s\n' "$1" "$2" "$3" "$4" >>"$FINDINGS"; }

# relativna cesta od korena repa (kvoli hlaskam aj kvoli zoznamu EXEMPT)
relpath() {
  case "$1" in
    "$REPO_DIR"/*) printf '%s' "${1#"$REPO_DIR"/}" ;;
    ./*)           printf '%s' "${1#./}" ;;
    *)             printf '%s' "$1" ;;
  esac
}

# Vrati 0, ked je dvojica (subor, najdeny text) na zozname EXEMPT.
is_exempt() {
  local rel="$1" hit="$2" e path pat reason
  for e in "${EXEMPT[@]}"; do
    path="${e%%|*}"; e="${e#*|}"; pat="${e%%|*}"; reason="${e#*|}"
    [ "$path" = "$rel" ] || continue
    if printf '%s' "$hit" | grep -qP "^(?:$pat)$"; then
      printf '%s|%s|%s\n' "$rel" "$hit" "$reason" >>"$EXEMPT_LOG"
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------- pomocne
# Rozvinie znacku: vrati OK / MISSING-FILE / MISSING-KEY / BAD-JSON:... /
# DIFF:<json>:<text>. Porovnava sa na tolko desatinnych miest, kolko ich ma text.
resolve_mark() {
  local jsonfile="$1" key="$2" textnum="$3"
  python3 - "$jsonfile" "$key" "$textnum" <<'PY'
import json, sys
path, key, textnum = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding="utf-8") as fh:
        cur = json.load(fh)
except Exception as exc:
    print("BAD-JSON:%s" % exc); raise SystemExit(0)
for part in key.split("."):
    if isinstance(cur, list):
        try:
            cur = cur[int(part)]
        except Exception:
            print("MISSING-KEY"); raise SystemExit(0)
    elif isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print("MISSING-KEY"); raise SystemExit(0)
if not textnum:
    print("OK"); raise SystemExit(0)
t = textnum.replace(",", ".")
nd = len(t.split(".")[1]) if "." in t else 0
try:
    tv = float(t)
except ValueError:
    print("OK"); raise SystemExit(0)
if isinstance(cur, bool) or not isinstance(cur, (int, float)):
    # necislena hodnota v JSON, ale v texte je cislo - porovnaj ako retazec
    print("OK" if str(cur) == textnum else "DIFF:%s:%s" % (cur, textnum))
    raise SystemExit(0)
print("OK" if abs(round(float(cur), nd) - tv) < 1e-9 else "DIFF:%s:%s" % (cur, textnum))
PY
}

# ---- D: zakazane slova. Hlada sa vsade, aj v oplotenom bloku kodu:
# preklep v komentari vo vypise je tiez text prace.
check_words() {
  local file="$1" rel="$2" lineno="$3" line="$4" w hit
  printf '%s' "$line" | grep -qiP "$COMBINED_WORD" || return 0
  for w in "${FORBIDDEN_WORD[@]}"; do
    if printf '%s' "$line" | grep -qiP "$w"; then
      hit="$(printf '%s' "$line" | grep -oiP "${w}[a-zá-žA-ZÁ-Ž]*" | head -1)"
      is_exempt "$rel" "$hit" && continue
      note "$rel" "$lineno" "ZAKAZANE-SLOVO" "'$hit' - pozri HONESTY.md P11"
    fi
  done
}

# ---- A: zakazane cisla. Hlada sa vsade vratane oploteneho bloku kodu:
# vysledok sa v texte prace bezne uvadza prave ako ukazka vystupu programu
# ({"f1": 99.70}), a taky riadok je tvrdenie ako kazde ine.
check_numbers() {
  local file="$1" rel="$2" lineno="$3" line="$4" entry pat desc hit
  case "$line" in *[0-9]*) ;; *) return 0 ;; esac
  printf '%s' "$line" | grep -qP "(?<![0-9])(?:$COMBINED_NUM)(?![0-9])" || return 0
  for entry in "${FORBIDDEN_NUM[@]}"; do
    pat="${entry%%|*}"; desc="${entry#*|}"
    hit="$(printf '%s' "$line" | grep -oP "(?<![0-9])(?:$pat)(?![0-9])" | head -1)"
    [ -z "$hit" ] && continue
    is_exempt "$rel" "$hit" && continue
    note "$rel" "$lineno" "ZAKAZANE-CISLO" "$hit - $desc"
  done
}

# ---- C: znacky zdroja
check_marks() {
  local file="$1" rel="$2" lineno="$3" line="$4"
  case "$line" in *'{{res:'*) ;; *) return 0 ;; esac
  # Znacka v inline kode (`{{res:...}}`) je ukazka zapisu v dokumentacii,
  # nie tvrdenie - z riadku sa pred kontrolou vyhodi.
  local scan_line mark
  scan_line="$(printf '%s' "$line" | sed -E 's/`[^`]*`//g')"
  while IFS= read -r mark; do
    [ -z "$mark" ] && continue
    local body rel_json key jsonfile prefix stripped textnum res
    body="${mark#\{\{res:}"; body="${body%\}\}}"
    rel_json="${body%%:*}"; key="${body#*:}"
    if [ "$rel_json" = "$body" ] || [ -z "$key" ]; then
      note "$rel" "$lineno" "ZNACKA-TVAR" "$mark - ocakavam {{res:subor.json:kluc}}"
      continue
    fi
    jsonfile="$RESULTS_DIR/$rel_json"
    if [ ! -f "$jsonfile" ]; then
      note "$rel" "$lineno" "ZNACKA-SUBOR" "$mark - subor $jsonfile neexistuje"
      continue
    fi
    # cislo tesne pred znackou (max 12 znakov jednotky a medzier medzi nimi)
    prefix="${scan_line%%"$mark"*}"
    stripped="$(printf '%s' "$prefix" | sed -E 's/[^0-9]*$//')"
    textnum=""
    if [ $(( ${#prefix} - ${#stripped} )) -le 12 ]; then
      textnum="$(printf '%s' "$stripped" | grep -oP '[0-9]+(?:[.,][0-9]+)?$' || true)"
    fi
    res="$(resolve_mark "$jsonfile" "$key" "$textnum")"
    case "$res" in
      OK) ;;
      MISSING-KEY)  note "$rel" "$lineno" "ZNACKA-KLUC" "$mark - kluc '$key' v $rel_json nie je" ;;
      BAD-JSON:*)   note "$rel" "$lineno" "ZNACKA-SUBOR" "$mark - $rel_json sa neda precitat: ${res#BAD-JSON:}" ;;
      DIFF:*)       note "$rel" "$lineno" "ZNACKA-HODNOTA" "$mark - v texte ${res##*:}, v JSON $(printf '%s' "${res#DIFF:}" | cut -d: -f1)" ;;
      *)            note "$rel" "$lineno" "ZNACKA-CHYBA" "$mark - neocakavana odpoved kontroly: $res" ;;
    esac
  done < <(printf '%s' "$scan_line" | grep -oP '\{\{res:[^}]*\}\}' || true)
}

# ---- B: cislo bez znacky zdroja (iba thesis/)
check_bare_numbers() {
  local file="$1" rel="$2" lineno="$3" line="$4"
  case "$line" in *[0-9]*) ;; *) return 0 ;; esac
  local bare tok
  bare="$(printf '%s' "$line" \
    | sed -E 's/`[^`]*`//g' \
    | sed -E 's#https?://[^ )]*##g' \
    | sed -E 's/[0-9]+([.,][0-9]+)?[[:space:]]*(%|[A-Za-z/]+)?[[:space:]]*\{\{res:[^}]*\}\}//g' \
    | sed -E 's/\{\{res:[^}]*\}\}//g' \
    | sed -E "s/$CTX_REF//gI" \
    | sed -E "s/$CTX_VER//gI")"
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    local allowed=0 arx
    for arx in "${DEFAULT_ALLOW[@]}"; do
      printf '%s' "$tok" | grep -qP "$arx" && { allowed=1; break; }
    done
    [ "$allowed" -eq 1 ] && continue
    if [ -f "$ALLOW_FILE" ] && printf '%s' "$tok" | grep -qf <(grep -v '^[[:space:]]*#' "$ALLOW_FILE" | grep -v '^[[:space:]]*$'); then
      continue
    fi
    note "$rel" "$lineno" "BEZ-ZNACKY" "'$tok' nema znacku {{res:subor.json:kluc}}"
  done < <(printf '%s' "$bare" | grep -oP '[0-9]+(?:[.,][0-9]+)+(?:-[0-9A-Za-z._]+)?|[0-9]+(?:[.,][0-9]+)?[[:space:]]?(?:ms|µs|us|MiB/s|GiB/s|MiB|GiB|KiB|TB|GB|%|s|h|min)(?![A-Za-z])' || true)
}

# ---------------------------------------------------------------- .md subor
check_md() {
  local file="$1" rel
  rel="$(relpath "$file")"
  local in_thesis=0 in_code=0 in_prevzate=0 lineno=0
  # thesis/ sa pozna z cesty; druhy vzor je kvoli spusteniu nad kopiou mimo repa (test)
  case "$rel" in thesis/*|*/thesis/*) in_thesis=1 ;; esac

  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))

    # oplotene bloky kodu: hranicny riadok prepina stav a sam sa nekontroluje
    case "$line" in
      '```'*|'~~~'*) in_code=$((1 - in_code)); continue ;;
    esac
    case "$line" in
      *'<!-- prevzate:start -->'*) in_prevzate=1; continue ;;
      *'<!-- prevzate:end -->'*)   in_prevzate=0; continue ;;
    esac

    local skip_line=0 is_retr=0
    case "$line" in *'<!-- noclaim'*) skip_line=1 ;; esac
    # riadok o retrakcii cituje stare cislo zamerne a znacku zdroja mat nemoze -
    # ten JSON v data/results neexistuje a existovat nema
    case "$line" in *RETRAKCIA*) is_retr=1 ;; esac

    [ "$skip_line" -eq 0 ] && check_words "$file" "$rel" "$lineno" "$line"
    if [ "$skip_line" -eq 0 ] && [ "$is_retr" -eq 0 ]; then
      check_numbers "$file" "$rel" "$lineno" "$line"
    fi

    # V bloku kodu sa dalej nekontroluje nic: znacka zdroja je tam ukazka zapisu
    # a cislo vo vypise programu je vypis, nie veta s tvrdenim.
    [ "$in_code" -eq 1 ] && continue

    [ "$skip_line" -eq 0 ] && check_marks "$file" "$rel" "$lineno" "$line"

    [ "$in_thesis" -eq 1 ] || continue
    [ "$skip_line" -eq 1 ] && continue
    [ "$is_retr" -eq 1 ] && continue
    [ "$in_prevzate" -eq 1 ] && continue
    case "$line" in '#'*) continue ;; esac
    check_bare_numbers "$file" "$rel" "$lineno" "$line"
  done <"$file"
}

# ------------------------------------------------------------- zdrojak
# Z komentarov sa kontroluju A, C a D. Kontrola B (cislo bez znacky) sa v
# zdrojakoch nerobi - je urcena pre thesis/.
extract_comments() {
  python3 - "$1" <<'PY'
import sys, os
path = sys.argv[1]
ext = os.path.splitext(path)[1]
base = os.path.basename(path)
hashlang = ext in (".py", ".sh", ".bash", ".mk", ".cfg", ".conf", ".yml", ".yaml") \
    or base in ("Makefile", "makefile", "GNUmakefile")
try:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
except OSError:
    raise SystemExit(0)
if hashlang:
    for i, line in enumerate(lines, 1):
        # jednoduche pravidlo: text za prvou mriezkou. Retazec s mriezkou sa
        # takto vyhodnoti ako komentar - je to nadpraca, nie diera.
        pos = line.find("#")
        if pos >= 0 and line[pos:].strip("# \t"):
            print("%d\t%s" % (i, line[pos:]))
    raise SystemExit(0)
# C/C++: riadkove // aj blokove /* */
inblock = False
for i, line in enumerate(lines, 1):
    out, rest = [], line
    while rest:
        if inblock:
            end = rest.find("*/")
            if end < 0:
                out.append(rest); rest = ""
            else:
                out.append(rest[:end]); rest = rest[end + 2:]; inblock = False
        else:
            b = rest.find("/*"); l = rest.find("//")
            if l >= 0 and (b < 0 or l < b):
                out.append(rest[l + 2:]); rest = ""
            elif b >= 0:
                rest = rest[b + 2:]; inblock = True
            else:
                rest = ""
    text = " ".join(s.strip() for s in out if s.strip())
    if text:
        print("%d\t%s" % (i, text))
PY
}

check_src() {
  local file="$1" rel
  rel="$(relpath "$file")"
  grep -qiP "(?:$COMBINED_NUM)|(?:$COMBINED_WORD)|\\{\\{res:" "$file" || return 0
  local lineno line
  while IFS=$'\t' read -r lineno line; do
    [ -z "${lineno:-}" ] && continue
    case "$line" in *'noclaim'*) continue ;; esac
    check_words "$file" "$rel" "$lineno" "$line"
    case "$line" in *RETRAKCIA*) ;; *) check_numbers "$file" "$rel" "$lineno" "$line" ;; esac
    check_marks "$file" "$rel" "$lineno" "$line"
  done < <(extract_comments "$file")
}

check_file() {
  case "$1" in
    *.md) check_md "$1" ;;
    *)    check_src "$1" ;;
  esac
}

# ------------------------------------------- F: aktualnost docs/PRIRUCKA.md
# Prirucka je generovana z kodu (scripts/gen_prirucka.py). Samotne porovnanie
# robi scripts/check_prirucka.sh - potrebuje zostavenu binarku, teda prekladac,
# co je iny druh zavislosti nez zvysok tohto skriptu, preto bezi zvlast.
# Kontrola sa robi iba vo vychodzom rozsahu; pri zadanych cestach nie.
#
# CHYBAJUCI ALEBO NESPUSTITELNY SKRIPT JE NALEZ, NIE TICHY NAVRAT. Predtym tu
# stalo '[ -x "$skript" ] || return 0': ked by check_prirucka.sh stratil priznak
# spustitelnosti (alebo ho niekto zmazal), kontrola prirucky by zmizla a tento
# skript by hlasil cisto. Kontrola, ktora sa da vypnut tak, ze o tom nikto
# nevie, nie je kontrola.
check_prirucka() {
  local skript="$SCRIPT_DIR/check_prirucka.sh"
  if [ ! -f "$skript" ]; then
    note "scripts/check_prirucka.sh" "1" "PRIRUCKA" \
      "kontrola aktualnosti docs/PRIRUCKA.md chyba: skript neexistuje"
    return 0
  fi
  if [ ! -x "$skript" ]; then
    note "scripts/check_prirucka.sh" "1" "PRIRUCKA" \
      "kontrola aktualnosti docs/PRIRUCKA.md sa nespustila: skript nie je spustitelny (chmod +x)"
    return 0
  fi
  local vystup rc
  vystup="$("$skript" 2>&1)"
  rc=$?
  [ "$rc" -eq 0 ] && return 0
  note "docs/PRIRUCKA.md" "1" "PRIRUCKA" "$(printf '%s' "$vystup" | head -1)"
}

# ------------------------------------------------- E: hlavicky JSON vysledkov
check_json_headers() {
  [ -d "$RESULTS_DIR" ] || { echo "check_claims.sh: $RESULTS_DIR neexistuje, kontrola hlaviciek sa preskakuje" >&2; return 0; }
  local skip_args=()
  local s
  for s in "${JSON_SKIP[@]}"; do skip_args+=("${s%%|*}"); done
  while IFS= read -r res_line; do
    [ -z "$res_line" ] && continue
    local f="${res_line%%|*}" msg="${res_line#*|}"
    note "$f" "1" "JSON-HLAVICKA" "$msg"
  done < <(python3 - "$RESULTS_DIR" "$REPO_DIR" "${skip_args[@]}" <<'PY'
import json, os, sys
root, repo = sys.argv[1], sys.argv[2]
skip = set(sys.argv[3:])
# Proveniencia je povinna vzdy: bez nej sa neda dohladat, ktora binarka a ktory
# stroj cislo vyrobili. Nazov bloku s hodnotami povinny NIE JE - artefakt smie mat
# vlastnu schemu a pomenovat si ho po svojom, ale musi to vyhlasit v "schema" a
# tento zoznam ho musi poznat. Prepisovat overeny artefakt kvoli nazvu kluca by
# znamenalo siahat na data kvoli kozmetike.
need = ["commit", "date", "host", "guest", "command", "n"]

# schema -> kluce, ktore v tej scheme nesu namerane hodnoty
PAYLOAD_BY_SCHEMA = {
    "hyptcn3/guestparse-validate/1": ["processes", "modules", "sockets", "checks"],
    "hyptcn3/vysledok-hlavicka/1": ["values"],
    "hyptcn3/once/1": ["summary", "values"],
    "hyptcn3/run/1": ["summary", "values"],
    "hyptcn3/probe/1": ["values"],
    "hyptcn3/env/1": ["values", "vmicollect", "prikazy"],
    "hyptcn3/summary/1": ["values"],
    "hyptcn3/snapshots/1": ["values", "snapshots"],
    "hyptcn3/optim/1": ["values", "pred", "po"],
}
DEFAULT_PAYLOAD = ["values"]
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in skip]
    for name in sorted(filenames):
        if not name.endswith(".json"):
            continue
        p = os.path.join(dirpath, name)
        rel = os.path.relpath(p, repo)
        try:
            with open(p, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            print("%s|subor sa neda precitat ako JSON: %s" % (rel, exc)); continue
        if not isinstance(doc, dict):
            print("%s|najvyssia uroven nie je objekt, hlavicka sa neda overit" % rel); continue
        missing = [k for k in need if k not in doc]
        if missing:
            print("%s|chybaju kluce proveniencie podla HONESTY.md kap. 4: %s"
                  % (rel, ", ".join(missing)))
        payload = PAYLOAD_BY_SCHEMA.get(doc.get("schema"), DEFAULT_PAYLOAD)
        if not any(k in doc for k in payload):
            print("%s|chyba blok s hodnotami: schema '%s' ma mat niektory z klucov %s"
                  % (rel, doc.get("schema", "(neuvedena)"), ", ".join(payload)))
PY
)
}

# ---------------------------------------------------------------- vstupy
ONLY_JSON=0
declare -a ARGS=()
for a in "$@"; do
  case "$a" in
    --json-hlavicky) ONLY_JSON=1 ;;
    -h|--help) sed -n '3,40p' "$0"; exit 0 ;;
    *) ARGS+=("$a") ;;
  esac
done

if [ "$ONLY_JSON" -eq 1 ]; then
  check_json_headers
  if [ -s "$FINDINGS" ]; then
    sort -t: -k1,1 -k2,2n "$FINDINGS"
    printf 'check_claims.sh: %d nalezov (kontrola hlaviciek JSON)\n' "$(wc -l <"$FINDINGS")"
    exit 1
  fi
  printf 'check_claims.sh: hlavicky JSON v %s su v poriadku\n' "$RESULTS_DIR"
  exit 0
fi

# Vychodzi rozsah podla prvej vety HONESTY.md.
DEFAULT_SCOPE=0
declare -a TARGETS=()
if [ "${#ARGS[@]}" -gt 0 ]; then
  TARGETS=("${ARGS[@]}")
else
  DEFAULT_SCOPE=1
  for t in thesis docs README.md vmicollect guestparse scripts features tcn; do
    [ -e "$REPO_DIR/$t" ] && TARGETS+=("$REPO_DIR/$t")
  done
fi

if [ "${#TARGETS[@]}" -eq 0 ]; then
  echo "check_claims.sh: ziadna z ciest vychodzieho rozsahu neexistuje, niet co kontrolovat" >&2
  exit 0
fi

declare -a FILES=()
for t in "${TARGETS[@]}"; do
  if [ -d "$t" ]; then
    while IFS= read -r f; do FILES+=("$f"); done < <(
      find "$t" -type f \
        \( -name '*.md' -o -name '*.c' -o -name '*.h' -o -name '*.py' \
           -o -name '*.sh' -o -name 'Makefile' \) \
        -not -path '*/__pycache__/*' -not -path '*/build/*' -not -path '*/.*/*' \
        | sort)
  elif [ -f "$t" ]; then
    FILES+=("$t")
  else
    echo "check_claims.sh: '$t' neexistuje" >&2
    exit 2
  fi
done

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "check_claims.sh: ziadne kontrolovatelne subory v zadanych cestach" >&2
  exit 0
fi

for f in "${FILES[@]}"; do
  # HONESTY.md obsahuje zoznam zakazanych cisel, hlasil by sam seba;
  # check_claims.sh ten zoznam obsahuje tiez (pole FORBIDDEN_NUM)
  case "$(basename "$f")" in HONESTY.md|check_claims.sh) continue ;; esac
  check_file "$f"
done

if [ "$DEFAULT_SCOPE" -eq 1 ]; then
  check_json_headers
  check_prirucka
fi

# Vynimky nie su ticho: co sa vynalo, sa vypise aj pri cistom behu.
if [ -s "$EXEMPT_LOG" ]; then
  printf 'check_claims.sh: uplatnene vynimky (pole EXEMPT, pozri HONESTY.md kap. 3):\n'
  sort -u "$EXEMPT_LOG" | while IFS='|' read -r ex_file ex_hit ex_why; do
    printf '  %s: %s - %s\n' "$ex_file" "$ex_hit" "$ex_why"
  done
fi

if [ -s "$FINDINGS" ]; then
  sort -t: -k1,1 -k2,2n "$FINDINGS"
  printf 'check_claims.sh: %d nalezov v %d suboroch\n' "$(wc -l <"$FINDINGS")" "${#FILES[@]}"
  exit 1
fi

printf 'check_claims.sh: ciste (%d suborov)\n' "${#FILES[@]}"
exit 0
