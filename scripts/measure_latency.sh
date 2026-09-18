#!/usr/bin/env bash
#
# measure_latency.sh - krok K16: latencia snimka -> per-bin priznakovy vektor.
#
# Preco samostatny skript a nie rucne poskladane prikazy: nazov prace obsahuje
# "real-time", takze to slovo musi mat cislo, a to cislo musi vediet zopakovat
# niekto iny jednym prikazom. Vsetko, co skript zmeria, konci v jednom JSONe
# s hlavickou proveniencie (HONESTY.md kap. 4).
#
# Co sa meria:
#   1) latencia cyklu zvonku - od zaciatku cyklu (sidecar.timestamp_unix, teda
#      okamih, kedy si zberac vzal cas cyklu) po okamih, kedy je sidecar
#      s blokom "features" zapisany a zavrety na disku. Zavretie chyta
#      inotifywait (udalost close_write), cas sa berie z bash EPOCHREALTIME.
#      PRECO zvonku a nie iba z total_ms: collector meria total_ms v
#      collector.c skor, nez sa sidecar zapise (vmic_meta_write az za
#      meranim), takze total_ms zapis sidecaru NEOBSAHUJE - a prave sidecar
#      je miesto, kde vektor vznikne.
#   2) vnutorne casy toho isteho cyklu zo sidecaru: capture_ms, write_ms,
#      total_ms a features.compute_ms.
#   3) cena samotneho vypoctu priznakov: rozdiel medianu capture_ms medzi
#      behmi s [features].enable=true a =false (prepinac existuje), a popri
#      tom compute_ms, ktory si modul meria sam.
#   4) latencia Pythonovej referencie (features perbin nad ulozenou snimkou) -
#      ukazuje, co by stalo pocitat ten isty vektor mimo modulu.
#
# Poradie variantov sa striedá (on, off, off, on pri 5 s; off, on pri 2 s), aby
# sa pomaly kolisajuca zataz hostitela nenamapovala na jeden variant.
#
# Root: samotny zber (eBPF nad KVM) potrebuje CAP_BPF a CAP_PERFMON. Spusta sa
# cez sudo -A, teda cez SUDO_ASKPASS. Vsetko ostatne bezi pod pouzivatelom.
#
# Pouzitie:
#   scripts/measure_latency.sh [-N cyklov] [-p n_pythonu] [-o vystup.json] [-n]
#   -n = vypis plan a skonci (root netreba)

set -uo pipefail
export LC_ALL=C          # EPOCHREALTIME musi mat desatinnu bodku

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || exit 1
BIN="$REPO/vmicollect/build/vmicollect"
PROBE="$REPO/data/results/2026-09-18_zmrazeny_host/probe.json"
DOMAIN="${VMIC_DOMAIN:-hyptcn-guest}"
GUEST_SSH="${VMIC_GUEST_SSH:-root@192.168.122.100}"

CYCLES=13                # cyklus 0 je plna snimka, 1..12 su delty
N_PY=10                  # opakovani na kazdy pripad Pythonovej referencie
BIN_BYTES=16777216       # 16 MiB - dohodnuty vychodzi bin
DRY=0
STAMP=$(date -u +%Y%m%d)
OUT="$REPO/data/results/latency_vector_${STAMP}.json"

# Snimky sa pisu na /var/tmp (plna snimka ma ~480 MiB), nie do scratchpadu -
# ten ma malu kvotu. Kazdy beh sa po odobrani sidecarov zmaze.
OUTBASE="${VMIC_LAT_OUTBASE:-/var/tmp/vmic-lat}"
WORK="${VMIC_LAT_WORK:-${TMPDIR:-/tmp}/vmic-lat-work}"

# plan behov: "variant interval" - variant je hodnota [features].enable
PLAN=("on 5.0" "off 5.0" "off 5.0" "on 5.0" "off 2.0" "on 2.0")

usage()
{
    sed -n '3,35p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -N|--cycles)  CYCLES="$2"; shift 2 ;;
        -p|--py)      N_PY="$2";   shift 2 ;;
        -o|--out)     OUT="$2";    shift 2 ;;
        -n|--dry-run) DRY=1;       shift ;;
        -h|--help)    usage ;;
        *) echo "neznamy parameter: $1" >&2; exit 2 ;;
    esac
done

die() { echo "measure_latency.sh: $*" >&2; exit 1; }

[ -x "$BIN" ]    || die "chyba binarka $BIN (make -C vmicollect)"
[ -f "$PROBE" ]  || die "chyba $PROBE - bez memslotov Pythonova referencia nepocita"
command -v inotifywait >/dev/null || die "chyba inotifywait (inotify-tools)"

echo "plan behov (cyklov: $CYCLES, bin: $BIN_BYTES B, writer delta, hash none):"
i=0
for entry in "${PLAN[@]}"; do
    i=$((i + 1))
    set -- $entry
    printf '  beh %d: features.enable=%-3s interval %s s\n' "$i" "$1" "$2"
done
echo "pythonova referencia: $N_PY opakovani na kazdy pripad"
echo "vystup: $OUT"
[ "$DRY" -eq 1 ] && exit 0

mkdir -p "$WORK/sidecars" "$OUTBASE" || die "nedaju sa vyrobit pracovne adresare"
rm -f "$WORK"/watch_*.txt "$WORK"/run_*.log "$WORK"/py_*.txt
rm -rf "${WORK:?}/sidecars"/*

# ------------------------------------------------------------------ prostredie
# Stav hosta sa cita PRED a PO merani, nikdy pocas neho: ssh do hosta je sam
# o sebe zataz (docs/MERANIA.md), a tu sa meria latencia, nie pozemna pravda.
guest_state()
{
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$GUEST_SSH" \
        'uname -r; cat /proc/loadavg; echo "procesov=$(ls -d /proc/[0-9]* | wc -l)"' \
        2>&1
}

{
    echo "== hostitel"; cat /proc/loadavg
    echo "== host"; guest_state
} > "$WORK/env_pred.txt" 2>&1

sha256sum "$BIN" > "$WORK/binarka.txt"

# ------------------------------------------------------------------ jeden beh
# Sledovac: inotifywait hlasi zavretie kazdeho zapisaneho suboru, citajuca
# slucka mu prilepi cas. Cas vznika az v slucke, takze obsahuje aj prechod
# rurou - namerana latencia je preto horny odhad, nie dolny.
run_one()
{
    local idx="$1" variant="$2" interval="$3"
    local dir="$OUTBASE/${idx}_${variant}_${interval}"
    local watch="$WORK/watch_${idx}.txt"
    local log="$WORK/run_${idx}.log"

    mkdir -p "$dir"
    : > "$watch"

    ( stdbuf -oL inotifywait -m -q -e close_write --format '%f' "$dir" |
      while IFS= read -r f; do printf '%s %s\n' "$EPOCHREALTIME" "$f"; done \
    ) >> "$watch" 2>/dev/null &
    sleep 1          # nech je sledovanie nastavene skor, nez padne prva snimka

    echo "beh $idx: features.enable=$variant, interval $interval s -> $dir"
    sudo -A "$BIN" run \
        -o vm.domain="$DOMAIN" \
        -o vm.backend=ebpf \
        -o output.writer=delta \
        -o output.dir="$dir" \
        -o output.hash=none \
        -o schedule.interval_s="$interval" \
        -o schedule.max_cycles="$CYCLES" \
        -o features.enable="$variant" \
        -o features.bin_bytes="$BIN_BYTES" \
        -o features.entropy=true \
        > "$log" 2>&1
    local rc=$?

    sleep 1          # posledny close_write este musi prejst rurou
    pkill -f "inotifywait -m -q -e close_write --format %f $dir" 2>/dev/null

    [ $rc -ne 0 ] && echo "  POZOR: beh $idx skoncil kodom $rc (log: $log)" >&2

    mkdir -p "$WORK/sidecars/$idx"
    cp "$dir"/*.json "$WORK/sidecars/$idx/" 2>/dev/null
    printf '%s %s %s\n' "$variant" "$interval" "$rc" > "$WORK/sidecars/$idx/VARIANT"

    # Snimky sa mazu hned - retazec 13 snimok ma cez 480 MiB a na disku uz nie
    # su na nic potrebne, cisla su v sidecaroch. Beh 1 si snimky necha na
    # Pythonovu referenciu a maze sa na konci skriptu.
    [ "$idx" != "1" ] && sudo -A rm -rf "$dir"
    return 0
}

idx=0
for entry in "${PLAN[@]}"; do
    idx=$((idx + 1))
    set -- $entry
    run_one "$idx" "$1" "$2"
done

KEEPDIR=$(ls -d "$OUTBASE"/1_* 2>/dev/null | head -1)

# --------------------------------------------------- pythonova referencia
# Tri pripady: plna snimka v repe, delta na konci kratkeho retazca (6 snimok)
# a delta na konci retazca z behu 1, teda nad tymi istymi datami, nad ktorymi
# vyrabal cisla C modul.
PY_CASES=("plna_snimka_repo|$REPO/data/sessions/20260918_validate2/snap"
          "delta_retazec6|/var/tmp/vmic-delta")
[ -n "$KEEPDIR" ] && PY_CASES+=("delta_retazec${CYCLES}_beh1|$KEEPDIR")

# Jeden zahrievaci beh na pripad sa zahadzuje a je to v reporte: prve citanie
# .vmicd ide z disku, dalsie z page cache, a miesat tieto dve veci do jedneho
# medianu by znamenalo merat stav cache, nie cenu vypoctu.
for c in "${PY_CASES[@]}"; do
    ( cd "$REPO" && python3 -m features perbin --snapshot "${c#*|}" \
          --memslots "$PROBE" --json > /dev/null 2>&1 )
done

for r in $(seq 1 "$N_PY"); do
    for c in "${PY_CASES[@]}"; do
        name="${c%%|*}"; path="${c#*|}"
        t0=$EPOCHREALTIME
        ( cd "$REPO" && python3 -m features perbin --snapshot "$path" \
              --memslots "$PROBE" --json > /dev/null 2>>"$WORK/py_err.txt" )
        rc=$?
        t1=$EPOCHREALTIME
        printf '%s %s %s %s\n' "$name" "$t0" "$t1" "$rc" >> "$WORK/py_casy.txt"
    done
done

{
    echo "== hostitel"; cat /proc/loadavg
    echo "== host"; guest_state
} > "$WORK/env_po.txt" 2>&1

[ -n "$KEEPDIR" ] && sudo -A rm -rf "$KEEPDIR"

# ------------------------------------------------------------------ vyhodnotenie
python3 - "$WORK" "$OUT" "$REPO" "$CYCLES" "$BIN_BYTES" "$N_PY" \
         "scripts/measure_latency.sh -N $CYCLES -p $N_PY" <<'PY'
"""Zlozi z watch logov, sidecarov a casov Pythonu jeden vysledkovy JSON."""
import datetime
import glob
import json
import math
import os
import re
import subprocess
import sys

work, out, repo, cycles, bin_bytes, n_py, command = sys.argv[1:8]
cycles, bin_bytes, n_py = int(cycles), int(bin_bytes), int(n_py)


def stat(xs, nd=3):
    """Median, p95, min, max, n. p95 je linearne interpolovana poradova
    statistika (ako numpy.percentile) - pri n radu desiatok je to odhad
    z dvoch najvyssich hodnot, nie hodnota s vlastnym intervalom."""
    if not xs:
        return {"n": 0, "median": None, "p95": None, "min": None, "max": None}
    s = sorted(xs)
    n = len(s)

    def q(p):
        if n == 1:
            return s[0]
        k = (n - 1) * p
        f, c = math.floor(k), math.ceil(k)
        return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)

    return {"n": n, "median": round(q(0.5), nd), "p95": round(q(0.95), nd),
            "min": round(s[0], nd), "max": round(s[-1], nd)}


# ---- casy zavretia sidecarov z inotify logov
close_at = {}
for wf in sorted(glob.glob(os.path.join(work, "watch_*.txt"))):
    idx = re.search(r"watch_(\d+)\.txt$", wf).group(1)
    for line in open(wf, encoding="utf-8"):
        parts = line.split()
        if len(parts) != 2 or not parts[1].endswith(".json"):
            continue
        close_at[(idx, parts[1])] = float(parts[0])

# ---- cykly zo sidecarov
cyklus = []
behy = []
for d in sorted(glob.glob(os.path.join(work, "sidecars", "*")),
                key=lambda p: int(os.path.basename(p))):
    idx = os.path.basename(d)
    variant, interval, rc = open(os.path.join(d, "VARIANT")).read().split()
    log = os.path.join(work, "run_%s.log" % idx)
    koniec = ""
    if os.path.exists(log):
        for line in open(log, encoding="utf-8", errors="replace"):
            if "koniec:" in line:
                koniec = line.strip()
    m = re.search(r"(\d+) zmeskanych slotov", koniec)
    behy.append({"beh": int(idx), "features_enable": variant,
                 "interval_s": float(interval), "navratovy_kod": int(rc),
                 "zmeskanych_slotov": int(m.group(1)) if m else None,
                 "riadok_koniec": koniec})
    for sf in sorted(glob.glob(os.path.join(d, "*.json"))):
        s = json.load(open(sf, encoding="utf-8"))
        name = os.path.basename(sf)
        t_close = close_at.get((idx, name))
        ft = s.get("features")
        rec = {
            "beh": int(idx),
            "features_enable": variant,
            "interval_s": float(interval),
            "seq": s["seq"],
            "plna": bool(s["output"]["full"]),
            "timestamp_unix": s["timestamp_unix"],
            "capture_ms": s["capture"]["capture_ms"],
            "write_ms": s["capture"]["write_ms"],
            "total_ms": s["capture"]["total_ms"],
            "compute_ms": ft.get("compute_ms") if ft else None,
            "bins_total": ft.get("bins_total") if ft else None,
            "pages_changed": s["output"]["pages_changed"],
            "sidecar_close_unix": t_close,
        }
        if t_close is not None:
            rec["latencia_ms"] = round((t_close - s["timestamp_unix"]) * 1000.0, 3)
            rec["sidecar_a_rezia_ms"] = round(rec["latencia_ms"] - rec["total_ms"], 3)
        cyklus.append(rec)

# ---- suhrn po skupinach
def sel(variant=None, interval=None, plna=None):
    r = cyklus
    if variant is not None:
        r = [c for c in r if c["features_enable"] == variant]
    if interval is not None:
        r = [c for c in r if c["interval_s"] == interval]
    if plna is not None:
        r = [c for c in r if c["plna"] == plna]
    return r


def skupina(rows):
    lat = [c["latencia_ms"] for c in rows if "latencia_ms" in c]
    return {
        "cyklov": len(rows),
        "latencia_ms": stat(lat),
        "total_ms": stat([c["total_ms"] for c in rows]),
        "capture_ms": stat([c["capture_ms"] for c in rows]),
        "write_ms": stat([c["write_ms"] for c in rows]),
        "compute_ms": stat([c["compute_ms"] for c in rows
                            if c["compute_ms"] is not None]),
        "sidecar_a_rezia_ms": stat([c["sidecar_a_rezia_ms"] for c in rows
                                    if "sidecar_a_rezia_ms" in c]),
        "pages_changed_median": stat([float(c["pages_changed"]) for c in rows],
                                     nd=1)["median"],
    }


suhrn = {}
for interval in sorted({c["interval_s"] for c in cyklus}):
    for variant in ("on", "off"):
        for plna, tag in ((False, "delta"), (True, "plna")):
            rows = sel(variant, interval, plna)
            if rows:
                suhrn["%s_%ss_%s" % (variant, interval, tag)] = skupina(rows)

# ---- cena priznakov: rozdiel medianu capture_ms on vs off (iba delta cykly)
cena = {}
for interval in sorted({c["interval_s"] for c in cyklus}):
    on = sel("on", interval, False)
    off = sel("off", interval, False)
    if not on or not off:
        continue
    c_on = stat([c["capture_ms"] for c in on])["median"]
    c_off = stat([c["capture_ms"] for c in off])["median"]
    l_on = stat([c["latencia_ms"] for c in on if "latencia_ms" in c])["median"]
    l_off = stat([c["latencia_ms"] for c in off if "latencia_ms" in c])["median"]
    cena["interval_%ss" % interval] = {
        "capture_ms_median_on": c_on,
        "capture_ms_median_off": c_off,
        "rozdiel_ms": round(c_on - c_off, 3),
        "latencia_ms_median_on": l_on,
        "latencia_ms_median_off": l_off,
        "rozdiel_latencie_ms": round(l_on - l_off, 3),
        "compute_ms_median_on": stat([c["compute_ms"] for c in on
                                      if c["compute_ms"] is not None])["median"],
        "n_on": len(on), "n_off": len(off),
    }

# ---- falzifikovatelne kriterium: p95 latencie cyklu < perioda
kriterium = []
for interval in sorted({c["interval_s"] for c in cyklus}):
    for variant in ("on", "off"):
        for tag, rows in (("vsetky cykly", sel(variant, interval)),
                          ("iba delta cykly", sel(variant, interval, False))):
            lat = [c["latencia_ms"] for c in rows if "latencia_ms" in c]
            if not lat:
                continue
            p95 = stat(lat)["p95"]
            kriterium.append({
                "interval_s": interval, "features_enable": variant,
                "rozsah": tag, "n": len(lat), "p95_ms": p95,
                "perioda_ms": interval * 1000.0,
                "plati": p95 < interval * 1000.0,
            })

# ---- pythonova referencia
py = {}
pf = os.path.join(work, "py_casy.txt")
if os.path.exists(pf):
    surove = {}
    for line in open(pf, encoding="utf-8"):
        name, t0, t1, rc = line.split()
        surove.setdefault(name, []).append(
            {"ms": round((float(t1) - float(t0)) * 1000.0, 3), "rc": int(rc)})
    for name, rows in surove.items():
        py[name] = stat([r["ms"] for r in rows])
        py[name]["navratove_kody"] = sorted({r["rc"] for r in rows})
        py[name]["surove_ms"] = [r["ms"] for r in rows]


def precitaj(p):
    return open(os.path.join(work, p), encoding="utf-8").read().strip() \
        if os.path.exists(os.path.join(work, p)) else None


def git(*a):
    try:
        return subprocess.check_output(["git", "-C", repo, *a], text=True).strip()
    except Exception:
        return None


os_name = ""
for line in open("/etc/os-release", encoding="utf-8"):
    if line.startswith("PRETTY_NAME="):
        os_name = line.split("=", 1)[1].strip().strip('"')
kernel = os.uname().release
env_pred = precitaj("env_pred.txt") or ""
guest_kernel = None
m = re.search(r"== host\n([^\n]+)", env_pred)
if m:
    guest_kernel = m.group(1).strip()

values = {
    "schema": "hyptcn3/latencia-vektor/1",
    "co_sa_meria": (
        "latencia od zaciatku cyklu zberu (sidecar.timestamp_unix) po zavretie "
        "sidecaru s blokom features na disku (inotify close_write). total_ms zo "
        "sidecaru zapis sidecaru neobsahuje - meria sa v collector.c pred nim."),
    "nastavenie": {
        "writer": "delta", "hash": "none", "bin_bytes": bin_bytes,
        "entropy": True, "cyklov_na_beh": cycles,
        "poradie_behov": [(b["features_enable"], b["interval_s"]) for b in behy],
    },
    "behy": behy,
    "suhrn": suhrn,
    "cena_priznakov": cena,
    "kriterium_p95_pod_periodou": kriterium,
    "python_referencia_ms": py,
    "prostredie": {
        "pred": env_pred,
        "po": precitaj("env_po.txt"),
        "binarka": precitaj("binarka.txt"),
        "poznamka": ("ssh do hosta sa pouzil iba pred a po merani; pocas "
                     "merania do hosta nesiahol nikto, lebo zber pozemnej "
                     "pravdy cez ssh je sam o sebe zataz (docs/MERANIA.md)"),
    },
    "cykly": cyklus,
}

doc = {
    "schema": "hyptcn3/vysledok-hlavicka/1",
    "schema_dat": "hyptcn3/latencia-vektor/1",
    "commit": git("rev-parse", "HEAD"),
    "commit_dirty": bool(git("status", "--porcelain")),
    "date": datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"),
    "host": "%s, jadro %s, hostname %s" % (os_name, kernel, os.uname().nodename),
    "guest": ("bezica libvirt domena hyptcn-guest (Debian 12, jadro %s), "
              "2 vCPU / 2,02 GiB; stav zatazenia pred a po merani je v "
              "values.prostredie" % (guest_kernel or "?")),
    "command": command,
    "n": len([c for c in cyklus if "latencia_ms" in c]),
    "n_poznamka": ("n = pocet cyklov zberu s nameranou latenciou (spolu cez "
                   "vsetky behy); rozpis po skupinach je vo values.suhrn"),
    "values": values,
}

os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=1, ensure_ascii=False)
    fh.write("\n")
print("zapisane: %s (cyklov s latenciou: %d)" % (out, doc["n"]))
for k in kriterium:
    print("  kriterium p95 < perioda | interval %.1f s | features %s | %s | "
          "p95 %.1f ms | %s"
          % (k["interval_s"], k["features_enable"], k["rozsah"], k["p95_ms"],
             "PLATI" if k["plati"] else "NEPLATI"))
PY
