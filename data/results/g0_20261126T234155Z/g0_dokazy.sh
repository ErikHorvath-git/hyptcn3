#!/bin/bash
# The evidence of the fifth G0 record, after package B15 (should_fix 1 of the fourth G0 verification and Q79, the
# executor's decision without the lead: the order share's stop in the generator's monotonic time, and the log audit
# binds the request log's end_mono). Runs alone in the main repository on the committed tree, while no G2 measurement
# runs. Every log starts with its provenance (commit, date, host, git status --porcelain and the command exactly as it
# runs: S2 of the first G0 verification) and ends with its exit code. The same commands as dokazy/G0/g0_dokazy4.sh.
# Both whole suites keep their temporary files in the tmpfs /tmp, as before. On the disk the whole suite took 3 h 23 min
# (dokazy/B15/suite_057550e_disk.log), longer than the 3600 s scripts/gen_prirucka.py gives the suite of check F, and
# PYTEST_ADDOPTS would hand one basetemp to the nested pytest runs of the tests. In /tmp the whole suite of B15 on
# 057550e failed for lack of space while other work of the host used /tmp (dokazy/B15/suite_057550e.log), so the
# script starts only with 4.5 GB free there (each whole suite keeps about 2.7 GB).
set -u
cd /home/eh/projects/hyptcn3 || exit 2
FREE=$(df --output=avail -B1 /tmp | tail -n 1)
[ "$FREE" -ge 4500000000 ] || { echo "only $FREE bytes free in /tmp, 4.5 GB needed"; exit 2; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
D=data/results/g0_$STAMP
mkdir -p $D
cp "$0" $D/g0_dokazy.sh
HEAD=$(git rev-parse HEAD)
PY=.venv/bin/python
hlavicka() {
  echo "# commit $HEAD"; echo "# date $(date -u +%FT%TZ)"; echo "# host $(hostname)"
  echo "# git status --porcelain (only this evidence directory, when clean):"
  git status --porcelain | sed 's/^/#   /'
  echo "# command $*"
}
beh() {  # $1 log name, then the command; the log gets the header, the whole output and the exit code
  local log=$1; shift
  { hlavicka "$@"; "$@" 2>&1; echo "exit $?"; } > $D/$log
}
clean_tmp() { for d in /tmp/pytest-of-eh/pytest-*; do [ -d "$d" ] && [ ! -L "$d" ] && rm -rf "$d"; done; }
# tests: the whole suite, then the claims check (each keeps about 2.7 GB under /tmp, so clean between them)
beh pytest.log nice -n 19 $PY -m pytest -q -p no:cacheprovider
clean_tmp
beh check_claims.log nice -n 19 bash scripts/check_claims.sh
clean_tmp
# protocol_selfcheck: both plan modes at stage G0, and every deliberate error of the self-check by id
for m in campaign rehearsal; do
  beh selfcheck_$m.log nice -n 19 $PY -B scripts/collection.py --protocol config/collection-v5.json selfcheck --mode $m --stage G0
done
beh selfcheck_errors.log nice -n 19 $PY -B -m pytest -v -p no:cacheprovider \
  "scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error"
# audit_selftest: the record that require_selftest accepts for this protocol file, measurement code and cases
REQ='from scripts.audit_selftest import require_selftest; d = require_selftest("config/collection-v5.json"); print({k: d[k] for k in ("date", "commit", "n", "passed", "protocol_sha256", "measurement_sha256", "cases_sha256")})'
beh audit_selftest_require.log nice -n 19 $PY -B -c "$REQ"
# corpus_to_training, analysis_plan_bound, test_sealed: the ids of their rows of the probe table, then whole files
riadok() {  # the test ids of the row of the probe table that holds the risk ($1 class, $2 id), one per line
  $PY -I -B - "$1" "$2" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("audit_probes", "scripts/tests/audit_probes.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
row = next(r for r in m.ROWS if (sys.argv[1], sys.argv[2]) in r.risks)
print(row.number); print("\n".join(row.tests))
PYEOF
}
for spec in "corpus_to_training process R1" "analysis_plan_bound model M9" "test_sealed model M5"; do
  set -- $spec; name=$1
  mapfile -t lines < <(riadok $2 $3)
  echo "# row ${lines[0]} of scripts/tests/audit_probes.py, risk $2 $3" > $D/${name}_row.txt
  beh ${name}_row.log nice -n 19 $PY -B -m pytest -q -p no:cacheprovider "${lines[@]:1}"
done
beh corpus_to_training_file.log nice -n 19 $PY -B -m pytest -q -p no:cacheprovider tcn/tests/test_odovzdanie_korpusu.py
beh analysis_plan_bound_all.log nice -n 19 $PY -B -m pytest -v -p no:cacheprovider \
  "safeguard/tests/test_training.py::test_analysis_parameters_are_refused_by_name" \
  "safeguard/tests/test_training.py::test_analysis_parameters_come_from_the_plan_and_overrides_are_recorded" \
  "tcn/tests/test_odovzdanie_korpusu.py::test_trening_berie_parametre_z_planu_analyzy" \
  "tcn/tests/test_odovzdanie_korpusu.py::test_porovnanie_berie_parametre_z_planu_analyzy"
beh test_sealed_pecat.log nice -n 19 $PY -B -m pytest -q -p no:cacheprovider tcn/tests/test_pecat.py
beh test_sealed_finalne.log nice -n 19 $PY -B -m pytest -q -p no:cacheprovider tcn/tests/test_finalne.py
# audit_probes_reproduced: the table's own test (every id of the table passes today), and B10's before and after
beh audit_probes.log nice -n 19 $PY -B -m pytest -q -p no:cacheprovider scripts/tests/test_audit_probes.py
clean_tmp
SRC=/home/eh/hyptcn3-logs/v5/dokazy/B10/pred_po_zlucene
mkdir -p $D/b10_pred_po/sondy
cp -p $SRC/pred.log $SRC/pred.xml $SRC/po.log $SRC/po.xml $SRC/SUHRN.md $D/b10_pred_po/
cp -p $SRC/sondy/*.out $D/b10_pred_po/sondy/
$PY -I -B - "$SRC" "$D/b10_pred_po" "$HEAD" <<'PYEOF'
import hashlib, json, socket, sys
from datetime import datetime, timezone
from pathlib import Path
src, out, head = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
for name in ("ids.json", "pred_runs.json", "pred_later.json"):
    raw = (src / name).read_bytes()
    values = json.loads(raw)
    doc = {"schema": "hyptcn3/g0-copy/1", "commit": head, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "host": socket.gethostname(), "guest": "none: a machine record of B10's before and after, made without a VM",
           "command": f"dokazy/G0/g0_dokazy5.sh: a copy of {src / name}", "n": len(values), "source": str(src / name),
           "source_sha256": hashlib.sha256(raw).hexdigest(),
           "source_made_by": "dokazy/B10/pred_po/pred_po.py --tree <merge clone of B10 at e5f7954>", "values": values}
    (out / name).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
PYEOF
{ hlavicka "sha256sum of every copied file and of its source"; (cd $SRC && sha256sum pred.log pred.xml po.log po.xml SUHRN.md sondy/*.out ids.json pred_runs.json pred_later.json); echo "# the copies (the three JSON files are wrapped; source_sha256 is inside):"; (cd $D/b10_pred_po && sha256sum pred.log pred.xml po.log po.xml SUHRN.md sondy/*.out); echo "exit 0"; } > $D/b10_pred_po/MANIFEST.log
echo "# $(date -u +%FT%TZ) evidence in $D"; ls -la $D; grep -h "^exit" $D/*.log | sort | uniq -c
