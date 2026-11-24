#!/bin/bash
# The evidence of the G0 record (docs/HARNESS_V5.sk.md chapter 2: the evidence of a criterion is the path of a file
# that a command made, never text typed by hand). Runs alone in the main repository, after B10 is in origin.
# Every log starts with its provenance: commit, date, host and the command.
set -u
cd /home/eh/projects/hyptcn3 || exit 2
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
D=data/results/g0_$STAMP
mkdir -p $D
# The record's command names this copy, so the script that made the directory is kept beside what it made.
cp "$0" $D/g0_dokazy.sh
PY=.venv/bin/python
HEAD=$(git rev-parse HEAD)
hlavicka() { echo "# commit $HEAD"; echo "# date $(date -u +%FT%TZ)"; echo "# host $(hostname)"; echo "# command $1"; }
clean_tmp() { for d in /tmp/pytest-of-eh/pytest-*; do [ -d "$d" ] && rm -rf "$d"; done; }
# tests: the whole suite, then the claims check (both runs keep about 2.7 GB under /tmp, so clean between them)
C="python3 -m pytest -q -p no:cacheprovider"
{ hlavicka "$C"; nice -n 19 $PY -m pytest -q -p no:cacheprovider 2>&1 | tail -40; echo "exit ${PIPESTATUS[0]}"; } > $D/pytest.log
clean_tmp
C="bash scripts/check_claims.sh"
{ hlavicka "$C"; nice -n 19 bash scripts/check_claims.sh 2>&1 | tail -20; echo "exit ${PIPESTATUS[0]}"; } > $D/check_claims.log
clean_tmp
# protocol_selfcheck: both plan modes at stage G0
for m in campaign rehearsal; do
  C="python3 scripts/collection.py --protocol config/collection-v5.json selfcheck --mode $m --stage G0"
  { hlavicka "$C"; nice -n 19 $PY scripts/collection.py --protocol config/collection-v5.json selfcheck --mode $m --stage G0 2>&1; echo "exit $?"; } > $D/selfcheck_$m.log
done
# audit_selftest: the record that require_selftest accepts for this protocol file, measurement code and cases
REQ='from scripts.audit_selftest import require_selftest; d = require_selftest("config/collection-v5.json"); print({k: d[k] for k in ("date", "commit", "n", "passed", "protocol_sha256", "measurement_sha256", "cases_sha256")})'
C="python3 -c '$REQ'"
{ hlavicka "$C"; nice -n 19 $PY -B -c "$REQ" 2>&1; echo "exit $?"; } > $D/audit_selftest_require.log
# corpus_to_training, analysis_plan_bound, test_sealed, audit_probes_reproduced: the tests of the probe table's rows
nice -n 19 $PY -B - "$D" <<'PYEOF'
import importlib.util, json, subprocess, sys
from pathlib import Path
d = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("audit_probes", "scripts/tests/audit_probes.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
# Each criterion: the ids of its row of the probe table, then the whole test files of the package that built it
# (B1 the corpus handover; B7c the seal and the one final command). Separate runs, so no test is collected twice.
pick = {"corpus_to_training": (("process", "R1"), ["tcn/tests/test_odovzdanie_korpusu.py"]),
        "analysis_plan_bound": (("model", "M9"), []),
        "test_sealed": (("model", "M5"), ["tcn/tests/test_pecat.py", "tcn/tests/test_finalne.py"])}
head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
for name, (risk, files) in pick.items():
    row = next(r for r in m.ROWS if risk in r.risks)
    text = f"# commit {head}\n# row {row.number} of scripts/tests/audit_probes.py: {row.risks}\n"
    for part in ([*row.tests], *([f] for f in files)):
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *part]
        out = subprocess.run(["nice", "-n", "19", *cmd], capture_output=True, text=True)
        text += (f"# command python3 {' '.join(cmd[1:])}\n{out.stdout[-4000:]}{out.stderr[-2000:]}"
                 f"exit {out.returncode}\n")
        print(name, "row", row.number, "part", part[0] if len(part) == 1 else f"{len(part)} ids", "exit", out.returncode)
    (d / f"{name}.log").write_text(text)
PYEOF
C="python3 -m pytest -q -p no:cacheprovider scripts/tests/test_audit_probes.py"
{ hlavicka "$C"; nice -n 19 $PY -m pytest -q -p no:cacheprovider scripts/tests/test_audit_probes.py 2>&1 | tail -20; echo "exit ${PIPESTATUS[0]}"; } > $D/audit_probes.log
clean_tmp
cp /home/eh/hyptcn3-logs/v5/dokazy/B10/pred_po_zlucene/SUHRN.md $D/audit_probes_pred_po_SUHRN.md
echo "# $(date -u +%FT%TZ) evidence in $D"; ls -la $D; grep -h "^exit" $D/*.log
