#!/bin/bash
# Supplementary evidence of the G0 record, on the suggestions of the G0 verifier (dokazy/G0/overenie/vysledok.json):
# - protocol_selfcheck: the test that the self-check fails on each deliberate error, every id listed;
# - analysis_plan_bound: every test that training reads the analysis plan and refuses each given parameter;
# - audit_probes_reproduced: the machine records of B10's before and after (dokazy/B10/pred_po_zlucene/), copied.
#   The JSON ones are wrapped in check E's provenance header, the original kept whole under "values".
# Runs alone in the main repository, on the commit of g0_dokazy.sh, before the record. Every log header carries
# the commit, the date, the host, git status --porcelain and the command exactly as it runs.
set -u
cd /home/eh/projects/hyptcn3 || exit 2
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
D=data/results/g0_doplnok_$STAMP
mkdir -p $D
cp "$0" $D/g0_doplnok.sh
HEAD=$(git rev-parse HEAD)
hlavicka() {
  echo "# commit $HEAD"; echo "# date $(date -u +%FT%TZ)"; echo "# host $(hostname)"
  echo "# git status --porcelain (untracked evidence directories only, when clean):"
  git status --porcelain | sed 's/^/#   /'
  echo "# command $1"
}
beh() {  # $1 log name, then the command; the log gets the header, the whole output and the exit code
  local log=$1; shift
  { hlavicka "$*"; "$@" 2>&1; echo "exit $?"; } > $D/$log
}
beh selfcheck_errors.log nice -n 19 .venv/bin/python -B -m pytest -v -p no:cacheprovider \
  "scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error"
beh analysis_plan_bound_all.log nice -n 19 .venv/bin/python -B -m pytest -v -p no:cacheprovider \
  "safeguard/tests/test_training.py::test_analysis_parameters_are_refused_by_name" \
  "safeguard/tests/test_training.py::test_analysis_parameters_come_from_the_plan_and_overrides_are_recorded" \
  "tcn/tests/test_odovzdanie_korpusu.py::test_trening_berie_parametre_z_planu_analyzy" \
  "tcn/tests/test_odovzdanie_korpusu.py::test_porovnanie_berie_parametre_z_planu_analyzy"
for d in /tmp/pytest-of-eh/pytest-*; do [ -d "$d" ] && [ ! -L "$d" ] && rm -rf "$d"; done
SRC=/home/eh/hyptcn3-logs/v5/dokazy/B10/pred_po_zlucene
mkdir -p $D/b10_pred_po/sondy
cp -p $SRC/pred.log $SRC/pred.xml $SRC/po.log $SRC/po.xml $SRC/SUHRN.md $D/b10_pred_po/
cp -p $SRC/sondy/*.out $D/b10_pred_po/sondy/
.venv/bin/python -I -B - "$SRC" "$D/b10_pred_po" "$HEAD" <<'PYEOF'
import hashlib, json, socket, sys
from datetime import datetime, timezone
from pathlib import Path
src, out, head = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
for name in ("ids.json", "pred_runs.json", "pred_later.json"):
    raw = (src / name).read_bytes()
    values = json.loads(raw)
    doc = {"schema": "hyptcn3/g0-copy/1", "commit": head, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "host": socket.gethostname(),
           "guest": "none: a machine record of B10's before and after, made without a VM",
           "command": f"dokazy/G0/g0_doplnok.sh: a copy of {src / name}",
           "n": len(values), "source": str(src / name), "source_sha256": hashlib.sha256(raw).hexdigest(),
           "source_made_by": "dokazy/B10/pred_po/pred_po.py --tree <merge clone of B10 at e5f7954>, whose code equals "
                             "ecbc04a's (git diff e5f7954 ecbc04a: only docs/PRIRUCKA.md and the self-test record)",
           "values": values}
    (out / name).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
PYEOF
{ hlavicka "sha256sum of every copied file and its source"; (cd $SRC && sha256sum pred.log pred.xml po.log po.xml SUHRN.md sondy/*.out ids.json pred_runs.json pred_later.json); echo "# the copies (the three JSON files are wrapped, so their own sha256 differs; source_sha256 is inside):"; (cd $D/b10_pred_po && sha256sum pred.log pred.xml po.log po.xml SUHRN.md sondy/*.out); echo "exit 0"; } > $D/b10_pred_po/MANIFEST.log
echo "# $(date -u +%FT%TZ) supplementary evidence in $D"; ls -la $D $D/b10_pred_po; grep -h "^exit" $D/*.log
