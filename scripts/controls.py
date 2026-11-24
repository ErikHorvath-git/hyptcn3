"""The outcomes of one control occurrence on the VM (protocol v5, package B8).

Proposal 7.4 (docs/NAVRH_PROTOKOL_V5.sk.md): every control and its paired negative get three recorded outcomes,
the parser saw it, a column moved by the expected value and a channel reacted. outcomes() computes the first two
from the features of the session and supplies what package B7 needs for the third (proposal 4.2 row O4, 6.4; the
lead's skeleton dokazy/B8/kostra/KOSTRA.md, section 4):

    parser_saw      every measured row wholly inside the occurrence shows the control's object in the parser's
                    view, matching the guest's effect evidence; for a negative no such row shows it
    column_moved    for every column of controls.kinds.<kind>.columns the mean over the measured rows wholly inside
                    minus the mean over the measured rows among the REFERENCE_ROWS rows before the start reaches
                    the expected shift in its direction; for a negative every column stays below it
    sensor_scored   at least one scored row within the horizon: a row that ends a scorable window of the live
                    detector (safeguard.features.WindowBuffer through features.coverage.scorable_windows). B7 judges
                    channel_reacted on these rows; without one its result is "sensor did not score", reported
                    apart (O4), never a miss of the channel

Rows. A row taken at time t covers (t - interval_s, t]. Before the start: the REFERENCE_ROWS last rows with
t <= host_start_unix, when the start call began. Wholly inside: host_started_unix + interval_s <= t <=
host_stop_unix, from the end of the start call to the beginning of the stop call (the rule of the protocol v4
positive control, collection.positive_controls). Horizon: host_start_unix < t <= host_start_unix +
controls.horizon_s. A row is measured when it is valid under the protocol's quality policy, is no full snapshot
and has a predecessor: in a full snapshot the memory part describes the whole memory, and without a predecessor
proc_new, proc_gone and mod_delta are not measured (features/snapshot.py). Means use measured rows only.

The parser's view. The extraction result keeps the parser's process identities only for memory patterns
(quality.memory_patterns: pid, comm, kind); modules, sockets and the other processes are counts. The W+X and memfd
control is therefore matched by pid with effect.evidence.members, every other kind by the count of its object
against the mean of the measured rows before the start: one module more (mod_total), one listening socket more
(sock_listen), at least one new PID more (proc_new), and the writer's size: the changed bytes of the row
(mem_changed_ratio times the memory of the bins it is a share of) above the reference by at least the dose in MiB.
Under a protocol of schema 3 mem_changed_ratio counts only the bins of at least analysis.scale.min_bin_pages pages
(features/snapshot.py counted_bin, the lead's answer to Q10), so their pages times the page size are that memory;
under schemas 1 and 2 every bin of the layout (V1 of dokazy/B11/odlozene_B11.md, package B10). Module names and ports
are G2's ground truth (proposal 10.3: ps, lsmod and ss in the guest against the parser).

Polarity. ok is the outcome a faultless occurrence of its polarity gives, as with the guest's effect predicate
(skeleton section 2): a control is seen and its columns reach their expected shift; a negative is seen in no row
and its columns stay below the shift its control is expected to reach (contract 1.1 gives each column one shift
and one direction, so that shift is the negative's tolerance). ok is None when the outcome cannot be judged, and
`why` says why: no measured row wholly inside or none before the start, or (parser_saw only) the guest's effect
predicate did not hold or its evidence names no process of the W+X and memfd control (nothing to match).

The sealed role. Results 1 and 2 are computed from features, so a session of role test_controls is opened only as
the seal of package B7c lets it (tcn/pecat.py; finding S4 of the verification of B8: the stage the caller states no
longer opens it), otherwise ValueError before any data is read:
  - final_evaluation=True is given only by the final command: a final run must be open in this process (tcn.pecat
    otvoreny, after spotrebuj); the archive, when named, must be one of its run or not sealed;
  - otherwise a record of stage "final" (proposal 11.1) stays refused, and at the stages suchy, skuska and generalka
    (G1, G2, G3a and G3b) the caller names the session's feature archive (archive=): the ledger refuses a sealed
    archive of a campaign and lets a rehearsal's through with its mark; an archive the ledger does not hold is not
    sealed (G1 and G2 data never become a dataset, skeleton B8 section 4).
Every result carries the decision under "seal". A role is one of the protocol's, pilot or diagnostic, so that a
misspelt role opens nothing.

Accepted inputs: the record of one occurrence in controls.json (contract 1.4 of design B8: its class and the
plan's polarity, kind, dose, executed, baseline, effect, and the runner's host times as in events.json), the
extraction result of the session or its loaded feature archive (features/snapshot.retazec, features/archive.load)
and the protocol. An occurrence that did not run (not executed, or without the return predicate) has no outcomes.
"""
import json
import math
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.coverage import scorable_windows  # noqa: E402
from features.snapshot import MENA, counted_bin  # noqa: E402
from scripts.protocol_v5 import CONTROL_ROLE, SCHEMA as SCHEMA_3  # noqa: E402

SCHEMA = "hyptcn3/control-outcomes/1"
# Skeleton B8 section 4 point 2: the mean of the 12 rows before the start (the lead's judgment, proposal 10.9).
REFERENCE_ROWS = 12
# Proposal 11.1: the stage of every record; only a record of stage final holds sealed data.
STAGES = ("suchy", "skuska", "generalka", "final")
# Roles outside the plan (features/acceptance.py assignment); the plan's roles are the protocol's.
UNPLANNED_ROLES = ("pilot", "diagnostic")
# The class of a record (contract 1.4) and the polarity of a plan item (contract 1.2), as one polarity.
RECORD_CLASSES = {"control": "control", "control_negative": "negative"}
POLARITIES = ("control", "negative")
DIRECTIONS = ("up", "down")
ROW_FLAGS = ("ma_predchodcu", "je_plna")
MIB = 1 << 20
# The object of each kind in the parser's view (module docstring). WX_MEMFD: the patterns of one process
# (guestparse/view.py memory_patterns; collection.CONTROL_KINDS of the v4 positive control). COUNTED: the column
# of the object's count and how many more than the reference rows show it. WRITER: the dose in MiB of changed bytes.
WX_MEMFD_KIND = "kontrola_wx_memfd"
WX_MEMFD = frozenset({"wx", "memfd_fd"})
COUNTED = {"kontrola_modul_jadra": ("mod_total", 1), "kontrola_pocuvajuci_soket": ("sock_listen", 1),
           "kontrola_davka_procesov": ("proc_new", 1)}
WRITER_KIND = "kontrola_zapisovac_pamate"
KINDS = (WX_MEMFD_KIND, *COUNTED, WRITER_KIND)


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _positive(value):
    return _number(value) and value > 0


# The entry point in a refusal of the seal (tcn/pecat.py kontrola).
PURPOSE = "scripts/controls.py outcomes of a control of role test_controls"
IN_RUN_RULE = ("final_evaluation=True inside the final run of this process (tcn/pecat.py spotrebuj): the run's seal "
               "covers the outcomes of its sessions; the caller named no archive")


def _seal(protocol, role, stage, final_evaluation, archive):
    """The decision of the seal (module docstring), or ValueError unless the caller may read the features of a session
    of this role at this stage."""
    if stage not in STAGES:
        raise ValueError(f"unknown stage of the record: {stage!r} (proposal 11.1: {', '.join(STAGES)})")
    if role not in UNPLANNED_ROLES and role not in protocol["roles"]:
        raise ValueError(f"unknown session role: {role!r}")
    if role != CONTROL_ROLE:
        return {"sealed": False, "rule": f"role {role} is no sealed role (tcn/pecat.py SEALED_ROLES)"}
    from tcn import pecat
    if final_evaluation is True:
        run = pecat.otvoreny()
        if run is None:
            raise ValueError("sealed role test_controls: final_evaluation=True is given only by the final command "
                             "(tcn/pecat.py spotrebuj); no final run is open in this process")
        if archive is None:
            return {"sealed": True, "allowed": "final_run", "identity": run.identity, **run.mark, "rule": IN_RUN_RULE}
        return pecat.kontrola(archive, purpose=PURPOSE)
    if stage == "final":
        raise ValueError("sealed role test_controls: only the final evaluation computes the outcomes of its "
                         "controls (final_evaluation=True)")
    if archive is None:
        raise ValueError(f"sealed role test_controls: at stage {stage} the outcomes name the session's feature archive "
                         "(archive=), so that the ledger (tcn/pecat.py) decides whether it is sealed, not the stage "
                         "the caller states")
    return pecat.kontrola(archive, purpose=PURPOSE)


def _spec(protocol, kind):
    """controls.kinds.<kind> of the protocol as outcomes() reads it (contract 1.1); ValueError names the key."""
    kinds = protocol["controls"]["kinds"]
    if kind not in kinds:
        raise ValueError(f"unknown control kind: {kind!r}")
    if kind not in KINDS:
        raise ValueError(f"no object in the parser's view for control kind {kind!r}")
    spec, where = kinds[kind], "controls.kinds." + kind
    if spec.get("class") not in ("A", "B"):
        raise ValueError(where + ".class: needs A or B")
    columns, doses, expect = spec.get("columns"), spec.get("doses"), spec.get("expect")
    if (type(columns) is not list or not columns or len(set(columns)) != len(columns)
            or not all(c in MENA and c not in ROW_FLAGS for c in columns)):
        raise ValueError(where + ".columns: needs distinct feature columns of features.snapshot.MENA")
    if not (doses is None if spec["class"] == "A" else type(doses) is list and doses
            and len(set(doses)) == len(doses) and all(_positive(d) for d in doses)):
        raise ValueError(where + ".doses: class A has none (null), class B distinct positive doses")
    if type(expect) is not dict or set(expect) != set(columns):
        raise ValueError(where + ".expect: needs one expectation for each of its columns")
    for column, e in expect.items():
        shift = e.get("shift") if type(e) is dict else None
        per_dose = spec["class"] == "B" and type(shift) is list and len(shift) == len(doses)
        if (type(e) is not dict or e.get("direction") not in DIRECTIONS
                or not (_positive(shift) or per_dose and all(_positive(x) for x in shift))):
            raise ValueError(f"{where}.expect.{column}: needs a positive shift (class B: or one per dose) and the "
                             f"direction up or down")
    return spec


def _polarity(record, spec, kind):
    """The polarity of the record: its class (contract 1.4) and its polarity (contract 1.2) name exactly one; a class
    A or B is the kind's class of the plan item, no polarity."""
    cls, polarity = record.get("class"), record.get("polarity")
    marks = {RECORD_CLASSES.get(cls, None if cls in (None, spec["class"]) else "?"),
             polarity if polarity in (None, *POLARITIES) else "?"} - {None}
    if len(marks) != 1 or "?" in marks:
        raise ValueError(f"{kind}: the record names no polarity, two or an unknown one (class {cls!r}, polarity "
                         f"{polarity!r})")
    return marks.pop()


def _occurrence(record, protocol):
    """(kind, polarity, spec, dose, expected {column: (shift, direction)}, effect, (start, started, stop)) of an
    occurrence that ran; ValueError for one that did not or for a malformed record."""
    kind = record.get("kind")
    spec = _spec(protocol, kind)
    polarity = _polarity(record, spec, kind)
    dose = record.get("dose")
    if not (dose is None if spec["class"] == "A" else _number(dose) and dose in spec["doses"]):
        raise ValueError(f"{kind}: dose {dose!r} is not one of the kind's doses {spec['doses']}")
    if record.get("executed") is not True:
        raise ValueError("control not executed: " + kind)
    baseline = record.get("baseline")
    if type(baseline) is not dict or baseline.get("ok") is not True:
        raise ValueError("control without baseline: " + kind)  # Skeleton section 3: it never started.
    effect = record.get("effect")
    if type(effect) is not dict or type(effect.get("ok")) is not bool:
        raise ValueError("control without a well-formed effect: " + kind)
    times = tuple(record.get(key) for key in ("host_start_unix", "host_started_unix", "host_stop_unix"))
    if not all(_number(t) for t in times) or not times[0] <= times[1] <= times[2]:
        raise ValueError("control without ordered host times: " + kind)
    expected = {}
    for column in spec["columns"]:
        e = spec["expect"][column]
        shift = e["shift"][spec["doses"].index(dose)] if type(e["shift"]) is list else e["shift"]
        expected[column] = (shift, e["direction"])
    return kind, polarity, spec, dose, expected, effect, times


def _table(result):
    """(seq, times, measured mask, matrix, quality, layout) of an extraction result or a loaded feature archive
    whose shape scorable_windows has checked."""
    quality = json.loads(str(result["quality_json"])) if "quality_json" in result else result["quality"]
    layout = json.loads(str(result["layout_json"])) if "layout_json" in result else result["layout"]
    matrix = np.asarray(result["matica"], dtype=np.float64)
    measured = (np.asarray(result["valid"], dtype=bool) & (matrix[:, MENA.index("je_plna")] == 0)
                & (matrix[:, MENA.index("ma_predchodcu")] == 1))
    return ([int(s) for s in result["seq"]], [float(t) for t in result["casy"]], measured.tolist(), matrix, quality,
            layout)


def _mean(matrix, rows, column):
    return math.fsum(matrix[i, MENA.index(column)] for i in rows) / len(rows)


def _patterns(quality_row):
    """{pid: kinds} of the memory patterns of one row; a row quality without them is no parser view of patterns."""
    if type(quality_row) is not dict or type(quality_row.get("memory_patterns")) is not list:
        raise ValueError("row quality without memory_patterns (features/snapshot.py, snapshot-vektor/4)")
    out = {}
    for pattern in quality_row["memory_patterns"]:
        out.setdefault(pattern["pid"], set()).add(pattern["kind"])
    return out


def _counted(protocol):
    """The min_bin_pages of the bins mem_changed_ratio is a share of (module docstring): analysis.scale.min_bin_pages
    under schema 3, None (every bin) under schemas 1 and 2; a schema-3 protocol without it is refused by name."""
    if protocol.get("schema") != SCHEMA_3:
        return None
    try:
        return protocol["analysis"]["scale"]["min_bin_pages"]
    except (KeyError, TypeError):
        raise ValueError("protocol schema 3 without analysis.scale.min_bin_pages: the bins of mem_changed_ratio "
                         "cannot be told (features/snapshot.py counted_bin)") from None


def _parser_saw(kind, polarity, dose, effect, rows, reference, matrix, quality, layout, seq, protocol):
    out = {"ok": None, "rows": [seq[i] for i in rows], "showing": [], "object": None, "why": None}
    if effect["ok"] is not True:
        out["why"] = "the guest's effect predicate did not hold"
        return out
    if not rows:
        out["why"] = "no measured row wholly inside the occurrence"
        return out
    if kind == WX_MEMFD_KIND:
        evidence = effect.get("evidence")
        pids = evidence.get("members") if type(evidence) is dict else None
        if type(pids) is not list or not pids or not all(type(pid) is int for pid in pids):
            out["why"] = "the effect evidence names no process (members)"
            return out
        out["object"] = {"pids": sorted(pids), "patterns": sorted(WX_MEMFD)}

        def shows(i):
            return any(WX_MEMFD <= kinds for pid, kinds in _patterns(quality[i]).items() if pid in pids)
    else:
        if not reference:
            out["why"] = "no measured row among the rows before the start"
            return out
        if kind == WRITER_KIND:
            min_bin_pages = _counted(protocol)
            counted = [pages for _, pages in layout["bins"] if counted_bin(pages, min_bin_pages)]
            if not counted:  # The extractor refuses such a snapshot; a result of one is refused here as well.
                raise ValueError(f"{kind}: no bin of the layout has at least min_bin_pages {min_bin_pages} pages, so "
                                 "mem_changed_ratio is a share of no memory (features/snapshot.py counted_bin)")
            memory = sum(counted) * layout["page_size"]
            ratio = MENA.index("mem_changed_ratio")
            base = _mean(matrix, reference, "mem_changed_ratio") * memory
            out["object"] = {"column": "mem_changed_ratio", "memory_bytes": memory, "min_bin_pages": min_bin_pages,
                             "bins": len(counted), "reference_bytes": base, "dose_bytes": dose * MIB}

            def shows(i):
                return matrix[i, ratio] * memory - base >= dose * MIB
        else:
            column, more = COUNTED[kind]
            base = _mean(matrix, reference, column)
            out["object"] = {"column": column, "reference": base, "more": more}

            def shows(i):
                return matrix[i, MENA.index(column)] - base >= more
    out["showing"] = [seq[i] for i in rows if shows(i)]
    out["ok"] = len(out["showing"]) == len(rows) if polarity == "control" else not out["showing"]
    return out


def _column_moved(polarity, expected, rows, reference, matrix, seq):
    out = {"ok": None, "reference": [seq[i] for i in reference], "columns": {}, "why": None}
    if not rows:
        out["why"] = "no measured row wholly inside the occurrence"
        return out
    if not reference:
        out["why"] = "no measured row among the rows before the start"
        return out
    for column, (shift, direction) in expected.items():
        reference_mean, inside_mean = _mean(matrix, reference, column), _mean(matrix, rows, column)
        moved = inside_mean - reference_mean
        out["columns"][column] = {"reference_mean": reference_mean, "inside_mean": inside_mean, "shift": moved,
                                  "expect": shift, "direction": direction,
                                  "reached": (moved if direction == "up" else -moved) >= shift}
    reached = [c["reached"] for c in out["columns"].values()]
    out["ok"] = all(reached) if polarity == "control" else not any(reached)
    return out


def outcomes(record, result, protocol, *, role, archive=None, final_evaluation=False, stage="final"):
    """The outcomes of one control occurrence (module docstring) as one JSON-ready object.

    record: the occurrence's record in the session's controls.json; result: the session's extraction result or
    its loaded feature archive; protocol: the loaded protocol; role: the session's role; archive: the path of the
    session's feature archive (the seal looks it up in the ledger: required for role test_controls outside the final
    run); stage: the stage of the record (proposal 11.1), final unless the caller says otherwise; final_evaluation:
    True only from the final command (G6), inside its run. Raises ValueError for the sealed role as the seal refuses
    it (module docstring), for an occurrence that did not run (not executed, no return to the baseline), for a
    malformed record or controls section and for an extraction result that does not cover the occurrence.
    """
    seal = _seal(protocol, role, stage, final_evaluation, archive)
    kind, polarity, spec, dose, expected, effect, (start, started, stop) = _occurrence(record, protocol)
    # The one rule of scored rows: the windows the live detector scores. It also checks the result's shape (schema,
    # names, quality policy, row counts, validity against quality, increasing seq and time) before it is indexed.
    windows, _ = scorable_windows(result, protocol, "control-" + kind, int(max(result["seq"])) + 1)
    scored = {int(m["seq_do"]) for m in windows.meta}
    seq, times, measured, matrix, quality, layout = _table(result)
    if not times[0] <= start <= stop <= times[-1]:
        raise ValueError(f"the extraction result does not cover the occurrence of {kind}")
    interval, horizon_s = protocol["interval_s"], protocol["controls"]["horizon_s"]
    before = [i for i, t in enumerate(times) if t <= start][-REFERENCE_ROWS:]
    inside = [i for i, t in enumerate(times) if started + interval <= t <= stop]
    horizon = [i for i, t in enumerate(times) if start < t <= start + horizon_s]
    rows = [i for i in inside if measured[i]]
    reference = [i for i in before if measured[i]]
    return {
        "schema": SCHEMA, "kind": kind, "class": spec["class"], "polarity": polarity, "dose": dose,
        "window": {"start_unix": start, "started_unix": started, "stop_unix": stop,
                   "horizon_end_unix": start + horizon_s,
                   "before": [seq[i] for i in before], "inside": [seq[i] for i in inside],
                   "horizon": [seq[i] for i in horizon], "scored": [seq[i] for i in horizon if seq[i] in scored]},
        "parser_saw": _parser_saw(kind, polarity, dose, effect, rows, reference, matrix, quality, layout, seq,
                                  protocol),
        "column_moved": _column_moved(polarity, expected, rows, reference, matrix, seq),
        "sensor_scored": any(seq[i] in scored for i in horizon),
        "seal": seal,
    }
