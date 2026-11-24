"""The bad sessions of the audit self-test, RAM side (protocol v5, package B3; proposal 6.2).

clean_session() builds one planned session of the first role of the protocol's plan, of full length, with one
event that ran, every field clean; run_case() builds it again below its own directory, applies one case and
audits it with the real scripts/collection.py::audit_session (boundary_sessions.audit: only collection.retazec,
the feature extraction from guest RAM, is replaced by the synthetic extraction result). RAM_CASES holds one case
for every reason audit_session and the acceptance verdict can give; UNREACHABLE names the reasons no session
built under such a protocol reaches, with the reason why. CASES adds the cases of the log audit
(scripts/tests/audit_cases_logs.py). The self-test runs cases(p): CASES, and the case of a bound once the protocol
sets it to a number (package B10, finding S1 of B3: the cap of rule-closed rows from G3b), with unreachable(p) for
UNREACHABLE. Expected reasons are written here, never taken from the code under test;
a case depends on the protocol only through its own parameters (grid, bounds, gate, rule). Where a bad session
also breaks what the log audit reads (end.json, some keys of session.json and raw/capture.json), its expected
reasons include the log audit's "logs: ..." ones.
"""
import copy
import json
import math
from pathlib import Path

from scripts import collection
from scripts.tests import boundary_sessions as bs
from scripts.tests import test_collection_logs as evidence
from scripts.tests.audit_case import Case
from scripts.tests.audit_cases_logs import LOG_CASES, under_v5

SESSION = "audit-selftest"  # The session id of every built session; each one lives in a directory of its own.
FRAME = 3  # The frame whose sidecar a case of a sidecar field edits (a delta snapshot under every protocol here).
INCOMPLETE = "incomplete model inputs under " + bs.fq.BEHAVIOR_POLICY


def clean_session(root, p, protocol_path, name):
    """The clean session of the self-test below `root`: a boundary_sessions.Session.

    One planned session of the first role of plan(p) (as its VM sees the protocol), of full length, with the
    evidence of one event that ran and its own synthetic profile (one file). Every field the audit reads is
    clean; a full snapshot takes longer than the delta bound and less than the full one, as on the lab host.
    """
    root = Path(root)
    place = collection.plan(p)["sessions"][0]
    pv = collection.for_vm(p, place.get("vm"))
    session = bs.build_session(root, pv, protocol_path, place, session_id=name,
                               base=bs.time_base(p, place["role"], 0), event=True,
                               profile=bs.profile_dir(root / (name + "-profile")))
    bounds = _bounds(p)
    if bounds is not None:
        cycle = bounds["cycle_ms_max"]
        for path in (session.directory / "raw").glob("*.json"):
            side = json.loads(path.read_text())
            if side.get("schema") == "vmicollect/1" and side["output"]["full"]:
                side["capture"]["total_ms"] = (cycle["delta"] + cycle["full"]) / 2
                evidence.write(path, side)
    return session


def run_case(root, p, protocol_path, case=None):
    """The clean session under `p` in root/<case id> (root/clean without a case), changed by case.mutate, audited.
    A case with its own clean session (case.session, package B8) starts from that one.

    Returns the boundary_sessions.Audit of the real audit (code 0 accepted, 2 refused).
    """
    where = "clean" if case is None else case.id.replace("/", "_")
    build = clean_session if case is None or case.session is None else case.session
    session = build(Path(root) / where, p, protocol_path, SESSION)
    result = None if case is None else case.mutate(session.directory, p, copy.deepcopy(session.result))
    return bs.audit(session, p, result=result)


def expected(case, p):
    """The exact reasons of a case under protocol `p`, sorted."""
    return sorted(case.expected(p) if callable(case.expected) else case.expected)


# Edits of the sealed session. A file listed in the logs manifest (protocol.json, profile/, raw/capture.json) is
# resealed after the edit; session.json, end.json and raw/ frames are not in the manifest.

def _edit(path, change):
    doc = json.loads(Path(path).read_text())
    change(doc)
    evidence.write(Path(path), doc)


def _drop(doc, dotted):
    *parents, key = dotted.split(".")
    for name in parents:
        doc = doc[name]
    del doc[key]


def _set(dotted, value):
    def change(doc):
        *parents, key = dotted.split(".")
        for name in parents:
            doc = doc[name]
        doc[key] = value
    return change


def _sidecar(d, seq, change):
    _edit(d / "raw" / f"frame{seq}.json", change)


def _rebuilt(d, p, result, quality=None, missing=()):
    """The extraction result of the session with other row quality or without rows: the same generator and seed
    as boundary_sessions.build_session, so every other row and value stays as it was."""
    meta = json.loads((d / "session.json").read_text())
    return bs.extraction_result(d.name, len(result["seq"]), p["full_every"], t0=result["casy"][0],
                                interval_s=p["interval_s"], quality=quality, missing=missing, seed=meta["seed"],
                                max_gap_s=p["max_gap_s"], domain=meta["domain"])[0]


def _bounds(p):
    from features import audit_policy  # A module of package B3: imported here, so this file collects before it.
    return audit_policy.audit_bounds(p)


def _middle(p):
    """A row inside the first chain with window_rows valid rows on both sides."""
    return p["full_every"] // 2


# Cases of the existing checks of audit_session.

def _historical(d, p, result):
    """A capture without session.json, its frames in the session directory itself (the layout before v2)."""
    (d / "session.json").unlink()
    for path in (d / "raw").iterdir():
        path.rename(d / path.name)


def _protocol_hash(d, p, result):
    """Captured under another protocol: its copy and session.json agree, the protocol of the audit differs."""
    _edit(d / "protocol.json", lambda doc: doc.update(name=str(doc.get("name")) + "-other"))
    _edit(d / "session.json", _set("protocol_sha256", collection.digest(d / "protocol.json")))
    evidence.seal(d)


def _profile(d, p, result):
    (d / "profile" / "symbols.txt").write_text("another profile\n")
    evidence.seal(d)


def _capture(dotted, value):
    def mutate(d, p, result):
        _edit(d / "raw/capture.json", _set(dotted, value))
        evidence.seal(d)
    return mutate


def _remove_frame(seq):
    def mutate(d, p, result):
        for suffix in (".json", ".vmicd"):
            (d / "raw" / f"frame{seq}{suffix}").unlink()
    return mutate


def _rebin(side):
    """The sidecar with bins of 8 MiB instead of the protocol's 16 MiB, consistent in itself."""
    size, page = 8 << 20, side["features"]["page_size"]
    total = size // page
    for b in side["features"]["bins"]:
        changed = min(b["pages_changed"], total)
        b.update(gpa=b["bin"] * size, pages_total=total, pages_changed=changed, changed_ratio=changed / total,
                 has_changed=int(changed > 0), entropy_mean=b["entropy_mean"] if changed else 0.)
    side["features"]["bin_bytes"] = size
    side["output"].update(pages_total=sum(b["pages_total"] for b in side["features"]["bins"]),
                          pages_changed=sum(b["pages_changed"] for b in side["features"]["bins"]))


def _image(d, p, result):
    (d / "raw" / f"frame{FRAME}.vmicd").write_bytes(b"other RAM")


def _extra_image(d, p, result):
    (d / "raw" / "orphan.vmicd").write_bytes(b"image without a sidecar")


def _frame(change):
    return lambda d, p, result: _sidecar(d, FRAME, change)


def _session(change):
    return lambda d, p, result: _edit(d / "session.json", change)


def _end(change):
    return lambda d, p, result: _edit(d / "end.json", change)


def _guest_line(d, p, result):
    """The guest identity without the hash line of the installed unit file (before and after the capture)."""
    path = "/etc/systemd/system/hyptcn-lab@.service"
    for name, key in (("session.json", "guest_before"), ("end.json", "guest_after")):
        _edit(d / name, lambda doc: doc[key].update(
            stack_manifest=[line for line in doc[key]["stack_manifest"] if not line.endswith("  " + path)]))


def _lab_hash(d, p, result):
    _edit(d / "session.json", lambda doc: doc["lab_sha256"].update({sorted(doc["lab_sha256"])[0]: "0" * 64}))


def _manifest_dropped(d, p, result):
    for name, key in (("session.json", "guest_before"), ("end.json", "guest_after")):
        _edit(d / name, lambda doc: doc[key].pop("stack_manifest"))


# Cases of the verdict (features/acceptance.py) through the extraction result.

def _rows_quality(rows):
    """mutate: the extraction result with the rows rows(p) = {seq: quality record} changed."""
    return lambda d, p, result: _rebuilt(d, p, result, quality=rows(p))


def _without_row(seq):
    return lambda d, p, result: _rebuilt(d, p, result, missing=(seq(p),))


def _times(change):
    def mutate(d, p, result):
        result["casy"] = [float(t) for t in change(p, result["casy"])]
        return result
    return mutate


def _gap(p, times):
    """Every row from the middle on one interval later: one gap of two intervals."""
    k = _middle(p)
    return times[:k] + [t + p["interval_s"] for t in times[k:]]


def _period(p, times):
    """Rows 0.8 intervals apart: no gap above max_gap_s, a span of 0.8 (rows - 1) intervals."""
    return [times[0] + .8 * p["interval_s"] * i for i in range(len(times))]


def _no_predecessor(d, p, result):
    """Valid delta rows without a predecessor, window_rows apart from the first window on: each costs window_rows
    windows, as many as take the session's windows below the coverage gate (no other check reads the flag)."""
    w, rows = p["window_rows"], p["cycles"]
    clean = bs.window_count(rows, w, p["full_every"])
    below = max(n for n in range(rows + 1) if n / rows < p["min_score_coverage"])
    column = bs.MENA.index("ma_predchodcu")
    for j in range(math.ceil((clean - below) / w)):
        result["matica"][w + j * w][column] = 0.
    return result


def _clustered_open_walks(p):
    count = p["invalid_rows"]["max"] + 1 if "invalid_rows" in p else 1
    return {seq: bs.unclosed_row() for seq in range(_middle(p), _middle(p) + count)}


# The walk of a row a parser rule closed, by its letter in _periodic (features/acceptance.py RULE_CLOSED_WALKS).
WALKS = {"r": "prev", "t": "tail", "m": "meet"}


def _periodic(kinds):
    """Rows of the given kinds (open walk 'u', or closed by a parser rule: 'r' prev, 't' tail, 'm' meet) at the
    smallest spacing the bound counts."""
    def rows(p):
        spacing, start = _bounds(p)["periodicity"]["min_spacing_rows"], p["window_rows"] + 1
        return {start + i * spacing: bs.unclosed_row() if kind == "u" else bs.rule_closed_row(WALKS[kind])
                for i, kind in enumerate(kinds)}
    return rows


# The cap of rule-closed rows (finding S1 of B3): audit.rule_closed_rows_max is null until G3b sets it (proposal
# 10.9). Once it is a number, a case with more rule-closed rows than the cap gets the cap's reason too, and the
# self-test builds the case of cap + 1 such rows (cases()).
CAP = "rows closed by a parser rule above the cap"


def _cap(p):
    """audit.rule_closed_rows_max of p: an int from G3b, None before, and None without an audit section (schemas 1
    and 2 have no cap, features/audit_policy.py audit_bounds)."""
    bounds = _bounds(p)
    return None if bounds is None else bounds["rule_closed_rows_max"]


def _capped(reasons, kinds):
    """expected: `reasons`, and the cap's reason where p's cap is below the rule-closed rows of the kinds."""
    closed = sum(kind in WALKS for kind in kinds)
    return lambda p: sorted([*reasons, *([CAP] if type(_cap(p)) is int and closed > _cap(p) else [])])


def _cap_reachable(p):
    """Whether a session of p can hold more rule-closed rows than the cap: the cap is a number below the rows."""
    return type(_cap(p)) is int and _cap(p) + 1 <= p["cycles"]


def _above_cap(p):
    """cap + 1 rows closed by a parser rule side by side, from the middle of the first chain where they fit there and
    from row 0 otherwise: one burst, so never periodic, and valid rows, so the windows stay those of the clean
    session."""
    count = _cap(p) + 1
    start = _middle(p) if _middle(p) + count <= p["cycles"] else 0
    return {seq: bs.rule_closed_row() for seq in range(start, start + count)}


def _coverage(p):
    return [f"score coverage below design gate {p['min_score_coverage']:g}"]


# Cases of the new checks of proposal 6.2 (with a bound: values of the protocol's audit section).

def _late(d, p, result):
    _sidecar(d, FRAME, _set("sched.lateness_s", 2 * _bounds(p)["lateness_max_s"]))


def _cycle(kind):
    def mutate(d, p, result):
        seq = 0 if kind == "full" else FRAME
        _sidecar(d, seq, _set("capture.total_ms", _bounds(p)["cycle_ms_max"][kind] + 1))
    return mutate


def _over_period(d, p, result):
    _sidecar(d, FRAME, _set("capture.total_ms", p["interval_s"] * 1000))


SESSION_KEYS = ("protocol_sha256", "guest_before", "profile_sha256", "collector_sha256", "collector_settings.mlock",
                "role", "cycles", "domain", "host_context.qemu.pid", "host_context.memory.qemu_swap_max",
                "host_context.memory.qemu_swap_kb", "lab_sha256")
END_KEYS = ("completed", "guest_after")
CAPTURE_KEYS = ("values.collector_sha256", "values.full_every", "values.interval_s", "values.mlock")
SIDECAR_KEYS = ("output.full", "output.sha256", "sched.skipped_before", "sched.lateness_s", "capture.total_ms",
                "capture.queue_wait_ms", "output.mlock", "output.data_closed_ms", "output.queue_bytes",
                "output.queue_jobs", "vm.domain", "vm.vmid")
# What else a missing key takes away. The log audit reads some keys too (scripts/collection_logs.py).
ALSO_MISSING = {
    "session.json:protocol_sha256": ["logs: protocol_hash"],
    "session.json:guest_before": ["logs: correlation:unreadable:KeyError: 'auth'",
                                  "logs: guest:unreadable:KeyError: 'guest_before'", "logs: guest_identity_changed",
                                  "missing key: session.json:guest_before.stack_manifest"],
    "session.json:collector_sha256": ["logs: collector:unreadable:KeyError: 'collector_sha256'"],
    "session.json:role": ["session role is not assigned by the protocol"],
    "session.json:cycles": ["logs: collector:unreadable:KeyError: 'cycles'"],
    "end.json:completed": ["logs: incomplete_capture"],
    "end.json:guest_after": ["logs: guest_identity_changed"],
    "raw/capture.json:values.collector_sha256": ["logs: collector:unreadable:KeyError: 'collector_sha256'"],
}
# What a missing key takes away from the v5 traffic checks as well (package B5b): the generator's header names the
# protocol hash session.json states.
V5_ALSO_MISSING = {"session.json:protocol_sha256": ["logs: traffic_config:protocol_sha256"]}


def _missing(name, dotted):
    """A case for one key the audit reads from the file `name`, removed from it (and only there)."""
    file = name if name != "frame" else f"frame{FRAME}.json"
    reason = f"missing key: {file}:{dotted}"

    def mutate(d, p, result):
        path = d / ("raw" if name.startswith("raw/") or name == "frame" else "") / Path(file).name
        _edit(path, lambda doc: _drop(doc, dotted))
        if name == "raw/capture.json":
            evidence.seal(d)
    base = sorted([reason, *ALSO_MISSING.get(f"{file}:{dotted}", [])])
    extra = V5_ALSO_MISSING.get(f"{file}:{dotted}")
    return Case("missing_key:" + file + ":" + dotted, "6.2 every audited key is mandatory",
                under_v5(base, extra) if extra else base, mutate)


RAM_CASES = [
    # Existing reasons of audit_session.
    Case("historical", "historical capture without provenance", sorted([
        "historical capture without protocol/session provenance; exploratory only",
        "session role is not assigned by the protocol"]), _historical),
    # Under v5 the generator's header still names the protocol it read (package B5b).
    Case("protocol_hash", "protocol hash mismatch",
         under_v5(["protocol hash mismatch"], ["logs: traffic_config:protocol_sha256"]), _protocol_hash),
    Case("incomplete_capture", "incomplete capture or changed guest identity",
         ["incomplete capture or changed guest identity", "logs: incomplete_capture"],
         _end(_set("completed", False))),
    Case("guest_changed", "incomplete capture or changed guest identity (another guest after the capture)",
         ["incomplete capture or changed guest identity", "logs: guest_identity_changed"],
         _end(lambda doc: doc["guest_after"].update(boot_id="another-boot"))),
    Case("profile_changed", "kernel profile changed since capture", ["kernel profile changed since capture"],
         _profile),
    Case("collector_settings", "collector binary or temporal settings mismatch",
         ["collector binary or temporal settings mismatch"],
         lambda d, p, result: _capture("values.interval_s", p["interval_s"] + 1)(d, p, result)),
    Case("mlock_capture", "collector memory locking differs from session settings",
         ["collector memory locking differs from session settings"], _capture("values.mlock", False)),
    Case("mlock_sidecar", "collector memory locking differs from session settings",
         ["collector memory locking differs from session settings"], _frame(_set("output.mlock", False))),
    Case("bin_width", "bin width differs from protocol", ["bin width differs from protocol"], _frame(_rebin)),
    Case("image_count", "image/sidecar count mismatch", ["image/sidecar count mismatch"], _extra_image),
    Case("sidecar_count", "snapshot count differs from assigned protocol (sidecars)",
         ["snapshot count differs from assigned protocol"],
         lambda d, p, result: _remove_frame(p["cycles"] - 1)(d, p, result)),
    Case("sidecar_sequence", "sequence must start at zero and be contiguous (sidecars)",
         ["sequence must start at zero and be contiguous", "snapshot count differs from assigned protocol"],
         lambda d, p, result: _remove_frame(_middle(p))(d, p, result)),
    Case("cadence", "full snapshot cadence differs from protocol", ["full snapshot cadence differs from protocol"],
         lambda d, p, result: _sidecar(d, 1, _set("output.full", True))),
    Case("image_checksum", "image checksum mismatch", [f"image checksum mismatch: frame{FRAME}.vmicd"], _image),
    Case("missed_slot", "read errors/fill/missed slots", [f"read errors/fill/missed slots: frame{FRAME}.vmicd"],
         _frame(_set("sched.skipped_before", 1))),
    Case("cycle_over_period", "collector cycle exceeded period",
         ["collector cycle exceeded period", "collector cycle time above the audit bound"], _over_period),
    Case("queue_wait", "collector waited for queue memory", [f"collector waited for queue memory: frame{FRAME}.vmicd"],
         _frame(_set("capture.queue_wait_ms", 1.))),
    Case("sequence_gap", "sequence gap", sorted([
        "sequence gap", "sequence must start at zero and be contiguous",
        "snapshot count differs from assigned protocol", "timestamp gap"]), _without_row(_middle)),
    # Reasons of the verdict (features/acceptance.py), the timing ones moved there from the audit in B3.
    Case("role_unassigned", "session role is not assigned by the protocol",
         ["session role is not assigned by the protocol"], _session(_set("role", "holdout"))),
    Case("verdict_rows", "snapshot count differs from assigned protocol (rows)",
         ["snapshot count differs from assigned protocol"], _without_row(lambda p: p["cycles"] - 1)),
    Case("timestamp_gap", "timestamp gap (B2 deferred point 9)", ["timestamp gap"], _times(_gap)),
    Case("sampling_period", "sampling period differs from protocol (B2 deferred point 9)",
         ["sampling period differs from protocol"], _times(_period)),
    Case("invalid_rows_over_max", "invalid_rows rule: more rows than max", [INCOMPLETE],
         _rows_quality(_clustered_open_walks)),
    Case("invalid_rows_cause", "invalid_rows rule: a cause it does not tolerate", [INCOMPLETE],
         _rows_quality(lambda p: {_middle(p): bs.read_error_row()})),
    Case("integrity_finding", "integrity findings require review", [
        "integrity findings require review before benign admission"],
         _rows_quality(lambda p: {_middle(p): bs.finding_row()})),
    Case("coverage", "score coverage below design gate", _coverage, _no_predecessor),
    # Rule-closed rows of all three walks (finding S3 of B3): a wrong list of walks misses one, and with it the pattern.
    Case("periodicity_rule_closed", "6.2 periodicity of flagged rows (rule-closed rows of the walks prev, tail, meet)",
         _capped(["periodic flagged rows"], "rtmr"), _rows_quality(_periodic("rtmr"))),
    Case("periodicity_union", "6.2 periodicity over invalid and rule-closed rows together",
         _capped(["periodic flagged rows"], "urur"), _rows_quality(_periodic("urur"))),
    # New checks of proposal 6.2.
    Case("lateness", "6.2 cycle start lateness", ["cycle start later than the audit bound"], _late),
    Case("cycle_delta", "6.2 cycle time of a delta snapshot", ["collector cycle time above the audit bound"],
         _cycle("delta")),
    Case("cycle_full", "6.2 cycle time of a full snapshot", ["collector cycle time above the audit bound"],
         _cycle("full")),
    Case("vm_domain", "6.2 VM identity: domain", ["sidecar VM identity differs from session"],
         _frame(_set("vm.domain", "another-domain"))),
    Case("vm_vmid", "6.2 VM identity: QEMU pid", ["sidecar VM identity differs from session"],
         _frame(lambda side: side["vm"].update(vmid=side["vm"]["vmid"] + 1))),
    Case("qemu_swap", "6.2 QEMU swap forbidden before start", ["QEMU swap was not disabled before start"],
         _session(_set("host_context.memory.qemu_swap_max", "max"))),
    # memory.swap.max 0 and yet 4 kB in swap: pages swapped out before a late move (KOSTRA B5, addendum 20:50Z).
    Case("qemu_swapped", "6.2 no QEMU memory in swap before start", ["QEMU memory was swapped before start"],
         _session(_set("host_context.memory.qemu_swap_kb", 4))),
    Case("guest_file_differs", "6.2 deployed guest files equal lab/", ["deployed guest files differ from lab/"],
         _lab_hash),
    Case("guest_file_missing", "6.2 deployed guest files equal lab/ (a file not hashed)",
         ["deployed guest files differ from lab/"], _guest_line),
    Case("missing_key:session.json:guest_before.stack_manifest", "6.2 every audited key is mandatory",
         ["missing key: session.json:guest_before.stack_manifest"], _manifest_dropped),
    *(_missing("session.json", key) for key in SESSION_KEYS),
    *(_missing("end.json", key) for key in END_KEYS),
    *(_missing("raw/capture.json", key) for key in CAPTURE_KEYS),
    *(_missing("frame", key) for key in SIDECAR_KEYS),
]

POSITIVE_CONTROL = ("judged only for a pilot under a protocol with events.pilot_controls, and the self-test audits a "
                    "planned session of the first role; scripts/tests/test_pozitivna_kontrola.py tests the gate. "
                    "Protocol v5 has no pilot: the four cases of finding S2 of B3 (events.json missing, a control "
                    "not executed, not detected, missing) are those of role test_controls in "
                    "scripts/tests/audit_cases_logs.py (controls:unreadable, control_not_executed, "
                    "control_without_effect, controls_differ_from_plan:missing; package B8, skeleton addendum)")
UNREACHABLE = {
    "positive control: events.json missing or unreadable": POSITIVE_CONTROL,
    "positive control not executed: <type>": POSITIVE_CONTROL,
    "positive control not detected: <type> <hits>/<rows> rows": POSITIVE_CONTROL,
    "positive control missing from events.json": POSITIVE_CONTROL,
    CAP: (
        "audit.rule_closed_rows_max is null until G3b (proposal 10.9), so the count is recorded and never a "
        "reason; once it is a number the self-test builds the case rule_closed_above_cap (cases()), and "
        "scripts/tests/test_audit_selftest.py checks it under a copy with an integer cap"),
}
# Finding S1 of B3: the case of the cap, which the self-test builds only under a protocol whose cap a session can
# exceed (cases()).
CAP_CASE = Case("rule_closed_above_cap", "rule_closed_rows_max of proposal 10.9: cap + 1 rule-closed rows, no pattern",
                [CAP], _rows_quality(_above_cap))


CASES = RAM_CASES + LOG_CASES  # The cases under every protocol; cases(p) is the self-test's list under p.


def cases(p):
    """The cases of the self-test under protocol p (scripts/audit_selftest.py; finding S1 of B3): CASES, and after the
    RAM cases the case of cap + 1 rule-closed rows (CAP_CASE) once p's cap is a number a session of p can exceed.
    Every other case takes its expectation from p (the periodicity cases name the cap's reason where their
    rule-closed rows exceed it)."""
    return [*RAM_CASES, *([CAP_CASE] if _cap_reachable(p) else []), *LOG_CASES]


def unreachable(p):
    """UNREACHABLE under p: the cap's reason while no case of cases(p) reaches it (null until G3b, or a cap no session
    of p can exceed), and without it once CAP_CASE is built."""
    out = dict(UNREACHABLE)
    if _cap_reachable(p):
        del out[CAP]
    elif type(_cap(p)) is int:
        out[CAP] = (f"audit.rule_closed_rows_max is {_cap(p)}, and a session of {p['cycles']} rows cannot hold more "
                    "rule-closed rows")
    return out


# Package B6a (design B6a 1.5): the audit records the summary of every column (values.columns) and never makes it a
# reason. The case: the clean session with a known matrix, accepted, recording the summary written here. In the
# measured rows (valid, no full snapshot, with a predecessor: every row of the clean session but those at a multiple
# of full_every) column k of BEHAVIOR_NAMES follows pattern k % 4 by the measured row's index i of n; every other
# row holds SENTINEL, which no summary may show.
SUMMARY_ID = "column_summary"
SENTINEL = 10 ** 6
PATTERNS = ("constant 7", "5 at i = 3, else 0", "i", "1 for i < n // 2, else 3")


def _value(pattern, i, n):
    return (7, 5 if i == 3 else 0, i, 1 if i < n // 2 else 3)[pattern]


def known_matrix(result):
    """A copy of the clean session's extraction result with the known values in its columns of BEHAVIOR_NAMES."""
    from features.archive import BEHAVIOR_NAMES
    flags = [bs.MENA.index("je_plna"), bs.MENA.index("ma_predchodcu")]
    rows = [r for r, (good, row) in enumerate(zip(result["valid"], result["matica"]))
            if good and [row[k] for k in flags] == [0, 1]]
    out = copy.deepcopy(result)
    for row in out["matica"]:
        row[:len(BEHAVIOR_NAMES)] = [SENTINEL] * len(BEHAVIOR_NAMES)
    for i, r in enumerate(rows):
        out["matica"][r][:len(BEHAVIOR_NAMES)] = [_value(k % 4, i, len(rows)) for k in range(len(BEHAVIOR_NAMES))]
    return out


def expected_summary(p):
    """values.columns of the known matrix under the grid of `p`, by the formulas of each pattern (std with ddof 0,
    the mode the smallest of the most frequent values, diff_std over the n - 1 first differences)."""
    from features.archive import BEHAVIOR_NAMES
    n = p["cycles"] - len(range(0, p["cycles"], p["full_every"]))
    h = n // 2
    mean = (h + 3 * (n - h)) / n
    one = h >= n - h  # Pattern 3: the mode is 1 unless the 3s are more.
    step = 2 / (n - 1)  # Pattern 3: one first difference of 2 among n - 1.
    patterns = (
        {"min": 7.0, "max": 7.0, "mean": 7.0, "std": 0.0, "mode": 7.0, "off_mode_share": 0.0, "diff_std": 0.0},
        {"min": 0.0, "max": 5.0, "mean": 5 / n, "std": 5 * math.sqrt(n - 1) / n, "mode": 0.0, "off_mode_share": 1 / n,
         "diff_std": math.sqrt(50 / (n - 1))},
        {"min": 0.0, "max": n - 1.0, "mean": (n - 1) / 2, "std": math.sqrt((n * n - 1) / 12), "mode": 0.0,
         "off_mode_share": (n - 1) / n, "diff_std": 0.0},
        {"min": 1.0, "max": 3.0, "mean": mean,
         "std": math.sqrt((h * (1 - mean) ** 2 + (n - h) * (3 - mean) ** 2) / n), "mode": 1.0 if one else 3.0,
         "off_mode_share": (n - h) / n if one else h / n, "diff_std": math.sqrt(2 * step - step * step)})
    return {name: {"rows": n, **patterns[k % 4]} for k, name in enumerate(BEHAVIOR_NAMES)}


def _same(recorded, expected):
    """Equal keys, the counts equal, the other values within 1e-12 (relative and absolute: float sums)."""
    return type(recorded) is dict and set(recorded) == set(expected) and all(
        type(recorded[c]) is dict and set(recorded[c]) == set(expected[c])
        and recorded[c]["rows"] == expected[c]["rows"]
        and all(math.isclose(recorded[c][k], v, rel_tol=1e-12, abs_tol=1e-12) for k, v in expected[c].items()
                if k != "rows")
        for c in expected)


def summary_case(root, p, protocol_path):
    """The self-test's check of values.columns: {id, check, code, reasons, expected, recorded, passed}; passed when
    the session with the known matrix is accepted with no reason and records exactly the expected summary."""
    session = clean_session(Path(root) / SUMMARY_ID, p, protocol_path, SESSION)
    audit = bs.audit(session, p, result=known_matrix(session.result))
    expected = expected_summary(p)
    recorded = audit.values.get("columns")
    return {"id": SUMMARY_ID, "check": "B6a 1.5 summary of every column over the measured rows, recorded only",
            "patterns": list(PATTERNS), "code": audit.code, "reasons": audit.values["reasons"], "expected": expected,
            "recorded": recorded,
            "passed": audit.code == 0 and audit.values["reasons"] == [] and _same(recorded, expected)}
