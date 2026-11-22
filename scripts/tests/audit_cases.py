"""The bad sessions of the audit self-test, RAM side (protocol v5, package B3; proposal 6.2).

clean_session() builds one planned session of the first role of the protocol's plan, of full length, with one
event that ran, every field clean; run_case() builds it again below its own directory, applies one case and
audits it with the real scripts/collection.py::audit_session (boundary_sessions.audit: only collection.retazec,
the feature extraction from guest RAM, is replaced by the synthetic extraction result). RAM_CASES holds one case
for every reason audit_session and the acceptance verdict can give; UNREACHABLE names the reasons no session
built under such a protocol reaches, with the reason why. CASES adds the cases of the log audit
(scripts/tests/audit_cases_logs.py). Expected reasons are written here, never taken from the code under test;
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

    Returns the boundary_sessions.Audit of the real audit (code 0 accepted, 2 refused).
    """
    where = "clean" if case is None else case.id.replace("/", "_")
    session = clean_session(Path(root) / where, p, protocol_path, SESSION)
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


def _periodic(kinds):
    """Rows of the given kinds (open walk 'u' or rule-closed 'r') at the smallest spacing the bound counts."""
    def rows(p):
        spacing, start = _bounds(p)["periodicity"]["min_spacing_rows"], p["window_rows"] + 1
        return {start + i * spacing: bs.unclosed_row() if kind == "u" else bs.rule_closed_row()
                for i, kind in enumerate(kinds)}
    return rows


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
    Case("periodicity_rule_closed", "6.2 periodicity of flagged rows (rule-closed rows)", ["periodic flagged rows"],
         _rows_quality(_periodic("rrrr"))),
    Case("periodicity_union", "6.2 periodicity over invalid and rule-closed rows together",
         ["periodic flagged rows"], _rows_quality(_periodic("urur"))),
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
                    "planned session of the first role; scripts/tests/test_pozitivna_kontrola.py tests the gate")
UNREACHABLE = {
    "positive control: events.json missing or unreadable": POSITIVE_CONTROL,
    "positive control not executed: <type>": POSITIVE_CONTROL,
    "positive control not detected: <type> <hits>/<rows> rows": POSITIVE_CONTROL,
    "positive control missing from events.json": POSITIVE_CONTROL,
    "rows closed by a parser rule above the cap": (
        "audit.rule_closed_rows_max is null until G3b (proposal 10.9), so the count is recorded and never a "
        "reason; scripts/tests/test_audit_selftest.py checks the reason under a copy with an integer cap"),
}


CASES = RAM_CASES + LOG_CASES
