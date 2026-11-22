"""Boundary sessions for the acceptance criterion tests (protocol v5, package B2) and the audit self-test (B3).

A session is built as a capture leaves it and audited by the real scripts/collection.py::audit_session. The
evidence comes from scripts/tests/test_collection_logs.build, the raw frames and the extraction result from the
generator below; only collection.retazec (feature extraction from guest RAM) is replaced, for one audit call.
Window counts are predicted by window_count(), an oracle that reads no product code. Nothing here imports a
name package B2 adds, so the same module runs on the code before and after B2. Since B3 every key the audit
reads is written with a clean value: the VM identity, lateness, cycle and publication fields of each sidecar,
and in session.json the host context, the collector settings and the lab/ files with the guest's manifest.
"""
from collections import namedtuple
import contextlib
import copy
import hashlib
import io
import json
import math
from pathlib import Path
import shutil

import numpy as np

from features import quality as fq
from features.archive import save
from features.contract import validate_sidecar
from features.snapshot import MENA, SCHEMA
from features.windows import BIN_PRIZNAKY
from scripts import collection
from scripts.tests import test_collection_logs as evidence

BIN_BYTES, PAGE = 16777216, 4096
KERNEL, STACK = "synthetic-kernel", "5" * 64  # One guest kernel and one service stack for every session.
BASE = evidence.BASE + 5000  # Time base of slot 0 of the first lane (time_base).
FIRST_SNAPSHOT_S = 1.5  # Snapshot i of a session with time base b is taken at b + 1.5 + i * interval_s.
SLOTS = 64  # Sessions per lane of time_base.
RULE = {"max": 3, "traversals": ["processes"]}
SCENARIOS = {"steady": {"workers": 4, "burst": 1, "catalog_share": 3 / 5, "write_share": 1 / 10},
             "bursty": {"workers": 8, "burst": 4, "catalog_share": 1 / 2, "write_share": 1 / 5}}
V4_KEYS = ("schema", "cycles", "pilot_cycles", "window_rows", "full_every", "min_score_coverage", "invalid_rows",
           "quality_policy")
# Every field features/snapshot.py records for a row, with the values of a clean snapshot: the forward walk closed
# the process list and the backward walk closed over the same tasks, no W+X or memfd pattern, no process skipped for
# W+X, no task skipped by the socket and memory traversals, no unconfirmed cross-view difference.
_GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "truncated_traversals": [],
         "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0,
         "process_walk": "next", "process_walk_backward": {"closed": True, "agrees": True}, "memory_patterns": [],
         "skipped_wx": [], "skipped_tasks": {"sockets": 0, "memory_patterns": 0}, "unconfirmed_findings": []}
DOMAIN = "hyptcn-test"  # The domain of protocol_doc's one VM.
# The QEMU process of every session: the eBPF backend writes its pid into each sidecar as vm.vmid.
QEMU = {"pid": 4242, "start_ticks": 1, "host_boot": "synthetic-host-boot"}
# What a deployment of lab/ leaves in the guest: every top-level file under /opt/hyptcn-lab and two of them
# installed once more (lab/install.sh). Synthetic digests; session.json lab_sha256 names the same ones.
LAB_SHA256 = {"lab/" + f.name: hashlib.sha256(b"synthetic " + f.name.encode()).hexdigest()
              for f in sorted((collection.ROOT / "lab").iterdir()) if f.is_file()}
DEPLOYED = {**{"/opt/hyptcn-lab/" + name[4:]: name for name in LAB_SHA256},
            "/etc/nginx/conf.d/hyptcn-lab.conf": "lab/nginx.conf",
            "/etc/systemd/system/hyptcn-lab@.service": "lab/hyptcn-lab@.service"}
# The guest identity's manifest as collection.guest_identity reads it: sha256sum, the packages, the timers.
STACK_MANIFEST = [*(f"{LAB_SHA256[source]}  {path}" for path, source in DEPLOYED.items()),
                  "nginx\t1.22.1-9", "postgresql\t15+248", "python3\t3.11.2-1+b1", "python3-psycopg2\t2.9.5-1+b1",
                  "timers: "]
# The register of a schema-3 test protocol: per id of features/audit_policy.py TOLERATED the cause and the
# decision as the comments of the admitting code state them.
REGISTER = {
    "invalid_rows": ("rows invalid only because a named traversal did not close",
                     "invalid_rows rule of the protocol (owner 2026-11-17): at most max such rows, never scored"),
    "rule_closed_rows": ("process lists a parser rule closed (prev, tail, meet)",
                         "complete lists, only reported; rule_closed_rows_max caps them from G3b"),
    "unconfirmed_findings": ("cross-view differences seen in one snapshot only",
                             "a difference of the live read is a finding once the next snapshot confirms it"),
    "inconclusive_integrity": ("integrity checks that could not conclude",
                               "integrity availability is no behaviour input (features/quality.py)"),
    "collector_warnings": ("collector warnings that match an allowed pattern",
                           "audit.warnings_allowed, determined in G2; null allows none"),
    "event_traffic_exit": ("traffic generator exit code 1 in an event session",
                           "failed requests inside an event window are evidence of the event"),
    "event_unit_restarts": ("units an event type restarts by design (EVENT_UNITS)",
                            "any other restart stays a problem"),
    "event_window_requests": ("requests inside an event window",
                              "inside [host start - 1 s, host stop done + grace] failures are expected"),
    "event_window_health_checks": ("health polls without request id inside a window",
                                   "lab/udalosti.py polls health without a request id"),
    "event_window_journal": ("tracebacks and worker errors inside a window",
                             "outside every window they reject the session"),
    "event_window_nginx_errors": ("nginx error lines inside a window",
                                  "outside every window they reject the session"),
}

Session = namedtuple("Session", "directory protocol_path result")
Audit = namedtuple("Audit", "code path record values archive calls stdout")


def complete_row():
    """Quality of a row whose traversals all closed: valid under every policy."""
    return copy.deepcopy(_GOOD)


def unclosed_row(*traversals):
    """Quality of a row invalid only because the named traversals (default: processes) did not close."""
    return dict(complete_row(), model_valid=False, behavior_valid=False, traversals_complete=False,
                truncated_traversals=list(traversals or ("processes",)))


def finding_row(check="syscall_table"):
    """Quality of a behaviour-valid row that carries one integrity finding (guestparse/checks.py _finding shape)."""
    return dict(complete_row(), findings=[{"check": check, "index": 0, "detail": "synthetic"}])


def read_error_row(read_errors=1):
    """Quality of a row invalid because of RAM read errors, a cause no invalid_rows rule tolerates."""
    return dict(complete_row(), model_valid=False, behavior_valid=False, read_errors=read_errors)


def rule_closed_row(walk="prev"):
    """Quality of a valid row whose process list a parser rule closed (process_walk prev, tail or meet)."""
    return dict(complete_row(), process_walk=walk)


def window_count(rows, window_rows, full_every, invalid=()):
    """Oracle of plan section 2: sum over chains and maximal runs of valid rows of max(0, len(run) - window_rows)."""
    invalid = set(invalid)
    if not invalid <= set(range(rows)):
        raise ValueError("invalid seq outside the session")
    total = 0
    for start in range(0, rows, full_every):
        run = 0
        for seq in range(start, min(start + full_every, rows)):
            if seq in invalid:
                total, run = total + max(0, run - window_rows), 0
            else:
                run += 1
        total += max(0, run - window_rows)
    return total


def isolated_seqs(count, window_rows, full_every):
    """Seq of `count` isolated rows at step * (j + 1), step = full_every // 6; each costs window_rows + 1 windows."""
    step = full_every // 6
    if step - 1 < window_rows or full_every - 1 - step * count < window_rows:
        raise ValueError("isolated rows need window_rows valid rows of chain 0 on both sides")
    return [step * (j + 1) for j in range(count)]


def clustered_seqs(count, window_rows, full_every):
    """Seq of `count` adjacent rows from full_every // 2; together they cost count + window_rows windows."""
    start = full_every // 2
    if start < window_rows or full_every - start - count < window_rows:
        raise ValueError("clustered rows need window_rows valid rows of chain 0 on both sides")
    return list(range(start, start + count))


def clean_sidecar(side, domain=DOMAIN, vmid=QEMU["pid"]):
    """The sidecar `side` (changed in place and returned) with every field the audit reads beyond the feature
    contract, clean: the VM `domain` with the QEMU pid `vmid`, no missed slot and no lateness, no wait for queue
    memory, and a snapshot the writer thread published from an empty queue with memory locking on
    (collection.COLLECTOR_MLOCK). The cycle time (capture.total_ms) is the caller's."""
    side.setdefault("vm", {}).update(domain=domain, vmid=vmid)
    side.setdefault("sched", {}).update(lateness_s=0., skipped_before=0)
    side.setdefault("capture", {}).update(queue_wait_ms=0.)
    side.setdefault("output", {}).update(mlock=True, queue_jobs=0, queue_bytes=0, data_closed_ms=.2)
    return side


def managed_fields(p, guest, domain=None):
    """session.json fields a managed capture records (collection.run_session), clean: the VM's domain (default
    p["domain"]), the guest identity `guest` with the manifest of a deployment of lab/ (LAB_SHA256), the QEMU
    process with swap forbidden for its cgroup and the collector settings of the capture."""
    return {"domain": p.get("domain") if domain is None else domain,
            "guest_before": dict(guest, stack_manifest=list(STACK_MANIFEST)), "lab_sha256": dict(LAB_SHA256),
            "host_context": {"host_boot": QEMU["host_boot"], "qemu": dict(QEMU), "python": "python3",
                             "memory": {"vm_swappiness": 1, "qemu_swap_kb": 0, "qemu_swap_max": "0"}},
            "collector_settings": {"writer": "delta", "fsync": False, "hash": "sha256", "writer_thread": True,
                                   "mlock": True, "interval_s": p["interval_s"], "full_every": p["full_every"],
                                   "bin_bytes": p["bin_bytes"]}}


def _sidecar(seq, timestamp, full, chain_id, quality, changed, zero, entropy, domain=DOMAIN, vmid=QEMU["pid"]):
    """Sidecar of frame `seq` as vmicollect writes it (schema vmicollect/1): bin b has changed[b] changed pages,
    zero ratio zero[b] and entropy mean entropy[b]; `full` and `chain_id` go to output, the row's read errors and
    zero fill to stats, no missed slot to sched (the audit's own sidecar check reads both). The cycle took 0.1 ms;
    the other fields the audit reads are those of clean_sidecar."""
    total = BIN_BYTES // PAGE
    bins = [{"bin": b, "gpa": b * BIN_BYTES, "pages_total": total, "pages_changed": int(c),
             "changed_ratio": int(c) / total, "zero_ratio": float(z), "entropy_mean": float(e) if c else 0.,
             "has_changed": int(c > 0)} for b, (c, z, e) in enumerate(zip(changed, zero, entropy))]
    n = len(bins)
    return clean_sidecar({
        "schema": "vmicollect/1", "seq": seq, "timestamp_unix": timestamp,
        "vm": {"memsize": n * BIN_BYTES, "num_vcpus": 2},
        "stats": {"read_errors": quality["read_errors"], "filled_zero": quality["filled_zero"]},
        "sched": {"skipped_before": 0}, "capture": {"total_ms": .1},
        "output": {"pages_total": n * total, "pages_changed": int(sum(changed)), "page_size": PAGE,
                   "full": full, "chain_id": chain_id},
        "features": {"schema": "hyptcn3/perbin/1", "entropy": True, "bin_bytes": BIN_BYTES, "page_size": PAGE,
                     "bins_total": n, "regions": [{"gpa": 0, "bytes": n * BIN_BYTES}], "bins": bins}},
        domain, vmid)


def extraction_result(session, rows, full_every, *, t0, interval_s=1, quality=None, missing=(), seed=0, bins=3,
                      max_gap_s=None, domain=DOMAIN, vmid=QEMU["pid"]):
    """(result, sidecars) as collection.retazec gives them: seq 0..rows-1 without `missing`, at the float times
    t0 + seq * interval_s. quality: {seq: quality record}; full_every: cadence of full snapshots and chains; seed:
    the synthetic values; domain and vmid: the VM each sidecar names."""
    quality, missing = quality or {}, set(missing)
    seqs = [seq for seq in range(rows) if seq not in missing]
    if not seqs or not missing <= set(range(rows)) or not set(quality) <= set(seqs):
        raise ValueError("quality or missing seq outside the session rows")
    rng = np.random.default_rng(seed)
    total, n = BIN_BYTES // PAGE, len(seqs)
    times = [float(t0 + interval_s * seq) for seq in seqs]  # Floats, as retazec reads float(timestamp_unix).
    chains = [f"{session}-chain-{seq // full_every}" for seq in seqs]
    rows_quality = [copy.deepcopy(quality.get(seq, _GOOD)) for seq in seqs]
    valid = [fq.valid_for(q, fq.BEHAVIOR_POLICY) for q in rows_quality]
    sidecars = [_sidecar(seq, times[i], seq % full_every == 0, chains[i], rows_quality[i],
                         rng.integers(0, total + 1, bins), rng.uniform(1 / 10, 3 / 10, bins), rng.uniform(2, 6, bins),
                         domain, vmid)
                for i, seq in enumerate(seqs)]
    perbin = [[[b[name] for name in BIN_PRIZNAKY] for b in s["features"]["bins"]] for s in sidecars]
    matrix = np.zeros((n, len(MENA)))
    matrix[:, :8] = rng.uniform(0, 1, (n, 8))
    matrix[:, 8:18] = rng.integers(20, 40, (n, 10))
    has_prev = np.array([i > 0 and valid[i - 1] and seqs[i - 1] == seq - 1 for i, seq in enumerate(seqs)])
    matrix[:, MENA.index("ma_predchodcu")] = has_prev
    matrix[:, MENA.index("je_plna")] = [seq % full_every == 0 for seq in seqs]
    for name in ("proc_new", "proc_gone", "mod_delta"):  # No difference without a predecessor.
        matrix[~has_prev, MENA.index(name)] = 0
    result = {"schema": SCHEMA, "mena": list(MENA), "matica": matrix.tolist(), "snimky": [f"frame{s}" for s in seqs],
              "poznamky": [[] for _ in seqs], "trvanie_s": [0.] * n, "seq": seqs, "casy": times,
              "quality": rows_quality, "valid": valid, "quality_policy": fq.BEHAVIOR_POLICY, "perbin": perbin,
              "biny": list(range(bins)), "chain_ids": chains, "layout": validate_sidecar(sidecars[0]),
              "max_medzera_s": 1.5 * interval_s if max_gap_s is None else max_gap_s}
    return result, sidecars


def write_frames(raw, sidecars):
    """frame<seq>.vmicd and its sidecar for each sidecar; the sidecar names the image's SHA-256."""
    for side in sidecars:
        image = Path(raw) / f"frame{side['seq']}.vmicd"
        image.write_bytes(b"synthetic RAM %d" % side["seq"])
        side = dict(side, output=dict(side["output"], sha256=hashlib.sha256(image.read_bytes()).hexdigest()))
        evidence.write(image.with_suffix(".json"), side)


def save_archive(path, result):
    """Write `result` as a feature archive (features.archive.save); returns (path, sha256)."""
    path = save(path, result)
    return path, collection.digest(path)


def audit_sections(interval_s, min_spacing_rows=2):
    """The audit and exceptions sections of a schema-3 test protocol (features/audit_policy.py).

    The bounds of proposal 6.2 for an interval of 5 s scaled to `interval_s`: the cycle starts at most a tenth of
    the interval late, a delta cycle takes at most 30 % of it and a full one 70 %. Periodicity: 3 equal spacings in
    a row, each of at least `min_spacing_rows` rows (the author's judgment in G0). No collector warning is allowed
    and the cap of rule-closed rows is not set, as until G2 and G3b. Every TOLERATED id is registered (REGISTER),
    with no expected count.
    """
    from features import audit_policy  # A module of package B3: imported here, so this file collects before it.
    return {"audit": {"lateness_max_s": interval_s / 10,
                      "cycle_ms_max": {"delta": round(300 * interval_s, 6), "full": round(700 * interval_s, 6)},
                      "periodicity": {"equal_spacings": 3, "min_spacing_rows": min_spacing_rows,
                                      "note": "author's judgment in G0 (proposal 10.9), not a mechanism"},
                      "warnings_allowed": None, "rule_closed_rows_max": None},
            "exceptions": {name: {"cause": REGISTER[name][0], "decision": REGISTER[name][1], "expected": None}
                           for name in audit_policy.TOLERATED}}


def protocol_doc(profile, *, schema, cycles, pilot_cycles, window_rows, full_every, gate, rule=RULE, roles_each=3,
                 scenarios=SCENARIOS, group_prefix="bt-", name="boundary"):
    """Protocol of plan section 3: interval 1 s, gap 1.5 s, one unnamed VM, no events; rule None omits invalid_rows."""
    doc = {"schema": schema, "name": name, "quality_policy": fq.BEHAVIOR_POLICY, "profile": str(profile),
           "domain": DOMAIN, "target": "http://127.0.0.1:28080", "interval_s": 1, "max_gap_s": 1.5,
           "bin_bytes": BIN_BYTES, "window_rows": window_rows, "stride": 1, "full_every": full_every,
           "cycles": cycles, "pilot_cycles": pilot_cycles, "min_score_coverage": gate,
           "scenarios": copy.deepcopy(scenarios), "group_prefix": group_prefix,
           "roles": {role: roles_each for role in ("train", "dev", "calibration", "test_benign")}}
    if rule is not None:
        doc["invalid_rows"] = copy.deepcopy(rule)
    return doc


def worst_gate(cycles, window_rows, full_every, count, extra=0):
    """(windows + extra) / cycles for `count` isolated rows: the gate those rows meet exactly (extra 0)."""
    return (window_count(cycles, window_rows, full_every, isolated_seqs(count, window_rows, full_every))
            + extra) / cycles


def family(name, profile):
    """Protocol document of family S3, S2G or V4 (plan section 3), or of the file S3+ (S3 with the S2G gate).

    S3 and S3+ (schema 3) carry the audit and exceptions sections of audit_sections(1): no B2 construction meets
    a new rule there. Every row is sampled on the grid and no row is closed by a parser rule; the flagged rows of
    a cell are at most four isolated rows (isolated_seqs, full_every // 6 = 10 apart) or adjacent ones, so the
    periodicity bound counts spacings of full_every // 6 + 1 = 11 rows and more only.
    """
    if name == "V4":
        config = json.loads((collection.ROOT / "config/collection-v4.json").read_text())
        doc = protocol_doc(profile, schema=config["schema"], cycles=config["cycles"],
                           pilot_cycles=config["pilot_cycles"], window_rows=config["window_rows"],
                           full_every=config["full_every"], gate=config["min_score_coverage"],
                           rule=config["invalid_rows"], roles_each=2, group_prefix="v4-", name="boundary-v4")
        return dict(doc, quality_policy=config["quality_policy"])
    shape = {"S3": ("hyptcn3/collection-protocol/3", 0), "S2G": ("hyptcn3/collection-protocol/2", 1),
             "S3+": ("hyptcn3/collection-protocol/3", 1)}
    if name not in shape:
        raise ValueError("unknown protocol family: " + str(name))
    schema, extra = shape[name]
    doc = protocol_doc(profile, schema=schema, cycles=96, pilot_cycles=80, window_rows=8, full_every=64,
                       gate=worst_gate(96, 8, 64, RULE["max"], extra), group_prefix=name.lower() + "-",
                       name="boundary-" + name.lower())
    if schema == "hyptcn3/collection-protocol/3":
        doc.update(audit_sections(doc["interval_s"], min_spacing_rows=doc["full_every"] // 6 + 1))
    return doc


def write_protocol(path, doc):
    """Write a protocol document as JSON; returns the path (load it with collection.protocol)."""
    evidence.write(Path(path), doc)
    return Path(path)


def profile_dir(path):
    """A guest profile directory with one file; protocols name it by absolute path."""
    path = Path(path)
    path.mkdir(parents=True)
    (path / "symbols.txt").write_text("synthetic profile\n")
    return path.resolve()


def places(p, role=None):
    """Planned sessions of the protocol (collection.plan), optionally of one role."""
    return [s for s in collection.plan(p)["sessions"] if role is None or s["role"] == role]


def time_base(p, role, slot):
    """Time base of a slot in the role's lane: lanes follow protocol["roles"], then pilot, diagnostic, any other;
    every session of a lane ends before the next lane starts (roles chronologically separated)."""
    if type(slot) is not int or not 0 <= slot < SLOTS:
        raise ValueError("slot outside the lane")
    lanes = [*p["roles"], "pilot", "diagnostic"]
    lane = lanes.index(role) if role in lanes else len(lanes)
    span = max(p["cycles"], p["pilot_cycles"]) * p["interval_s"] + 100
    return BASE + (lane * SLOTS + slot) * span


def boot_id(group):
    """Guest boot id of a boot group: one boot per group and one group per boot."""
    return "boot-" + str(group)


def build_session(root, p, protocol_path, place, *, session_id, base, rows=None, quality=None, seed=None,
                  boot=None, meta=None, event=False, profile=None):
    """Sealed session at `place` (a plan row or a dict like it) with `rows` snapshots (default: the role's length);
    `quality` as in extraction_result, `meta` merged into session.json last. Returns Session. The traffic seed of
    session.json and of both traffic log headers is the session seed; the other traffic fields keep the placeholder
    values of test_collection_logs.build, not those of the place's scenario. event: the evidence of one event that
    ran (test_collection_logs.build); profile: the profile directory to copy instead of p["profile"]."""
    rows = rows if rows is not None else p["pilot_cycles"] if place.get("role") == "pilot" else p["cycles"]
    # The measurement lasts beyond the last snapshot (base + 1.5 + (rows - 1) * interval_s); one more second.
    d = evidence.build(Path(root), event=event, session_name=session_id, base=base, snapshots=rows,
                       measure_s=math.ceil(rows * p["interval_s"]) + 1)
    shutil.copyfile(protocol_path, d / "protocol.json")  # The log audit hashes this copy, the audit the original.
    shutil.copytree(p["profile"] if profile is None else profile, d / "profile")
    meta_doc = json.loads((d / "session.json").read_text())
    meta_doc.update({key: place[key] for key in ("role", "group", "scenario", "seed") if key in place})
    meta_doc.update(vm=place.get("vm"), typ="benign",
                    **managed_fields(p, {"kernel": KERNEL, "boot_id": boot or boot_id(place.get("group")),
                                         "stack_sha256": STACK}),
                    profile_sha256={str(f.relative_to(d / "profile")): collection.digest(f)
                                    for f in (d / "profile").rglob("*") if f.is_file()},
                    protocol_sha256=collection.digest(protocol_path), **(meta or {}))
    # The traffic generator runs with the session seed; the log audit compares both headers with session.json.
    meta_doc["traffic"] = dict(meta_doc["traffic"], seed=meta_doc["seed"])
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
        records = [json.loads(line) for line in (d / name).read_text().splitlines()]
        (d / name).write_text("".join(json.dumps(dict(r, config=dict(r["config"], seed=meta_doc["seed"]))
                                                 if r.get("type") == "header" else r) + "\n" for r in records))
    evidence.write(d / "session.json", meta_doc)
    guest = meta_doc["guest_before"]
    end = json.loads((d / "end.json").read_text())
    evidence.write(d / "end.json", dict(end, guest_after=guest))
    for when in ("before", "after"):  # The log audit compares them with session.json guest_before.
        state = json.loads((d / "guest" / f"state_{when}.json").read_text())
        evidence.write(d / "guest" / f"state_{when}.json", dict(state, boot_id=guest["boot_id"],
                                                                 kernel=guest["kernel"]))
    capture = json.loads((d / "raw/capture.json").read_text())
    capture["values"].update(interval_s=p["interval_s"], full_every=p["full_every"], mlock=True)
    evidence.write(d / "raw/capture.json", capture)
    result, sidecars = extraction_result(session_id, rows, p["full_every"], t0=base + FIRST_SNAPSHOT_S,
                                         interval_s=p["interval_s"], quality=quality,
                                         seed=place.get("seed", 0) if seed is None else seed,
                                         max_gap_s=p["max_gap_s"], domain=meta_doc.get("domain"))
    write_frames(d / "raw", sidecars)
    evidence.seal(d)  # Last: protocol.json, profile/, guest state and raw/capture.json are in the logs manifest.
    return Session(d, Path(protocol_path), result)


def audit(session, p, output=None, result=None):
    """The real collection.audit_session on a Session with collection.retazec returning a copy of `result` during
    the call only; output defaults to <session>/audit.json. Returns Audit (code 0 accepted, 2 refused)."""
    result = session.result if result is None else result
    output = Path(output) if output is not None else session.directory / "audit.json"
    calls, out = [], io.StringIO()

    def extraction(*args, **kwargs):
        calls.append({"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}})
        return copy.deepcopy(result)
    original, collection.retazec = collection.retazec, extraction
    try:
        with contextlib.redirect_stdout(out):
            code = collection.audit_session(session.directory, p, session.protocol_path, output)
    finally:
        collection.retazec = original
    record = json.loads(output.read_text())
    return Audit(code, output, record, record["values"], output.with_suffix(".npz"), calls, out.getvalue())
