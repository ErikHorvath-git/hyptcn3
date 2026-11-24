"""Self-test of the boundary-session helper: the real audit counts the windows the oracle predicts.

Runs unchanged on the code before and after package B2 (no name B2 adds is imported).
"""
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
import pytest

from features.archive import load
from features.contract import validate_sidecar
from features.coverage import scorable_windows
from features.windows import perbin_zo_sidecaru
from scripts import collection
from scripts.tests import boundary_sessions as bs

COVERAGE = "score coverage below design gate"
INTEGRITY = "integrity findings require review before benign admission"
INCOMPLETE = "incomplete model inputs under " + bs.fq.BEHAVIOR_POLICY
SLOT = itertools.count()  # Every session of this module has its own time slot.


@pytest.fixture(scope="module")
def families(tmp_path_factory):
    """Loaded S3 and V4 protocols: {name: (protocol, path)} and the root for their sessions."""
    root = tmp_path_factory.mktemp("families")
    profile = bs.profile_dir(root / "profile")
    loaded = {}
    for name in ("S3", "V4"):
        path = bs.write_protocol(root / f"{name}.json", bs.family(name, profile))
        loaded[name] = collection.protocol(path), path
    return loaded, root


def audited(families, name, session_id, *, quality=None, role="train", index=0, rows=None, meta=None, boot=None):
    """Build planned place `index` of `role` (a pilot or diagnostic place of its own otherwise) and audit it."""
    (p, path), root = families[0][name], families[1]
    planned = bs.places(p, role) if role in p["roles"] else []
    place = planned[index] if planned else {"role": role, "group": role + "-1", "scenario": "steady", "seed": 7}
    session = bs.build_session(root / "sessions", p, path, place, session_id=session_id,
                               base=bs.time_base(p, role, next(SLOT)), rows=rows, quality=quality, meta=meta,
                               boot=boot)
    return p, session, bs.audit(session, p)


def shape(p):
    return p["cycles"], p["window_rows"], p["full_every"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digests(directory):
    """{relative path: SHA-256} of every file below `directory`, computed here and not by the product."""
    directory = Path(directory)
    return {str(f.relative_to(directory)): sha256(f) for f in directory.rglob("*") if f.is_file()}


def test_oracle_gives_the_numbers_of_the_plan(tmp_path):
    cells = {"k0": lambda w, f: [], "k1": lambda w, f: bs.isolated_seqs(1, w, f),
             "k2i": lambda w, f: bs.isolated_seqs(2, w, f), "k2c": lambda w, f: bs.clustered_seqs(2, w, f),
             "k3i": lambda w, f: bs.isolated_seqs(3, w, f), "k3c": lambda w, f: bs.clustered_seqs(3, w, f),
             "k4i": lambda w, f: bs.isolated_seqs(4, w, f), "k4c": lambda w, f: bs.clustered_seqs(4, w, f)}
    table = {"S3": [80, 71, 62, 70, 53, 69, 44, 68], "V4": [656, 623, 590, 622, 557, 621, 524, 620]}
    profile = bs.profile_dir(tmp_path / "profile")
    for name, expected in table.items():
        p = bs.family(name, profile)
        n, w, f = shape(p)
        assert [bs.window_count(n, w, f, cell(w, f)) for cell in cells.values()] == expected
        ideal = bs.window_count(n, w, f)
        assert all(ideal - bs.window_count(n, w, f, bs.isolated_seqs(k, w, f)) == k * (w + 1) for k in range(5))
        assert all(ideal - bs.window_count(n, w, f, bs.clustered_seqs(k, w, f)) == k + w for k in range(1, 5))
        for k in range(1, 5):  # Rows of plan section 4: isolated at F // 6 * (j + 1), clustered from F // 2.
            assert bs.isolated_seqs(k, w, f) == [f // 6 * (j + 1) for j in range(k)]
            assert bs.clustered_seqs(k, w, f) == list(range(f // 2, f // 2 + k))
    s3, s2g, plus = (bs.family(name, profile) for name in ("S3", "S2G", "S3+"))
    assert s3["min_score_coverage"] == 53 / 96 and s2g["min_score_coverage"] == plus["min_score_coverage"] == 54 / 96
    assert (s3["schema"], s2g["schema"], plus["schema"]) == (
        "hyptcn3/collection-protocol/3", "hyptcn3/collection-protocol/2", "hyptcn3/collection-protocol/3")
    v4 = json.loads((collection.ROOT / "config/collection-v4.json").read_text())
    assert {k: bs.family("V4", profile)[k] for k in bs.V4_KEYS} == {k: v4[k] for k in bs.V4_KEYS}
    with pytest.raises(ValueError, match="isolated rows need"):
        bs.isolated_seqs(1, 10, 64)
    assert bs.isolated_seqs(1, 9, 64) == [10]  # step - 1 == window_rows: just enough valid rows between rows.
    # After the last isolated row (seq 30) a chain of 35 rows keeps 4 = window_rows valid rows, one of 34 only 3.
    assert bs.isolated_seqs(6, 4, 35) == [5, 10, 15, 20, 25, 30]
    assert bs.window_count(35, 4, 35) - bs.window_count(35, 4, 35, bs.isolated_seqs(6, 4, 35)) == 6 * (4 + 1)
    with pytest.raises(ValueError, match="isolated rows need"):
        bs.isolated_seqs(6, 4, 34)
    with pytest.raises(ValueError, match="clustered rows need"):
        bs.clustered_seqs(3, 30, 64)


def test_families_carry_the_parameters_of_section_3(tmp_path):
    profile = bs.profile_dir(tmp_path / "profile")
    config = json.loads((collection.ROOT / "config/collection-v4.json").read_text())
    # The keys V4 takes from config/collection-v4.json (plan section 3); every other key is the test's own.
    from_config = ("schema", "cycles", "pilot_cycles", "window_rows", "full_every", "min_score_coverage",
                   "invalid_rows", "quality_policy")
    assert sorted(bs.V4_KEYS) == sorted(from_config)
    common = {"interval_s": 1, "max_gap_s": 1.5, "stride": 1, "bin_bytes": 16777216, "profile": str(profile)}
    s3 = dict(common, cycles=96, window_rows=8, full_every=64, pilot_cycles=80,
              invalid_rows={"max": 3, "traversals": ["processes"]}, quality_policy=bs.fq.BEHAVIOR_POLICY)
    rows = {"S3": (dict(s3, schema="hyptcn3/collection-protocol/3", min_score_coverage=53 / 96), 3),
            "S2G": (dict(s3, schema="hyptcn3/collection-protocol/2", min_score_coverage=54 / 96), 3),
            "S3+": (dict(s3, schema="hyptcn3/collection-protocol/3", min_score_coverage=54 / 96), 3),
            "V4": (dict(common, **{key: config[key] for key in from_config}), 2)}
    roles = ("train", "dev", "calibration", "test_benign")
    # Since B4 a schema-3 family is a v5 document (bs.v5_sections): test_controls without a group, the scenario
    # names with v5 entries, events of which none can be planned and a replacement rule that replaces nothing.
    v5_scenarios = {"steady": {"profile": "eshop", "intensity": "low", "rate": None},
                    "bursty": {"profile": "eshop", "intensity": "high", "rate": None}}
    for name, (row, each) in rows.items():
        doc = bs.family(name, profile)
        v5 = doc["schema"] == "hyptcn3/collection-protocol/3"
        assert {key: doc.get(key) for key in row} == row, name
        assert list(doc["roles"].items()) == [(role, each) for role in roles] + [("test_controls", 0)] * v5, name
        assert len(doc["scenarios"]) == 2 and doc["scenarios"] == (v5_scenarios if v5 else bs.SCENARIOS), name
        assert type(doc.get("group_prefix")) is str and doc["group_prefix"], name
        assert all(type(doc.get(key)) is str and doc[key] for key in ("domain", "target")), name  # One unnamed VM.
        assert "vms" not in doc, name
        if v5:
            assert (doc["group_sessions"], doc["events"]["per_session"], doc["replacement"]["max_per_campaign"],
                    doc["interleave"]) == (2, [0], 0, []), name
        else:
            assert not {"events", "replacement"} & set(doc), name


def test_places_lanes_and_boot_ids(families):
    for name, roles_each in (("S3", 3), ("V4", 2)):
        p = families[0][name][0]
        roles = ["train", "dev", "calibration", "test_benign"]
        # Since B4 the schema-3 family also names test_controls, with no group and so no place (bs.v5_sections).
        assert list(p["roles"]) == roles + ["test_controls"] * (name == "S3")
        assert bs.places(p, "test_controls") == []
        for role in roles:
            rows = bs.places(p, role)
            assert len(rows) == 2 * roles_each and all("vm" not in r for r in rows)
            assert len({bs.boot_id(r["group"]) for r in rows}) == roles_each
        span = max(p["cycles"], p["pilot_cycles"]) * p["interval_s"]
        lanes = [*p["roles"], "pilot", "diagnostic", None]
        for left, right in zip(lanes, lanes[1:]):
            # The last snapshot of a lane's last slot comes before the measurement of the next lane's first slot.
            assert bs.time_base(p, left, bs.SLOTS - 1) + bs.FIRST_SNAPSHOT_S + span < bs.time_base(p, right, 0)
    with pytest.raises(ValueError, match="slot outside"):
        bs.time_base(p, "train", bs.SLOTS)


@pytest.mark.parametrize("name", ["S3", "V4"])
def test_clean_session_is_accepted_with_the_oracle_windows(families, name):
    p, session, run = audited(families, name, f"clean-{name.lower()}")
    v, (n, w, f) = run.values, shape(p)
    assert (run.code, v["accepted"], v["reasons"], v["snapshots"]) == (0, True, [], n), v["reasons"]
    assert v["windows"] == bs.window_count(n, w, f) and v["score_coverage"] == v["windows"] / n
    assert v["logs"]["accepted"] and v["logs"]["problems"] == []
    assert v["quality"]["tolerated_invalid_seq"] == [] and v["role"] == "train"
    assert run.archive.is_file() and v["features_sha256"] == collection.digest(run.archive)
    assert len(run.calls) == 1 and run.calls[0]["args"][0] == str(session.directory / "raw")


def test_the_audit_extracts_the_memory_columns_from_the_bins_of_its_protocol(families, tmp_path):
    """Question Q10 to the lead (2026-11-24), the audit's path: under schema 3 the audit gives the extraction
    (collection.retazec) analysis.scale.min_bin_pages of its protocol, 1024 as config/collection-v5.json has it and
    512 in a copy that says 512, so the archive's eight memory columns come from the bins the normalizer scores; under
    schema 2 (V4) it gives None, every bin, by name."""
    p, _, run = audited(families, "S3", "bins-s3")
    assert p["analysis"]["scale"]["min_bin_pages"] == 1024
    assert run.code == 0 and run.calls[0]["kwargs"]["min_bin_pages"] == "1024"
    _, _, run = audited(families, "V4", "bins-v4")
    assert run.code == 0 and run.calls[0]["kwargs"]["min_bin_pages"] == "None"
    doc = bs.family("S3", bs.profile_dir(tmp_path / "profile"))
    doc["analysis"]["scale"]["min_bin_pages"] = 512
    path = bs.write_protocol(tmp_path / "S3-512.json", doc)
    other = ({"S3": (collection.protocol(path), path)}, families[1])
    _, _, run = audited(other, "S3", "bins-s3-512")
    assert run.code == 0 and run.calls[0]["kwargs"]["min_bin_pages"] == "512"


PLACEMENTS = {
    "mid_chain": lambda n, w, f: [f // 2],
    "three_isolated": lambda n, w, f: bs.isolated_seqs(3, w, f),
    "adjacent": lambda n, w, f: bs.clustered_seqs(3, w, f),
    "last_of_session": lambda n, w, f: [n - 1],
    "last_of_inner_chain": lambda n, w, f: [f - 1],
    "first_of_later_chain": lambda n, w, f: [f],
}
COST = {"mid_chain": lambda w: w + 1, "three_isolated": lambda w: 3 * (w + 1), "adjacent": lambda w: 3 + w,
        "last_of_session": lambda w: 1, "last_of_inner_chain": lambda w: 1, "first_of_later_chain": lambda w: 1}


@pytest.mark.parametrize("placement", list(PLACEMENTS))
@pytest.mark.parametrize("name", ["S3", "V4"])
def test_recorded_windows_equal_the_oracle_for_every_placement(families, name, placement):
    p = families[0][name][0]
    n, w, f = shape(p)
    invalid = PLACEMENTS[placement](n, w, f)
    assert f < n - 1 and len(invalid) <= p["invalid_rows"]["max"]  # Every class is a later or inner chain here.
    expected = bs.window_count(n, w, f, invalid)
    assert bs.window_count(n, w, f) - expected == COST[placement](w)
    _, _, run = audited(families, name, f"{placement}-{name.lower()}",
                        quality={seq: bs.unclosed_row() for seq in invalid})
    v = run.values
    assert (v["snapshots"], v["windows"], v["score_coverage"]) == (n, expected, expected / n)
    assert v["quality"]["tolerated_invalid_seq"] == v["quality"]["invalid_input_seq"] == sorted(invalid)
    accepted = not expected / n < p["min_score_coverage"]
    assert (run.code, v["accepted"]) == ((0, True) if accepted else (2, False)), v["reasons"]
    assert [r.startswith(COVERAGE) for r in v["reasons"]] == ([] if accepted else [True])


def test_pilot_and_diagnostic_sessions_of_their_own_length(families):
    p = families[0]["S3"][0]
    _, w, f = shape(p)
    for role, rows in (("pilot", p["pilot_cycles"]), ("diagnostic", f + w + 1)):
        _, session, run = audited(families, "S3", f"{role}-clean", role=role, rows=None if role == "pilot" else rows)
        v = run.values
        assert json.loads((session.directory / "session.json").read_text())["cycles"] == rows
        assert (run.code, v["accepted"], v["reasons"], v["role"]) == (0, True, [], role), v["reasons"]
        assert (v["snapshots"], v["windows"]) == (rows, bs.window_count(rows, w, f))


def test_finding_and_read_error_rows(families):
    p = families[0]["S3"][0]
    n, w, f = shape(p)
    seq = f // 2
    _, _, run = audited(families, "S3", "finding", quality={seq: bs.finding_row()})
    v = run.values
    assert (run.code, v["reasons"], v["windows"]) == (2, [INTEGRITY], bs.window_count(n, w, f))
    assert v["quality"]["invalid_input_seq"] == [] and v["quality"]["integrity_findings"] == 1
    _, _, run = audited(families, "S3", "read-error", quality={seq: bs.read_error_row()})
    v = run.values
    assert run.code == 2 and v["windows"] == bs.window_count(n, w, f, [seq])
    # The audit's own sidecar check sees the read error too: the frames repeat the row's quality.
    assert v["reasons"] == sorted([INCOMPLETE, f"read errors/fill/missed slots: frame{seq}.vmicd"])
    assert v["quality"]["invalid_input_seq"] == [seq] and v["quality"]["tolerated_invalid_seq"] == []


def test_rows_carry_the_quality_fields_and_float_times_of_the_extractor():
    # features/snapshot.py: objekty_z_pohladu records eleven fields, potvrd_krizove the unconfirmed cross-view
    # differences, _retazec_cyklus the read errors and the zero fill of the frame.
    fields = {"traversals_complete", "truncated_traversals", "behavior_valid", "inconclusive", "findings",
              "model_valid", "process_walk", "process_walk_backward", "memory_patterns", "skipped_wx", "skipped_tasks",
              "unconfirmed_findings", "read_errors", "filled_zero"}
    rows = [bs.complete_row(), bs.unclosed_row(), bs.finding_row(), bs.read_error_row()]
    assert [set(q) for q in rows] == [fields] * len(rows)
    # A clean snapshot: both walks closed the process list over the same tasks, no pattern, no process or task
    # skipped, nothing unconfirmed.
    clean = {"process_walk": "next", "process_walk_backward": {"closed": True, "agrees": True}, "memory_patterns": [],
             "skipped_wx": [], "skipped_tasks": {"sockets": 0, "memory_patterns": 0}, "unconfirmed_findings": []}
    assert {key: bs.complete_row()[key] for key in clean} == clean
    result, _ = bs.extraction_result("types", 10, 4, t0=100, quality={3: bs.unclosed_row()})
    assert [set(q) for q in result["quality"]] == [fields] * 10
    # retazec reads float(timestamp_unix): float times also from an integer time base and interval.
    assert result["casy"] == [100 + seq for seq in result["seq"]] and all(type(t) is float for t in result["casy"])


def test_session_identity_and_truthful_frames(families):
    p = families[0]["S3"][0]
    source = "scripts/collection.py"
    extra = {"measurement_sha256": {source: collection.digest(collection.ROOT / source)}}
    _, session, run = audited(families, "S3", "identity", role="dev", meta=extra)
    place = bs.places(p, "dev")[0]
    meta = json.loads((session.directory / "session.json").read_text())
    assert {k: meta[k] for k in ("role", "group", "scenario", "seed")} == {k: place[k] for k in
                                                                         ("role", "group", "scenario", "seed")}
    assert (meta["vm"], meta["domain"], meta["typ"], meta["cycles"]) == (None, p["domain"], "benign", p["cycles"])
    assert meta["guest_before"] == {"kernel": bs.KERNEL, "boot_id": bs.boot_id(place["group"]),
                                    "stack_sha256": bs.STACK, "stack_manifest": bs.STACK_MANIFEST}
    assert meta["measurement_sha256"] == extra["measurement_sha256"]
    assert meta["traffic"]["seed"] == meta["seed"]  # Only the seed: the other traffic fields are placeholders.
    profile = digests(p["profile"])  # The protocol's own profile; the audit compares only with the session's copy.
    assert profile and meta["profile_sha256"] == profile == digests(session.directory / "profile")
    for when in ("before", "after"):
        state = json.loads((session.directory / "guest" / f"state_{when}.json").read_text())
        assert (state["boot_id"], state["kernel"]) == (bs.boot_id(place["group"]), bs.KERNEL)
    assert run.code == 0 and run.values["session_sha256"] == collection.digest(session.directory / "session.json")
    result = session.result
    for i, seq in enumerate(result["seq"]):  # The real readers give the result's perbin, bins and layout.
        path = session.directory / "raw" / f"frame{seq}.json"
        ids, values = perbin_zo_sidecaru(str(path))
        assert list(ids) == result["biny"] and np.array_equal(values, np.asarray(result["perbin"][i]))
        assert validate_sidecar(json.loads(path.read_text())) == result["layout"]


def test_explicit_boot_id_reaches_every_guest_record(families):
    p = families[0]["S3"][0]
    place, boot = bs.places(p, "test_benign")[0], "boot-explicit"
    assert boot != bs.boot_id(place["group"])  # Else the group's default would pass for the argument.
    _, session, run = audited(families, "S3", "explicit-boot", role="test_benign", boot=boot)
    d = session.directory
    meta, end = (json.loads((d / name).read_text()) for name in ("session.json", "end.json"))
    assert meta["guest_before"] == end["guest_after"] == {"kernel": bs.KERNEL, "boot_id": boot,
                                                          "stack_sha256": bs.STACK,
                                                          "stack_manifest": bs.STACK_MANIFEST}
    for when in ("before", "after"):
        state = json.loads((d / "guest" / f"state_{when}.json").read_text())
        assert (state["boot_id"], state["kernel"]) == (boot, bs.KERNEL)
    v = run.values
    assert (run.code, v["accepted"], v["reasons"], v["role"]) == (0, True, [], "test_benign"), v["reasons"]
    assert v["logs"]["accepted"] and v["logs"]["problems"] == []


def test_different_seeds_give_different_archives(families, tmp_path):
    p = families[0]["S3"][0]
    (_, a, run_a), (_, b, run_b) = (audited(families, "S3", f"seed-{index}", role="calibration", index=index)
                                    for index in (0, 1))
    seeds = [json.loads((s.directory / "session.json").read_text())["seed"] for s in (a, b)]
    assert seeds == [r["seed"] for r in bs.places(p, "calibration")[:2]] and seeds[0] != seeds[1]
    assert a.result["matica"] != b.result["matica"]
    assert run_a.values["features_sha256"] != run_b.values["features_sha256"]
    n, _, f = shape(p)
    same = [bs.extraction_result("s", n, f, t0=0., seed=seed)[0] for seed in (1, 1, 2)]
    assert same[0] == same[1] and same[0]["matica"] != same[2]["matica"]
    paths = [bs.save_archive(tmp_path / f"seed{i}.npz", r) for i, r in enumerate(same)]
    loaded = [load(path) for path, _ in paths]
    assert np.array_equal(loaded[0]["matica"], loaded[1]["matica"]) and paths[0][1] == paths[1][1]
    assert not np.array_equal(loaded[0]["matica"], loaded[2]["matica"]) and paths[0][1] != paths[2][1]


def test_forged_archives_keep_times_and_layout(families, tmp_path):
    p = families[0]["S3"][0]
    n, w, f = shape(p)
    clean, _ = bs.extraction_result("forged", n, f, t0=100.)
    first, last = clean["casy"][0], clean["casy"][-1]

    def archive(label, rows=n, **changes):
        result, _ = bs.extraction_result("forged", rows, changes.pop("full_every", f), t0=100., **changes)
        path, sha = bs.save_archive(tmp_path / f"{label}.npz", result)
        again, sha_again = bs.save_archive(tmp_path / f"{label}-again.npz", result)
        # One result saved twice gives the same bytes and the same digest, the SHA-256 of those bytes.
        assert path.read_bytes() == again.read_bytes() and sha == sha_again == sha256(again), label
        return load(path)

    middle = archive("middle", missing={n // 2})
    assert [int(s) for s in middle["seq"]] == [s for s in range(n) if s != n // 2]
    assert (float(middle["casy"][0]), float(middle["casy"][-1])) == (first, last)
    assert float(middle["casy"][n // 2]) == clean["casy"][n // 2 + 1]
    assert middle["matica"][n // 2][bs.MENA.index("ma_predchodcu")] == 0  # No predecessor after a seq gap.
    tail = archive("tail", missing={n - 1})
    assert [int(s) for s in tail["seq"]] == list(range(n - 1))
    skipped = archive("skipped", rows=n + 1, missing={n // 2})
    assert len(skipped["seq"]) == n and int(skipped["seq"][-1]) == n
    short = f // 4
    cadence = archive("cadence", full_every=short)
    assert [bool(x) for x in cadence["matica"][:, bs.MENA.index("je_plna")]] == [s % short == 0 for s in range(n)]
    assert len(set(cadence["chain_ids"])) == -(-n // short)
    assert (float(cadence["casy"][0]), float(cadence["casy"][-1])) == (first, last)
    _, report = scorable_windows(cadence, p, "forged", n)
    assert report["scorable_windows"] == bs.window_count(n, w, short) < p["min_score_coverage"] * n
    finding = archive("finding", quality={n // 2: bs.finding_row()})
    rows = json.loads(str(finding["quality_json"]))
    assert all(finding["valid"]) and [len(q["findings"]) for q in rows].count(1) == 1
    for data in (middle, tail, skipped, cadence, finding):
        assert json.loads(str(data["layout_json"])) == clean["layout"]


def test_audit_restores_the_extractor(families):
    original = collection.retazec
    p, session, run = audited(families, "S3", "restore")
    assert run.code == 0 and collection.retazec is original
    broken = dict(session.result, quality_policy=bs.fq.LEGACY_POLICY)
    with pytest.raises(ValueError, match="extraction quality policy differs from protocol"):
        bs.audit(session, p, output=session.directory / "again.json", result=broken)
    assert collection.retazec is original
