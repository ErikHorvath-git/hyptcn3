"""Continuation of a closed campaign (PLAN_multivm_dataset.md, chapter 8). No root, no libvirt.

Two VMs, four roles with one group per VM, two scenarios per group: 16 sessions, 8 groups of two.
The first campaign has one replacement; its second rejection stops VM b inside its dev group.
"""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import campaign as c
from scripts import collection
from scripts.collection_archive import digest, read_json, write_new
from scripts.tests.test_multivm import multi_protocol, no_inherited_lock  # noqa: F401 (autouse fixture)

RUNTIME = {"vm_swappiness": 1, "collector_sha256": "test-collector"}
PROFILE = {"profile.json": "test-profile"}


def environment(vm):
    return {"kernel": "test-kernel", "machine_id": "machine-" + vm, "stack_sha256": "test-stack"}


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Fake capture/audit subprocesses that serve any campaign under tmp_path; real orchestration and archiver."""
    captures = tmp_path / "collections"
    captures.mkdir()
    source = json.loads(multi_protocol(tmp_path, min_free_gib=0,
                                       roles=dict.fromkeys(("train", "dev", "calibration", "test_benign"), 2),
                                       replacement={"max_per_campaign": 1, "same": ["vm", "role", "scenario"],
                                                    "covers": ["audit_rejected", "capture_incomplete"]}).read_text())
    source["scenarios"] = {k: source["scenarios"][k] for k in ("quiet", "steady")}
    protocol = tmp_path / "protocol.json"
    protocol.write_text(json.dumps(source))
    state = {"tmp": tmp_path, "captures": captures, "protocol": protocol, "calls": [], "reject": set(),
             "boot": {"a": "pilot-a", "b": "pilot-b"}, "reboots": 0, "finished": []}
    qemu = lambda domain: {"pid": len(domain), "start_ticks": 1, "host_boot": "host-boot"}
    monkeypatch.setattr(c, "COLLECTIONS", captures)
    monkeypatch.setattr(c, "BASE", tmp_path)
    for name in ("RETRY_PAUSE_S", "WAIT_POLL_S", "START_GRACE_S"):
        monkeypatch.setattr(c, name, 0)
    monkeypatch.setattr(collection, "qemu_process", qemu)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "test-owner")
    monkeypatch.setattr(collection, "user_command", lambda args: list(map(str, args)))
    monkeypatch.setattr(collection, "guest_identity",
                        lambda p: {**environment(p["vm"]), "boot_id": state["boot"][p["vm"]]})
    monkeypatch.setattr(c, "verify_frozen", lambda *a: None)
    monkeypatch.setattr(c, "hold_sleep_inhibitor", lambda: None)
    monkeypatch.setattr(c, "sleep_inhibited", lambda: False)
    monkeypatch.setattr(c, "guard_mount", lambda *a: None)

    def child(command, log, **kw):
        command = list(map(str, command))
        log.write_text("Synthetic test subprocess\n")
        if "reboot" in command:
            vm = command[command.index("--vm") + 1]
            state["reboots"] += 1
            state["boot"][vm] = f"boot-{vm}-{state['reboots']}"
            return 0
        directory = Path(command[command.index("--protocol") + 1]).parent
        manifest = read_json(directory / "campaign.json")
        find = lambda sid: next(r for r in manifest["sessions"] if r["session_id"] == sid.split("-r")[0])
        if "run" in command:
            vm, sid = command[command.index("--vm") + 1], command[command.index("--session-id") + 1]
            row = find(sid)
            assert row["vm"] == vm and command[command.index("--campaign-id") + 1] == manifest["id"]
            assert command[command.index("--expected-boot-id") + 1] == state["boot"][vm]
            replaces = command[command.index("--replaces") + 1] if "--replaces" in command else None
            state["calls"].append(("capture", manifest["id"], vm, row["group"], sid))
            src = captures / manifest["id"] / vm / sid
            src.mkdir(parents=True)
            identity = {**environment(vm), "boot_id": state["boot"][vm]}
            write_new(src / "session.json", {**row, "session_id": sid, "schema": "hyptcn3/collection-session/2",
                       **({"replaces": replaces} if replaces else {}),
                       "campaign_id": manifest["id"], "commit": manifest["commit"], "measurement_dirty": [],
                       "host_context": {"qemu": qemu(collection.for_vm(
                           collection.protocol(directory / "protocol.json"), vm)["domain"])},
                       "protocol_sha256": manifest["protocol_sha256"], "guest_before": identity})
            (src / "raw").mkdir()
            (src / "raw/frame.vmicd").write_bytes(b"synthetic RAM " + sid.encode())
            write_new(src / "end.json", {"completed": True, "guest_after": identity, "measurement_started": True})
            return 0
        src, report = Path(command[command.index("audit") + 1]), Path(command[command.index("--out") + 1])
        row = find(src.name)
        state["calls"].append(("audit", manifest["id"], row["vm"], row["group"], src.name))
        feature = report.with_suffix(".npz")
        feature.write_bytes(b"synthetic feature archive " + src.name.encode())
        accepted = src.name not in state["reject"]
        write_new(report, {"schema": "hyptcn3/collection-audit/1", "commit": manifest["commit"],
                  "measurement_dirty": [],
                  "values": {"accepted": accepted, "reasons": [] if accepted else ["missed sampling slot"],
                             "protocol_sha256": manifest["protocol_sha256"],
                             "extractor_sha256": manifest["extractor_sha256"], "session_dir": str(src),
                             "role": row["role"], "session_sha256": digest(src / "session.json"),
                             "source_sha256": {"frame.vmicd": digest(src / "raw/frame.vmicd")},
                             "features": str(feature), "features_sha256": digest(feature)}})
        return 0 if accepted else 2
    monkeypatch.setattr(c, "run_child", child)

    def finish(directory, manifest, protocol, reports):
        state["finished"].append((manifest["id"], manifest["vm"], list(reports)))
        c.update_state(directory, vm=manifest["vm"], status="complete", stage="complete")
    monkeypatch.setattr(c, "finish_corpus", finish)
    monkeypatch.setattr(c, "process_identity", lambda pid: {"alive": pid} if pid == os.getpid() else None)
    return state


def campaign(lab, name, commit="first-commit", continues=None, env=environment, **changes):
    """A frozen campaign directory as init leaves it; continues: the closed campaign it takes over from."""
    directory = lab["tmp"] / name
    for child in ("events", "groups", "attempts", "logs"):
        (directory / child).mkdir(parents=True)
    (directory / "protocol.json").write_bytes(lab["protocol"].read_bytes())
    p = collection.protocol(directory / "protocol.json")
    rows = collection.plan(p)["sessions"]
    for i, row in enumerate(rows):
        row["session_id"] = f"{name}_{i:02d}_{row['vm']}"
    external = lab["tmp"] / "external" / name
    external.mkdir(parents=True)
    per_vm = {}
    for vm in ("a", "b"):
        write_new(directory / f"pilot-{vm}.json", {"synthetic": vm, "campaign": name})
        per_vm[vm] = {"guest_environment": env(vm), "pilot_report_sha256": digest(directory / f"pilot-{vm}.json"),
                      "estimated_session_bytes_with_reserve": 100, "estimated_archive_bytes_per_session": 10}
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": name, "workspace": str(c.ROOT), "commit": commit,
                "sessions": rows, "owner": {"name": "test-owner"}, "extractor_sha256": {"test": "test"},
                "profile_sha256": PROFILE, "runtime": RUNTIME, "vms": per_vm,
                "protocol_sha256": digest(directory / "protocol.json"),
                "archive_dir": str(external), "archive_root": str(external), "archive_mount": {},
                "planned_capture_hours": len(rows), **changes}
    if continues is not None:
        manifest["continues"] = c.take_over(continues, manifest, p)
    write_new(directory / "campaign.json", manifest)
    return directory


def rows_of(directory, **where):
    return [r for r in read_json(directory / "campaign.json")["sessions"]
            if all(r[k] == v for k, v in where.items())]


def captures(lab, directory):
    return [call for call in lab["calls"] if call[:2] == ("capture", directory.name)]


def run_to_end(directory):
    for _ in range(10):
        for vm in ("a", "b"):
            c.execute(directory, vm=vm)
        if all(read_json(directory / f"status-{vm}.json")["status"] == "complete" for vm in ("a", "b")):
            return
    pytest.fail("campaign did not complete")


@pytest.fixture
def stopped(lab):
    """The first campaign, stopped for good inside VM b's dev group and closed by the operator."""
    first = campaign(lab, "prva")
    quiet, steady = (r["session_id"] for r in rows_of(first, vm="b", role="dev"))
    lab["reject"].update({quiet, steady})  # quiet is replaced (the only replacement), steady cannot be.
    c.execute(first, vm="a")  # train, then waits for VM b
    with pytest.raises(ValueError, match="archived without replacement"):
        c.execute(first, vm="b")  # train, dev: quiet rejected and replaced, steady rejected
    c.execute(first, vm="a")  # dev, then VM b can never finish dev
    assert "VM b has not finished the roles before calibration" in read_json(first / "status-a.json")["message"]
    assert len(captures(lab, first)) == 4 + 2 + 3
    lab.update(first=first, quiet=quiet, steady=steady)
    return first


def test_continuation_takes_over_complete_groups_and_captures_the_rest(lab, stopped):
    first = stopped
    with pytest.raises(ValueError, match="closed by the operator"):
        campaign(lab, "skoro", "second-commit", continues=first)
    c.close(first, "replacements used up; continued under chapter 8")
    second = campaign(lab, "druha", "second-commit", continues=first)
    manifest = read_json(second / "campaign.json")
    record = manifest["continues"]
    # Train on both VMs and dev on VM a are complete there; VM b's dev group is not.
    taken = {r["session_id"] for role, vm in (("train", "a"), ("train", "b"), ("dev", "a"))
             for r in rows_of(second, role=role, vm=vm)}
    assert set(record["sessions"]) == taken and len(taken) == 6
    old_ids = {r["session_id"] for r in rows_of(first)}
    assert {s["session_id"] for s in record["sessions"].values()} <= old_ids
    group = rows_of(first, vm="b", role="dev")[0]["group"]
    old_boot = read_json(first / "groups" / (group + ".json"))["identity"]["boot_id"]
    assert record["discarded_groups"] == [{"group": group, "role": "dev", "vm": "b", "boot_id": old_boot,
                                           "accepted_sessions": [lab["quiet"] + "-r1"]}]
    assert (record["campaign"], record["commit"], record["replacements_used"], record["not_replaced"]) \
        == ("prva", "first-commit", 1, [lab["steady"]])
    assert record["campaign_sha256"] == digest(first / "campaign.json")

    lab["reject"].clear()
    reboots = lab["reboots"]
    run_to_end(second)
    new = captures(lab, second)
    # VM b's dev group again as a whole, then calibration and test_benign on both VMs; nothing of the taken groups.
    assert len(new) == 2 + 4 + 4 and lab["reboots"] - reboots == 5
    assert not {call[4] for call in new} & taken
    assert [call[3] for call in new if call[2] == "b"][:2] == [group, group]
    assert read_json(second / "groups" / (group + ".json"))["identity"]["boot_id"] != old_boot
    roles = list(collection.protocol(second / "protocol.json")["roles"])
    order = [roles.index(call[3].rsplit("-", 1)[0]) for call in new]
    assert order == sorted(order)
    # One index over both campaigns, in plan order: taken-over rows through the closed campaign's audits.
    builder = lab["finished"][0]
    assert builder[0] == "druha" and all(later[2] == builder[2] for later in lab["finished"])
    reports = builder[2]
    assert len(reports) == len(set(reports)) == 16
    where = [Path(read_json(r)["values"]["session_dir"]) for r in reports]
    for row, session in zip(manifest["sessions"], where):
        if row["session_id"] in taken:
            assert session.parts[-3] == "prva" and session.name == record["sessions"][row["session_id"]]["session_id"]
        else:
            assert session.parts[-3] == "druha" and session.name == row["session_id"]
    assert lab["quiet"] + "-r1" not in {s.name for s in where}  # Accepted there, but its group was discarded.
    assert all(read_json(r)["values"]["accepted"] for r in reports)
    status = c.status(second)["vms"]
    assert (status["a"]["taken_over"], status["b"]["taken_over"]) == (4, 2)
    assert status["a"]["continues"] == "prva" and status["a"]["accepted_archived"] == status["b"]["accepted_archived"] == 8
    calls = list(lab["calls"])
    run_to_end(second)
    assert lab["calls"] == calls


def test_continuation_needs_the_same_protocol_code_and_guests(lab, stopped):
    first = stopped
    c.close(first, "stopped")
    for changes, what in (({"extractor_sha256": {"test": "other"}}, "extractor_sha256"),
                          ({"runtime": {**RUNTIME, "collector_sha256": "rebuilt"}}, "runtime"),
                          ({"profile_sha256": {"profile.json": "other"}}, "profile_sha256"),
                          ({"protocol_sha256": "other"}, "protocol_sha256")):
        with pytest.raises(ValueError, match="differs from the closed campaign: " + what):
            campaign(lab, "ina-" + what, "second-commit", continues=first, **changes)
    other_guest = lambda vm: {**environment(vm), **({"kernel": "other-kernel"} if vm == "b" else {})}
    with pytest.raises(ValueError, match=r"differs from the closed campaign: guest_environment \(b\)"):
        campaign(lab, "iny-host", "second-commit", continues=first, env=other_guest)


def test_a_campaign_is_continued_once_and_a_continuation_never(lab, stopped):
    first = stopped
    c.close(first, "stopped")
    # A continuation closed before it captured anything may be set up again.
    unused = campaign(lab, "nepouzita", "second-commit", continues=first)
    with pytest.raises(ValueError, match="already has a continuation: nepouzita"):
        campaign(lab, "odmietnuta", "second-commit", continues=first)
    c.close(unused, "wrong pilot")
    second = campaign(lab, "druha", "second-commit", continues=first)
    lab["reject"].clear()
    c.execute(second, vm="b", stop_after=1)
    c.close(second, "stopped again")
    with pytest.raises(ValueError, match="already has a continuation: druha"):
        campaign(lab, "tretia", "third-commit", continues=first)
    with pytest.raises(ValueError, match="cannot be continued again"):
        campaign(lab, "stvrta", "third-commit", continues=second)


def test_records_of_taken_sessions_must_still_agree(lab, stopped):
    first = stopped
    c.close(first, "stopped")
    old = rows_of(first, vm="a", role="train")[0]
    report = Path(read_json(first / "attempts" / (old["session_id"] + ".audit.json"))["path"])
    feature = report.with_suffix(".npz")
    original = feature.read_bytes()
    feature.write_bytes(b"changed")
    with pytest.raises(ValueError, match=old["session_id"] + " cannot be taken over, records disagree: features"):
        campaign(lab, "zla", "second-commit", continues=first)
    feature.write_bytes(original)
    second = campaign(lab, "druha", "second-commit", continues=first)
    # After the freeze: the audit the index would use is checked again by every run.
    text = report.read_text()
    report.write_text(text.replace('"reasons": []', '"reasons": ["edited"]'))
    with pytest.raises(ValueError, match="audit of a taken-over session changed: " + old["session_id"]):
        c.execute(second, vm="a")
    report.write_text(text)
    # The frozen list of taken sessions cannot name an assignment outside the plan.
    manifest = read_json(second / "campaign.json")
    manifest["continues"]["sessions"]["druha_99_a"] = next(iter(manifest["continues"]["sessions"].values()))
    (second / "campaign.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="plan or frozen"):
        c.load_campaign(second)


def test_capacity_counts_only_sessions_still_to_capture(lab, stopped, monkeypatch):
    first = stopped
    c.close(first, "stopped")
    second = campaign(lab, "druha", "second-commit", continues=first)
    manifest, p = c.vm_view(*c.load_campaign(second), "a")
    free = {"value": 0}
    monkeypatch.setattr(c.shutil, "disk_usage", lambda path: SimpleNamespace(free=free["value"]))
    mine = sum(r["vm"] == "a" and c.taken_over(manifest, r) is None for r in manifest["sessions"])
    assert mine == 4
    # Working disk: this VM's session and the other VM's. Archive: 10 bytes for each of the 4 + 6
    # sessions still to capture, not for the 6 taken over (max: both must fit).
    free["value"] = 200
    c.capacity_guard(manifest, p, mine, second)
    free["value"] = 199
    with pytest.raises(ValueError, match="working space"):
        c.capacity_guard(manifest, p, mine, second)
    monkeypatch.setattr(c.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=1000 if Path(path) == c.COLLECTIONS else free["value"]))
    free["value"] = 100
    c.capacity_guard(manifest, p, mine, second)
    free["value"] = 99
    with pytest.raises(ValueError, match="archive space"):
        c.capacity_guard(manifest, p, mine, second)


def test_init_freezes_the_continuation(lab, stopped, monkeypatch):
    first = stopped
    c.close(first, "stopped")
    pilots = {}
    for vm in ("a", "b"):
        pilots[vm] = lab["tmp"] / f"new-pilot-{vm}.json"
        write_new(pilots[vm], {"values": {"session_dir": str(lab["tmp"] / f"pilot-session-{vm}")}, "vm": vm})

    def gate(path, protocol_path, p):
        vm = read_json(path)["vm"]
        return ({"vm": vm, "guest_before": {**environment(vm), "boot_id": "pilot"}, "profile_sha256": PROFILE,
                 "host_context": {"memory": {"vm_swappiness": 1}}}, 100)
    monkeypatch.setattr(c, "pilot_gate", gate)
    monkeypatch.setattr(c, "git", lambda *args: "" if args[0] == "status" else "second-commit")
    monkeypatch.setattr(c, "runtime_identity", lambda: RUNTIME)
    monkeypatch.setattr(c, "extractor_hashes", lambda: {"test": "test"})
    monkeypatch.setattr(c, "archive_estimate", lambda *a: {"bytes_per_session": 10})
    monkeypatch.setattr(c, "mount_identity", lambda *a, **kw: {})
    arguments = SimpleNamespace(protocol=first / "protocol.json", name="druha", archive_compression="zstd",
                                pilot_report=[f"{vm}={path}" for vm, path in pilots.items()],
                                archive_root=lab["tmp"] / "external" / "init", archive_on_system_disk=True,
                                continues=first)
    second = c.initialize(arguments)
    manifest, _ = c.load_campaign(second)
    assert manifest["continues"]["campaign"] == "prva" and len(manifest["continues"]["sessions"]) == 6
    # The list is part of the frozen manifest and of its copy next to the archive.
    assert digest(Path(manifest["archive_dir"]) / "campaign.json") == digest(second / "campaign.json")
    states = {vm: read_json(second / f"status-{vm}.json") for vm in ("a", "b")}
    assert [(states[vm]["accepted_archived"], states[vm]["total"]) for vm in ("a", "b")] == [(4, 8), (2, 8)]
    lab["reject"].clear()
    monkeypatch.setenv("SUDO_USER", manifest["owner"]["name"])  # init records the real account as owner.
    run_to_end(second)
    assert len(captures(lab, second)) == 10 and len(lab["finished"][0][2]) == 16
    # Without --continue the closed campaign's groups are simply free again: a whole new campaign.
    arguments.name, arguments.continues = "cela", None
    with pytest.raises(ValueError, match="planned group already has data"):
        c.initialize(arguments)  # ... but not while the continuation is open.


def test_taken_and_recaptured_groups_pass_the_corpus_builder(tmp_path):
    """features/dataset.py as it is: a group captured again in a new boot is indexed alone, never with its old part."""
    from features import dataset
    from features.tests.test_dataset import protocol, record
    train = record(tmp_path, "train", 0)  # Taken over from the closed campaign.
    old_dev = record(tmp_path, "dev", 1, boot="old-boot")  # Its group was not complete there.
    new_dev = record(tmp_path, "dev", 2, boot="new-boot")  # The same group, whole, in the continuation.
    later = [record(tmp_path, role, 3 + i) for i, role in enumerate(("calibration", "test_benign"))]
    assert dataset.build([train, new_dev, *later], protocol(), "protocol-test")["complete"]
    with pytest.raises(ValueError, match="boot/group mapping is not one to one"):
        dataset.build([train, old_dev, new_dev, *later], protocol(), "protocol-test")
