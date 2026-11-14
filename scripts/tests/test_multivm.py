"""Several lab VMs on one host: naming, group plan, exclusivity, audit lock. No root, no libvirt."""
import fcntl
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from scripts import campaign as c
from scripts import collection
from scripts import labctl
from scripts.collection_archive import digest, read_json, write_new

VMS = [{"name": "a", "domain": "hyptcn-lab", "port": 18080}, {"name": "b", "domain": "hyptcn-lab-b", "port": 18081}]


ROLES = {"train": 6, "dev": 2, "calibration": 4, "test_benign": 4}  # Groups over all VMs.


def multi_protocol(tmp_path, vms=VMS, **changes):
    doc = json.loads(collection.DEFAULT.read_text())
    doc["roles"] = ROLES
    if vms is not None:
        del doc["domain"], doc["target"]
        doc["vms"] = vms
    doc.update(changes)
    path = tmp_path / f"protocol-{'multi' if vms else 'single'}.json"
    path.write_text(json.dumps(doc))
    return path


@pytest.fixture(autouse=True)
def no_inherited_lock(monkeypatch):
    monkeypatch.delenv("HYPTCN_COLLECTION_LOCK_FD", raising=False)


# --- labctl: per-VM names ---------------------------------------------------------------------

def test_single_vm_keeps_original_names():
    lab = labctl.Lab()
    assert lab.state_file == labctl.REPO / "vms/lab-state.json"
    assert lab.unit == "hyptcn-lab-traffic"
    assert lab.target() == "http://127.0.0.1:18080"
    assert lab.traffic_status == labctl.REPO / "data/lab/traffic.json"


def test_named_vm_has_its_own_state_unit_port_and_status():
    lab = labctl.Lab(domain="hyptcn-lab-b", vm="b", port=18081)
    assert lab.state_file == labctl.REPO / "vms/lab-state-b.json"
    assert lab.unit == "hyptcn-lab-traffic-b"
    assert lab.target() == "http://127.0.0.1:18081"
    assert lab.traffic_status == labctl.REPO / "data/lab/traffic-b.json"
    for bad in ({"vm": "../x"}, {"vm": "B"}, {"port": 80}, {"port": "18081"}):
        with pytest.raises(ValueError):
            labctl.Lab(**{"domain": "hyptcn-lab-b", "vm": "b", "port": 18081, **bad})


@pytest.mark.parametrize("argv", [["status", "--vm", "b"], ["status", "--port", "18081"], ["clone"]])
def test_labctl_refuses_half_named_vm_before_touching_anything(argv, monkeypatch):
    monkeypatch.setattr(labctl, "run", lambda *a, **k: pytest.fail("no command may run"))
    monkeypatch.setattr(labctl.subprocess, "run", lambda *a, **k: pytest.fail("no command may run"))
    with pytest.raises(SystemExit):
        labctl.main(argv)


def fake_clone(tmp_path, monkeypatch, lab):
    calls = []
    monkeypatch.setattr(labctl, "REPO", tmp_path)
    monkeypatch.setattr(labctl.shutil, "which", lambda name: "/usr/bin/" + name)

    def run(args, **kw):
        args = list(map(str, args))
        calls.append(args)
        if args[0] == "qemu-img":
            Path(args[-1]).write_bytes(b"disk")
        if args[0] == "guestfish":
            assert Path(args[args.index("-a") + 1]).name.endswith(".partial.qcow2")  # Not yet the VM's disk.

    def virsh(*args):
        calls.append(list(args))
        return {"list": "hyptcn-guest", "domstate": "shut off", "define": "",
                "dumpxml": "<domain><devices><disk device='disk'><source file='/x/guest.qcow2'/></disk>"
                           "</devices></domain>"}[args[0]]
    monkeypatch.setattr(labctl, "run", run)
    monkeypatch.setattr(lab, "virsh", virsh)
    lab.clone("hyptcn-guest")
    definition = ET.parse(tmp_path / "vms" / f"{lab.domain}.xml")
    return calls, definition


def test_clone_of_named_vm_gets_identity_before_first_boot(tmp_path, monkeypatch):
    lab = labctl.Lab(domain="hyptcn-lab-b", vm="b", port=18081)
    calls, definition = fake_clone(tmp_path, monkeypatch, lab)
    order = [call[0] for call in calls]
    assert order.index("qemu-img") < order.index("guestfish") < order.index("define")
    assert "start" not in order
    guestfish = next(call for call in calls if call[0] == "guestfish")
    machine_id = guestfish[guestfish.index("/etc/machine-id") + 1]
    assert re.fullmatch(r"[0-9a-f]{32}\n", machine_id)
    assert guestfish[guestfish.index("/etc/hostname") + 1] == "hyptcn-lab-b\n"
    assert definition.find("./devices/interface/portForward/range").get("start") == "18081"
    assert (tmp_path / "vms/hyptcn-lab-b.qcow2").exists()
    assert not (tmp_path / "vms/hyptcn-lab-b.partial.qcow2").exists()


def test_clone_of_single_vm_is_unchanged(tmp_path, monkeypatch):
    calls, definition = fake_clone(tmp_path, monkeypatch, labctl.Lab())
    assert "guestfish" not in [call[0] for call in calls]
    assert definition.find("./devices/interface/portForward/range").get("start") == "18080"


def test_wrong_port_cannot_reach_another_vm(monkeypatch):
    lab = labctl.Lab(domain="hyptcn-lab-b", vm="b", port=18081)
    xml = ("<domain><description>hyptcn3 benign persistent lab</description><devices><interface>"
           "<portForward><range start='18080' to='8080'/></portForward></interface></devices></domain>")
    monkeypatch.setattr(lab, "virsh", lambda *args: xml)
    with pytest.raises(RuntimeError, match="does not forward host port 18081"):
        lab.owned()
    lab.port = 18080
    lab.owned()


# --- protocol and plan ------------------------------------------------------------------------

def test_single_vm_protocol_is_one_unnamed_vm():
    p = collection.protocol(collection.DEFAULT)
    assert collection.vms(p) == [{"name": None, "domain": p["domain"], "target": p["target"]}]
    assert collection.for_vm(p, None) is p
    assert collection.labctl_args(p) == ["--domain", p["domain"]]
    assert all("vm" not in s for s in collection.plan(p)["sessions"])
    with pytest.raises(ValueError, match="no VM a"):
        collection.for_vm(p, "a")


def test_vm_view_of_a_multi_vm_protocol(tmp_path):
    p = collection.protocol(multi_protocol(tmp_path))
    b = collection.for_vm(p, "b")
    assert (b["vm"], b["domain"], b["target"]) == ("b", "hyptcn-lab-b", "http://127.0.0.1:18081")
    assert collection.labctl_args(b) == ["--domain", "hyptcn-lab-b", "--vm", "b", "--port", "18081"]
    with pytest.raises(ValueError, match="choose one of: a, b"):
        collection.for_vm(p, None)
    with pytest.raises(ValueError, match="no VM c"):
        collection.for_vm(p, "c")


@pytest.mark.parametrize("vms, changes, message", [
    (VMS, {"domain": "hyptcn-lab"}, "either vms or one domain"),
    ([], {}, "either vms or one domain"),
    ([VMS[0], {**VMS[1], "port": 18080}], {}, "unique"),
    ([VMS[0], {**VMS[1], "domain": "hyptcn-lab"}], {}, "unique"),
    ([VMS[0], {**VMS[1], "name": "B/../x"}], {}, "invalid VM"),
    ([VMS[0], {**VMS[1], "port": 80}], {}, "invalid VM"),
    (VMS, {"roles": {"train": 2, "dev": 1, "calibration": 2, "test_benign": 2}}, "every role"),
])
def test_protocol_rejects_ambiguous_vm_lists(tmp_path, vms, changes, message):
    with pytest.raises(ValueError, match=message):
        collection.protocol(multi_protocol(tmp_path, vms, **changes))


def test_multi_vm_plan_is_the_single_vm_plan_with_a_vm_per_group(tmp_path):
    p = collection.protocol(multi_protocol(tmp_path))
    result = collection.plan(p)
    assert collection.plan(collection.protocol(multi_protocol(tmp_path))) == result  # Fixed before collection.
    single = collection.plan(collection.protocol(multi_protocol(tmp_path, None)))["sessions"]
    assert len(single) == 16 * 6
    assert [{k: v for k, v in s.items() if k != "vm"} for s in result["sessions"]] == single
    owner = {}
    for s in result["sessions"]:
        assert owner.setdefault(s["group"], s["vm"]) == s["vm"]  # A group is one boot of one VM.
    assert result["sessions_per_vm"] == {"a": len(single) // 2, "b": len(single) // 2}


@pytest.mark.parametrize("vms", [VMS, [*VMS, {"name": "c", "domain": "hyptcn-lab-c", "port": 18082}]])
def test_every_role_has_groups_on_every_vm_in_role_order(tmp_path, vms):
    roles = {"train": 6, "dev": 3, "calibration": 4, "test_benign": 4, "test_events": 8}
    p = collection.protocol(multi_protocol(tmp_path, vms, roles=roles))
    sessions = collection.plan(p)["sessions"]
    names = {v["name"] for v in vms}
    for role in roles:
        assert {s["vm"] for s in sessions if s["role"] == role} == names
    order = list(roles)
    for name in names:  # Train before test within each VM.
        mine = [order.index(s["role"]) for s in sessions if s["vm"] == name]
        assert mine == sorted(mine)


def test_odd_and_even_groups_are_not_split_by_vm(tmp_path):
    """The classifier trains on odd and tests on even test_events groups; VM must not be that split."""
    p = collection.protocol(multi_protocol(tmp_path, roles={"test_events": 8, "test_events_e2": 2}))
    groups = {s["group"]: s["vm"] for s in collection.plan(p)["sessions"]}
    for parity in (0, 1):
        on = {vm for group, vm in groups.items()
              if group.startswith("test_events-") and int(group.rsplit("-", 1)[1]) % 2 == parity}
        assert on == {"a", "b"}
    assert sorted(vm for group, vm in groups.items() if group.startswith("test_events-")) == ["a"] * 4 + ["b"] * 4
    assert {vm for group, vm in groups.items() if group.startswith("test_events_e2-")} == {"a", "b"}


# --- per-domain exclusivity -------------------------------------------------------------------

def blocked(base, domain=None):
    with pytest.raises(BlockingIOError):
        with collection.collection_lock(base, domain):
            pass


def test_collection_lock_refuses_only_the_same_domain(tmp_path):
    with collection.collection_lock(tmp_path, "hyptcn-lab"):
        with collection.collection_lock(tmp_path, "hyptcn-lab-b"):
            blocked(tmp_path, "hyptcn-lab-b")
        blocked(tmp_path, "hyptcn-lab")
        blocked(tmp_path)  # A single-VM run or the detector (exclusive .lock) is refused meanwhile.
    with collection.collection_lock(tmp_path):
        blocked(tmp_path, "hyptcn-lab-b")
    with collection.collection_lock(tmp_path, "hyptcn-lab"):
        pass


def test_domain_lock_is_inherited_by_the_capture_child(tmp_path, monkeypatch):
    with collection.collection_lock(tmp_path, "hyptcn-lab") as fd:
        monkeypatch.setenv("HYPTCN_COLLECTION_LOCK_FD", str(fd))
        with collection.collection_lock(tmp_path, "hyptcn-lab"):
            pass
        with pytest.raises(ValueError, match="another file"):
            with collection.collection_lock(tmp_path, "hyptcn-lab-b"):
                pass


PROCESSES = [
    (10, [b"/usr/bin/python3", b"/repo/scripts/host_traffic.py", b"--profile", b"lab",
          b"--target", b"http://127.0.0.1:18080", b"--dur", b"0"]),
    (11, [b"python3", b"scripts/host_traffic.py", b"--target=http://127.0.0.1:18081"]),
    (20, [b"vmicollect/build/vmicollect", b"run", b"-o", b"vm.domain=hyptcn-lab", b"-o", b"vm.backend=ebpf"]),
    (21, [b"/repo/vmicollect/build/vmicollect", b"run", b"-o", b"vm.domain=hyptcn-lab-b"]),
    (30, [b"vim", b"notes about host_traffic.py --target http://127.0.0.1:18080 vm.domain=hyptcn-lab"]),
]


def test_foreign_traffic_and_collectors_are_judged_per_vm(tmp_path, monkeypatch):
    monkeypatch.setattr(collection, "processes", lambda: iter(PROCESSES))
    monkeypatch.setattr(collection, "qemu_process", lambda domain: {"pid": len(domain)})
    p = collection.protocol(multi_protocol(tmp_path))
    a, b = collection.for_vm(p, "a"), collection.for_vm(p, "b")
    assert collection.foreign_traffic(a) == [10] and collection.foreign_traffic(b) == [11]
    assert collection.foreign_traffic(a, {10}) == []  # The session's own generator.
    assert collection.collectors("hyptcn-lab") == [20] and collection.collectors("hyptcn-lab-b") == [21]
    assert collection.collectors("hyptcn-lab-c") == []
    # Single-VM protocol: any generator on the host is foreign, as before.
    assert collection.foreign_traffic(collection.protocol(collection.DEFAULT)) == [10, 11]
    assert collection.other_vms(a) == [{"vm": "b", "domain": "hyptcn-lab-b", "qemu": {"pid": 12},
                                        "collectors": [21], "generators": [11]}]


def test_monitor_labels_processes_per_vm(tmp_path):
    single = collection.protocol(collection.DEFAULT)
    assert collection.monitor_matches(single) == [
        "qemu=guest=hyptcn-lab,", "vmicollect=vmicollect/build/vmicollect", "traffic=host_traffic.py",
        "passt=^passt ", "monitor=host_monitor.py"]
    p = collection.protocol(multi_protocol(tmp_path))
    matches = dict((label, re.compile(rx)) for label, _, rx in
                   (m.partition("=") for m in collection.monitor_matches(collection.for_vm(p, "a"))))
    lines = {  # Assumed command lines; the passt one is libvirt's usual form.
        "qemu": "/usr/bin/qemu-system-x86_64 -name guest={domain},debug-threads=on -S",
        "vmicollect": "vmicollect/build/vmicollect run -o vm.domain={domain} -o vm.backend=ebpf",
        "traffic": "/usr/bin/python3 /repo/scripts/host_traffic.py --profile lab --target http://127.0.0.1:{port} --dur 0",
        "passt": "passt --one-off --socket /run/user/1000/libvirt/qemu/run/passt/3-{domain}-net0.socket "
                 "--tcp-ports 127.0.0.1/{port}:8080"}
    for kind, line in lines.items():
        own, other = line.format(**VMS[0]), line.format(**VMS[1])
        assert matches[kind].search(own) and not matches[kind].search(other)
        assert matches[kind + "@b"].search(other) and not matches[kind + "@b"].search(own)


def test_session_records_cover_both_layouts_and_survive_a_concurrent_writer(tmp_path, monkeypatch):
    for relative in ("flat-1", "kampan/a/s-1", "kampan/b/s-2", "_bez-kampane/a/pilot-1"):
        (tmp_path / relative).mkdir(parents=True)
        (tmp_path / relative / "session.json").write_text(json.dumps({"id": relative}))
    partial = tmp_path / "kampan/b/s-2/session.json"
    partial.write_text('{"id": ')  # Another VM's runner is writing it right now.
    monkeypatch.setattr(collection.time, "sleep", lambda s: partial.write_text(json.dumps({"id": "kampan/b/s-2"})))
    found = {doc["id"] for _, doc in collection.session_records(tmp_path)}
    assert found == {"flat-1", "kampan/a/s-1", "kampan/b/s-2", "_bez-kampane/a/pilot-1"}


# --- campaign with one runner per VM ----------------------------------------------------------

@pytest.fixture
def multi(tmp_path, monkeypatch):
    """Fake capture/audit subprocesses for two VMs; real orchestration, files and archiver."""
    directory = tmp_path / "multi-campaign"
    for name in ("events", "groups", "attempts", "logs"):
        (directory / name).mkdir(parents=True)
    captures, external = tmp_path / "collections", tmp_path / "external"
    captures.mkdir()
    external.mkdir()
    doc = json.loads(multi_protocol(tmp_path, roles=dict.fromkeys(("train", "dev", "calibration", "test_benign"), 2),
                                    min_free_gib=0).read_text())
    doc["scenarios"] = {"quiet": doc["scenarios"]["quiet"]}
    write_new(directory / "protocol.json", doc)
    p = collection.protocol(directory / "protocol.json")
    rows = collection.plan(p)["sessions"]
    for i, row in enumerate(rows):
        row["session_id"] = f"multi-campaign_{i:02d}_{row['vm']}"
    env = lambda vm: {"kernel": "test-kernel", "machine_id": "machine-" + vm, "stack_sha256": "test-stack"}
    per_vm = {}
    for vm in ("a", "b"):
        write_new(directory / f"pilot-{vm}.json", {"synthetic": vm})
        per_vm[vm] = {"guest_environment": env(vm), "pilot_report_sha256": digest(directory / f"pilot-{vm}.json"),
                      "estimated_session_bytes_with_reserve": 100, "estimated_archive_bytes_per_session": 10}
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": directory.name,
                "workspace": str(c.ROOT), "commit": "test-commit", "sessions": rows,
                "owner": {"name": "test-owner"}, "extractor_sha256": {"test": "test"}, "vms": per_vm,
                "protocol_sha256": digest(directory / "protocol.json"),
                "archive_dir": str(external), "archive_root": str(external), "archive_mount": {},
                "planned_capture_hours": len(rows)}
    write_new(directory / "campaign.json", manifest)
    state = {"directory": directory, "manifest": manifest, "p": p, "rows": rows, "captures": captures,
             "calls": [], "boot": {"a": "pilot-a", "b": "pilot-b"}, "reboots": 0, "finished": []}
    qemu = lambda domain: {"pid": len(domain), "start_ticks": 1, "host_boot": "host-boot"}
    monkeypatch.setattr(c, "COLLECTIONS", captures)
    monkeypatch.setattr(c, "BASE", tmp_path)
    for name in ("RETRY_PAUSE_S", "WAIT_POLL_S", "START_GRACE_S"):
        monkeypatch.setattr(c, name, 0)
    monkeypatch.setattr(collection, "qemu_process", qemu)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "test-owner")
    monkeypatch.setattr(collection, "user_command", lambda args: list(map(str, args)))
    monkeypatch.setattr(collection, "guest_identity", lambda p: {**env(p["vm"]), "boot_id": state["boot"][p["vm"]]})
    monkeypatch.setattr(c, "verify_frozen", lambda *a: None)
    monkeypatch.setattr(c, "hold_sleep_inhibitor", lambda: None)
    monkeypatch.setattr(c, "sleep_inhibited", lambda: False)
    monkeypatch.setattr(c, "guard_mount", lambda *a: None)

    def child(command, log, **kw):
        command = list(map(str, command))
        log.write_text("Synthetic test subprocess\n")
        if "reboot" in command:
            vm = command[command.index("--vm") + 1]
            assert command[command.index("--port") + 1] == str(collection.for_vm(p, vm)["port"])
            state["reboots"] += 1
            state["boot"][vm] = f"boot-{vm}-{state['reboots']}"
            return 0
        if "run" in command:
            vm = command[command.index("--vm") + 1]
            sid = command[command.index("--session-id") + 1]
            row = next(r for r in rows if r["session_id"] == sid)
            assert row["vm"] == vm and command[command.index("--pilot-report") + 1].endswith(f"pilot-{vm}.json")
            assert command[command.index("--expected-boot-id") + 1] == state["boot"][vm]
            state["calls"].append(("capture", vm, row["group"]))
            src = captures / manifest["id"] / vm / sid
            src.mkdir(parents=True)
            identity = {**env(vm), "boot_id": state["boot"][vm]}
            write_new(src / "session.json", {**row, "schema": "hyptcn3/collection-session/2",
                       "campaign_id": manifest["id"], "commit": manifest["commit"], "measurement_dirty": [],
                       "host_context": {"qemu": qemu(collection.for_vm(p, vm)["domain"])},
                       "protocol_sha256": manifest["protocol_sha256"], "guest_before": identity})
            (src / "raw").mkdir()
            (src / "raw/frame.vmicd").write_bytes(b"synthetic RAM " + sid.encode())
            write_new(src / "end.json", {"completed": True, "guest_after": identity, "measurement_started": True})
            return 0
        src = Path(command[command.index("audit") + 1])
        report = Path(command[command.index("--out") + 1])
        row = next(r for r in rows if r["session_id"] == src.name)
        state["calls"].append(("audit", row["vm"], row["group"]))
        feature = report.with_suffix(".npz")
        feature.write_bytes(b"synthetic feature archive")
        write_new(report, {"schema": "hyptcn3/collection-audit/1", "commit": manifest["commit"],
                  "measurement_dirty": [],
                  "values": {"accepted": True, "reasons": [], "protocol_sha256": manifest["protocol_sha256"],
                             "extractor_sha256": manifest["extractor_sha256"], "session_dir": str(src),
                             "role": row["role"], "session_sha256": digest(src / "session.json"),
                             "source_sha256": {"frame.vmicd": digest(src / "raw/frame.vmicd")},
                             "features": str(feature), "features_sha256": digest(feature)}})
        return 0
    monkeypatch.setattr(c, "run_child", child)

    def finish(directory, manifest, protocol, reports):
        state["finished"].append((manifest["vm"], protocol, list(reports)))
        c.update_state(directory, vm=manifest["vm"], status="complete", stage="complete")
    monkeypatch.setattr(c, "finish_corpus", finish)
    monkeypatch.setattr(c, "process_identity", lambda pid: {"alive": pid} if pid == os.getpid() else None)
    return state


def vm_state(multi, vm):
    return read_json(multi["directory"] / f"status-{vm}.json")


def run_to_end(multi):
    for _ in range(10):
        for vm in ("a", "b"):
            c.execute(multi["directory"], vm=vm)
        if vm_state(multi, "a")["status"] == vm_state(multi, "b")["status"] == "complete":
            return
    pytest.fail("campaign did not complete")


def test_multi_vm_campaign_keeps_groups_roles_and_layout_per_vm(multi):
    run_to_end(multi)
    directory, captures, manifest = multi["directory"], multi["captures"], multi["manifest"]
    assert len([call for call in multi["calls"] if call[0] == "capture"]) == len(multi["rows"]) == 8
    assert multi["reboots"] == 8  # One boot per group.
    for row in multi["rows"]:
        session = captures / manifest["id"] / row["vm"] / row["session_id"]
        assert read_json(session / "session.json")["vm"] == row["vm"]
        assert os.readlink(session / "raw") == str(Path(manifest["archive_dir"]) / "collections" / row["vm"]
                                                   / row["session_id"] / "raw")
        group = read_json(directory / "groups" / (row["group"] + ".json"))
        assert (group["vm"], group["domain"]) == (row["vm"], collection.for_vm(multi["p"], row["vm"])["domain"])
    assert not (directory / "status.json").exists() and not list(captures.glob("*/session.json"))
    boots = {vm: {read_json(g)["identity"]["boot_id"] for g in (directory / "groups").glob("*.json")
                  if read_json(g).get("vm") == vm} for vm in ("a", "b")}
    assert len(boots["a"]) == len(boots["b"]) == 4 and not boots["a"] & boots["b"]
    # One index over both VMs, built once, in plan order, from the protocol itself (not one VM's view).
    builder, protocol, reports = multi["finished"][0]
    assert builder == "a" and all(later[1:] == (protocol, reports) for later in multi["finished"])
    assert "vm" not in protocol and len(reports) == len(set(reports)) == 8
    assert [read_json(r)["values"]["session_dir"].rsplit("/", 1)[1] for r in reports] \
        == [row["session_id"] for row in multi["rows"]]
    # VM b archived its share first and only recorded that; the campaign completed with VM a's last session.
    events = [read_json(e) for e in sorted((directory / "events").glob("*.json"))]
    assert [(e["vm"], e["stage"]) for e in events if e["status"] == "complete"][:2] \
        == [("b", "vm-complete"), ("a", "complete")]
    calls = list(multi["calls"])
    run_to_end(multi)
    assert multi["calls"] == calls


def test_later_role_waits_for_earlier_roles_on_the_other_vm(multi):
    c.execute(multi["directory"], vm="a")
    assert [call for call in multi["calls"] if call[0] == "capture"] == [("capture", "a", "train-1")]
    state = vm_state(multi, "a")
    assert (state["status"], state["stage"]) == ("stopped", "between-sessions")
    assert "VM b has not finished the roles before dev" in state["message"]
    run_to_end(multi)
    order = [call[2].rsplit("-", 1)[0] for call in multi["calls"] if call[0] == "capture"]
    roles = list(multi["p"]["roles"])
    assert [roles.index(role) for role in order] == sorted(roles.index(role) for role in order)


def test_runner_needs_its_vm_and_cannot_take_another_vms_group(multi):
    with pytest.raises(ValueError, match="--vm is one of: a, b"):
        c.execute(multi["directory"])
    with pytest.raises(ValueError, match="no VM c"):
        c.execute(multi["directory"], vm="c")
    c.execute(multi["directory"], vm="a")
    manifest, p = c.vm_view(*c.load_campaign(multi["directory"]), "b")
    row = next(r for r in multi["rows"] if r["vm"] == "a")
    with pytest.raises(ValueError, match="another VM"):
        c.ensure_group(multi["directory"], manifest, p, {**row, "vm": "b"})


def test_second_runner_of_the_same_vm_is_refused_but_not_the_other_vm(multi):
    with collection.collection_lock(multi["captures"], "hyptcn-lab"):
        with pytest.raises(BlockingIOError):
            c.execute(multi["directory"], vm="a")
        c.execute(multi["directory"], vm="b")
    assert ("capture", "b", "train-2") in multi["calls"] and not (multi["directory"] / "status-a.json").exists()


def test_audits_and_archives_are_serialized_across_vms(multi, monkeypatch):
    holder = os.open(multi["captures"] / ".audit.lock", os.O_CREAT | os.O_RDWR, 0o644)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)  # The other VM's audit or archive is running.
    waits = []

    def sleep(seconds):
        assert not any(call[0] == "audit" for call in multi["calls"])  # Nothing audited while it is held.
        waits.append(vm_state(multi, "a")["stage"])
        if len(waits) == 3:
            fcntl.flock(holder, fcntl.LOCK_UN)
    monkeypatch.setattr(c.time, "sleep", sleep)
    c.execute(multi["directory"], vm="a", stop_after=1)
    os.close(holder)
    assert waits == ["audit-wait"] * 3
    assert multi["calls"] == [("capture", "a", "train-1"), ("audit", "a", "train-1")]
    with c.audit_lock(multi["directory"], vm="a"):  # Held during the block, released after it.
        with pytest.raises(BlockingIOError):
            fcntl.flock(os.open(multi["captures"] / ".audit.lock", os.O_RDWR), fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_capacity_counts_what_the_other_vm_still_writes(multi, monkeypatch):
    directory = multi["directory"]
    manifest, p = c.vm_view(*c.load_campaign(directory), "a")
    free = {"value": 0}
    monkeypatch.setattr(c.shutil, "disk_usage", lambda path: SimpleNamespace(free=free["value"]))
    mine = sum(r["vm"] == "a" for r in multi["rows"])
    free["value"] = 199  # 100 for this VM's session + 100 the other VM may still write.
    with pytest.raises(ValueError, match="working space"):
        c.capacity_guard(manifest, p, mine, directory)
    free["value"] = 200
    c.capacity_guard(manifest, p, mine, directory)
    # The other VM's current session already holds 60 bytes of RAM images.
    other = [r for r in multi["rows"] if r["vm"] == "b"]
    raw = c.session_dir(manifest, other[0]) / "raw"
    raw.mkdir(parents=True)
    (raw / "frame.vmicd").write_bytes(b"x" * 60)
    free["value"] = 140
    c.capacity_guard(manifest, p, mine, directory)
    free["value"] = 139
    with pytest.raises(ValueError, match="working space"):
        c.capacity_guard(manifest, p, mine, directory)
    # Archive disk: 10 bytes for every session not archived yet, on both VMs.
    free["value"] = 10 * len(multi["rows"]) + 100
    c.capacity_guard(manifest, p, mine, directory)
    for row in other:  # The other VM is finished: only this VM's session counts.
        write_new(directory / "attempts" / (row["session_id"] + ".done.json"), {})
    free["value"] = 100
    c.capacity_guard(manifest, p, mine, directory)
    free["value"] = 99
    with pytest.raises(ValueError, match="working space"):
        c.capacity_guard(manifest, p, mine, directory)


def test_stop_request_reaches_each_running_vm(multi, monkeypatch):
    directory = multi["directory"]
    for vm in ("a", "b"):
        c.update_state(directory, vm=vm, status="running", stage="capture", pid=os.getpid(),
                       process_identity={"alive": os.getpid()})
    c.request_stop(directory, "b")
    assert (directory / "stop-request-b.json").exists() and not (directory / "stop-request-a.json").exists()
    assert c.take_stop_request(directory, "b") and not c.take_stop_request(directory, "a")
    c.request_stop(directory)
    assert c.take_stop_request(directory, "a") and c.take_stop_request(directory, "b")
    assert not (directory / "stop-request.json").exists()
    assert set(c.status(directory)["vms"]) == {"a", "b"}


def test_per_vm_names_of_campaign_files_and_pilots(multi, tmp_path):
    assert c.vm_file("status.json", None) == "status.json" and c.vm_file("status.json", "b") == "status-b.json"
    assert c.vm_unit(None) == "hyptcn-collection.service" and c.vm_unit("b") == "hyptcn-collection-b.service"
    assert c.frozen_files(multi["manifest"]) == ["campaign.json", "protocol.json", "plan.json",
                                                 "pilot-a.json", "pilot-b.json"]
    assert c.frozen_files({}) == ["campaign.json", "protocol.json", "plan.json", "pilot.json"]
    assert c.session_dir({"id": "k"}, {"session_id": "s"}) == c.COLLECTIONS / "s"
    assert c.archive_dest({"archive_dir": "/x"}, {"session_id": "s"}) == Path("/x/collections/s")
    single = collection.protocol(collection.DEFAULT)
    assert c.pilot_reports(single, [Path("p.json")]) == {None: Path("p.json")}
    assert c.pilot_reports(multi["p"], ["b=pb.json", "a=pa.json"]) == {"a": Path("pa.json"), "b": Path("pb.json")}
    for values in (["pa.json"], ["a=pa.json"], ["a=pa.json", "a=x.json"], ["a=pa.json", "b=pb.json", "c=pc.json"]):
        with pytest.raises(ValueError, match="one accepted pilot per VM"):
            c.pilot_reports(multi["p"], values)
    path = multi["directory"] / "pilot-b.json"
    path.write_text(json.dumps({"synthetic": "changed"}))
    with pytest.raises(ValueError, match="plan or frozen"):
        c.load_campaign(multi["directory"])
