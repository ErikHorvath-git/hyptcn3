"""The order share of the log audit on the sessions of C4's qualification pass (package B13, the lead's answer to Q73
point 1, 2026-11-25T21:20Z).

The 16 sessions of profile eshop with three events of roles train and dev in the campaign plan of the dry run's working
copy of config/collection-v5.json (tcn/suchy_beh.py hodnoty_kopie: the file's rates, written by Zápis 1 of G2), each
built as the full path of the dry run builds it (scripts/tests/suchy_kampan.py postav_session with its traffic,
prevadzka true: the real scripts/host_traffic.py on a simulated clock) and judged by scripts/traffic_log.py realism
with its event windows as the log audit takes them (scripts/collection_logs.py event_window, the session's
event_grace_s). C3b's check is the model
(dokazy/G1/kod/skusky_c3b_c4a/test_order_share_realny.py), which found the share below its design value in 15 of
the 16 under the reading by overlap, and at it in the 16th (0.050012 against 0.05). The lead's test: after the fix the
share is centered in its tolerance, |z| < 1 in the mean, z = (share - design) / its standard error
sqrt(p (1 - p) / n). The executor's reading (package B13): the mean of z over the 16 sessions lies within (-1, 1).
Every session's traffic depends on its row's seeds alone, so the z values are those of every run. Each session is
deleted once judged: one holds 34 to 90 MB of traffic logs.
"""
import json
from pathlib import Path
import shutil
import socket
import statistics

ROOT = Path(__file__).resolve().parents[2]


def copy_of_the_file(directory):
    """(path, protocol) of the dry run's working copy of the protocol file (COPY_RULE of tcn/suchy_beh.py), its profile
    path absolute, as C3b's check writes it."""
    from scripts import collection
    from tcn import suchy_beh
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    for path, item in suchy_beh.hodnoty_kopie(doc).items():
        suchy_beh._nastav(doc, path, item["value"])
    doc["profile"] = str(ROOT / doc["profile"])
    path = Path(directory) / "kopia.json"
    path.write_text(json.dumps(doc))
    return path, collection.protocol(path)


def test_the_order_share_of_the_c4_pass_is_centered_in_its_tolerance(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("no network in the dry run")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    from scripts import collection, collection_logs, protocol_v5 as pv, traffic_log as tl
    from scripts.tests import boundary_sessions as bs, kampan_v5 as kv, suchy_kampan as sk
    path, protokol = copy_of_the_file(tmp_path)
    rows = [dict(s, attempt=1) for s in pv.plan(protokol, "campaign")["sessions"]
            if protokol["scenarios"][s["scenario"]]["profile"] == "eshop" and len(s.get("events", [])) == 3
            and s["role"] in ("train", "dev")]
    assert len(rows) == 16
    z = {}
    for row in rows:
        key = (row["role"], row["group"], row["scenario"], row["vm"])
        guest = {"kernel": kv.KERNEL, "boot_id": "os", "machine_id": "machine-a", "stack_sha256": kv.STACK,
                 "stack_manifest": list(bs.STACK_MANIFEST)}
        qemu = {"pid": kv.FIRST_PID, "start_ticks": 1, "host_boot": kv.HOST_BOOT}
        session = sk.postav_session(tmp_path / "s", collection.for_vm(protokol, row["vm"]), path, row, "nulovy", 0,
                                    protokol, session_id="os_" + "_".join(map(str, key)),
                                    prvy_riadok_unix=kv.Clock().now, guest=guest, qemu=qemu, prevadzka=True)
        d = session.directory
        meta, own = (json.loads((d / name).read_text()) for name in ("session.json", "protocol.json"))
        windows = [collection_logs.event_window(e, meta["event_grace_s"])
                   for e in json.loads((d / "events.json").read_text())["events"]]
        share = next(r for r in tl.realism(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", own,
                                           meta["scenario"], windows=windows)["requirements"]
                     if r["name"] == "order_share")
        shutil.rmtree(tmp_path / "s")
        assert len(windows) == 3 and share["ok"], (key, share)
        k = own["audit"]["traffic"]["order_share_tolerance_se"]  # The tolerance is k standard errors.
        z[key] = round((share["value"] - share["bound"]["share"]) * k / share["bound"]["tolerance"], 3)
    mean = statistics.mean(z.values())
    print(f"\norder share z of the C4 pass: {z}; mean {mean:.3f}")
    assert -1 < mean < 1, (mean, z)
