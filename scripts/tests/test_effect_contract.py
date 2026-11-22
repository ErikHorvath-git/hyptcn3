"""Effect contract of the events (protocol v5, package B5): the guest computes the effect (lab/udalosti.py), labctl
keeps it in the event record (scripts/labctl.py stored_effect), the log audit reads it.

An event record whose effect is not a dict with ok true is refused with exactly the reason event_without_effect;
an effect without ok is refused like a false one. Mutant m12 of the B3 verification (`effect.get("ok") is not
False`) survived because no case had an effect without ok.
"""
import json

import pytest

from scripts import collection_logs as logs
from scripts.tests import test_collection_logs as evidence

MISSING = object()


def audited(tmp_path, effect):
    """The log audit of the clean event session of test_collection_logs with this effect in its event record."""
    d = evidence.build(tmp_path, event=True)
    doc = json.loads((d / "events.json").read_text())
    if effect is MISSING:
        doc["events"][0].pop("effect")
    else:
        doc["events"][0]["effect"] = effect
    evidence.write(d / "events.json", doc)
    evidence.seal(d)
    return logs.audit_logs(d, snapshot_times=[evidence.BASE + 1.1, evidence.BASE + 2.5])


@pytest.mark.parametrize("effect", [
    {"predicate": "a predicate", "evidence": {"MainPID": "4200"}},
    {"ok": None, "evidence": {}},
    {"ok": "true", "evidence": {}},
    {"ok": 1, "evidence": {}},
    {"ok": False, "evidence": {}},
    [True],
    None,
    MISSING,
], ids=["without_ok", "ok_null", "ok_string", "ok_one", "ok_false", "list", "null", "missing"])
def test_event_record_without_a_true_ok_is_refused_for_exactly_that(tmp_path, effect):
    result = audited(tmp_path, effect)
    assert not result["accepted"]
    assert result["problems"] == ["event_without_effect:" + evidence.EVENT["type"]]


def test_the_effect_the_guest_computes_and_labctl_stores_passes_and_a_malformed_one_is_refused(tmp_path):
    from lab import udalosti
    from scripts import labctl
    trigger_only = labctl.stored_effect(udalosti.effect("naprazdno"))
    assert trigger_only == {"ok": True, "predicate": udalosti.PREDICATES["naprazdno"], "evidence": "iba spúšťač"}
    assert audited(tmp_path / "guest", trigger_only)["accepted"]
    malformed = labctl.stored_effect({"predicate": "a predicate", "evidence": {}})
    assert audited(tmp_path / "malformed", malformed)["problems"] == ["event_without_effect:" + evidence.EVENT["type"]]


class StopReplies:
    """labctl as the event steps of scripts/collection.py Events call it: start succeeds, stop answers `stop`."""

    def __init__(self, stop):
        self.stop = stop

    def __call__(self, p, *args, timeout=600):
        if args[2] == "start":
            return {"ok": True, "health": 200}
        if isinstance(self.stop, Exception):
            raise self.stop
        return self.stop


@pytest.mark.parametrize("reply, effect", [
    ({"ok": True, "health": 200, "effect": {"ok": True, "predicate": "p", "evidence": {"MainPID": "4200"}}},
     {"ok": True, "predicate": "p", "evidence": {"MainPID": "4200"}}),
    ({"ok": True, "health": 200, "effect": {"ok": False, "predicate": "p", "evidence": {"error": "no lock"}}},
     {"ok": False, "predicate": "p", "evidence": {"error": "no lock"}}),
    ({"ok": True, "health": 200}, None),
    (OSError("labctl failed"), None),
], ids=["effect", "no_effect", "reply_without_effect", "stop_call_failed"])
def test_events_keep_the_effect_of_the_stop_reply_at_the_top_of_the_record(monkeypatch, tmp_path, reply, effect):
    """scripts/collection.py Events.stop copies the effect labctl returns into the record the log audit reads
    (events.json); a stop call that fails leaves none, and the audit then refuses the event."""
    from scripts import collection
    monkeypatch.setattr(collection, "lab_json", StopReplies(reply))
    events = collection.Events({}, [{"type": "naprazdno", "class": "naprazdno", "start_s": 10, "duration_s": 20}],
                               lambda name, **values: None)
    try:
        for now in (10, 30):
            monkeypatch.setattr(collection.time, "time", lambda now=now: 1000. + now)
            events.tick(1000.)
    except ValueError as error:  # A failed stop call leaves the lab unrestored, and the capture stops.
        assert isinstance(reply, Exception) and str(error) == "lab not restored after event naprazdno"
    finally:
        events.close(tmp_path / "events.json")
    record = json.loads((tmp_path / "events.json").read_text())["events"][0]
    assert record["effect"] == effect
