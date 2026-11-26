"""The mode parity of scripts/campaign_report.py (the criterion live_archive_parity of G2; skuska/parita.py
COMPARE_RULE, package H1b5) on recorded outputs of safeguard watch and safeguard replay, without a bundle or a model.

Every test writes under tmp_path only: a session directory with its session.json, raw/ and an audit record beside
its feature archive, and the two outputs as safeguard/runtime.py run_directory and safeguard/cli.py replay_directory
write them (configuration.json, events.jsonl, status.json).
"""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts import campaign_report
from skuska import parita

KEYS_E = {"commit", "date", "host", "guest", "command", "n", "values"}
MANIFEST = {"schema": "hyptcn3/safeguard-bundle/1", "diagnostic": True, "calibration": {"threshold": 0.2}}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rows(n=12):
    """The rows of one path: seq 0 a full snapshot, 1 to 3 warming up, 4 on scored; the rule channel's alarm up from
    seq 6 (its event at 6), its hold failed (the user cannot write the collector's raw/)."""
    out = []
    for seq in range(n):
        scored = seq >= 4
        alarm = seq >= 6
        out.append({"schema": "hyptcn3/safeguard-events/1", "seq": seq, "session": "raw",
                    "state": "alarm" if alarm else ("monitoring" if scored else "warming_up"),
                    "model_state": "monitoring" if scored else "warming_up",
                    "reason": "scored" if scored else ("full_snapshot" if seq == 0 else "warming_up"),
                    "score": 0.1 + seq / 100 if scored else None, "alarm": alarm, "alarm_event": seq == 6,
                    "alarm_sources": ["rule_anomaly"] if seq == 6 else [], "model_alarm": False, "rule_alarm": alarm,
                    "integrity_alarm": False, "channel": ["rule"] if alarm else [],
                    "evidence": {"status": "error", "error": "Permission denied"} if alarm else
                    {"status": "not_requested"}, "snapshot_age_ms": 900.0 + seq})
    return out


def write(directory, configuration, lines, status):
    directory.mkdir(parents=True)
    (directory / "configuration.json").write_text(json.dumps(configuration))
    (directory / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in lines))
    (directory / "status.json").write_text(json.dumps(status))


def outputs(tmp_path, watch_rows=None, replay_rows=None, *, edit=None):
    """(WATCH_DIR, REPLAY_DIR, session directory) of a recorded parity session."""
    session = tmp_path / "diag" / "a" / "g2-a-w01-1"
    (session / "raw").mkdir(parents=True)
    (session / "session.json").write_text(json.dumps({"session_id": session.name, "vm": "a",
                                                      "scenario": "corp_high"}))
    npz = session / "audit_20261127T010000000000Z.npz"
    npz.write_bytes(b"the audit's feature archive")
    audit = {"schema": "hyptcn3/collection-audit/1", "values": {"session_dir": str(session), "features": str(npz),
                                                                 "features_sha256": sha(npz), "accepted": True,
                                                                 "reasons": []}}
    configs = {"watch": {"bundle_manifest": MANIFEST, "snapshots": str((session / "raw").resolve()), "follow": True,
                         "preserve": True, "idle_timeout": 60, "profile": str(session / "profile")},
               "replay": {"schema": "hyptcn3/safeguard-configuration/1", "bundle_manifest": MANIFEST,
                          "archive": str(npz), "archive_sha256": sha(npz), "follow": False, "preserve": False}}
    if edit:
        edit(configs, audit)
    npz.with_suffix(".json").write_text(json.dumps(audit))
    base = tmp_path / "G2" / "parita" / session.name
    write(base / "watch", configs["watch"], rows() if watch_rows is None else watch_rows,
          {"stop_reason": "idle_timeout", "processed": 12, "evidence_errors": 6, "ok": False})
    write(base / "replay", configs["replay"], rows() if replay_rows is None else replay_rows,
          {"stop_reason": "replay_complete", "processed": 12, "ok": True})
    return base / "watch", base / "replay", session


def run(watch, replay, out, capsys):
    code = campaign_report.main(["parity", str(watch), str(replay), "--out", str(out)])
    captured = capsys.readouterr()
    return code, (json.loads(Path(out).read_text()) if Path(out).exists() else None), captured


def test_equal_outputs_hold_and_count_the_alarms_of_both_paths(tmp_path, capsys):
    """Every row equal: parity holds (exit 0); the record has check E's header, the tolerance written before the data,
    the alarms of both paths counted and equal, the failed holds of watch counted and no finding (Q61)."""
    watch, replay, session = outputs(tmp_path)
    code, doc, captured = run(watch, replay, tmp_path / "parita.json", capsys)
    assert code == 0 and KEYS_E <= set(doc) and doc["schema"] == parita.TABLE_SCHEMA and doc["n"] == 12
    assert doc["guest"] == parita.PARITY_GUEST and doc["command"].startswith("scripts/campaign_report.py parity")
    v = doc["values"]
    assert (v["holds"], v["findings"], v["criterion"], v["g2_values"]) == (True, [], "live_archive_parity", False)
    assert v["session"] == {"session_id": "g2-a-w01-1", "vm": "a", "scenario": "corp_high",
                            "session_dir": str(session)}
    assert v["tolerance"]["score_rel_tol"] == 1e-5 and v["tolerance"]["score_abs_tol"] == 0.0
    assert v["tolerance"]["network"] == "float32" and v["tolerance"]["rule"] == parita.TOLERANCE_RULE
    for path in ("watch", "replay"):
        a = v["alarms"][path]
        assert (a["alarm_rows"], a["alarm_events"], a["event_seq"]) == (6, 1, [6])
        assert a["events_by_source"] == {"rule_anomaly": 1} and a["alarm_rows_by_channel"] == {"rule": 6}
    assert v["alarms"]["sequence_equal"] and v["alarms"]["event_seq_equal"]
    assert v["compared"] == {"seq_watch": 12, "seq_replay": 12, "seq_both": 12, "scored_both": 8,
                             "largest_relative_difference": 0.0}
    assert v["failed_holds"]["rows"] == 6 and v["failed_holds"]["note"] == parita.FAILED_HOLD_NOTE
    assert v["lag_ms"] == {"max": 911.0, "p95": 911.0, "rows": 12}
    assert v["replay"]["archive_sha256"] == sha(session / "audit_20261127T010000000000Z.npz")
    assert v["bundle"]["diagnostic"] is True and "holds" in captured.out


def test_a_score_outside_the_tolerance_a_differing_alarm_and_a_missing_row_are_findings(tmp_path, capsys):
    """One score inside the tolerance (no finding), one outside, one alarm that differs although its score is equal
    (Q45: every differing alarm is a finding), one row the watch path lacks; exit 1 and the record names each."""
    live = rows()
    live[5]["score"] *= 1 + 5e-6
    live[7]["score"] *= 1 + 5e-5
    live[9].update(alarm=False, rule_alarm=False, channel=[], state="monitoring")
    del live[11]
    watch, replay, _ = outputs(tmp_path, live)
    code, doc, captured = run(watch, replay, tmp_path / "parita.json", capsys)
    assert code == 1
    v = doc["values"]
    found = [(f["kind"], f["seq"], f.get("field")) for f in v["findings"]]
    assert found == [("score_outside_tolerance", 7, None), ("alarm_field", 9, "alarm"),
                     ("alarm_field", 9, "rule_alarm"), ("alarm_field", 9, "channel"), ("only_replay", 11, None)]
    outside = v["findings"][0]
    assert outside["watch"] == pytest.approx(0.17 * (1 + 5e-5)) and outside["replay"] == 0.17
    assert 4.9e-5 < outside["relative"] < 5.1e-5 and v["compared"]["largest_relative_difference"] == outside["relative"]
    assert v["findings_by_kind"]["alarm_field"] == 3 and v["findings_by_kind"]["only_replay"] == 1
    assert v["holds"] is False and v["compared"]["seq_both"] == 11 and doc["n"] == 11
    assert (v["alarms"]["watch"]["alarm_rows"], v["alarms"]["replay"]["alarm_rows"]) == (4, 6)
    assert not v["alarms"]["sequence_equal"] and v["alarms"]["event_seq_equal"]
    assert "5 finding(s)" in captured.out


def test_unscored_rows_rows_without_seq_and_twice_the_same_seq_are_findings(tmp_path, capsys):
    """On a row neither path scored, model_state and reason; a row scored on one path only; a row without seq and a
    seq that watch holds twice (an input error of a duplicate sequence) are findings by name."""
    live, archived = rows(), rows()
    live[2]["reason"] = "no_predecessor"
    archived[4].update(score=None, model_state="input_error", reason="invalid_input")
    live.append(dict(live[8], seq=8, model_state="input_error", reason="duplicate snapshot sequence: 8", score=None))
    live.append(dict(live[0], seq=None, model_state="input_error", reason="no snapshots were processed"))
    watch, replay, _ = outputs(tmp_path, live, archived)
    code, doc, _ = run(watch, replay, tmp_path / "parita.json", capsys)
    assert code == 1
    kinds = doc["values"]["findings_by_kind"]
    assert (kinds["no_seq"], kinds["duplicate_seq"], kinds["unscored_field"], kinds["scored_on_one_path"]) == (
        1, 1, 1, 1)
    unscored = next(f for f in doc["values"]["findings"] if f["kind"] == "unscored_field")
    assert (unscored["seq"], unscored["field"], unscored["watch"], unscored["replay"]) == (
        2, "reason", "no_predecessor", "warming_up")


def wrong_bundle(configs, audit):
    configs["replay"]["bundle_manifest"] = dict(MANIFEST, diagnostic=False)


def no_archive(configs, audit):
    del configs["replay"]["archive_sha256"]


def other_features(configs, audit):
    audit["values"]["features_sha256"] = "0" * 64


def other_session(configs, audit):
    configs["watch"]["snapshots"] = "/elsewhere/raw"


@pytest.mark.parametrize("edit, why", [
    (wrong_bundle, "scored with two bundles"), (no_archive, "no configuration of safeguard replay --archive"),
    (other_features, "not the feature archive its audit"), (other_session, "not raw/ of the session")])
def test_outputs_that_are_no_pair_of_one_session_are_refused_and_nothing_is_written(tmp_path, capsys, edit, why):
    watch, replay, _ = outputs(tmp_path, edit=edit)
    code, doc, captured = run(watch, replay, tmp_path / "parita.json", capsys)
    assert (code, doc) == (2, None) and why in captured.err


def test_an_out_that_exists_or_lies_in_an_input_code_other_than_the_tolerances_and_a_missing_audit(
        tmp_path, capsys, monkeypatch):
    """Refused, exit 2, nothing written: an --out that exists (nothing read), one inside an input directory, an
    archive without its audit record, and code other than PRECISION_SOURCES (the precision must be found out again
    before a comparison, Q45)."""
    watch, replay, session = outputs(tmp_path)
    (tmp_path / "exists.json").write_text("{}")
    code, _, captured = run(watch, replay, tmp_path / "exists.json", capsys)
    assert code == 2 and "already exists" in captured.err and (tmp_path / "exists.json").read_text() == "{}"
    code, doc, captured = run(watch, replay, watch / "parita.json", capsys)
    assert (code, doc) == (2, None) and "inside the input directory" in captured.err
    monkeypatch.setattr(parita, "PRECISION_SOURCES", dict(parita.PRECISION_SOURCES,
                                                          **{"safeguard/bundle.py": "0" * 64}))
    code, doc, captured = run(watch, replay, tmp_path / "a.json", capsys)
    assert (code, doc) == (2, None) and "find out the precision again" in captured.err
    monkeypatch.undo()
    (session / "audit_20261127T010000000000Z.json").unlink()
    code, doc, captured = run(watch, replay, tmp_path / "b.json", capsys)
    assert (code, doc) == (2, None) and "the audit record beside the replayed archive" in captured.err


def test_the_comparison_reads_the_fields_the_runtime_writes():
    """The fields COMPARE_RULE compares are the fields safeguard/runtime.py Detector writes on every row."""
    import inspect
    from safeguard import runtime
    finish = inspect.getsource(runtime.Detector._finish) + inspect.getsource(runtime.Detector.input_error)
    for field in (*parita.EXACT, *parita.UNSCORED, "score", "seq", "snapshot_age_ms", "evidence"):
        assert f'"{field}"' in finish or f"{field}=" in finish, field
    assert copy.deepcopy(parita.EXACT) == ("alarm", "alarm_event", "alarm_sources", "model_alarm", "rule_alarm",
                                           "integrity_alarm", "channel")


def test_the_mode_is_in_the_usage_of_the_report_and_no_measurement_code():
    from scripts import collection
    assert "scripts/campaign_report.py parity WATCH_DIR REPLAY_DIR --out NEW_FILE" in campaign_report.__doc__
    assert not collection.is_measurement("scripts/campaign_report.py")
    assert not collection.is_measurement("skuska/parita.py")
