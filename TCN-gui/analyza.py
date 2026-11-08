"""Analysis behind the TCN GUI: one session of snapshots scored by a safeguard bundle.

Uses the same replay path as the detector (`safeguard.runtime.Detector`) so every
score, threshold crossing and k-of-n alarm in the GUI is the one the detector
would produce. The only additions are read-only decompositions of the score:

  score = 0.5 * mean_i(global_error_i) + 0.5 * max_b(bin_error_b)

so the GUI shows how much each global feature and the worst memory bin
contributed. An anomaly is a deviation from the benign training data, not a
malware verdict (HONESTY P4).
"""
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import torch  # noqa: E402

from safeguard.bundle import load_bundle  # noqa: E402
from safeguard.features import GLOBAL_NAMES, LOCAL_NAMES, SCHEMA as ARCHIVE_SCHEMA, arrays, frames_from_archive  # noqa: E402
from safeguard.runtime import Detector, run_directory  # noqa: E402

DEFAULT_PROFILE = ROOT / "profiles" / "debian12-6.1.0-42-cloud-amd64"


class _Recorder:
    """Bundle proxy: the detector scores through it, the GUI keeps the decomposition."""

    def __init__(self, bundle):
        self._bundle = bundle
        self.windows = {}
        self.frames = {}

    def __getattr__(self, name):
        return getattr(self._bundle, name)

    def score(self, window):
        result = self._bundle.score(window)
        g, local = self._bundle.normalizer.transform(*arrays(window))
        gt = torch.as_tensor(g, dtype=torch.float32).unsqueeze(0)
        lt = torch.as_tensor(local, dtype=torch.float32).unsqueeze(0)
        with torch.inference_mode():
            global_prediction, _ = self._bundle.predictor(gt[:, :-1], lt[:, :-1])
            per_feature = (global_prediction - gt[:, -1]).square()[0].tolist()
        last = window[-1]
        self.windows[(last.session, int(last.seq))] = per_feature
        for frame in window:
            self.frames.setdefault(int(frame.seq), frame)
        return result


def _finite(value):
    if value is None:
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _is_archive(path):
    try:
        with np.load(path, allow_pickle=False) as data:
            return "schema" in data and str(data["schema"]) == ARCHIVE_SCHEMA
    except (OSError, ValueError):
        return False


def resolve_input(path):
    """Return (kind, path, session_dir). kind: archive | snapshots."""
    path = Path(path).expanduser().resolve()
    if path.is_file():
        if path.suffix == ".npz" and _is_archive(path):
            return "archive", path, path.parent
        raise ValueError("vstup nie je archív príznakov (.npz so schémou " + ARCHIVE_SCHEMA + ")")
    if not path.is_dir():
        raise ValueError("vstup neexistuje: " + str(path))
    if any(path.glob("*.vmicd")):
        return "snapshots", path, path.parent
    if (path / "raw").is_dir() and any((path / "raw").glob("*.vmicd")):
        return "snapshots", path / "raw", path
    archives = sorted((p for p in path.glob("*.npz") if _is_archive(p)), key=lambda p: p.stat().st_mtime)
    if archives:
        return "archive", archives[-1], path
    raise ValueError("v adresári nie sú snímky .vmicd ani archív príznakov .npz: " + str(path))


def busy_collecting():
    """True while a capture runs on this host; scoring then competes with the collector."""
    try:
        if subprocess.run(["systemctl", "is-active", "--quiet", "hyptcn-collection.service"],
                          timeout=5).returncode == 0:
            return True
        return subprocess.run(["pgrep", "-f", "collection.py .*run|vmicollect run"],
                              capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _session_context(session_dir):
    context = {}
    meta = Path(session_dir) / "session.json"
    if meta.is_file():
        doc = json.loads(meta.read_text())
        context = {k: doc.get(k) for k in ("session_id", "role", "group", "scenario", "typ")}
    events = Path(session_dir) / "events.json"
    if events.is_file():
        context["events"] = [
            {"type": e.get("type"), "class": e.get("class"), "executed": e.get("executed"),
             "start": e.get("host_start_unix"), "stop": e.get("host_stopped_unix")}
            for e in json.loads(events.read_text()).get("events", [])]
    return context


def model_summary(bundle):
    m = bundle.manifest
    training = m.get("training", {})
    calibration = {k: v for k, v in m.get("calibration", {}).items()
                   if isinstance(v, (int, float, str, bool)) or v is None}
    sessions = m.get("provenance", {}).get("sessions", [])
    roles = {}
    for record in sessions:
        roles[record.get("role")] = roles.get(record.get("role"), 0) + 1
    return {
        "name": None, "created_utc": m.get("created_utc"), "diagnostic": m.get("diagnostic"),
        "classes": m.get("classes"), "architecture": m.get("architecture"),
        "score_formula": m.get("score_formula"), "loss_formula": m.get("loss_formula"),
        "classification_task": m.get("classification_task"),
        "calibration": calibration, "environment": m.get("environment"),
        "history": training.get("history", []),
        "selected_predictor_epoch": training.get("selected_predictor_epoch"),
        "selected_classifier_epoch": training.get("selected_classifier_epoch"),
        "epochs": training.get("epochs"), "windows": training.get("windows"),
        "normalization_rows": training.get("normalization_rows"),
        "corpus_sessions_by_role": roles, "limitations": m.get("limitations", []),
        "feature_contract": {"window_rows": m["feature_contract"]["window_rows"],
                             "max_gap_s": m["feature_contract"]["max_gap_s"],
                             "bins": len(m["feature_contract"]["biny"])},
    }


def _verdict(rows, integrity_rows, alarm_events, scored, fatal):
    if fatal:
        return {"level": "error", "label": "CHYBA VSTUPU",
                "detail": "Prehratie sa zastavilo: " + str(fatal)}
    if integrity_rows:
        return {"level": "alarm", "label": "NÁLEZ INTEGRITY JADRA",
                "detail": f"{integrity_rows} snímok s nálezom kontroly integrity jadra hosťa."}
    if alarm_events:
        return {"level": "alarm", "label": "ANOMÁLIA",
                "detail": f"{alarm_events} alarm(ov) modelu (pravidlo k z n). Správanie sa odchýlilo "
                          "od benígnej prevádzky z tréningu; nie je to verdikt o malvéri."}
    if not rows or scored < 0.5 * len(rows):
        return {"level": "unknown", "label": "NEDOSTATOČNÉ POKRYTIE",
                "detail": f"Skórovaných je iba {scored} z {len(rows)} snímok; o session sa nedá rozhodnúť."}
    return {"level": "ok", "label": "BEZ ALARMU",
            "detail": "Model ani kontroly integrity nič nehlásia. Znamená to zhodu s benígnou prevádzkou "
                      "z tréningu, nie dôkaz, že hosť je čistý."}


def analyze(bundle_path, input_path, *, profile=None, allow_diagnostic=False):
    bundle = load_bundle(bundle_path, allow_diagnostic=allow_diagnostic)
    recorder = _Recorder(bundle)
    kind, source, session_dir = resolve_input(input_path)
    if kind == "archive":
        detector = Detector(recorder, preserve=False)
        with np.load(source, allow_pickle=False) as data:
            frames = frames_from_archive(data, session_dir.name)
        rows = []
        for frame in frames:
            rows.append(detector.process(frame))
            if rows[-1].get("fatal"):
                break
        all_frames = {int(f.seq): f for f in frames}
    else:
        with tempfile.TemporaryDirectory(prefix="tcn-gui-") as temporary:
            out = Path(temporary) / "replay"
            run_directory(recorder, source, profile or DEFAULT_PROFILE, out, preserve=False)
            rows = [json.loads(line) for line in (out / "events.jsonl").read_text().splitlines()]
        all_frames = recorder.frames
    report = _report(bundle, rows, all_frames, recorder.windows, kind, source, session_dir)
    report["model"]["name"] = Path(bundle_path).resolve().name
    report["model"]["path"] = str(Path(bundle_path).resolve())
    return report


def _report(bundle, rows, frames, windows, kind, source, session_dir):
    contract = bundle.contract
    bins = list(contract["biny"])
    bin_bytes = int(contract["layout"]["bin_bytes"])
    times, score, global_part, bin_part, top_bin, state = [], [], [], [], [], []
    bin_err, feature_err, model_alarm, alarm_event, integrity = [], [], [], [], []
    model_events = 0
    activity = {c: [] for c in bundle.manifest["classes"]}
    fatal = None
    for row in rows:
        t = row.get("timestamp")
        if t is None:
            fatal = fatal or row.get("reason")
            continue
        times.append(float(t))
        state.append(row.get("state"))
        s = _finite(row.get("score"))
        score.append(s)
        errors = row.get("bin_errors")
        bin_err.append([_finite(v) for v in errors] if errors else None)
        if s is not None and errors:
            worst = int(np.argmax(errors))
            global_part.append(0.5 * float(row["global_error"]))
            bin_part.append(0.5 * float(errors[worst]))
            top_bin.append(worst)
        else:
            global_part.append(None)
            bin_part.append(None)
            top_bin.append(None)
        per_feature = windows.get((row.get("session"), row.get("seq")))
        feature_err.append([_finite(v) for v in per_feature] if per_feature and s is not None else None)
        for c in activity:
            activity[c].append(_finite((row.get("activity_probabilities") or {}).get(c)))
        model_alarm.append(bool(row.get("model_alarm")))
        alarm_event.append(bool(row.get("alarm_event")))
        model_events += "model_anomaly" in (row.get("alarm_sources") or [])
        findings = (row.get("integrity") or {}).get("findings") or []
        integrity.append([str(f) for f in findings])
        if row.get("fatal"):
            fatal = row.get("reason")
    seqs = sorted(frames)
    input_times = [float(frames[q].timestamp) for q in seqs]
    changed = [[_finite(v) for v in np.asarray(frames[q].perbin)[:, 0]] for q in seqs]
    scored = [s for s in score if s is not None]
    threshold = float(bundle.threshold)
    counts = {}
    for b in top_bin:
        if b is not None:
            counts[b] = counts.get(b, 0) + 1
    columns = [b for b in range(len(bins)) if any(r and r[b] is not None for r in bin_err)]
    mean_bin = [float(np.mean([r[b] for r in bin_err if r and r[b] is not None])) if b in columns else None
                for b in range(len(bins))]
    top = sorted(range(len(bins)), key=lambda b: -(mean_bin[b] or 0))[:10]
    integrity_rows = sum(bool(f) for f in integrity)
    alarm_events = model_events
    return {
        "schema": "hyptcn3/tcn-gui-analysis/1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "input": {"kind": kind, "path": str(source), "session_dir": str(session_dir),
                  "context": _session_context(session_dir)},
        "model": model_summary(bundle),
        "threshold": threshold, "k": bundle.k, "n": bundle.n,
        "verdict": _verdict(times, integrity_rows, alarm_events, len(scored), fatal),
        "summary": {
            "rows": len(rows), "scored": len(scored), "warmup_or_invalid": len(times) - len(scored),
            "above_threshold": sum(s > threshold for s in scored),
            "model_alarm_rows": sum(model_alarm), "model_alarm_events": alarm_events,
            "integrity_rows": integrity_rows,
            "score_max": max(scored) if scored else None,
            "score_median": float(np.median(scored)) if scored else None,
            "duration_s": (times[-1] - times[0]) if len(times) > 1 else 0.0,
        },
        "series": {"t": times, "score": score, "global_part": global_part, "bin_part": bin_part,
                   "top_bin": top_bin, "state": state, "model_alarm": model_alarm,
                   "alarm_event": alarm_event, "integrity": integrity, "activity": activity},
        "bins": {"ids": bins, "gpa_mib": [int(b) * bin_bytes / 2**20 for b in bins],
                 "errors": bin_err, "mean_error": mean_bin, "top_counts": counts, "top_by_mean": top},
        "features": {"names": list(GLOBAL_NAMES), "errors": feature_err},
        "input_heat": {"t": input_times, "name": LOCAL_NAMES[0], "values": changed},
    }
