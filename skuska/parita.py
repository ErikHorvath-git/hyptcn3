"""The live/archive parity of stage G2 (protocol v5, package H1b5): the tolerance of the criterion live_archive_parity,
written from the precision the code computes in before any comparison, the diagnostic bundle of the parity and the
comparison of safeguard watch with the replay of the same session's archive.

    python -m skuska.parita zvazok --protocol P --audit AUDIT.json [--audit AUDIT.json ...] --praca WORK --out DIR
                                   --epochs N|plan [--vysledky R]
    .venv/bin/python scripts/campaign_report.py parity WATCH_DIR REPLAY_DIR --out F    (parity_table, COMPARE_RULE)

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H3, the criterion live_archive_parity,
section 6 point 4), the map dokazy/G2/mapa.md (row 11, points A, B, D and E, its questions 15 and 16) and the lead's
answers Q45 (the tolerance follows the precision of the network and the batch of both paths, written with its reason
before the first comparison; the sequence of the alarms must match exactly, every differing alarm is a finding), Q61
(map question 16, accepted as proposed: a diagnostic bundle of schema 3 from the chain of G1, the C1 synthetic
sessions with the layout of the audit of a real G2 session, per VM where it differs, loaded with --allow-diagnostic;
math.isclose with abs_tol 0 on the score, the fields of the alarm exactly; the record counts the alarms of both paths;
a failed hold as the user is no parity error; parity sessions give no values of G2) and Q60 (map question 15: a run
beside watch is no error-free run). skuska/ is no directory of scripts/collection.py MEASUREMENT_DIRS, so nothing here
changes the measurement code (map point E).

zvazok (BUNDLE_RULE) makes the bundle once, run by the main session between the blocks of G2 sessions (its chain and
its training are heavy processes for the load rule of G2): from the audit of a real G2 session of each VM its layout
(LAYOUT_RULE), then for each distinct layout the chain of G1 up to its corpus (tcn/suchy_beh.py, steps 1 to 5 of
Beh: the gates, the working copies, the qualification pass and the rehearsal and campaign on the harness of
scripts/tests/suchy_kampan.py, with the rows of scripts/tests/suchy_generatory.py in that layout) and a diagnostic
training through the real command line, python -m safeguard train --diagnostic. DIR receives the bundles and their
record zvazok.json (check E's header) with the sha256 of every file of each bundle.

The comparison (COMPARE_RULE) is the mode parity of scripts/campaign_report.py, which runs parity_table: by seq, the
score within the tolerance written before it (TOLERANCE_RULE), the fields of the alarm exactly, model_state and reason
of the unscored rows, a row of one path only named; it counts the alarms of both paths.
"""
import contextlib
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python -m skuska.parita from another directory
    sys.path.insert(0, str(ROOT))

from scripts import collection  # noqa: E402
from skuska import g2  # noqa: E402

# ------------------------------------------------------------------ the tolerance (Q45), before any comparison

# What the code at commit 2a89b6c computes in (TOLERANCE_RULE), read from the files of PRECISION_SOURCES.
NETWORK_DTYPE = "float32"
BATCH = {"watch": 1, "replay": 1}  # Windows per call of the network on each path.
THREADS = 1  # Map row 11: --threads 1 for safeguard watch and safeguard replay alike.
# The sha256 of the files the precision and the batch were read from (TOLERANCE_RULE); the comparison refuses other
# files by name, since the precision must then be found out again before a comparison (Q45).
PRECISION_SOURCES = {
    "safeguard/bundle.py": "438f761d83960629c34281ec9d1ebbfbdb3301c0ef64b894bbf05234257cd976",
    "safeguard/runtime.py": "8e22a89fd9ee987460a19c98bda01effbb874345efd8f2afc0198cfe3a5f0480",
    "safeguard/model.py": "2afbb91abe0cf268632763f80a680235b74d5ce8780466f5ca8630e064b62bde",
    "safeguard/cli.py": "813ebe8e5800c9f3c086952e25e69e7829ce50b512f454f71f99764d2f9c36ce",
    "safeguard/features.py": "05e45f1147a31ea321d65adc679a191a911c341586e6f3749c3d9a4099a12019",
    "tcn/model.py": "7da3a3f38398bb3536cb6a3a5e12605b3594ede1eefd907be7d0ca3e79470f97",
}
# Q45: float64 and the same batch on both paths give 1e-9 relative, float32 or another batch 1e-5 relative.
TOLERANCES = {("float64", True): 1e-9, ("float64", False): 1e-5, ("float32", True): 1e-5, ("float32", False): 1e-5}
SCORE_REL_TOL = 1e-5  # TOLERANCES[(NETWORK_DTYPE, BATCH["watch"] == BATCH["replay"])]
SCORE_ABS_TOL = 0.0  # Map question 16 (Q61, accepted as proposed): abs_tol 0, so a score of 0 must be 0 on both paths.
TOLERANCE_RULE = (
    "the lead's answer to Q45 (2026-11-24T22:12Z), written before the first comparison: the network computes in "
    "float32 and both paths score one window per call, so the score of a row agrees when math.isclose(live, replay, "
    "rel_tol=1e-5, abs_tol=0) holds, |live - replay| <= 1e-5 x max(|live|, |replay|) (Q45: float32 or another batch "
    "1e-5 relative, float64 and the same batch 1e-9; abs_tol 0 by map question 16, which Q61 accepted). The precision, "
    "read from the code at commit 2a89b6c (the files of PRECISION_SOURCES): safeguard/bundle.py Bundle.score casts "
    "the normalized inputs of its window with torch.as_tensor(..., dtype=torch.float32) and runs the predictor and the "
    "classifier on them, torch modules of the default dtype float32 (safeguard/model.py Predictor and Classifier, the "
    "TCN blocks of tcn/model.py, no set_default_dtype and no double() anywhere in them), whose weights load_bundle "
    "loads with load_state_dict from the bundle's predictor.pt and classifier.pt; the features before the network are "
    "float64 on both paths (safeguard/features.py Frame and FeatureNormalizer.transform; the audit's feature archive "
    "stores matica and perbin as float64, features/archive.py save), so the network, not the features, sets the "
    "precision. The batch: safeguard watch (safeguard/cli.py execute -> safeguard/runtime.py run_directory) and "
    "safeguard replay --archive (safeguard/cli.py replay_directory -> safeguard/runtime.py replay_archive) both give "
    "each frame to Detector.process, which scores at most one window per frame through Bundle.score, whose "
    "unsqueeze(0) makes a batch of one; so one window per call on both paths, the same batch. Both run with --threads "
    "1 (map row 11; torch.set_num_threads in safeguard/cli.py execute). Beside the score: a row scored on one path and "
    "not on the other is a finding; the fields of the alarm (alarm, alarm_event, alarm_sources, model_alarm, "
    "rule_alarm, integrity_alarm, channel) must be equal exactly on every row, and every differing alarm is a finding "
    "even when the score is within the tolerance (Q45), so the sequence of the alarms of both paths must be the same")


def tolerance(dtype, same_batch):
    """The relative tolerance of the score by the lead's rule of Q45: 1e-9 for float64 and the same batch on both
    paths, 1e-5 for float32 or another batch. ValueError for another dtype."""
    try:
        return TOLERANCES[(dtype, bool(same_batch))]
    except KeyError:
        raise ValueError(f"Q45 names float32 and float64, not {dtype!r}") from None


def score_agrees(live, replay):
    """Whether two scores of a row agree within the tolerance written before the data (TOLERANCE_RULE)."""
    return math.isclose(live, replay, rel_tol=SCORE_REL_TOL, abs_tol=SCORE_ABS_TOL)


# ------------------------------------------------------------------ the bundle (Q61)

BUNDLE_SCHEMA = "hyptcn3/g2-parity-bundle/1"
AUDIT_SCHEMA = "hyptcn3/collection-audit/1"  # scripts/collection.py audit_session.
BUNDLE_RECORD = "zvazok.json"  # The record of the bundles in --out.
# The chain of G1 the bundle comes from (tcn/suchy_beh.py): the null generator at seed 0, the run of C4 that goes the
# whole chain (POKYNY_TEMPO point 5), by the shortened path (suchy_kampan.SKRATENA_RULE: no traffic logs, which no
# training reads). The parity compares two paths of one detector, not its model, so the generator is no choice of the
# criterion (the executor's judgment).
GENERATOR, GENERATOR_SEED, PATH = "nulovy", 0, "skratena"
TRAIN_THREADS = 2  # tcn/suchy_beh.py VLAKNA (the lead's answer to Q37): the threads of the training of the chain.
TRAIN_TIMEOUT_S = 24 * 3600  # The executor's judgment: a training that has not ended in a day is refused.
EPOCHS_PLAN = "plan"  # --epochs plan: the analysis plan's stopping rule; --epochs N: a diagnostic override of the cap.
LAYOUT_RULE = (
    "the lead's decision on map question 16 (Q61): the C1 synthetic sessions with the layout of the audit of a real "
    "G2 session, per VM where it differs; the layout is what check_frame compares besides the names "
    "(safeguard/features.py feature_contract: biny and layout, the VM's memory geometry: bin_bytes, page_size, the "
    "bins with their pages, the regions, memsize and vcpus), from values.layout of the audit record (a diagnostic run "
    "with the campaign id g2, skuska/g2.py), which must equal layout_json of its feature archive, whose biny must be "
    "the bins of the layout in order; a row of scripts/tests/suchy_generatory.py riadky keeps its global columns, its "
    "quality and its times, and its BINS bins are dealt over the bins of the layout in order (bin j of the layout "
    "takes the generator's bin j mod BINS): changed_ratio in whole pages of that bin (the generator's ratio times its "
    "pages, rounded, at least one page, as the generator keeps every bin changed), zero_ratio and entropy_mean as "
    "drawn, has_changed 1; biny and layout those of the audit. The sidecars of raw/ keep the harness's own layout "
    "(scripts/tests/boundary_sessions.py), which no step of the chain compares with the rows: the audit records the "
    "layout of its extraction (scripts/collection.py audit_session values.layout) and training compares the archives "
    "with the audits (safeguard/training.py train_bundle)")
BUNDLE_RULE = (
    "the lead's decision on map question 16 (Q61): refused by name before anything is made, an --out or a --praca that "
    "exists or lies in the other, a --praca on a tmpfs (the lead's answer to Q73), an audit that is no audit of a "
    "real G2 session or whose layout breaks LAYOUT_RULE, two audits of one VM, a VM the protocol has not, a session "
    "whose protocol extracts the memory columns from other "
    "bins than the protocol of the bundle (analysis.scale.min_bin_pages: the live run extracts with its bundle's, the "
    "audit extracted the archive the replay reads with the session's), and a host that is not quiet (a collector of a "
    "VM of the protocol, a collection.py run, a lab trial on a VM, a block of G2: the chain and the training are heavy "
    "processes, which void a run of G2), checked again before every training; for every distinct layout (the VMs that "
    "share it share the bundle) the chain of G1 up to its corpus, in --praca/<bundle>: tcn/suchy_beh.py Beh with the "
    "generator nulovy at seed 0 by the shortened path, its steps 1 to 5 as Beh._chain runs them (the gate of G1 on the "
    "protocol file and on the working copies, the copy without the mask, the qualification pass, the copy with its "
    "mask, the rehearsal and the campaign on the harness of scripts/tests/suchy_kampan.py with one injected "
    "rejection), under its threads, its refusal of the network and of a write of the ledger of record, every row of "
    "suchy_generatory.riadky in the layout (LAYOUT_RULE), every session of the corpus audited in that layout; then the "
    "real command line of a diagnostic training, python -m safeguard --threads 2 train --corpus <the corpus> --out "
    "<--out>/<bundle> --diagnostic, with --epochs N when --epochs N is given (a diagnostic override of "
    "analysis.stopping.max_epochs, which the manifest lists; --epochs plan keeps the plan's stopping rule), nice 19 "
    "(scripts/collection.py background_command), its output in <--out>/<bundle>.trening.log; the bundle must be "
    "diagnostic, hold the layout and the bins of its audits in its feature contract and the protocol's "
    "min_bin_pages in its normalizer; the record <--out>/zvazok.json (check E's header) names the audits, every "
    "bundle with the sha256 of each of its files and of their list, the VMs it serves, its corpus, the chain's steps "
    "with their times and the training's command, exit code and seconds; --praca stays for the main session to "
    "delete (it holds the corpus the manifest names)")


class Refused(ValueError):
    """A bundle, a block or a comparison the rules refuse before anything is done, by name."""


def _sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical(value):
    """The sha256 of a JSON value written canonically (sorted keys, no spaces), as gates.measurement_sha256 hashes."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _json(path, what):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise Refused(f"{what} {path} cannot be read: {type(error).__name__}: {error}") from None


def check_layout(layout, biny):
    """Refused unless `layout` and `biny` describe one geometry, as a frame of the bundle's contract must
    (safeguard/features.py Frame, the check bundle.load_bundle makes on a frame of zeros)."""
    from features.snapshot import MENA
    from safeguard.features import Frame
    if [entry[0] if type(entry) in (list, tuple) and entry else None for entry in layout["bins"]] != list(biny):
        raise Refused("the bins of the feature archive are not the bins of the layout in order")
    quality = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "inconclusive": [],
               "findings": [], "read_errors": 0, "filled_zero": 0}
    try:
        Frame("layout-check", 0, 0.0, np.zeros(len(MENA)), np.zeros((len(biny), 4)), tuple(biny), quality,
              "layout-check", layout)
    except (TypeError, ValueError, KeyError) as error:
        raise Refused(f"the layout breaks the geometry of a frame: {error}") from None


def read_audit(path):
    """The layout of the audit of a real G2 session (LAYOUT_RULE): {audit, sha256, session_id, vm, session_dir,
    features, features_sha256, layout, biny, layout_sha256, min_bin_pages, protocol_sha256}; Refused by name."""
    path = Path(path).absolute()
    doc = _json(path, "the audit record")
    if type(doc) is not dict or doc.get("schema") != AUDIT_SCHEMA or type(doc.get("values")) is not dict:
        raise Refused(f"{path} is no audit record ({AUDIT_SCHEMA})")
    v = doc["values"]
    session_dir = Path(str(v.get("session_dir") or ""))
    meta = _json(session_dir / "session.json", f"the session.json of the session the audit {path} names:")
    if v.get("session_sha256") != _sha(session_dir / "session.json"):
        raise Refused(f"{path} audited another session.json than {session_dir / 'session.json'}")
    if meta.get("role") != g2.ROLE or meta.get("campaign_id") != g2.CAMPAIGN_ID:
        raise Refused(f"{path} is no audit of a G2 session (role {meta.get('role')!r}, campaign id "
                      f"{meta.get('campaign_id')!r}; a G2 session is a {g2.ROLE} run with the campaign id "
                      f"{g2.CAMPAIGN_ID}, skuska/g2.py)")
    features = Path(str(v.get("features") or ""))
    if not features.is_file() or _sha(features) != v.get("features_sha256"):
        raise Refused(f"{path}: its feature archive {features} is missing or differs from values.features_sha256")
    layout = v.get("layout")
    if type(layout) is not dict or type(layout.get("bins")) is not list:
        raise Refused(f"{path} has no values.layout")
    try:
        with np.load(features, allow_pickle=False) as data:
            biny = [int(b) for b in data["biny"]]
            stored = json.loads(str(data["layout_json"]))
    except (OSError, ValueError, KeyError) as error:
        raise Refused(f"{path}: its feature archive {features} cannot be read: {error}") from None
    if stored != layout:
        raise Refused(f"{path}: the layout of its feature archive differs from values.layout")
    check_layout(layout, biny)
    protocol = _json(session_dir / "protocol.json", "the protocol.json of the session")
    try:
        min_bin_pages = protocol["analysis"]["scale"]["min_bin_pages"]
    except (KeyError, TypeError):
        raise Refused(f"{session_dir / 'protocol.json'} has no analysis.scale.min_bin_pages (no protocol of schema "
                      "3)") from None
    return {"audit": str(path), "sha256": _sha(path), "session_id": meta.get("session_id"), "vm": meta.get("vm"),
            "session_dir": str(session_dir), "features": str(features), "features_sha256": v["features_sha256"],
            "layout": layout, "biny": biny, "layout_sha256": _canonical({"layout": layout, "biny": biny}),
            "min_bin_pages": min_bin_pages, "protocol_sha256": v.get("protocol_sha256")}


def relayout(result, layout, biny):
    """An extraction result of suchy_generatory.riadky in the layout of an audit (LAYOUT_RULE): a new dict with its
    perbin dealt over the layout's bins, its biny and its layout."""
    pages = [int(entry[1]) for entry in layout["bins"]]
    if [int(entry[0]) for entry in layout["bins"]] != [int(b) for b in biny]:
        raise ValueError("the bins of the layout are not biny in order")
    source = np.asarray(result["perbin"], dtype=np.float64)
    drawn = source.shape[1]
    perbin = np.empty((source.shape[0], len(pages), 4))
    for j, count in enumerate(pages):
        bin_ = source[:, j % drawn]
        perbin[:, j, 0] = np.maximum(1.0, np.rint(bin_[:, 0] * count)) / count
        perbin[:, j, 1] = bin_[:, 1]
        perbin[:, j, 2] = bin_[:, 2]
        perbin[:, j, 3] = 1.0
    return dict(result, perbin=perbin.tolist(), biny=[int(b) for b in biny], layout=copy.deepcopy(layout))


@contextlib.contextmanager
def real_layout(layout, biny):
    """Every row suchy_generatory.riadky gives in the layout of the audit (LAYOUT_RULE) for the length of the block:
    the harness (suchy_kampan.postav_session) and the qualification pass read it by its module's name."""
    from scripts.tests import suchy_generatory as sg
    original = sg.riadky

    def riadky(riadok_planu, rezim, seed, protokol):
        return relayout(original(riadok_planu, rezim, seed, protokol), layout, biny)
    sg.riadky = riadky
    try:
        yield
    finally:
        sg.riadky = original


def _resolved(base, path):
    path = Path(path)
    return path if path.is_absolute() else Path(base) / path


def g1_chain(protocol, work, vysledky, layout, biny, command):
    """BUNDLE_RULE: the chain of G1 up to its corpus in `work` (steps 1 to 5 of tcn/suchy_beh.py Beh._chain, as it
    runs them), every row in the layout; {index, index_sha256, sessions, roles, copy, copy_sha256, qualification, mask,
    steps, log, captures, rule}. Refused when a session of the corpus was audited in another layout."""
    from tcn import suchy_beh as sb
    work = Path(work)
    beh = sb.Beh(GENERATOR, GENERATOR_SEED, work / "g1_out", work / "g1_praca", PATH, protocol=protocol,
                 vysledky=vysledky, command=command)
    with sb.vlakna(), sb.bez_siete(), sb.strazena_kniha(), real_layout(layout, biny):
        with beh.krok("1 protokol a stupne"):
            beh.real_doc = json.loads(beh.protocol.read_text())
            collection.protocol(beh.protocol)
            beh.gates = [sb._gate(beh.vysledky, beh.protocol)]
        with beh.krok("2 pracovna kopia bez masky"):
            doc0 = sb._copy_value(beh.real_doc)
            beh.values = sb.hodnoty_kopie(doc0)
            for key, item in beh.values.items():
                sb._nastav(doc0, key, item["value"])
            beh.kopia0 = sb._zapis(beh.praca / "protokol_kopia_bez_masky.json", doc0)
            sb.over_kopiu(beh.protocol, beh.kopia0)
            p0 = collection.protocol(beh.kopia0)
        with beh.krok("3 kvalifikacny prechod"):
            values, proposed = sb.kvalifikacny_prechod(beh.praca / "kvalifikacia", beh.kopia0, p0, beh.generator,
                                                       beh.cesta, beh.ponuky)
            beh.kvalifikacia = sb._zapis(beh.out / "kvalifikacia.json", sb.hlavicka_e(
                sb.SCHEMA_QUALIFICATION, beh.command, len(values["sessions"]), values))
        with beh.krok("4 pracovna kopia"):
            doc = sb._copy_value(doc0)
            doc["analysis"]["columns"] = proposed
            beh.values["analysis.columns"] = {"value": proposed, "origin": sb.COLUMNS_ORIGIN}
            beh.kopia = sb._zapis(beh.praca / "protokol_kopia.json", doc)
            beh.copy_check = sb.over_kopiu(beh.protocol, beh.kopia)
            beh.gates.append(sb._gate(beh.vysledky, beh.kopia))
            beh.P = collection.protocol(beh.kopia)
        with beh.krok("5 generalka a kampan"):
            beh._kampan()
    index = Path(beh.index)
    records = json.loads(index.read_text())["sessions"]
    wanted = json.dumps(layout, sort_keys=True)
    other = sorted(r["id"] for r in records if json.dumps(json.loads(_resolved(index.parent, r["audit"]).read_text())[
        "values"]["layout"], sort_keys=True) != wanted)
    if other:
        raise Refused(f"the corpus {index} holds sessions audited in another layout: {', '.join(other)}")
    roles = {}
    for r in records:
        roles[r["role"]] = roles.get(r["role"], 0) + 1
    return {"index": str(index), "index_sha256": _sha(index), "sessions": len(records), "roles": roles,
            "copy": str(beh.kopia), "copy_sha256": _sha(beh.kopia), "qualification": str(beh.kvalifikacia),
            "mask": proposed, "mask_differences": values["differences"], "steps": beh.kroky, "log": str(beh.log),
            "captures": len(beh.h.captures), "generator": GENERATOR, "seed": GENERATOR_SEED, "path": PATH,
            "rule": LAYOUT_RULE}


def train_command(index, out, epochs):
    """The real command line of the diagnostic training (BUNDLE_RULE), nice 19."""
    argv = [sys.executable, "-m", "safeguard", "--threads", str(TRAIN_THREADS), "train", "--corpus", str(index),
            "--out", str(out), "--diagnostic", *([] if epochs == EPOCHS_PLAN else ["--epochs", str(epochs)])]
    return collection.background_command(argv)


def run_logged(argv, log, timeout):
    """A child into the new file `log`; its exit code, None at a timeout."""
    with Path(log).open("x") as stream:
        try:
            return subprocess.run([str(a) for a in argv], cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                  timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return None


def busy(p, processes=collection.processes):
    """{what: [pids]} of what makes the host not quiet for the chain and the training (BUNDLE_RULE)."""
    out = {}
    domains = [row["domain"] for row in collection.vms(p)]
    for pid, argv in processes():
        args = [arg.decode(errors="replace") if isinstance(arg, bytes) else str(arg) for arg in argv]
        raw = [arg if isinstance(arg, bytes) else str(arg).encode() for arg in argv]
        found = [f"collector of {domain}" for domain in domains if collection.is_collector(raw, domain)]
        tools = g2.invoked(args) if args else set()
        if "collection.py" in tools and "run" in args:
            found.append("collection.py run")
        if "lab_trial.py" in tools and g2._option(args, "--vm") is not None:
            found.append("lab_trial.py on a VM")
        if "block" in args and any(flag == "-m" and module.startswith("skuska.")
                                   for flag, module in zip(args, args[1:])):
            found.append("a block of G2")
        for what in found:
            out.setdefault(what, []).append(pid)
    return out


def bundle_files(directory):
    """{relative path: sha256} of every file of a bundle directory."""
    directory = Path(directory)
    return {str(path.relative_to(directory)): _sha(path) for path in sorted(directory.rglob("*")) if path.is_file()}


def check_bundle(directory, layout, biny, min_bin_pages):
    """BUNDLE_RULE: the summary of a trained bundle, Refused unless it is diagnostic, holds the layout and the bins of
    its audits in its feature contract and min_bin_pages in its normalizer."""
    manifest = _json(Path(directory) / "manifest.json", "the manifest of the bundle")
    contract = manifest.get("feature_contract") or {}
    rule = (manifest.get("normalizer") or {}).get("rule") or {}
    why = [text for text, bad in (
        ("it is not diagnostic", manifest.get("diagnostic") is not True),
        ("its feature contract holds another layout than its audits", contract.get("layout") != layout),
        ("its feature contract holds other bins than its audits", contract.get("biny") != list(biny)),
        (f"its normalizer extracts from the bins of {rule.get('min_bin_pages')!r} pages, the protocol's "
         f"analysis.scale.min_bin_pages is {min_bin_pages}", rule.get("min_bin_pages") != min_bin_pages)) if bad]
    if why:
        raise Refused(f"the bundle {directory}: " + "; ".join(why))
    files = bundle_files(directory)
    calibration = manifest.get("calibration") or {}
    parameters = manifest.get("parameters") or {}
    return {"files": files, "sha256": _canonical(files), "manifest_sha256": files["manifest.json"],
            "diagnostic": True, "threshold": calibration.get("threshold"), "k": calibration.get("k"),
            "n": calibration.get("n"), "normalization_rule": rule.get("name"),
            "rule_channel_columns": (manifest.get("rule_channel") or {}).get("columns"),
            "overrides": parameters.get("overrides"), "max_epochs": (parameters.get("stopping") or {}).get(
                "max_epochs"), "corpus_index_sha256": (manifest.get("provenance") or {}).get("corpus_index_sha256")}


def _bytes(path):
    return sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file() and not f.is_symlink())


def filesystem(path):
    """The type of the filesystem that holds `path` or, while it does not exist, its nearest existing parent."""
    path = Path(path).absolute()
    while not path.exists():
        path = path.parent
    return collection.storage_identity(path).get("fstype")


def make_bundles(protocol, audits, praca, out, epochs, *, vysledky, command, chain=g1_chain, run=run_logged,
                 processes=collection.processes, tmpfs=False):
    """BUNDLE_RULE: the bundles of the audits and their record <out>/zvazok.json (check E's header); returns the
    record. Refused by name before anything is made. tmpfs True lets --praca lie on a tmpfs (a test's chain)."""
    from scripts import gates
    protocol, praca, out = Path(protocol).absolute(), Path(praca).absolute(), Path(out).absolute()
    for path, option in ((out, "--out"), (praca, "--praca")):
        if path.exists() or path.is_symlink():
            raise Refused(f"{option} {path} exists: a bundle is made into new directories")
    if out == praca or out.is_relative_to(praca) or praca.is_relative_to(out):
        raise Refused("--out and --praca are two directories, neither inside the other")
    if not tmpfs and filesystem(praca) == "tmpfs":
        raise Refused(f"--praca {praca} lies on a tmpfs: the chain writes about 22 MB per session of the plan, some "
                      "200 sessions (the lead's answer to Q73: the work of the dry run never in /tmp)")
    if epochs != EPOCHS_PLAN and (type(epochs) is not int or epochs < 1):
        raise Refused(f"--epochs {epochs!r}: a number of epochs above 0 or {EPOCHS_PLAN}")
    p = collection.protocol(protocol)
    vms = [row["name"] for row in collection.vms(p)]
    found = [read_audit(path) for path in audits]
    if not found:
        raise Refused("no --audit: the layout comes from the audit of a real G2 session")
    seen = [a["vm"] for a in found]
    twice = sorted({vm for vm in seen if seen.count(vm) > 1})
    foreign = sorted({str(vm) for vm in seen if vm not in vms})
    minimum = p["analysis"]["scale"]["min_bin_pages"]
    other_bins = [a["session_id"] for a in found if a["min_bin_pages"] != minimum]
    problems = ([f"two audits of VM {vm}: one audit per VM gives its layout" for vm in twice]
                + [f"VM {vm} is no VM of the protocol {protocol}" for vm in foreign]
                + [f"the session {sid} extracted its memory columns with another analysis.scale.min_bin_pages than "
                   f"the protocol's {minimum}" for sid in other_bins])
    quiet = busy(p, processes)
    problems += [f"the host is not quiet: {what} (PID {', '.join(map(str, pids))})" for what, pids in quiet.items()]
    if problems:
        raise Refused("no bundle is made: " + " | ".join(problems))
    groups = {}
    for audit in found:
        groups.setdefault(audit["layout_sha256"], []).append(audit)
    out.mkdir(parents=True)
    praca.mkdir(parents=True)
    bundles = []
    for members in groups.values():
        names = sorted(a["vm"] for a in members)
        key = "zvazok_" + "_".join(names)
        layout, biny = members[0]["layout"], members[0]["biny"]
        started = time.monotonic()
        made = chain(protocol, praca / key, vysledky, layout, biny, command)
        chain_s = round(time.monotonic() - started, 3)
        quiet = busy(p, processes)
        if quiet:
            raise Refused("the training does not start, the host is not quiet: " + "; ".join(
                f"{what} (PID {', '.join(map(str, pids))})" for what, pids in quiet.items()))
        target, log = out / key, out / f"{key}.trening.log"
        argv = train_command(made["index"], target, epochs)
        started = time.monotonic()
        code = run(argv, log, TRAIN_TIMEOUT_S)
        train_s = round(time.monotonic() - started, 3)
        if code != 0 or not (target / "manifest.json").is_file():
            raise Refused(f"the training of {key} ended with exit {code} and no bundle; see {log}")
        summary = check_bundle(target, layout, biny, minimum)
        bundles.append({"name": key, "dir": str(target), "vms": names, "layout_sha256": members[0]["layout_sha256"],
                        "audits": [a["audit"] for a in members], **summary,
                        "corpus": {k: made[k] for k in ("index", "index_sha256", "sessions", "roles")},
                        "chain": {k: v for k, v in made.items() if k not in ("index", "index_sha256", "sessions",
                                                                              "roles")},
                        "training": {"command": [str(x) for x in argv], "log": str(log), "exit_code": code,
                                     "seconds": train_s},
                        "seconds": {"chain": chain_s, "training": train_s}})
    values = {"stage": g2.STAGE, "rule": BUNDLE_RULE, "layout_rule": LAYOUT_RULE, "protocol": str(protocol),
              "protocol_sha256": _sha(protocol), "protocol_g0_binding": gates.stage_sha256(protocol, "G0"),
              "min_bin_pages": minimum, "epochs": epochs, "generator": {"mode": GENERATOR, "seed": GENERATOR_SEED,
                                                                        "path": PATH},
              "audits": [{k: v for k, v in a.items() if k not in ("layout", "biny")} for a in found],
              "layouts": {a["layout_sha256"]: {"layout": a["layout"], "biny": a["biny"]} for a in found},
              "vms": {vm: next(b["name"] for b in bundles if vm in b["vms"]) for vm in sorted(seen)},
              "bundles": bundles, "praca": str(praca), "praca_bytes": _bytes(praca),
              "g2_values": False, "note": ("a diagnostic bundle of synthetic sessions for the parity of two paths of "
                                           "one detector, loaded with --allow-diagnostic; it detects nothing and "
                                           "gives no value of G2 (Q61)")}
    doc = g2.header(BUNDLE_SCHEMA, command, len(bundles), values)
    doc["note"] = ("Stage G2 (proposal 10.3): the diagnostic bundle of the parity sessions, whose data never become a "
                   "dataset. Written by python -m skuska.parita zvazok.")
    g2.write_new(out / BUNDLE_RECORD, doc)
    return doc


# ------------------------------------------------------------------ the comparison (scripts/campaign_report.py parity)

TABLE_SCHEMA = "hyptcn3/g2-parity/1"
EXACT = ("alarm", "alarm_event", "alarm_sources", "model_alarm", "rule_alarm", "integrity_alarm", "channel")
UNSCORED = ("model_state", "reason")  # Compared exactly on a row neither path scored.
FINDING_KINDS = ("only_watch", "only_replay", "no_seq", "duplicate_seq", "scored_on_one_path",
                 "score_outside_tolerance", "alarm_field", "unscored_field")
PARITY_GUEST = ("none: the mode parity reads the saved outputs of safeguard watch and safeguard replay, the audit "
                "record beside the replayed archive and the session.json it names; no VM is contacted and no RAM image "
                "is opened")
FAILED_HOLD_NOTE = ("the lead's decision on map question 16 (Q61): a failed hold as the user is no parity error; watch "
                    "runs as the VM's owner and the collector's raw/ belongs to root, so vmicollect hold fails there "
                    "and the row's evidence names the error; the evidence of a row is never compared")
COMPARE_RULE = (
    "the criterion live_archive_parity of stage G2 (the lead's G2 skeleton, map row 11, Q45, Q61): safeguard watch "
    "beside the collection gives on every row the same score and alarm as the replay of the same session's archive. "
    "The mode reads WATCH_DIR, the --out of python -m safeguard watch --snapshots S/raw, and REPLAY_DIR, the --out of "
    "python -m safeguard replay --archive <the audit's feature archive>: of each configuration.json, events.jsonl and "
    "status.json, and the audit record beside the archive (the same name with .json) with the session.json of its "
    "values.session_dir. Refused by name, each a data error and nothing written: a directory that is no output of "
    "watch (follow true, snapshots) or of replay --archive (archive, archive_sha256), a file of them that cannot be "
    "read, two bundles (their bundle_manifest differs), an archive without its audit record or one whose features or "
    "features_sha256 are not the replayed archive, a watch whose snapshots are not raw/ of the session the audit "
    "names, and code other than the code the tolerance was read from (PRECISION_SOURCES: the precision must then be "
    "found out again, Q45). The rows of both paths are compared by seq: a seq only one path has is a finding "
    "(only_watch, only_replay), and so are a row without seq (no_seq) and a seq a path holds twice (duplicate_seq); "
    "of a seq both have, the first row of each: a score present on one path only (scored_on_one_path); two scores "
    "outside TOLERANCE_RULE, math.isclose(watch, replay, rel_tol=SCORE_REL_TOL, abs_tol=SCORE_ABS_TOL) "
    "(score_outside_tolerance); every field of EXACT that differs (alarm_field: alarm, alarm_event, alarm_sources, "
    "model_alarm, rule_alarm, integrity_alarm, channel), each a finding even when the score agrees (Q45); and on a row "
    "neither path scored model_state and reason (unscored_field). The record counts the alarms of both paths (rows "
    "with alarm, alarm events by source, rows by channel and the seq of every alarm event) and says whether the "
    "sequences of the alarms are the same; it gives the largest relative difference of the scores compared, the "
    "failed holds of watch (FAILED_HOLD_NOTE, no finding) and the lag of watch behind the collector (snapshot_age_ms "
    "of its rows, recorded only). Parity holds when there is no finding. A parity session gives no value of G2 (Q61). "
    "Exit 0: the record is written to --out (a new JSON file with check E's header) and parity holds; 1: the record "
    "is written and names every finding; 2: a usage or data error, nothing written")


def _read_rows(path):
    try:
        rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    except (OSError, ValueError) as error:
        raise Refused(f"{path} cannot be read: {type(error).__name__}: {error}") from None
    if not all(type(row) is dict for row in rows):
        raise Refused(f"{path} holds a line that is no JSON object")
    return rows


def read_output(directory, kind):
    """The output of safeguard watch (kind watch) or safeguard replay --archive (kind replay) in `directory`:
    {dir, configuration, configuration_sha256, rows, events_sha256, status, status_sha256}; Refused by name."""
    directory = Path(os.path.abspath(directory))
    if not directory.is_dir():
        raise Refused(f"{directory}: no output directory of safeguard {kind}")
    out = {"dir": str(directory)}
    for name in ("configuration", "status"):
        doc = _json(directory / f"{name}.json", f"the {name}.json of safeguard {kind}:")
        if type(doc) is not dict:
            raise Refused(f"{directory / (name + '.json')} is no JSON object")
        out[name], out[f"{name}_sha256"] = doc, _sha(directory / f"{name}.json")
    out["rows"], out["events_sha256"] = _read_rows(directory / "events.jsonl"), _sha(directory / "events.jsonl")
    c = out["configuration"]
    ok = (c.get("follow") is True and isinstance(c.get("snapshots"), str) if kind == "watch" else
          c.get("follow") is False and isinstance(c.get("archive"), str) and isinstance(c.get("archive_sha256"), str))
    if not ok or type(c.get("bundle_manifest")) is not dict:
        raise Refused(f"{directory}: its configuration.json is no configuration of safeguard {kind}"
                      + (" (follow true and the snapshots)" if kind == "watch"
                         else " --archive (follow false, the archive and its sha256)"))
    return out


def _counts(rows):
    """The alarms of the rows of one path: rows with alarm, alarm events by source, rows by channel, the seq of every
    alarm event, and the sequence of the alarms [(seq, channels)] of the rows with alarm, in their order."""
    sources, channels = {}, {}
    for row in rows:
        for source in row.get("alarm_sources") or []:
            sources[source] = sources.get(source, 0) + 1
        for channel in row.get("channel") or []:
            channels[channel] = channels.get(channel, 0) + 1
    return {"rows": len(rows), "alarm_rows": sum(row.get("alarm") is True for row in rows),
            "alarm_events": sum(row.get("alarm_event") is True for row in rows), "events_by_source": sources,
            "alarm_rows_by_channel": channels,
            "event_seq": [row.get("seq") for row in rows if row.get("alarm_event") is True],
            "sequence": [[row.get("seq"), list(row.get("channel") or [])] for row in rows if row.get("alarm") is True]}


def _short(row):
    return {key: row.get(key) for key in ("seq", "model_state", "reason", "score", "alarm")}


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def compare(watch_dir, replay_dir):
    """COMPARE_RULE: the values of the record of the comparison of the two outputs; Refused for a data error."""
    sources = {name: _sha(ROOT / name) for name in PRECISION_SOURCES}
    if sources != PRECISION_SOURCES:
        raise Refused("the code differs from the code the tolerance was read from (PRECISION_SOURCES: "
                      + ", ".join(name for name in sources if sources[name] != PRECISION_SOURCES[name])
                      + "): find out the precision again before a comparison (Q45)")
    watch, replay = read_output(watch_dir, "watch"), read_output(replay_dir, "replay")
    bundle = {path: _canonical(out["configuration"]["bundle_manifest"]) for path, out in (("watch", watch),
                                                                                           ("replay", replay))}
    if bundle["watch"] != bundle["replay"]:
        raise Refused("the two outputs scored with two bundles: their bundle_manifest differs")
    archive = Path(replay["configuration"]["archive"])
    audit_path = archive.with_suffix(".json")
    audit = _json(audit_path, "the audit record beside the replayed archive:")
    v = audit.get("values") if type(audit) is dict and audit.get("schema") == AUDIT_SCHEMA else None
    if type(v) is not dict:
        raise Refused(f"{audit_path} is no audit record ({AUDIT_SCHEMA})")
    if (os.path.realpath(str(v.get("features") or "")) != os.path.realpath(archive)
            or v.get("features_sha256") != replay["configuration"]["archive_sha256"]):
        raise Refused(f"the replay read {archive} ({replay['configuration']['archive_sha256']}), not the feature "
                      f"archive its audit {audit_path} wrote")
    session_dir = Path(str(v.get("session_dir") or ""))
    snapshots = Path(watch["configuration"]["snapshots"])
    if os.path.realpath(snapshots) != os.path.realpath(session_dir / "raw"):
        raise Refused(f"watch read {snapshots}, not raw/ of the session {session_dir} whose archive the replay read")
    meta = _json(session_dir / "session.json", "the session.json of the audited session:")
    findings, compared, scored, largest = [], 0, 0, 0.0
    by_seq = {}
    for path, out in (("watch", watch), ("replay", replay)):
        table = by_seq[path] = {}
        for row in out["rows"]:
            seq = row.get("seq")
            if type(seq) is not int:
                findings.append({"kind": "no_seq", "path": path, "row": _short(row)})
                continue
            table.setdefault(seq, []).append(row)
        findings += [{"kind": "duplicate_seq", "path": path, "seq": seq, "rows": len(rows),
                      "reasons": [row.get("reason") for row in rows]} for seq, rows in sorted(table.items())
                     if len(rows) > 1]
    for seq in sorted(set(by_seq["watch"]) | set(by_seq["replay"])):
        if seq not in by_seq["replay"]:
            findings.append({"kind": "only_watch", "seq": seq, "row": _short(by_seq["watch"][seq][0])})
            continue
        if seq not in by_seq["watch"]:
            findings.append({"kind": "only_replay", "seq": seq, "row": _short(by_seq["replay"][seq][0])})
            continue
        w, r = by_seq["watch"][seq][0], by_seq["replay"][seq][0]
        compared += 1
        sw, sr = w.get("score"), r.get("score")
        if (sw is None) != (sr is None) or (sw is not None and not (_number(sw) and _number(sr))):
            findings.append({"kind": "scored_on_one_path", "seq": seq, "watch": _short(w), "replay": _short(r)})
        elif sw is not None:
            scored += 1
            difference = abs(sw - sr)
            relative = difference / max(abs(sw), abs(sr)) if difference else 0.0
            largest = max(largest, relative)
            if not score_agrees(sw, sr):
                findings.append({"kind": "score_outside_tolerance", "seq": seq, "watch": sw, "replay": sr,
                                 "difference": difference, "relative": relative})
        findings += [{"kind": "alarm_field", "seq": seq, "field": field, "watch": w.get(field),
                      "replay": r.get(field)} for field in EXACT if w.get(field) != r.get(field)]
        if sw is None and sr is None:
            findings += [{"kind": "unscored_field", "seq": seq, "field": field, "watch": w.get(field),
                          "replay": r.get(field)} for field in UNSCORED if w.get(field) != r.get(field)]
    alarms = {"watch": _counts(watch["rows"]), "replay": _counts(replay["rows"])}
    alarms["sequence_equal"] = alarms["watch"]["sequence"] == alarms["replay"]["sequence"]
    alarms["event_seq_equal"] = alarms["watch"]["event_seq"] == alarms["replay"]["event_seq"]
    failed = [row.get("seq") for row in watch["rows"] if (row.get("evidence") or {}).get("status") == "error"]
    ages = sorted(row["snapshot_age_ms"] for row in watch["rows"] if _number(row.get("snapshot_age_ms")))
    by_kind = {kind: sum(f["kind"] == kind for f in findings) for kind in FINDING_KINDS}
    summary = lambda out: {k: out[k] for k in ("dir", "configuration_sha256", "events_sha256", "status_sha256")} | {
        "rows": len(out["rows"]), "status": {k: out["status"].get(k) for k in (
            "stop_reason", "processed", "scored", "input_errors", "alarm_events", "evidence_errors", "fatal", "ok")}}
    return {"stage": g2.STAGE, "criterion": "live_archive_parity",
            "session": {"session_id": meta.get("session_id"), "vm": meta.get("vm"), "scenario": meta.get("scenario"),
                        "session_dir": str(session_dir)},
            "watch": {**summary(watch), "snapshots": str(snapshots)},
            "replay": {**summary(replay), "archive": str(archive),
                       "archive_sha256": replay["configuration"]["archive_sha256"],
                       "audit": {"path": str(audit_path), "sha256": _sha(audit_path), "accepted": v.get("accepted"),
                                 "reasons": v.get("reasons")}},
            "bundle": {"manifest_sha256": bundle["watch"], "diagnostic": watch["configuration"]["bundle_manifest"].get(
                "diagnostic")},
            "tolerance": {"score_rel_tol": SCORE_REL_TOL, "score_abs_tol": SCORE_ABS_TOL, "network": NETWORK_DTYPE,
                          "batch": BATCH, "threads": THREADS, "sources": PRECISION_SOURCES, "rule": TOLERANCE_RULE},
            "compared": {"seq_watch": len(by_seq["watch"]), "seq_replay": len(by_seq["replay"]), "seq_both": compared,
                         "scored_both": scored, "largest_relative_difference": largest},
            "alarms": alarms, "findings": findings, "findings_by_kind": by_kind, "holds": not findings,
            "failed_holds": {"rows": len(failed), "seq": failed, "note": FAILED_HOLD_NOTE},
            "lag_ms": None if not ages else {"max": ages[-1], "p95": ages[-(-95 * len(ages) // 100) - 1],
                                             "rows": len(ages)},
            "g2_values": False, "rule": COMPARE_RULE}


def parity_table(watch_dir, replay_dir, out, command):
    """The mode parity of scripts/campaign_report.py (COMPARE_RULE): its exit code; the record is a new JSON file
    with check E's header, and a refusal or a data error is printed on stderr with nothing written."""
    out = Path(os.path.abspath(out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: parity: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    try:
        values = compare(watch_dir, replay_dir)
        inputs = [values["watch"]["dir"], values["replay"]["dir"], values["session"]["session_dir"]]
        inside = [d for d in inputs if Path(os.path.realpath(out.parent)).is_relative_to(os.path.realpath(d))]
        if inside:
            raise Refused(f"refusing to write {out} inside the input directory {inside[0]}")
        doc = g2.header(TABLE_SCHEMA, command, values["compared"]["seq_both"], values,
                        guest=PARITY_GUEST)
        doc["note"] = ("The comparison of safeguard watch beside a G2 session with the replay of its archive "
                       "(criterion live_archive_parity of G2); a diagnostic bundle, nothing is detected.")
        out.parent.mkdir(parents=True, exist_ok=True)
        g2.write_new(out, doc)
    except (Refused, OSError) as error:
        print(f"campaign_report: parity: {' '.join(str(error).split())}", file=sys.stderr)
        return 2
    a = values["alarms"]
    print(f"live_archive_parity {values['session']['session_id']}: "
          + ("holds" if values["holds"] else f"{len(values['findings'])} finding(s): " + ", ".join(
              f"{k} {n}" for k, n in values["findings_by_kind"].items() if n))
          + f"; {values['compared']['seq_both']} rows compared, alarms watch {a['watch']['alarm_rows']} rows "
          f"({a['watch']['alarm_events']} events), replay {a['replay']['alarm_rows']} rows "
          f"({a['replay']['alarm_events']} events); record {out}", flush=True)
    return 0 if values["holds"] else 1


# ------------------------------------------------------------------ the command line

def _epochs(text):
    if text == EPOCHS_PLAN:
        return text
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(f"--epochs {text}: a number of epochs above 0 or {EPOCHS_PLAN}")
    return value


def main(argv=None):
    import argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m skuska.parita", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    zv = sub.add_parser("zvazok", help="make the diagnostic bundle of the parity sessions once (BUNDLE_RULE)")
    zv.add_argument("--protocol", type=Path, required=True)
    zv.add_argument("--audit", type=Path, action="append", required=True,
                    help="the audit record of a real G2 session (audit_<UTC>.json in its directory), one per VM")
    zv.add_argument("--praca", type=Path, required=True, help="a new work directory on a disk, never a tmpfs")
    zv.add_argument("--out", type=Path, required=True, help="a new directory for the bundles and zvazok.json")
    zv.add_argument("--epochs", type=_epochs, required=True,
                    help=f"N: a diagnostic override of analysis.stopping.max_epochs; {EPOCHS_PLAN}: the plan's")
    zv.add_argument("--vysledky", type=Path, default=ROOT / "data/results",
                    help="the gate records the chain requires G0 from (scripts/gates.py require G1)")
    a = parser.parse_args(argv)
    line = shlex.join(["python", "-m", "skuska.parita", *argv])
    try:
        doc = make_bundles(a.protocol, a.audit, a.praca, a.out, a.epochs, vysledky=a.vysledky, command=line)
        print(json.dumps({"record": str(Path(a.out).absolute() / BUNDLE_RECORD), "vms": doc["values"]["vms"],
                          "bundles": [{k: b[k] for k in ("name", "dir", "sha256", "seconds")}
                                      for b in doc["values"]["bundles"]]}, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"skuska.parita: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
