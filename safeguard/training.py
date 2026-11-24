"""Train, select and calibrate from explicit, disjoint corpus roles.

Original hyptcn3 integration. No test feature arrays are loaded during fitting.
Diagnostic bundles demonstrate mechanics only and cannot be loaded for normal
deployment. Workload classification is distinct from maliciousness detection.

Parameters (package B6b, design NAVRH_B6b section 1.4). Under protocol schema 3 the analysis plan of the protocol
(its section analysis, checked by scripts/protocol_v5.py analysis_plan) gives every parameter: the TCN and its
optimizer (analysis.architecture), the stopping rule (analysis.stopping), the seeds (analysis.seeds; the deployed
bundle has analysis.deploy_seed, D14), the quantile of the threshold (analysis.fpr) and the alarm rule
(analysis.alarm_rule). An argument that sets one of them is refused by name unless the bundle is diagnostic, and a
diagnostic bundle lists every override. A seed of analysis.seeds is a choice among the planned seeds, not an
override. Under schemas 1 and 2 the named rule legacy_schema_2 keeps today's values (LEGACY_VALUES, LEGACY_OPTIMIZER,
the architecture of safeguard/model.py architecture(), every epoch up to the cap). The manifest names the rule that
gave the parameters and every argument that was given.

The two models (proposal 8.2 and 8.3). The predictor and the classifier head are trained one after the other, each
with its own Adam optimizer, its own gradient clip and its own random streams (STREAMS: initialization, dropout,
batch order), so the predictor's weights at a seed do not depend on the classifier. Each model keeps the epoch of its
best dev loss and stops on its own: patience_epochs epochs after that epoch, or at the cap max_epochs. When the
selected epoch is the last one the cap allows, training goes on once to twice the cap (proposal 8.3: repeated once
with twice the cap; the first max_epochs epochs of that training are the epochs already run, with the same seed and
streams, so they are not run again). The manifest records the stop of each model and both learning curves.

The manifest also carries (skeleton B6 sections 2, 4 and 5; design 1.3 to 1.5): the classes of the columns and the
mask, the scale rule and the normalizer, the ranges of the rule channel, the sensitivity table, and the pre-written
wording for the case that the rule channel carries all detection (question Q6, confirmed by the lead 2026-11-24).
Under a rule with a column of class rule_differenced its limitations also state what that rule cannot see
(SESSION_START_LIMITATION of safeguard/features.py, the lead's answer to question Q8).

The normalizer, the score and the rule channel are those of safeguard/features.py, model.py and bundle.py (design B6b
1.1 to 1.3): the rule of the protocol (NormalizationRule.from_protocol), the TCN inputs of its classes neural and
differenced, the scored bins, and under a differenced input windows that also hold the measured row before them
(WindowBuffer anchored), as Bundle.score takes them.
"""
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone
import copy
import json
import math
import os
from pathlib import Path
import random
import shutil
import tempfile

import numpy as np
import torch
from torch import nn

from features.archive import load as load_archive
from features.acceptance import require_accepted, require_recorded
# One list of the roles for the index builder and training (package B6a); FIT_ROLES are the roles training loads.
from features.dataset import FIT_ROLES, ROLES, allocation, chronology, named, row_key
from features.quality import BEHAVIOR_POLICY, protocol_policy
from .bundle import SCHEMA, digest
from .features import (LEGACY_RULE, MENA, FeatureNormalizer, NormalizationRule, WindowBuffer, check_frame,
                       feature_contract, frames_from_archive, rule_channel)
from .model import (Classifier, Predictor, SCORE_FORMULA, LOSS_FORMULA,
                    anomaly_score, architecture, prediction_errors)


def _json(path):
    return json.loads(Path(path).read_text())


def _resolve(base, path):
    path = Path(path)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _validate_current_semantics(extractor_hashes, profile_hashes, protocol):
    """A schema name alone cannot establish unchanged extraction semantics."""
    root = Path(__file__).resolve().parents[1]
    current_extractors = {str(file.relative_to(root)): digest(file)
                          for directory in (root / "features", root / "guestparse")
                          for file in directory.rglob("*.py") if "tests" not in file.parts}
    if extractor_hashes != current_extractors:
        raise ValueError("stale extractor implementation; re-audit raw captures with current source")
    if not isinstance(protocol.get("profile"), str):
        raise ValueError("production protocol lacks guest profile path")
    profile = _resolve(root, protocol["profile"])
    if not profile.is_dir():
        raise ValueError("current guest profile is missing")
    current_profile = {str(file.relative_to(profile)): digest(file)
                       for file in profile.rglob("*") if file.is_file()}
    if not current_profile or profile_hashes != current_profile:
        raise ValueError("stale guest profile; restore the captured profile before training")


def validate_index(path, diagnostic=False):
    """Recheck frozen artifacts; inspecting test metadata/hashes is not fitting."""
    path = Path(path).resolve()
    doc = _json(path)
    if doc.get("schema") != "hyptcn3/corpus-index/1":
        raise ValueError("unsupported corpus index")
    if not diagnostic and (doc.get("complete") is not True or doc.get("diagnostic", False)):
        raise ValueError("production training requires a complete non-diagnostic corpus")
    if (doc.get("normalization_fit_role", "train") != "train"
            or doc.get("threshold_fit_role", "calibration") != "calibration"):
        raise ValueError("unsupported corpus fitting roles")
    protocol_path = _resolve(path.parent, doc["protocol"])
    protocol_hash = digest(protocol_path)
    protocol = _json(protocol_path)
    if protocol_hash != doc["protocol_sha256"] or protocol != doc["protocol_config"]:
        raise ValueError("corpus protocol checksum/configuration mismatch")
    if protocol_policy(protocol) != BEHAVIOR_POLICY:
        raise ValueError("safeguard training requires the behavioral input protocol")
    # The rule the index was built under (design B6a 1.3): the plan of its mode under schema 3, every scenario in
    # every group under schemas 1 and 2. An index that states another rule, or none, is refused.
    try:
        rule, roles, rows = allocation(protocol, doc.get("plan_mode"))
    except ValueError as error:
        raise ValueError("corpus index allocation: " + str(error)) from None
    if doc.get("allocation_rule") != rule:
        raise ValueError(f"corpus index states allocation rule {doc.get('allocation_rule')!r}; its protocol and plan "
                         f"mode give {rule}")
    records = copy.deepcopy(doc["sessions"])
    if not records:
        raise ValueError("empty corpus")
    ids, files, hashes, assignments = set(), set(), set(), set()
    boot_roles, group_roles, boot_groups, group_boots = {}, {}, {}, {}
    layouts, extractors, environments, profiles = set(), set(), set(), set()
    for record in records:
        role, group, boot = record["role"], record["group"], record["boot_id"]
        if role not in roles or record.get("typ") != "benign":
            raise ValueError("only explicit benign corpus roles are accepted")
        if not all(isinstance(value, str) and value for value in (record["id"], group, boot, record["scenario"])):
            raise ValueError("missing session identity")
        if record["id"] in ids:
            raise ValueError("duplicate session identity")
        ids.add(record["id"])
        for registry, key in ((boot_roles, boot), (group_roles, group)):
            if registry.setdefault(key, role) != role:
                raise ValueError("boot/group shared across dataset roles")
        if boot_groups.setdefault(boot, group) != group or group_boots.setdefault(group, boot) != boot:
            raise ValueError("boot/group mapping must be one to one")
        assignment = (group, record["scenario"])
        if assignment in assignments:
            raise ValueError("duplicate group/scenario assignment")
        assignments.add(assignment)
        if record.get("protocol_sha256") != protocol_hash:
            raise ValueError("session protocol mismatch")
        for field in ("session", "audit", "features"):
            file = _resolve(path.parent, record[field])
            record[field] = str(file)
            if digest(file) != record[field + "_sha256"]:
                raise ValueError(field + " checksum mismatch")
        if role == "test_controls":  # Package B7c: the index hashes controls.json of this role (features/dataset.py).
            if type(record.get("controls")) is not str or type(record.get("controls_sha256")) is not str:
                raise ValueError("index record of role test_controls names no controls.json and its sha256: an "
                                 "index built before package B7c")
            controls = _resolve(path.parent, record["controls"])
            record["controls"] = str(controls)
            if digest(controls) != record["controls_sha256"]:
                raise ValueError("controls checksum mismatch")
        if record["features"] in files or record["features_sha256"] in hashes:
            raise ValueError("duplicate feature archive")
        files.add(record["features"])
        hashes.add(record["features_sha256"])
        meta, audit = _json(record["session"]), _json(record["audit"])
        if (meta.get("schema") not in ("hyptcn3/collection-session/1", "hyptcn3/collection-session/2")
                or audit.get("schema") != "hyptcn3/collection-audit/1"):
            raise ValueError("unsupported session/audit provenance")
        for key in ("role", "group", "scenario", "typ", "protocol_sha256"):
            if meta.get(key) != record[key]:
                raise ValueError("index/session mismatch: " + key)
        if meta.get("session_id") != record["id"] or meta["guest_before"]["boot_id"] != boot:
            raise ValueError("index/session identity mismatch")
        if meta.get("vm") != record.get("vm"):  # The VM names the planned row as well (design B6a 1.2).
            raise ValueError("index/session mismatch: vm")
        if not diagnostic and (meta.get("diagnostic") or audit["values"].get("diagnostic")):
            raise ValueError("diagnostic artifacts cannot be used in production training")
        values = audit["values"]
        from features.quality import require_log_audit
        require_log_audit(meta, values)
        if (values.get("accepted") is not True or values.get("reasons")
                or values.get("role") != role or values.get("protocol_sha256") != protocol_hash
                or values.get("session_sha256") != record["session_sha256"]
                or values.get("features_sha256") != record["features_sha256"]
                or _resolve(Path(record["audit"]).parent, values["features"]) != Path(record["features"])):
            raise ValueError("audit provenance mismatch or unaccepted audit")
        # The recorded verdict must be the one the protocol gives for the recorded facts. No archive is opened
        # here, so the final test stays sealed; train_bundle decides the fitted roles again from their archives.
        require_recorded(protocol, role, values)
        layouts.add(json.dumps(values["layout"], sort_keys=True))
        extractors.add(json.dumps(values["extractor_sha256"], sort_keys=True))
        profiles.add(json.dumps(meta.get("profile_sha256", {}), sort_keys=True))
        if not diagnostic and (not meta.get("profile_sha256") or not values["extractor_sha256"]):
            raise ValueError("production corpus lacks profile/extractor provenance")
        guest = meta["guest_before"]
        environments.add((guest["kernel"], guest["stack_sha256"], meta["collector_sha256"]))
        if not all(math.isfinite(record[k]) for k in ("start", "end")) or record["end"] < record["start"]:
            raise ValueError("invalid session time range")
        if record["scenario"] not in protocol["scenarios"]:
            raise ValueError("scenario outside protocol")
    if len(layouts) != 1 or len(extractors) != 1 or len(environments) != 1 or len(profiles) != 1:
        raise ValueError("mixed layout, extractor or guest/collector environment")
    if not diagnostic:
        _validate_current_semantics(json.loads(next(iter(extractors))),
                                    json.loads(next(iter(profiles))), protocol)
    # Every role the plan gives sessions (schemas 1 and 2: each of their four roles) is present.
    for role in roles if rows is None else [role for role in roles if any(row["role"] == role for row in rows)]:
        if not any(r["role"] == role for r in records):
            raise ValueError("missing corpus role: " + role)
    if rows is not None:
        _check_plan(records, rows, rule, diagnostic)
    elif not diagnostic:
        # Same group names as scripts/collection.py plan and features/dataset.py build.
        prefix = protocol.get("group_prefix", "")
        for role in roles:
            expected = {f"{prefix}{role}-{i + 1}" for i in range(protocol["roles"][role])}
            for scenario in protocol["scenarios"]:
                if {r["group"] for r in records if r["role"] == role and r["scenario"] == scenario} != expected:
                    raise ValueError(f"incomplete planned allocation: groups of role {role} with scenario {scenario} "
                                     f"differ from {rule}")
    late = chronology(records)
    if late is not None:
        raise ValueError(f"corpus roles must be chronologically separated: {late[0]['role']} session {late[0]['id']} "
                         f"ends after {late[1]['role']} session {late[1]['id']} starts")
    return doc, protocol, records


def _check_plan(records, rows, rule, diagnostic):
    """The sessions of a schema-3 index against the planned rows of its mode (design B6a 1.3): every session holds
    one row, matched by (role, group, scenario, vm), and carries its position; production training also needs a
    session for every row. A row with two sessions is a duplicate group/scenario assignment of validate_index."""
    planned = {row_key(row): row for row in rows}
    held = set()
    for record in records:
        row = planned.get(row_key(record))
        if row is None:
            raise ValueError(f"incomplete planned allocation: session {named(record)} holds no row of {rule}")
        if record.get("position") != row["position"]:
            raise ValueError(f"index/plan mismatch: position of session {record['id']} is {record.get('position')!r}, "
                             f"its row {row['label']} has {row['position']}")
        held.add(row["label"])
    missing = [row for row in rows if row["label"] not in held]
    if missing and not diagnostic:
        raise ValueError(f"incomplete planned allocation: planned session {named(missing[0])} of {rule} has no "
                         "session")


# ------------------------------------------------------------------ the parameters of a training (design B6b 1.4, 1.6)

# Schemas 1 and 2 keep today's values under the name LEGACY_RULE (legacy_schema_2, the name of their normalization
# rule too, safeguard/features.py); never a silent default.
PLAN_RULE = "analysis"  # Schema 3: the analysis plan of the protocol gives every parameter.
LEGACY_SCHEMAS = ("hyptcn3/collection-protocol/1", "hyptcn3/collection-protocol/2")
# Today's values (rule legacy_schema_2): the defaults of train_bundle and of the command line before package B6b and
# the constants of its optimizer. analysis.architecture of config/collection-v5.json states the same numbers.
LEGACY_VALUES = {"epochs": 10, "batch_size": 32, "seed": 0, "fpr": 0.01, "k": 3, "n": 5}
LEGACY_OPTIMIZER = {"learning_rate": 0.001, "gradient_clip": 5, "classifier_gradient_clip": 5}
# The arguments of train_bundle (and the options of safeguard train and tcn.seedy train) that set a parameter of the
# analysis plan, with the path where a protocol of schema 3 states it. None means not given.
OPTIONS = {"epochs": "analysis.stopping.max_epochs", "batch_size": "analysis.architecture.batch_size",
           "seed": "analysis.seeds", "fpr": "analysis.fpr", "k": "analysis.alarm_rule.k", "n": "analysis.alarm_rule.n"}
MODEL = "safeguard/model.py TCN"  # analysis.architecture.model: the one model this training builds.
STOPPING = "best dev loss, patience"  # analysis.stopping.rule: the one stopping rule this training implements.
REPEAT = "once with twice the cap"  # analysis.stopping.repeat_if_last_epoch: the one repeat it implements.


def _checked(given):
    """The given parameters of OPTIONS (None: not given), each of its type and range; ValueError names a bad one."""
    for name, value in given.items():
        if value is None:
            continue
        if name == "fpr":
            ok = (isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
                  and 0 < value < 1)
        else:
            ok = type(value) is int and value >= (0 if name == "seed" else 1)
        if not ok:
            raise ValueError(f"invalid training parameters: {name} {value!r}")
    return given


def training_parameters(protocol, given, *, window_rows, diagnostic):
    """The parameters of one training (module docstring): {rule, source, model, learning_rate, gradient_clip,
    classifier_gradient_clip, batch_size, stopping, seed, seeds, deploy_seed, fpr, k, n, given, overrides}.

    `given` maps the names of OPTIONS to the arguments, None where one was not given. Schema 3: the analysis plan, a
    given parameter refused by name outside a diagnostic bundle and recorded in overrides inside one; a given seed of
    analysis.seeds is a choice, never an override; the plan's model, stopping rule and repeat must be the ones this
    training implements and weight normalization is refused (the TCN of the thesis has none). Schemas 1 and 2: the
    rule legacy_schema_2. Any other schema is refused."""
    from scripts.protocol_v5 import SCHEMA as PLAN_SCHEMA, analysis_plan
    given = _checked({name: given.get(name) for name in OPTIONS})
    schema = protocol.get("schema")
    if schema == PLAN_SCHEMA:
        plan = analysis_plan(protocol)
        arch, stop = plan["architecture"], plan["stopping"]
        for path, value, implemented in (("analysis.architecture.model", arch["model"], MODEL),
                                         ("analysis.stopping.rule", stop["rule"], STOPPING),
                                         ("analysis.stopping.repeat_if_last_epoch", stop["repeat_if_last_epoch"],
                                          REPEAT)):
            if value != implemented:
                raise ValueError(f"{path} is {value!r}; this training implements {implemented!r}")
        if arch["weight_norm"] is not False:
            raise ValueError("analysis.architecture.weight_norm is true: the TCN of the thesis has no weight "
                             "normalization (SULAD_S_TEXTOM_PRACE table 1) and safeguard/model.py builds none")
        planned = {"epochs": stop["max_epochs"], "batch_size": arch["batch_size"], "seed": plan["seeds"],
                   "fpr": plan["fpr"], "k": plan["alarm_rule"]["k"], "n": plan["alarm_rule"]["n"]}
        values, overrides = dict(planned, seed=plan["deploy_seed"]), {}
        for name, value in given.items():
            if value is None:
                continue
            if name == "seed" and value in plan["seeds"]:
                values["seed"] = value  # One of the planned seeds: a choice, not an override.
                continue
            if not diagnostic:
                raise ValueError(f"analysis parameter {name} is given ({value!r}) under protocol schema 3, whose "
                                 f"analysis plan fixes {OPTIONS[name]} = {planned[name]!r}; a given analysis "
                                 "parameter is applied only to a diagnostic bundle (--diagnostic)")
            values[name] = value
            overrides[name] = {"path": OPTIONS[name], "planned": planned[name], "applied": value}
        parameters = {"rule": PLAN_RULE,
                      "source": "the analysis section of the protocol (schema 3), checked by scripts/protocol_v5.py "
                                "analysis_plan",
                      "model": {key: arch[key] for key in ("kernel", "blocks", "channels", "dropout", "weight_norm")},
                      **{key: arch[key] for key in LEGACY_OPTIMIZER},
                      "stopping": {"rule": STOPPING, "patience_epochs": stop["patience_epochs"],
                                   "max_epochs": values["epochs"], "repeat_if_last_epoch": REPEAT},
                      "seeds": list(plan["seeds"]), "deploy_seed": plan["deploy_seed"]}
    elif schema in LEGACY_SCHEMAS:
        values = {name: LEGACY_VALUES[name] if value is None else value for name, value in given.items()}
        overrides, today = {}, architecture(window_rows)
        parameters = {"rule": LEGACY_RULE,
                      "source": "today's values of safeguard/training.py (LEGACY_VALUES, LEGACY_OPTIMIZER) and of "
                                "safeguard/model.py architecture(), and the arguments given (schemas 1 and 2)",
                      "model": {**{key: today[key] for key in ("kernel", "blocks", "channels", "dropout")},
                                "weight_norm": False},
                      **LEGACY_OPTIMIZER,
                      "stopping": {"rule": LEGACY_RULE + ": every epoch up to max_epochs; each model keeps the epoch "
                                                         "of its best dev loss", "patience_epochs": None,
                                   "max_epochs": values["epochs"], "repeat_if_last_epoch": None},
                      "seeds": None, "deploy_seed": None}
    else:
        raise ValueError(f"protocol schema {schema!r} states no training parameters: schema 3 gives them in its "
                         f"analysis section, schemas 1 and 2 keep {LEGACY_RULE}")
    if values["k"] > values["n"]:
        raise ValueError(f"invalid training parameters: k {values['k']} above n {values['n']}")
    return dict(parameters, batch_size=values["batch_size"], seed=values["seed"], fpr=values["fpr"], k=values["k"],
                n=values["n"], given={name: value for name, value in given.items() if value is not None},
                overrides=overrides)


def model_config(parameters, window_rows, width):
    """The architecture of safeguard/model.py (Predictor, Classifier) at the parameters, with `width` TCN columns."""
    config = architecture(window_rows)
    config.update({key: parameters["model"][key] for key in ("kernel", "blocks", "channels", "dropout")},
                  global_features=width)
    return config


# ------------------------------------------------------------------ the normalizer and the score (contract 1.1, 1.2)
# Where training meets the normalizer and the score (design B6b section 1): the rule is
# safeguard.features.NormalizationRule.from_protocol (train_bundle), the normalizer FeatureNormalizer.fit(frames, rule);
# its inputs are the rule's columns of class neural and differenced (rule.tcn_names, the mask) and its bins the scored
# bins, so the loss and the score of a batch below are those of Bundle.score (LOSS_FORMULA, SCORE_FORMULA). The rule
# channel's ranges come from safeguard.features.rule_channel.

LEGACY_SCALE = ("every column neural; one pooled scale over the bins; the machine-epsilon floor (a scale at or below "
                "it becomes 1); every bin scored")


def scale_rule(normalizer):
    """The scale rule the fitted normalizer applies, for manifest.normalization.scale: under a rule of protocol schema 3
    the rule of analysis.scale (per_bin, min_bin_pages, floor, local_floor) with the bins it scored and those it did
    not; under legacy_schema_2 the pooled scale (LEGACY_SCALE)."""
    rule = normalizer.rule
    if rule.floor is None:
        return {"rule": LEGACY_SCALE}
    return {"rule": "analysis.scale", "per_bin": rule.per_bin, "min_bin_pages": rule.min_bin_pages,
            "floor": dict(rule.floor), "local_floor": dict(rule.local_floor), "floor_policy": rule.floor_policy,
            "bins": [list(b) for b in normalizer.bins], "unscored_bins": [list(b) for b in normalizer.unscored]}


def column_scales(normalizer, columns):
    """{column: the normalizer's scale of it in original units} for the TCN columns (of its first difference for a
    differenced column): global_scale holds one scale per input of the TCN, in the order of normalizer.input_names."""
    return {name: float(normalizer.global_scale[normalizer.input_names.index(name)]) for name in columns}


def _prediction_loss(predictor, global_values, local_values, labels=None):
    """The loss of the predictor on a batch (LOSS_FORMULA: the batch holds the rule's inputs and the scored bins only);
    the last row of each window is the target."""
    global_error, bin_error = prediction_errors(predictor(global_values[:, :-1], local_values[:, :-1]),
                                                global_values[:, -1], local_values[:, -1])
    return 0.5 * global_error.mean() + 0.5 * bin_error.mean()


def _scores(predictor, dataset, batch_size):
    """The anomaly score (SCORE_FORMULA, as Bundle.score gives it) of every window of `dataset`, in the order of its
    indices."""
    scores = []
    predictor.eval()
    with torch.inference_mode():
        for g, local, _ in dataset.batches(batch_size):
            errors = prediction_errors(predictor(g[:, :-1], local[:, :-1]), g[:, -1], local[:, -1])
            scores.extend(anomaly_score(*errors).tolist())
    return scores


class Windows:
    """Normalized session arrays and small indices, not copied sliding tensors.

    The arrays are the normalizer's inputs of each session (normalizer.inputs: a differenced column against the
    measured row before it); a window is what the bundle's WindowBuffer gives, so under a rule with a differenced
    input it also needs the measured row before its first row (anchored), and frames() gives the anchor first."""

    def __init__(self, sessions, normalizer, contract, classes):
        self.sessions, self.indices, self.anchors = [], [], []
        self.window_rows = contract["window_rows"]
        self.max_gap_s = contract["max_gap_s"]
        anchored = normalizer.rule.anchored
        for record, frames in sessions:
            if record["scenario"] not in classes:
                raise ValueError("workload class absent from training role")
            values = normalizer.inputs(frames)
            session_index = len(self.sessions)
            self.sessions.append((record, frames, *values, classes.index(record["scenario"])))
            buffer = WindowBuffer(contract["window_rows"], contract["max_gap_s"], anchored=anchored)
            position_of = {id(frame): position for position, frame in enumerate(frames)}
            for position, frame in enumerate(frames):
                check_frame(frame, contract)
                window = buffer.push(frame)
                if window is not None:
                    self.indices.append((session_index, position))
                    self.anchors.append(position_of[id(window[0])] if anchored else None)
        if not self.indices:
            raise ValueError("role has no eligible windows")

    def frames(self, index):
        """The frames of window `index` as Bundle.score takes them: the window_rows rows ending at its target, after
        the measured row before them (the anchor) under a rule with a differenced input."""
        session, end = self.indices[index]
        frames = self.sessions[session][1]
        rows = frames[end + 1 - self.window_rows:end + 1]
        anchor = self.anchors[index]
        return rows if anchor is None else [frames[anchor], *rows]

    def batch(self, selection):
        global_values, local_values, labels = [], [], []
        for index in selection:
            session, end = self.indices[int(index)]
            _, _, global_array, local_array, label = self.sessions[session]
            start = end + 1 - self.window_rows
            global_values.append(global_array[start:end + 1])
            local_values.append(local_array[start:end + 1])
            labels.append(label)
        return (torch.as_tensor(np.stack(global_values), dtype=torch.float32),
                torch.as_tensor(np.stack(local_values), dtype=torch.float32),
                torch.tensor(labels, dtype=torch.long))

    def batches(self, batch_size, order=None):
        if order is None:
            order = np.arange(len(self.indices))
        for start in range(0, len(order), batch_size):
            yield self.batch(order[start:start + batch_size])


# ------------------------------------------------------------------ the two models (proposal 8.2, 8.3)

# The random streams of one training seed: each model draws its initialization, its dropout and its batch order from
# streams of its own, so that the predictor's weights do not depend on the classifier (skeleton B6 test 6).
STREAMS = ("predictor_init", "predictor_dropout", "predictor_order",
           "classifier_init", "classifier_dropout", "classifier_order")
STREAM_RULE = ("numpy SeedSequence(seed, spawn_key=(index of the stream in STREAMS,)).generate_state(1)[0] seeds "
               "torch for the initialization (before the model is built) and the dropout (during its training), and "
               "numpy default_rng for the batch order; torch's global generator is restored after each")


def stream_seed(seed, stream):
    """The seed of one random stream (STREAM_RULE) of the training seed `seed`."""
    return int(np.random.SeedSequence(seed, spawn_key=(STREAMS.index(stream),)).generate_state(1)[0])


def _classification_loss(classifier, global_values, local_values, labels):
    return nn.functional.cross_entropy(classifier(global_values, local_values), labels)


def _dev_loss(model, loss, dataset, batch_size):
    """The mean loss of `model` over the windows of `dataset` (dev), in eval mode."""
    model.eval()
    total = 0.0
    with torch.inference_mode():
        for g, local, labels in dataset.batches(batch_size):
            total += float(loss(model, g, local, labels)) * len(labels)
    value = total / len(dataset.indices)
    if not math.isfinite(value):
        raise ValueError("non-finite development loss")
    return value


def _fit(model, loss, train, dev, *, learning_rate, clip, batch_size, stopping, seed, name):
    """Train one model alone (module docstring) and leave it at its selected epoch, in eval mode: (record, history).

    Its own Adam optimizer and gradient clip; dropout and batch order from its streams. `stopping` as in
    training_parameters: patience_epochs None and repeat_if_last_epoch None (legacy_schema_2) run every epoch up to
    max_epochs. history holds (epoch, train loss, dev loss) per epoch."""
    cap, patience = stopping["max_epochs"], stopping["patience_epochs"]
    repeat = stopping["repeat_if_last_epoch"] is not None
    best, state, selected, history = math.inf, None, None, []
    limit, epoch, repeated, stopped_by = cap, 0, False, "max_epochs"
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(stream_seed(seed, name + "_dropout"))
        order = np.random.default_rng(stream_seed(seed, name + "_order"))
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
        while True:
            while epoch < limit:
                epoch += 1
                model.train()
                total, count = 0.0, 0
                for g, local, labels in train.batches(batch_size, order.permutation(len(train.indices))):
                    optimizer.zero_grad(set_to_none=True)
                    value = loss(model, g, local, labels)
                    if not torch.isfinite(value):
                        raise ValueError("non-finite training loss")
                    value.backward()
                    nn.utils.clip_grad_norm_(model.parameters(), clip)
                    optimizer.step()
                    total += float(value.detach()) * len(labels)
                    count += len(labels)
                dev_loss = _dev_loss(model, loss, dev, batch_size)
                history.append((epoch, total / count, dev_loss))
                if dev_loss < best:  # Strict: a tie keeps the earlier epoch.
                    best, state, selected = dev_loss, copy.deepcopy(model.state_dict()), epoch
                if patience is not None and epoch - selected >= patience:
                    stopped_by = "patience_epochs"
                    break
            if stopped_by != "max_epochs" or selected != limit or not repeat or repeated:
                break
            repeated, limit = True, 2 * cap  # Proposal 8.3: the selected epoch is the last one; once, twice the cap.
    model.load_state_dict(state)
    model.eval()
    return {"max_epochs": cap, "patience_epochs": patience, "epochs_run": epoch, "selected_epoch": selected,
            "best_dev_loss": best, "stopped_by": stopped_by, "repeated": repeated,
            "max_epochs_after_repeat": 2 * cap if repeated else None, "selected_is_last": selected == limit}, history


def _settings(parameters, clip):
    return dict(learning_rate=parameters["learning_rate"], clip=parameters[clip], batch_size=parameters["batch_size"],
                stopping=parameters["stopping"], seed=parameters["seed"])


def _train_predictor(config, datasets, parameters):
    """(predictor, its stop, its learning curve): built from its own initialization stream, trained alone."""
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(stream_seed(parameters["seed"], "predictor_init"))
        predictor = Predictor(config)
    record, history = _fit(predictor, _prediction_loss, datasets["train"], datasets["dev"],
                           **_settings(parameters, "gradient_clip"), name="predictor")
    return predictor, record, [{"epoch": epoch, "train_prediction_loss": train, "dev_prediction_loss": dev}
                               for epoch, train, dev in history]


def _train_classifier(config, classes, datasets, parameters):
    """(classifier head, its stop, its learning curve): trained after the predictor and apart from it (proposal 8.2),
    with its own optimizer, its own clip (classifier_gradient_clip) and its own streams."""
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(stream_seed(parameters["seed"], "classifier_init"))
        classifier = Classifier(config, classes)
    record, history = _fit(classifier, _classification_loss, datasets["train"], datasets["dev"],
                           **_settings(parameters, "classifier_gradient_clip"), name="classifier")
    return classifier, record, [{"epoch": epoch, "train_classification_loss": train,
                                 "dev_classification_loss": dev} for epoch, train, dev in history]


def calibrate(scores, dataset, *, fpr, k, n, interval_s, diagnostic):
    scores = np.asarray(scores, dtype=np.float64)
    if (not math.isfinite(fpr) or not 0 < fpr < 1 or not 1 <= k <= n
            or not math.isfinite(interval_s) or interval_s <= 0
            or scores.ndim != 1 or len(scores) != len(dataset.indices)):
        raise ValueError("invalid calibration parameters or score index")
    required = 20 if diagnostic else max(100, math.ceil(10 / fpr))
    if len(scores) < required or not np.isfinite(scores).all() or (scores < 0).any():
        raise ValueError(f"calibration needs at least {required} finite nonnegative scores")
    threshold = float(np.quantile(scores, 1 - fpr, method="higher"))
    history, previous, active, events = deque(maxlen=n), None, False, 0
    for score, (session, end) in zip(scores, dataset.indices):
        frame = dataset.sessions[session][1][end]
        current = (session, frame.seq, frame.timestamp, frame.chain_id)
        if (previous is None or current[0] != previous[0] or current[1] != previous[1] + 1
                or current[3] != previous[3] or not 0 < current[2] - previous[2] <= dataset.max_gap_s):
            history.clear()
            active = False
        history.append(bool(score > threshold))
        condition = len(history) == n and sum(history) >= k
        events += int(condition and not active)
        active, previous = condition, current
    exposure_hours = len(scores) * interval_s / 3600
    return {"role": "calibration", "threshold": threshold, "k": k, "n": n,
            "method": "benign_score_quantile_higher", "comparison": ">",
            "fpr_design": fpr, "n_scores": len(scores), "minimum_scores": required,
            "window_exceedance_fraction": float((scores > threshold).mean()),
            "alarm_events": events, "scorable_hours": exposure_hours,
            "calibration_alarm_events_per_hour": events / exposure_hours,
            "exposure_definition": "scored targets times nominal interval; warmup/gaps excluded",
            "event_definition": "k of n after n scored targets; rising edges; reset at barriers",
            "diagnostic": diagnostic,
            "note": "Calibration frequency is not a held-out false-alarm measurement or guarantee."}


# ------------------------------------------------------------------ the sensitivity table (skeleton section 5)

SENSITIVITY_RTOL = 1e-4  # judgment: the bisection stops when its bracket is narrower than this share of the change.
SENSITIVITY_DOUBLINGS = 40  # judgment: no change beyond 2^40 scales of the column (about 1e12) is searched.
SENSITIVITY_METHOD = (
    "Bundle.score of the saved bundle on the calibration window with the median score (the lower median of the "
    "calibration scores, ties by window order; judgment): for every TCN column, the raw value of the window's last "
    "row is moved up (down) from 0 by the column's scale, doubled until the row's score exceeds the threshold and "
    "then bisected to a relative width of SENSITIVITY_RTOL. The predictor reads only the rows before the last, so the "
    "move changes only the target: under the score formula the score is a convex function of the move and the first "
    "crossing found is the smallest change. one_unit_suffices scores a move of one unit (analysis.scale.floor; null "
    "when the protocol states no unit) in either direction.")
SENSITIVITY_NOTE = (
    "The table speaks of one row: the change lifts the score of that one row above the threshold. An alarm of the "
    "neural channel needs k of the last n scored rows above it (calibration.k, calibration.n), so one changed row "
    "alone raises none. A change is reported whether or not the column can take the moved value (a count below 0, a "
    "ratio above 1); up or down null: no move up to 2^SENSITIVITY_DOUBLINGS scales exceeds the threshold.")


def _smallest_change(exceeds, start):
    """The smallest move d >= 0 with exceeds(d): 0 when the unmoved row exceeds; else doubling from `start`, then
    bisection to SENSITIVITY_RTOL; None when no move up to 2^SENSITIVITY_DOUBLINGS times `start` exceeds."""
    if exceeds(0.0):
        return 0.0
    low, high = 0.0, float(start)
    for _ in range(SENSITIVITY_DOUBLINGS + 1):
        if exceeds(high):
            break
        low, high = high, 2 * high
    else:
        return None
    while high - low > SENSITIVITY_RTOL * high:
        middle = (low + high) / 2
        if exceeds(middle):
            high = middle
        else:
            low = middle
    return high


def sensitivity_table(bundle, window, threshold, columns, scales, units):
    """{base_score, columns}: for every column of `columns`, the smallest change of that one column in the last row
    of `window` that alone lifts the row's score (bundle.score, the real score function) above `threshold`, up and
    down (SENSITIVITY_METHOD). `scales` gives each column's scale in original units and `units` its unit (a column
    absent from it: none stated). Rows: {name, scale, unit, value, up, down, one_unit_suffices}."""
    last = window[-1]

    def score(name, move):
        vector = last.vector.copy()
        vector[MENA.index(name)] += move
        return bundle.score([*window[:-1], replace(last, vector=vector)])["score"]

    rows = []
    for name in columns:
        found = {direction: _smallest_change(lambda move: score(name, sign * move) > threshold, scales[name])
                 for direction, sign in (("up", 1.0), ("down", -1.0))}
        unit = units.get(name)
        rows.append({"name": name, "scale": float(scales[name]), "unit": unit,
                     "value": float(last.vector[MENA.index(name)]), **found,
                     "one_unit_suffices": None if unit is None else bool(
                         score(name, unit) > threshold or score(name, -unit) > threshold)})
    return {"base_score": float(bundle.score(window)["score"]), "columns": rows}


def _sensitivity(bundle, dataset, scores, threshold, columns, scales, units):
    """The sensitivity table of the manifest on the calibration window with the (lower) median score."""
    order = sorted(range(len(scores)), key=lambda i: (scores[i], i))
    rank = (len(order) - 1) // 2
    window = dataset.frames(order[rank])  # As Bundle.score takes it: the anchor first under a differenced input.
    table = sensitivity_table(bundle, window, threshold, columns, scales, units)
    # The batch score (float32) of the window against Bundle.score of it alone: the tolerance of the same check in
    # tcn/porovnanie.py (judgment).
    if not math.isclose(table["base_score"], scores[order[rank]], rel_tol=1e-5, abs_tol=1e-6):
        raise ValueError("score of the saved bundle differs from the calibration score of the median window")
    rows = window[-dataset.window_rows:]
    anchor = {} if len(window) == len(rows) else {"anchor_seq": window[0].seq}  # The measured row before it.
    return {"window": {"role": "calibration", "session": rows[-1].session, "first_seq": rows[0].seq,
                       "last_seq": rows[-1].seq, **anchor, "calibration_score": float(scores[order[rank]]),
                       "rank": rank, "of": len(scores)},
            "threshold": threshold, **table, "method": SENSITIVITY_METHOD, "note": SENSITIVITY_NOTE,
            "rtol": SENSITIVITY_RTOL, "doublings": SENSITIVITY_DOUBLINGS}


# The pre-written wording for the case that the rule channel carries all detection (skeleton B6 section 4): the
# executor's proposal of question Q6 (OTAZKY_VEDUCEMU.md), composed only of verbatim parts of proposal 8.2, which the
# lead accepted as pre-written on 2026-11-24; source is the lead's mark, and proposal 8.2 holds the same wording word
# for word (safeguard/tests/test_training.py checks both). The final evaluation fills the ellipsis with the number.
RULE_CHANNEL_ONLY = {
    "text": "Všetku detekciu nesie pravidlový kanál: deklarované pravidlá s rozsahom z `train` a `calibration`; nikdy "
            "sa neuvádzajú ako neurónová detekcia. Výsledky O2 a O4 sa uvádzajú po kanáloch aj za ich zjednotenie; "
            "prírastok citlivosti neurónového kanála nad pravidlovým je …",
    "source": "NAVRH kap. 8.2, zložené vykonávateľom, potvrdené vedúcim 2026-11-24",
    "status": "pre-written: confirmed by the lead 2026-11-24 (question Q6, OTAZKY_VEDUCEMU.md), word for word in "
              "proposal 8.2; the final evaluation fills the ellipsis with the number (tcn/finalne.py "
              "rule_channel_only)",
}


def train_bundle(corpus_path, output_dir, *, window_rows=32, max_gap_s=7.5, epochs=None, seed=None,
                 batch_size=None, fpr=None, k=None, n=None, diagnostic=False):
    """Fit, select and calibrate one bundle (module docstring). epochs (the cap max_epochs), seed, batch_size, fpr, k
    and n are the analysis parameters of OPTIONS: None means not given (training_parameters)."""
    given = _checked({"epochs": epochs, "batch_size": batch_size, "seed": seed, "fpr": fpr, "k": k, "n": n})
    if (type(window_rows) is not int or window_rows < 2
            or not math.isfinite(max_gap_s) or max_gap_s <= 0):
        raise ValueError("invalid training parameters")
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise FileExistsError("bundle output exists; choose a new immutable path")
    index, protocol, records = validate_index(corpus_path, diagnostic)
    if window_rows != protocol["window_rows"] or max_gap_s != protocol["max_gap_s"]:
        raise ValueError("training temporal settings differ from frozen protocol")
    parameters = training_parameters(protocol, given, window_rows=window_rows, diagnostic=diagnostic)
    # The classes of the columns and the scale rule (design B6b 1.1), before any archive is opened.
    rule = NormalizationRule.from_protocol(protocol, diagnostic=diagnostic)
    sessions = {role: [] for role in FIT_ROLES}
    contract = None
    for record in records:
        if record["role"] not in FIT_ROLES:
            continue  # No array/statistic of a test role (test_benign, test_controls) enters fitting.
        archive = load_archive(record["features"])
        frames = list(frames_from_archive(archive, record["id"]))
        if not frames or frames[0].timestamp != record["start"] or frames[-1].timestamp != record["end"]:
            raise ValueError("feature times differ from frozen session index")
        audit = _json(record["audit"])["values"]
        # A session is fitted only as the audit accepted it: the acceptance is decided again from the archive and
        # must equal the record (features/acceptance.py). Invalid rows it tolerates are never fitted or scored.
        require_accepted(archive, protocol, record["id"], record["role"], audit)
        if contract is None:
            contract = feature_contract(frames[0], window_rows, max_gap_s)
        if frames[0].layout != audit["layout"]:
            raise ValueError("feature/audit layout mismatch")
        for frame in frames:
            check_frame(frame, contract)
        sessions[record["role"]].append((record, frames))
    fit_frames = [frame for _, frames in sessions["train"] for frame in frames
                  if frame.valid and frame.has_predecessor and not frame.full]
    normalizer = FeatureNormalizer.fit(fit_frames, rule)
    classes = sorted({record["scenario"] for record, _ in sessions["train"]})
    if len(classes) < 2:
        raise ValueError("activity classification requires at least two train workload classes")
    datasets = {role: Windows(data, normalizer, contract, classes) for role, data in sessions.items()}
    required_calibration = 20 if diagnostic else max(100, math.ceil(10 / parameters["fpr"]))
    if len(datasets["calibration"].indices) < required_calibration:
        raise ValueError(f"calibration needs at least {required_calibration} eligible windows")
    tcn = list(rule.tcn_names)  # The mask: the inputs of the TCN (normalizer.input_names).
    config = model_config(parameters, window_rows, len(tcn))
    seed = parameters["seed"]
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    old_threads = torch.get_num_threads()
    torch.set_num_threads(min(old_threads, 4))
    try:
        predictor, predictor_stop, history = _train_predictor(config, datasets, parameters)
        classifier, classifier_stop, classifier_history = _train_classifier(config, len(classes), datasets,
                                                                            parameters)
        scores = _scores(predictor, datasets["calibration"], parameters["batch_size"])
        calibration = calibrate(scores, datasets["calibration"], fpr=parameters["fpr"], k=parameters["k"],
                                n=parameters["n"], interval_s=protocol["interval_s"], diagnostic=diagnostic)
        root = Path(__file__).resolve().parents[1]
        source_hashes = {str(path.relative_to(root)): digest(path)
                         for directory in (root / "safeguard", root / "tcn", root / "features", root / "guestparse")
                         for path in directory.rglob("*.py") if "tests" not in path.parts}
        # validate_index reads the plan of the corpus and training_parameters the analysis plan from this module
        # (design B6b section 5). No other module of scripts/ runs in training: require_log_audit without snapshot
        # times does not import scripts/collection_logs.py.
        source_hashes["scripts/protocol_v5.py"] = digest(root / "scripts" / "protocol_v5.py")
        first_meta = _json(records[0]["session"])
        first_audit = _json(records[0]["audit"])
        environment = {"kernel": first_meta["guest_before"]["kernel"],
                       "stack_sha256": first_meta["guest_before"]["stack_sha256"],
                       "collector_sha256": first_meta["collector_sha256"],
                       "profile_sha256": first_meta.get("profile_sha256", {}),
                       "extractor_sha256": first_audit["values"]["extractor_sha256"]}
        channel = rule_channel(sessions, rule.classes, k=parameters["k"], n=parameters["n"])
        manifest = {"schema": SCHEMA, "diagnostic": diagnostic,
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "feature_contract": contract, "normalizer": normalizer.to_dict(),
                    "architecture": config, "classes": classes,
                    "environment": environment,
                    "classification_task": "recorded benign workload scenario; not maliciousness or malware family",
                    "score_formula": SCORE_FORMULA, "loss_formula": LOSS_FORMULA,
                    "calibration": calibration, "weights": {},
                    "parameters": parameters,
                    "normalization": {"rule": rule.name, "columns": dict(rule.classes), "tcn_columns": tcn,
                                      "scale": scale_rule(normalizer)},
                    "rule_channel": channel,
                    "analysis_wording": {"rule_channel_only": dict(RULE_CHANNEL_ONLY)},
                    "training": {"seed": seed, "epochs": parameters["stopping"]["max_epochs"],
                                 "batch_size": parameters["batch_size"],
                                 "normalization_fit_role": "train", "checkpoint_selection_role": "dev",
                                 "selected_predictor_epoch": predictor_stop["selected_epoch"],
                                 "selected_classifier_epoch": classifier_stop["selected_epoch"],
                                 "history": history, "classifier_history": classifier_history,
                                 "stopping": {"rule": parameters["stopping"]["rule"], "predictor": predictor_stop,
                                              "classifier": classifier_stop},
                                 "random_streams": {"rule": STREAM_RULE, "streams": list(STREAMS)},
                                 "windows": {role: len(data.indices) for role, data in datasets.items()},
                                 "normalization_rows": len(fit_frames), "test_feature_arrays_loaded": False},
                    "provenance": {"corpus_index": str(Path(corpus_path).resolve()),
                                   "corpus_index_sha256": digest(corpus_path),
                                   "protocol_sha256": index["protocol_sha256"], "protocol": protocol,
                                   "source_sha256": source_hashes, "sessions": records},
                    "limitations": ["No attack detection or held-out false-alarm metric is inferred from training.",
                                    "Classifier labels describe collection workload settings; they are not per-process ground truth.",
                                    # Question Q8 (the lead, 2026-11-24): only under a column of class rule_differenced.
                                    *([channel["limitation"]] if channel["limitation"] is not None else [])]}
        units = protocol["analysis"]["scale"]["floor"] if parameters["rule"] == PLAN_RULE else {}
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        lock = output_dir.with_name(output_dir.name + ".lock")
        with lock.open("x"):
            temporary = Path(tempfile.mkdtemp(prefix="." + output_dir.name + ".", dir=output_dir.parent))
            try:
                if output_dir.exists():
                    raise FileExistsError("bundle output already exists")
                for name, model in (("predictor", predictor), ("classifier", classifier)):
                    file = temporary / (name + ".pt")
                    torch.save(model.state_dict(), file)
                    manifest["weights"][name] = {"file": file.name, "sha256": digest(file)}
                (temporary / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
                # The sensitivity table is measured on the saved bundle, the one that is published: its weights do
                # not change, only the manifest is written again with the table.
                from .bundle import load_bundle
                loaded = load_bundle(temporary, allow_diagnostic=diagnostic)
                manifest["sensitivity"] = _sensitivity(
                    loaded, datasets["calibration"], scores, calibration["threshold"], tcn,
                    column_scales(normalizer, tcn), {name: units[name] for name in tcn if name in units})
                (temporary / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
                # Verify serialized form before publishing the directory.
                loaded = load_bundle(temporary, allow_diagnostic=diagnostic)
                loaded.score(datasets["dev"].frames(0))
                os.rename(temporary, output_dir)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
                lock.unlink()
        return {"bundle": str(output_dir), "diagnostic": diagnostic, "classes": classes,
                "calibration": calibration, "training": manifest["training"]}
    finally:
        torch.set_num_threads(old_threads)
