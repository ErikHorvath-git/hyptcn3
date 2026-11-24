"""The one final evaluation of a corpus of protocol v5 (package B7c, agent E, with the merge of agents S and M).

Binding texts: the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 7, the B7c row of its section 8 and points 2 and
4 of its addendum of 2026-11-22T20:55Z; the design dokazy/B7/navrh/NAVRH_B7c.md sections 1.1 to 1.4 and 4 and its
addendum 5 (the merge, after the questions Q15 to Q17); SULAD_S_TEXTOM_PRACE (the test role is used once, all five
seeds run on it in one final run, the metrics are computed over alarm events); proposal 10.8 (G6: one command
evaluates every pre-registered model and method on the same replays and writes one record) and 11.1 (the stage of
every record).

    python -m tcn.finalne --corpus I --models B0 B1 B2 B3 B4 --campaign C --replays R --out O [--threads T]

    --corpus    the corpus index (features/dataset.py build) of a campaign or of its rehearsal (plan_mode)
    --models    the bundles of M (safeguard train), exactly one for every seed of analysis.seeds; each is named in
                the record by its manifest (sha256, seed, created_utc); a diagnostic bundle is refused
    --campaign  the record of the campaign in data/results (package B9): its rejected and replaced sessions by cause
    --replays   a new directory for the replays (REPLAY_RULE), outside data/results
    --out       the new record (data/results); an existing one is never overwritten
    --threads   the CPU threads of PyTorch (default 4, as safeguard train)

The stage of the record is no option (tcn/pecat.py STAGE_RULE; design 5.1, question Q15): it is the stage of the run
on its ledger. The command line runs on the ledger of record (data/results/kniha_pecati.json), stage final for a
campaign and generalka for a rehearsal. Only the Python entry evaluate(..., ledger=L) takes another ledger, which the
guards of the process then read (tcn.pecat vlastna_kniha): stage suchy, a G1 dry run or a test.

What runs (design 1.4) is pre-registered in the protocol of the corpus, and the command takes no choice of its own:
M at every seed of analysis.seeds, Z0 to Z5 (analysis.methods, Z4 by both its variants), the descriptive methods of
analysis.descriptive_methods at their seeds, K1 (tcn/tvrdenia.py k1), the interventions and K2 (tcn/zasahy.py,
tcn/k2.py), the diagnostics (tcn/diagnostiky.py) and the metrics of design 1.3 (tcn/eval.py, agent M).

THE RECORD (CONFIRMATORY_RULE, proposal 9.1: only K1 and K2 are confirmatory). The top level of its values holds the
metadata of the run and the claims of K1, K2a and K2b with the values they rest on (the budget, the matched thresholds
and fits of M and Z0 to Z5, the interventions, the values of K2 of M and Z0 to Z5); every other result is under
values["opisné"]. A record of stage final or generalka lies under data/results (OUT_RULE). Package B11 (agent E; the
lead's answers to questions Q17 and Q28, 2026-11-24): the record carries the attachments its protocol lists in
advance (analysis.attachments: series, losses, copies; ATTACHMENT_RULE), each a file <record stem>.<name>.npz beside
it that values.attachments names by its path, sha256 and bytes; a figure drawn from them is not a new reading of a test
role, and a failed record names none.

ORDER (ORDER_RULE, design 5.4). 0: every refusal that reads no data of a session, before anything is computed (among
them the carrier boots of a campaign, BOOTS_RULE, the seal's state on the ledger, the outputs and the gate records of
the run's stage, GATE_RULE). 1: everything that reads only
the roles without a seal (the fits, the budget, the matched thresholds, the summary of every training, the
diagnostics of calibration and the retrained networks). 2: tcn.pecat spotrebuj consumes the seal. 3: inside the run,
the sealed sessions, their controls and replays, and every value on the sealed roles. 4: the attachments, then one
record.

THE CODE OF AGENTS S AND M (design 1.1 to 1.3): tcn/pecat.py (stav, spotrebuj and its run, kontrola, vlastna_kniha,
REHEARSAL_MARK), safeguard.cli replay_directory (the replays, with the unscored stretches of safeguard.runtime
unscored), features.dataset controls_of and scripts/controls.py outcomes (the controls), tcn.eval vyhodnot_far,
vyhodnot_udalosti, training_summary, control_records and metriky_protokolu (the metrics and their levels,
analysis.metrics), analysis.linkage (copied into the record as the protocol states it); besides them
scripts/gates.py require (the gate records, design 5.3) and the campaign record of package B9 (CAMPAIGN_RULE).
"""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import sys

import numpy as np

from scripts import protocol_v5
from tcn import metody, pecat

REPO = Path(__file__).resolve().parents[1]
SCHEMA = "hyptcn3/final-evaluation/1"
INDEX_SCHEMA = "hyptcn3/corpus-index/1"
SEALED = pecat.SEALED_ROLES  # Design 1.1: the sealed roles, test_benign and test_controls.
FIT_ROLES = ("train", "dev", "calibration")
CONTROL_ROLE = protocol_v5.CONTROL_ROLE
EVENT_ROLE = "test_benign"  # K1, O2 and O3 (proposal 4.1, 4.2).
UNEVALUATED = metody.UNEVALUATED  # "nevyhodnotené" (proposal 6.4), one constant with tcn/k2.py and diagnostiky.py.
EVALUATED = "evaluated"
GROUPINGS = ("boot", "vm", "profile")  # Proposal 9.1: every main number has a table by boot, VM and profile.
# The paths of the code whose change refuses a final evaluation of stage final (CLEAN_TREE_RULE).
CODE = ("tcn/", "safeguard/", "features/", "guestparse/", "scripts/")
TRAINING_ROLES = ("dev", "calibration")  # The fit roles a summary of a training reads (design B7c 1.3, Q11).
GATES = {"final": "G6", "generalka": "G3a", "suchy": "G1"}  # GATE_RULE: the gate the run of each stage requires.
# The tracked results: the gate records of GATE_RULE and the record of a run of stage final or generalka (OUT_RULE).
RESULTS = REPO / "data" / "results"
RECORD_STAGES = ("final", "generalka")  # OUT_RULE: the stages whose record lies under data/results.
OPISNE = "opisné"  # Proposal 9.1: every result but those of K1 and K2 is written under this key (CONFIRMATORY_RULE).

# ------------------------------------------------------------------ the rules (written into the record)

ORDER_RULE = (
    "design B7c 5.4, the order of the merge over that of 1.4: 0 every refusal that reads no data of a session, before "
    "anything is computed (the analysis plan with the bounds m of G1 and the list of its attachments, ATTACHMENT_RULE, "
    "in plan mode campaign the carrier boots of the index against analysis.interventions.boots, BOOTS_RULE, the seal's "
    "state on the ledger by tcn.pecat stav, so that a seal that cannot be consumed is refused here, the outputs with "
    "the paths of the attachments, OUT_RULE, the gate records of the run's stage, GATE_RULE, at stage final a "
    "committed tree of code, the campaign record, the bundles with the one wording of the rule channel they carry "
    "(RULE_CHANNEL_RULE, finding N5 of the B7c confirmation), the sharp check of the index of safeguard/training.py "
    "validate_index, which opens no archive, and the files of every session); 1 everything that reads only the roles "
    "without a seal: the sessions of train, dev and calibration, the budget from M's clean calibration traffic "
    "(tcn.metody BUDGET_RULE), the fits of Z0 to Z5 (Z1 selected by the interventions inserted into dev at the budget) "
    "and of the descriptive methods, the matched threshold of every method and seed of M on calibration (tcn.metody "
    "matched_rate over calibration alone), the summary of every training on dev and calibration (TRAINING_RULE), and "
    "of the diagnostics the boot left out of calibration and the fits of the networks (the context truncation, the "
    "retrained networks, SEED_RULE); 2 tcn.pecat spotrebuj consumes the seal, immediately before the first sealed "
    "archive is checked or opened; 3 inside the run: every sealed session after tcn.pecat kontrola, the outcomes of "
    "its controls (CONTROLS_RULE), its replays for every seed of M (REPLAY_RULE), the rates of the matched thresholds "
    "on the sealed roles (tcn.metody rate at each threshold, the rates matched_rate gives), Z0's random alarms, K1, "
    "the interventions and K2, the diagnostics on the sealed roles, the metrics of design 1.3 (METRICS_RULE) and the "
    "arrays of the attachments (ATTACHMENT_RULE); 4 the attachments, each a new file, and one record, after which the "
    "run closes completed in the ledger; a step that fails before 2 consumes nothing and writes no record, one that "
    "fails after it writes the record of FAILURE_RULE and closes the run failed; the inputs and the seeds are those of "
    "design 1.4, so the order changes no number")
SEAL_NOTE = ("the ledger protects against mistakes, not intent; its time stamp is the push of the repository to the "
             "remote (proposal 10.6, design B7c 1.1); the run closes in the ledger after this record is written, so "
             "closed is null in the record's seal (tcn.pecat stav gives the closure)")
CLEAN_TREE_RULE = (
    "the commit and the changed paths of the working tree (tcn.eval _git_stav); at stage final (tcn/pecat.py "
    "STAGE_RULE) a change under " + ", ".join(CODE) + " or no git refuses the final evaluation before the seal is "
    "consumed (the audit's R2: a clean tree for all measurement and model code); at stages generalka and suchy they "
    "are recorded")
GATE_RULE = (
    "design B7c 5.3 (question Q16): before the seal is consumed, scripts/gates.py require asks the gate records of "
    "data/results for the stage of the run against the protocol file of the index (protocol, checked against its "
    "protocol_sha256) and the current code: stage final requires G6 (valid records of G0 to G5), generalka G3a (G0 to "
    "G2) and suchy G1 (G0); the bundles are not registered apart: the list fixed in advance is the protocol's methods "
    "and seeds, the seal is consumed once, so a bundle chosen before the run carries nothing of the test roles, and "
    "the record names every bundle by its manifest sha256")
OUT_RULE = (
    "proposal 10 and FAILURE_RULE: every stage has its record in data/results, so the record of a run of stage final "
    "or generalka (a run on the ledger of record, tcn/pecat.py STAGE_RULE) lies under data/results, and another --out "
    "is refused before the seal is consumed; the replays lie outside data/results (REPLAY_RULE); a dry run (stage "
    "suchy) writes its record where it is told; the attachments lie beside the record, <record stem>.<name>.npz, and "
    "an existing one, or one that is the directory of the replays, is refused before the seal is consumed "
    "(ATTACHMENT_RULE)")
BOOTS_RULE = (
    "the boots of K2 (design B7c 5.4, finding F3 of its verification): in plan mode campaign the carrier roles of the "
    "index (its sessions of test_benign and test_controls, one boot per group) hold analysis.interventions.boots "
    "boots, which tcn/k2.py k2_values requires after the seal; the index and the protocol are compared before it, so "
    "that an inconsistent protocol consumes nothing")
CONFIRMATORY_RULE = (
    "proposal 9.1 ('Potvrdzujúce sú iba K1 a K2. Všetko ostatné sa zapisuje pod kľúč „opisné“.'): the top level of the "
    "values holds the metadata of the run (its stage, mark, status and seal, the gate records, the tree, the corpus, "
    "the campaign record, the bundles of M, the replays, the attachments and the rules) and the confirmatory part, the "
    "claims and conclusions of K1, K2a and K2b and the values they rest on: the budget, the matched thresholds and the "
    "fits of M and Z0 to Z5, the interventions and the values of K2 of M and Z0 to Z5; every other result is under "
    "opisné: the metrics of design 1.3 (O2 to O4 and the thesis block, the outcomes of the controls), the diagnostics, "
    "every value of the descriptive methods (their fits, matched rates and values of K2), the losses of the "
    "predictors, the tables by boot, VM and profile, the summaries of the trainings, the unscored time, Z0's random "
    "alarms, the linkage table and the wording of the rule channel (RULE_CHANNEL_RULE); a failed record has opisné as "
    "well, empty")
RULE_CHANNEL_RULE = (
    "proposal 8.2 and question Q6 (the wording accepted by the lead 2026-11-24 as written in advance): the wording "
    "that the bundles of M carry (analysis_wording.rule_channel_only, safeguard/training.py RULE_CHANNEL_ONLY), its "
    "ellipsis filled with the increment of the neural channel over the rule channel on the planned controls of "
    "polarity control of test_controls (tcn.eval INCREMENT_RULE, the total group of O4): the median over the seeds of "
    "M (judgment: M enters every claim by that median, D14), each seed's counts beside it, nevyhodnotené when the "
    "increment of a seed is; all detection is carried by the rule channel (all_detection_by_rule_channel) when that "
    "increment is 0 while the rule channel detects a planned control; the sentence is the conclusion of that case "
    "only, so the record holds its text only when the flag is true, and otherwise text null with the reason (why), "
    "the increment and its counts kept (finding N3 of the B7c confirmation, package B10)")
REPLAY_RULE = (
    "one replay per seed of M and sealed session, inside the run, by safeguard.cli replay_directory (safeguard replay "
    "--archive of the loaded bundle: tcn.pecat kontrola first, configuration.json with archive_sha256 and the seal's "
    "decision, events.jsonl, evidence/event-NNNNNN.json, status.json with the unscored stretches of safeguard.runtime "
    "unscored) under <replays>/seed-<seed>/<session id>; a replay that stops at a fatal row, holds an input error that "
    "the invalid_rows rule of the protocol does not tolerate, or replays fewer rows than the archive has frames "
    "refuses the evaluation")
LOAD_RULE = ("the offered load of every frame from the session's traffic_intervals.jsonl (features/qualification.py "
             "offered_load); Z4 is pre-registered, so a session without it refuses the evaluation")
SEED_RULE = ("Z0 to Z5 draw nothing and take seed analysis.deploy_seed in their fit record; the descriptive methods "
             "take their seeds of analysis.descriptive_methods; the networks of the diagnostics (tcn/diagnostiky.py "
             "Siet, the context truncation, the shuffled context) are fitted at analysis.deploy_seed (judgment: they "
             "are descriptive, proposal 8.5, and one training per variant bounds their cost; D14: the deployed "
             "bundle's seed)")
CONTROLS_RULE = (
    "the outcomes of every planned control of a session of test_controls (the records of its controls.json with a "
    "kind: features.dataset controls_of, which checks its hash against the index, and tcn.eval control_records), "
    "computed once inside the run by scripts/controls.py outcomes (final_evaluation=True, the session's archive, the "
    "run's stage) and given to O4 for every seed (METRICS_RULE); a control whose outcomes cannot be computed refuses "
    "the evaluation by name: O4 counts every planned occurrence (tcn.eval O4_RULE), and the log audit refuses an "
    "accepted session with a control that did not run")
METRICS_RULE = (
    "design B7c 1.3 and 5.6, by tcn.eval (agent M) with every level and α from analysis.metrics (tcn.eval "
    "metriky_protokolu): for every seed of M, O2 and O3 on its replays of test_benign (vyhodnot_far and "
    "vyhodnot_udalosti, final_evaluation=True, inside the run) and O4 on its replays of test_controls with the "
    "outcomes of every planned control (vyhodnot_far with vysledky_kontrol, CONTROLS_RULE), each with the metrics of "
    "the thesis of its block v5; the α of their sections of iteration 1 (the exact two-sided interval of the rate) is "
    "1 - analysis.metrics.alarm_rate_interval.level")
TABLE_RULE = (
    "proposal 9.1, a table by boot (the index's group, one boot of one VM), by VM and by profile (the scenario's "
    "protocol profile): K1 over the clean windows of test_benign of each group, M by the median over its seeds of the "
    "group's mean loss and I = 1 - loss(M) / loss(Z) for each method of analysis.k1.compare, a group without a clean "
    "window nevyhodnotené; K2 over the interventions of the classes pooled in K2 (tcn/k2.py POOL_RULE) of each group, "
    "the share detected and evaluable over planned of every method, M by the median of its seeds, D = M - Z for each "
    "method of analysis.k2a.compare and analysis.k2b.compare; an intervention not placed has a boot and its VM but no "
    "session, so it stays out of the table by profile and is counted there; all descriptive")
UNSCORED_RULE = (
    "proposal 6.4: the unscored time of every sealed session is that of the status of its replays (safeguard.runtime "
    "unscored, the one rule of design B7c 5.6: every stretch nevyhodnotené with its seq, time, rows and reasons), the "
    "same for every seed of M (one feature contract scores the same rows, so a difference refuses the evaluation); "
    "per event, control, type and kind it is in the metrics (METRICS_RULE: O3 and O4 give the unscored time of every "
    "horizon and the evaluable occurrence of analysis.evaluable, tcn.eval OCCURRENCE_RULE)")
CAMPAIGN_RULE = (
    "the record of the campaign in data/results (package B9): values.planned_sessions and accepted_sessions "
    "(integers; accepted_sessions equals the sessions of the index) and values.rejected_sessions, each {session, "
    "cause, replacement: the session that replaced it or null}; tabulated by cause. Only the record of the complete "
    "ending of the campaign of the index is read (F7 of the verification of B9b): its schema "
    "hyptcn3/campaign-ending/1 (scripts/campaign.py ENDING_RULE), values.ending complete, values.campaign the campaign "
    "of the index (the campaign_id that the session.json of every session of the index names, but of those it took "
    "over from the campaign it continues, continues.taken_over_sessions), and its accepted sessions (the rows of "
    "values.sessions in state accepted) the sessions of the index as a set; any other record is refused by name "
    "before anything is computed")
ENDING_SCHEMA = "hyptcn3/campaign-ending/1"  # scripts/campaign.py ENDING_SCHEMA: the record of a campaign's ending.
TRAINING_RULE = (
    "design B7c 1.3 (question Q11, accepted by the lead 2026-11-24: package B7) and 5.4: before the seal, for every "
    "seed of M, on each of the fit roles dev and calibration, tcn.eval training_summary: the loss against the methods "
    "of analysis.k1.compare and the score by context and by scenario, in the record that names the bundle "
    "(values.models)")
FAILURE_RULE = (
    "a step that fails after the seal is consumed (ORDER_RULE 2) leaves this record: status failed, the step under "
    "way, the error and the seal, so that the one final run of the corpus is in data/results even when it gives no "
    "number, and the run closes failed in the ledger; the replays written before it stay where they are, and the "
    "attachments it wrote are removed, so that a failed record names none and none lies beside it (ATTACHMENT_RULE); a "
    "step that fails before the seal is consumed consumes nothing and writes no record")
IMPROVEMENT_RULE = ("descriptive: I = 1 - loss(method) / loss(Z) per boot over the clean windows of test_benign, as "
                    "tcn/tvrdenia.py hodnoty_k1 for one seed, and their mean")
# Package B11 (agent E; proposal 10.8, the lead's answers to questions Q17 and Q28, 2026-11-24): the attachments of the
# record, the list of scripts/protocol_v5.py (analysis.attachments, checked by attachments_problem).
ATTACHMENTS = protocol_v5.ATTACHMENTS
ATTACHMENT_FORMAT = (
    "numpy .npz written by numpy.savez_compressed (the executor's format): arrays of float64 (exact), int64, bool and "
    "fixed-width unicode text, none of objects, so that numpy.load(path, allow_pickle=False) reads every array")
ATTACHMENT_RULE = (
    "the attachments of the record (package B11; proposal 10.8, the lead's answers to questions Q17 and Q28, "
    "2026-11-24): exactly those of the protocol's list analysis.attachments (scripts/protocol_v5.py ATTACHMENTS and "
    "attachments_problem, refused by name before the seal is consumed), each one file <record stem>.<name>.npz beside "
    "the record (ATTACHMENT_FORMAT), whose path must not exist before the seal is consumed (OUT_RULE); their arrays "
    "are computed inside the run from the values of the record (ORDER_RULE 3), each file is written new just before "
    "the record (ORDER_RULE 4), and values.attachments names it by its path, sha256, bytes, format, contents and rule; "
    "a figure drawn from an attachment is not a new reading of a test role (Q17), and the attachments are metadata "
    "beside the replays that decide nothing (CONFIRMATORY_RULE); a run that fails removes the attachments it wrote, so "
    "that a failed record names none and none lies beside it (FAILURE_RULE); not attached (judgment): the random "
    "variant of Z0, drawn per window set from the stream z0_alarms (its record gives the seeds and the mean rates), "
    "and the networks of the diagnostics, which are no methods of the comparison")
SERIES_RULE = (
    "the attachment series (the lead's answer to question Q17): every row of every session of test_benign and "
    "test_controls, in the order of those roles and of their window sets, by its seq and time; for every method and "
    "seed of the evaluation (M at every seed of analysis.seeds, Z0 to Z5 with both variants of Z4, the descriptive "
    "methods at their seeds: the labels of values.matched and of opisné.descriptive_methods.matched) its matched "
    "threshold (one number, matched.<label>.threshold) and per row the score of the window that ends at the row (NaN "
    "where none ends), whether it exceeds the threshold, whether the alarm k of n is up and whether an alarm begins "
    "there (tcn/metody.py alarm_states, ALARM_RULE), with whether that window is clean (CLEAN_RULE), so that the "
    "alarms that begin in the clean windows of a role are the alarms of its matched rate; M also by the rows of its "
    "replays at the bundle threshold (safeguard replay, events.jsonl, read after the check of its sha256 in the "
    "replay's record: the score, the alarm of each channel, the alarm, alarm_event, the channels up and the sources "
    "that rise); and every event and control of those sessions (events.json, the controls of controls.json) with its "
    "type or kind, its polarity, whether it ran and its four host times")
LOSSES_RULE = (
    "the attachment losses (the lead's answer to question Q28): the rows of the attachment series; for every "
    "predictor of the evaluation (kind predictor: M at every seed, Z3, Z5, the GRU and LSTM predictors at their seeds; "
    "the labels of opisné.losses) the loss of the window that ends at each row (tcn/metody.py LOSS_FORMULA; NaN where "
    "none ends), with whether that window is clean (CLEAN_RULE): K1 and opisné.losses take the clean windows of "
    "test_benign")
COPIES_RULE = (
    "the attachment copies (the lead's answer to question Q28): every placed intervention of the plans of test_benign "
    "and test_controls that K2 detects (tcn/zasahy.py, in the order of those roles and of their copies) with its id, "
    "role, class, length, order or group, boot, session, start and status, and every row of its copy by its seq and "
    "time with whether it lies in the block and whether the window that ends there lies in the horizon of the "
    "intervention (tcn/k2.py DETECTION_RULE); for every method and seed of K2 (the labels of k2_values.thresholds) "
    "its matched threshold and per row the score of the window that ends there (NaN where none ends), whether it "
    "exceeds, whether the alarm k of n is up and whether an alarm begins there, so that a label detects an "
    "intervention when an alarm begins in its horizon")
HOST_TIMES = ("host_start_unix", "host_started_unix", "host_stop_unix", "host_stopped_unix")
_SESSIONS = {
    "session_id": "(N,) text: the id of every session of test_benign and test_controls, in the order of the rows",
    "session_role": "(N,) text: its role",
    "session_boot": "(N,) text: its boot (the group of the corpus index)",
    "session_vm": "(N,) text: its VM ('' when the corpus index names none)",
    "session_scenario": "(N,) text: its scenario",
    "session_profile": "(N,) text: the protocol profile of its scenario",
    "session_first_row": "(N,) int64: the index of its first row",
    "session_rows": "(N,) int64: its rows, one per frame of its feature archive",
    "row_session": "(R,) int64: the session of each row, an index of session_id",
    "row_seq": "(R,) int64: the seq of the row",
    "row_time": "(R,) float64: the time of the row (the timestamp of its frame, unix seconds)",
    "row_window": "(R,) bool: a window of the evaluation ends at the row",
    "row_clean": "(R,) bool: that window is clean traffic (tcn/metody.py CLEAN_RULE); false where none ends"}
_STATES = {
    "label": "(L,) text: the label of every method and seed",
    "label_name": "(L,) text: the name of its method",
    "threshold": "(L,) float64: the matched threshold of every label",
    "score": "(L, R) float64: the score of the window that ends at the row, NaN where none ends",
    "exceed": "(L, R) bool: the score lies above the threshold",
    "up": "(L, R) bool: the alarm k of n is up (tcn/metody.py ALARM_RULE)",
    "edge": "(L, R) bool: an alarm begins at the row"}
CONTENTS = {
    "series": {
        **_SESSIONS, **_STATES,
        "replay_seed": "(S,) int64: the seeds of M in the order of analysis.seeds",
        "replay_threshold": "(S,) float64: the threshold of the bundle of every seed, at which its replay alarms",
        "replay_score": "(S, R) float64: the score of the row of the replay, NaN where it has none",
        "replay_alarm": "(S, R) bool: alarm of the row, the union of the channels up",
        "replay_alarm_event": "(S, R) bool: alarm_event of the row, some channel rises there",
        "replay_model_alarm": "(S, R) bool: model_alarm of the row, the neural channel up",
        "replay_rule_alarm": "(S, R) bool: rule_alarm of the row, the rule channel up",
        "replay_integrity_alarm": "(S, R) bool: integrity_alarm of the row, a finding of the integrity checks",
        "channels": "(3,) text: the channels of safeguard.runtime CHANNELS",
        "replay_channel": "(S, R, 3) bool: the channels up at the row (its channel)",
        "sources": "(3,) text: the sources of safeguard.runtime SOURCES",
        "replay_sources": "(S, R, 3) bool: the sources that rise at the row (its alarm_sources)",
        "occurrence_session": "(E,) int64: the session of every event and control, an index of session_id",
        "occurrence_what": "(E,) text: event or control",
        "occurrence_type": "(E,) text: the type of the event or the kind of the control",
        "occurrence_polarity": "(E,) text: the polarity of a control (control or negative), '' for an event",
        "occurrence_executed": "(E,) bool: it ran (executed true in its record)",
        **{f"occurrence_{key}": f"(E,) float64: {key} of its record, NaN where it has none" for key in HOST_TIMES}},
    "losses": {
        **_SESSIONS,
        "label": "(P,) text: the label of every predictor and seed",
        "label_name": "(P,) text: the name of its method",
        "loss": "(P, R) float64: the loss of the window that ends at the row (tcn/metody.py LOSS_FORMULA), NaN where "
                "none ends"},
    "copies": {
        "intervention_id": "(I,) text: the id of every placed intervention of K2, in the order of its rows",
        "intervention_role": "(I,) text: its carrier role",
        "intervention_class": "(I,) text: its class, C or D",
        "intervention_length": "(I,) int64: the rows of its block",
        "intervention_variant": "(I,) text: its order (class C) or its group (class D)",
        "intervention_boot": "(I,) text: its boot",
        "intervention_session": "(I,) text: the session it is a copy of",
        "intervention_status": "(I,) text: evaluable or volume (tcn/zasahy.py VALIDITY_RULE)",
        "intervention_start_seq": "(I,) int64: the seq of the first row of its block",
        "intervention_start_time": "(I,) float64: the time of the first row of its block",
        "intervention_first_row": "(I,) int64: the index of the first row of its copy",
        "intervention_rows": "(I,) int64: the rows of its copy",
        "row_intervention": "(R,) int64: the intervention of each row, an index of intervention_id",
        "row_seq": "(R,) int64: the seq of the row",
        "row_time": "(R,) float64: the time of the row",
        "row_block": "(R,) bool: the row lies in the block",
        "row_window": "(R,) bool: a window of the copy ends at the row",
        "row_horizon": "(R,) bool: that window lies in the horizon of the intervention (tcn/k2.py DETECTION_RULE)",
        **_STATES}}
ATTACHMENT_RULES = {"series": SERIES_RULE, "losses": LOSSES_RULE, "copies": COPIES_RULE}


# ------------------------------------------------------------------ small helpers


def _digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _json_default(value):
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    raise TypeError("not JSON serializable: " + type(value).__name__)


def _dumps(value, indent=None):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, default=_json_default, indent=indent)


def _cache(method):
    """The method with its scores and losses computed once per window set (a set of one call stays alive, so its
    identity keys the cache; the cache keeps it alive). The instance keeps its class, so tcn/diagnostiky.py members
    still reads Z1, Z2, Z3 and M."""
    def cached(inner):
        seen = {}

        def call(windows):
            key = id(windows)
            if key not in seen:
                seen[key] = (windows, inner(windows))
            return seen[key][1]
        return call
    for name in ("_errors", "scores", "losses"):
        inner = getattr(method, name, None)
        if callable(inner):
            setattr(method, name, cached(inner))
    return method


# ------------------------------------------------------------------ 0: the refusals before anything is computed


def read_index(corpus):
    """(path, doc, protocol, mode) of the corpus index: schema 3, a plan mode, complete. No archive is opened."""
    path = Path(corpus).resolve()
    doc = json.loads(path.read_text())
    if type(doc) is not dict or doc.get("schema") != INDEX_SCHEMA:
        raise ValueError(f"{path}: not a corpus index of schema {INDEX_SCHEMA}")
    protocol = doc.get("protocol_config")
    if type(protocol) is not dict or protocol.get("schema") != protocol_v5.SCHEMA:
        raise ValueError(f"{path}: the final evaluation reads a corpus of protocol schema {protocol_v5.SCHEMA}; "
                         "schemas 1 and 2 keep tcn.eval far --final")
    mode = doc.get("plan_mode")
    if mode not in protocol_v5.MODES:
        raise ValueError(f"{path}: plan mode {mode!r}; the index of a plan of protocol schema 3 is of mode "
                         + " or ".join(protocol_v5.MODES) + " (features/dataset.py build)")
    if doc.get("complete") is not True:
        raise ValueError(f"{path}: the corpus index is not complete (allocation_mismatches): the final evaluation "
                         "takes the whole plan of its mode")
    return path, doc, protocol, mode


def analysis(protocol):
    """The checked analysis plan of the protocol of the corpus (scripts/protocol_v5.py analysis_plan, with
    analysis.metrics and analysis.linkage of agent M), after every key the evaluation needs: the list of the
    attachments (ATTACHMENT_RULE: exactly ATTACHMENTS, scripts/protocol_v5.py attachments_problem, refused by name
    first), the bounds m of G1 (a null one refused by name), the grids of G3a (tcn.metody grid), the keys of the
    interventions, of the diagnostics and of the descriptive methods."""
    from tcn import diagnostiky, opisne, zasahy
    section = protocol.get("analysis") if type(protocol.get("analysis")) is dict else {}
    problem = protocol_v5.attachments_problem(section.get("attachments"))
    if problem is not None:
        raise ValueError(f"{problem}: the final evaluation writes exactly the attachments its protocol lists in "
                         "advance (ATTACHMENT_RULE); refused before the seal is consumed")
    plan = protocol_v5.analysis_plan(protocol)
    for claim in protocol_v5.CLAIMS:
        if plan[claim]["m"] is None:
            raise ValueError(f"analysis.{claim}.m is null: the bound m is determined in G1 (determined_at), and the "
                             "final evaluation decides no claim without it; refused before the seal is consumed")
    for method in protocol_v5.GRIDDED:
        metody.grid(protocol, method)
    zasahy.protocol_keys(protocol)
    diagnostiky.diagnostics(protocol)
    opisne.runs(protocol)
    opisne.training_settings(protocol)
    return plan


def attachment_paths(out):
    """{name: <record stem>.<name>.npz beside the record `out`} for every attachment of ATTACHMENTS
    (ATTACHMENT_RULE)."""
    out = Path(out)
    return {name: out.with_name(f"{out.stem}.{name}.npz") for name in ATTACHMENTS}


def check_outputs(out, replays, stage):
    """The record, the directory of the replays and every attachment beside the record (ATTACHMENT_RULE) are new,
    their parent directories exist, no attachment is the directory of the replays, the replays lie outside
    data/results, which git tracks (REPLAY_RULE), and the record of a run of stage final or generalka lies under it
    (OUT_RULE)."""
    for path, option in ((Path(out), "--out"), (Path(replays), "--replays")):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"{option} {path} exists; the final evaluation writes a new one")
        if not path.parent.is_dir():
            raise ValueError(f"{option} {path}: its directory {path.parent} does not exist")
    for name, path in attachment_paths(out).items():
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"--out {out}: its attachment {name} {path} exists; the final evaluation writes a "
                                  "new one (ATTACHMENT_RULE)")
        if path.resolve() == Path(replays).resolve():
            raise ValueError(f"--replays {replays} is the attachment {name} of --out {out} (ATTACHMENT_RULE)")
    results = Path(RESULTS).resolve()
    if results == Path(replays).resolve() or results in Path(replays).resolve().parents:
        raise ValueError(f"--replays {replays} lies in {results}: the replays stay outside the tracked results")
    if stage in RECORD_STAGES and results not in Path(out).resolve().parents:
        raise ValueError(f"--out {out}: the record of a run of stage {stage} lies in {results} (OUT_RULE); refused "
                         "before the seal is consumed")


def check_carriers(path, doc, protocol, mode):
    """BOOTS_RULE: in plan mode campaign the carrier boots of the index against analysis.interventions.boots, refused
    by name before the seal; nothing to compare in plan mode rehearsal (tcn/k2.py k2_values compares in campaign
    only)."""
    from tcn import zasahy
    if mode != "campaign":
        return
    boots = zasahy.protocol_keys(protocol)["boots"]
    groups = {role: sorted({r["group"] for r in doc["sessions"] if r.get("role") == role})
              for role in zasahy.CARRIER_ROLES}
    found = sum(len(mine) for mine in groups.values())
    if found != boots:
        raise ValueError(f"{path}: the carrier roles of the index hold {found} boots ("
                         + ", ".join(f"{role} {len(mine)}" for role, mine in groups.items())
                         + f"), analysis.interventions.boots is {boots}: K2 takes every boot of the plan (tcn/k2.py "
                         "k2_values), so the protocol and the index disagree; refused before the seal is consumed "
                         "(BOOTS_RULE)")


def seal_state(path):
    """The seal of the index on the ledger of this process before anything is computed (tcn.pecat stav, which
    consumes nothing): its state with the stage of the run (STAGE_RULE). A seal that spotrebuj would refuse is refused
    here by name, so that a refused run computes nothing (design B7c 5.4): a seal of a campaign consumed by an earlier
    final run, sessions of a campaign the ledger does not hold, sessions it holds for another session, plan or mode,
    and at stage final a ledger at HEAD without the seal; spotrebuj checks again when it consumes."""
    state = pecat.stav(path)
    if state["ready"]:
        return state
    why = []
    if state["mode"] == "campaign":
        for run in state["runs"]:
            if run["mode"] == "campaign":
                done = (f"final run {run['number']} of seal {run['identity']} opened "
                        f"{(run['opened'] or {}).get('date')} (out {run['out']}): a second final run is refused")
                why.append(f"its seal was consumed by the {done}" if run["identity"] == state["identity"] else
                           f"its sessions were in the {done} (the seal binds the sessions, tcn/pecat.py RUN_RULE)")
                break
        if state["missing"]:
            why.append("the ledger does not hold the archives of the sessions " + ", ".join(state["missing"])
                       + " (the campaign writes them, tcn/pecat.py zapis)")
    if state["mismatched"]:
        why.append("the ledger holds the archives of the sessions " + ", ".join(state["mismatched"])
                   + " for another session, plan or mode")
    if state["stage"] == "final" and state["seal_in_git"] is not True:
        why.append(f"at stage final the ledger at HEAD does not hold the seal (seal_in_git {state['seal_in_git']}, "
                   "SEAL_IN_GIT_RULE)")
    raise pecat.Zapecatene(f"{state['corpus']}: the seal of the corpus cannot be consumed on the ledger "
                           f"{state['ledger']} ({'; '.join(why)}); refused before anything is computed (tcn.pecat "
                           "stav, RUN_RULE)")


def gate(path, doc, stage):
    """GATE_RULE: the gate records of data/results for the stage of the run (scripts/gates.py require), against the
    protocol file of the index checked against its protocol_sha256; refused by name before the seal is consumed."""
    from scripts import gates
    named = doc.get("protocol")
    if type(named) is not str or not named:
        raise ValueError(f"{path}: the index names no protocol file (protocol; features/dataset.py): the gate records "
                         "are checked against it (GATE_RULE)")
    protocol_file = Path(named) if Path(named).is_absolute() else path.parent / named
    if not protocol_file.is_file() or _digest(protocol_file) != doc.get("protocol_sha256"):
        raise ValueError(f"the protocol file {protocol_file} of the index is not that of its protocol_sha256 "
                         f"{doc.get('protocol_sha256')}: the gate records are checked against the file of the index "
                         "(GATE_RULE)")
    required, results = GATES[stage], Path(RESULTS)
    try:
        gates.require(results, protocol_file, required)
    except ValueError as error:
        raise ValueError(f"the gate records do not admit a final run of stage {stage} ({required} needs every stage "
                         f"before it valid; scripts/gates.py require, {results}): {error}; refused before the seal is "
                         "consumed (GATE_RULE)") from None
    return {"stage": stage, "required": required, "results": str(results), "protocol": str(protocol_file),
            "protocol_sha256": doc["protocol_sha256"], "rule": GATE_RULE}


def index_campaign(doc, index=None):
    """CAMPAIGN_RULE: the campaign of a corpus index, which the index states nowhere itself: the campaign_id that the
    session.json of every session of the index names (scripts/collection.py run writes it), but of the sessions the
    index takes over from the campaign it continues (continues.taken_over_sessions, scripts/campaign.py
    continuation_note); a relative path of a session.json is read beside the index `index`. Refused by name when a
    session.json cannot be read or the sessions name no single campaign."""
    taken = set((doc.get("continues") or {}).get("taken_over_sessions") or [])
    named = set()
    for record in doc["sessions"]:
        if record.get("id") in taken:
            continue
        file = Path(record.get("session") or "")
        if not file.is_absolute() and index is not None:
            file = Path(index).parent / file
        try:
            meta = json.loads(file.read_text())
        except (OSError, ValueError) as error:
            raise ValueError(f"the session.json of session {record.get('id')} of the corpus index cannot be read "
                             f"({type(error).__name__}: {error}), so its campaign is not known "
                             "(CAMPAIGN_RULE)") from None
        named.add(meta.get("campaign_id") if type(meta) is dict else None)
    if len(named) != 1 or type(next(iter(named))) is not str:
        raise ValueError("the sessions of the corpus index name no single campaign (campaign_id of their session.json: "
                         + ", ".join(sorted(map(repr, named))) + "), so no campaign record is its own (CAMPAIGN_RULE)")
    return named.pop()


def campaign_record(path, doc, index=None):
    """CAMPAIGN_RULE: the record of the complete ending of the campaign of the corpus index `doc` (its file `index`,
    for the relative paths of its sessions), checked, and its rejected and replaced sessions by cause. Each condition
    is refused by name: the schema of the record of an ending, the ending complete, the campaign of the index, the
    accepted sessions of the record the sessions of the index, the counts."""
    path = Path(path).resolve()
    record = json.loads(path.read_text())
    values = record.get("values") if type(record) is dict else None
    schema = record.get("schema") if type(record) is dict else None
    if schema != ENDING_SCHEMA:
        raise ValueError(f"{path}: a record of schema {schema!r} is no record of the ending of a campaign "
                         f"({ENDING_SCHEMA}, scripts/campaign.py ENDING_RULE): it is not the record of a corpus "
                         "(CAMPAIGN_RULE)")
    if type(values) is not dict or not all(key in values for key in ("planned_sessions", "accepted_sessions",
                                                                       "rejected_sessions")):
        raise ValueError(f"{path}: the campaign record has values.planned_sessions, accepted_sessions and "
                         "rejected_sessions (package B9)")
    if values.get("ending") != "complete":
        raise ValueError(f"{path}: the record of the ending {values.get('ending')!r} of campaign "
                         f"{values.get('campaign')!r} is not the record of a corpus: only the record of the complete "
                         "ending is (CAMPAIGN_RULE)")
    campaign = index_campaign(doc, index)
    if values.get("campaign") != campaign:
        raise ValueError(f"{path}: the record of campaign {values.get('campaign')!r} is not the record of the corpus "
                         f"index of campaign {campaign!r} (CAMPAIGN_RULE)")
    rows = values.get("sessions")
    if type(rows) is not list or not all(type(row) is dict and type(row.get("session")) is str
                                         and type(row.get("state")) is str for row in rows):
        raise ValueError(f"{path}: the record has no values.sessions, a row {{session, state, ...}} per planned "
                         "session and attempt (scripts/campaign.py ENDING_RULE) (CAMPAIGN_RULE)")
    held = {row["session"] for row in rows if row["state"] == "accepted"}
    indexed = {r["id"] for r in doc["sessions"]}
    if held != indexed:
        raise ValueError(f"{path}: the accepted sessions of the record are not the sessions of the corpus index (only "
                         f"in the record: {', '.join(sorted(held - indexed)[:3]) or 'none'}; only in the index: "
                         f"{', '.join(sorted(indexed - held)[:3]) or 'none'}): it is not the record of this corpus "
                         "(CAMPAIGN_RULE)")
    planned, accepted, rejected = (values[key] for key in ("planned_sessions", "accepted_sessions",
                                                          "rejected_sessions"))
    if type(planned) is not int or type(accepted) is not int or type(rejected) is not list:
        raise ValueError(f"{path}: planned_sessions and accepted_sessions are integers and rejected_sessions a list")
    if accepted != len(doc["sessions"]):
        raise ValueError(f"{path}: the campaign record names {accepted} accepted sessions, the corpus index holds "
                         f"{len(doc['sessions'])}: it is not the record of this corpus")
    by_cause = {}
    for item in rejected:
        if not (type(item) is dict and type(item.get("session")) is str and item["session"]
                and type(item.get("cause")) is str and item["cause"]
                and (item.get("replacement") is None or type(item["replacement"]) is str and item["replacement"])):
            raise ValueError(f"{path}: a rejected session is {{session, cause, replacement or null}}")
        row = by_cause.setdefault(item["cause"], {"rejected": 0, "replaced": 0, "not_replaced": 0, "sessions": []})
        row["rejected"] += 1
        row["replaced" if item.get("replacement") else "not_replaced"] += 1
        row["sessions"].append({"session": item["session"], "replacement": item.get("replacement")})
    return {"record": str(path), "sha256": _digest(path), "planned_sessions": planned, "accepted_sessions": accepted,
            "rejected_sessions": len(rejected), "replaced_sessions": sum(r["replaced"] for r in by_cause.values()),
            "by_cause": dict(sorted(by_cause.items())), "rule": CAMPAIGN_RULE}


def bundles(paths, index_sha256, protocol, plan):
    """(M of every seed in the order of analysis.seeds, their records): production bundles of this corpus index and
    protocol, exactly one per seed of analysis.seeds, of one normalizer, window and the alarm rule of the protocol. A
    diagnostic bundle is refused by name before it is loaded."""
    from safeguard.bundle import load_bundle
    found = []
    for path in paths:
        path = Path(path).resolve()
        manifest = json.loads((path / "manifest.json").read_text())
        if type(manifest) is not dict or manifest.get("diagnostic") is not False:
            raise ValueError(f"bundle {path} is diagnostic (manifest diagnostic "
                             f"{manifest.get('diagnostic') if type(manifest) is dict else None!r}): the final "
                             "evaluation takes the production bundles of M at analysis.seeds only (design B7c 1.4)")
        bundle = load_bundle(path, allow_diagnostic=False)
        provenance = bundle.manifest.get("provenance") or {}
        if provenance.get("corpus_index_sha256") != index_sha256:
            raise ValueError(f"bundle {path} was trained on another corpus index (provenance corpus_index_sha256)")
        if provenance.get("protocol") != protocol:
            raise ValueError(f"bundle {path} was trained under another protocol than the corpus index states")
        found.append((path, bundle))
    models = [metody.MetodaM(bundle) for _, bundle in found]
    planned = list(plan["seeds"])
    seeds = [model.seed for model in models]
    if len(set(seeds)) != len(seeds) or sorted(seeds) != sorted(planned):
        raise ValueError(f"the bundles are of the seeds {seeds}; the final evaluation takes M at every seed of "
                         f"analysis.seeds {planned}, each once (SULAD: all five seeds on the test role in one run)")
    first = models[0]
    for (path, bundle), model in zip(found, models):
        if metody.fingerprint(bundle.normalizer) != metody.fingerprint(first.bundle.normalizer):
            raise ValueError(f"bundle {path} has another normalizer than bundle {found[0][0]}: every method sees "
                             "the windows of one normalizer of M")
        if bundle.contract != first.bundle.contract:
            raise ValueError(f"bundle {path} has another feature contract than bundle {found[0][0]}")
        if (bundle.k, bundle.n) != (plan["alarm_rule"]["k"], plan["alarm_rule"]["n"]):
            raise ValueError(f"bundle {path} alarms {bundle.k} of {bundle.n}, analysis.alarm_rule is "
                             f"{plan['alarm_rule']['k']} of {plan['alarm_rule']['n']}")
    order = {seed: i for i, seed in enumerate(planned)}
    pairs = sorted(zip(found, models), key=lambda pair: order[pair[1].seed])
    records = [{"seed": model.seed, "bundle": str(path), "manifest_sha256": _digest(path / "manifest.json"),
                "created_utc": bundle.manifest.get("created_utc"), "threshold": bundle.threshold, "k": bundle.k,
                "n": bundle.n, "selected_predictor_epoch": bundle.manifest["training"].get("selected_predictor_epoch"),
                "label": model.label} for (path, bundle), model in pairs]
    return [model for _, model in pairs], records


def tree(stage):
    """CLEAN_TREE_RULE."""
    from tcn.eval import _git_stav
    commit, changed = _git_stav()
    code = None if changed is None else sorted(path for path in changed if path.startswith(CODE))
    if stage == "final" and (commit is None or code is None or code):
        raise ValueError("the final evaluation of stage final needs git and a committed tree of code: "
                         + ("git is not available" if commit is None or code is None
                            else "changed " + ", ".join(code)))
    return {"commit": commit, "changed": changed, "changed_code": code, "rule": CLEAN_TREE_RULE}


def check_inputs(records):
    """Before anything is computed: every role of the evaluation holds a session (K1, K2 and the budget read all
    five), every session's events.json has the hash of the index, so has controls.json of role test_controls
    (features.dataset controls_of), and its traffic_intervals.jsonl exists (LOAD_RULE)."""
    from features.dataset import controls_of
    empty = [role for role in (*FIT_ROLES, *SEALED) if not any(r["role"] == role for r in records)]
    if empty:
        raise ValueError(f"the corpus index holds no session of role {empty[0]}: the final evaluation reads "
                         + ", ".join((*FIT_ROLES, *SEALED)))
    for record in records:
        if type(record.get("events")) is not str or type(record.get("events_sha256")) is not str:
            raise ValueError(f"the index record of session {record['id']} names no events with events_sha256 "
                             "(features/dataset.py build)")
        if _digest(record["events"]) != record["events_sha256"]:
            raise ValueError(f"events of session {record['id']} changed since the index")
        if record["role"] == CONTROL_ROLE:
            controls_of(record)
        traffic = Path(record["session"]).parent / "traffic_intervals.jsonl"
        if not traffic.is_file():
            raise ValueError(f"session {record['id']} has no {traffic.name}: {LOAD_RULE}")


# ------------------------------------------------------------------ sessions, windows and traffic


def _events(record):
    """The records of the session's events.json, its hash checked against the index (features/dataset.py build)."""
    if _digest(record["events"]) != record["events_sha256"]:
        raise ValueError(f"events of session {record['id']} changed since the index")
    doc = json.loads(Path(record["events"]).read_text())
    if type(doc) is not dict or type(doc.get("events")) is not list:
        raise ValueError(f"{record['events']}: no list events of records")
    return doc["events"]


def _load_archive(path):
    """features.archive.load: the one place where this command opens a feature archive (the replays open theirs in
    safeguard.runtime replay_archive)."""
    from features.archive import load
    return load(path)


def load_session(record, protocol, contract, *, sealed):
    """One session of the index, read as training reads a session (the archive by the hash of the index, its frames
    against the times of the index and the bundle's contract, its acceptance decided again, features/acceptance.py):
    {record, archive, frames, load, events, controls}. A session of a sealed role (sealed true, and only such a
    session) is read inside the run after tcn.pecat kontrola. The records of events.json and of the controls of
    controls.json with a kind (tcn.eval control_records; None outside test_controls) go as they are to tcn.metody
    traffic (CLEAN_RULE) and to the metrics."""
    from features.acceptance import require_accepted
    from features.dataset import controls_of
    from features.qualification import offered_load
    from safeguard.features import check_frame, frames_from_archive
    from tcn.eval import control_records
    if sealed != (record["role"] in SEALED):
        raise ValueError(f"session {record['id']} of role {record['role']}: a sealed session is read after "
                         "tcn.pecat kontrola, and only a sealed one")
    if sealed:
        pecat.kontrola(record["features"], purpose="tcn.finalne loads a sealed session")
    if _digest(record["features"]) != record["features_sha256"]:
        raise ValueError(f"feature archive of session {record['id']} changed since the index")
    archive = _load_archive(record["features"])
    frames = frames_from_archive(archive, record["id"])
    if not frames or frames[0].timestamp != record["start"] or frames[-1].timestamp != record["end"]:
        raise ValueError(f"the times of the archive of session {record['id']} differ from the index")
    audit = json.loads(Path(record["audit"]).read_text())["values"]
    require_accepted(archive, protocol, record["id"], record["role"], audit)
    if frames[0].layout != audit["layout"]:
        raise ValueError(f"the layout of the archive of session {record['id']} differs from its audit")
    for frame in frames:
        check_frame(frame, contract)
    load_of = offered_load(Path(record["session"]).parent / "traffic_intervals.jsonl",
                           [frame.timestamp for frame in frames], protocol["interval_s"])
    if type(load_of) is str:
        raise ValueError(f"session {record['id']}: {load_of}; {LOAD_RULE}")
    controls = control_records(controls_of(record)) if record["role"] == CONTROL_ROLE else None
    return {"record": record, "archive": archive, "frames": frames, "load": load_of, "events": _events(record),
            "controls": controls}


def window_set(role, sessions, model, protocol):
    """(the window set of the role under M's normalizer and window, its Traffic, the boot, scenario and position of
    every session) (tcn.metody Okna, traffic)."""
    okna = metody.Okna.from_sessions([(s["record"], s["frames"]) for s in sessions], model.bundle.normalizer,
                                     model.bundle.contract, role=role, interval_s=protocol["interval_s"],
                                     load={s["record"]["id"]: s["load"] for s in sessions})
    events = {s["record"]["id"]: s["events"] for s in sessions}
    controls = {s["record"]["id"]: s["controls"] for s in sessions} if role == CONTROL_ROLE else None
    traffic = metody.traffic(okna, events, protocol, controls=controls)
    meta = {s["record"]["id"]: {"boot": s["record"]["group"], "scenario": s["record"]["scenario"],
                                "position": s["record"]["position"]} for s in sessions}
    return okna, traffic, meta


# ------------------------------------------------------------------ 3: the controls and the replays


def control_outcomes(session, protocol, stage):
    """CONTROLS_RULE: the outcomes of every planned control of one session of test_controls, inside the run."""
    from scripts import controls
    out = []
    for item in session["controls"]:
        try:
            out.append(controls.outcomes(item, session["archive"], protocol, role=CONTROL_ROLE,
                                         archive=session["record"]["features"], final_evaluation=True, stage=stage))
        except ValueError as error:
            raise ValueError(f"the outcomes of the control {item.get('kind')} ({item.get('polarity')}) of session "
                             f"{session['record']['id']} cannot be computed: {error}; O4 counts every planned "
                             "occurrence (CONTROLS_RULE)") from None
    return out


def replay_sealed(sessions, models, root):
    """REPLAY_RULE and UNSCORED_RULE: every sealed session replayed by every seed of M (safeguard.cli
    replay_directory). Returns (directories {seed: {role: [directory]}}, records {session: {seed: replay record}},
    unscored {session: the unscored stretches of its replays})."""
    from safeguard.cli import replay_directory
    directories = {model.seed: {role: [] for role in SEALED} for model in models}
    records, unscored = {}, {}
    for session in sessions:
        record = session["record"]
        ident = record["id"]
        records[ident] = {}
        for model in models:
            directory = Path(root) / f"seed-{model.seed}" / ident
            status = replay_directory(model.bundle, record["features"], directory)
            if status["fatal"] or not status["ok"] or status["processed"] != len(session["frames"]):
                raise ValueError(f"the replay of session {ident} by seed {model.seed} is not complete (rows "
                                 f"{status['processed']} of {len(session['frames'])} frames, fatal {status['fatal']}, "
                                 f"ok {status['ok']}): every sealed session is replayed in full (REPLAY_RULE)")
            records[ident][str(model.seed)] = {
                "directory": str(directory), "rows": status["processed"], "alarm_events": status["alarm_events"],
                "seal": status["seal"], "files_sha256": {name: _digest(directory / name) for name in (
                    "configuration.json", "events.jsonl", "status.json")}}
            directories[model.seed][record["role"]].append(str(directory))
            found = {key: value for key, value in status["unscored"].items() if key != "rule"}
            if ident not in unscored:
                unscored[ident] = dict(found, role=record["role"])
            elif dict(found, role=record["role"]) != unscored[ident]:
                raise ValueError(f"the replays of session {ident} leave other rows unscored by seed {model.seed} than "
                                 f"by seed {models[0].seed}: one feature contract scores the same rows "
                                 "(UNSCORED_RULE)")
    return directories, records, unscored


# ------------------------------------------------------------------ 1: the methods


def _named(methods, entry, claim):
    """The method that an entry of analysis.<claim>.compare names: by its label when it names a variant (Z4:load),
    else by its name, one method (as tcn/k2.py)."""
    found = [m for m in methods if (m.label if ":" in entry else m.name) == entry]
    if len(found) != 1:
        raise ValueError(f"analysis.{claim}.compare names {entry}, of which {len(found)} methods are fitted")
    return found[0]


def fit_methods(fit, models, protocol, plan, budget, mode):
    """Z0 to Z5 and the descriptive methods fitted on train and dev under M's normalizer (Z1 selected by the share of
    the interventions inserted into dev it detects at its matched threshold at the budget, tcn/k2.py z1_criterion),
    each wrapped by _cache. Returns (methods, fit records, the plan of dev, the ranges of the validity predicate, the
    labels of the descriptive methods)."""
    from tcn import k2, opisne, zasahy
    train, dev, calibration = (fit[role][0] for role in FIT_ROLES)
    seed = plan["deploy_seed"]
    ranges = zasahy.train_ranges(train, protocol)
    carriers = {role: zasahy.Carriers(fit[role][0], fit[role][1], fit[role][2]) for role in ("train", "dev")}
    dev_plan = zasahy.plan(carriers["dev"], protocol=protocol, mode=mode, ranges=ranges,
                           donors={"train": carriers["train"]})
    criterion = k2.z1_criterion(dev_plan, calibration, fit["calibration"][1].clean, budget, protocol=protocol)
    methods = [metody.Z0(), metody.Z1(criterion), metody.Z2(), metody.Z3(),
               *(metody.Z4(variant) for variant in metody.Z4_VARIANTS), metody.Z5()]
    records = {}
    for method in methods:
        record = method.fit(train, dev, protocol=protocol, seed=seed)
        records[method.label] = record
    descriptive = set()
    for name, mine in opisne.runs(protocol):
        method = opisne.method(name)
        record = method.fit(train, dev, protocol=protocol, seed=mine)
        records[method.label] = record
        methods.append(method)
        descriptive.add(method.label)
    labels = [m.label for m in [*models, *methods]]
    if len(set(labels)) != len(labels):
        raise ValueError(f"two methods have one label: {labels}")
    return [_cache(m) for m in methods], records, dev_plan, ranges, descriptive


def rates_on(found, method, roles, *, k, n):
    """A matched rate of tcn.metody matched_rate over calibration alone (found, before the seal) with the rates of its
    threshold on the sealed roles (`roles`, {name: (window set, its Traffic)}) by tcn.metody rate, as matched_rate
    gives them for these roles (ORDER_RULE 3)."""
    rates = dict(found["rates"])
    for name, (windows, traffic) in roles.items():
        rates[name] = metody.rate(method.scores(windows), windows, found["threshold"], k=k, n=n, traffic=traffic)
    return dict(found, rates=rates)


# ------------------------------------------------------------------ 3: K1, K2 and their tables


def improvement(losses, against, boots, clean):
    """IMPROVEMENT_RULE: {boots: {boot: I}, mean} of `losses` against `against` (window arrays)."""
    values = {}
    for boot in sorted(set(boots)):
        selection = (boots == boot) & clean
        if not selection.any():
            continue
        z = float(np.mean(against[selection]))
        values[str(boot)] = 1 - float(np.mean(losses[selection])) / z if z > 0 else None
    found = [v for v in values.values() if v is not None]
    return {"boots": values, "mean": float(np.mean(found)) if found else None, "rule": IMPROVEMENT_RULE}


def loss_summary(losses, boots, clean):
    """The mean loss over the clean windows of test_benign and per boot."""
    return {"mean": float(np.mean(losses[clean])) if clean.any() else None,
            "boots": {str(b): float(np.mean(losses[(boots == b) & clean])) for b in sorted(set(boots))
                      if ((boots == b) & clean).any()}}


def k1_tables(model_losses, method_losses, keys, clean):
    """TABLE_RULE for K1: {grouping: {group: {windows, model_loss, per_seed_loss, methods {entry: {loss,
    improvement}}}}}."""
    out = {}
    for grouping, key in keys.items():
        rows = {}
        for value in sorted(set(key)):
            selection = (key == value) & clean
            if not selection.any():
                rows[str(value)] = {"windows": 0, "status": UNEVALUATED, "why": "no clean scored window"}
                continue
            per_seed = {str(seed): float(np.mean(losses[selection])) for seed, losses in model_losses.items()}
            model = float(np.median(list(per_seed.values())))
            methods = {}
            for entry, losses in method_losses.items():
                z = float(np.mean(losses[selection]))
                methods[entry] = {"loss": z, "improvement": 1 - model / z if z > 0 else None}
            rows[str(value)] = {"windows": int(selection.sum()), "status": EVALUATED, "model_loss": model,
                                "per_seed_loss": per_seed, "methods": methods}
        out[grouping] = rows
    return dict(out, rule=TABLE_RULE)


def k2_tables(values, plans, session_keys, boot_vm, seeds, model_labels):
    """TABLE_RULE for K2 from tcn.k2 k2_values: {grouping: {group: {planned, model_share, per_seed, methods {entry:
    {label, share, difference}}}}}; nevyhodnotené when no class is evaluated."""
    from tcn.k2 import CLAIMS
    if values["status"] == UNEVALUATED:
        return {"status": UNEVALUATED, "why": "no class of the interventions is evaluated (tcn/k2.py POOL_RULE)",
                "rule": TABLE_RULE}
    classes = values["pooled"]
    items = [item for plan in plans.values() for item in plan.interventions if item["class"] in classes]
    compare = {f"{claim}/{entry}": label for claim in CLAIMS for entry, label in values["compare"][claim].items()}
    detected = values["detected"]

    def key_of(item, grouping):
        if grouping == "boot":
            return item["boot"]
        if grouping == "vm":
            return boot_vm[item["boot"]]
        return session_keys[item["session"]]["profile"] if item.get("placed") else None

    out = {}
    for grouping in GROUPINGS:
        groups, unplaced = {}, 0
        for item in items:
            value = key_of(item, grouping)
            if value is None:
                unplaced += 1
                continue
            groups.setdefault(str(value), []).append(item)

        def share(mine, label):
            return sum(item["status"] == "evaluable" and bool(detected[label][item["id"]]) for item in mine) / len(mine)
        rows = {}
        for value, mine in sorted(groups.items()):
            per_seed = {str(seed): share(mine, label) for seed, label in zip(seeds, model_labels)}
            model = float(np.median(list(per_seed.values())))
            rows[value] = {"planned": len(mine), "evaluable": sum(i["status"] == "evaluable" for i in mine),
                           "model_share": model, "per_seed": per_seed,
                           "methods": {entry: {"label": label, "share": share(mine, label),
                                               "difference": model - share(mine, label)}
                                       for entry, label in compare.items()}}
        out[grouping] = dict(groups=rows, **({"not_placed": unplaced} if grouping == "profile" else {}))
    return dict(out, classes=list(classes), rule=TABLE_RULE)


def _by_label(mapping, labels, inside):
    return {label: value for label, value in mapping.items() if (label in labels) == inside}


def _volume_cell(cell, labels, inside):
    out = dict(cell, detected=_by_label(cell["detected"], labels, inside),
               shares=None if cell["shares"] is None else _by_label(cell["shares"], labels, inside))
    if "lengths" in cell:
        out["lengths"] = {length: _volume_cell(mine, labels, inside) for length, mine in cell["lengths"].items()}
    return out


def split_k2(values, descriptive):
    """CONFIRMATORY_RULE for the values of K2 (tcn.k2 k2_values over every method): (the confirmatory part, the
    descriptive part). The confirmatory part is the values as they are without the labels of the descriptive methods
    (`descriptive`); the descriptive part holds those labels' thresholds, detections and shares and their columns of
    the table by class and length and of the volume class. Every value of k2_values is per label or of the
    interventions, so the parting changes no number."""
    confirmatory = dict(values, thresholds=_by_label(values["thresholds"], descriptive, False),
                        detected=_by_label(values["detected"], descriptive, False),
                        table=[dict(row, shares=_by_label(row["shares"], descriptive, False)) if "shares" in row
                               else dict(row) for row in values["table"]],
                        volume={cls: _volume_cell(cell, descriptive, False) for cls, cell in values["volume"].items()})
    if "shares" in values:
        confirmatory["shares"] = _by_label(values["shares"], descriptive, False)
    rows = []
    for row in values["table"]:
        mine = {key: value for key, value in row.items() if key != "model_median"}
        if "shares" in row:
            mine["shares"] = _by_label(row["shares"], descriptive, True)
        rows.append(mine)
    part = {"labels": sorted(descriptive), "thresholds": _by_label(values["thresholds"], descriptive, True),
            "detected": _by_label(values["detected"], descriptive, True),
            "shares": _by_label(values["shares"], descriptive, True) if "shares" in values else None, "table": rows,
            "volume": {cls: _volume_cell(cell, descriptive, True) for cls, cell in values["volume"].items()},
            "rules": values["rules"]}
    return confirmatory, part


def wording_of(manifests, labels=None, *, before_seal=False):
    """RULE_CHANNEL_RULE: the one wording analysis_wording.rule_channel_only that the bundles of M carry (the manifests
    in the order of `labels`, the labels of M), a text with its ellipsis; else ValueError by name. It reads only the
    manifests, so the final command asks it in step 0 (ORDER_RULE, before_seal: the refusal says so), before the seal
    is consumed (finding N5 of the B7c confirmation, package B10), and rule_channel_only once more when it fills the
    text."""
    labels = [f"bundle {i + 1}" for i in range(len(manifests))] if labels is None else list(labels)
    wordings = [((m.get("analysis_wording") or {}).get("rule_channel_only")) if type(m) is dict else None
                for m in manifests]
    if not wordings:
        raise ValueError("no bundle of M carries the wording analysis_wording.rule_channel_only")
    first = wordings[0]
    other = [label for label, wording in zip(labels, wordings) if wording != first]
    if other or type(first) is not dict or "…" not in str(first.get("text")):
        verb = "carries" if len(other) == 1 else "carry"
        why = (f"{', '.join(other)} {verb} another one than {labels[0]}" if other else
               f"{labels[0]} carries none" if type(first) is not dict else "its text holds no ellipsis")
        raise ValueError("the bundles of M carry one wording analysis_wording.rule_channel_only with its ellipsis "
                         f"(safeguard/training.py RULE_CHANNEL_ONLY): {why}"
                         + ("; refused before the seal is consumed (RULE_CHANNEL_RULE)" if before_seal else ""))
    return first


def rule_channel_only(manifests, o4):
    """RULE_CHANNEL_RULE: the wording of the bundles (one text with its ellipsis, wording_of) filled with the median
    over the seeds of the increment of the neural channel over the rule channel in the total of the planned controls
    (o4: {seed: the O4 block of tcn.eval for test_controls}), the counts of every seed, and whether all detection is
    carried by the rule channel; the filled text only when it is, else text null with the reason why (finding N3 of
    the B7c confirmation)."""
    first = wording_of(manifests)
    per_seed = {}
    for seed, block in o4.items():
        computed = type(block) is dict and block.get("computed") is True
        per_seed[str(seed)] = (block["control"]["total"]["neural_over_rule"] if computed else
                               {"share": None, "status": UNEVALUATED, "why": "O4 is not computed"})
    shares = [item["share"] for item in per_seed.values()]
    value = None if not shares or any(x is None for x in shares) else float(np.median(shares))
    rule_detects = any(item.get("rule", 0) > 0 for item in per_seed.values())
    flag = None if value is None else (value == 0 and rule_detects)
    if flag is True:
        why = None
    elif flag is None:
        why = ("the increment of a seed is nevyhodnotené, so whether all detection is carried by the rule channel is "
               "not decided")
    elif value > 0:
        why = f"the neural channel adds detections over the rule channel (median increment {value:.4g})"
    else:
        why = "the rule channel detects no planned control, so it carries no detection"
    return {"text": first["text"].replace("…", f"{value:.4g}") if flag is True else None, "why": why,
            "wording": first, "increment": {"median": value, "per_seed": per_seed},
            "all_detection_by_rule_channel": flag, "rule": RULE_CHANNEL_RULE}


# ------------------------------------------------------------------ the diagnostics


def _variants():
    """The networks of the diagnostics fitted on train and dev at analysis.deploy_seed (SEED_RULE): the network with
    random weights, the partial models and the shuffled context (of M's network, Z3 and Z5)."""
    from tcn import diagnostiky as d
    return {"random weights": d.Siet("random"), "mem_* only": d.Siet("mem"), "global only": d.Siet("global"),
            "bins only": d.Siet("bins"), "shuffled context": d.Shuffled(d.Siet("retrained")),
            "shuffled context Z3": d.Shuffled(metody.Z3()), "shuffled context Z5": d.Shuffled(metody.Z5())}


def diagnostic_fits(fit, models, methods, protocol, plan, budget):
    """The diagnostics of proposal 8.5 (tcn/diagnostiky.py) that read only the roles without a seal (ORDER_RULE 1):
    the boot left out of calibration, the context truncation of Z3, Z5 and M fitted on train and dev, and the
    retrained networks fitted, each with its matched threshold on calibration."""
    from tcn import diagnostiky as d
    train, dev = fit["train"][0], fit["dev"][0]
    calibration, cal_traffic, cal_meta = fit["calibration"]
    k, n, seed = plan["alarm_rule"]["k"], plan["alarm_rule"]["n"], plan["deploy_seed"]
    cal_boots = {ident: meta["boot"] for ident, meta in cal_meta.items()}
    context = {name: d.context_truncation(make, train, dev, {}, protocol=protocol, seed=seed)
               for name, make in (("Z3", metody.Z3), ("Z5", metody.Z5), ("M", lambda: d.Siet("retrained")))}
    networks = {}
    for name, method in _variants().items():
        record = method.fit(train, dev, protocol=protocol, seed=seed)
        method = _cache(method)
        networks[name] = {"method": method, "fit": record,
                          "matched": metody.matched_rate(method, calibration, cal_traffic, budget, k=k, n=n, roles={})}
    return {"leave_one_boot_out": d.leave_one_boot_out(models, methods, calibration, cal_traffic, cal_boots,
                                                       protocol=protocol),
            "context": context, "networks": networks}


def diagnostic_values(prepared, sealed, protocol, plan, detection, roles):
    """The diagnostics of proposal 8.5 on the sealed roles, descriptive (ORDER_RULE 3): the threshold-likeness of Z1,
    Z2, Z3 and M on test_benign at their matched thresholds, the alarm rules, the threshold from clean traffic, the
    loss of the context truncation of Z3, Z5 and M over the clean windows of test_benign (tcn/diagnostiky.py
    CONTEXT_LOSS), and of every retrained network its loss, its improvement against the methods of
    analysis.k1.compare, its matched rate and the share of the interventions it detects."""
    from tcn import diagnostiky as d
    fit, models, methods, matched = prepared["fit"], prepared["models"], prepared["methods"], prepared["matched"]
    calibration, cal_traffic = fit["calibration"][0], fit["calibration"][1]
    tb, tb_traffic, tb_meta = sealed[EVENT_ROLE]
    k, n = plan["alarm_rule"]["k"], plan["alarm_rule"]["n"]
    tb_boots = {ident: meta["boot"] for ident, meta in tb_meta.items()}
    by_name = {m.name: m for m in methods if m.name in d.REFERENCE}
    thresholds = {label: found["threshold"] for label, found in matched.items()}
    entries = [(by_name[name], thresholds[by_name[name].label]) for name in d.REFERENCE]
    entries += [(m, thresholds[m.label]) for m in models]
    out = {"seed": plan["deploy_seed"], "seed_rule": SEED_RULE,
           "threshold_likeness": d.threshold_likeness(entries, tb, tb_boots, protocol=protocol),
           "alarm_rules": d.alarm_rules(models, methods, calibration, cal_traffic, protocol=protocol, roles=roles,
                                        detection=detection),
           "leave_one_boot_out": prepared["diagnostics"]["leave_one_boot_out"],
           "clean_threshold": d.clean_threshold(models, methods, calibration, cal_traffic, protocol=protocol,
                                                roles=roles, detection=detection)}
    boots = np.array([tb_meta[ident]["boot"] for ident in tb.session])
    clean = np.asarray(tb_traffic.clean, dtype=bool)
    against = {entry: m.losses(tb) for entry, m in prepared["compare"].items()}
    context = {}
    for name, (fitted, record) in prepared["diagnostics"]["context"].items():
        for row in record["contexts"]:
            losses = fitted[row["rows"]].losses(tb)
            row["loss"][EVENT_ROLE] = float(losses[clean].mean()) if clean.any() else None
            row["improvement"] = {entry: improvement(losses, z, boots, clean) for entry, z in against.items()}
        context[name] = record
    out["context"] = context
    rows = {}
    for name, item in prepared["diagnostics"]["networks"].items():
        method = item["method"]
        losses = method.losses(tb)
        found = rates_on(item["matched"], method, roles, k=k, n=n)
        rows[name] = {"label": method.label, "fit": item["fit"], "loss": loss_summary(losses, boots, clean),
                      "improvement": {entry: improvement(losses, z, boots, clean) for entry, z in against.items()},
                      "matched_rate": found, "detection": detection(method, found["threshold"], k, n)}
    out["models"] = rows
    return out


# ------------------------------------------------------------------ the attachments (package B11, ATTACHMENT_RULE)


def _text(values):
    """An array of fixed-width unicode text (no objects: ATTACHMENT_FORMAT)."""
    return np.array([str(value) for value in values], dtype=str)


class _Grid:
    """The rows of an attachment (ATTACHMENT_RULE): every row of every session of the window sets `sets`, in their
    order, by seq and time; rows(w) is the row of every window of the window set w (the first row of its session plus
    the position of its last row)."""

    def __init__(self, sets):
        self.sets, self.sessions, self._first = list(sets), [], {}
        seqs, times = [], []
        start = 0
        for windows in self.sets:
            for s in range(len(windows.session_ids)):
                arrays = windows.session_arrays(s)
                self._first[id(windows), s] = start
                self.sessions.append((windows, s))
                seqs.append(np.asarray(arrays["seq"], dtype=np.int64))
                times.append(np.asarray(arrays["timestamp"], dtype=np.float64))
                start += len(seqs[-1])
        self.lengths = np.array([len(seq) for seq in seqs], dtype=np.int64)
        self.starts = np.array([self._first[id(w), s] for w, s in self.sessions], dtype=np.int64)
        self.seq = np.concatenate(seqs) if seqs else np.zeros(0, dtype=np.int64)
        self.time = np.concatenate(times) if times else np.zeros(0, dtype=np.float64)
        self.owner = np.repeat(np.arange(len(seqs), dtype=np.int64), self.lengths)
        self.size = start

    def rows(self, windows):
        base = np.array([self._first[id(windows), s] for s in range(len(windows.session_ids))], dtype=np.int64)
        return base[windows.window_session] + windows.index[:, 1]


def _states(grid, labelled, thresholds, *, k, n):
    """The arrays of the labels `labelled` [(label, method)] on the window sets of `grid` at `thresholds` {label:
    threshold}: label, label_name, threshold, score (NaN where no window ends), exceed, up and edge (tcn.metody
    alarm_states)."""
    labels = [label for label, _ in labelled]
    score = np.full((len(labels), grid.size), np.nan)
    states = {key: np.zeros((len(labels), grid.size), dtype=bool) for key in ("exceed", "up", "edge")}
    for i, (label, method) in enumerate(labelled):
        for windows in grid.sets:
            rows, values = grid.rows(windows), method.scores(windows)
            found = metody.alarm_states(values, windows, thresholds[label], k=k, n=n)
            score[i, rows] = values
            for key, mask in states.items():
                mask[i, rows] = found[key]
    return {"label": _text(labels), "label_name": _text(method.name for _, method in labelled),
            "threshold": np.array([thresholds[label] for label in labels], dtype=np.float64), "score": score,
            **states}


def _session_table(grid, sealed, meta):
    """The sessions and the rows of the attachments series and losses (CONTENTS): meta {session id: {role, boot,
    vm, scenario, profile}}; the clean windows are those of the Traffic of each role (sealed)."""
    window, clean = np.zeros(grid.size, dtype=bool), np.zeros(grid.size, dtype=bool)
    for role in SEALED:
        windows, traffic = sealed[role][0], sealed[role][1]
        rows = grid.rows(windows)
        window[rows] = True
        clean[rows] = traffic.clean
    ids = [windows.session_ids[s] for windows, s in grid.sessions]

    def column(key):
        return _text("" if meta[ident][key] is None else meta[ident][key] for ident in ids)
    return {"session_id": _text(ids), "session_role": column("role"), "session_boot": column("boot"),
            "session_vm": column("vm"), "session_scenario": column("scenario"), "session_profile": column("profile"),
            "session_first_row": grid.starts.copy(), "session_rows": grid.lengths.copy(), "row_session": grid.owner,
            "row_seq": grid.seq, "row_time": grid.time, "row_window": window, "row_clean": clean}


def _replay_rows(grid, replays, models):
    """The rows of the replays of M (SERIES_RULE): the events.jsonl of every seed and session of `grid`, read after
    its sha256 is checked against the replay's record (replays {session: {seed: record}}, replay_sealed), one row per
    frame, each at the row of its seq."""
    from safeguard.runtime import CHANNELS, SOURCES
    flags = ("alarm", "alarm_event", "model_alarm", "rule_alarm", "integrity_alarm")
    score = np.full((len(models), grid.size), np.nan)
    marks = {key: np.zeros((len(models), grid.size), dtype=bool) for key in flags}
    channel = np.zeros((len(models), grid.size, len(CHANNELS)), dtype=bool)
    sources = np.zeros((len(models), grid.size, len(SOURCES)), dtype=bool)
    for j, model in enumerate(models):
        for i, (windows, s) in enumerate(grid.sessions):
            ident = windows.session_ids[s]
            item = replays[ident][str(model.seed)]
            path = Path(item["directory"]) / "events.jsonl"
            if _digest(path) != item["files_sha256"]["events.jsonl"]:
                raise ValueError(f"the events.jsonl of the replay of session {ident} by seed {model.seed} is not the "
                                 "one its replay wrote (files_sha256; SERIES_RULE)")
            rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            first, count = int(grid.starts[i]), int(grid.lengths[i])
            if [row.get("seq") for row in rows] != grid.seq[first:first + count].tolist():
                raise ValueError(f"the replay of session {ident} by seed {model.seed} has not one row per frame of the "
                                 "session in the order of seq (REPLAY_RULE, SERIES_RULE)")
            for r, row in enumerate(rows):
                at = first + r
                if row.get("score") is not None:
                    score[j, at] = float(row["score"])
                for key in flags:
                    marks[key][j, at] = row.get(key) is True
                channel[j, at] = [name in (row.get("channel") or ()) for name in CHANNELS]
                sources[j, at] = [name in (row.get("alarm_sources") or ()) for name in SOURCES]
    return {"replay_seed": np.array([model.seed for model in models], dtype=np.int64),
            "replay_threshold": np.array([model.threshold for model in models], dtype=np.float64),
            "replay_score": score, **{f"replay_{key}": mask for key, mask in marks.items()},
            "channels": _text(CHANNELS), "replay_channel": channel, "sources": _text(SOURCES),
            "replay_sources": sources}


def _occurrences(grid, occurrences):
    """Every event and control of the sessions of `grid` (SERIES_RULE): occurrences {session: {events, controls}},
    the records of its events.json and of the controls of its controls.json (None outside test_controls)."""
    found = []
    for i, (windows, s) in enumerate(grid.sessions):
        mine = occurrences[windows.session_ids[s]]
        found += [(i, "event", record) for record in mine["events"]]
        found += [(i, "control", record) for record in mine["controls"] or ()]

    def text(record, key):
        value = record.get(key) if type(record) is dict else None
        return "" if value is None else str(value)

    def time(record, key):
        value = record.get(key) if type(record) is dict else None
        return float(value) if type(value) in (int, float) and np.isfinite(value) else np.nan
    return {"occurrence_session": np.array([i for i, _, _ in found], dtype=np.int64),
            "occurrence_what": _text(what for _, what, _ in found),
            "occurrence_type": _text(text(record, "type" if what == "event" else "kind") for _, what, record in found),
            "occurrence_polarity": _text(text(record, "polarity") if what == "control" else ""
                                         for _, what, record in found),
            "occurrence_executed": np.array([type(record) is dict and record.get("executed") is True
                                             for _, _, record in found], dtype=bool),
            **{f"occurrence_{key}": np.array([time(record, key) for _, _, record in found], dtype=np.float64)
               for key in HOST_TIMES}}


def series_arrays(sealed, labelled, thresholds, replays, models, occurrences, meta, *, k, n):
    """SERIES_RULE: the arrays of the attachment series over the window sets of the sealed roles (sealed {role:
    (window set, Traffic, meta)}), every method and seed `labelled` [(label, method)] at its matched threshold
    (thresholds {label: threshold}), the replays of M (replay_sealed records) and the events and controls of every
    session."""
    grid = _Grid([sealed[role][0] for role in SEALED])
    return {**_session_table(grid, sealed, meta), **_states(grid, labelled, thresholds, k=k, n=n),
            **_replay_rows(grid, replays, models), **_occurrences(grid, occurrences)}


def losses_arrays(sealed, predictors, meta):
    """LOSSES_RULE: the arrays of the attachment losses of the predictors `predictors` over the window sets of the
    sealed roles."""
    grid = _Grid([sealed[role][0] for role in SEALED])
    loss = np.full((len(predictors), grid.size), np.nan)
    for i, method in enumerate(predictors):
        for windows in grid.sets:
            loss[i, grid.rows(windows)] = method.losses(windows)
    return {**_session_table(grid, sealed, meta), "label": _text(method.label for method in predictors),
            "label_name": _text(method.name for method in predictors), "loss": loss}


def copies_arrays(plans, labelled, thresholds, *, k, n):
    """COPIES_RULE: the arrays of the attachment copies of the plans of K2 (plans {role: tcn.zasahy plan}) for every
    method and seed of K2 `labelled` [(label, method)] at its matched threshold of K2 (thresholds {label:
    threshold})."""
    mine = [plans[role] for role in SEALED if plans[role].copies is not None]
    grid = _Grid([plan.copies for plan in mine])
    items = []
    for plan in mine:
        by_id = {item["id"]: item for item in plan.interventions}
        items += [by_id[ident] for ident in plan.copies.session_ids]
    block = np.zeros(grid.size, dtype=bool)
    for i, item in enumerate(items):
        first, count = int(grid.starts[i]), int(grid.lengths[i])
        seq = grid.seq[first:first + count]
        inside = (seq >= item["start"]["seq"]) & (seq < item["start"]["seq"] + item["length"])
        if int(inside.sum()) != item["length"]:
            raise ValueError(f"the copy of intervention {item['id']} does not hold its block of {item['length']} rows "
                             "of consecutive seq (COPIES_RULE)")
        block[first:first + count] = inside
    window, horizon = np.zeros(grid.size, dtype=bool), np.zeros(grid.size, dtype=bool)
    for plan in mine:
        rows = grid.rows(plan.copies)
        window[rows] = True
        for ident, windows in plan.horizons.items():
            horizon[rows[windows]] = True
    return {"intervention_id": _text(item["id"] for item in items),
            "intervention_role": _text(item["role"] for item in items),
            "intervention_class": _text(item["class"] for item in items),
            "intervention_length": np.array([item["length"] for item in items], dtype=np.int64),
            "intervention_variant": _text(item["order"] if item["class"] == "C" else item["group"] for item in items),
            "intervention_boot": _text(item["boot"] for item in items),
            "intervention_session": _text(item["session"] for item in items),
            "intervention_status": _text(item["status"] for item in items),
            "intervention_start_seq": np.array([item["start"]["seq"] for item in items], dtype=np.int64),
            "intervention_start_time": np.array([item["start"]["time"] for item in items], dtype=np.float64),
            "intervention_first_row": grid.starts.copy(), "intervention_rows": grid.lengths.copy(),
            "row_intervention": grid.owner, "row_seq": grid.seq, "row_time": grid.time, "row_block": block,
            "row_window": window, "row_horizon": horizon, **_states(grid, labelled, thresholds, k=k, n=n)}


def write_attachments(out, attached, written):
    """ATTACHMENT_RULE: every attachment of `attached` {name: its arrays, exactly the arrays of CONTENTS[name]} into
    its new file beside the record `out` (attachment_paths; created, never overwritten), each path appended to
    `written` as soon as it exists (a failure removes them, FAILURE_RULE); returns values.attachments {name: {path,
    sha256, bytes, format, contents, rule}}."""
    found = {}
    for name, path in attachment_paths(out).items():
        arrays = attached[name]
        if set(arrays) != set(CONTENTS[name]) or any(np.asarray(a).dtype.kind == "O" for a in arrays.values()):
            raise ValueError(f"the attachment {name} holds exactly the arrays of its contents, none of objects "
                             "(ATTACHMENT_FORMAT)")
        with path.open("xb") as stream:
            written.append(path)
            np.savez_compressed(stream, **{key: arrays[key] for key in CONTENTS[name]})
        found[name] = {"path": str(path.resolve()), "sha256": _digest(path), "bytes": path.stat().st_size,
                       "format": ATTACHMENT_FORMAT, "contents": CONTENTS[name], "rule": ATTACHMENT_RULES[name]}
    return found


def _remove(paths):
    """The attachments a failed run wrote (FAILURE_RULE); an error here leaves the run's own error to report."""
    for path in paths:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass


def _with_attachments(values, attachments):
    """The values of a complete record with attachments after replays (ATTACHMENT_RULE: metadata beside them)."""
    out = {}
    for key, value in values.items():
        out[key] = value
        if key == "replays":
            out["attachments"] = attachments
    return out


# ------------------------------------------------------------------ the whole evaluation


def refusals(corpus, models, *, campaign, replays, out):
    """Step 0 (ORDER_RULE): every refusal that reads no data of a session, in this order; nothing is computed or
    consumed. Returns the context of the evaluation."""
    from safeguard.training import validate_index
    path, doc, protocol, mode = read_index(corpus)
    plan = analysis(protocol)
    check_carriers(path, doc, protocol, mode)
    state = seal_state(path)
    check_outputs(out, replays, state["stage"])
    gated = gate(path, doc, state["stage"])
    checked_tree = tree(state["stage"])
    kampan = campaign_record(campaign, doc, path)
    index_sha256 = _digest(path)
    ms, model_records = bundles(models, index_sha256, protocol, plan)
    wording_of([m.bundle.manifest for m in ms], [m.label for m in ms], before_seal=True)  # N5 of the B7c confirmation.
    _, _, records = validate_index(path, diagnostic=False)
    check_inputs(records)
    rehearsal = None if mode == "campaign" else {
        "plan_mode": mode, "name": pecat.plan_name(protocol, mode),
        "group_prefix": protocol["rehearsal"]["group_prefix"], "mark": pecat.REHEARSAL_MARK}
    final = {"schema": SCHEMA, "plan_mode": mode, "corpus_index": str(path), "corpus_index_sha256": index_sha256,
             "rehearsal": rehearsal}
    return {"path": path, "doc": doc, "protocol": protocol, "mode": mode, "plan": plan, "seal_state": state,
            "gate": gated, "campaign": kampan, "models": ms, "model_records": model_records, "records": records,
            "tree": checked_tree, "rehearsal": rehearsal, "final": final, "replays": Path(replays)}


def unsealed_part(ctx, progress):
    """Step 1 (ORDER_RULE, design B7c 5.4): everything that reads only the roles without a seal, before the seal is
    consumed; progress["step"] names the step under way."""
    from tcn import eval as ev
    protocol, mode, plan, records = ctx["protocol"], ctx["mode"], ctx["plan"], ctx["records"]
    contract, k, n = ctx["models"][0].bundle.contract, plan["alarm_rule"]["k"], plan["alarm_rule"]["n"]
    progress["step"] = "1: the sessions of the fit roles"
    sessions = {role: [load_session(r, protocol, contract, sealed=False) for r in records if r["role"] == role]
                for role in FIT_ROLES}
    fit = {role: window_set(role, mine, ctx["models"][0], protocol) for role, mine in sessions.items()}
    events = {role: {s["record"]["id"]: s["events"] for s in mine} for role, mine in sessions.items()}
    del sessions
    ms = [_cache(model) for model in ctx["models"]]
    calibration, cal_traffic = fit["calibration"][0], fit["calibration"][1]
    progress["step"] = "1: the budget from M's clean calibration traffic"
    budget = metody.model_budget(ms, calibration, cal_traffic, protocol=protocol)
    progress["step"] = "1: the fits of the methods"
    methods, fits, dev_plan, ranges, descriptive = fit_methods(fit, ms, protocol, plan, budget["budget"], mode)
    progress["step"] = "1: the matched thresholds on calibration"
    matched = {m.label: metody.matched_rate(m, calibration, cal_traffic, budget["budget"], k=k, n=n, roles={})
               for m in [*ms, *methods]}
    progress["step"] = "1: the summary of every training (tcn.eval training_summary)"
    compare = {entry: _named(methods, entry, "k1") for entry in plan["k1"]["compare"]}
    scenarios = {r["id"]: r["scenario"] for r in records}
    training = {str(m.seed): {role: ev.training_summary(
        fit[role][0], events[role], protocol, model=m, methods=compare,
        scenarios={ident: scenarios[ident] for ident in fit[role][0].session_ids}) for role in TRAINING_ROLES}
        for m in ms}
    progress["step"] = "1: the diagnostics of calibration and the retrained networks"
    diagnostics = diagnostic_fits(fit, ms, methods, protocol, plan, budget["budget"])
    return {"fit": fit, "models": ms, "budget": budget, "methods": methods, "fits": fits, "dev_plan": dev_plan,
            "ranges": ranges, "descriptive": descriptive, "matched": matched, "compare": compare,
            "training": training, "diagnostics": diagnostics}


def sealed_part(ctx, prepared, run, progress):
    """Step 3 (ORDER_RULE) inside the run `run` of tcn.pecat spotrebuj: (the values of the record, the arrays of its
    attachments {name: arrays}, ATTACHMENT_RULE). progress["step"] names the step under way (FAILURE_RULE)."""
    from safeguard.runtime import UNSCORED_RULE as STRETCH_RULE
    from tcn import eval as ev
    from tcn import k2, tvrdenia, zasahy
    path, protocol, mode, plan, records = ctx["path"], ctx["protocol"], ctx["mode"], ctx["plan"], ctx["records"]
    ms, methods, fit, budget = prepared["models"], prepared["methods"], prepared["fit"], prepared["budget"]
    contract, k, n = ms[0].bundle.contract, plan["alarm_rule"]["k"], plan["alarm_rule"]["n"]
    calibration, cal_traffic = fit["calibration"][0], fit["calibration"][1]
    progress["step"] = "3: the sealed sessions, each after tcn.pecat kontrola"
    sealed_sessions = [load_session(r, protocol, contract, sealed=True) for r in records if r["role"] in SEALED]
    progress["step"] = "3: the outcomes of the controls"
    outcomes = {s["record"]["id"]: control_outcomes(s, protocol, run.stage) for s in sealed_sessions
                if s["record"]["role"] == CONTROL_ROLE}
    progress["step"] = "3: the replays of every sealed session for every seed of M"
    directories, replay_records, unscored = replay_sealed(sealed_sessions, ms, ctx["replays"])
    sealed = {role: window_set(role, [s for s in sealed_sessions if s["record"]["role"] == role], ms[0], protocol)
              for role in SEALED}
    # The events and controls of every sealed session, for the attachment series (SERIES_RULE).
    occurrences = {s["record"]["id"]: {"events": s["events"], "controls": s["controls"]} for s in sealed_sessions}
    del sealed_sessions
    roles = {role: (sealed[role][0], sealed[role][1]) for role in SEALED}
    progress["step"] = "3: the matched rates on the sealed roles"
    matched = {m.label: rates_on(prepared["matched"][m.label], m, roles, k=k, n=n) for m in [*ms, *methods]}
    z0 = metody.z0_random(calibration, budget["budget"], protocol=protocol, mode=mode, k=k, n=n, traffic=cal_traffic,
                          roles=roles)
    progress["step"] = "3: K1"
    tb, tb_traffic, tb_meta = sealed[EVENT_ROLE]
    boots = np.array([tb_meta[ident]["boot"] for ident in tb.session])
    model_losses = {model.seed: model.losses(tb) for model in ms}
    method_losses = {entry: m.losses(tb) for entry, m in prepared["compare"].items()}
    claim_k1 = tvrdenia.k1(protocol, model_losses, method_losses, boots.tolist(), tb_traffic.clean, rezim=mode,
                           rola=EVENT_ROLE)
    progress["step"] = "3: the interventions and K2"
    carriers = {role: zasahy.Carriers(*sealed[role]) for role in SEALED}
    plans = {role: zasahy.plan(carriers[role], protocol=protocol, mode=mode, ranges=prepared["ranges"],
                               donors=carriers) for role in SEALED}
    values = k2.k2_values(protocol, plans, models={m.seed: m for m in ms}, methods=methods, calibration=calibration,
                          clean=cal_traffic.clean, budget=budget["budget"], mode=mode)
    claims_k2 = k2.k2(protocol, values, mode=mode)
    progress["step"] = "3: the diagnostics"
    detection = k2.detection(plans, protocol=protocol)
    diagnostics = diagnostic_values(dict(prepared, matched=matched), sealed, protocol, plan, detection, roles)
    progress["step"] = "3: the metrics of design 1.3 (tcn.eval)"
    levels = ev.metriky_protokolu(protocol)
    alfa = 1 - levels["alarm_rate_interval"]["level"]
    kampan = ctx["campaign"]["record"]
    metrics = {
        "alpha": alfa, "levels": levels, "rule": METRICS_RULE,
        "o2": {str(m.seed): ev.vyhodnot_far(str(path), EVENT_ROLE, directories[m.seed][EVENT_ROLE], alfa, False,
                                            kampan, final_evaluation=True)[0] for m in ms},
        "o3": {str(m.seed): ev.vyhodnot_udalosti(str(path), directories[m.seed][EVENT_ROLE], alfa, EVENT_ROLE,
                                                 final_evaluation=True)[0] for m in ms},
        "o4": {str(m.seed): ev.vyhodnot_far(str(path), CONTROL_ROLE, directories[m.seed][CONTROL_ROLE], alfa, False,
                                            kampan, final_evaluation=True, vysledky_kontrol=outcomes)[0] for m in ms},
        "controls": {"outcomes": outcomes, "rule": CONTROLS_RULE}}
    progress["step"] = "3: the tables by boot, VM and profile"
    session_keys = {r["id"]: {"boot": r["group"], "vm": r.get("vm"),
                              "profile": protocol["scenarios"][r["scenario"]]["profile"]} for r in records}
    keys = {grouping: np.array([session_keys[ident][grouping] for ident in tb.session], dtype=object)
            for grouping in GROUPINGS}
    boot_vm = {r["group"]: r.get("vm") for r in records}
    tables = {"k1": k1_tables(model_losses, method_losses, keys, tb_traffic.clean),
              "k2": k2_tables(values, plans, session_keys, boot_vm, [m.seed for m in ms], [m.label for m in ms])}
    predictors = [m for m in [*ms, *methods] if m.kind == "predictor"]
    losses = {m.label: dict(loss_summary(m.losses(tb), boots, tb_traffic.clean),
                            improvement={entry: improvement(m.losses(tb), z, boots, tb_traffic.clean)
                                         for entry, z in method_losses.items()}) for m in predictors}
    progress["step"] = "3: the arrays of the attachments (ATTACHMENT_RULE)"
    meta = {r["id"]: {"role": r["role"], "boot": r["group"], "vm": r.get("vm"), "scenario": r["scenario"],
                      "profile": protocol["scenarios"][r["scenario"]]["profile"]} for r in records}
    everyone = {m.label: m for m in [*ms, *methods]}
    attached = {
        "series": series_arrays(sealed, list(everyone.items()),
                                {label: found["threshold"] for label, found in matched.items()}, replay_records, ms,
                                occurrences, meta, k=k, n=n),
        "losses": losses_arrays(sealed, predictors, meta),
        "copies": copies_arrays(plans, [(label, everyone[label]) for label in values["thresholds"]],
                                {label: found["threshold"] for label, found in values["thresholds"].items()}, k=k, n=n)}
    progress["step"] = "4: the record"
    claims = {"k1": claim_k1, **claims_k2}
    descriptive = prepared["descriptive"]
    k2_confirmatory, k2_descriptive = split_k2(values, descriptive)
    wording = rule_channel_only([m.bundle.manifest for m in ms],
                                {seed: found["v5"]["o4"] for seed, found in metrics["o4"].items()})
    complete = {
        **_common(ctx, run), "status": "complete",
        "replays": {"directory": str(ctx["replays"].resolve()), "rule": REPLAY_RULE, "sessions": replay_records},
        "budget": budget, "methods": _by_label(prepared["fits"], descriptive, False),
        "matched": _by_label(matched, descriptive, False), "claims": claims,
        "conclusions": {claim: {"outcome": value.get("outcome"), "status": value.get("status", EVALUATED),
                                "wording": value.get("wording"), "conclusion": value.get("conclusion")}
                        for claim, value in claims.items()},
        "k2_values": k2_confirmatory,
        "interventions": {"dev": prepared["dev_plan"].record(), **{role: plans[role].record() for role in SEALED}},
        "rules": {"load": LOAD_RULE, "seed": SEED_RULE, "table": TABLE_RULE, "campaign": CAMPAIGN_RULE,
                  "improvement": IMPROVEMENT_RULE, "confirmatory": CONFIRMATORY_RULE, "boots": BOOTS_RULE,
                  "out": OUT_RULE, "attachments": ATTACHMENT_RULE},
        OPISNE: {
            "metrics": metrics, "diagnostics": diagnostics,
            "descriptive_methods": {"methods": _by_label(prepared["fits"], descriptive, True),
                                    "matched": _by_label(matched, descriptive, True), "k2_values": k2_descriptive},
            "losses": losses, "tables": tables, "training": dict(prepared["training"], rule=TRAINING_RULE),
            "unscored": {"sessions": unscored, "rule": UNSCORED_RULE, "stretch_rule": STRETCH_RULE},
            "z0_random": z0, "linkage": plan["linkage"], "rule_channel_only": wording},
    }
    return complete, attached


def _sealed_ids(records):
    return {role: [r["id"] for r in records if r["role"] == role] for role in SEALED}


def _common(ctx, run):
    """The part of the values a complete record and a failed one share: the stage and the mark of the run and its
    seal (tcn.pecat spotrebuj, STAGE_RULE)."""
    doc, records = ctx["doc"], ctx["records"]
    return {**ctx["final"], "stage": run.stage, "mark": run.mark, "order_rule": ORDER_RULE, "campaign": ctx["campaign"],
            "corpus": {"index": str(ctx["path"]), "sha256": ctx["final"]["corpus_index_sha256"],
                       "plan_mode": ctx["mode"], "allocation_rule": doc.get("allocation_rule"),
                       "sessions": len(records),
                       "sealed_sessions": {role: len(ids) for role, ids in _sealed_ids(records).items()},
                       "protocol_sha256": doc.get("protocol_sha256")},
            "seal": run.record(), "seal_note": SEAL_NOTE, "gate": ctx["gate"], "tree": ctx["tree"],
            "models": ctx["model_records"]}


def _record(ctx, run, values):
    """The record of data/results with its provenance fields (scripts/check_claims.sh check E)."""
    from tcn.eval import _git_stav
    commit, changed = _git_stav()
    environment = ctx["models"][0].bundle.manifest["environment"]
    return {"schema": SCHEMA, "stage": run.stage, "mark": run.mark, "rehearsal": ctx["rehearsal"], "commit": commit,
            "commit_dirty": None if changed is None else bool(changed),
            "evaluator_sha256": _digest(Path(__file__).resolve()),
            "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
            "guest": "jadro %s, stack_sha256 %s" % (environment["kernel"], environment["stack_sha256"]),
            "command": ctx["command"], "cwd": os.getcwd(),
            "n": sum(len(ids) for ids in _sealed_ids(ctx["records"]).values()), "values": values}


def _write_record(out, record):
    with Path(out).open("x", encoding="utf-8") as stream:
        stream.write(_dumps(record, indent=1) + "\n")


def evaluate(corpus, models, *, campaign, replays, out, ledger=None, argv=()):
    """The final evaluation (module docstring, ORDER_RULE): writes the record `out` and the replays under `replays`;
    returns the record. ledger: None for the ledger of this process (tcn.pecat KNIHA: the ledger of record unless
    vlastna_kniha switched it), else a ledger the guards then read for the whole run (tcn.pecat vlastna_kniha: a G1
    dry run or a test, stage suchy). A failure before the seal is consumed writes nothing; one after it writes the
    record of FAILURE_RULE, closes the run failed and raises again. The attachments (ATTACHMENT_RULE) are written
    beside the record just before it; a run that fails removes those it wrote, so its record names none."""
    if ledger is not None and Path(ledger).resolve() != Path(pecat.KNIHA).resolve():
        switched = pecat.vlastna_kniha(ledger)
    else:
        switched = nullcontext()
    with switched:
        ctx = refusals(corpus, models, campaign=campaign, replays=replays, out=out)
        ctx["command"] = (shlex.join(["python3", "-m", "tcn.finalne", *map(str, argv)]) if argv else
                          f"tcn.finalne.evaluate(corpus={ctx['path']}, out={Path(out).resolve()})")
        progress = {"step": "1: before the seal"}
        prepared = unsealed_part(ctx, progress)
        progress["step"] = "2: the seal"
        run = pecat.spotrebuj(ctx["path"], out=out, command=ctx["command"])
        with run:
            written = []
            try:
                values, attached = sealed_part(ctx, prepared, run, progress)
                progress["step"] = "4: the attachments"
                values = _with_attachments(values, write_attachments(out, attached, written))
            except BaseException as error:
                _remove(written)
                failed = dict(_common(ctx, run), status="failed", failed_step=progress["step"],
                              error=f"{type(error).__name__}: {error}", rule=FAILURE_RULE,
                              replays={"directory": str(ctx["replays"].resolve()), "rule": REPLAY_RULE},
                              **{OPISNE: {}})
                _write_record(out, _record(ctx, run, failed))
                raise
            record = _record(ctx, run, values)
            try:
                _write_record(out, record)
            except BaseException:
                _remove(written)  # No attachment lies beside no record (ATTACHMENT_RULE).
                raise
    return record


# ------------------------------------------------------------------ the command


def _hlavny(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="python3 -m tcn.finalne", description=__doc__.split("\n")[0])
    p.add_argument("--corpus", required=True, type=Path, help="the corpus index (features/dataset.py build)")
    p.add_argument("--models", required=True, nargs="+", type=Path,
                   help="the bundles of M, one for every seed of analysis.seeds (safeguard train)")
    p.add_argument("--campaign", required=True, type=Path, help="the record of the campaign (package B9)")
    p.add_argument("--replays", required=True, type=Path, help="a new directory for the replays")
    p.add_argument("--out", required=True, type=Path, help="the new record; an existing one is never overwritten")
    p.add_argument("--threads", type=int, default=4, help="CPU threads for PyTorch (default: 4, as safeguard train)")
    a = p.parse_args(argv)
    if a.threads < 1:
        p.error("--threads must be positive")
    import torch
    torch.set_num_threads(a.threads)
    try:
        record = evaluate(a.corpus, a.models, campaign=a.campaign, replays=a.replays, out=a.out, argv=argv)
    except (OSError, ValueError, KeyError) as error:
        print(f"tcn.finalne: {error}", file=sys.stderr)
        return 2
    values = record["values"]
    print(_dumps({"record": str(a.out), "stage": values["stage"], "mark": values["mark"]["mark"],
                  "plan_mode": values["plan_mode"], "sessions": record["n"],
                  "claims": {claim: c["outcome"] or c["status"] for claim, c in values["conclusions"].items()}},
                 indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(_hlavny())
