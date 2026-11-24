"""The probes of the code audit as a table of tests (protocol v5, package B10, agent A).

Binding texts: the lead's skeleton dokazy/B10/kostra/KOSTRA.md (sections 1.1 to 1.4, 2 and 6) and the executor's design
dokazy/B10/navrh/NAVRH_B10.md (section 1, decisions 1 to 5). The record is RECORD (schema hyptcn3/code-audit/1): six
areas of twelve risks, each with the auditor's evidence and, for 68 of them, a second reader's verdict with evidence of
its own. Nothing in the record marks a probe, so CLASSES reads the evidence.

CLASSES gives each of the 72 risk ids of the record a class, the reader whose evidence it rests on (A the auditor's
evidence; V the verifier's evidence or corrected statement) and a phrase of that text, verbatim:
    P  a probe of the code: a synthetic input given to the real code, and its outcome (accepted, refused, passed);
    D  a run of code that measured a property of the design (a synthetic training or scoring), no outcome of a check;
    C  code run only to compute over stored records, the plan or the existing tests; the record names the code (a
       script, plan(), pytest, a function of the repository);
    N  no run of code: code and records read, arithmetic, and a recomputation the record does not attribute to code.
The classes are those of the code map (dokazy/B10/navrh/MAPA_KODU.md section 1), applied by its definitions; one
reading differs from the map's table: features GF-8 is C, since its only run is collection.plan over the protocol file
(the group names it plans), while the refusal of training is read in the code (the map has P).

ROWS holds the table (skeleton 1.1): one row per risk of class P and one per row of the skeleton's section 2
(SKELETON), 18 rows. A row names:
    number   1 to 15 are the rows of SKELETON in its order, 16 to 18 the risks of class P that SKELETON leaves out;
    risks    (area, risk id) of the record;
    probe    what the probe found (SKELETON's column "Sonda", and the record's own probe where it ran one);
    tests    pytest node ids that repeat the probe on today's code; each passes today (test_audit_probes.py) and fails
             on the commit `before` (the records dokazy/B10/pred_po/ of agent A's tree and dokazy/B10/pred_po_zlucene/
             of the merged tree, design decision 5);
    fixed    (package, commit) of each package that fixed it, the oldest first; beside the skeleton's packages a
             later fix inside B10 is (LATER, commit, item), whose commit's subject names package B10 and the item it
             fixes (the deferred item or the lead's answer; the verification of B10, F2);
    before   the parent of the oldest commit of `fixed` (skeleton 6: of two packages the older);
    kind     refusal, or limit (row 9, a bound of a unit file) or status (row 11, the status nevyhodnotené): design
             decision 3;
    reasons  (text, "path:line"): the exact text the code or the configuration states, verbatim on that line of the
             file (placeholders of an f-string as written; a message over several lines by the part on its first
             line), for the probe's input;
    open     what of the risk today's code still leaves open, with its basis, as sentences (empty: nothing of the
             record's probe or of the skeleton's row).
A risk of class P sits in exactly one row, and so does every risk SKELETON names.

The test of the table is scripts/tests/test_audit_probes.py. The test ids and the line numbers are facts of the tree at
the merge of B10: agent A wrote them at base 966ff9b; the merge moved the lines that agent C's and agent Q's commits
shift, added agent D's tests of the numeric cap to row 4, and gave row 5 agent Q's test and reason of the
collector's major faults (Q29); the fix round names those two fixes of B10 in `fixed` of rows 4 and 5. A merge that
moves a line or renames a test changes this table with it.
Only a table: no number here is a measurement.
"""
from collections import namedtuple

RECORD = "data/results/audit_kodu_v5_20261120.json"
KINDS = ("refusal", "limit", "status")
CLASS_NAMES = {"P": "probe of the code", "D": "run of code measuring the design", "C": "code over stored data",
               "N": "no run of code"}
READERS = {"A": "the auditor's evidence", "V": "the verifier's evidence or corrected statement"}

# (area, id): (class, reader, phrase of that reader's text in RECORD).
CLASSES = {
    ("capture", "R1"): ("N", "V", "delays recomputed over 15 data/results/*_audit.json and *_reaudit.json records"),
    ("capture", "R2"): ("N", "V", "vmicollect/src/sched.c:84-93"),
    ("capture", "R3"): ("P", "V", "scratchpad probe of collection.audit_session built on "
                                  "scripts/tests/test_collection_logs.py:360-389 (accepted, 10 prev rows)"),
    ("capture", "R4"): ("P", "V", "Probes accepted a swap storm, a monitor file without any process or memory data, "
                                  "and 500 collector major faults per cycle"),
    ("capture", "R5"): ("P", "V", "a probe with lateness 4.0 s in every sidecar was accepted"),
    ("capture", "R6"): ("P", "V", "scratchpad probe of audit_logs with two WARN lines (accepted)"),
    ("capture", "R7"): ("P", "V", "a probe was accepted with executed=0"),
    ("capture", "R8"): ("P", "V", "My probe confirmed that the untested 'timestamp gap' gate fires"),
    ("capture", "R9"): ("N", "V", "config/collection-v5.json events.pilot, events.classes"),
    ("capture", "R10"): ("C", "V", "scripts/tests/test_protocol_v5.py:36-44,60-67 (6 passed)"),
    ("capture", "R11"): ("P", "A", "probe: sidecars without capture.queue_wait_ms were accepted"),
    ("capture", "R12"): ("N", "V", "data/results/collection_pilot_7_20261026_timing.json values.full_snapshots"),
    ("features", "GF-1"): ("N", "V", "(recomputed locally)"),
    ("features", "GF-2"): ("D", "V", "150 training steps of safeguard.model.Predictor on synthetic windows"),
    ("features", "GF-3"): ("N", "V", "data/results/collection_campaign_benign_v6_20261026.json values.summary.by_group"),
    ("features", "GF-4"): ("N", "V", "guestparse/view.py:463-465, 471-477, 488-504, 553-563"),
    ("features", "GF-5"): ("N", "V", "guestparse/view.py:777-800"),
    ("features", "GF-6"): ("N", "V", "data/results/collection_worker_resonance_20261120.json values.lock_event"),
    ("features", "GF-7"): ("N", "V", "vmicollect/src/sched.c:82-93"),
    ("features", "GF-8"): ("C", "V", "local run of collection.plan: groups 'v5-train-1' versus expected 'train-1'"),
    ("features", "GF-9"): ("N", "V", "listing and grep of data/results"),
    ("features", "GF-10"): ("N", "V", "grep of data/results/*.json found no correlation or per-column error record"),
    ("features", "GF-11"): ("N", "A", "features/snapshot.py:385-388"),
    ("features", "GF-12"): ("N", "V", "grep of global_scale over data/results/*.json"),
    ("model", "M1"): ("D", "V", "(real tcn.model.TCNPrediktor, 20 features, window 32; not a measurement)"),
    ("model", "M2"): ("D", "A", "synthetic check: window-mean 0.236 versus TCN 0.209 versus mean 0.946"),
    ("model", "M3"): ("N", "V", "safeguard/training.py:237, 246-249"),
    ("model", "M4"): ("P", "A", "both failures reproduced on scratch corpora"),
    ("model", "M5"): ("N", "V", "tcn/eval.py:384, 396, 462, 699, 1220-1237"),
    ("model", "M6"): ("D", "A", "synthetic check: +1 in a train-constant column moved the zscore score"),
    ("model", "M7"): ("D", "A", "synthetic check: +1 proc_wx changed the TCN score by 0.027"),
    ("model", "M8"): ("N", "V", "config/collection-v5.json:25, 89-111"),
    ("model", "M9"): ("N", "V", "safeguard/cli.py:20-25, 72-75"),
    ("model", "M10"): ("N", "V", "safeguard/model.py:60-63, 91-92"),
    ("model", "M11"): ("D", "V", "re-run of scratchpad/exp4_run.py against the scratchpad/exp1 bundle"),
    ("model", "M12"): ("N", "V", "config/collection-v5.json:29-34"),
    ("evaluation", "R1"): ("N", "V", "safeguard/training.py:237, 295-297, 343-349"),
    ("evaluation", "R2"): ("P", "V", "output: first final 0, same path blocked, copy 0, direct call final True"),
    ("evaluation", "R3"): ("N", "V", "tcn/porovnanie.py:45-51, 589-623 (only fit and replay commands)"),
    ("evaluation", "R4"): ("N", "V", "my grep for a last-value, persistence or naive predictor"),
    ("evaluation", "R5"): ("N", "V", "tcn/eval.py:198-206, 216-221, 477-478, 542"),
    ("evaluation", "R6"): ("N", "V", "Poisson and Clopper-Pearson recomputation mine (scipy)"),
    ("evaluation", "R7"): ("N", "V", "session start derived by me"),
    ("evaluation", "R8"): ("N", "V", "my grep for Holm, Bonferroni, primary and pre-registration terms"),
    ("evaluation", "R9"): ("N", "V", "safeguard/training.py:159-161; PLAN_multivm_dataset.md:69-70"),
    ("evaluation", "R10"): ("N", "V", "listing of data/results (mine)"),
    ("evaluation", "R11"): ("N", "V", "per-type counts recomputed by me"),
    ("evaluation", "R12"): ("N", "V", "safeguard/training.py:263-265, 336-338, 369-374"),
    ("lab", "LAB-01"): ("C", "V", "against plan() of config/collection-v4.json"),
    ("lab", "LAB-02"): ("C", "V", "gaps computed by script"),
    ("lab", "LAB-03"): ("N", "V", "scripts/collection.py:470-486"),
    ("lab", "LAB-04"): ("C", "V", "window share computed with plan() on config/collection-v5.json"),
    ("lab", "LAB-05"): ("N", "V", "lab/services.py:220-233"),
    ("lab", "LAB-06"): ("N", "V", "scripts/host_traffic.py:239-240,410-442"),
    ("lab", "LAB-07"): ("N", "V", "scripts/labctl.py:98-100,149-152"),
    ("lab", "LAB-08"): ("C", "V", "plan() on config/collection-v5.json (counts by role, type and scenario computed)"),
    ("lab", "LAB-09"): ("N", "V", "scripts/collection.py:290-299,805,842,1366"),
    ("lab", "LAB-10"): ("C", "V", "plan() on config/collection-v5.json (role order per VM and first zataz_pamate "
                                  "computed)"),
    ("lab", "LAB-11"): ("C", "A", "plan comparison v4 vs v5 by script"),
    ("lab", "LAB-12"): ("N", "V", "scripts/collection_logs.py:216-219,233-237"),
    ("process", "R1"): ("P", "A", "both reproduced on synthetic corpora (prefix 'v5-' rejected, one tolerated invalid "
                                  "row rejected)"),
    ("process", "R2"): ("N", "V", "own closed-form computation (negative binomial, Clopper-Pearson limits)"),
    ("process", "R3"): ("N", "V", "(own median)"),
    ("process", "R4"): ("N", "V", "data/results/collection_worker_resonance_20261120.json values.worker_restart "
                                  "(sessions 20, period_s_mean 6.25)"),
    ("process", "R5"): ("N", "V", "grep for 'swap' in scripts/collection_logs.py: no match"),
    ("process", "R6"): ("N", "V", "scripts/campaign.py:908-913, 926-950"),
    ("process", "R7"): ("C", "V", "own arithmetic with features.coverage.ideal_windows (536 for 600 cycles, 656 for "
                                  "720)"),
    ("process", "R8"): ("N", "V", "tcn/eval.py:373-375, 1226-1237, 1276-1286"),
    ("process", "R9"): ("N", "V", "grep for 2026-11-20 in docs/*.md and root *.md: no match"),
    ("process", "R10"): ("N", "V", "docs/STAV.sk.md:26, 39-41, 70-82, 215-216"),
    ("process", "R11"): ("P", "V", "own run of python3 -m safeguard smoke"),
    ("process", "R12"): ("N", "A", "docs/PRIPRAVENOST_KAMPANE.sk.md:130-136"),
}

# The lead's skeleton section 2: (risks, the packages of its column "Opravil"), in its order.
SKELETON = (
    ((("capture", "R5"),), ("B3",)),
    ((("capture", "R7"), ("lab", "LAB-04")), ("B3", "B5")),
    ((("capture", "R6"),), ("B3",)),
    ((("capture", "R3"),), ("B3",)),
    ((("capture", "R4"), ("process", "R5")), ("B3", "B5")),
    ((("capture", "R1"), ("lab", "LAB-01")), ("B4",)),
    ((("lab", "LAB-11"),), ("B4",)),
    ((("lab", "LAB-12"),), ("B5",)),
    ((("lab", "LAB-02"),), ("B5",)),
    ((("model", "M5"), ("evaluation", "R2"), ("process", "R8")), ("B7",)),
    ((("evaluation", "R7"),), ("B7",)),
    ((("model", "M9"), ("evaluation", "R8")), ("B6", "B7")),
    ((("process", "R1"), ("features", "GF-8"), ("model", "M4")), ("B1",)),
    ((("process", "R7"), ("capture", "R10")), ("B2", "B4")),
    ((("process", "R9"),), ("B9",)),
)

# Test ids recorded as gone (dokazy/B11/odlozene_B11.md, agent G): never a test of this table.
GONE = ("scripts/tests/test_early_stop_count.py::test_a_continuation_counts_only_its_own_sessions",)

Row = namedtuple("Row", "number risks probe tests fixed before kind reasons open")
# The package whose later fix may stand in `fixed` beside the skeleton's packages, with the item it fixes (the
# verification of B10, F2): B10 makes the deferred fixes of the closed packages (design B10 decision 6).
LATER = "B10"

SELFTEST = "scripts/tests/test_audit_selftest.py::"
CASE = SELFTEST + "test_bad_session_is_refused_with_exactly_its_reasons"
HANDOFF = "tcn/tests/test_odovzdanie_korpusu.py::"

ROWS = (
    Row(1, (("capture", "R5"),),
        "a session whose cycles started 4 s late was accepted (the verifier's probe: sched.lateness_s 4.0 s in every "
        "sidecar)",
        (CASE + "[lateness]",),
        (("B3", "0b3c276"),), "c39accb", "refusal",
        (("cycle start later than the audit bound", "scripts/collection.py:1923"),),
        ()),
    Row(2, (("capture", "R7"), ("lab", "LAB-04")),
        "an event that did not run or had no effect was accepted (the auditor's probe: an unexecuted event accepted "
        "with executed=0; LAB-04: the lock, the backup and the memory load return ok right after the start)",
        (CASE + "[logs:event_not_executed]", CASE + "[logs:event_without_effect]",
         "scripts/tests/test_effect_contract.py::test_event_record_without_a_true_ok_is_refused_for_exactly_that"
         "[ok_false]",
         "lab/tests/test_udalosti_effect.py::test_predicate_is_true_with_the_effect_and_false_without"
         "[zamok_tabulky-none-9]",
         "lab/tests/test_udalosti_effect.py::test_predicate_is_true_with_the_effect_and_false_without"
         "[udrzba_zaloha-none-11]",
         "lab/tests/test_udalosti_effect.py::test_predicate_is_true_with_the_effect_and_false_without"
         "[zataz_pamate-none-14]"),
        (("B3", "0b3c276"), ("B5a", "2a95852")), "c39accb", "refusal",
        (("event_not_executed", "scripts/collection_logs.py:608"),
         ("event_without_effect", "scripts/collection_logs.py:611")),
        ()),
    Row(3, (("capture", "R6"),),
        "a collector warning did not reject the session (the verifier's probe: two WARN lines accepted)",
        ("scripts/tests/test_collection_logs.py::test_collector_warning_is_judged_by_the_allowed_patterns[null]",
         CASE + "[logs:collector_warning_unlisted]"),
        (("B3", "0b3c276"),), "c39accb", "refusal",
        (("collector_warning_unlisted", "scripts/collection_logs.py:591"),),
        ()),
    Row(4, (("capture", "R3"),),
        "rows closed by a parser rule were accepted without a limit, a test with a numeric cap (the verifier's probe: "
        "10 rows closed by rule prev accepted)",
        (SELFTEST + "test_cap_of_rule_closed_rows_once_it_is_set[above]",
         SELFTEST + "test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[zero]",
         SELFTEST + "test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[three]",
         SELFTEST + "test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[four]",
         SELFTEST + "test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[every_row]"),
        (("B3", "0b3c276"), (LATER, "f0506e8", "B3 S1")), "c39accb", "refusal",
        (("rows closed by a parser rule above the cap", "features/acceptance.py:250"),),
        ("audit.rule_closed_rows_max is null in config/collection-v5.json until G3b (proposal 10.9), so under the G0 "
         "file the verifier's probe is still accepted: its rows are counted in exceptions.rule_closed_rows and are "
         "never a reason (scripts/tests/audit_cases.py UNREACHABLE); the cap refuses under a copy with an integer cap",)),
    Row(5, (("capture", "R4"), ("process", "R5")),
        "QEMU swap was no condition of the start (the probes: a swap storm in the monitor, a monitor file without "
        "process or memory data, and 500 collector major faults per cycle were accepted)",
        (CASE + "[logs:qemu_swap]", CASE + "[logs:qemu_swap:absent]", CASE + "[qemu_swap]", CASE + "[qemu_swapped]",
         SELFTEST + "test_run_session_refuses_qemu_swap_that_is_not_forbidden[max]",
         SELFTEST + "test_run_session_refuses_qemu_memory_that_was_swapped_before_start[8592]",
         "scripts/tests/test_collector_majflt.py::test_a_bound_refuses_one_cycle_above_it_and_accepts_a_cycle_at_it"
         "[zero]"),
        (("B3", "0b3c276"), ("B5a", "2a95852"), (LATER, "a446043", "Q29")), "c39accb", "refusal",
        (("QEMU swap was not disabled before start: memory.swap.max is ", "scripts/collection.py:1177"),
         ("QEMU memory was swapped before start: qemu_swap_kb is ", "scripts/collection.py:1181"),
         ("QEMU swap was not disabled before start", "scripts/collection.py:1857"),
         ("QEMU memory was swapped before start", "scripts/collection.py:1861"),
         ("qemu_swap", "scripts/collection_logs.py:561"),
         ("collector major faults per cycle above the audit bound", "scripts/collection.py:1951")),
        ("audit.collector_majflt_max is null in config/collection-v5.json until G2 (proposal 10.9, the lead's answer "
         "to Q29; the fix of B10, agent Q), so under the G0 file the probe of 500 collector major faults per cycle is "
         "still accepted: the audit records and prints the counts (values.collector_majflt) and they are never a "
         "reason (scripts/tests/audit_cases.py UNREACHABLE); the bound refuses under a copy with a numeric bound, and "
         "the self-test then builds the case collector_majflt_above_bound",)),
    Row(6, (("capture", "R1"), ("lab", "LAB-01")),
        "event starts on multiples of the capture interval (the record ran no probe: the verifier recomputed the "
        "phases over stored records)",
        ("scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error"
         "[locked_to_grid]",
         "scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error"
         "[phases_at_tenth_edges]"),
        (("B4", "9e7e43c"), ("B4b", "fd021b1")), "8ae9f39", "refusal",
        (("role {role}: {what} per tenth of the interval differ by more than 1", "scripts/protocol_v5.py:2189"),
         ("{what} phases fail the Kolmogorov-Smirnov test against the uniform law at ", "scripts/protocol_v5.py:2193")),
        ()),
    Row(7, (("lab", "LAB-11"),),
        "one seed for two purposes (the record ran no probe of the code: the auditor compared the plans of v4 and v5 "
        "by script)",
        ("scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error"
         "[common_seed]",),
        (("B4", "9e7e43c"),), "8ae9f39", "refusal",
        (("purposes {a} and {b} share a seed", "scripts/protocol_v5.py:2241"),),
        ()),
    Row(8, (("lab", "LAB-12"),),
        "the delivered load was not compared with the scenario (the record ran no probe)",
        ("scripts/tests/test_traffic_realism.py::test_a_log_that_breaks_one_requirement_is_refused_with_its_name"
         "[offered_load_differs_from_plan]",
         CASE + "[logs:offered_load_differs_from_plan]"),
        (("B5b", "e64e619"),), "11319ee", "refusal",
        (("offered_load_differs_from_plan", "scripts/collection_logs.py:733"),),
        ()),
    Row(9, (("lab", "LAB-02"),),
        "a loop of restarts without end (the record ran no probe of the code: the verifier computed the gaps by "
        "script over a stored record)",
        ("lab/tests/test_periods.py::test_entries_are_complete_and_process_creating_ones_are_bounded_or_random",
         "lab/tests/test_periods.py::test_bounds_and_random_delays_of_the_register_are_those_of_the_source"),
        (("B5a", "2a95852"),), "8bdc2ae", "limit",
        (("StartLimitIntervalSec=60", "lab/hyptcn-lab@.service:7"),
         ("StartLimitBurst=5", "lab/hyptcn-lab@.service:8")),
        ()),
    Row(10, (("model", "M5"), ("evaluation", "R2"), ("process", "R8")),
        "the mark of the one evaluation was bypassed by a copy of the index (the verifier's run: a second --final "
        "through a copy of the index passed, --final ran with modified files, vyhodnot_far(final=True) ran directly)",
        ("tcn/tests/test_pecat.py::test_a_second_final_run_is_refused[copy_of_the_index]",
         "tcn/tests/test_finalne.py::test_a_second_run_is_refused[copy_elsewhere]",
         "tcn/tests/test_finalne.py::test_a_refusal_before_the_seal_consumes_nothing[dirty_tree]",
         "tcn/tests/test_eval_v5.py::test_a_sealed_role_is_evaluated_by_the_final_command_or_in_a_rehearsal"
         "[campaign-False-False-sealed role test_benign]",
         "tcn/tests/test_pecat.py::test_replay_of_a_sealed_archive_is_refused[safeguard.runtime.replay_archive]"),
        (("B7c", "576aa4b"),), "062178d", "refusal",
        (("a second final run is refused: the seal of its sealed archives was consumed by the final run ",
          "tcn/pecat.py:1010"),
         ("the seal of the corpus cannot be consumed on the ledger ", "tcn/finalne.py:518"),
         ("the final evaluation of stage final needs git and a committed tree of code: ", "tcn/finalne.py:684"),
         ("sealed role {rola} (design B7c 1.1): only the final command evaluates it ", "tcn/eval.py:1795"),
         ("{purpose}: refused, {what} is sealed (sha256 {sha}; session {entry.get('session')} of role ",
          "tcn/pecat.py:688")),
        ("an index of protocol schema 1 or 2 keeps the mark beside the index (tcn/eval.py --final), so the record's "
         "copy of such an index still passes there; protocol v5 is schema 3, sealed by tcn/pecat.py",)),
    Row(11, (("evaluation", "R7"),),
        "unscored time counted as silence (the record ran no probe: the verifier read the stored E2 record)",
        ("tcn/tests/test_eval_v5.py::test_an_occurrence_is_evaluable_at_half_of_its_first_60_s_scored[7-False]",
         "tcn/tests/test_eval_v5.py::test_an_unscored_stretch_is_nevyhodnotene_in_the_output"),
        (("B7c", "576aa4b"),), "062178d", "status",
        (("nevyhodnotené", "tcn/eval.py:960"),),
        ()),
    Row(12, (("model", "M9"), ("evaluation", "R8")),
        "a parameter of the analysis overridden from the command line (the record ran no probe)",
        ("safeguard/tests/test_training.py::test_analysis_parameters_are_refused_by_name[fpr_outside_diagnostic]",
         HANDOFF + "test_parameter_analyzy_z_prikazoveho_riadka_iba_s_diagnostikou",
         "tcn/tests/test_porovnanie.py::test_fit_pod_schemou_3_odmietne_parameter_analyzy[fpr]"),
        (("B6b", "dea37ca"), ("B7c", "576aa4b")), "f99b924", "refusal",
        (("analysis parameter {name} is given ({value!r}) under protocol schema 3, whose ",
          "safeguard/training.py:313"),),
        ()),
    Row(13, (("process", "R1"), ("features", "GF-8"), ("model", "M4")),
        "the corpus of a campaign did not pass into training (the probes: the production check refused the groups of "
        "prefix v5-, and training refused one tolerated invalid row)",
        (HANDOFF + "test_ostra_kontrola_indexu_prijme_predponu_skupin",
         HANDOFF + "test_ostra_kontrola_indexu_odmietne_skupinu_bez_predpony",
         HANDOFF + "test_trening_prijme_tolerovany_riadok",
         HANDOFF + "test_kazda_metoda_prijme_tolerovany_riadok",
         HANDOFF + "test_prehratie_s_tolerovanym_riadkom_konci_nulou",
         HANDOFF + "test_trening_a_metody_odmietnu_riadok_mimo_pravidla[nad_pocet-prva-train]"),
        (("B1", "a41973e"),), "48e198c", "refusal",
        (("incomplete planned allocation: session {named(record)} holds no row of {rule}", "safeguard/training.py:234"),
         ("more invalid rows than the protocol tolerates", "features/acceptance.py:380")),
        ()),
    Row(14, (("process", "R7"), ("capture", "R10")),
        "the coverage gate was unreachable at the number of invalid rows the rule allows (the record ran no probe of "
        "the code: the verifier's arithmetic with features.coverage.ideal_windows; the audit accepted a pilot with "
        "tolerated rows that pilot_gate refused)",
        ("scripts/tests/test_pilot_gate.py::test_pilot_cell_audit_decision[V4-one_row]",
         "scripts/tests/test_pilot_gate.py::test_pilot_gate_follows_the_audit[V4-one_row-honest]",
         "scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error"
         "[gate_085]"),
        (("B2", "7a459eb"), ("B4", "9e7e43c")), "432dd2e", "refusal",
        (("incomplete model inputs under ", "features/acceptance.py:245"),
         ("pilot is not accepted for this protocol: ", "scripts/campaign.py:654"),
         ("invalid_rows.max is unreachable under the score coverage gate", "scripts/collection.py:195"),
         ("score coverage gate outside the interval bound to invalid_rows.max", "scripts/protocol_v5.py:1877")),
        ()),
    Row(15, (("process", "R9"),),
        "a failed campaign left no record (the record ran no probe)",
        ("scripts/tests/test_campaign_v5.py::test_finish_corpus_without_the_record_of_the_complete_ending_fails",
         "scripts/tests/test_campaign_endings.py::test_the_record_of_a_closing_ending_carries_the_entry_of_the_"
         "measurement_log",
         "scripts/tests/test_campaign_endings.py::test_a_hash_that_changes_during_a_run_makes_the_campaign_invalid"
         "[measurement]"),
        (("B9b", "f700204"),), "bae0ee8", "refusal",
        (("the record of the complete ending of campaign {name} is missing (its last ending: {last}): ",
          "scripts/campaign.py:2512"),
         ("campaign {name} is invalid: an invalid campaign has no corpus (scripts/campaign.py ",
          "scripts/campaign.py:2506")),
        ()),
    Row(16, (("capture", "R8"),),
        "most gates of the acceptance were proven by no test (the verifier's probe: the untested gate of the timestamp "
        "gap fires; the risk is the missing test of each gate)",
        (SELFTEST + "test_every_reason_of_the_audit_and_the_verdict_has_a_case",
         "scripts/tests/test_audit_cases_logs.py::test_cases_cover_every_problem_key_of_the_log_audit",
         SELFTEST + "test_require_selftest_refuses_without_a_valid_record[absent]",
         CASE + "[timestamp_gap]"),
        (("B3", "0b3c276"),), "c39accb", "refusal",
        (("no valid audit self-test record for the current code and protocol", "scripts/audit_selftest.py:40"),
         ("timestamp gap", "features/acceptance.py:239")),
        ()),
    Row(17, (("capture", "R11"),),
        "sidecars without capture.queue_wait_ms were accepted (the auditor's probe; the record has no verdict on "
        "capture R11)",
        (CASE + "[missing_key:frame3.json:capture.queue_wait_ms]",),
        (("B3", "0b3c276"),), "c39accb", "refusal",
        (("missing key: {name}:{path}", "scripts/collection.py:1736"),),
        ("the collector still writes no effective interval, jitter, full_every or build into its sidecars, which "
         "capture R11's control asked for; docs/NAVRH_PROTOKOL_V5_SLEDOVATELNOST.sk.md marks R11 partly done "
         "(a change of the collector binary)",)),
    Row(18, (("process", "R11"),),
        "the tooling of a dry run passed without the hard paths (the verifier's run of python3 -m safeguard smoke: ok "
        "on a diagnostic corpus, the production check of the allocation never ran; the campaign fixtures replaced "
        "finish_corpus)",
        ("scripts/tests/test_campaign.py::test_finish_corpus_keeps_the_error_text_of_the_production_check",
         "scripts/tests/test_campaign_v5.py::test_a_small_campaign_runs_from_initialize_to_finish_corpus"),
        (("B9a", "a0bfa61"),), "ac95f01", "refusal",
        (("the production check of training refused the corpus index {index} (safeguard/training.py ",
          "scripts/campaign.py:3496"),),
        ("python3 -m safeguard smoke (safeguard/demo.py) still ends ok on its diagnostic corpus; it is no gate of "
         "protocol v5. The hand-off tests of B1 (row 13) run the production check, training, every method, the "
         "replay and the evaluation without the diagnostic flag; the dry run of G1 (proposal 10.2) is where the "
         "mutations of process R11's control are refused, by the injected errors of scripts/tests/vlozene_chyby.py "
         "(B10, agent G)",)),
)
