# B10 agent A: before and after of the table of the audit's probes

The table is `scripts/tests/audit_probes.py` at `e5f7954` (tree `/tmp/claude-1000/-home-eh-projects-hyptcn3/9a8a89c1-0c71-4e83-9fec-bd4ea2021d22/scratchpad/b10/c`): 18 rows, 57 test ids. Design B10 decision 5 and the lead's skeleton 1.3 and 6: every id fails on the commit before its row's oldest fix and passes today.

- **Before** (`pred.log`, `pred.xml`, `pred_runs.json`): each id ran in a pytest of its own on its row's commit before, in a worktree of that commit with today's test files of its rows, the test modules they import and `config/collection-v5.json` copied in (`pred_po.py` HELPERS); the product code of the commit stayed as it was.
- **After** (`po.log`, `po.xml`): the 57 ids in one run at `e5f7954`: 57 passed.
- **Result:** 57 of 57 fail before: 5 by an assertion, 52 by an error (at setup, inside the test, or at collection). For the ids that fail only by an error, the probes of `sondy/` show the old behaviour on the same commit with that tree's own code and test helpers (B3's pred2 is the model), and the notes say where the old code has no counterpart.
- **A cause shared by 8 ids** (at 062178d, ac95f01, bae0ee8, f99b924): the copied config/collection-v5.json has no field status (Q23, B9b), which the loaders of these commits require; their failure says nothing of the fix, and their row's probe shows the old behaviour.
- The driver is `pred_po.py` (rerun on the merged tree: `--tree <merged repository>`), the summary `suhrn.py`.
- **Later fixes of B10** (`pred_later.json`, the B10 fix round): 1 id(s) also ran on the parent of the later fix of B10 that its row names beside the skeleton's packages, and 1 failed there; see their rows.

## Row 1: capture R5 (fixed by B3 0b3c276; before `c39accb`; refusal)

- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[lateness]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- Old behaviour, the probes on the same commit:
  - before: lateness 4.0 s in every sidecar (capture R5); input: sched.lateness_s = 4.0 in each of the 96 sidecars; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)

## Row 2: capture R7, lab LAB-04 (fixed by B3 0b3c276, B5a 2a95852; before `c39accb`; refusal)

- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[logs:event_not_executed]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[logs:event_without_effect]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_effect_contract.py::test_event_record_without_a_true_ok_is_refused_for_exactly_that[ok_false]`: fails by an assertion: assert not True; after: passed.
- `lab/tests/test_udalosti_effect.py::test_predicate_is_true_with_the_effect_and_false_without[zamok_tabulky-none-9]`: fails by an error at setup: "AttributeError: <module 'udalosti' from '<scratch>/pred_c39accb/lab/udalosti.py'> has no attribute 'http'"; after: passed.
- `lab/tests/test_udalosti_effect.py::test_predicate_is_true_with_the_effect_and_false_without[udrzba_zaloha-none-11]`: fails by an error at setup: "AttributeError: <module 'udalosti' from '<scratch>/pred_c39accb/lab/udalosti.py'> has no attribute 'http'"; after: passed.
- `lab/tests/test_udalosti_effect.py::test_predicate_is_true_with_the_effect_and_false_without[zataz_pamate-none-14]`: fails by an error at setup: "AttributeError: <module 'udalosti' from '<scratch>/pred_c39accb/lab/udalosti.py'> has no attribute 'http'"; after: passed.
- Old behaviour, the probes on the same commit:
  - before: an event that did not run (capture R7); input: events.json: executed false, start ok false; {"accepted": true, "problems": []} (sondy/sonda_c39accb_c39accb.out)
  - before: an event without effect (LAB-04); input: events.json: effect {ok: false}; {"accepted": true, "problems": []} (sondy/sonda_c39accb_c39accb.out)
- Note: The lab test of LAB-04 has no counterpart at c39accb: lab/udalosti.py there has no effect() and no predicate (B5a added them); its stop returned ok right after the start (the record's capture R7).

## Row 3: capture R6 (fixed by B3 0b3c276; before `c39accb`; refusal)

- `scripts/tests/test_collection_logs.py::test_collector_warning_is_judged_by_the_allowed_patterns[null]`: fails by an assertion: AssertionError: assert [] == ['collector_w...oda 5.000 s)']; after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[logs:collector_warning_unlisted]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- Old behaviour, the probes on the same commit:
  - before: two WARN lines of the collector (capture R6); input: raw/collect.log: two lines ' WARN '; {"accepted": true, "problems": []} (sondy/sonda_c39accb_c39accb.out)

## Row 4: capture R3 (fixed by B3 0b3c276, B10 f0506e8 (B3 S1); before `c39accb`; refusal)

- `scripts/tests/test_audit_selftest.py::test_cap_of_rule_closed_rows_once_it_is_set[above]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_audit_selftest.py::test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[zero]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_audit_selftest.py::test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[three]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_audit_selftest.py::test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[four]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_audit_selftest.py::test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number[every_row]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- Old behaviour, the probes on the same commit:
  - before: 10 rows closed by rule prev (capture R3); input: seq 10 to 19: process_walk prev, behavior valid; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)

## Row 5: capture R4, process R5 (fixed by B3 0b3c276, B5a 2a95852, B10 a446043 (Q29); before `c39accb`; refusal)

- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[logs:qemu_swap]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[logs:qemu_swap:absent]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[qemu_swap]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[qemu_swapped]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_audit_selftest.py::test_run_session_refuses_qemu_swap_that_is_not_forbidden[max]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_audit_selftest.py::test_run_session_refuses_qemu_memory_that_was_swapped_before_start[8592]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_collector_majflt.py::test_a_bound_refuses_one_cycle_above_it_and_accepts_a_cycle_at_it[zero]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
  - On `7eb6ac2`, the parent of the later fix a446043 of B10, it fails by an error at setup: "ValueError: invalid audit bounds".
- Old behaviour, the probes on the same commit:
  - before: a host monitor file without any process or memory data (capture R4); input: the clean session: 0 of 102 records of host_monitor.jsonl hold procs or memory; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)
  - before: QEMU swap not forbidden and QEMU memory in swap before start (capture R4, process R5); input: session.json host_context.memory: qemu_swap_max 'max', qemu_swap_kb 4; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)
  - before: a swap storm in the host monitor (capture R4); input: procs.qemu swap_kb 26832, 53664, ... in every sample; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)
  - before: 500 collector major faults per cycle (capture R4); input: capture.rusage.majflt = 500 in each of the 96 sidecars; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_majflt_c39accb.out)
- Note: run_session is the counterpart of the start check, but it reaches the lab, so no probe runs it: at c39accb it records vm.swappiness and qemu_swap_kb and reads swapped pages back in (prefault_swapped), and refuses no start for swap; it reads no memory.swap.max (git show c39accb:scripts/collection.py, host_memory and run_session).

## Row 6: capture R1, lab LAB-01 (fixed by B4 9e7e43c, B4b fd021b1; before `8ae9f39`; refusal)

- `scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error[locked_to_grid]`: fails by an error inside the test: ImportError: cannot import name 'protocol_v5' from 'scripts' (unknown location); after: passed.
- `scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error[phases_at_tenth_edges]`: fails by an error inside the test: ImportError: cannot import name 'protocol_v5' from 'scripts' (unknown location); after: passed.
- Old behaviour, the probes on the same commit:
  - before: event starts and stops on multiples of the capture interval (capture R1, LAB-01); input: plan() of config/collection-v4.json: 96 sessions, 238 events; {"interval_s": 5, "start_phases_s": [0], "starts_modulo_30_s": [0], "stop_phases_s": [0]} (sondy/sonda_8ae9f39_8ae9f39.out)
- Note: 8ae9f39 has no scripts/protocol_v5.py: the self-check has no counterpart. The counterpart of the schedule is the plan of config/collection-v4.json.

## Row 7: lab LAB-11 (fixed by B4 9e7e43c; before `8ae9f39`; refusal)

- `scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error[common_seed]`: fails by an error inside the test: ImportError: cannot import name 'protocol_v5' from 'scripts' (unknown location); after: passed.
- Old behaviour, the probes on the same commit:
  - before: one seed for two purposes, and the same seeds under another protocol (LAB-11); input: plan() of config/collection-v4.json and of a copy under another name; {"event_schedule_draws_from": "random.Random(session seed)", "same_seeds_under_another_name": true, "seed_keys_of_a_session": ["seed"], "traffic_generator_gets": ["\"--dur\", \"0\", \"--seed\", str(metadata[\"seed\"]), \"--vlakien\", str(s[\"workers\"]),"]} (sondy/sonda_8ae9f39_8ae9f39.out)
- Note: As row 6: no self-check at 8ae9f39; the plan's seeds are its counterpart.

## Row 8: lab LAB-12 (fixed by B5b e64e619; before `11319ee`; refusal)

- `scripts/tests/test_traffic_realism.py::test_a_log_that_breaks_one_requirement_is_refused_with_its_name[offered_load_differs_from_plan]`: fails by an error inside the test: ImportError: cannot import name 'CONTROL_RECORD_CLASS' from 'scripts.protocol_v5' (<scratch>/pred_11319ee/scripts/protocol_v5.py); after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[logs:offered_load_differs_from_plan]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ImportError: cannot import name 'CONTROL_RECORD_CLASS' from 'scripts.protocol_v5' (<scratch>/pred_11319ee/scripts/protocol_v5.py)); after: passed.
- Old behaviour, the probes on the same commit:
  - before: the delivered load against the scenario (LAB-12); {"accepted": true, "measured_catalog_requests": 1, "measured_requests": 3, "problems": [], "scenario": {"burst": 4, "catalog_share": 1.0, "initial_phase": "warmup", "profile": "lab", "seed": 1, "summary_interval_s": 1, "target": "http://lab", "workers": 64, "write_share": 0.0}} (sondy/sonda_11319ee_11319ee.out)

## Row 9: lab LAB-02 (fixed by B5a 2a95852; before `8bdc2ae`; limit)

- `lab/tests/test_periods.py::test_entries_are_complete_and_process_creating_ones_are_bounded_or_random`: fails by an error inside the test: FileNotFoundError: [Errno 2] No such file or directory: '<scratch>/pred_8bdc2ae/lab/periods.json'; after: passed.
- `lab/tests/test_periods.py::test_bounds_and_random_delays_of_the_register_are_those_of_the_source`: fails by an error inside the test: TypeError: 'NoneType' object is not subscriptable; after: passed.
- Old behaviour, the probes on the same commit:
  - before: a unit that fails at once, restarted for one hour (LAB-02); input: the unit file of 8bdc2ae; {"Restart": "on-failure", "RestartSec": "3", "StartLimitBurst": "absent (default 5)", "StartLimitIntervalSec": "absent (default 10)", "ends_in_state_failed": false, "starts_in_one_hour": 1201} (sondy/sonda_8bdc2ae_8bdc2ae.out)
  - before: a unit that fails at once, restarted for one hour (LAB-02); input: today's unit file; {"Restart": "on-failure", "RestartSec": "3", "StartLimitBurst": "5", "StartLimitIntervalSec": "60", "ends_in_state_failed": true, "starts_in_one_hour": 5} (sondy/sonda_8bdc2ae_8bdc2ae.out)
- Note: 8bdc2ae has no lab/periods.json, the register the tests read: no counterpart. The unit file is the counterpart of the bound.

## Row 10: model M5, evaluation R2, process R8 (fixed by B7c 576aa4b; before `062178d`; refusal)

- `tcn/tests/test_pecat.py::test_a_second_final_run_is_refused[copy_of_the_index]`: fails by an error at setup: "ImportError: cannot import name 'pecat' from 'tcn' (<scratch>/pred_062178d/tcn/__init__.py)"; after: passed.
- `tcn/tests/test_finalne.py::test_a_second_run_is_refused[copy_elsewhere]`: fails by an error at setup: "ValueError: missing protocol key: status"; after: passed.
- `tcn/tests/test_finalne.py::test_a_refusal_before_the_seal_consumes_nothing[dirty_tree]`: fails by an error at setup: "ValueError: missing protocol key: status"; after: passed.
- `tcn/tests/test_eval_v5.py::test_a_sealed_role_is_evaluated_by_the_final_command_or_in_a_rehearsal[campaign-False-False-sealed role test_benign]`: fails by an error inside the test: ImportError: cannot import name 'REHEARSAL_MARK' from 'tcn.eval' (<scratch>/pred_062178d/tcn/eval.py); after: passed.
- `tcn/tests/test_pecat.py::test_replay_of_a_sealed_archive_is_refused[safeguard.runtime.replay_archive]`: fails by an error at setup: "ImportError: cannot import name 'pecat' from 'tcn' (<scratch>/pred_062178d/tcn/__init__.py)"; after: passed.
- Old behaviour, the probes on the same commit:
  - before: the one final evaluation (model M5, evaluation R2, process R8); input: tcn.eval far --final on the index; git: safeguard/runtime.py and safeguard/model.py changed; {"exit": 0, "marks": ["corpus.json.test_benign-final.json"]} (sondy/sonda_062178d_062178d.out)
  - before: the one final evaluation (model M5, evaluation R2, process R8); input: tcn.eval far --final on the same index again; git: safeguard/runtime.py and safeguard/model.py changed; {"marks": ["corpus.json.test_benign-final.json"], "refused": "FileExistsError: [Errno 17] File exists: '<scratch>/sonda_tmp/062178d/corpus.json.test_benign-final.json'"} (sondy/sonda_062178d_062178d.out)
  - before: the one final evaluation (model M5, evaluation R2, process R8); input: tcn.eval far --final on a byte-identical copy of the index at another path; git: safeguard/runtime.py and safeguard/model.py changed; {"exit": 0, "marks": ["corpus.json.test_benign-final.json", "elsewhere/corpus.json.test_benign-final.json"]} (sondy/sonda_062178d_062178d.out)
- Note: The direct call vyhodnot_far(..., final=True) at 062178d takes final from its caller and checks no mark (git show 062178d:tcn/eval.py, vyhodnot_far): no probe is needed for it.

## Row 11: evaluation R7 (fixed by B7c 576aa4b; before `062178d`; status)

- `tcn/tests/test_eval_v5.py::test_an_occurrence_is_evaluable_at_half_of_its_first_60_s_scored[7-False]`: fails by an error inside the test: ImportError: cannot import name 'metriky_v5' from 'tcn.eval' (<scratch>/pred_062178d/tcn/eval.py); after: passed.
- `tcn/tests/test_eval_v5.py::test_an_unscored_stretch_is_nevyhodnotene_in_the_output`: fails by an error inside the test: ImportError: cannot import name 'metriky_v5' from 'tcn.eval' (<scratch>/pred_062178d/tcn/eval.py); after: passed.
- Old behaviour, the probes on the same commit:
  - before: an occurrence whose rows are all unscored (evaluation R7); input: 40 rows 5 s apart with score null, the event from 1050 s to 1110 s, window 32; {"keys_about_scoring": [], "record_of_the_occurrence": {"alarm_modelu": false, "alarm_na_konci_dozvuku": false, "alarm_riadkov": 0, "alarm_v_dozvuku_riadkov": 0, "class": "chyba_aplikacie", "dozvuk_riadkov": 0, "executed": true, "oneskorenie_s": null, "start_unix": 1050.0, "stop_unix": 1110.0, "type": "zamok_tabulky"}} (sondy/sonda_062178d_062178d.out)

## Row 12: model M9, evaluation R8 (fixed by B6b dea37ca, B7c 576aa4b; before `f99b924`; refusal)

- `safeguard/tests/test_training.py::test_analysis_parameters_are_refused_by_name[fpr_outside_diagnostic]`: fails by an error inside the test: ImportError: cannot import name 'training_parameters' from 'safeguard.training' (<scratch>/pred_f99b924/safeguard/training.py); after: passed.
- `tcn/tests/test_odovzdanie_korpusu.py::test_parameter_analyzy_z_prikazoveho_riadka_iba_s_diagnostikou`: fails by an error at setup: "ValueError: missing protocol key: status"; after: passed.
- `tcn/tests/test_porovnanie.py::test_fit_pod_schemou_3_odmietne_parameter_analyzy[fpr]`: fails by an assertion: AssertionError: Regex pattern did not match.; after: passed.
- Old behaviour, the probes on the same commit:
  - before: a parameter of the analysis from the command line (model M9, evaluation R8); {"analysis_fpr": 0.01, "bundle_diagnostic": false, "calibration_fpr_design": 0.1, "command": "safeguard train --epochs 1 --batch-size 64 --fpr 0.1 (no --diagnostic)", "errors": "", "exit": 0, "schema": "hyptcn3/collection-protocol/3"} (sondy/test_sonda_f99b924_f99b924.out)
- Note: porovnanie fit at f99b924 opened the corpus without refusing the given parameter: its assertion failure says so ('production training requires a complete non-diagnostic corpus' in place of the refusal).

## Row 13: process R1, features GF-8, model M4 (fixed by B1 a41973e; before `48e198c`; refusal)

- `tcn/tests/test_odovzdanie_korpusu.py::test_ostra_kontrola_indexu_prijme_predponu_skupin`: fails at collection: its module does not import (tcn.tests.test_odovzdanie_korpusu: ImportError: cannot import name 'FIT_ROLES' from 'safeguard.training' (<scratch>/pred_48e198c/safeguard/training.py)); after: passed.
- `tcn/tests/test_odovzdanie_korpusu.py::test_ostra_kontrola_indexu_odmietne_skupinu_bez_predpony`: fails at collection: its module does not import (tcn.tests.test_odovzdanie_korpusu: ImportError: cannot import name 'FIT_ROLES' from 'safeguard.training' (<scratch>/pred_48e198c/safeguard/training.py)); after: passed.
- `tcn/tests/test_odovzdanie_korpusu.py::test_trening_prijme_tolerovany_riadok`: fails at collection: its module does not import (tcn.tests.test_odovzdanie_korpusu: ImportError: cannot import name 'FIT_ROLES' from 'safeguard.training' (<scratch>/pred_48e198c/safeguard/training.py)); after: passed.
- `tcn/tests/test_odovzdanie_korpusu.py::test_kazda_metoda_prijme_tolerovany_riadok`: fails at collection: its module does not import (tcn.tests.test_odovzdanie_korpusu: ImportError: cannot import name 'FIT_ROLES' from 'safeguard.training' (<scratch>/pred_48e198c/safeguard/training.py)); after: passed.
- `tcn/tests/test_odovzdanie_korpusu.py::test_prehratie_s_tolerovanym_riadkom_konci_nulou`: fails at collection: its module does not import (tcn.tests.test_odovzdanie_korpusu: ImportError: cannot import name 'FIT_ROLES' from 'safeguard.training' (<scratch>/pred_48e198c/safeguard/training.py)); after: passed.
- `tcn/tests/test_odovzdanie_korpusu.py::test_trening_a_metody_odmietnu_riadok_mimo_pravidla[nad_pocet-prva-train]`: fails at collection: its module does not import (tcn.tests.test_odovzdanie_korpusu: ImportError: cannot import name 'FIT_ROLES' from 'safeguard.training' (<scratch>/pred_48e198c/safeguard/training.py)); after: passed.
- Old behaviour, the probes on the same commit:
  - before: the production check of training on the groups of prefix v5- (process R1, GF-8); input: a closed campaign of 16 sessions, groups v5-<role>-<n>; {"validate_index": "refused: incomplete planned allocation"} (sondy/test_sonda_48e198c_48e198c.out)
  - before: training on sessions with one tolerated invalid row (process R1, M4); input: the same corpus without a group prefix; in each role two sessions carry one invalid row the rule tolerates; {"train_bundle": "refused: accepted corpus archive contains invalid model rows", "validate_index": "accepted"} (sondy/test_sonda_48e198c_48e198c.out)

## Row 14: process R7, capture R10 (fixed by B2 7a459eb, B4 9e7e43c; before `432dd2e`; refusal)

- `scripts/tests/test_pilot_gate.py::test_pilot_cell_audit_decision[V4-one_row]`: fails by an assertion: AssertionError: assert (0, True, []) == (2, False, ['...l-inputs-v1']); after: passed.
- `scripts/tests/test_pilot_gate.py::test_pilot_gate_follows_the_audit[V4-one_row-honest]`: fails by an assertion: AssertionError: Regex pattern did not match.; after: passed.
- `scripts/tests/test_protocol_v5.py::test_selfcheck_passes_the_file_and_fails_each_deliberate_error[gate_085]`: fails by an error inside the test: ImportError: cannot import name 'protocol_v5' from 'scripts' (unknown location); after: passed.
- Old behaviour, the probes on the same commit:
  - before: the loader on a gate the worst session of the rule cannot reach (case gate_085); input: config/collection-v4.json under schema 3, min_score_coverage 0.85, invalid_rows.max 3, cycles 720; {"collection.protocol": "refused: invalid_rows.max is unreachable under the score coverage gate"} (sondy/sonda_432dd2e_432dd2e.out)
- Note: The loader refused the gate of case gate_085 before B2 too (the probe), so that case shows B4's self-check rows, which have no counterpart at 432dd2e. The two pilot tests fail by assertion: the old audit accepted a pilot with one tolerated row, and the old pilot_gate refused it with its own rule ('accepted pilot with current extractor and frozen protocol required').

## Row 15: process R9 (fixed by B9b f700204; before `bae0ee8`; refusal)

- `scripts/tests/test_campaign_v5.py::test_finish_corpus_without_the_record_of_the_complete_ending_fails`: fails by an error at setup: "ValueError: missing protocol key: status"; after: passed.
- `scripts/tests/test_campaign_endings.py::test_the_record_of_a_closing_ending_carries_the_entry_of_the_measurement_log`: fails by an error inside the test: ValueError: missing protocol key: status; after: passed.
- `scripts/tests/test_campaign_endings.py::test_a_hash_that_changes_during_a_run_makes_the_campaign_invalid[measurement]`: fails by an error inside the test: ValueError: missing protocol key: status; after: passed.
- Old behaviour, the probes on the same commit:
  - before: the complete ending of a rehearsal (process R9); {"corpus_index": true, "data_results_changed": [], "files_written": 509, "outside_the_campaign_its_archive_and_its_sessions": ["ledger/kniha_pecati.json"], "records_of_an_ending": [], "status": {"a": "complete", "b": "complete"}} (sondy/test_sonda_bae0ee8_bae0ee8.out)
  - before: a campaign the operator closes after one session (process R9); {"data_results_changed": [], "records_of_an_ending": [], "status": {"a": "closed", "b": "closed"}, "written_by_close": ["second/archive/campaigns/plan-b6a-test-generalka/closed.json", "second/campaigns/plan-b6a-test-generalka/closed.json", "second/campaigns/plan-b6a-test-generalka/events/20261124T172811086698Z_c92fc74c.json", "second/campaigns/plan-b6a-test-generalka/events/20261124T172811087016Z_997aa801.json", "second/collections/.lock-hyptcn-test-b"]} (sondy/test_sonda_bae0ee8_bae0ee8.out)

## Row 16: capture R8 (fixed by B3 0b3c276; before `c39accb`; refusal)

- `scripts/tests/test_audit_selftest.py::test_every_reason_of_the_audit_and_the_verdict_has_a_case`: fails by an error inside the test: ModuleNotFoundError: No module named 'scripts.protocol_v5'; after: passed.
- `scripts/tests/test_audit_cases_logs.py::test_cases_cover_every_problem_key_of_the_log_audit`: fails at collection: its module does not import (scripts.tests.test_audit_cases_logs: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- `scripts/tests/test_audit_selftest.py::test_require_selftest_refuses_without_a_valid_record[absent]`: fails by an error at setup: "ImportError: cannot import name 'audit_policy' from 'features' (<scratch>/pred_c39accb/features/__init__.py)"; after: passed.
- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[timestamp_gap]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- Old behaviour, the probes on the same commit:
  - before: the gate of the timestamp gap (capture R8: the verifier's probe found that it fires); input: every row from seq 32 on one interval later; {"accepted": false, "code": 2, "reasons": ["timestamp gap"]} (sondy/sonda_c39accb_c39accb.out)
- Note: The gate of the timestamp gap refused before B3 too (the verifier's finding, and the probe); the risk was that no test proved the gates. The self-test of every reason and require_selftest have no counterpart at c39accb (no scripts/audit_selftest.py, no case module).

## Row 17: capture R11 (fixed by B3 0b3c276; before `c39accb`; refusal)

- `scripts/tests/test_audit_selftest.py::test_bad_session_is_refused_with_exactly_its_reasons[missing_key:frame3.json:capture.queue_wait_ms]`: fails at collection: the id does not exist on this tree (its function gives test_bad_session_is_refused_with_exactly_its_reasons[audit_cases_missing]; scripts.tests.audit_cases: ModuleNotFoundError: No module named 'scripts.protocol_v5'); after: passed.
- Old behaviour, the probes on the same commit:
  - before: sidecars without capture.queue_wait_ms (capture R11); input: the clean session: 0 of 96 sidecars hold capture.queue_wait_ms; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)
- Note: At c39accb the audit read capture.get('queue_wait_ms', 0) (a silent default); the fixture's sidecars hold no such key, and the session is accepted.

## Row 18: process R11 (fixed by B9a a0bfa61; before `ac95f01`; refusal)

- `scripts/tests/test_campaign.py::test_finish_corpus_keeps_the_error_text_of_the_production_check`: fails by an error inside the test: ValueError: missing protocol key: status; after: passed.
- `scripts/tests/test_campaign_v5.py::test_a_small_campaign_runs_from_initialize_to_finish_corpus`: fails by an error at setup: "ValueError: missing protocol key: status"; after: passed.
- Old behaviour, the probes on the same commit:
  - before: the campaign fixture of scripts/tests/test_campaign.py (process R11); {"corpus_indexes_built": [], "execute": 0, "status": "complete"} (sondy/test_sonda_ac95f01_ac95f01.out)
  - before: python3 -m safeguard smoke, the verifier's own run (process R11); {"corpus": {"complete": false, "diagnostic": true}, "exit": 0, "groups": ["calibration-1", "dev-1", "test_benign-1", "train-1"], "report": {"diagnostic": true, "input_errors": 0, "ok": true, "rows": 96, "scored": 80, "states": ["monitoring", "warming_up"]}} (sondy/test_sonda_ac95f01_ac95f01.out)
  - after, at HEAD: the campaign fixture of scripts/tests/test_campaign.py (process R11); {"corpus_indexes_built": ["<scratch>/sonda_tmp/HEAD/test_the_campaign_fixture_comp0/test-campaign/corpus.json"], "execute": 0, "status": "complete"} (sondy/test_sonda_ac95f01_HEAD.out)
  - after, at HEAD: python3 -m safeguard smoke, the verifier's own run (process R11); {"corpus": {"complete": false, "diagnostic": true}, "exit": 0, "groups": ["calibration-1", "dev-1", "test_benign-1", "train-1"], "report": {"diagnostic": true, "input_errors": 0, "ok": true, "rows": 96, "scored": 80, "states": ["monitoring", "warming_up"]}} (sondy/test_sonda_ac95f01_HEAD.out)
- Note: At ac95f01 the fixture's finish_corpus is a stand-in that builds no index; at HEAD it is a spy that calls the real one, and the index is built. safeguard smoke ends ok on its diagnostic corpus on both trees (row 18's open item).

## The controls of the probes

The probes of an audit (c39accb, 11319ee) first audit the unchanged session of their tree's helpers: accepted, so what a probe's session gets is the probe's own.

- c39accb: clean session of family S3 (control); input: none; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_c39accb.out)
- c39accb: session with one executed event (control of the log probes); input: test_collection_logs.build(event=True); {"accepted": true, "problems": []} (sondy/sonda_c39accb_c39accb.out)
- c39accb: clean session of family S3 (control of the probe of major faults); input: none; 0 of 96 sidecars hold capture.rusage; {"accepted": true, "code": 0, "reasons": []} (sondy/sonda_c39accb_majflt_c39accb.out)
- 11319ee: the fixture as built (control); {"accepted": true, "measured_catalog_requests": 1, "measured_requests": 3, "problems": [], "scenario": {"burst": 0, "catalog_share": 0.5, "initial_phase": "warmup", "profile": "lab", "seed": 1, "summary_interval_s": 1, "target": "http://lab", "workers": 1, "write_share": 0.2}} (sondy/sonda_11319ee_11319ee.out)
