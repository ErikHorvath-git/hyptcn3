"""The feature interventions of classes C and D and the claim K2 (protocol v5, package B7b, agent I; design
dokazy/B7/navrh/NAVRH_B7b.md sections 1.2 and 2, the lead's skeleton dokazy/B7/kostra/KOSTRA.md sections 4, 5 and 9
and the B7b row of section 8).

Design section 2 and skeleton sections 5 and 8: C keeps the set of values of every column in the block; D changes no
column outside its group; the validity predicate on both sides (an intervention that fails goes to the volume class,
reported apart); the placement never meets an event, a control, the reverberation or the band; the lengths balanced;
one intervention per copy; fewer than 8 evaluable gives nevyhodnotené; K2 on a generator without structure gives
not_better or undecided and with structure better (a small fast run; 20 seeds are G1). With them the keys of design
1.4 that agent F writes, read through tcn.zasahy.protocol_keys on synthetic protocol dicts (refused by name), the
stream injections, the shares per boot with M as the median of its seeds, the names of analysis.k2a.compare with the
two variants of Z4 (question Q13), and Z1's criterion of the interventions inserted into dev.

The data are synthetic normalized inputs (tcn.k2.known_answer and the sessions below); the trained TCN of the K2 test
is a stand-in of M trained by safeguard.training's own loop for a few epochs: mechanics, no number is a detection
result (HONESTY P4). The names of package B7b are imported inside the tests, so this file collects on the code before
it. The merge of B7b: protocol() is config/collection-v5.json with the values of these tests (the stream injections is
scripts/protocol_v5.py analysis_seed's, which reads the checked analysis plan of the schema-3 file); the decision of K2
reads the analysis plan of the file itself (decision_protocol, tcn.tvrdenia.rozhodni); the diagnostics of
tcn/diagnostiky.py take the detection of tcn.k2.detection. The fixes of the verification of B7b: K2 and Z1's criterion
pool both classes whenever one is evaluated (F1, tcn.k2 POOL_RULE); every placed intervention has its whole horizon
(F6); a test for each mutant that survived the verifier's round (F5: the jump back after a block, a detected
intervention of the volume class, the boots of the campaign, a reset inside a placeable stretch).
"""
import copy
import json
from pathlib import Path

import numpy as np
import pytest
import torch

ROOT = Path(__file__).resolve().parents[2]
WINDOW, INTERVAL, GAP, K, N = 8, 5.0, 7.5, 3, 5
DELETE = object()
# The groups of class D as agent F proposes them (its commit 416f962, config/collection-v5.json): a partition of the
# inputs of the neural channel, the four channels of a bin with the memory aggregates.
GROUPS = {"memory": ["mem_changed_ratio", "mem_bins_active", "mem_changed_max", "mem_changed_p95", "mem_changed_spread",
                     "mem_entropy_mean", "mem_entropy_max", "mem_zero_ratio", "changed_ratio", "zero_ratio",
                     "entropy_mean", "has_changed"],
          "processes": ["proc_total", "proc_user", "proc_kernel", "proc_new", "proc_gone", "proc_wx", "proc_memfd"],
          "modules": ["mod_total", "mod_delta"], "sockets": ["sock_total", "sock_listen", "sock_estab"]}


@pytest.fixture(scope="module", autouse=True)
def _threads():
    """Two torch threads for this file (as tcn/tests/test_metody.py)."""
    before = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(before)


# The values of these tests over config/collection-v5.json (protocol()): the name, the window of 8 rows (and the
# TCN's, and the contexts of the diagnostics within it: the protocol binds them to window_rows since F2 of the
# verification of B7b), one seed of M, a horizon of 60 s, the grids of Z1, Z3 and Z5, and interventions of 6 boots
# with blocks of 3 and 6 rows and a moving average of 4 rows (judgment: small and fast).
TEST_VALUES = (("name", "v5-test"), ("window_rows", WINDOW), ("analysis.architecture.window_rows", WINDOW),
               ("analysis.diagnostics.contexts", [1, 2, 4, WINDOW - 1]),
               ("analysis.seeds", [0]), ("analysis.horizon_s", 60),
               ("analysis.methods.Z1.grid", {"moving_average_rows": [4], "cusum_shift": [0.5]}),
               ("analysis.methods.Z3.grid", {"ewma_alpha": [0.5]}),
               ("analysis.methods.Z5.grid", {"ridge_alpha": [1.0]}),
               ("analysis.interventions.boots", 6), ("analysis.interventions.validity.moving_average_rows", 4),
               ("analysis.interventions.C.lengths", [3, 6]), ("analysis.interventions.D.lengths", [3, 6]))


def protocol(*changes):
    """config/collection-v5.json, a schema-3 protocol (the merge of B7b: scripts/protocol_v5.py analysis_seed draws the
    stream injections from its checked analysis plan), with TEST_VALUES and then `changes` ((dotted path, value or
    DELETE)); the descriptive methods that draw from a seed take the seeds of analysis.seeds, as the plan's check wants.
    K2a compares Z1, Z2, Z4:load and Z4:residual, as the file does (question Q13, provisional)."""
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    for path, value in TEST_VALUES + changes:
        *parents, last = path.split(".")
        node = doc
        for part in parents:
            node = node[part]
        if value is DELETE:
            del node[last]
        else:
            node[last] = copy.deepcopy(value)
    seeds = doc["analysis"].get("seeds")
    if type(seeds) is list:
        for name in ("iforest", "gru", "lstm"):
            doc["analysis"]["descriptive_methods"][name]["seeds"] = list(seeds)
    return doc


def decision_protocol(m):
    """config/collection-v5.json with the bounds m of K2a and K2b (null there until G1): the analysis plan that
    tcn.tvrdenia.rozhodni reads (K2a compares Z1, Z2 and Z4 there)."""
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    for claim in ("k2a", "k2b"):
        doc["analysis"][claim]["m"] = m
    return doc


def generated(structured=True, *, seed=1, boots=None, rows=150):
    from tcn.k2 import known_answer
    boots = boots or {"train": 2, "dev": 2, "calibration": 2, "test_benign": 3, "test_controls": 3}
    return known_answer(structured, seed=seed, boots=boots, rows=rows, window_rows=WINDOW, interval_s=INTERVAL,
                        max_gap_s=GAP)[0]


def with_bins(roles):
    """The same sessions with a bin that changes: random scaled values and has_changed 0 or 1 in every row."""
    from tcn.metody import Okna
    from tcn.zasahy import Carriers
    rng = np.random.default_rng(7)
    out = {}
    for role, carriers in roles.items():
        w = carriers.windows
        rows = []
        for s in range(len(w.session_ids)):
            arrays = w.session_arrays(s)
            local = rng.normal(size=arrays["local"].shape)
            local[..., 3] = rng.integers(0, 2, len(local))[:, None]
            rows.append(dict(arrays, local=local, full_times=[]))
        okna = Okna(rows, [tuple(int(x) for x in row[:2]) + (None,) for row in w.index], role=role,
                    normalizer=w.normalizer, window_rows=WINDOW, max_gap_s=GAP, interval_s=INTERVAL)
        out[role] = Carriers(okna, carriers.placeable, carriers.meta)
    return out


def plans(roles, doc=None, *, mode="campaign"):
    """The plans of test_benign and test_controls (their donors both test roles) under the ranges of role train."""
    from tcn import zasahy
    doc = doc or protocol()
    ranges = zasahy.train_ranges(roles["train"].windows, doc)
    donors = {role: roles[role] for role in zasahy.CARRIER_ROLES}
    return {role: zasahy.plan(roles[role], protocol=doc, mode=mode, ranges=ranges, donors=donors)
            for role in zasahy.CARRIER_ROLES}


def pair(plan, item):
    """(original global, original bins, copy global, copy bins, the block's first row in them) of one intervention."""
    copies, carriers = plan.copies, plan.carriers
    c = copies.session_ids.index(item["id"])
    s = carriers.windows.session_ids.index(item["session"])
    original, copied = carriers.windows.session_arrays(s), copies.session_arrays(c)
    rows = np.searchsorted(original["seq"], copied["seq"])
    assert np.array_equal(original["seq"][rows], copied["seq"])
    return (original["global"][rows], original["local"][rows], copied["global"], copied["local"],
            int(item["start"]["position"] - rows[0]))


def placed(plan, cls=None):
    return [item for item in plan.interventions if item["placed"] and cls in (None, item["class"])]


# ------------------------------------------------------------------ the interventions (skeleton section 5)


def test_c_keeps_the_values_of_every_column_in_the_block():
    """Class C: in the block every TCN input and every channel of the bin hold the same multiset of values as in the
    session, a reversed block is the session's rows backwards and a random one a permutation other than the identity;
    every row outside the block is the session's, bit for bit."""
    plan = plans(with_bins(generated()))["test_benign"]
    items = placed(plan, "C")
    assert {item["order"] for item in items} == {"reversed", "random"}
    for item in items:
        g, local, copy_g, copy_local, block = pair(plan, item)
        length, order = item["length"], np.array(item["permutation"])
        inside = slice(block, block + length)
        assert not np.array_equal(copy_local[inside], local[inside])  # The bins move with the rows.
        for original, changed in ((g, copy_g), (local, copy_local)):
            assert np.array_equal(np.sort(original[inside], axis=0), np.sort(changed[inside], axis=0))
            assert np.array_equal(changed[inside], original[inside][order])
            assert np.array_equal(np.delete(changed, np.s_[inside], axis=0), np.delete(original, np.s_[inside], axis=0))
        if item["order"] == "reversed":
            assert order.tolist() == list(range(length))[::-1]
        else:
            assert sorted(order.tolist()) == list(range(length)) and order.tolist() != list(range(length))


def test_d_changes_no_column_outside_its_group():
    """Class D: the TCN inputs of the group (and every scored bin for the group memory, which holds the four channels
    of a bin) are the donor's at the same seq in the block, a session of the same scenario and position in another
    boot; every other input and every row outside the block are the session's."""
    roles = with_bins(generated())
    plan = plans(roles)["test_benign"]
    items = placed(plan, "D")
    assert {item["group"] for item in items} == {"memory", "processes"}
    names = plan.carriers.windows.input_names
    for item in items:
        g, local, copy_g, copy_local, block = pair(plan, item)
        length = item["length"]
        inside = slice(block, block + length)
        columns = [names.index(name) for name in GROUPS[item["group"]] if name in names]
        assert item["inputs"] == [names[j] for j in columns] and item["bins"] == (item["group"] == "memory")
        others = [j for j in range(len(names)) if j not in columns]
        assert np.array_equal(copy_g[:, others], g[:, others])
        assert np.array_equal(np.delete(copy_g, np.s_[inside], axis=0), np.delete(g, np.s_[inside], axis=0))
        assert np.array_equal(np.delete(copy_local, np.s_[inside], axis=0), np.delete(local, np.s_[inside], axis=0))
        donor = roles[item["donor"]["role"]]
        d = donor.windows.session_ids.index(item["donor"]["session"])
        where = item["donor"]["position"]
        given = donor.windows.session_arrays(d)
        session = plan.carriers.windows.session_arrays(plan.carriers.windows.session_ids.index(item["session"]))
        assert np.array_equal(copy_local[inside],
                              given["local"][where:where + length] if item["bins"] else local[inside])
        assert np.array_equal(given["seq"][where:where + length],
                              session["seq"][item["start"]["position"]:item["start"]["position"] + length])
        assert np.array_equal(copy_g[inside][:, columns], given["global"][where:where + length][:, columns])
        mine, theirs = plan.carriers.meta[item["session"]], donor.meta[item["donor"]["session"]]
        assert (theirs["scenario"], theirs["position"]) == (mine["scenario"], mine["position"])
        assert theirs["boot"] != mine["boot"] and item["donor"]["boot"] == theirs["boot"]


def test_one_intervention_per_copy_and_the_session_never_changes():
    """Every placed intervention has a copy of its own, which differs from its session in its block only; planning
    writes nothing into the sessions of the carriers or of the donors."""
    roles = generated()
    before = {role: [session["global"].copy() for session in roles[role].windows.sessions()] for role in roles}
    plan = plans(roles)["test_controls"]
    assert plan.copies.session_ids == [item["id"] for item in placed(plan)]
    assert len(set(plan.copies.session_ids)) == len(placed(plan)) == len(plan.interventions)
    for item in placed(plan):
        g, local, copy_g, copy_local, block = pair(plan, item)
        changed = np.flatnonzero((copy_g != g).any(axis=1) | (copy_local != local).any(axis=(1, 2)))
        assert len(changed) and block <= changed.min() and changed.max() < block + item["length"]
    for role, arrays in before.items():
        assert all(np.array_equal(a, session["global"]) for a, session in zip(arrays, roles[role].windows.sessions()))


EXCLUDED = 70  # A row of every session that no window holds (an invalid row): the anchor after it lies before it.
# The placeable windows of the anchored test: from the first window after EXCLUDED, as many as one block needs (its
# history of window_rows windows and its horizon of 60 s), so that every copy begins with that window.
PLACEABLE = (EXCLUDED + WINDOW, EXCLUDED + 3 * WINDOW + 4)


def anchored(roles):
    """The same sessions under a normalizer with proc_new differenced: every window anchored by the measured row before
    its first row, the one after EXCLUDED by the row before it; placeable are the windows ending in PLACEABLE."""
    from tcn.k2 import GENERATOR_INPUTS, synthetic_normalizer
    from tcn.metody import Okna
    from tcn.zasahy import Carriers
    norm = synthetic_normalizer(GENERATOR_INPUTS, differenced=("proc_new",))
    out = {}
    for role, carriers in roles.items():
        w = carriers.windows
        rows, windows = [], []
        for s in range(len(w.session_ids)):
            arrays = w.session_arrays(s)
            rows.append(dict(arrays, full_times=[]))
            for end in range(WINDOW, len(arrays["seq"])):
                first = end - WINDOW + 1
                if not first <= EXCLUDED <= end:
                    windows.append((s, end, first - 1 if first - 1 != EXCLUDED else first - 2))
        okna = Okna(rows, windows, role=role, normalizer=norm, window_rows=WINDOW, max_gap_s=GAP,
                    interval_s=INTERVAL)
        ends = okna.index[:, 1]
        out[role] = Carriers(okna, (ends >= PLACEABLE[0]) & (ends <= PLACEABLE[1]), carriers.meta)
    return out


class Probe:
    """A method that reads what every method reads, the rows of a window after its anchor: their sum."""
    name, kind = "probe", "detector"

    def scores(self, windows):
        return np.concatenate([windows.rows(g).sum(axis=(1, 2)) for _, g, _ in windows.arrays(bins=False)])


def test_the_copies_of_anchored_windows_read_the_sessions_rows_and_anchors():
    """With a differenced input every window is anchored, the one after an excluded row across it, and every copy here
    begins with that window: every window of a copy has the anchor and the rows of the session's window of the same
    seq, and a window that reads no row of the block scores as the session's; the block changes some window that
    reads it."""
    roles = anchored(generated(boots={"train": 2, "test_benign": 3, "test_controls": 3}))
    found = plans(roles)
    probe = Probe()
    for plan in found.values():
        copies, w = plan.copies, plan.carriers.windows
        assert copies.anchored and placed(plan) == plan.interventions
        mine, theirs = probe.scores(copies), probe.scores(w)
        for item in placed(plan):
            c, s = copies.session_ids.index(item["id"]), w.session_ids.index(item["session"])
            _, end, anchor = copies.index[np.flatnonzero(copies.window_session == c)[0]]
            seq_copy, seq_session = copies.session_arrays(c)["seq"], w.session_arrays(s)["seq"]
            assert (seq_copy[anchor], seq_copy[end - WINDOW + 1]) == (EXCLUDED - 1, EXCLUDED + 1)
            block = item["start"]["seq"]
            changed = False
            for i in np.flatnonzero(copies.window_session == c):
                _, end, anchor = copies.index[i]
                j = np.flatnonzero((w.window_session == s) & (w.seq == seq_copy[end]))[0]
                assert seq_copy[anchor] == seq_session[w.index[j, 2]]
                reads = seq_copy[end] >= block and seq_copy[end] - WINDOW + 1 < block + item["length"]
                if not reads:
                    assert mine[i] == theirs[j]
                changed |= bool(reads and mine[i] != theirs[j])
            assert changed


def test_the_lengths_variants_and_groups_are_balanced_within_the_role():
    """18 interventions of each class in a role of three boots: each of the four lengths 4 or 5 times, each order of C
    and each group of D 9 times (DEAL_RULE), per_boot of each class in every boot."""
    from collections import Counter
    doc = protocol(("analysis.interventions.C.lengths", [2, 3, 4, 5]),
                   ("analysis.interventions.D.lengths", [2, 3, 4, 5]))
    plan = plans(generated(), doc)["test_benign"]
    for cls, variant in (("C", "order"), ("D", "group")):
        mine = [item for item in plan.interventions if item["class"] == cls]
        assert sorted(Counter(item["length"] for item in mine).values()) == [4, 4, 5, 5]
        assert sorted(Counter(item[variant] for item in mine).values()) == [9, 9]
        assert Counter(item["boot"] for item in mine) == dict.fromkeys(plan.boots, 6)
        assert plan.record()["counts"][cls]["lengths"] == {str(n): sum(item["length"] == n for item in mine)
                                                           for n in (2, 3, 4, 5)}


# ------------------------------------------------------------------ the placement (design 1.1, skeleton section 5)

T = 240
FULL = (0, 120)  # Full snapshots: barriers of the windows and the centres of the bands.
EVENT = (40, 50)  # test_benign, positions 0 and 1: host_start and host_stopped at these rows.
CONTROL = (170, 180)  # test_controls: the occurrence of a control at these rows.
REVERBERATION_S, BEFORE_S = 30., 30.


def time(session, row):
    return 1000. + 10000. * session + INTERVAL * row


def intervals(role, session, position):
    """[(start, end, closed end)] in time of every interval a placement must not meet: the event and its
    reverberation, the control, and the band of each full snapshot (design 1.1, tcn.metody CLEAN_RULE)."""
    out = [(time(session, t) - BEFORE_S, time(session, t) + WINDOW * INTERVAL, False) for t in FULL]
    if role == "test_benign" and position < 2:
        out.append((time(session, EVENT[0]), time(session, EVENT[1]) + REVERBERATION_S, True))
    if role == "test_controls":
        out.append((time(session, CONTROL[0]), time(session, CONTROL[1]), True))
    return out


def meets(start, end, spans):
    return any(end >= a and (start <= b if closed else start < b) for a, b, closed in spans)


def busy_carriers(role, sessions, everything=False):
    """Carriers of `role` with events (test_benign), controls (test_controls) and full snapshots: the placeable mask is
    that of design 1.1 (no window's span meets an interval) or, with everything, every window."""
    from tcn.k2 import GENERATOR_INPUTS, synthetic_normalizer
    from tcn.metody import Okna
    from tcn.zasahy import Carriers
    norm = synthetic_normalizer(GENERATOR_INPUTS)
    rng = np.random.default_rng(len(role))
    rows, windows, meta, spans = [], [], {}, []
    for s, (session, boot, position) in enumerate(sessions):
        rows.append({"id": f"{role}-{boot}-{position}", "global": rng.normal(0, .3, (T, 5)),
                     "local": np.zeros((T, 1, 4)), "seq": np.arange(T),
                     "timestamp": np.array([time(session, t) for t in range(T)]),
                     "full_times": [time(session, t) for t in FULL], "load": None})
        meta[rows[-1]["id"]] = {"boot": f"{role}-{boot}", "scenario": "s", "position": position}
        mine = intervals(role, session, position)
        for end in range(WINDOW - 1, T):
            if any(end - WINDOW + 1 <= f <= end for f in FULL):
                continue
            windows.append((s, end, None))
            spans.append((time(session, end - WINDOW + 1), time(session, end), mine))
    okna = Okna(rows, windows, role=role, normalizer=norm, window_rows=WINDOW, max_gap_s=GAP, interval_s=INTERVAL)
    placeable = np.array([everything or not meets(a, b, mine) for a, b, mine in spans])
    return Carriers(okna, placeable, meta)


def busy_roles(everything=False):
    sessions = {role: [(10 * r + 3 * b + p, b, p) for b in range(2) for p in range(3)]
                for r, role in enumerate(("test_benign", "test_controls"))}
    roles = {role: busy_carriers(role, mine, everything) for role, mine in sessions.items()}
    train = generated(boots={"train": 2})["train"]
    return dict(roles, train=train), sessions


def spans_of(plan, item, sessions):
    """The time span of an intervention's copy (every row its windows read) and the intervals of its session."""
    c = plan.copies.session_ids.index(item["id"])
    s = plan.carriers.windows.session_ids.index(item["session"])
    session, _, position = sessions[plan.role][s]
    times = plan.copies.session_arrays(c)["timestamp"]
    return (times[0], times[-1]), intervals(plan.role, session, position)


def test_the_placement_never_meets_an_event_a_control_the_reverberation_or_the_band():
    """Sessions with an event, a control and full snapshots: every row that the windows of a copy read (the history,
    the block, the windows that read it and the horizon) and every row of a donor's segment and of its windows lies
    outside the events with their reverberation, the controls and the bands; the same sessions with every window
    placeable put some copy on one of them, so the mask decides."""
    roles, sessions = busy_roles()
    found = plans(roles)
    for role, plan in found.items():
        assert placed(plan) == plan.interventions  # There is room for every one.
        for item in plan.interventions:
            (start, end), spans = spans_of(plan, item, sessions)
            assert not meets(start, end, spans)
            if item["class"] == "D":
                donor = roles[item["donor"]["role"]]
                d = donor.windows.session_ids.index(item["donor"]["session"])
                session, _, position = sessions[donor.role][d]
                where = item["donor"]["position"]
                times = donor.windows.session_arrays(d)["timestamp"]
                assert not meets(times[where - WINDOW + 1], times[where + item["length"] - 1],
                                 intervals(donor.role, session, position))
    loose, sessions = busy_roles(everything=True)
    hits = []
    for plan in plans(loose).values():
        for item in placed(plan):
            (start, end), spans = spans_of(plan, item, sessions)
            hits.append(meets(start, end, spans))
    assert any(hits)


def test_an_intervention_without_room_is_not_placed_and_stays_planned():
    """A block longer than any placeable stretch: every intervention of that length is not placed, with its reason,
    counted in the plan and never in the copies."""
    roles, _ = busy_roles()
    doc = protocol(("analysis.interventions.C.lengths", [3, 200]))
    plan = plans(roles, doc)["test_benign"]
    long = [item for item in plan.interventions if item["class"] == "C" and item["length"] == 200]
    assert long and all(item["status"] == "not_placed" and not item["placed"] for item in long)
    assert long[0]["why"] == "no row of the boot's sessions meets PLACEMENT_RULE"
    assert not set(item["id"] for item in long) & set(plan.copies.session_ids)
    assert plan.record()["counts"]["C"]["not_placed"] == len(long)


def test_every_placed_intervention_has_its_whole_horizon():
    """PLACEMENT_RULE (F6 of the verification of B7b, the verifier's probe_horizon): the windows that read a block of 3
    rows end 3 + 8 - 2 = 9 rows after its start, before the 13 rows of the horizon of 60 s, so a start near the end of a
    session would cut the horizon there; a start needs a row at or after t + horizon_s in the same run. Every window of
    a session of 150 rows is placeable here: the starts of such a block are the rows 15 (8 windows of history from the
    first window, which ends at row 7) to 137 (the row 12 rows before the last), and every placed intervention of both
    roles has all 13 windows of its horizon."""
    doc = protocol(("analysis.interventions.C.lengths", [3]), ("analysis.interventions.D.lengths", [3]))
    expected = int(doc["analysis"]["horizon_s"] / INTERVAL) + 1
    roles = generated()
    carriers = roles["test_controls"]
    times = carriers.windows.session_arrays(0)["timestamp"]
    starts, _ = carriers.starts(0, 3, doc["analysis"]["horizon_s"])
    assert starts.tolist() == list(range(2 * WINDOW - 1, len(times) - expected + 1))
    assert times[starts[-1]] + doc["analysis"]["horizon_s"] == times[-1]
    for plan in plans(roles, doc).values():
        assert placed(plan) == plan.interventions
        assert all(len(horizon) == expected for horizon in plan.horizons.values())
        assert all(item["windows"]["horizon"] == expected for item in plan.interventions)


SKIP, STRETCH = 75, (60, 90)  # The row whose seq is skipped, the windows placeable (their last rows) around it.


def stretch_carriers(carriers, skip):
    """The sessions of `carriers` whose windows are placeable when their last row lies in STRETCH only and, with skip,
    the seq of every row from SKIP on one higher: a reset of the alarm rule at the window ending at row SKIP (the seq
    skips one), while every row still ends a placeable window (no window of tcn.metody.Okna.from_sessions spans such a
    skip; a window set given by hand can)."""
    from tcn.metody import Okna
    from tcn.zasahy import Carriers
    w = carriers.windows
    rows = []
    for s in range(len(w.session_ids)):
        arrays = w.session_arrays(s)
        rows.append(dict(arrays, seq=arrays["seq"] + (np.arange(len(arrays["seq"])) >= SKIP) * int(skip)))
    okna = Okna(rows, [tuple(int(x) for x in row[:2]) + (None,) for row in w.index], role=w.role,
                normalizer=w.normalizer, window_rows=WINDOW, max_gap_s=GAP, interval_s=INTERVAL)
    ends = okna.index[:, 1]
    return Carriers(okna, (ends >= STRETCH[0]) & (ends <= STRETCH[1]), carriers.meta)


def test_a_reset_inside_a_stretch_of_placeable_windows_splits_it():
    """PLACEMENT_RULE: the windows a placement needs (8 of history, the block of 3, the horizon of 13 rows: 21 rows)
    are of one run. A stretch of 31 placeable windows takes blocks of class C; the same stretch with a reset in its
    middle (the seq skips a row) leaves two runs of 15 and 16 windows, too short, and no intervention is placed though
    every row ends a placeable window (mutant V4 of the verification of B7b)."""
    doc = protocol(("analysis.interventions.C.lengths", [3]), ("analysis.interventions.D.lengths", [3]))
    roles = generated()
    for skip in (False, True):
        mine = dict(roles, test_benign=stretch_carriers(roles["test_benign"], skip))
        windows = mine["test_benign"].windows
        assert int(windows.resets.sum()) == len(windows.session_ids) * (1 + skip)
        assert int(mine["test_benign"].placeable.sum()) == 31 * len(windows.session_ids)
        plan = plans(mine, doc)["test_benign"]
        if skip:
            assert placed(plan) == [] and {item["why"] for item in plan.interventions} == {
                "no row of the boot's sessions meets PLACEMENT_RULE",
                "no row of the boot's sessions meets PLACEMENT_RULE with a donor (DONOR_RULE)"}
        else:  # Every copy is one run: its windows reset the alarm rule at its first window only.
            copy = plan.copies.window_session
            assert placed(plan, "C") and np.array_equal(plan.copies.resets,
                                                        np.concatenate(([True], copy[1:] != copy[:-1])))


# ------------------------------------------------------------------ the validity predicate (skeleton section 5)


def ranges_of(columns):
    """train_ranges of a train role whose two inputs are `columns` (rows, 2) over four sessions of 80 rows."""
    from tcn.k2 import synthetic_normalizer
    from tcn.metody import Okna
    from tcn.zasahy import train_ranges
    norm = synthetic_normalizer(("mem_changed_ratio", "mem_bins_active"))
    rows = [{"id": f"t{s}", "global": columns(s), "local": np.zeros((80, 1, 4)), "seq": np.arange(80),
             "timestamp": 1000. + 1000. * s + INTERVAL * np.arange(80), "full_times": [], "load": None}
            for s in range(4)]
    windows = [(s, end, None) for s in range(4) for end in range(WINDOW - 1, 80)]
    train = Okna(rows, windows, role="train", normalizer=norm, window_rows=WINDOW, max_gap_s=GAP,
                 interval_s=INTERVAL)
    return train_ranges(train, protocol())


def series(s, rows=80):
    """Two columns: +-1 alternating (moving averages near 0) and a slow sine (small first differences)."""
    t = np.arange(rows) + 7 * s
    noise = np.random.default_rng(s).normal(0, .01, (rows, 2))
    return np.stack([np.where(t % 2 == 0, 1., -1.), np.sin(2 * np.pi * t / 40)], axis=1) + noise


def _reversed_first(c):
    c[8:11, 0] = c[8:11, 0][::-1]


def _spike(c):
    c[9, 0] = 1.5


def _jump(c):
    c[8:11, 1] = series(0)[28:31, 1]


def _run(c):
    c[8:12, 0] = 1.


def _backwards(c):
    """The block of the slow sine runs backwards at the sine's own pace (every value and difference in it in range), so
    its only excursion is the jump back at the first row after it (the verifier's probe_after_block)."""
    original = series(0, 24)
    step = float(np.median(np.diff(original[6:12, 1])))
    c[8:11, 1] = original[7, 1] - step * np.arange(1, 4)


@pytest.mark.parametrize("change, length, reason", [
    (_reversed_first, 3, None),                                       # a permutation of the values: in every range
    (_spike, 3, ("value", "mem_changed_ratio", 1)),                   # 1.5 above every value of train
    (_jump, 3, ("difference", "mem_bins_active", 0)),                 # half a period away: values in range, a jump
    (_run, 4, ("moving_average", "mem_changed_ratio", 1)),            # four +1 in a row: a mean train never has
    (_backwards, 3, ("difference", "mem_bins_active", 3)),            # the jump back after the block (mutant V6)
])
def test_the_validity_predicate_on_both_sides(change, length, reason):
    """VALIDITY_RULE: the first violation names the quantity, the input and the row from the block's first row; a
    value the intervention leaves as it was is not judged; the rows after the block whose difference or moving average
    reads it are judged (the jump back at the first row after a block, F5 of the verification of B7b)."""
    from tcn.zasahy import violations
    ranges = ranges_of(series)
    original = series(0, 24)
    changed = original.copy()
    change(changed)
    found = violations(ranges, original, changed, 8, length)
    if reason is None:
        assert found == []
        return
    assert (found[0]["quantity"], found[0]["input"], found[0]["row"]) == reason
    lo, hi = found[0]["range"]
    assert not lo <= found[0]["value"] <= hi


def test_an_invalid_intervention_goes_to_the_volume_class_and_a_class_below_the_minimum_is_unevaluated():
    """Ranges of a quiet train (a tenth of the carriers' spread): every intervention fails the predicate, goes to the
    volume class with its first violation and is reported apart in the values of K2; with fewer than min_evaluable
    evaluable interventions both classes are nevyhodnotené, and so are K2a and K2b, decided without rozhodni (whose m
    is null in the protocol file)."""
    from tcn import k2, zasahy
    roles = generated()
    quiet = generated(boots={"train": 2})["train"].windows
    for values in quiet._global:  # In place, on the fresh arrays of the generator (the accessor's views are read-only).
        values *= .1
    doc = protocol()
    ranges = zasahy.train_ranges(quiet, doc)
    donors = {role: roles[role] for role in zasahy.CARRIER_ROLES}
    found = {role: zasahy.plan(roles[role], protocol=doc, mode="campaign", ranges=ranges, donors=donors)
             for role in zasahy.CARRIER_ROLES}
    items = [item for plan in found.values() for item in plan.interventions]
    assert all(item["status"] == "volume" and not item["valid"] and item["first_violation"] for item in items)
    model = Stub("M", "seed 0", seed=0)
    values = k2.k2_values(doc, found, models={0: model},
                          methods=[Stub("Z1"), Stub("Z2"), Stub("Z3"), Stub("Z4", "load"), Stub("Z4", "residual"),
                                   Stub("Z5")],
                          calibration=roles["calibration"].windows,
                          clean=np.ones(len(roles["calibration"].windows), dtype=bool), budget=0, mode="campaign")
    assert values["status"] == "nevyhodnotené" and values["evaluated"] == []
    assert {cls: (c["evaluable"], c["volume"], c["status"]) for cls, c in values["classes"].items()} == {
        "C": (0, 36, "nevyhodnotené"), "D": (0, 36, "nevyhodnotené")}
    assert values["volume"]["C"]["count"] == 36 and len(values["volume"]["D"]["ids"]) == 36
    assert {n: cell["count"] for n, cell in values["volume"]["C"]["lengths"].items()} == {
        str(n): sum(item["class"] == "C" and item["length"] == n for item in items) for n in (3, 6)}
    decided = k2.k2(decision_protocol(None), values, mode="campaign")
    assert {claim: (r["status"], r["outcome"]) for claim, r in decided.items()} == {
        "k2a": ("nevyhodnotené", None), "k2b": ("nevyhodnotené", None)}


@pytest.mark.parametrize("evaluable, status", [(7, "nevyhodnotené"), (8, "evaluated")])
def test_fewer_than_eight_evaluable_give_nevyhodnotene(evaluable, status):
    """class_status: the denominator is the planned count; a class with fewer than min_evaluable (8) evaluable
    interventions is nevyhodnotené (proposal 6.4), the volume and the not placed ones counted apart."""
    from tcn.k2 import class_status
    items = ([{"class": "C", "status": "evaluable"}] * evaluable + [{"class": "C", "status": "volume"}] * 2
             + [{"class": "C", "status": "not_placed"}] + [{"class": "D", "status": "evaluable"}] * 8)
    assert class_status(items, 8) == {
        "C": {"planned": evaluable + 3, "evaluable": evaluable, "volume": 2, "not_placed": 1, "status": status},
        "D": {"planned": 8, "evaluable": 8, "volume": 0, "not_placed": 0, "status": "evaluated"}}


# ------------------------------------------------------------------ shares, D and the names of compare (K2_RULE)


class Stub:
    """A method of the interface whose score is 1 in the horizon of the interventions it is told to detect and 0
    everywhere else, calibration included (its matched threshold is then 0 at any budget)."""
    kind = "detector"

    def __init__(self, name, variant=None, *, seed=None, hits=()):
        self.name, self.variant, self.hits, self.plans = name, variant, set(hits), []
        if seed is not None:
            self.seed = seed

    @property
    def label(self):
        return self.name if self.variant is None else f"{self.name}:{self.variant}"

    def scores(self, windows):
        out = np.zeros(len(windows))
        for plan in self.plans:
            if windows is plan.copies:
                for ident in self.hits & set(plan.horizons):
                    out[plan.horizons[ident]] = 1.
        return out


def test_the_shares_per_boot_and_d_against_every_compared_method():
    """SHARE_RULE and K2_RULE by hand: the share of a boot is its detected evaluable interventions over the planned
    ones, M's the median of its seeds, D = M - Z per boot; Z4:load and Z4:residual are two comparisons of K2a (Q13),
    every intervention of the table counted once."""
    from tcn import k2
    roles = generated()
    found = plans(roles, protocol(("analysis.seeds", [0, 1, 2])))
    items = [item for role in ("test_benign", "test_controls") for item in found[role].interventions]
    every = [item["id"] for item in items if item["status"] == "evaluable"]
    first = {item["boot"]: item["id"] for item in reversed(items) if item["status"] == "evaluable"}
    seeds = [Stub("M", "seed 0", seed=0, hits=every), Stub("M", "seed 1", seed=1, hits=every[::2]),
             Stub("M", "seed 2", seed=2, hits=())]
    z = [Stub("Z1", "value", hits=first.values()), Stub("Z2"), Stub("Z3", "last"), Stub("Z4", "load", hits=every),
         Stub("Z4", "residual"), Stub("Z5", "ridge(1.0)")]
    for method in seeds + z:
        method.plans = list(found.values())
    doc = protocol(("analysis.seeds", [0, 1, 2]), ("analysis.k2a.compare", ["Z1", "Z2", "Z4:load", "Z4:residual"]))
    calibration = roles["calibration"].windows
    values = k2.k2_values(doc, found, models=dict(enumerate(seeds)), methods=z, calibration=calibration,
                          clean=np.ones(len(calibration), dtype=bool), budget=0, mode="campaign")
    assert values["compare"] == {"k2a": {"Z1": "Z1:value", "Z2": "Z2", "Z4:load": "Z4:load",
                                         "Z4:residual": "Z4:residual"}, "k2b": {"Z3": "Z3:last", "Z5": "Z5:ridge(1.0)"}}
    for boot in values["boots"]:
        mine = [item for item in items if item["boot"] == boot]
        share = {name: sum(item["id"] in hits for item in mine) / len(mine)
                 for name, hits in (("M0", set(every)), ("M1", set(every[::2])), ("Z1", {first[boot]}))}
        assert values["model"]["median"][boot] == pytest.approx(share["M1"])  # The median of three seeds.
        assert values["values"]["k2a"]["Z1"][boot] == pytest.approx(share["M1"] - share["Z1"])
        assert values["values"]["k2a"]["Z4:load"][boot] == pytest.approx(share["M1"] - share["M0"])
        assert values["values"]["k2b"]["Z5"][boot] == pytest.approx(share["M1"])
    assert sum(row["planned"] for row in values["table"]) == len(items) == 72
    assert all(values["thresholds"][label]["threshold"] == 0 for label in values["thresholds"])
    assert json.loads(json.dumps(values))["values"] == json.loads(json.dumps(values["values"]))  # A JSON record.


def to_volume(items, cls, keep):
    """Every evaluable intervention of class `cls` but the first `keep` goes to the volume class (its status in the
    plan's record; its copy and its horizon stay): the ids of those moved."""
    mine = [item for item in items if item["class"] == cls and item["status"] == "evaluable"]
    assert len(mine) > keep
    for item in mine[keep:]:
        item["status"] = "volume"
    return [item["id"] for item in mine[keep:]]


ALSO_COMPARED = ("Z2", "Z3", ("Z4", "load"), ("Z4", "residual"), "Z5")  # The methods that detect nothing here.


def stubs(found, **hits):
    """M of seed 0 and Z1 detecting the interventions given (hits M=..., Z1=...), the other methods none."""
    model = Stub("M", "seed 0", seed=0, hits=hits.get("M", ()))
    methods = [Stub("Z1", hits=hits.get("Z1", ())), *(Stub(*([m] if type(m) is str else m)) for m in ALSO_COMPARED)]
    for method in (model, *methods):
        method.plans = list(found.values())
    return model, methods


def test_a_class_below_the_minimum_stays_pooled_in_k2():
    """POOL_RULE (skeleton section 9: D is computed from every intervention of both classes; F1 of the verification of
    B7b, the verifier's probe_one_class2): class C keeps 7 evaluable interventions (nevyhodnotené), D is evaluated; M
    detects every evaluable one of D and Z1 every evaluable one of C. The share of a boot is over every planned
    intervention of both classes (the volume ones and those not placed in the denominator, never a success), so D
    against Z1 per boot is M's detections of D minus Z1's of C over the boot's planned interventions; the status of C
    is kept in the record and in the table by class and length, and K2a and K2b are decided on the pooled values."""
    from tcn import k2
    roles = generated()
    found = plans(roles)
    items = [item for role in ("test_benign", "test_controls") for item in found[role].interventions]
    to_volume(items, "C", 7)
    evaluable = {cls: [item["id"] for item in items if item["class"] == cls and item["status"] == "evaluable"]
                 for cls in ("C", "D")}
    model, methods = stubs(found, M=evaluable["D"], Z1=evaluable["C"])
    calibration = roles["calibration"].windows
    values = k2.k2_values(protocol(), found, models={0: model}, methods=methods, calibration=calibration,
                          clean=np.ones(len(calibration), dtype=bool), budget=0, mode="campaign")
    assert {cls: c["status"] for cls, c in values["classes"].items()} == {"C": "nevyhodnotené", "D": "evaluated"}
    assert (values["classes"]["C"]["evaluable"], values["classes"]["C"]["planned"]) == (7, 36)
    assert (values["status"], values["evaluated"], values["pooled"]) == ("evaluated", ["D"], ["C", "D"])
    for boot in values["boots"]:
        mine = [item for item in items if item["boot"] == boot]
        assert len(mine) == 12  # Six of each class.
        share = {cls: sum(item["id"] in evaluable[cls] for item in mine) / len(mine) for cls in ("C", "D")}
        assert values["model"]["median"][boot] == pytest.approx(share["D"])
        assert values["shares"]["Z1"][boot] == pytest.approx(share["C"])
        assert values["values"]["k2a"]["Z1"][boot] == pytest.approx(share["D"] - share["C"])
        assert values["values"]["k2b"]["Z5"][boot] == pytest.approx(share["D"])
    assert {(row["class"], row["class_status"]) for row in values["table"]} == {
        ("C", "nevyhodnotené"), ("D", "evaluated")}
    # The detection of the diagnostics (tcn.k2.detection) pools the classes alike: M's shares at its threshold here.
    found_by_m = k2.detection(found, protocol=protocol())(model, .5, K, N)
    assert (found_by_m["evaluated"], found_by_m["pooled"]) == (["D"], ["C", "D"])
    assert found_by_m["shares"] == {boot: pytest.approx(value) for boot, value in values["shares"]["M:seed 0"].items()}
    decided = k2.k2(decision_protocol(0.1), values, mode="campaign")
    for claim in ("k2a", "k2b"):
        assert (decided[claim]["status"], decided[claim]["classes_pooled"]) == ("evaluated", ["C", "D"])
        assert decided[claim]["classes"] == values["classes"]
    assert decided["k2a"]["methods"]["Z1"]["values"] == {boot: pytest.approx(value) for boot, value
                                                         in values["values"]["k2a"]["Z1"].items()}


def test_a_detected_intervention_of_the_volume_class_is_no_success():
    """SHARE_RULE (proposal 6.4: an intervention of the volume class is never a success of its class): five evaluable
    interventions of D go to the volume class (D stays evaluated); M and Z1 detect every placed intervention, the
    volume ones too. A share counts the evaluable ones only, over every planned one; the volume class reports what
    each method detects there apart (mutant K2_volume_counts of the verification of B7b)."""
    from tcn import k2
    roles = generated()
    found = plans(roles)
    items = [item for role in ("test_benign", "test_controls") for item in found[role].interventions]
    moved = to_volume(items, "D", len([i for i in items if i["class"] == "D" and i["status"] == "evaluable"]) - 5)
    every = [item["id"] for item in items if item["placed"]]
    model, methods = stubs(found, M=every, Z1=every)
    calibration = roles["calibration"].windows
    values = k2.k2_values(protocol(), found, models={0: model}, methods=methods, calibration=calibration,
                          clean=np.ones(len(calibration), dtype=bool), budget=0, mode="campaign")
    assert values["classes"]["D"]["status"] == "evaluated" and values["classes"]["D"]["volume"] >= 5
    for boot in values["boots"]:
        mine = [item for item in items if item["boot"] == boot]
        share = sum(item["status"] == "evaluable" for item in mine) / len(mine)
        assert values["model"]["median"][boot] == pytest.approx(share) == values["shares"]["Z1"][boot]
    volume = values["volume"]["D"]
    assert set(moved) <= set(volume["ids"]) and volume["detected"]["M:seed 0"] == volume["count"]
    for row in values["table"]:
        assert row["shares"]["M:seed 0"] == pytest.approx(row["evaluable"] / row["planned"])


def test_k2_of_the_campaign_takes_exactly_the_boots_of_the_protocol():
    """k2_values in mode campaign: the carrier roles hold exactly analysis.interventions.boots boots (20 in the file;
    6 in these tests), so plans of 6 boots under a protocol of 8 are refused; the rehearsal holds fewer groups and is
    not checked (mutant K10 of the verification of B7b)."""
    from tcn import k2
    roles = generated()
    calibration = roles["calibration"].windows
    doc = protocol(("analysis.interventions.boots", 8))
    model, methods = stubs(plans(roles))
    with pytest.raises(ValueError, match=r"^the carrier roles hold 6 boots, analysis\.interventions\.boots is 8$"):
        k2.k2_values(doc, plans(roles), models={0: model}, methods=methods, calibration=calibration,
                     clean=np.ones(len(calibration), dtype=bool), budget=0, mode="campaign")
    rehearsal = plans(roles, mode="rehearsal")
    model, methods = stubs(rehearsal)
    values = k2.k2_values(doc, rehearsal, models={0: model}, methods=methods, calibration=calibration,
                          clean=np.ones(len(calibration), dtype=bool), budget=0, mode="rehearsal")
    assert (values["mode"], len(values["boots"])) == ("rehearsal", 6)


class Edge:
    """A method whose score is 1 at three windows of every copy, the third `offset` windows after the window that
    ends at the block's first row, and 0 elsewhere: an alarm (3 of 5) begins exactly there."""
    name, kind = "edge", "detector"

    def __init__(self, plan, offset):
        self.plan, self.offset = plan, offset

    def scores(self, windows):
        out = np.zeros(len(windows))
        if windows is self.plan.copies:
            for horizon in self.plan.horizons.values():
                at = horizon[0] + self.offset
                out[at - 2:at + 1] = 1.
        return out


@pytest.mark.parametrize("offset, detected", [
    (-1, False),  # The alarm begins at the window before the block's first row: it is no detection.
    (0, True),    # At the window that ends at the block's first row (t).
    (12, True),   # At t + horizon_s exactly (60 s, 12 rows): the horizon is closed.
    (13, False),  # One row after it.
])
def test_an_alarm_detects_within_the_closed_horizon_from_the_block(offset, detected):
    """DETECTION_RULE: an alarm detects an intervention when it begins at a window of the copy whose last row lies in
    [t, t + analysis.horizon_s]; an alarm up from before the block detects nothing."""
    from tcn import k2
    doc = protocol(("analysis.interventions.C.lengths", [12]), ("analysis.interventions.D.lengths", [12]))
    plan = plans(generated(), doc)["test_benign"]
    assert all(len(h) == 13 for h in plan.horizons.values())  # Rows t, t + 5 s, ..., t + 60 s.
    found = k2.detect(Edge(plan, offset), .5, plan, k=K, n=N)
    assert set(found.values()) == {detected}


@pytest.mark.parametrize("compare, methods, reason", [
    (["Z1", "Z2", "Z4"], ("load", "residual"),
     r"^analysis\.k2a\.compare names Z4, of which 2 methods are given \(Z4:load, Z4:residual\): name the variant "
     r"\(question Q13: Z4:load and Z4:residual\)$"),
    (["Z1", "Z2", "Z4:residual"], ("load",),
     r"^analysis\.k2a\.compare names Z4:residual, which is not among the methods given \(Z1, Z2, Z3, Z5, Z4:load\)$"),
])
def test_the_names_of_compare_name_one_method_each(compare, methods, reason):
    from tcn import k2
    roles = generated()
    found = plans(roles)
    z = [Stub("Z1"), Stub("Z2"), Stub("Z3"), Stub("Z5"), *(Stub("Z4", v) for v in methods)]
    calibration = roles["calibration"].windows
    with pytest.raises(ValueError, match=reason):
        k2.k2_values(protocol(("analysis.k2a.compare", compare)), found, models={0: Stub("M", "seed 0", seed=0)},
                     methods=z, calibration=calibration, clean=np.ones(len(calibration), dtype=bool), budget=0,
                     mode="campaign")


@pytest.mark.parametrize("call, reason", [
    ("dev", r"^K2 takes the plans of exactly test_benign and test_controls; the interventions of dev select Z1 and "
            r"never enter K2$"),
    ("seeds", r"^models gives M of exactly the seeds analysis\.seeds \[0\] \(M enters by their median, D14\)$"),
    ("random", r"^the random variant of Z0 draws the numbers of a whole window set, so a copy would get other numbers "
               r"than its session: it detects no intervention \(Z0 is in no comparison of K2\)$"),
])
def test_k2_refuses_what_it_does_not_take(call, reason):
    from tcn import k2, zasahy
    roles = generated()
    found = plans(roles)
    models, methods = {0: Stub("M", "seed 0", seed=0)}, [Stub("Z1"), Stub("Z2"), Stub("Z3"), Stub("Z4"), Stub("Z5")]
    if call == "dev":
        doc = protocol()
        found = {"dev": zasahy.plan(roles["dev"], protocol=doc, mode="campaign",
                                    ranges=zasahy.train_ranges(roles["train"].windows, doc),
                                    donors={"train": roles["train"]})}
    elif call == "seeds":
        models = {1: Stub("M", "seed 1", seed=1)}
    else:
        methods.append(Stub("Z0", "random"))
    calibration = roles["calibration"].windows
    with pytest.raises(ValueError, match=reason):
        k2.k2_values(protocol(), found, models=models, methods=methods, calibration=calibration,
                     clean=np.ones(len(calibration), dtype=bool), budget=0, mode="campaign")


# ------------------------------------------------------------------ K2 on the generators with a known answer


def trained_m(roles):
    """A stand-in of M: the predictor of analysis.architecture's TCN on the synthetic inputs, trained by
    safeguard.training's own loop (_train_predictor: Adam, the clip, batches of 32) for 12 epochs at a learning rate of
    0.02 (test only: a fast run), in a bundle whose threshold is the 0.99 quantile of its calibration scores (fpr
    0.01); MetodaM of it, seed 0."""
    from safeguard.bundle import Bundle
    from safeguard.model import architecture
    from safeguard.training import _train_predictor
    from tcn.metody import MetodaM
    windows = roles["train"].windows
    config = architecture(WINDOW, global_features=len(windows.input_names))
    parameters = {"learning_rate": .02, "gradient_clip": 5, "batch_size": 32, "seed": 0,
                  "stopping": {"max_epochs": 12, "patience_epochs": None, "repeat_if_last_epoch": None}}
    predictor, _, _ = _train_predictor(config, {"train": windows, "dev": roles["dev"].windows}, parameters)
    manifest = {"feature_contract": {"window_rows": WINDOW, "max_gap_s": GAP},
                "calibration": {"threshold": 0., "k": K, "n": N}, "training": {"seed": 0}}
    model = MetodaM(Bundle(manifest, predictor, None, windows.normalizer))
    manifest["calibration"]["threshold"] = float(np.quantile(model.scores(roles["calibration"].windows), .99))
    return model


@pytest.mark.parametrize("structured, outcomes", [
    (True, {"better"}),
    (False, {"not_better", "undecided"}),
])
def test_k2_without_structure_is_not_better_and_with_structure_better(structured, outcomes):
    """The whole chain on tcn.k2.known_answer (GENERATOR_RULE), one seed of each generator: M trained on train, Z1
    selected by the interventions inserted into dev (its criterion), Z2, Z3, Z4 and Z5 fitted, the budget of M on
    calibration and every threshold matched to it, the interventions of test_benign and test_controls detected,
    and K2a and K2b decided by tcn.tvrdenia.rozhodni at m = 0.1 (judgment for this run: G1 sets m from at least 20
    structure-free seeds) against the methods that config/collection-v5.json compares (Z4 by the variants it names,
    question Q13). The negative case decides (skeleton section 9): without structure every method detects about as
    rarely as the others."""
    from tcn import k2, zasahy
    from tcn.metody import Z1, Z2, Z3, Z4, Z5, model_budget
    roles = generated(structured)
    decision = decision_protocol(0.1)
    compare = {claim: decision["analysis"][claim]["compare"] for claim in ("k2a", "k2b")}
    doc = protocol(*((f"analysis.{claim}.compare", names) for claim, names in compare.items()))
    variants = [name.split(":")[1] for name in compare["k2a"] if name.startswith("Z4:")] or ["residual"]
    model = trained_m(roles)
    calibration = roles["calibration"].windows
    clean = np.ones(len(calibration), dtype=bool)
    # BUDGET_RULE of tcn.metody: M at exactly analysis.seeds (the merge of B7b: model_budget takes the protocol).
    budget = model_budget([model], calibration, clean, protocol=doc)["budget"]
    ranges = zasahy.train_ranges(roles["train"].windows, doc)
    dev = zasahy.plan(roles["dev"], protocol=doc, mode="campaign", ranges=ranges, donors={"train": roles["train"]})
    criterion = k2.z1_criterion(dev, calibration, clean, budget, protocol=doc)
    methods = [Z1(criterion), Z2(), Z3(), *(Z4(variant) for variant in variants), Z5()]
    for method in methods:
        method.fit(roles["train"].windows, roles["dev"].windows, protocol=doc, seed=0)
    values = k2.k2_values(doc, plans(roles, doc), models={0: model}, methods=methods, calibration=calibration,
                          clean=clean, budget=budget, mode="campaign")
    assert values["status"] == "evaluated" and values["evaluated"] == ["C", "D"]
    decided = k2.k2(decision, values, mode="campaign")
    assert {decided["k2a"]["outcome"], decided["k2b"]["outcome"]} <= outcomes
    assert (decided["k2a"]["compare"], decided["k2b"]["compare"]) == (compare["k2a"], compare["k2b"])
    assert decided["k2a"]["boots"] == sorted(values["boots"]) and len(values["boots"]) == 6


# ------------------------------------------------------------------ Z1's criterion on dev (skeleton sections 2 and 9)


def test_z1_is_selected_by_the_share_of_the_interventions_inserted_into_dev():
    """CRITERION_RULE: the criterion of a candidate is the share of the interventions of dev (donors of train) that it
    detects at its matched threshold, detected and evaluable over planned; Z1(criterion) records it for every candidate
    of its grid; a window set other than the plan's dev is refused."""
    from tcn import k2, zasahy
    from tcn.metody import Z1
    roles = generated()
    doc = protocol()
    dev = zasahy.plan(roles["dev"], protocol=doc, mode="campaign", ranges=zasahy.train_ranges(roles["train"].windows,
                                                                                              doc),
                      donors={"train": roles["train"]})
    assert {item["donor"]["role"] for item in placed(dev, "D")} == {"train"}
    calibration = roles["calibration"].windows
    criterion = k2.z1_criterion(dev, calibration, np.ones(len(calibration), dtype=bool), 0, protocol=doc)
    evaluable = [item["id"] for item in dev.interventions if item["status"] == "evaluable"]
    stub = Stub("Z1", "value", hits=evaluable[:5])
    stub.plans = [dev]
    assert criterion(stub, roles["dev"].windows) == pytest.approx(5 / len(dev.interventions))
    with pytest.raises(ValueError, match=r"^Z1's criterion takes the window set of dev its interventions were placed "
                                         r"in$"):
        criterion(stub, roles["train"].windows)
    record = Z1(criterion).fit(roles["train"].windows, roles["dev"].windows, protocol=doc, seed=0)
    assert record["criterion"] == "share_of_dev_interventions_detected"
    assert [c["statistic"] for c in record["candidates"]] == ["value", "difference", "moving_average", "cusum"]
    assert all(0 <= c["criterion"] <= 1 for c in record["candidates"])
    with pytest.raises(ValueError, match=r"^Z1 is selected by the interventions inserted into dev \(a plan of role "
                                         r"dev\)$"):
        k2.z1_criterion(plans(roles)["test_benign"], calibration, np.ones(len(calibration), dtype=bool), 0,
                        protocol=doc)


def test_z1s_criterion_pools_a_class_of_dev_below_the_minimum():
    """CRITERION_RULE and POOL_RULE (F1 of the verification of B7b): with class C of dev below min_evaluable (7
    evaluable) and D evaluated, the criterion of a candidate is its evaluable interventions of both classes detected
    over every planned intervention of dev, C included; with no class of dev evaluated Z1 has no criterion."""
    from tcn import k2, zasahy
    roles = generated(boots={"train": 2, "dev": 3, "calibration": 2, "test_benign": 3, "test_controls": 3})
    doc = protocol()
    dev = zasahy.plan(roles["dev"], protocol=doc, mode="campaign",
                      ranges=zasahy.train_ranges(roles["train"].windows, doc), donors={"train": roles["train"]})
    to_volume(dev.interventions, "C", 7)
    calibration = roles["calibration"].windows
    clean = np.ones(len(calibration), dtype=bool)
    criterion = k2.z1_criterion(dev, calibration, clean, 0, protocol=doc)
    assert criterion.classes == ["C", "D"]
    assert {cls: status["status"] for cls, status in criterion.status.items()} == {"C": "nevyhodnotené",
                                                                                   "D": "evaluated"}
    evaluable = [item["id"] for item in dev.interventions if item["status"] == "evaluable"]
    for hits in (evaluable, [i for i in evaluable if "/C/" in i]):
        stub = Stub("Z1", "value", hits=hits)
        stub.plans = [dev]
        assert criterion(stub, roles["dev"].windows) == pytest.approx(len(hits) / len(dev.interventions))
    to_volume(dev.interventions, "D", 7)
    with pytest.raises(ValueError, match=r"^no class of the interventions of dev has "
                                         r"analysis\.interventions\.min_evaluable evaluable ones: Z1 has no "
                                         r"criterion$"):
        k2.z1_criterion(dev, calibration, clean, 0, protocol=doc)


# ------------------------------------------------------------------ the keys of design 1.4 and the stream


def test_the_keys_of_design_1_4_are_read_by_one_accessor():
    from tcn.zasahy import protocol_keys
    keys = protocol_keys(protocol())
    assert keys["classes"] == {"C": {"lengths": [3, 6], "per_boot": 6, "orders": ["reversed", "random"]},
                               "D": {"lengths": [3, 6], "per_boot": 6, "groups": GROUPS}}
    assert (keys["quantiles"], keys["moving_average_rows"], keys["min_evaluable"], keys["horizon_s"],
            keys["boots"]) == ([0.001, 0.999], 4, 8, 60., 6)


@pytest.mark.parametrize("path, value, reason", [
    ("analysis.interventions.C.orders", DELETE,
     r"^protocol key analysis\.interventions\.C\.orders is missing \(design B7b 1\.4\)$"),
    ("analysis.interventions.C.orders", ["reversed", "sideways"],
     r"^analysis\.interventions\.C\.orders must be a non-empty list of distinct order variants of reversed and "
     r"random$"),
    ("analysis.interventions.C.lengths", [1, 6],
     r"^analysis\.interventions\.C\.lengths must be a non-empty list of distinct integers of at least 2$"),
    ("analysis.interventions.D.per_boot", 0,
     r"^analysis\.interventions\.D\.per_boot must be an integer of at least 1$"),
    ("analysis.interventions.D.groups", {"a": ["mem_changed_ratio"], "b": ["mem_changed_ratio", "proc_new"]},
     r"^analysis\.interventions\.D\.groups\.b: the groups share no column \(D swaps one group against the others\)$"),
    ("analysis.interventions.D.groups", {"a": ["mem_changed_ratio", "kernel_hooks"]},
     r"^analysis\.interventions\.D\.groups\.a must be a non-empty list of distinct columns of "
     r"features\.archive\.BEHAVIOR_NAMES and channels of a bin$"),
    ("analysis.interventions.D.groups", {"a": ["mem_changed_ratio", "changed_ratio", "zero_ratio"]},
     r"^analysis\.interventions\.D\.groups\.a: the four channels of a bin changed_ratio, zero_ratio, entropy_mean, "
     r"has_changed lie in one group \(a bin stays whole\)$"),
    ("analysis.interventions.validity.quantiles", [0.999, 0.001],
     r"^analysis\.interventions\.validity\.quantiles must be \[lo, hi\] with 0 <= lo < hi <= 1$"),
    ("analysis.interventions.validity.moving_average_rows", 9,
     r"^analysis\.interventions\.validity\.moving_average_rows must be an integer of at least 1 and at most "
     r"window_rows$"),
    ("analysis.interventions.min_evaluable", 0,
     r"^analysis\.interventions\.min_evaluable must be an integer of at least 1$"),
    ("analysis.interventions.volume_class", " ",
     r"^analysis\.interventions\.volume_class must be the rule of the volume class, a non-empty text$"),
    ("analysis.horizon_s", 0, r"^analysis\.horizon_s must be a positive number$"),
    ("analysis.evaluable.first_s", 90,
     r"^analysis\.evaluable\.first_s must be a positive number of at most analysis\.horizon_s: a placed intervention "
     r"has every window of its horizon, so its first first_s seconds are scored$"),
])
def test_a_malformed_key_of_design_1_4_is_refused_by_name(path, value, reason):
    from tcn.zasahy import protocol_keys
    with pytest.raises(ValueError, match=reason):
        protocol_keys(protocol((path, value)))


@pytest.mark.parametrize("mode, name", [("campaign", "v5-test"), ("rehearsal", "v5-test-generalka")])
def test_the_stream_injections_is_drawn_per_role_and_class(mode, name):
    """UNIT_RULE: the seed of each unit is streams.rule's for a purpose of the analysis (scripts/protocol_v5.py seed
    with the plan's name in this mode, the unit as group, session -1 and attempt 0); the units of test_benign are
    <role>/<class>, dev has one unit; the same inputs give the same plan; a protocol without the stream is refused."""
    from scripts.protocol_v5 import seed
    from tcn import zasahy
    roles = generated()
    first, again = plans(roles, mode=mode)["test_benign"], plans(roles, mode=mode)["test_benign"]
    assert first.record()["stream_seeds"] == {unit: seed(name, "injections", unit, -1, 0)
                                              for unit in ("test_benign/C", "test_benign/D")}
    assert json.dumps(first.record()) == json.dumps(again.record())
    assert zasahy.units("dev") == {"C": "dev", "D": "dev"}
    with pytest.raises(ValueError, match=r"^streams\.purposes has no injections: the stream of the interventions "
                                         r"\(design B7b 1\.4\)$"):
        plans(roles, protocol(("streams.purposes", ["traffic", "z0_alarms", "bootstrap"])), mode=mode)


@pytest.mark.parametrize("donors, reason", [
    ("train", r"^the donors of test_benign are the carriers of exactly the roles test_benign, test_controls "
              r"\(DONOR_RULE\)$"),
    ("copy", r"^the donors of role test_benign are its own carriers \(the same object\)$"),
])
def test_the_donors_are_those_of_the_donor_roles(donors, reason):
    from tcn import zasahy
    roles = generated()
    doc = protocol()
    given = {"train": roles["train"]} if donors == "train" else {
        "test_benign": zasahy.Carriers(roles["test_benign"].windows, roles["test_benign"].placeable,
                                       roles["test_benign"].meta),
        "test_controls": roles["test_controls"]}
    with pytest.raises(ValueError, match=reason):
        zasahy.plan(roles["test_benign"], protocol=doc, mode="campaign",
                    ranges=zasahy.train_ranges(roles["train"].windows, doc), donors=given)


def test_a_group_without_a_tcn_input_is_left_out_and_recorded():
    """D_RULE: a group whose columns are all outside the TCN inputs (here modules and sockets, in the rule channel) is
    left out with the class of each column, and the deal takes the other groups; no group left is refused."""
    roles = generated()
    plan = plans(roles)["test_benign"]
    why = "no column is a TCN input under rule analysis.columns"
    assert plan.record()["groups"]["left_out"] == [
        {"name": "modules", "columns": {"mod_total": "rule", "mod_delta": "rule"}, "why": why},
        {"name": "sockets", "columns": {"sock_total": "rule", "sock_listen": "rule", "sock_estab": "rule"}, "why": why}]
    assert [(g["name"], g["bins"]) for g in plan.record()["groups"]["used"]] == [("memory", True), ("processes", False)]
    assert {item["group"] for item in plan.interventions if item["class"] == "D"} == {"memory", "processes"}
    with pytest.raises(ValueError, match=r"^no group of analysis\.interventions\.D\.groups has a TCN input or the bins "
                                         r"under rule analysis\.columns: class D has nothing to swap$"):
        plans(roles, protocol(("analysis.interventions.D.groups", {"modules": GROUPS["modules"]})))


# ------------------------------------------------------------------ the merge of B7b (agent F)


def test_the_units_of_the_interventions_are_those_of_the_protocol():
    """The units of the stream injections of tcn/zasahy.py are scripts/protocol_v5.py INJECTION_UNITS, and the stream
    goes through protocol_v5.analysis_seed, which refuses a unit outside them (a role without interventions)."""
    from scripts import protocol_v5
    from tcn import zasahy
    assert sorted({unit for role in (*zasahy.CARRIER_ROLES, zasahy.DEV_ROLE) for unit in zasahy.units(role).values()}
                  ) == sorted(protocol_v5.INJECTION_UNITS)
    assert (zasahy.CLASSES, zasahy.ORDERS, zasahy.MIN_LENGTH) == (
        protocol_v5.INTERVENTION_CLASSES, protocol_v5.ORDERS, protocol_v5.MIN_BLOCK_ROWS)
    with pytest.raises(ValueError, match=r"^'calibration/C' is no unit of the analysis stream injections "):
        zasahy._stream(protocol(), "calibration/C", "campaign")


def test_the_diagnostics_take_the_detection_of_the_interventions():
    """tcn.k2.detection(plans, protocol=) is the function (method, threshold, k, n) -> its record that
    tcn/diagnostiky.py alarm_rules and clean_threshold call at every threshold: a method that scores every evaluable
    intervention's horizon (M here) detects them all at each rule k of n of analysis.diagnostics.alarm_rules and at
    both thresholds, so its share is evaluable over planned (SHARE_RULE); a method that never scores (Z1 here) detects
    none."""
    from tcn import diagnostiky, k2
    from tcn.metody import traffic
    roles = generated()
    doc = protocol(("analysis.diagnostics.contexts", [1, 2, 4, 7]))
    found = plans(roles, doc)
    items = [item for plan in found.values() for item in plan.interventions]
    evaluable = [item["id"] for item in items if item["status"] == "evaluable"]
    model, never = Stub("M", "seed 0", seed=0, hits=evaluable), Stub("Z1", "value")
    model.threshold = .5
    for method in (model, never):
        method.plans = list(found.values())
    detection = k2.detection(found, protocol=doc)
    quiet = {role: traffic(roles[role].windows, {ident: [] for ident in roles[role].windows.session_ids}, doc)
             for role in ("calibration", "test_benign")}
    calibration = roles["calibration"].windows
    rules = diagnostiky.alarm_rules([model], [never], calibration, quiet["calibration"], protocol=doc,
                                    roles={"test_benign": (roles["test_benign"].windows, quiet["test_benign"])},
                                    detection=detection)
    thresholds = diagnostiky.clean_threshold([model], [never], calibration, quiet["calibration"], protocol=doc,
                                             roles={}, detection=detection)
    rows = [(row["seeds"][0], row["methods"][0]) for row in rules["rules"]]
    rows += [(variant["seeds"][0], variant["methods"][0]) for variant in thresholds["variants"]]
    evaluated = detection(model, .5, K, N)["evaluated"]
    planned = [item for item in items if item["class"] in evaluated]
    assert evaluated == ["C", "D"] and len(rows) == 5
    for seed, method in rows:
        assert (seed["detection"]["status"], seed["detection"]["label"]) == ("evaluated", "M:seed 0")
        assert seed["detection"]["share"] == pytest.approx(
            sum(item["status"] == "evaluable" for item in planned) / len(planned))
        assert (method["detection"]["label"], method["detection"]["share"]) == ("Z1:value", 0)
    assert [(row["k"], row["n"]) for row in rules["rules"]] == [(2, 3), (3, 5), (4, 7)]
    json.dumps({"rules": rules, "thresholds": thresholds}, allow_nan=False)
