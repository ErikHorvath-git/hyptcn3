"""Protocol schema 3: the acceptance rule must be reachable (the v4 rule was not).

Expectations are counted here from first principles (window_count, worst_windows) and never by a product
function; the loader is reached only through collection.protocol(path).
"""
from functools import lru_cache
from itertools import combinations, product
import json
import math
from pathlib import Path

import pytest

from features.coverage import scorable_windows
from features.quality import tolerated_invalid_rows
from features.tests.test_coverage import data
from safeguard.tests.test_features import sample
from scripts import collection

ROOT = Path(__file__).resolve().parents[2]
V4 = ROOT / "config/collection-v4.json"
SCHEMA = "hyptcn3/collection-protocol/"
BEHAVIOR = "behavioral-inputs-v1"
CLEAN = "score coverage gate is unreachable for "
WORST = "invalid_rows.max is unreachable under the score coverage gate"
DEFAULT_GATE = 17 / 20  # what protocol versions 1 and 2 mean without min_score_coverage
# Since package B7b the loader refuses a schema-3 window under 2 rows; since package B10 by naming window_rows (the
# grid's one such window has 1 row).
ANALYSIS = ("invalid window_rows: 1, protocol schema 3 needs an integer of at least 2 rows, the target and one row of "
            "context (analysis.interventions.validity.moving_average_rows lies in [2, window_rows], "
            "analysis.diagnostics.contexts in [1, window_rows - 1])")


def window_count(rows, window_rows, full_every, invalid=()):
    """Oracle: per chain, every maximal run of valid rows ends max(0, len(run) - window_rows) windows."""
    total = 0
    for start in range(0, rows, full_every):
        run = 0
        for seq in range(start, min(start + full_every, rows)):
            if seq in invalid:
                total, run = total + max(0, run - window_rows), 0
            else:
                run += 1
        total += max(0, run - window_rows)
    return total


@lru_cache(maxsize=None)
def worst_windows(rows, window_rows, full_every, count):
    """Brute force: the fewest windows left by any placement of `count` invalid rows (all rows when fewer)."""
    return min(window_count(rows, window_rows, full_every, set(seq))
               for seq in combinations(range(rows), min(count, rows)))


def worst_by_chains(rows, window_rows, full_every, count):
    """The same brute force for longer sessions: chains are counted apart, so try every split of the rows."""
    chains = [min(full_every, rows - start) for start in range(0, rows, full_every)]
    return min(sum(worst_windows(n, window_rows, n, k) for n, k in zip(chains, split))
               for split in product(range(count + 1), repeat=len(chains))
               if sum(split) == count and all(k <= n for n, k in zip(chains, split)))


def sections(interval_s):
    """The audit and exceptions sections schema 3 requires since package B3 (bounds scaled to the interval)."""
    from scripts.tests.boundary_sessions import audit_sections
    return audit_sections(interval_s)


def v5(doc, max_per_campaign=0):
    """The sections a schema-3 document takes from config/collection-v5.json since package B4 (schema 3 is the v5
    layout): for the document's scenarios, roles and window (scripts/tests/boundary_sessions.py v5_sections)."""
    from scripts.tests.boundary_sessions import v5_sections
    return v5_sections(list(doc.get("scenarios", {"steady": None})), doc.get("roles", {}),
                       group_sessions=len(doc.get("scenarios", {"steady": None})), window_rows=doc["window_rows"],
                       max_per_campaign=max_per_campaign)


def schema3(tmp_path, **changes):
    """The v4 protocol under schema 3, as a v5 document: the v4 grid, gate, rule, VMs, roles and scenario names
    with the v5 sections (no event planned; the v4 replacement limit). Schema 3 has no field status (question Q23,
    the fix of B9b), so the v4 file's status pilot_required is left out."""
    doc = {key: value for key, value in json.loads(V4.read_text()).items() if key != "status"}
    doc.update(schema=SCHEMA + "3", **v5(doc, doc["replacement"]["max_per_campaign"]), **sections(doc["interval_s"]),
               **changes)
    path = tmp_path / "p.json"
    path.write_text(json.dumps(doc))
    return path


def unclosed(valid):
    """Quality of a row; an invalid one only lacks a closed process traversal, the cause invalid_rows tolerates."""
    q = sample(valid=valid).quality
    return q if valid else {**q, "truncated_traversals": ["processes"]}


def session(p, invalid=()):
    """A full session as the audit sees it: a full snapshot opens every chain, `invalid` rows did not close."""
    frames = []
    for seq in range(p["cycles"]):
        full = seq % p["full_every"] == 0
        previous_usable = seq > 0 and seq - 1 not in invalid
        frame = sample(seq, full=full, predecessor=previous_usable, valid=seq not in invalid)
        frames.append(frame.__class__(**{**frame.__dict__, "chain_id": f"chain-{seq // p['full_every']}",
                                         "quality": unclosed(seq not in invalid)}))
    result = data(frames)
    if len(invalid) <= p["invalid_rows"]["max"]:
        assert tolerated_invalid_rows(result, p) == sorted(invalid)  # the rule covers every such row
    report = scorable_windows(result, p, "synthetic", p["cycles"])[1]
    assert report["scorable_windows"] == window_count(p["cycles"], p["window_rows"], p["full_every"], set(invalid))
    return report


def v4_gate(p, rows):
    """Gate a v4-shaped session with `rows` isolated invalid rows lands on exactly (counted by the oracle).

    Each of them costs W + 1 windows, which no single row can exceed: no placement leaves fewer windows.
    """
    left = window_count(p["cycles"], p["window_rows"], p["full_every"], set(rows))
    assert left == window_count(p["cycles"], p["window_rows"], p["full_every"]) - len(rows) * (p["window_rows"] + 1)
    return left / p["cycles"]


def test_an_isolated_invalid_row_costs_what_the_loader_assumes():
    p = collection.protocol(V4)
    ideal = window_count(p["cycles"], p["window_rows"], p["full_every"])
    assert session(p)["scorable_windows"] == ideal == 656
    assert session(p, {100})["scorable_windows"] == ideal - (p["window_rows"] + 1)
    assert session(p, {100, 250, 500})["scorable_windows"] == ideal - 3 * (p["window_rows"] + 1)


def test_v4_allowed_three_invalid_rows_and_its_gate_admitted_one():
    p = collection.protocol(V4)
    assert p["invalid_rows"]["max"] == 3 and p["schema"].endswith("/2")  # the frozen file still loads as it is
    assert session(p, {100})["score_coverage"] >= p["min_score_coverage"]
    assert session(p, {100, 250})["score_coverage"] < p["min_score_coverage"]
    # Three rows the rule tolerates (session() checks it) still fall below the gate: rule and gate contradict.
    assert session(p, {100, 250, 500})["score_coverage"] < p["min_score_coverage"]


def test_schema_3_refuses_a_rule_the_gate_cannot_admit(tmp_path):
    with pytest.raises(ValueError, match="invalid_rows.max is unreachable"):
        collection.protocol(schema3(tmp_path))
    one = json.loads(V4.read_text())["invalid_rows"] | {"max": 1}  # what the v4 gate really admitted
    assert collection.protocol(schema3(tmp_path, invalid_rows=one))["invalid_rows"]["max"] == 1
    v4 = json.loads(V4.read_text())
    gate = v4_gate(v4, {100, 250, 500})  # three isolated rows cost the most; the gate they land on
    p = collection.protocol(schema3(tmp_path, min_score_coverage=gate))
    assert session(p, {100, 250, 500})["score_coverage"] >= p["min_score_coverage"]
    assert session(p, {100, 250, 400, 550})["score_coverage"] < p["min_score_coverage"]
    with pytest.raises(ValueError, match=WORST):  # one window more than the worst case leaves
        collection.protocol(schema3(tmp_path, min_score_coverage=gate + 1 / v4["cycles"]))


def test_schema_3_plans_by_protocol_v5(tmp_path):
    """Since package B4 schema 3 is the v5 layout and plans the v5 schedule; the schema-2 file keeps its plan."""
    from scripts import protocol_v5
    gate = v4_gate(json.loads(V4.read_text()), {100, 250, 500})
    a, b = collection.protocol(V4), collection.protocol(schema3(tmp_path, min_score_coverage=gate))
    assert collection.plan(b) == protocol_v5.plan(b, mode="campaign") != collection.plan(a)
    assert collection.plan(a)["schema"] == "hyptcn3/collection-plan/1"


# T09: the gate is mandatory under schema 3; versions 1 and 2 keep their default.

def smallest(schema, window_rows, full_every, cycles, pilot_cycles, gate=None, rule=None):
    """The smallest document collection.protocol() takes (both trees); `rule` is invalid_rows.max.

    Since package B4 a schema-3 document has every key of the v5 layout, and so an invalid_rows rule: without
    `rule` it tolerates no row (max 0), which the loader decides as it decides a document without a rule.
    """
    doc = {"schema": SCHEMA + str(schema), "interval_s": 1, "max_gap_s": 1.5, "stride": 1, "bin_bytes": 16777216,
           "window_rows": window_rows, "full_every": full_every, "cycles": cycles, "pilot_cycles": pilot_cycles}
    if schema > 1:
        doc["quality_policy"] = BEHAVIOR
    if schema == 3:
        doc.update(name="smallest", profile="profiles/smallest", domain="smallest", target="http://127.0.0.1:18080",
                   group_prefix="sm-", roles=dict.fromkeys(("train", "dev", "calibration", "test_benign"), 1),
                   scenarios={"steady": None}, **sections(doc["interval_s"]))
        doc.update(v5(doc))
        rule = 0 if rule is None else rule
    if gate is not None:
        doc["min_score_coverage"] = gate
    if rule is not None:
        doc["invalid_rows"] = {"max": rule, "traversals": ["processes"]}
    return doc


def write(path, doc):
    path.write_text(json.dumps(doc))
    return path


def load(path, doc):
    """The loader's decision on a document: "loads" (and returns it unchanged) or its refusal message."""
    try:
        p = collection.protocol(write(path, doc))
    except ValueError as error:
        return str(error)
    return "loads" if p == doc else "loads changed"


def test_the_smallest_document_needs_every_key(tmp_path):
    doc = smallest(3, 3, 12, 30, 16, gate=1 / 4, rule=3)
    assert load(tmp_path / "p.json", doc) == "loads"
    for key in set(doc) - {"invalid_rows", "min_score_coverage"}:
        with pytest.raises((KeyError, ValueError)):
            collection.protocol(write(tmp_path / "p.json", {k: v for k, v in doc.items() if k != key}))


def test_schema_3_requires_the_coverage_gate(tmp_path):
    # Clean shares 18/20 and 36/40, above the old default. Window 2: since package B7b a schema-3 document needs a
    # window of 2 rows at least (F2 of its verification: the contexts and the moving average of the analysis plan).
    doc = smallest(3, 2, 20, 20, 40, rule=0)
    assert window_count(20, 2, 20) / 20 >= DEFAULT_GATE and window_count(40, 2, 20) / 40 >= DEFAULT_GATE
    # Since package B4 the loader names every missing key of the v5 layout before the gate's reader is asked.
    with pytest.raises(ValueError, match="^missing protocol key: min_score_coverage$"):
        collection.protocol(write(tmp_path / "p.json", doc))
    assert load(tmp_path / "p.json", doc | {"min_score_coverage": DEFAULT_GATE}) == "loads"


@pytest.mark.parametrize("schema", [1, 2])
def test_schemas_1_and_2_keep_the_default_gate(tmp_path, schema):
    # Window 3 in chains of 20: both clean shares are exactly the default; window 4 is one window per chain below.
    at, below = smallest(schema, 3, 20, 20, 40), smallest(schema, 4, 20, 20, 40)
    assert window_count(20, 3, 20) / 20 == window_count(40, 3, 20) / 40 == DEFAULT_GATE
    assert window_count(40, 4, 20) / 40 < DEFAULT_GATE
    assert load(tmp_path / "p.json", at) == "loads"
    assert load(tmp_path / "p.json", below) == CLEAN + "pilot_cycles"
    assert load(tmp_path / "p.json", below | {"min_score_coverage": window_count(40, 4, 20) / 40}) == "loads"


@pytest.mark.parametrize("schema", [1, 2])
def test_schemas_1_and_2_keep_the_default_gate_to_one_window_in_2000(tmp_path, schema):
    # The same in chains of 2000: window 300 lands on the default, window 301 one window of 2000 below it.
    at, below = smallest(schema, 300, 2000, 2000, 4000), smallest(schema, 301, 2000, 2000, 4000)
    assert window_count(2000, 300, 2000) / 2000 == window_count(4000, 300, 2000) / 4000 == DEFAULT_GATE
    assert window_count(2000, 301, 2000) == window_count(2000, 300, 2000) - 1
    share = window_count(4000, 301, 2000) / 4000
    assert share == window_count(2000, 301, 2000) / 2000 and 0 < DEFAULT_GATE - share <= 1 / 1000
    assert load(tmp_path / "p.json", at) == "loads"
    assert load(tmp_path / "p.json", below) == CLEAN + "pilot_cycles"
    assert load(tmp_path / "p.json", below | {"min_score_coverage": share}) == "loads"


# T09, the reader itself: a stated gate is a number in (0, 1]; anything else is refused before a window is counted.

INVALID_GATE = "invalid minimum score coverage"
# window_rows, full_every, cycles, pilot_cycles: clean shares 18/20 and 36/40 (window 2: a schema-3 document needs a
# window of 2 rows at least since package B7b, F2 of its verification).
GATE_SHAPE = (2, 20, 20, 40)
OUT_OF_RANGE = {"zero": 0, "zero_float": float(0), "negative": -DEFAULT_GATE, "above_1": 21 / 20,
                "next_above_1": math.nextafter(1, 2)}
WRONG_TYPE = {"true": True, "false": False, "string": str(DEFAULT_GATE), "null": None, "list": [DEFAULT_GATE],
              "nan": math.nan, "infinity": math.inf, "minus_infinity": -math.inf}


def stated(path, schema, gate):
    """The loader's answer to the GATE_SHAPE document stating `gate`; the file holds that very value and type."""
    answer = load(path, smallest(schema, *GATE_SHAPE) | {"min_score_coverage": gate})
    read = json.loads(path.read_text())["min_score_coverage"]  # parsed as collection.protocol() parses the file
    assert type(read) is type(gate) and (read == gate or read != read and gate != gate)  # NaN stays a float NaN
    return answer


@pytest.mark.parametrize("schema", [1, 2, 3])
@pytest.mark.parametrize("name", OUT_OF_RANGE)
def test_a_gate_out_of_range_is_refused_by_the_reader(tmp_path, schema, name):
    assert stated(tmp_path / "p.json", schema, DEFAULT_GATE) == "loads"  # the document itself is acceptable
    assert stated(tmp_path / "p.json", schema, OUT_OF_RANGE[name]) == INVALID_GATE


@pytest.mark.parametrize("schema", [1, 2, 3])
@pytest.mark.parametrize("name", WRONG_TYPE)
def test_a_gate_of_the_wrong_type_is_refused_by_the_reader(tmp_path, schema, name):
    assert stated(tmp_path / "p.json", schema, DEFAULT_GATE) == "loads"
    assert stated(tmp_path / "p.json", schema, WRONG_TYPE[name]) == INVALID_GATE


@pytest.mark.parametrize("schema", [1, 2, 3])
@pytest.mark.parametrize("gate", [math.nextafter(0, 1), 1 / 20], ids=["smallest_float", "one_twentieth"])
def test_a_small_positive_gate_loads(tmp_path, schema, gate):
    W, F, N, P = GATE_SHAPE
    assert window_count(P, W, F) / P >= gate and window_count(N, W, F) / N >= gate
    assert stated(tmp_path / "p.json", schema, gate) == "loads"


@pytest.mark.parametrize("schema", [1, 2, 3])
@pytest.mark.parametrize("gate", [1, float(1)], ids=["int", "float"])
def test_a_gate_of_1_passes_the_reader_and_the_clean_check_refuses_it(tmp_path, schema, gate):
    # The upper end is closed: 1 passes the reader, then no clean pilot reaches it (every chain loses W windows).
    W, F, N, P = GATE_SHAPE
    assert window_count(P, W, F) / P < gate
    answer = stated(tmp_path / "p.json", schema, gate)
    assert answer == CLEAN + "pilot_cycles" and answer != INVALID_GATE


def test_schema_3_tells_a_missing_gate_from_a_stated_gate_of_the_wrong_type(tmp_path):
    assert stated(tmp_path / "p.json", 3, DEFAULT_GATE) == "loads"
    missing = load(tmp_path / "p.json", smallest(3, *GATE_SHAPE))
    wrong = {stated(tmp_path / "p.json", 3, gate) for gate in WRONG_TYPE.values()}
    # Two refusals, two messages: the key is absent, or it is there and holds no number in (0, 1]. Since package B4
    # the loader names the missing key of the v5 layout before the gate's reader is asked.
    assert (missing, wrong) == ("missing protocol key: min_score_coverage", {INVALID_GATE})


# T15: the protocol files in the repository load unchanged.

@pytest.mark.parametrize("name", ["v1", "v2", "v3", "v4", "v4-events"])
def test_existing_protocol_files_load_unchanged(name):
    path = ROOT / f"config/collection-{name}.json"
    assert collection.protocol(path) == json.loads(path.read_text())


# L8, loader side: the families S3 and S2G of the criterion tests (audit side: tcn/tests/test_prijatie_session.py).

S3 = {"cycles": 96, "window_rows": 8, "full_every": 64, "pilot_cycles": 80, "max": 3}


def isolated(family, count):
    """Isolated rows of the criterion cells: step * (j + 1), all inside chain 0, each W + 1 rows from the next."""
    step = family["full_every"] // 6
    assert step - 1 >= family["window_rows"] and step * count < family["full_every"] - family["window_rows"]
    return {step * (j + 1) for j in range(count)}


def s3_windows(family=S3):
    """Windows the S3 gate asks for: the clean ideal less max * (W + 1), where `max` isolated rows land exactly."""
    ideal = window_count(family["cycles"], family["window_rows"], family["full_every"])
    left = window_count(family["cycles"], family["window_rows"], family["full_every"], isolated(family, family["max"]))
    assert left == ideal - family["max"] * (family["window_rows"] + 1)
    return left


def s3_gate():
    return s3_windows() / S3["cycles"]


def family(tmp_path, schema, gate, **changes):
    """Protocol file of a criterion family (section 3 of the plan): one unnamed VM, no events, vms, replacement;
    under schema 3 the v5 sections, by which no event is planned and nothing is replaced."""
    f = S3 | changes
    profile = tmp_path / "profile"
    profile.mkdir(exist_ok=True)
    doc = {"schema": SCHEMA + str(schema), "name": "criterion-s" + str(schema), "domain": "criterion",
           "target": "http://127.0.0.1:18080", "profile": str(profile), "interval_s": 1, "max_gap_s": 1.5,
           "bin_bytes": 16777216, "window_rows": f["window_rows"], "stride": 1, "full_every": f["full_every"],
           "cycles": f["cycles"], "pilot_cycles": f["pilot_cycles"],
           "roles": {"train": 3, "dev": 3, "calibration": 3, "test_benign": 3},
           "scenarios": {"quiet": {"workers": 1, "burst": 0, "catalog_share": 1 / 2, "write_share": 1 / 5},
                         "steady": {"workers": 4, "burst": 1 / 5, "catalog_share": 1 / 2, "write_share": 1 / 5}},
           "quality_policy": BEHAVIOR, "min_score_coverage": gate, "group_prefix": "kt-",
           "invalid_rows": {"max": f["max"], "traversals": ["processes"]}}
    if schema == 1:
        del doc["quality_policy"]
    if schema == 3:
        doc.update(**v5(doc), **sections(doc["interval_s"]))
    path = tmp_path / f"s{schema}.json"
    path.write_text(json.dumps(doc))
    return path, doc


def test_s3_loads(tmp_path):
    path, doc = family(tmp_path, 3, s3_gate())
    assert collection.protocol(path) == doc
    # No placement of max rows leaves fewer windows than the isolated ones: the loader iff the audit (k3i accepted).
    assert worst_by_chains(S3["cycles"], S3["window_rows"], S3["full_every"], S3["max"]) == s3_windows()


def test_s3_with_the_s2g_gate_is_refused(tmp_path):
    path, _ = family(tmp_path, 3, s3_gate() + 1 / S3["cycles"])
    with pytest.raises(ValueError, match="^" + WORST + "$"):
        collection.protocol(path)


def test_s2g_loads_under_schema_2(tmp_path):
    path, doc = family(tmp_path, 2, s3_gate() + 1 / S3["cycles"])
    assert collection.protocol(path) == doc


@pytest.mark.parametrize("schema", [1, 2, 3])
@pytest.mark.parametrize("key", ["pilot_cycles", "cycles"])
def test_a_gate_above_the_clean_ideal_is_refused(tmp_path, schema, key):
    W, F = S3["window_rows"], S3["full_every"]
    if key == "pilot_cycles":  # the pilot's clean share is the lower one in the S3 shape
        changes, gate = {}, (window_count(S3["pilot_cycles"], W, F) + 1) / S3["pilot_cycles"]
        assert window_count(S3["cycles"], W, F) / S3["cycles"] >= gate
    else:  # a longer pilot whose clean share is above the session's
        changes, gate = {"pilot_cycles": 128}, (window_count(S3["cycles"], W, F) + 1) / S3["cycles"]
        assert window_count(128, W, F) / 128 >= gate
    path, _ = family(tmp_path, schema, gate, **changes)
    with pytest.raises(ValueError, match="^" + CLEAN + key + "$"):
        collection.protocol(path)


# T14: the loader's decision on small shapes equals the brute force over all placements.

def shapes():
    """(W, F, N, P) with N up to 30; short chains (F a little above W) leave the exact worst case above the bound."""
    out = []
    for W in range(1, 7):
        for F in sorted({W + 1, W + 2, W + 3, 2 * W, 2 * W + 1, 2 * W + 2, 2 * W + 3, 3 * W + 4}):
            for N in sorted({W + 1, W + 2, F - 1, F, F + 1, F + W, F + W + 1, 2 * F - 1, 2 * F, 2 * F + W + 1,
                             2 * F + W + 2, 3 * F}):
                for P in sorted({F + W + 1, F + W + 2, 2 * F, 2 * F + 1, 2 * F + W + 1} - set(range(F + W + 1))):
                    if N <= 30 and P <= 40:
                        out.append((W, F, N, P))
    return out


def around(*counts):
    """Gates at, one window below and one above each (windows, rows) pair, inside (0, 1]."""
    return sorted({g for windows, rows in counts for g in ((windows - 1) / rows, windows / rows, (windows + 1) / rows)
                   if 0 < g <= 1})


def expected(W, F, N, P, gate, schema, rule):
    """Decision of the oracle: the clean pilot, then the clean session, then (schema 3) the worst session. Before them,
    since package B7b (F2 of its verification), schema 3 refuses a window under 2 rows by its analysis plan: the
    contexts of the diagnostics (1 to window_rows - 1) and the moving average of the validity predicate (2 to
    window_rows rows) have no value there."""
    if schema == 3 and W < 2:
        return ANALYSIS
    for key, rows in (("pilot_cycles", P), ("cycles", N)):
        if window_count(rows, W, F) / rows < gate:
            return CLEAN + key
    if schema == 3 and rule is not None and worst_windows(N, W, F, rule) / N < gate:
        return WORST
    return "loads"


@pytest.fixture(scope="module")
def grid(tmp_path_factory):
    """Every cell: (shape, gate, schema, rule) -> (oracle, loader, between the one-row bound and the exact case)."""
    path = tmp_path_factory.mktemp("t14") / "p.json"
    cells = {}
    for W, F, N, P in shapes():
        clean = around((window_count(P, W, F), P), (window_count(N, W, F), N))
        for schema in (2, 3):
            for gate in clean:
                cells[(W, F, N, P, gate, schema, None)] = None
            for rule in range(4):
                bound = window_count(N, W, F) - rule * (W + 1)
                for gate in around((worst_windows(N, W, F, rule), N), (bound, N)):
                    cells[(W, F, N, P, gate, schema, rule)] = None
    for cell in cells:
        W, F, N, P, gate, schema, rule = cell
        want, bound = expected(*cell), window_count(N, W, F) - (rule or 0) * (W + 1)
        # Between: schema 3 loads by the exact rule, but the bound ideal - max * (W + 1) is below the gate.
        cells[cell] = (want, load(path, smallest(schema, W, F, N, P, gate, rule)),
                       want == "loads" and schema == 3 and rule is not None and bound / N < gate)
    return cells


def disagreements(grid, select):
    found = [(cell, want, got) for cell, (want, got, between) in grid.items() if select(cell, want, between)
             and got != want]
    return len(found), found[:5]


def test_grid_has_every_kind_of_cell(grid):
    wants = [want for want, _, _ in grid.values()]
    assert {CLEAN + "pilot_cycles", CLEAN + "cycles", WORST, "loads", ANALYSIS} == set(wants)
    between = [cell for cell, (want, _, b) in grid.items() if b]
    assert len({cell[:4] for cell in between}) >= 10
    # A gate above both clean shares names the pilot: the pilot is checked first.
    assert any(want == CLEAN + "pilot_cycles" and window_count(N, W, F) / N < gate
               for (W, F, N, P, gate, _, _), (want, _, _) in grid.items())


def test_reachability_names_the_first_unreachable_clean_length(grid):
    assert disagreements(grid, lambda cell, want, between: want.startswith(CLEAN)) == (0, [])


def test_schema_3_refuses_exactly_an_unreachable_worst_case(grid):
    assert disagreements(grid, lambda cell, want, between: cell[5] == 3 and not want.startswith(CLEAN)
                         and not between) == (0, [])


def test_schema_3_admits_a_worst_case_above_the_one_row_bound(grid):
    assert disagreements(grid, lambda cell, want, between: between) == (0, [])


def test_schema_2_does_not_check_the_worst_case(grid):
    assert disagreements(grid, lambda cell, want, between: cell[5] == 2 and not want.startswith(CLEAN)) == (0, [])
