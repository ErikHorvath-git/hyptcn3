"""Explicit validity policies; integrity availability is not a behavior input.

The legacy 22-column path includes integrity counts. The safeguard uses only
the 18 behavior columns and per-bin measurements, so it requires their own
complete traversals and successful memory reads. Neither policy fills gaps.
"""

LEGACY_POLICY = "legacy-vector-v1"
BEHAVIOR_POLICY = "behavioral-inputs-v1"


def valid_for(quality, policy):
    if policy == LEGACY_POLICY:
        key = "model_valid"
    elif policy == BEHAVIOR_POLICY:
        key = "behavior_valid"
    else:
        raise ValueError("unsupported feature quality policy: " + str(policy))
    value = quality[key]
    if type(value) is not bool:
        raise ValueError("feature validity must be boolean")
    return value


def protocol_policy(protocol):
    schema = protocol.get("schema")
    if schema == "hyptcn3/collection-protocol/1":
        if "quality_policy" in protocol:
            raise ValueError("quality policy changes require protocol version 2")
        return LEGACY_POLICY
    # Version 3 must state min_score_coverage (coverage_gate) and may only carry an invalid_rows rule whose
    # worst case still reaches that gate (features/acceptance.py, protocol_reachability).
    if (schema in ("hyptcn3/collection-protocol/2", "hyptcn3/collection-protocol/3")
            and protocol.get("quality_policy") == BEHAVIOR_POLICY):
        return BEHAVIOR_POLICY
    raise ValueError("unsupported collection protocol/quality policy")


def coverage_gate(protocol):
    """The protocol's minimum score coverage; every comparison of a coverage with the gate reads it here.

    Protocol versions 1 and 2 may omit the key and then mean .85; version 3 must state it. A boolean, a NaN and
    a value outside (0, 1] are refused, also when the protocol reaches this reader without the loader. The one
    exception is the campaign report (scripts/campaign_report.py), which never imports the extractor: it reads
    the key itself and falls back to its own .85.
    """
    if type(protocol) is not dict:
        raise ValueError("invalid minimum score coverage")
    if "min_score_coverage" not in protocol:
        if protocol.get("schema") == "hyptcn3/collection-protocol/3":
            raise ValueError("protocol schema 3 requires min_score_coverage")
        return .85
    gate = protocol["min_score_coverage"]
    if type(gate) not in (int, float) or not 0 < gate <= 1:
        raise ValueError("invalid minimum score coverage")
    return gate


def require_log_audit(metadata, values):
    """Managed v2 sessions need the evidence verdict as well as valid features.

    Historical v1 provenance remains readable; it does not acquire new claims
    about request-level logs that were never recorded.
    """
    if metadata.get("schema") != "hyptcn3/collection-session/2":
        return
    logs = values.get("logs") or {}
    if (logs.get("schema") != "hyptcn3/collection-logs-audit/1"
            or logs.get("accepted") is not True or logs.get("problems") != []
            or logs.get("sections", {}).get("metadata", {}).get("session_sha256") != values.get("session_sha256")
            or not values.get("session_sha256")):
        raise ValueError("managed session requires an accepted log audit; re-audit the session")


INVALID_ROW_TRAVERSALS = ("processes", "modules", "sockets", "memory_patterns")


def invalid_rows_rule(protocol):
    """The protocol's invalid_rows rule, None when it has none; ValueError when the rule is malformed.

    Every reader of the rule takes it through this check. A rule of a malformed
    shape is therefore refused wherever it is applied, also when the protocol
    comes from a corpus index or a bundle manifest. Whether the rule is reachable
    under the score coverage gate is checked only when the protocol file is
    loaded (scripts/collection.py, protocol schema 3).
    """
    if type(protocol) is not dict:
        raise ValueError("invalid invalid_rows rule")
    if "invalid_rows" not in protocol:
        return None
    r = protocol["invalid_rows"]
    if (type(r) is not dict or not {"max", "traversals"} <= set(r) <= {"max", "traversals", "note"}
            or type(r["max"]) is not int or r["max"] < 0 or type(r["traversals"]) is not list
            or not r["traversals"] or not set(map(str, r["traversals"])) <= set(INVALID_ROW_TRAVERSALS)):
        raise ValueError("invalid invalid_rows rule")
    return r


# Resolved rule of a session whose role gets no tolerance at all (the pilot, a role the protocol does not assign).
NO_TOLERANCE = False


def row_rule_failure(bad, rule):
    """Why the invalid rows are outside the rule: "no_tolerance", "no_rule", "over_max" or "cause"; None when covered.

    `bad` holds one (seq, quality) pair per invalid row. `rule` is the session's resolved rule: the object
    invalid_rows_rule() returned, None for a protocol without a rule, NO_TOLERANCE for a role that gets none.
    A row is covered only when its quality names nothing but tolerated open traversals and states zero read
    errors and zero filled bytes as integers; a missing or differently typed field is not a tolerable row.
    """
    if not bad:
        return None
    if rule is NO_TOLERANCE:
        return "no_tolerance"
    if rule is None:
        return "no_rule"
    if len(bad) > rule["max"]:
        return "over_max"
    allowed = set(rule["traversals"])
    for _, q in bad:
        names = q.get("truncated_traversals") if type(q) is dict else None
        if (type(names) is not list or not names or not set(map(str, names)) <= allowed
                or type(q.get("read_errors")) is not int or q["read_errors"]
                or type(q.get("filled_zero")) is not int or q["filled_zero"]):
            return "cause"
    return None


def tolerated_rows(bad, rule):
    """Seq of the invalid rows when the rule covers all of them ([] when there are none), else None."""
    return None if row_rule_failure(bad, rule) else [seq for seq, _ in bad]


def tolerated_invalid_rows(result, p):
    """Seq of invalid rows the protocol tolerates, [] when all are valid, None when not tolerated."""
    rule = invalid_rows_rule(p)
    if not len(result["seq"]) == len(result["quality"]) == len(result["valid"]):
        raise ValueError("rows, validity and quality differ in length")
    return tolerated_rows([(seq, q) for seq, q, good in zip(result["seq"], result["quality"], result["valid"])
                           if not good], rule)


def tolerated_input_errors(rows, protocol):
    """Seq of a replay's input-error rows when the protocol's invalid_rows rule covers all of them, else None.

    The detector never scores an invalid row and reports it as an input error.
    In the replay of an accepted archive that is the trace of a row the audit
    tolerated. Any other input error (another reason, a fatal one, more rows
    than the rule allows, a cause outside it) is not covered.
    """
    bad = [row for row in rows if row["model_state"] == "input_error"]
    if any(row.get("fatal") or row.get("reason") != "invalid_input" for row in bad):
        return None
    return tolerated_invalid_rows({"seq": [row["seq"] for row in bad], "valid": [False] * len(bad),
                                   "quality": [row.get("quality") for row in bad]}, protocol)
