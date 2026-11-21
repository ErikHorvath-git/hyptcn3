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
    # Version 3 only adds a load-time check of the acceptance rule (scripts/collection.py).
    if (schema in ("hyptcn3/collection-protocol/2", "hyptcn3/collection-protocol/3")
            and protocol.get("quality_policy") == BEHAVIOR_POLICY):
        return BEHAVIOR_POLICY
    raise ValueError("unsupported collection protocol/quality policy")


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


def tolerated_invalid_rows(result, p):
    """Seq of invalid rows the protocol tolerates, [] when all are valid, None when not tolerated."""
    rule = invalid_rows_rule(p)
    if not len(result["seq"]) == len(result["quality"]) == len(result["valid"]):
        raise ValueError("rows, validity and quality differ in length")
    bad = [(seq, q) for seq, q, good in zip(result["seq"], result["quality"], result["valid"]) if not good]
    if not bad:
        return []
    if rule is None or len(bad) > rule["max"]:
        return None
    allowed = set(rule["traversals"])
    for _, q in bad:
        names = q.get("truncated_traversals") if type(q) is dict else None
        if (type(names) is not list or not names or not set(map(str, names)) <= allowed
                or q.get("read_errors") or q.get("filled_zero")):
            return None
    return [seq for seq, _ in bad]


def accepted_invalid_rows(seq, valid, quality, audit_values, protocol):
    """Seq of the invalid rows in the archive of an accepted session; ValueError when the rule does not cover them.

    Corpus building, training and the comparison methods read accepted archives
    through this one check, so each of them admits what the audit admitted under
    the protocol's invalid_rows rule and nothing else: the audit must list every
    invalid row, their number must fit the rule and each must have a cause the
    rule names. A malformed rule is refused even when no row is invalid.
    """
    rule = invalid_rows_rule(protocol)
    if not len(seq) == len(valid) == len(quality):
        raise ValueError("rows, validity and quality differ in length")
    invalid = [int(s) for s, good in zip(seq, valid) if not good]
    if not invalid:
        return []
    report = audit_values.get("quality") if type(audit_values) is dict else None
    listed = report.get("tolerated_invalid_seq") if type(report) is dict else None
    if type(listed) is not list or any(type(s) is not int for s in listed) or set(invalid) - set(listed):
        raise ValueError("incomplete features in accepted audit")
    if rule is None or len(invalid) > rule["max"]:
        raise ValueError("more invalid rows than the protocol tolerates")
    if tolerated_invalid_rows({"seq": seq, "valid": valid, "quality": quality}, protocol) is None:
        raise ValueError("invalid rows have a cause the protocol does not tolerate")
    return invalid


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
