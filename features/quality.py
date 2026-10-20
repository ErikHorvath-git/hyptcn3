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
    if (schema == "hyptcn3/collection-protocol/2"
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
