"""Recorded boot identity for native captures; never infer it from a profile.

Original implementation. The collector's host orchestration records this
identity before capture. Reading it here does not query the running guest.
"""
import json
from pathlib import Path
from uuid import UUID


def boot_uuid(value):
    if not isinstance(value, str):
        raise ValueError("capture boot_id must be a UUID string")
    try:
        result = UUID(value)
    except ValueError as exc:
        raise ValueError("invalid capture boot_id") from exc
    if result.int == 0:
        raise ValueError("capture boot_id must not be zero")
    return str(result)


def capture_boot_id(image_path, explicit=None):
    """Resolve a recorded identity, rejecting conflicting explicit input.

    Only native raw/ directories have implicit context. Standalone historical
    images may supply an explicit identity, or require an unambiguous anchor.
    A profile's boot.json belongs to its symbol addresses, not to the capture.
    """
    expected = boot_uuid(explicit) if explicit is not None else None
    path = Path(image_path).resolve()
    raw = path if path.is_dir() else path.parent
    if raw.name != "raw":
        return expected
    # Session schema 2 adds evidence/provenance fields; guest_before is unchanged.
    for filename, schemas, guest_key in (
        ("session.json", ("hyptcn3/collection-session/1", "hyptcn3/collection-session/2"), "guest_before"),
        ("run.json", ("hyptcn3/safeguard-supervisor/1",), "guest"),
    ):
        metadata = raw.parent / filename
        if not metadata.exists():
            continue
        doc = json.loads(metadata.read_text())
        if not isinstance(doc, dict) or doc.get("schema") not in schemas:
            raise ValueError("unrecognized capture metadata: " + str(metadata))
        guest = doc.get(guest_key)
        if not isinstance(guest, dict):
            raise ValueError("capture metadata lacks guest identity: " + str(metadata))
        recorded = boot_uuid(guest.get("boot_id"))
        if expected is not None and expected != recorded:
            raise ValueError("boot_id conflicts with recorded capture identity")
        expected = recorded
    return expected
