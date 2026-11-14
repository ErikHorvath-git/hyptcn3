"""Event index of the closed campaign events-v3-20261108 (protocol v3, step A): 45 of 48 planned sessions.

usage: index.py CAMPAIGN_DIR

The runner writes events_index.json only for a complete allocation (scripts/campaign.py finish_corpus). This campaign
was closed after the audit rejected session 46, so the index is built here from the same function
(scripts.campaign.event_index) over the accepted checkpoints, and it states the incomplete allocation explicitly:
the owner accepted it (decision 2026-11-13), the rejected session keeps its audit verdict, and the two sessions that
were never captured are listed. The records are exactly those event_index produces; "complete" stays false.
The index is published next to the campaign files and copied into the campaign archive, as for a complete one.
"""
import json
from pathlib import Path
import sys

ROOT = Path("/home/eh/projects/hyptcn3")
sys.path.insert(0, str(ROOT))
from scripts import campaign  # noqa: E402
from scripts.collection_archive import digest, guard_mount, read_json, write_new  # noqa: E402

DECISION = ("Owner decision 2026-11-13: close events-v3-20261108 with its 45 accepted sessions and evaluate them "
            "without further collection. The rejected session stays archived with its verdict; sessions 47 and 48 "
            "were never captured. No new campaign: a fix of the process-list walk in guestparse would change "
            "extractor_sha256, so the bundle server-v2-benign-v6 and the audits of corpus benign-v6 would no longer "
            "match. Groups 1 to 7 are complete (6 scenarios each), group 8 has 3 of its 6 sessions; nothing is "
            "redistributed.")

directory = Path(sys.argv[1]).resolve()
manifest, p = campaign.load_campaign(directory)
closed = directory / "closed.json"
state = read_json(directory / "status.json")
if not closed.exists() or state.get("status") != "closed":
    raise SystemExit("the campaign must be closed before its incomplete index is built")

reports, rejected, missing = [], [], []
for row in manifest["sessions"]:
    sid = row["session_id"]
    done = directory / "attempts" / (sid + ".done.json")
    pointer = directory / "attempts" / (sid + ".audit.json")
    plan = {"id": sid, "group": row["group"], "role": row["role"], "scenario": row["scenario"], "seed": row["seed"]}
    if done.exists():
        d = read_json(done)
        if digest(d["audit"]) != d["audit_sha256"]:
            raise SystemExit("audit changed since its checkpoint: " + d["audit"])
        reports.append(d["audit"])
    elif pointer.exists():
        ref = read_json(pointer)
        if digest(ref["path"]) != ref["sha256"]:
            raise SystemExit("audit changed since the run: " + ref["path"])
        v = read_json(ref["path"])["values"]
        if v["accepted"]:
            raise SystemExit("accepted audit without a checkpoint: " + ref["path"])
        archive = Path(manifest["archive_dir"]) / "collections" / sid
        rejected.append({**plan, "audit": ref["path"], "audit_sha256": ref["sha256"], "reasons": v["reasons"],
                         "invalid_input_seq": v["quality"]["invalid_input_seq"],
                         "archive_manifest_sha256": digest(archive / "archive-manifest.json")})
    elif (campaign.COLLECTIONS / sid).exists():
        raise SystemExit("session without a checkpoint or an audit: " + sid)
    else:
        missing.append(plan)

doc = campaign.event_index(reports, p, manifest["protocol_sha256"])
doc["protocol"] = str(directory / "protocol.json")
groups = {}
for record in doc["sessions"]:
    groups[record["group"]] = groups.get(record["group"], 0) + 1
if doc["complete"] or len(doc["sessions"]) + len(rejected) + len(missing) != doc["planned_sessions"]:
    raise SystemExit("allocation does not add up")
doc["incomplete_allocation"] = {
    "accepted": True,
    "decision": DECISION,
    "planned_sessions": doc["planned_sessions"],
    "indexed_sessions": len(doc["sessions"]),
    "sessions_per_group": dict(sorted(groups.items())),
    "rejected": rejected,
    "not_captured": missing,
    "closed": str(closed),
    "closed_sha256": digest(closed),
}
index = directory / "events_index.json"
write_new(index, doc)
guard_mount(manifest["archive_root"], manifest["archive_mount"])
campaign.copy_exclusive(index, Path(manifest["archive_dir"]) / "events_index.json")
print(json.dumps({"index": str(index), "sha256": digest(index), "sessions": len(doc["sessions"]),
                  "rejected": [r["id"] for r in rejected], "not_captured": [m["id"] for m in missing],
                  "groups": doc["incomplete_allocation"]["sessions_per_group"]}, indent=2))
