"""Full-snapshot size and time of every pilot and campaign session on one QEMU process.

usage: record.py OUT_JSON SESSION_DIR [SESSION_DIR ...]
Reads session.json (guest boot, QEMU process identity) and raw/collect.log (full
snapshot lines: pages read and cycle time) of each session, in the given order.
The least-squares line of cycle time over pages leaves out fulls named in
EXCLUDED, with the reason; the projection to all guest pages is an estimate.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path("/home/eh/projects/hyptcn3")
out, sessions = Path(sys.argv[1]), [Path(p) for p in sys.argv[2:]]
FULL = re.compile(r"^(\S+) INFO  #(\d+) PLNA\s+([\d.]+) (MiB|GiB)/[\d.]+ GiB\s+stranky (\d+)/(\d+).*"
                  r"citanie ([\d.]+) ms\s+spolu ([\d.]+) ms")
# Concurrent writeback of the first full snapshot (MERANIA, pilot 3), not a size effect.
EXCLUDED = {("20261022T003017919708Z_pilot_bursty", 360): "concurrent writeback (MERANIA: pilot 3)"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


rows, totals, inputs = [], set(), {}
for directory in sessions:
    meta = json.loads((directory / "session.json").read_text())
    log = directory / "raw/collect.log"
    inputs[directory.name] = {"session.json": sha(directory / "session.json"), "collect.log": sha(log)}
    for m in map(FULL.match, log.read_text().splitlines()):
        if not m:
            continue
        totals.add(int(m[6]))
        rows.append({"session": directory.name, "guest_boot": meta["guest_before"]["boot_id"],
                     "qemu": meta["host_context"]["qemu"], "seq": int(m[2]), "t_utc": m[1],
                     "pages": int(m[5]), "read_ms": float(m[7]), "cycle_ms": float(m[8]),
                     "excluded_from_fit": EXCLUDED.get((directory.name, int(m[2])))})
fit_rows = [r for r in rows if not r["excluded_from_fit"]]
n = len(fit_rows)
mx = sum(r["pages"] for r in fit_rows) / n
my = sum(r["cycle_ms"] for r in fit_rows) / n
slope = sum((r["pages"] - mx) * (r["cycle_ms"] - my) for r in fit_rows) / sum((r["pages"] - mx) ** 2 for r in fit_rows)
intercept = my - slope * mx
boots = []
for r in rows:
    if not boots or boots[-1]["guest_boot"] != r["guest_boot"]:
        boots.append({"guest_boot": r["guest_boot"], "first_session": r["session"], "pages": []})
    boots[-1]["pages"].append(r["pages"])
(total,) = totals
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": json.loads((sessions[-1] / "session.json").read_text())["guest_before"],
    "command": " ".join(sys.argv), "n": len(rows),
    "values": {
        "qemu_processes": sorted({json.dumps(r["qemu"], sort_keys=True) for r in rows}),
        "guest_pages_total": total,
        "fulls": rows,
        "by_guest_boot": [{"guest_boot": b["guest_boot"], "first_session": b["first_session"],
                           "pages_min": min(b["pages"]), "pages_max": max(b["pages"])} for b in boots],
        "fit_cycle_ms_per_page": {"n": n, "slope_ms": slope, "intercept_ms": intercept,
                                  "excluded": [dict(session=s, seq=q, reason=why) for (s, q), why in EXCLUDED.items()]},
        "estimate_all_pages_ms": intercept + slope * total,
        "note": "Pages are the guest pages the host had allocated and the full snapshot read. They grew "
                "across guest reboots on one QEMU process. estimate_all_pages_ms extends the fitted line to every "
                "guest page; it is an estimate, not a measurement.",
        "inputs_sha256": inputs,
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
v = doc["values"]
print(json.dumps({k: v[k] for k in ("qemu_processes", "guest_pages_total", "by_guest_boot",
                                    "fit_cycle_ms_per_page", "estimate_all_pages_ms")}, indent=1))
