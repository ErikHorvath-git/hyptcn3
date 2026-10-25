"""Where the QEMU memory swapped out during the collector 1.1 diagnostic lies, read after the capture.

usage: qemu_swap_record.py SESSION_DIR BALLAST_LOG OUT_JSON
Reads /proc/PID/smaps of the diagnostic's QEMU process (same pid and start time as in session.json) and splits the
swapped-out memory into the guest RAM mapping (the anonymous mapping of the domain's <memory> size) and the rest of
QEMU. The host monitor of the session gives when the swap-out happened (pswpout, QEMU VmSwap per 1 s sample).
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
session, ballast_log, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
HEAD = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)$")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


meta = json.loads((session / "session.json").read_text())
qemu = meta["host_context"]["qemu"]
pid = qemu["pid"]
start_ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
if start_ticks != qemu["start_ticks"]:
    raise SystemExit("QEMU process of the session is gone")
guest_kb = int(re.search(r"<memory unit='KiB'>(\d+)</memory>", (session / "domain.xml").read_text())[1])
read_at = datetime.now(timezone.utc)
maps, cur = [], None
for line in Path(f"/proc/{pid}/smaps").read_text().splitlines():
    m = HEAD.match(line)
    if m:
        cur = {"range": f"{m[1]}-{m[2]}", "perms": m[3], "path": m[4] or None,
               "size_kb": (int(m[2], 16) - int(m[1], 16)) // 1024}
        maps.append(cur)
    elif line.startswith(("Swap:", "Rss:")):
        cur[line.split(":")[0].lower() + "_kb"] = int(line.split()[1])
status = dict(l.split(":", 1) for l in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in l)
guest = [m for m in maps if m["size_kb"] == guest_kb and m["path"] is None and m["perms"].startswith("rw")]
if len(guest) != 1:
    raise SystemExit(f"expected one guest RAM mapping of {guest_kb} kB, found {len(guest)}")
swapped = sorted((m for m in maps if m.get("swap_kb")), key=lambda m: -m["swap_kb"])

text = ballast_log.read_text()
b0 = unix(re.search(r"^start (\S+)", text, re.M)[1])
b1 = unix(re.search(r"^end (\S+)", text, re.M)[1])
samples = [r for r in map(json.loads, (session / "host_monitor.jsonl").open()) if r.get("type") == "sample"]


def qswap(r):
    return max((p.get("swap_kb") or 0 for p in r["procs"].get("qemu", [])), default=0)


first_swap = next((r for r in samples if qswap(r) > 0), None)
inside = [r for r in samples if b0 <= unix(r["t_utc"]) <= b1]
before = [r for r in samples if unix(r["t_utc"]) < b0]
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": read_at.isoformat(), "host": platform.platform(), "guest": meta["guest_before"],
    "command": " ".join(sys.argv), "n": len(swapped),
    "values": {
        "session": session.name, "qemu_pid": pid, "qemu_start_ticks": start_ticks,
        "smaps_read_utc": read_at.isoformat(),
        "vm_swap_kb": int(status["VmSwap"].split()[0]), "vm_rss_kb": int(status["VmRSS"].split()[0]),
        "guest_ram_mapping": guest[0] | {"guest_memory_kb": guest_kb},
        "swapped_kb_outside_guest_ram": sum(m["swap_kb"] for m in swapped if m is not guest[0]),
        "swapped_mappings": swapped,
        "monitor": {
            "first_sample_qemu_swap_utc": first_swap["t_utc"] if first_swap else None,
            "first_sample_qemu_swap_kb": qswap(first_swap) if first_swap else None,
            "qemu_swap_kb_max_before_ballast": max((qswap(r) for r in before), default=None),
            "pswpout_delta_before_ballast": before[-1]["vmstat"]["pswpout"] - samples[0]["vmstat"]["pswpout"],
            "pswpout_delta_in_ballast": inside[-1]["vmstat"]["pswpout"] - before[-1]["vmstat"]["pswpout"],
            "pswpout_delta_after_ballast": samples[-1]["vmstat"]["pswpout"] - inside[-1]["vmstat"]["pswpout"],
            # Whole host-monitor run (from before the warmup to after the guest-evidence step), host-wide.
            "pswpin_delta_capture": samples[-1]["vmstat"]["pswpin"] - samples[0]["vmstat"]["pswpin"],
            "cached_mib_before_ballast": round(before[-1]["mem_kb"]["Cached"] / 1024),
            "cached_mib_min_in_ballast": min(round(r["mem_kb"]["Cached"] / 1024) for r in inside),
            "memfree_mib_before_ballast": round(before[-1]["mem_kb"]["MemFree"] / 1024),
            "memfree_mib_max_in_ballast": max(round(r["mem_kb"]["MemFree"] / 1024) for r in inside),
        },
        "inputs_sha256": {"session.json": sha(session / "session.json"), "domain.xml": sha(session / "domain.xml"),
                          "host_monitor.jsonl": sha(session / "host_monitor.jsonl"), "ballast_log": sha(ballast_log)},
        "note": ("Read after the capture with the guest idle; QEMU kept running since the capture. Swapped pages "
                 "return only by a swap-in, and the collector reads every guest page in each cycle through "
                 "access_process_vm, which would swap a guest RAM page back in (pswpin)."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k != "swapped_mappings"}, indent=1, ensure_ascii=False))
print("swapped mappings:", len(swapped), swapped[:3])
