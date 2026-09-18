#!/usr/bin/env python3
"""Tabulka PRVY BEH (kontaminovany host, binarka zo scratchpadu) vs ZMRAZENY HOST.

Cita summary.json oboch sad a nic ine. Vystup: logs/porovnanie_prvy_beh.txt.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "..", "2026-09-18_prvy_beh", "summary.json")))["values"]
B = json.load(open(os.path.join(HERE, "summary.json")))["values"]

rows = []


def row(n, x, y):
    rows.append("%-44s | %-32s | %s" % (n, x, y))


def rng(d, fmt="%.1f"):
    return (fmt + "-" + fmt + " (n=%d)") % (d["min"], d["max"], d["n"])


pn, ps = B["once_raw_hash_none"], B["once_raw_hash_sha256"]
dv = B["run_delta_perioda_5s"]["prirastkove_snimky_vsetky"]
di = B["run_delta_perioda_5s"]["prirastkove_snimky_bez_sedenia_ssh"]
da = A["delta_snimka"]
v = B["validacia_voci_pozemnej_prave"]

row("velicina", "PRVY BEH (kontaminovany)", "ZMRAZENY HOST")
row("-" * 44, "-" * 32, "-" * 40)
row("once raw hash=none: capture_ms", "554.305 (n=1)", rng(pn["capture_ms"]))
row("once raw hash=none: write_ms", "194.153 (n=1)", rng(pn["write_ms"]))
row("once raw hash=none: total_ms", "748.48 (n=1)", rng(pn["total_ms"]))
row("once raw hash=sha256: capture_ms", "430.579 (n=1)", rng(ps["capture_ms"]))
row("once raw hash=sha256: write_ms", "41774.078 (n=1)", rng(ps["write_ms"], "%.0f"))
row("once raw hash=sha256: total_ms", "42204.67 (n=1)", rng(ps["total_ms"], "%.0f"))
row("pomer total_ms sha256/none (medianov)", "56.4", "%.1f" % (ps["total_ms"]["median"] / pn["total_ms"]["median"]))
row("zmeskane sloty once sha256 / none", "8 / 0 (n=1 kazde)", "%s / %s (n=3 kazde)" % (ps["zmeskane_sloty"]["hodnoty"], pn["zmeskane_sloty"]["hodnoty"]))
row("bytes_logical raw snimky", "2164396032", "%d" % pn["bytes_logical"][0])
row("bytes_on_disk raw sha256 / none", "322043904 / 517079040", "%d / %d" % (ps["bytes_on_disk"][0], pn["bytes_on_disk"][0]))
row("delta capture_ms (perioda 5 s)", rng(da["capture_ms"]), rng(dv["capture_ms"]))
row("delta total_ms", rng(da["total_ms"]), rng(dv["total_ms"]))
row("delta pages_changed", rng(da["pages_changed"], "%d"), rng(dv["pages_changed"], "%d"))
row("  z toho bez ssh relacie v hostovi", "-", rng(di["pages_changed"], "%d"))
row("delta changed_ratio", rng(da["changed_ratio"], "%.6f"), rng(dv["changed_ratio"], "%.6f"))
row("  z toho bez ssh relacie v hostovi", "-", rng(di["changed_ratio"], "%.6f"))
row("pages_total", "%d" % da["pages_total"][0], "%d" % dv["pages_total"][0])
row("procesy: stabilna mnozina / najdene", "80 / 80", "%d / %d" % (v["procesy"]["stable"], v["procesy"]["found"]))
row("procesy: chybajuce / falosne / zle meno", "0 / 0 / 0", "%d / %d / %d" % (v["procesy"]["missing"], v["procesy"]["false_positive"], v["procesy"]["name_mismatch"]))
row("moduly: snimka / lsmod / sediace", "47 / 47 / 47", "%d / %d / %d" % (v["moduly"]["snapshot"], v["moduly"]["ground_truth"], v["moduly"]["matched"]))
row("sokety voci ss -tulpn: sediace/chyb/navyse", "10 sedelo, 13 zo snimky", "%d / %d / %d" % (v["sokety_voci_ss_tulpn"]["matched"], v["sokety_voci_ss_tulpn"]["missing"], v["sokety_voci_ss_tulpn"]["extra"]))
row("sokety voci ss -tuanp: sediace/chyb/navyse", "nemerane (vystup ss nebol ulozeny)", "%d / %d / %d" % (v["sokety_voci_ss_tuanp"]["matched"], v["sokety_voci_ss_tuanp"]["missing"], v["sokety_voci_ss_tuanp"]["extra"]))
row("probe: memsloty / vCPU", "10 / 2", "%d / %d" % (B["probe"]["memslots"], B["probe"]["vcpus"]))
row("probe: test citania MiB/s", "2297", "%s" % B["probe"]["test_citania_mib_s"])

text = "\n".join(rows) + "\n"
with open(os.path.join(HERE, "logs", "porovnanie_prvy_beh.txt"), "w") as fh:
    fh.write("# tabulku vyrobil porovnanie_prvy_beh.py zo summary.json oboch sad\n\n")
    fh.write(text)
print(text)
