#!/usr/bin/env python3
"""Poskladanie summary.json a env.json z artefaktov v tomto adresari.

Skript necita nic ine nez subory v tomto adresari a v sesii
data/sessions/20260918_validate2 - kazde cislo v summary.json sa teda da
dohladat v sidecari alebo vo vystupe behu, ktory lezi vedla neho.
Hodnoty z prostredia (uname, qemu, ...) su odpisom vystupov v logs/env_zdroj.txt.
"""
import glob
import json
import os
import statistics

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SESSION = os.path.join(REPO, "data", "sessions", "20260918_validate2")
COMMIT = "178ce4fd83e7c504e02fb06a5756de3e79255007"
DATE = "2026-09-18"


def stat(values):
    """Min, max, median a n - ziadne priemery, vzoriek je malo."""
    vals = sorted(values)
    return {"min": vals[0], "max": vals[-1], "median": statistics.median(vals),
            "n": len(vals), "hodnoty": vals}


def sidecars(pattern):
    out = []
    for f in sorted(glob.glob(os.path.join(HERE, "sidecars", pattern, "*.json"))):
        with open(f) as fh:
            d = json.load(fh)
        d["_subor"] = os.path.relpath(f, HERE)
        out.append(d)
    return out


def once_runs(tag):
    """JSONy, ktore vyrobil root_run.sh - zmeskane sloty su iba v nich, nie v sidecari."""
    out = []
    for f in sorted(glob.glob(os.path.join(HERE, tag + "_*.json"))):
        with open(f) as fh:
            out.append((os.path.basename(f), json.load(fh)))
    return out


def once_group(tag):
    ds = sidecars(tag + "_*")
    runs = once_runs(tag)
    return {
        "behy": [{"subor": n,
                  "exit_code": d["exit_code"],
                  "zmeskane_sloty": d["summary"]["cycles_skipped"],
                  "chybne_cykly": d["summary"]["cycles_failed"],
                  "binarka_sha256": d["binary"]["sha256"]} for n, d in runs],
        "zmeskane_sloty": stat([d["summary"]["cycles_skipped"] for _, d in runs]),

        "popis": "vmicollect once, writer=raw, %s; %d opakovani"
                 % ("output.hash=sha256 (vychodzie)" if tag.endswith("sha256")
                    else "output.hash=none", len(ds)),
        "subory": [d["_subor"] for d in ds],
        "capture_ms": stat([d["capture"]["capture_ms"] for d in ds]),
        "write_ms": stat([d["capture"]["write_ms"] for d in ds]),
        "total_ms": stat([d["capture"]["total_ms"] for d in ds]),
        "read_mib_s": stat([d["stats"]["read_mib_s"] for d in ds]),
        "bytes_logical": sorted({d["output"]["bytes_logical"] for d in ds}),
        "bytes_on_disk": sorted({d["output"]["bytes_on_disk"] for d in ds}),
        "read_errors": sorted({d["stats"]["read_errors"] for d in ds}),
        "paused": sorted({d["capture"]["paused"] for d in ds}),
        "pause_ms": sorted({d["capture"]["pause_ms"] for d in ds}),
    }


def main():
    with open(os.path.join(HERE, "probe.json")) as fh:
        probe = json.load(fh)
    with open(os.path.join(HERE, "run_delta_5s.json")) as fh:
        rundoc = json.load(fh)
    with open(os.path.join(HERE, "validate2.json")) as fh:
        val = json.load(fh)
    with open(os.path.join(HERE, "validate2_ss_vsetky.json")) as fh:
        val_all = json.load(fh)

    ds = sidecars("run_delta")
    full = [d for d in ds if d["output"]["full"]]
    delta = [d for d in ds if not d["output"]["full"]]

    values = {
        "probe": {
            "popis": "vmicollect probe -v; cely vystup je v probe.json",
            "subor": "probe.json",
            "memslots": probe["values"]["memslots"],
            "ram_bytes": probe["values"]["ram_bytes"],
            "max_paddr": probe["values"]["max_paddr"],
            "vcpus": probe["values"]["vcpus"],
            "vmid": probe["values"]["vmid"],
            "backend": probe["values"]["backend"],
            "test_citania_mib_s": probe["values"]["read_test"]["mib_s"],
            "poznamka_test_citania": "test citania v probe je jedno kratke citanie "
                                     "16,6 MB, nie priepustnost plnej snimky",
        },
        "once_raw_hash_sha256": once_group("once_raw_sha256"),
        "once_raw_hash_none": once_group("once_raw_none"),
        "run_delta_perioda_5s": {
            "popis": "vmicollect run, writer=delta, perioda 5 s, 12 cyklov; "
                     "cyklus #0 je plna snimka, cykly #1-#11 su prirastkove",
            "subor_behu": "run_delta_5s.json",
            "perioda_s": rundoc["params"]["interval_s"],
            "cyklov_ziadanych": rundoc["params"]["max_cycles"],
            "summary_z_behu": rundoc["summary"],
            "plna_snimka_cyklus_0": {
                "capture_ms": full[0]["capture"]["capture_ms"],
                "write_ms": full[0]["capture"]["write_ms"],
                "total_ms": full[0]["capture"]["total_ms"],
                "pages_changed": full[0]["output"]["pages_changed"],
                "pages_total": full[0]["output"]["pages_total"],
                "changed_ratio": full[0]["output"]["changed_ratio"],
                "bytes_on_disk": full[0]["output"]["bytes_on_disk"],
                "poznamka": "changed_ratio plnej snimky je podiel stranok, ktore "
                            "writer zapisal, nie miera zmeny medzi snimkami",
            },
            "prirastkove_snimky_bez_sedenia_ssh": {
                "popis": "cykly #1-#3 a #8-#11; v hostovi v tomto case nebola "
                         "ziadna prihlasovacia relacia (doklad: "
                         "logs/host_journal_pocas_run.txt)",
                "cykly": [d["seq"] for d in delta if d["seq"] not in (4, 5, 6, 7)],
                "pages_changed": stat([d["output"]["pages_changed"]
                                       for d in delta if d["seq"] not in (4, 5, 6, 7)]),
                "changed_ratio": stat([d["output"]["changed_ratio"]
                                       for d in delta if d["seq"] not in (4, 5, 6, 7)]),
                "bytes_on_disk": stat([d["output"]["bytes_on_disk"]
                                       for d in delta if d["seq"] not in (4, 5, 6, 7)]),
            },
            "prirastkove_snimky_pocas_sedenia_ssh": {
                "popis": "cykly #4-#7 (16:32:37-16:32:52 UTC); o 16:32:36 sa do "
                         "hosta prihlasil a odhlasil ssh (sshd[2154], relacia 141) "
                         "a o 16:32:46 sa ukoncoval user@0.service - tieto cykly "
                         "teda nemeraju necinnu VM",
                "cykly": [4, 5, 6, 7],
                "pages_changed": stat([d["output"]["pages_changed"]
                                       for d in delta if d["seq"] in (4, 5, 6, 7)]),
                "changed_ratio": stat([d["output"]["changed_ratio"]
                                       for d in delta if d["seq"] in (4, 5, 6, 7)]),
                "bytes_on_disk": stat([d["output"]["bytes_on_disk"]
                                       for d in delta if d["seq"] in (4, 5, 6, 7)]),
            },
            "prirastkove_snimky_vsetky": {
                "capture_ms": stat([d["capture"]["capture_ms"] for d in delta]),
                "write_ms": stat([d["capture"]["write_ms"] for d in delta]),
                "total_ms": stat([d["capture"]["total_ms"] for d in delta]),
                "read_mib_s": stat([d["stats"]["read_mib_s"] for d in delta]),
                "pages_changed": stat([d["output"]["pages_changed"] for d in delta]),
                "changed_ratio": stat([d["output"]["changed_ratio"] for d in delta]),
                "bytes_on_disk": stat([d["output"]["bytes_on_disk"] for d in delta]),
                "pages_total": sorted({d["output"]["pages_total"] for d in delta}),
                "read_errors": sorted({d["stats"]["read_errors"] for d in delta}),
                "subory": [d["_subor"] for d in delta],
                "casove_znacky": [d["timestamp"] for d in delta],
            },
        },
        "validacia_voci_pozemnej_prave": {
            "popis": "guestparse validate nad plnou delta snimkou zo sedenia "
                     "data/sessions/20260918_validate2",
            "subory": ["validate2.json", "validate2_ss_vsetky.json"],
            "snimka": os.path.basename(val["snapshot"]["path"]),
            "procesy": val["processes"],
            "moduly": val["modules"],
            "sokety_voci_ss_tulpn": val["sockets"],
            "sokety_voci_ss_tuanp": val_all["sockets"],
            "kontroly": val["checks"],
        },
    }

    summary = {
        "schema": "hyptcn3/summary/1",
        "commit": COMMIT,
        "date": DATE,
        "host": "Fedora Linux 43, jadro 7.1.13-100.fc43.x86_64, Intel i7-12650H, "
                "16 CPU, 16 355 631 104 B RAM (detaily v env.json)",
        "guest": "libvirt domena hyptcn-guest, Debian 12.13, jadro "
                 "6.1.0-42-cloud-amd64, 2 vCPU, 2 GiB; zmrazeny stav - "
                 "bez agenta hyptcn_guest_ag, unattended-upgrades zamaskovane "
                 "(doklad: logs/host_cistota.txt)",
        "command": "scripts/root_run.sh probe|once|run|validate, binarka "
                   "vmicollect/build/vmicollect zostavena z tohto repa "
                   "(sha256 v env.json)",
        "n": {"probe": 1, "once_raw_hash_sha256": 3, "once_raw_hash_none": 3,
              "run_delta_plnych": len(full), "run_delta_prirastkovych": len(delta),
              "validacnych_sedeni": 1},
        "values": values,
    }
    with open(os.path.join(HERE, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("zapisane: summary.json")


if __name__ == "__main__":
    main()
