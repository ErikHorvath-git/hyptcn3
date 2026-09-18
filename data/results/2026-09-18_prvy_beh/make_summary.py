#!/usr/bin/env python3
"""Zostavi summary.json zo sidecarov ulozenych v tomto adresari.

Preco skript a nie rucne napisany JSON: kazde cislo v summary.json musi byt
dohladatelne v konkretnom sidecari. Rucne prepisane cislo by nikto nezachytil.
Hodnoty, ktore v sidecaroch nie su (zmeskane sloty zo stdout, rekonstrukcia
objektov z parsera), sa sem dostanu z MERANIA_2026-09-18.md a maju v JSONe
vlastne pole "zdroj", aby bolo vidno, ze nepochadzaju zo sidecara.

Spustenie:  python3 make_summary.py   (v adresari s podadresarom sidecars/)
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# poradie behov, v akom sa robili - drzime ho kvoli citatelnosti reportu
RUNS = ["vmic-test", "vmic-delta", "vmic-nohash", "vmic-val"]


def nacitaj():
    out = {}
    for run in RUNS:
        d = os.path.join(HERE, "sidecars", run)
        out[run] = [json.load(open(os.path.join(d, f)))
                    for f in sorted(os.listdir(d)) if f.endswith(".json")]
    return out


def statistika(hodnoty):
    """min/max/median/n - bez priemeru, pri n=4 az 5 by to nic nepridalo."""
    h = sorted(hodnoty)
    n = len(h)
    med = h[n // 2] if n % 2 else (h[n // 2 - 1] + h[n // 2]) / 2.0
    return {"min": h[0], "max": h[-1], "median": med, "n": n, "hodnoty": h}


def ref(sc, run):
    return "sidecars/%s/%s.json" % (run, sc["id"])


def main():
    sc = nacitaj()
    commit = subprocess.check_output(
        ["git", "-C", REPO, "rev-parse", "HEAD"]).decode().strip()

    # plna snimka = output.full == true, bez ohladu na writer (raw aj delta)
    plne = [(s, r) for r in RUNS for s in sc[r] if s["output"]["full"]]
    delty = [(s, "vmic-delta") for s in sc["vmic-delta"] if not s["output"]["full"]]

    d = {
        "schema": "hyptcn3/summary/1",
        "date": "2026-09-18",
        "commit": commit,
        "host": "Fedora 43, jadro 7.1.13-100.fc43.x86_64, 16 CPU (detaily v env.json)",
        "guest": "libvirt domena hyptcn-guest, Debian 12, jadro 6.1.0-42-cloud-amd64, "
                 "2 vCPU, 2 GiB (detaily v env.json)",
        "command": "vmicollect once/run nad bezacou domenou hyptcn-guest; "
                   "binarka zo scratchpadu (viz env.json), nie z tohto repa",
        "n": len(plne) + len(delty),
        "poznamka": "Polozky s 'zdroj' = 'sidecar' su vytiahnute zo sidecarov v tomto "
                    "adresari. Polozky s 'zdroj' = 'MERANIA_2026-09-18.md' pochadzaju zo "
                    "stdout behu alebo z behu parsera a v sidecaroch NIE SU - do repa sa "
                    "dostali iba ako text, nie ako strojovy vystup.",
        "values": {},
    }
    v = d["values"]

    v["plna_snimka"] = {
        "popis": "vsetky snimky s output.full=true (raw aj prva plna delta)",
        "zdroj": "sidecar",
        "subory": [ref(s, r) for s, r in plne],
        "capture_ms": statistika([s["capture"]["capture_ms"] for s, _ in plne]),
        "read_mib_s": statistika([s["stats"]["read_mib_s"] for s, _ in plne]),
        "total_ms": statistika([s["capture"]["total_ms"] for s, _ in plne]),
        "read_errors": sorted({s["stats"]["read_errors"] for s, _ in plne}),
        "paused": sorted({s["capture"]["paused"] for s, _ in plne}),
        "pause_ms": sorted({s["capture"]["pause_ms"] for s, _ in plne}),
    }

    v["delta_snimka"] = {
        "popis": "prirastkove snimky z behu run, writer=delta, perioda 5 s, 6 cyklov "
                 "(cyklus #0 je plna snimka a je zapocitany v plna_snimka)",
        "zdroj": "sidecar",
        "subory": [ref(s, r) for s, r in delty],
        "perioda_s": 5,
        "capture_ms": statistika([s["capture"]["capture_ms"] for s, _ in delty]),
        "total_ms": statistika([s["capture"]["total_ms"] for s, _ in delty]),
        "read_mib_s": statistika([s["stats"]["read_mib_s"] for s, _ in delty]),
        "pages_changed": statistika([s["output"]["pages_changed"] for s, _ in delty]),
        "changed_ratio": statistika([s["output"]["changed_ratio"] for s, _ in delty]),
        "bytes_on_disk": statistika([s["output"]["bytes_on_disk"] for s, _ in delty]),
        "pages_total": sorted({s["output"]["pages_total"] for s, _ in delty}),
        "read_errors": sorted({s["stats"]["read_errors"] for s, _ in delty}),
    }

    full_delta = [s for s, _ in plne if s["output"]["writer"] == "delta"]
    v["changed_ratio_plnych_snimok"] = {
        "popis": "changed_ratio prvej (plnej) snimky retazca - podiel stranok, ktore "
                 "writer skutocne zapisal; nie je to miera zmeny medzi snimkami",
        "zdroj": "sidecar",
        "hodnoty": {s["id"]: s["output"]["changed_ratio"] for s in full_delta},
    }

    t = sc["vmic-test"][0]
    nh = sc["vmic-nohash"][0]
    v["hash_experiment"] = {
        "popis": "ten isty prikaz (once, writer=raw) s output.hash=sha256 a s "
                 "output.hash=none; SHA-256 sa v predvolenom rezime pocita nad celym "
                 "4 GiB riedkym suborom vratane dier",
        "zdroj": "sidecar",
        "sha256": {
            "subor": ref(t, "vmic-test"),
            "capture_ms": t["capture"]["capture_ms"],
            "write_ms": t["capture"]["write_ms"],
            "total_ms": t["capture"]["total_ms"],
            "read_mib_s": t["stats"]["read_mib_s"],
            "bytes_on_disk": t["output"]["bytes_on_disk"],
        },
        "none": {
            "subor": ref(nh, "vmic-nohash"),
            "capture_ms": nh["capture"]["capture_ms"],
            "write_ms": nh["capture"]["write_ms"],
            "total_ms": nh["capture"]["total_ms"],
            "read_mib_s": nh["stats"]["read_mib_s"],
            "bytes_on_disk": nh["output"]["bytes_on_disk"],
        },
        "pomer_total_ms": round(t["capture"]["total_ms"] / nh["capture"]["total_ms"], 1),
    }

    v["zmeskane_sloty"] = {
        "popis": "pocet zahodenych slotov planovaca; v sidecari nie je ziadne take pole, "
                 "cislo pochadza zo stdout prislusneho behu",
        "zdroj": "MERANIA_2026-09-18.md",
        "run_delta_perioda_5s": 0,
        "once_raw_hash_sha256": 8,
        "once_raw_hash_none": 0,
        "najvacsie_meskanie_s_run_delta": 0.0,
    }

    # stabilnu mnozinu prepocitavame z ulozenej pozemnej pravdy, nie z textu MERANIA -
    # je to jedina cast rekonstrukcie, ktoru vieme z repa overit bez parsera
    gt = os.path.join(HERE, "ground_truth")
    pred = [l.split(None, 1) for l in open(os.path.join(gt, "ps_before.txt")).read().split("\n") if l.strip()]
    po = [l.split(None, 1) for l in open(os.path.join(gt, "ps_after.txt")).read().split("\n") if l.strip()]
    pid_pred = {p[0] for p in pred}
    pid_po = {p[0] for p in po}
    par_pred = {(p[0], p[1]) for p in pred}
    par_po = {(p[0], p[1]) for p in po}

    v["rekonstrukcia_objektov"] = {
        "popis": "vystup parsera vmi_parse.py nad snimkou "
                 "sidecars/vmic-val/%s.json; parser este nie je v repe (krok K07), "
                 "preto sa jeho vystup nedal ulozit ako JSON" % sc["vmic-val"][0]["id"],
        "zdroj": "MERANIA_2026-09-18.md",
        "procesy": {
            "ps_pred": 84,
            "ps_po": 82,
            "stabilna_mnozina": 80,
            "rekonstruovanych_zo_snimky": 82,
            "najdenych_zo_stabilnej_mnoziny": 80,
            "chybajuce": 0,
            "falosne": 0,
            "nezhoda_mien": 0,
            "pozemna_prava": ["ground_truth/ps_before.txt", "ground_truth/ps_after.txt"],
            "prepocet_z_pozemnej_pravdy": {
                "zdroj": "tento skript nad ground_truth/ps_*.txt, 2026-09-18",
                "ps_pred_riadkov": len(pred),
                "ps_po_riadkov": len(po),
                "prienik_podla_pid": len(pid_pred & pid_po),
                "prienik_podla_pid_a_mena": len(par_pred & par_po),
                "poznamka": "stabilna mnozina 80 je prienik podla PID; prienik podla "
                            "dvojice (pid, meno) je o 3 mensi, lebo trom vlaknam kworker "
                            "sa medzi oboma behmi ps zmenil nazov podla prave vykonavanej "
                            "prace (napr. kworker/1:0-events -> kworker/1:0-mm_percpu_wq)",
            },
        },
        "moduly": {
            "rekonstruovanych": 47,
            "lsmod_v_case_snimky": 47,
            "zhoda": "47 / 47 vratane poradia zavadzania",
            "pozemna_prava": "vystup lsmod nebol ulozeny do suboru",
        },
        "sokety": {
            "rekonstruovanych": 13,
            "pocuvajucich_zhodnych_so_ss": 10,
            "pocuvajucich_v_ss": 10,
            "poznamka": "IPv6 adresy sa citaju ako IPv4 polia a protokol IPv6 soketov sa "
                        "neurci (chyba skc_v6_daddr a tcpv6_prot/udpv6_prot) - krok K10",
            "pozemna_prava": "vystup ss -tulpn nebol ulozeny do suboru",
        },
        "preklad_adries": {
            "posun_kaslr": "-0x200000",
            "page_offset_base": "0xffff99c940000000",
            "krizova_kontrola": {"linux_banner": "0x16f1f560", "init_task": "0x1781aa40"},
        },
    }

    v["probe"] = {
        "popis": "vmicollect probe -v nad bezacou domenou; vystup nebol ulozeny do suboru",
        "zdroj": "MERANIA_2026-09-18.md",
        "memslotov": 10,
        "pamat_gib": 2.02,
        "max_gpa": "0x100000000",
        "vcpu": 2,
        "test_citania_mib_s": 2297,
    }

    v["snimky"] = {
        "popis": "identita samotnych .vmicd/.raw suborov (su mimo gitu, zostavaju v "
                 "/var/tmp) a vysledok porovnania ich sha256 so sidecarom",
        "zdroj": "snapshots.json",
    }

    d["chyba_v_datach"] = [
        "Pocet zmeskanych slotov nie je v ziadnom sidecari - schema vmicollect/1 take pole "
        "nema. Do repa sa dostal iba ako cislo z MERANIA_2026-09-18.md.",
        "Vystup prikazov lsmod a ss -tulpn (pozemna prava k modulom a soketom) nebol "
        "ulozeny; ulozena je iba pozemna prava k procesom (ps_before/ps_after).",
        "Vystup vmicollect probe nebol ulozeny ako subor.",
        "Vystup parsera (procesy, moduly, sokety) nebol ulozeny ako JSON, lebo parser v "
        "case merania este nebol v repe.",
    ]

    with open(os.path.join(HERE, "summary.json"), "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("summary.json zapisany, n =", d["n"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
