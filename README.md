# hyptcn3

Diplomová práca: **Návrh a implementácia hypervisor modulu pre real-time RAM introspekciu
s využitím Temporal Convolutional Networks** (UKF Nitra, aplikačný charakter).
Zadanie je v `zadanie-zp_105826.pdf`.

## Začni tu

**Integrovaný safeguard:** [`docs/SAFEGUARD.sk.md`](docs/SAFEGUARD.sk.md).
`python3 -m safeguard` poskytuje tréning, načítanie, prehrávanie a spoločný
beh zberača s detektorom. `smoke` overuje mechaniku na syntetických dátach;
nový korpus, živý spoločný beh a účinnosť detekcie zostávajú na overenie.

**Metodika zberu a príznakov:** [`docs/METODIKA_ZBERU.sk.md`](docs/METODIKA_ZBERU.sk.md).
`make collection-plan` vypíše pridelenie behov do tréningu, vývoja, kalibrácie
a testu. Nové merania začínajú pilotom a auditom dát; staré krátke zbery
nie sú automaticky súčasťou finálneho korpusu.
Pilot protokolu v2 prešiel po oprave výberu jadra podľa boot UUID;
[prijatý audit](data/results/collection_pilot_v2_20261013_reaudit.json) a história
oboch zamietnutých auditov sú zaznamenané v [`docs/MERANIA.md`](docs/MERANIA.md).
Pilot sa nepoužije na tréning ani kalibráciu.

**Kontrola pripravenosti dát:** [`docs/KONTROLA_ZBERU.sk.md`](docs/KONTROLA_ZBERU.sk.md).
`collection.py coverage` vysvetlí skórovateľné okná a výpadky z uložených
príznakov; `collection_logs.py` overí klientské, nginx a aplikačné logy,
ich kontrolné súčty a priebeh merania. Obe kontroly sú súčasťou úplného auditu.

**Automatická kampaň:** [`docs/AUTOMATICKY_ZBER.sk.md`](docs/AUTOMATICKY_ZBER.sk.md).
`scripts/campaign.py` riadi reštarty skupín, zber, audit a overený presun RAM
do archívu na systémovom HDD (rozloženie v [`docs/AUTOMATICKY_ZBER.sk.md`](docs/AUTOMATICKY_ZBER.sk.md)).
Na konci vytvorí index pre tréning; stav kampane rozlišuje
naplánované, rozpracované a prijaté dáta.

**Serverové laboratórium:** `make lab-up` spustí samostatnú VM s nginx,
API službami, PostgreSQL a premávkou z hostiteľa. Vstup je
**http://127.0.0.1:18080**; `make lab-status`, `make lab-test` a `make lab-stop`
slúžia na kontrolu a vypnutie. Postup a napojenie RAM zberu:
[`docs/LAB.sk.md`](docs/LAB.sk.md).

**[`docs/PRIRUCKA.md`](docs/PRIRUCKA.md)** — čo to je, čo treba mať, ako vznikne snímka,
čo je kde, ako to funguje, aké čísla sú namerané a čo nefunguje. Generuje sa z kódu
a z uložených artefaktov, takže sa s kódom nerozíde ticho, a všetko ostatné je odtiaľ
odkázané. Tento súbor zámerne neopakuje jej obsah: dve ručne písané kópie toho istého
sa rozídu a nič to neohlási.

Bez virtuálneho stroja a bez roota sa repozitár preloží a otestuje takto:

```sh
make -C vmicollect && make -C vmicollect test && python3 -m pytest -q
```

Zber nad bežiacou VM, profil jadra hosťa a rekonštrukcia objektov zo snímky sú
v príručke (kapitoly *Čo treba mať* a *Ako vznikne snímka*), zoznam adresárov
v kapitole *Čo je kde* a zoznam ostatných dokumentov v kapitole *Kam ďalej*.

## Pôvod kódu

Zberač `vmicollect/` pochádza zo staršej vetvy projektu (súbory z 2026-08-25/26) a je
vlastnou prácou autora. Commit `6b9053d` obsahuje stav zo staršej vetvy bajt po bajte bez
zmien; slovo „prevzatý“ v správe tohto commitu znamená prenesenie zo staršej vetvy, nie
cudzie autorstvo. Commit `178ce4f` mení jediný súbor,
`vmicollect/bpf/vmic_kvm.bpf.c`, a opravuje štyri dôvody, prečo sa BPF program nenačítal
do jadra 7.1 (nezhoda BTF pri `bpf_task_from_vpid` a trikrát limit verifikátora riešený
`bpf_loop()`). Bez týchto opráv `probe` nad bežiacou VM zlyhával. Rozbor je
v `docs/MERANIA.md`.

`guestparse/` nadväzuje na prototyp parsera `vmi_parse.py` z prípravnej fázy (mimo repa).
Provenienciu jednotlivých častí uvádza `docs/ARCHITEKTURA.md` (kapitola o pôvode);
hlavičky súborov `guestparse/` ju neopakujú.

Profil jadra hosťa (`profiles/`) je priznaná jednorazová vstupná závislosť získaná
z hosťa — rovnako ako profil pri LibVMI alebo Volatility. Podrobne
v `profiles/debian12-6.1.0-42-cloud-amd64/README.md`.

## Pravidlá pre text a čísla

Platí [`HONESTY.md`](HONESTY.md) a kontroluje to `scripts/check_claims.sh`, ktorý musí
pred odovzdaním vrátiť 0 nálezov. Pravidlá sú v tom súbore; tu sa neopakujú.
