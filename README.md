# hyptcn3

Diplomová práca: **Návrh a implementácia hypervisor modulu pre real-time RAM introspekciu
s využitím Temporal Convolutional Networks** (UKF Nitra, aplikačný charakter).
Zadanie je v `zadanie-zp_105826.pdf`.

## Začni tu

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

`vmicollect/` je prevzatý kód zo staršej vetvy projektu (súbory z 2026-08-25/26);
autorstvo sa zatiaľ nepodarilo doložiť a uvádza sa ako neznáme. Commit `6b9053d` obsahuje
tento stav bajt po bajte bez zmien. Commit `178ce4f` mení jediný súbor,
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
