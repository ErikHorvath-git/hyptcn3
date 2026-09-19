# Syntetické scenáre správania

Šesť malých programov v Pythone, ktoré v hosťovi vyrobia **definované správanie**.
Slúžia ako trieda (label) pri zbere korpusu: `scripts/collect_corpus.sh` spustí scenár
v hosťovi a na hostiteľovi počas jeho behu zbiera snímky pamäte.

## Prečo sa volajú podľa správania, nie podľa rodín malvéru

V tejto práci **nie je ani jedna reálna malvérová vzorka**. Trieda sa preto volá
`mass_file_rewrite`, nie „ransomware“, a `anon_exec`, nie „fileless malware“ — názov
hovorí, čo program naozaj robí. Je to pravidlo P4 z `HONESTY.md`: keby sa trieda volala
podľa rodiny malvéru, čitateľ by tabuľku výsledkov prečítal ako meranie voči reálnemu
malvéru, ktoré sa nekonalo. Veta „presnosť voči reálnym malvérovým vzorkám nebola
meraná“ platí aj pre tieto scenáre.

Žiadny zo scenárov nič nešifruje, nič neskrýva, nemení konfiguráciu hosťa a nesiaha mimo
vlastný dočasný adresár.

## Scenáre

| scenár | čo robí | akú stopu má zanechať |
|---|---|---|
| `idle.py` | spí | referencia: „stroj stojí“ |
| `cpu_burn.py` | celočíselný výpočet v slučke, žiadne súbory, žiadna alokácia | záťaž CPU bez práce s pamäťou a diskom |
| `mass_file_rewrite.py` | opakovane prepisuje 200 súborov po 64 KiB vo vlastnom dočasnom adresári náhodnými bajtmi | veľa zapísaných stránok page cache s vysokou entropiou |
| `proc_scan.py` | opakovane číta `/proc/<pid>/{stat,status,cmdline,maps}` | prieskum: záťaž v jadre, len čítanie |
| `anon_exec.py` | mapuje anonymnú pamäť so zápisom **aj** spúšťaním, vyplní ju náhodnými bajtmi, spustí z nej 6 bajtov strojového kódu (`mov eax, 42; ret`) | kód, ktorý nikdy nie je súborom — presne to, čo má introspekcia RAM vidieť |
| `fork_storm.py` | po dávkach vytvára a hneď zbiera krátkožijúce procesy | obmena zoznamu procesov medzi snímkami (príznaky `proc_new`, `proc_gone`) |

Každý sa spúšťa rovnako a má jediný parameter — trvanie v sekundách:

```sh
python3 scenarios/idle.py 10
```

Na konci vypíše **jeden riadok JSON** so súhrnom toho, čo spravil; ten riadok sa ukladá
do `labels.json` sedenia, takže pri každom sedení je doložené nielen čo sa spustilo, ale
aj koľko práce to stihlo.

## Prečo je každý scenár samostatný súbor bez spoločného modulu

Hosť nemá sieť do vonkajšieho sveta ani `scp`; scenár sa doňho prenáša ako base64
v jednom príkaze (`scripts/guest_exec.sh`, ktorý funguje aj cez `qemu-guest-agent`, teda
aj bez siete v hosťovi). Prenáša sa vždy **jeden súbor**. Spoločný modul by sa musel
prenášať tiež a scenár by prestal byť spustiteľný sám o sebe. Cenou je zopár riadkov,
ktoré sa opakujú (spracovanie parametra a slučka po čas trvania).

Hosť nemá gcc ani make (overené), preto Python a nie C.

## Bezpečnosť — a ako je overená

Požiadavky: bežať obmedzený čas, upratať po sebe, nenechať bežiaci proces, nesiahať
mimo vlastný dočasný adresár. Overené **behom**, nie čítaním:

- každý scenár bežal v hosťovi 10 s (2026-09-19, doména `hyptcn-guest`,
  jadro `6.1.0-42-cloud-amd64`), všetky skončili s návratovým kódom 0;
- po každom behu `pgrep -af 'scen_<trieda>.py'` nevypísal nič a `ls -d /tmp/mass_file_rewrite.*`
  nenašiel žiadny zvyšný adresár; počet zombie procesov bol 0;
- `mass_file_rewrite` hlási v súhrne `"adresar_zmazany": true` (`shutil.rmtree` je vo
  `finally`, takže adresár zmizne aj pri prerušení);
- `fork_storm` čaká `waitpid` na každé vytvorené dieťa — v behu 7 960 detí,
  7 960 pozbieraných;
- `anon_exec` kontroluje návratovú hodnotu spusteného kódu (v behu 181 kôl,
  0 zlých návratov) a oblasť po každom kole odmapuje.

`scripts/collect_corpus.sh` navyše po **každom** sedení zisťuje, či v hosťovi nezostal
bežať proces scenára, a zapíše to do `labels.json` (`zvysne_procesy_v_hostovi`). Zvyšok
po jednom sedení by inak ticho kontaminoval všetky nasledujúce.

Čo scenáre **nerobia**: nemenia nastavenia hosťa, nepíšu mimo `tempfile.mkdtemp()`,
nesiahajú na sieť, nespúšťajú nič stiahnuté a `mass_file_rewrite` nikdy nemaže ani
neprepisuje cudzí súbor — pracuje len so súbormi, ktoré si sám vytvoril.

## Ako sa z nich zbiera korpus

```sh
scripts/collect_corpus.sh --dry-run          # plán, root netreba
sudo -A scripts/collect_corpus.sh -s 3 -t 60 # ostrý zber
```

Jedno sedenie = jeden scenár + reťazec snímok, ktoré vznikli počas jeho behu +
`labels.json`. Poradie tried sa v každom kole pootočí, aby sa do dát nedostal čas ako
confound. Podrobnosti sú v hlavičke `scripts/collect_corpus.sh`.

Veľkosť: v overovacom sedení (`fork_storm`, 10 s, perióda 5 s, 2 snímky) mala plná
snímka na disku 574 046 208 B (547,45 MiB) a delta za ňou 29 798 400 B (28,41 MiB) —
plná snímka je preto nastavená na jednu na sedenie (`output.delta_full_every` je o jedna
vyššie než počet cyklov). Zdroj čísel: pole `output.bytes_on_disk` v sidecaroch sedenia,
beh je zapísaný v `data/results/run_20260919T011815Z.json` (snímky samotné sú v
`data/raw/`, teda mimo gitu).
