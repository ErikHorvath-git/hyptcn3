# GitHub issues — dostavba hyptcn3 do day-0 safeguardu (fáza 0)

Jeden issue na blok. Každý obsahuje: čo treba, existujúci kód, z ktorého stavať
(overené v `docs/AUDIT.md`), a akceptačné kritériá (test/artefakt). Po schválení
plánu sa vytvoria príkazom `gh issue create --title "…" --body-file …`
(v repozitári `ErikHorvath-git/hyptcn3`).

---

## A1 — Overenie výberu domény podľa mena pri viacerých VM + znovupripojenie po reštarte

**Stav podľa auditu:** výber menom je implementovaný (`pick_vm`, presná zhoda →
substring → chyba pri nejednoznačnosti; `pid:N`), znovupripojenie po zmene pidu je
implementované (`eb_begin_cycle` + `refresh_vm`). **Neoverené naživo.**

- Existujúci kód: `vmicollect/src/backend_ebpf.c:493-587` (scan_vms, pick_vm),
  `:1028-1054` (eb_begin_cycle), `vmicollect/src/collector.c:125-142` (refresh_vm).
- Čo treba: druhá VM (klon domény) + test: (1) `probe` vyberie správnu doménu pri
  dvoch bežiacich; (2) `run` počas behu prežije reštart hosťa (nový QEMU pid) a
  pokračuje rovnakým menom; (3) záznam v sidecari (`vm.vmid` sa zmení, meno ostane).
- Akceptácia: nový test/artefakt `data/results/` s oboma scenármi; bez prepisovania
  existujúcej logiky (len oprava, ak test ukáže dieru).

---

## A2 — Automatické preukotvenie profilu po KASLR posune (namiesto pádu s kódom 5)

**Stav:** detekcia nesúladu je hotová a overená naživo (exit 5, `NESULAD PROFILU`);
nástroj vie nájsť banner, vypočítať posun aj potvrdiť lineárne čítanie, ale vždy
vyžaduje ručný `get_profile.sh -f`.

- Existujúci kód: `guestparse/view.py:76-112` (resolve: banner + posun),
  `:657-738` (_linear_confirmed, _mismatch_text), `guestparse/cli.py:309-359`
  (kontrola pred podpríkazom, final, exit 5), `scripts/get_profile.sh`.
- Čo treba: po zistení posunu skúsiť preukotvenie (aplikovať posun na kallsyms adresy
  a znova krížovo overiť walk) a pokračovať; ak to nejde (napr. FGKASLR), automaticky
  spustiť `get_profile.sh -f` cez `guest_exec.sh` a pokračovať; výsledok aj dôvod
  zapísať do výstupu. Debian 6.1 bez FGKASLR → posun by mal stačiť.
- Akceptácia: snímka zo staršieho bootu + profil z novšieho (dnes v repe: relácia
  `20260918T154914Z_validate`) → `ps/lsmod/ss/validate` dobehnú s oznámením o
  preukotvení, nie exit 5. Test v `guestparse/tests/`.

---

## A3 — 4. invariant: zmena v binoch rozsahu textu jadra (chytí inline hooky, ktoré invariant #1 nevidí)

**Stav:** 3 invarianty hotové; priznané slepé miesto — hook smerujúci vnútri
`[_stext,_etext)` je pre kontrolu sys_call_table neviditeľný.

- Existujúci kód: `guestparse/checks.py:105-158` (vzor kontroly + `summary.inconclusive`),
  `docs/kontroly.md:53-59` (pomenované slepé miesta), rozsah textu z kallsyms v profile.
- Čo treba: rozsah textu jadra (z profilu) rozdeliť na biny rovnakej veľkosti ako
  per-bin zber; referenčný hash/entropiu textu odobrať pri čistom stave; kontrola
  hlási bin mimo očakávania. Text sa nikdy nemá meniť — invariant je deterministický.
- Akceptácia: injekčný test do **kópie** snímky (prepis v texte) → nález; čistá snímka → 0 nálezov; pole v `checks` JSON + HONESTY značka.

---

## A4 — Mapovanie bin → proces cez tabuľky stránok hosťa (alarm povie „ktorý proces“)

**Stav:** preklad adries funguje len pre jadro (4-úrovňový walk z `init_top_pgt`);
user-space preklad neexistuje; per-bin vektor je fyzický (GPA), nie procesový.

- Existujúci kód: `guestparse/view.py:165-275` (walk PGD/PUD/PMD/PTE),
  `guestparse/view.py:365,376` (task_struct.mm sa číta len pre kernel_thread flag),
  `vmicollect/src/perbin.c` (fyzické biny).
- Čo treba: pre každý bežiaci proces odčítať CR3/`mm->pgd`, prejsť jeho tabuľky a
  pre zmenený bin (GPA) určiť, ktorého procesu (alebo jadra) stránka patrí.
- Akceptácia: test na kópii snímky so známym procesom, ktorý si alokoval pamäť →
  zmenený bin sa priradí správnemu PID; výstup v alarmovom JSON (A6).

---

## A5 — `hold` marker v `retention.c` (označený reťazec sa nezmaže — flight recorder)

**Stav:** retencia maže celé reťazce podľa `max_snapshots/max_bytes/max_age_s`;
ochrana je len v pamäti (aktívny + najnovší reťazec).

- Existujúci kód: `vmicollect/src/retention.c:101-287` (zoskupenie po reťazcoch,
  politiky `:239-249`, ochrana `:212-235`).
- Čo treba: trvalý marker (súbor/atribút, napr. `HOLD` vedľa snímky alebo
  `.hold` v adresári), ktorý prežije reštart zberaca; reťazec s markerom sa pri
  upratovaní preskočí.
- Akceptácia: `make test` + nový regresný test (retazec s markerom prežije
  `max_snapshots=1`), dokumentované v `vmicollect/README.md`.

---

## A6 — Alarmové rozhranie: `alarm.json` (čas, skóre, top biny, invarianty) + hook, ktorý alarm dostane

**Stav:** hook API má jediný event po snímke (`vmic_hook_snapshot`); žiadny alarm.

- Existujúci kód: `vmicollect/src/hooks.c:62-160`, `vmicollect/include/vmic.h:432-462`
  (ABI), `vmicollect/src/meta.c:42-202` (JSON writer, `json_str`).
- Čo treba: nový event `vmic_hook_alarm` + štruktúra alarmu (timestamp, seq, zdroj
  — invariant/prediktor —, skóre, top-N binov s adresami, stav invariantov, prípadné
  PID z A4); zber zapíše `alarm.json` do výstupného adresára; example hook alarm
  prijíma (rozšírenie `example_hook.c`).
- Akceptácia: test — injekcia do kópie snímky → vznikne alarm.json so správnymi
  poľami a hook ho dostane; čistý beh → žiadny alarm.

---

## A7 — VOLITEĽNÁ reakcia na úrovni hypervízora cez libvirt (default VYPNUTÁ, s meranou latenciou alarm→reakcia)

**Stav:** neexistuje; v kóde sú len prázdne `ops->pause/resume` a rady v komentároch.

- Existujúci kód: `vmicollect/src/backend.c:102-133` (`vmic_backend_pause/resume`),
  `vmicollect/src/backend_ebpf.c:1167-1168` (prázdne ops),
  `vmicollect/src/collector.c:303-304` (komentár o `virsh resume`).
- Čo treba: nový backend/reakčný plugin nad libvirt (`qemu:///session`):
  `suspend` / `domif-setlink down` / `snapshot-create-as`, voliteľný a **default
  vypnutý**; latencia alarm→reakcia meraná a zapísaná do artefaktu.
- Akceptácia: test s vypnutou reakciou (nič sa nestane) + jeden meraný beh s
  reakciou (`data/results/` s latenciou); bez zásahu do VMM/jadra (iba libvirt API).

---

## A8 — Dlhý beh (hodiny) s evidenciou zmeškaných slotov

**Stav:** počíta sa (`cycles_skipped`), ale iba loguje na koniec behu, nepersistuje sa.

- Existujúci kód: `vmicollect/src/sched.c:110-134`, `vmicollect/include/vmic.h:413-418`
  (vmic_sched_stats_t), `vmicollect/src/main.c:237-240`, `scripts/root_run.sh run`.
- Čo treba: štatistiky plánovača do sidecaru každej snímky (alebo summary JSON);
  aspoň jeden viac-hodinový beh s periódou T a artefaktom s počtom zmeškaných slotov.
- Akceptácia: artefakt v `data/results/` s n, trvaním, 0 zmeškaných slotov (alebo
  čestne priznané) + HONESTY značka; feed do H (soft real-time dôkaz).

---

## B1 — Golden image z cloud-init, definícia v repe

**Stav:** na disku existuje backing `debian-12-base.qcow2` + `cloud-init.iso`
(`/home/eh/vms/`), ale definícia nie je v repe.

- Existujúci kód: `scripts/get_profile.sh` (vzor šablón pre hosť), doména
  `hyptcn-guest` (Debian 12, jadro 6.1.0-42-cloud).
- Čo treba: do repa cloud-init `user-data`/`meta-data` (qemu-guest-agent, sshd,
  nevyhnutné balíky), skript `make_golden.sh` (build base qcow2) a XML domény ako
  šablónu; výsledný SHA-256 base image do manifestu.
- Akceptácia: čerstvý klon domény z definície v repe sa spustí a `guest_exec.sh
  --self-test` dá 4/4.

---

## B2 — Overlay qcow2 + `virsh snapshot-revert` pred každým sedením

**Stav:** štruktúra overlay/backing na disku existuje, ale `snapshot-list` je prázdny.

- Existujúci kód: doména `hyptcn-guest` (disk `/home/eh/vms/hyptcn-guest.qcow2`),
  `scripts/root_run.sh` (štart/kontrola domény).
- Čo treba: snapshot čistého stavu (`virsh snapshot-create-as`) a `snapshot-revert`
  pred každým sedením; sedenie nikdy nepracuje na čistom base, iba na overlayi,
  ktorý sa po behu zahodí.
- Akceptácia: dve po sebe idúce sedenia dajú rovnaký počiatočný stav (porovnanie
  `ps`/`lsmod`/SHA stavu) — čistota štartu overená artefaktom.

---

## B3 — Izolovaná libvirt sieť bez NAT; fake služby na hostiteľovi

**Stav:** existuje len `default` (virbr0, NAT); hosť má statickú IP.

- Existujúci kód: doména (bridge virbr0), `scripts/guest_exec.sh` (ssh + agent —
  agent funguje aj bez siete).
- Čo treba: izolovaná/privátna sieť (bez NAT/MASQUERADE, bez forwardu),
  definícia XML v repe; hostiteľ v nej má falošné služby (DNS/HTTP/SMTP — INetSim
  alebo FakeNet) pre malvérové sedenia G2.
- Akceptácia: z hosťa sa dá dosiahnuť len izolovaná sieť + falošné služby;
  `guest_exec.sh -m agent` stále funguje (ground truth bez siete).

---

## B4 — `root_run.sh session <manifest>`: revert → štart → zber → injekcia → beh → ground truth → stop → zahoď overlay → manifest + tcpdump

**Stav:** podpríkazy probe/validate/once/run existujú; session flow chýba celý.

- Existujúci kód: `scripts/root_run.sh:602-643` (podpríkazy), `scripts/guest_exec.sh`
  (injekcia/ground truth), `scripts/stamp_results.py` (proveniencia),
  `scripts/measure_latency.sh` (vzor merania s JSON výstupom).
- Čo treba: podpríkaz `session` riadený manifestom (typ, štítok, parametre,
  SHA-256 binárky, commit, čas behu): B2 revert → štart → zber → injekcia binárky
  cez guest-agent → pevný čas behu → ground truth pred/po → stop → zahoď overlay →
  zapíš manifest sedenia + `tcpdump` na virbr.
- Akceptácia: jedno sedenie od A po Z spustiteľné jedným príkazom; manifest obsahuje
  všetky polia; výsledky `data/sessions/<stamp>/` + `data/results/`.

---

## B5 — KRITICKÉ: identický priebeh benígnych aj škodlivých sedení (revert, zahriatie, injekcia agentom, ukončenie agenta)

**Stav:** neexistuje žiadny priebeh sedení; chyba prvej iterácie (model sa naučí
harness, nie správanie) sa nesmie zopakovať.

- Existujúci kód: `scripts/root_run.sh validate` (vzor ground truth pred/po),
  `scripts/guest_exec.sh`.
- Čo treba: jediný code path pre oba typy sedení — jediný rozdiel je obsah
  injikovanej binárky (benígna vs. PoC/malvér); zahrievacia fáza rovnako dlhá,
  agent sa spúšťa aj ukončuje rovnako; manifest zaznamenáva priebeh na dôkaz.
- Akceptácia: difftime/profily priebehu benígneho a škodlivého sedenia sa líšia
  len v injekcii (porovnanie z manifestov); test, ktorý to kontroluje.

---

## C — Benígne záťaže (generátory s náhodnými parametrami): idle / nginx+wrk / pgbench / build / rsync+tar|zstd / mix

**Stav:** neexistujú; labely aktivít pre E4 chýbajú.

- Existujúci kód: `scripts/guest_exec.sh` (spúšťanie v hosťovi), per-bin sidecar
  (vstup okien), `features/windows.py` (segmentácia po sedeniach).
- Čo treba: generátor pre každú záťaž s náhodnými parametrami (seed do manifestu),
  štítok aktivity v manifeste sedenia; korpus prvých 10 benígnych sedení.
- Akceptácia: `pytest` — manifest sedenia má štítok; dva behy rovnakej záťaže s
  rôznym seedom dávajú rôzne, ale štítkom rovnaké dáta.

---

## D — Per-bin späť do okien: voliteľný tvar `(N, L, B*4 + 22)` popri `(N, L, 22)`

**Stav:** per-bin vetva bola zmazaná 2026-09-19 (`b574b8d`); tvar
`(N,L,B*4+22)` nikdy neexistoval; dnes len `(N,L,22)`. Počet binov (131 @ 16 MiB
pre hyptcn-guest) závisí od VM → priznať ako obmedzenie.

- Existujúci kód: `b574b8d~1` (čítačky `vektor_z_binov`, `snimka_zo_sidecaru`,
  `nacitaj_session`, `ako_kanaly`), `features/manifest.py:60-78,126-210` (rezim
  `bin_priznak` a `podmienene` ostali), `features/PERBIN.md` (kontrakt),
  `features/windows.py` (dnešný tvar + segmentácia).
- Čo treba: voliteľný tvar okna `(N, L, B*4+22)` (per-bin príznaky + snapshot
  vektor); test tvaru + crosscheck s C vektorom (AUDIT: crosscheck 6/6 na
  `/var/tmp/perbin_c/on`); dokumentovať, že tvar je VM-špecifický.
- Akceptácia: `pytest features` — test tvarov `(N,L,22)` aj `(N,L,B*4+22)` na
  rovnakom vstupe; `python3 -m features crosscheck` stále 6/6.

---

## E1 — Regresná hlava TCN: predikcia vektora v čase t z okna t−n..t−1, strata MSE, tréning BEZ štítkov

**Stav:** `train.py` podporuje len klasifikátor (`CrossEntropyLoss`); prediktor chýba.

- Existujúci kód: `tcn/model.py` (kauzálne dilatované konv. + testy),
  `tcn/train.py:197-245` (slučka + loss — miesto pre MSE vetvu),
  `tcn/tests/test_tcn.py` (kauzalita/RF/determinizmus).
- Čo treba: `tcn/train.py --uloha predikcia` — výstup = vektor v t, strata MSE,
  tréning len na benígnych sedeniach bez štítkov; regresná hlava nad rovnakým
  backbone-om; split po sedeniach (nie oknách).
- Akceptácia: test — model s nulovými vstupmi predpovedá stred (priemer výstupu
  ≈ vektorová nula po z-score); tréningový artefakt (`.pt` + JSON metrík) do
  `data/results/` s HONESTY značkou.

---

## E2 — Skóre anomálie = chyba predikcie; per-bin chyba = lokalizácia

**Stav:** `score.py` dáva softmax netrénovaného modelu, nie chybu predikcie.

- Existujúci kód: `tcn/score.py:103-216` (okná → skóre, medián/p95),
  `features/perbin.py` (per-bin vektory), `features/snapshot.py:103-112` (MENA).
- Čo treba: skóre okna = MSE(reálny vektor, predpovedaný); pri per-bin tvare (D)
  rozložiť chybu na biny → top-N binov do alarmu (A6); latencia snímka→skóre naďalej
  meraná.
- Akceptácia: test — injekcia zmeny do konkrétneho binu kópie snímky zvýši chybu
  práve v tom bine; artefakt `data/results/`.

---

## E3 — `tcn/kalibracia.py`: prah z kvantilu chýb na odloženej benígnej validácii s rozpočtom FP; alarm = k z n okien nad prahom

**Stav:** neexistuje.

- Existujúci kód: `tcn/eval.py` (metriky), `features/normalize.py` (fit len na
  benign train), okná `features/windows.py`.
- Čo treba: prah na základe kvantilu chýb benígnej validačnej časti; prepočet
  base rate (T=5 s → 17 280 okien/deň; „1 FP/deň“ ≈ FPR 6e-5/okno); alarm =
  k z n posledných okien nad prahom; kalibračný JSON s všetkými parametrami.
- Akceptácia: kalibračný artefakt + HONESTY značka; test determinizmu prahu.

---

## E4 — Klasifikátor aktivít = dnešná TCN so štítkami záťaží (zostáva)

**Stav:** celá cesta existuje (train/baseliny/eval), chýba len korpus so štítkami.

- Existujúci kód: `tcn/train.py`, `tcn/baselines.py`, `tcn/eval.py:49-88`,
  `data/results/smoke/` (syntetika).
- Čo treba: natrénovať na benígnych sedeniach z C (split po sedeniach), manifest
  normalizácie uložiť (`normalize.py` už vie), vyhodnotiť s baselinami do jednej
  tabuľky.
- Akceptácia: `data/results/` s per-trieda metrikami + HONESTY značky; model a
  manifest sa dajú načítať cez `tcn/score.py`.

---

## F — Anomálne baseliny: z-score na vektore, Isolation Forest, GRU prediktor (porovnateľný počet parametrov) — do JEDNEJ tabuľky s TCN

**Stav:** baseliny existujú len ako klasifikátory.

- Existujúci kód: `tcn/baselines.py:43-86`, `tcn/eval.py` (tabuľka),
  `features/normalize.py`.
- Čo treba: anomálne verzie troch baselin (z-score/Mahalanobis, IsolationForest,
  GRU s regresnou hlavou ≈ parametre TCN), rovnaký kalibračný rozpočet FP (E3),
  výsledky do jednej tabuľky s TCN.
- Akceptácia: tabuľka FAR/h + ttd pre všetky modely v `data/results/`;
  ak baseline dorovná TCN — je to výsledok (P8), uviesť čestne.

---

## G1 — PoC techniky (ground truth, LEN na vývoj/validáciu citlivosti, NIKDY tréning): Diamorphine LKM, LD_PRELOAD hider, memfd_create, šifrovanie súborov, kryptominer

**Stav:** neexistujú (injekčný test je prepis 8 bajtov v kópii snímky).

- Existujúci kód: `guestparse/checks.py` (invarianty), `scripts/guest_exec.sh`
  (spustenie v hosťovi), `data/sessions/` (vzor ground truth).
- Čo treba: zostaviť/spustiť PoC v hosťovi počas sedenia (B4); pozemná pravda;
  meranie citlivosti skóre/invariantov (Diamorphine musí chytiť invarianty —
  overiť!). PoC binárky NIKDY do gitu.
- Akceptácia: artefakty `data/results/` (skóre pred/po, lokalizácia E2, čas do
  detekcie); manifesty sedení s SHA-256 PoC binárok.

---

## G2 — MalwareBazaar: API sťahovanie, filter ELF x86-64 (`file`), manifest (SHA-256, rodina, first_seen); LEN hashe do repa, LEN v teste

**Stav:** neexistuje.

- Existujúci kód: `scripts/guest_exec.sh`, B3/B4 harness, HONESTY P1-P4.
- Čo treba: fetcher (API, rate-limit, limit N vzoriek), validácia `file` ELF
  x86-64, do repa iba `hashes.json`/manifest (bez binárok); behy len v izolovanej
  sieti (B3), vzorky na disku mimo repa.
- Akceptácia: manifest v repe (hashe+metadáta), nula malvérových binárok v gite
  (kontrola `.gitignore` + `git ls-files`), jeden vzorový beh s artefaktom.

---

## G3 — Označenie behu aktívny/neaktívny podľa nezávislého pozorovania (nové procesy, sieť, zmenené súbory); detekcia sa počíta nad aktívnymi behmi

**Stav:** neexistuje (predchádzajúce sedenia majú labely, ale scenáre sú zmazané).

- Existujúci kód: `scripts/guest_exec.sh` (ps/ss/súbory v hosťovi),
  `data/sessions/` (ground truth vzory), `features/snapshot.py` (proc_new/gone).
- Čo treba: počas behu nezávisle (mimo zberača) zaznamenávať procesy/sieť/zmeny
  súborov; po behu označiť aktívny/neaktívny; metrika detekcie len nad aktívnymi.
- Akceptácia: manifest sedenia má `aktivny: true/false` s dôkazom (logy);
  `eval.py` filtruje podľa neho.

---

## H — Rozšírenie `eval.py`: FAR/h na benígnom teste + ťažké negatíva; detekcia/ttd PER technika a PER rodina; konfunder test; klasifikácia s baselinami; výkon (latencia p50/p95, cena príznakov, SHA-NI); A/B/A vplyv na hosťa; sweep periódy a veľkosti binu; dôkaz soft real-time

**Stav:** `eval.py` má len klasifikačné metriky; merania latencie existujú
(`measure_latency.sh`, `latency_vector/score_*.json`), A/B/A vplyv nemeraný.

- Existujúci kód: `tcn/eval.py:49-88`, `scripts/measure_latency.sh`,
  `data/results/optim_hash_20260918.json`, A8 (zmeškané sloty),
  `tcn/score.py` (medián/p95).
- Čo treba: (1) FAR/h na benígnom teste + ťažkých negatívach (apt upgrade, reštart
  služby, nový nástroj); (2) detekcia + čas-do-detekcie per technika a per rodina;
  (3) konfunder — prediktor len zo záťažových príznakov nesmie dorovnať plný;
  (4) tabuľka aktivít s baselinami, split po sedeniach; (5) latencia
  snímka→vektor→skóre (medián, p95), cena príznakov, SHA-NI; (6) A/B/A s pevným
  objemom práce + CPU/RAM zberača; (7) sweep periódy a veľkosti binu;
  (8) soft real-time dôkaz: latencia < T, 0 zmeškaných slotov, ttd počas behu.
- Akceptácia: každé číslo s artefaktom v `data/results/` + HONESTY značkou,
  `check_claims.sh` = 0 nálezov, negatívne výsledky uvedené (P8).
