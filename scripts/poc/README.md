# PoC techniky (blok G1) - LEN na test a validáciu citlivosti

Tieto techniky slúžia **výlučne** na vývoj a validáciu citlivosti systému
(ground-truth sedenia). NIKDY sa nepoužijú na tréning modelu - tréning je
len na benígnych sedeniach (HONESTY P4, zadanie). Diamorphine sa pri sedení
stiahne a zbuildí v hosťovi (zdroj tu NEJE - pôjde len o SHA-256 do manifestu).

## Čo je kde

| súbor | technika | čo v hosťovi robí |
|---|---|---|
| `hider.c` | LD_PRELOAD hider | knižnica, ktorá v `readdir()` skryje adresár `/tmp/hidden` (klasický userspace hider; **nie** rootkit) |
| `memfd_exec.c` | fileless spustenie | `memfd_create` + zápis payloadu + `fexecve` - proces bez súboru na disku |
| `encrypt_files.sh` | šifrovanie súborov | zašifruje testovacie súbory (deterministický seed), originály zmazané |
| `diamorphine.sh` | Diamorphine LKM | stiahne pripnutý commit, zbuildí proti headers hosťa, `insmod`; **rootkit na úrovni jadra - len v overlayi sedenia** |
| `miner.sh` | kryptominer | stiahne pripnutý release, overí SHA-256, beží `DUR` s |
| `build.sh` | príprava | skompiluje lokálne zdroje v hosťovi (gcc) a vráti ich SHA-256 |

## Pravidlá

- Binárky NIKDY nejdú do gitu: do manifestu sedenia ide iba SHA-256.
- Diamorphine a miner sa sťahujú z pripnutých URL/SHA (sieť v hosťovi, NAT
  alebo predpripravené v overlayi pred izolovaným behom).
- Každé PoC sedenie má manifest `typ=malicious`, `label=<technika>` a beh
  cez `scripts/session.sh` - rovnaký priebeh ako benígne sedenie (B5).
- Úspech techniky sa overuje pozemnou pravdou (nový proces v `ps`, zmenené
  súbory, sieť) - označenie aktívny/neaktívny (G3).
