# Denník odchýlok protokolu v5

Zapisuje sa sem každé miesto, kde sa práca odchyľuje od [NAVRH_PROTOKOL_V5.sk.md](NAVRH_PROTOKOL_V5.sk.md)
alebo od [HARNESS_V5.sk.md](HARNESS_V5.sk.md), s dátumom, rozhodnutím a dôvodom. Denník sa otvoril
2026-11-22 pred stupňom G4 (odpoveď na otázku 9 hlásenia balíka B1); v G4 je jeho otvorenie kritériom
`deviation_log_open`. Zápisy sa nemažú ani neprepisujú; zmena sa zapíše novým zápisom.

| # | dátum | odchýlka | od čoho | rozhodol | dôvod |
|---|---|---|---|---|---|
| 1 | 2026-11-21 | Vykonávateľ smie sám spúšťať príkazy so sudo cez skill `/sudo`, iba na zberovom PC a iba pre tento projekt, nie v stupni G0. | harness, kap. 1 a kap. 5 bod 6 („Sudo nemá.“) | vlastník | vlastník nechce byť pri každom kroku so sudo |
| 2 | 2026-11-22 | Úsporný režim: hlavná relácia na Opuse, Fable iba na kostru balíka; jedno nezávislé overenie na balík; mutanty najviac jedno kolo; žiadne panely ani ďalšie kolá bez pokynu; krátky stav práce. | harness, kap. 6 a 8 (doplnené kap. 9) | vlastník | relácia sa 2026-11-22 zastavila na preplnenom kontexte; za 31 hodín vznikol jeden uzavretý balík z desiatich |
