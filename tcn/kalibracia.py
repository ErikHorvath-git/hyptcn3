"""
kalibracia.py - blok E3: prah anomálie z kvantilu chyb na odloženej
benígnej validácii s ROZPOČTOM falošných poplachov.

PRECO KVANTIL A NIE "prah = max chyba": pri T=5 s vznikne 17 280 okien za
deň. "1 falošný poplach za deň" teda znamená FPR ~ 5,8e-5 na OKNO - prah
nastavený na maximum benígnych chýb by dal nulu falošných poplachov, ale
len preto, že validačných okien je príliš málo na to, aby maximum odhadli
(kvantil 1 - 1/n je vždy pod maximom). Kvantil s explicitným FPR je jediný
postup, ktorý svoje číslo vie pomenovať a overiť.

ALARM = k z n okien nad prahom: jednotlivé okná nie sú nezávislé (okná sa
prekrývajú, krok=1), takže sa nepočíta jednoduchá binomická veta - počet
alarmov sa odmeria NA VALIDÁCII a teoretický odhad sa uvádza vedľa, nie
namiesto merania.
"""

import numpy as np

OKIEN_ZA_DEN = {"1s": 86400, "2s": 43200, "5s": 17280, "10s": 8640}


def okien_za_den(perioda_s):
    """Pocet okien za den pri danej periode zberu (okna maju krok 1)."""
    return int(round(86400.0 / float(perioda_s)))


def kalibracia(chyby_val, perioda_s=5.0, fp_za_den=1.0, k=3, n=5, seed=0):
    """
    Prah z benígnych validačných chýb pri rozpočte falošných poplachov.

    `chyby_val` = skóre anomálie (chyby predikcie) benígnych okien, ktoré
    NEVIDELI tréning (odložená validačná časť). Vracia dict:
      prah          - kvantil (1 - fpr_okno) z chýb
      fpr_okno       - rozpočet / okná za deň
      fpr_okno_odmerane - podiel validačných okien nad prahom
      alarm_k_z_n    - (k, n) pravidlo
      alarmov_odmerane - pocet k-z-n alarmov vo validácii
      far_h_odhad   - alarmov_odmerane prepočítané na hodiny (najlepší
                      dostupný odhad; pri malom n je to dolna hranica)
      n_okien        - velkost validácie
    """
    chyby = np.asarray(chyby_val, dtype=np.float64)
    if chyby.ndim != 1 or len(chyby) < 100:
        raise ValueError(
            "kalibracia potrebuje aspon 100 benígnych validačných okien, "
            "má ich %d - kvantil z menšieho vzorku je hadanie"
            % len(chyby))
    if not (1 <= k <= n):
        raise ValueError("pravidlo alarmu k z n: treba 1 <= k <= n, je %d z %d"
                         % (k, n))
    if fp_za_den <= 0:
        raise ValueError("rozpočet falošných poplachov musí byť kladný")

    okien_den = okien_za_den(perioda_s)
    fpr_okno = float(fp_za_den) / okien_den
    if fpr_okno >= 1.0:
        raise ValueError("rozpočet %s FP/deň pri %s s = FPR okna %.3g >= 1"
                         % (fp_za_den, perioda_s, fpr_okno))
    if fpr_okno * len(chyby) < 1.0:
        raise ValueError(
            "validácia má %d okien, pri FPR %.3g okna treba aspoň 1 okno nad "
            "prahom - kvantil by bol maximum a rozpočet by sa nedal overiť"
            % (len(chyby), fpr_okno))

    rng = np.random.default_rng(seed)
    prah = float(np.quantile(chyby, 1.0 - fpr_okno))

    nad = chyby >= prah
    fpr_merane = float(np.mean(nad))

    # k z n: posuvne okno po validačných oknách (krok 1, ako pri zbere)
    alarmy = 0
    for i in range(len(chyby) - n + 1):
        if int(np.sum(nad[i:i + n])) >= k:
            alarmy += 1

    hodiny_val = (len(chyby) / okien_den) * 24.0
    return {
        "schema": "hyptcn3/kalibracia/1",
        "perioda_s": float(perioda_s),
        "okien_za_den": okien_den,
        "fp_za_den": float(fp_za_den),
        "fpr_okno_rozpocet": fpr_okno,
        "prah": prah,
        "n_okien": int(len(chyby)),
        "fpr_okno_odmerane": fpr_merane,
        "alarm_k_z_n": [int(k), int(n)],
        "alarmov_odmerane": alarmy,
        "far_h_odhad": (alarmy / hodiny_val) if hodiny_val > 0 else None,
        "hodiny_validacie": hodiny_val,
        "poznamka": ("fpr_okno_odmerane je okolo rozpočtu Z KONSTRUKCIE "
                     "(prah je kvantil); far_h_odhad je odhad z validácie "
                     "a pri malom n je dolnou hranicou, nie zárukou"),
    }


def skore_okna_z_chyb(chyba_okna):
    """Skóre okna = priemerná štvorcová chyba cez priznaky (E2).

    Vstup (N, F) stvorcov chyb; vystup (N,). Priznaky ma_predchodcu/je_plna
    sa vynechávajú volajúcim (sú to 0/1 indikátory, nie meranie).
    """
    return np.mean(chyba_okna, axis=1)


def run(args):
    """CLI: kalibruj z JSONu s benígnymi chybami (vstup score.py)."""
    import json
    import sys
    doc = json.load(open(args.subor, encoding="utf-8"))
    chyby = doc.get("chyby_val") or doc.get("chyby")
    if chyby is None:
        raise ValueError("JSON nema pole 'chyby'")
    res = kalibracia(chyby, perioda_s=args.perioda, fp_za_den=args.fp_den,
                     k=args.k, n=args.n, seed=args.seed)
    json.dump(res, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")
