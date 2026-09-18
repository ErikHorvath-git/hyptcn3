"""
features - priznakovy priestor nad pamatovymi snimkami.

Obsah balika:

  perbin.py     nezavisla Pythonova referencia per-bin vektora, ktory pocita
                C modul (vmicollect/src/perbin.c). Sluzi na krizovu kontrolu -
                dve nezavisle implementacie toho isteho vzorca sa musia
                zhodovat na cislo, inak je jedna z nich zla (krok K14)
  crosscheck.py porovnanie oboch vektorov po poliach
  cli.py        'python3 -m features perbin|crosscheck'
  windows.py    sekvencne okna nad vektormi (krok K15)
  normalize.py  normalizacia a manifest (krok K15)
  manifest.py   nazvy priznakov a manifest priznakoveho priestoru (krok K15)

Z korena balika sa exportuje iba perbin; ostatne moduly sa importuju priamo
(napr. 'from features.windows import okna'), aby sa pri praci na jednom module
nedal rozbit import ostatnych.

Zavisi od stdlib a od balika guestparse (citanie .vmicd). numpy je pre perbin
volitelna a pouzije sa iba na histogram bajtov.
"""

from .perbin import (DEFAULT_BIN_BYTES, PAGE, SCHEMA, FeatureError, Memslots,
                     check_against_sidecar, entropy_from_counts,
                     load_memslots, page_entropy, per_bin)

__all__ = [
    "PAGE", "SCHEMA", "DEFAULT_BIN_BYTES", "FeatureError", "Memslots",
    "load_memslots", "per_bin", "page_entropy", "entropy_from_counts",
    "check_against_sidecar",
]

__version__ = "0.1.0"
