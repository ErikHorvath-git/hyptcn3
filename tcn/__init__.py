"""
tcn - model a baseliny nad oknami snimkovych vektorov.

  model.py      TCN: kauzalne dilatovane konvolucie, rezidualne bloky
  baselines.py  logisticka regresia, bag-of-frames, GRU
  train.py      data, chronologicky session-disjunktny split, normalizacia,
                trening; zaroven CLI celeho behu
  eval.py       binarne aj viactriedne metriky, tabulka, JSON do data/results/

Vstup je kontrakt z features/snapshot.py (20 priznakov + ma_predchodcu).
Z korena balika sa nic neexportuje zamerne - moduly sa importuju priamo
(`from tcn.model import TCN`), aby import jedneho nezavisel od ostatnych.
"""
