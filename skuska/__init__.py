"""Stage G2 of protocol v5, the test on the VMs (proposal 10.3): its tools outside the measurement code.

scripts/collection.py is_measurement() takes no file of this package, so nothing here changes measurement_sha256 or
reopens G0 (map dokazy/G2/mapa.md point E). The data of G2 never become a dataset (proposal 10.3).

  g2.py   the deck of events of G2 and the driver of a block of G2 sessions on one VM (package H1a)
  kontroly.py  the draw of the controls of G2, the controls wrapper of Q46 and the block with controls (package H1b2)
  pozemna_pravda.py  the ground truth under load: the dedicated sessions, the sampler beside them, the comparison
          on a restored copy and the table of matches (package H1b1)
  poruchy.py  the six faults of G2, their injector beside a session and the block of the fault plan (package H1b3)
"""
