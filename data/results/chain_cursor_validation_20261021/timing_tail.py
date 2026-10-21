import sys, time, json
from pathlib import Path
sys.path.insert(0, "/home/eh/projects/hyptcn3")
from guestparse.image import ChainCursor
from features.snapshot import vektor_snimky
T = Path(sys.argv[1]); raw, prof = str(T / "raw"), str(T / "profile")
times = {}
with ChainCursor(raw) as cursor:
    for seq in range(340):
        cursor.image_at(seq)
    for seq in range(340, 400):
        t0 = time.monotonic(); vektor_snimky(raw, prof, seq, None, cursor); times[seq] = round(time.monotonic() - t0, 2)
print(json.dumps(times))
