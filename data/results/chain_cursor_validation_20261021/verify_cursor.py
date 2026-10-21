"""Real-data equivalence and timing check for ChainCursor (scratch verification)."""
import json, sys, time
from pathlib import Path
import numpy as np
ROOT = Path("/home/eh/projects/hyptcn3"); sys.path.insert(0, str(ROOT))
from guestparse.image import ChainCursor, open_image
from features.snapshot import retazec, vektor_snimky
from features.quality import BEHAVIOR_POLICY

T = Path(sys.argv[1]); raw = str(T / "raw"); prof = str(T / "profile")
old_npz = Path(sys.argv[2]); out = Path(sys.argv[3])
report = {"session": str(T), "index_checks": [], "feature_checks": {}}
samples = {0, 1, 2, 100, 358, 359, 360, 361, 362, 399}
t0 = time.monotonic()
with ChainCursor(raw) as cursor:
    for seq in range(400):
        img = cursor.image_at(seq)
        if seq in samples:
            with open_image(raw, until_seq=seq) as fresh:
                same = img.index == fresh.index and img.memsize == fresh.memsize and img.page_size == fresh.page_size
            report["index_checks"].append({"seq": seq, "pages": len(img.index), "identical": same})
            print(json.dumps(report["index_checks"][-1]), flush=True)
report["cursor_walk_s"] = time.monotonic() - t0
t0 = time.monotonic()
new = retazec(raw, prof, 7.5, quality_policy=BEHAVIOR_POLICY)
report["retazec_s"] = time.monotonic() - t0
t = new["trvanie_s"]; report["extraction_s"] = {"p50": float(np.median(t)), "p95": float(np.percentile(t, 95)), "max": float(max(t)), "sum": float(sum(t)),
    "mean_0_50": float(np.mean(t[:50])), "mean_300_360": float(np.mean(t[300:360])), "mean_360_400": float(np.mean(t[360:400]))}
old = np.load(old_npz, allow_pickle=False)
m_new, m_old = np.asarray(new["matica"]), old["matica"]
p_new, p_old = np.asarray(new["perbin"]), old["perbin"]
q_old = json.loads(str(old["quality_json"]))
pre = slice(0, 360)
report["feature_checks"]["rows_0_359_vs_original_audit"] = {
    "matica_equal": bool(np.array_equal(m_new[pre], m_old[pre])), "perbin_equal": bool(np.array_equal(p_new[pre], p_old[pre])),
    "valid_equal": bool(list(new["valid"][:360]) == old["valid"][:360].tolist()),
    "quality_equal": new["quality"][:360] == q_old[:360],
    "seq_equal": list(new["seq"]) == old["seq"].tolist(), "casy_equal": bool(np.array_equal(np.asarray(new["casy"]), old["casy"]))}
rows = {}
for s in (360, 361, 380, 399):
    has_pred = new["matica"][s][-2] == 1.0
    predch = vektor_snimky(raw, prof, s - 1)[1] if has_pred else None
    vec, _, _ = vektor_snimky(raw, prof, s, predch)
    rows[str(s)] = {"equal": vec == new["matica"][s], "had_predecessor": bool(has_pred)}
report["feature_checks"]["rows_after_second_full_vs_no_cursor"] = rows
report["after_reset_differs_from_old_parser_rows"] = int(sum(not np.array_equal(m_new[i], m_old[i]) for i in range(360, 400)))
out.write_text(json.dumps(report, indent=2))
print(json.dumps({k: report[k] for k in ("cursor_walk_s", "retazec_s", "extraction_s", "feature_checks", "after_reset_differs_from_old_parser_rows")}, indent=1))
