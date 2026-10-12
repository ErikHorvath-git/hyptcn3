"""Structural checks for collector data. These do not decide attack labels.

Original implementation for this project; rounded C floats use print precision.
"""
import math

from .perbin import FeatureError


def validate_sidecar(doc):
    try:
        if doc["schema"] != "vmicollect/1":
            raise ValueError("unsupported collector schema")
        f, out, stats = doc["features"], doc["output"], doc["stats"]
        if f["schema"] != "hyptcn3/perbin/1" or f["entropy"] is not True:
            raise ValueError("per-bin features with entropy required")
        size, page = f["bin_bytes"], f["page_size"]
        if size < page or size & (size - 1) or page != out["page_size"]:
            raise ValueError("invalid bin/page size")
        if not math.isfinite(doc["timestamp_unix"]) or doc["seq"] < 0:
            raise ValueError("invalid time/sequence")
        rows = sorted(f["bins"], key=lambda b: b["bin"])
        if not rows or len(rows) != f["bins_total"] or len({b["bin"] for b in rows}) != len(rows):
            raise ValueError("missing or duplicate bins")
        for b in rows:
            total, changed = b["pages_total"], b["pages_changed"]
            if (type(total) is not int or type(changed) is not int
                    or not 0 <= changed <= total or not 0 < total <= size // page):
                raise ValueError("invalid page counts")
            if b["gpa"] != b["bin"] * size:
                raise ValueError("bin identity does not match GPA")
            if b["has_changed"] not in (0, 1) or bool(changed) != bool(b["has_changed"]):
                raise ValueError("invalid change mask")
            for name, upper in (("changed_ratio", 1), ("zero_ratio", 1), ("entropy_mean", 8)):
                if not math.isfinite(b[name]) or not 0 <= b[name] <= upper:
                    raise ValueError("invalid " + name)
            if abs(b["changed_ratio"] - changed / total) > 0.00000051:
                raise ValueError("changed ratio/count mismatch")
            if not changed and b["entropy_mean"] != 0:
                raise ValueError("entropy without changed pages")
        if (sum(b["pages_total"] for b in rows) != out["pages_total"]
                or sum(b["pages_changed"] for b in rows) != out["pages_changed"]):
            raise ValueError("per-bin totals do not match collector")
        for key in ("read_errors", "filled_zero"):
            if type(stats[key]) is not int or stats[key] < 0:
                raise ValueError("invalid read counters")
        return {"bin_bytes": size, "page_size": page,
                "bins": [[b["bin"], b["pages_total"]] for b in rows],
                "regions": f["regions"], "memsize": doc["vm"]["memsize"],
                "vcpus": doc["vm"]["num_vcpus"]}
    except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
        raise FeatureError("invalid collector sidecar: %s" % exc) from exc
