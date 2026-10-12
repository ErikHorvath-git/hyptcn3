"""The same window eligibility rules for replay, training and live scoring.

Written for this project. Missing rows are barriers, never interpolated.
"""
from collections import deque
import math

from .snapshot import MENA
from .windows import okna, snimky_z_matice


class WindowStream:
    def __init__(self, length, max_gap_s=7.5):
        if length < 1:
            raise ValueError("window length must be positive")
        if not math.isfinite(max_gap_s) or max_gap_s <= 0:
            raise ValueError("maximum gap must be finite and positive")
        self.length, self.max_gap_s = length, max_gap_s
        self.rows = deque(maxlen=length)
        self.last = None
        self.reason = "zahrievanie"
        self.reset = False

    def discontinuity(self, seq, timestamp):
        return self.last is not None and (
            seq != self.last[0] + 1 or timestamp <= self.last[1]
            or timestamp - self.last[1] > self.max_gap_s)

    def push(self, seq, timestamp, vector, valid=True):
        if self.last is not None and (seq <= self.last[0] or timestamp <= self.last[1]):
            raise ValueError("non-increasing snapshot sequence/time")
        self.reset = self.discontinuity(seq, timestamp)
        if self.reset:
            self.rows.clear()
        row = snimky_z_matice("stream", [vector], MENA, [timestamp],
                             [seq], [valid])[0]
        self.last = (seq, timestamp)
        if row.dovody():
            self.reason = "; ".join(row.dovody())
            self.rows.clear()
            self.reset = True
            return None
        self.rows.append(row)
        self.reason = "zahrievanie"
        if len(self.rows) < self.length:
            return None
        result = okna(self.rows, dlzka=self.length, max_medzera_s=self.max_gap_s)
        if not len(result):
            return None
        self.reason = "skore"
        return result.X[0]


def valid_state(state):
    """Missing structured quality is permitted only for legacy callers."""
    return state is None or state.get("quality", {}).get("model_valid", True)
