"""
app/ml/perf_stats.py
=====================
Tracks REAL model inference latency, timed around the actual
model.predict_proba() calls in app.ml.inference. Replaces the old
`round(1.12 + random.random() * 0.12, 2)` fake latency number in
app/generators.py's dashboard ticker.

A simple rolling window average — no external metrics library needed
for a project this size.
"""

import threading
from collections import deque

_lock = threading.Lock()
_WINDOW = 200
_samples = deque(maxlen=_WINDOW)


def record_latency_ms(ms: float):
    with _lock:
        _samples.append(ms)


def average_latency_ms() -> float | None:
    with _lock:
        if not _samples:
            return None
        return round(sum(_samples) / len(_samples), 3)


# Streaming benchmark counters (process-local).
_total_ingested = 0
_total_alerts = 0
_started_at = None

def record_flow(alert_count=0):
    global _total_ingested, _total_alerts, _started_at
    with _lock:
        if _started_at is None: _started_at = __import__("time").monotonic()
        _total_ingested += 1; _total_alerts += int(alert_count)

def throughput_stats():
    with _lock:
        if _started_at is None: return {"flows":0,"alerts":0,"flows_per_sec":0.0,"duration_sec":0.0}
        elapsed=max(__import__("time").monotonic()-_started_at,0.000001)
        return {"flows":_total_ingested,"alerts":_total_alerts,"flows_per_sec":round(_total_ingested/elapsed,2),"duration_sec":round(elapsed,3)}
