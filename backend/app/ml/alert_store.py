"""
app/ml/alert_store.py
======================
A single, process-wide, thread-safe home for alerts fired by the REAL
models — as opposed to app/data.py's ALERTS, which is static seed/demo
data baked in at import time.

Both the PCAP replay engine (app/routes/replay.py, via generators.py)
and the manual scoring endpoint (POST /api/inference/score) push into
this store. /api/alerts then reads seed alerts + real alerts together,
so the Forensics Inspector and the dashboard's threatsDetected counter
both reflect actual model output instead of the demo-only mock list.

Newest-first ordering; capped so a long-running replay session doesn't
grow this unboundedly.
"""

import threading

_MAX_STORED = 500

_lock = threading.Lock()
_real_alerts = []          # newest first
_real_alert_count = 0      # monotonic counter, never shrinks (feeds threatsDetected)


def add_alert(alert: dict):
    """Record a real model-fired alert. Thread-safe."""
    global _real_alert_count
    with _lock:
        _real_alerts.insert(0, alert)
        del _real_alerts[_MAX_STORED:]
        _real_alert_count += 1


def real_alerts():
    """Snapshot list of real alerts, newest first."""
    with _lock:
        return list(_real_alerts)


def real_alert_count():
    """Monotonic count of real alerts fired since startup (for dashboard stats)."""
    with _lock:
        return _real_alert_count


def find_real_alert(alert_id: str):
    with _lock:
        for alert in _real_alerts:
            if alert["id"] == alert_id:
                return alert
    return None
