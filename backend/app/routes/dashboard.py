"""
app/routes/dashboard.py
========================
Feeds HeroSection.jsx's KPI ticker. threatsDetected is real (baseline
seed + every alert actually fired by a loaded model, via app.ml.alert_store).
flowsPerSec/aiConfidence/latency are lightweight synthetic telemetry
(no trained model produces these), generated server-side so every
connected client sees the same numbers instead of each browser rolling
its own Math.random().
"""

import json
import time

from flask import Blueprint, Response, jsonify

from app.generators import next_dashboard_stats

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/stats")
def get_stats():
    return jsonify(next_dashboard_stats())


@dashboard_bp.get("/stream")
def stream_stats():
    def event_stream():
        while True:
            payload = next_dashboard_stats()
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(1.5)

    return Response(event_stream(), mimetype="text/event-stream")
