
"""
app/routes/inference.py

Inference API endpoints.

GET  /api/inference/models
POST /api/inference/score
"""

from flask import Blueprint, jsonify, request

from app.ml import alert_store
from app.ml.inference import score_flow_all
from app.ml.model_loader import (
    get_load_errors,
    loaded_model_names,
    detector_status,
)

inference_bp = Blueprint("inference", __name__)


@inference_bp.get("/models")
def models_status():
    return jsonify({
        "loaded_models": loaded_model_names(),
        "load_errors": get_load_errors(),
        "detectors": detector_status(),
    })


@inference_bp.post("/score")
def score_flow():
    flow = request.get_json(silent=True)

    if not isinstance(flow, dict) or not flow:
        return jsonify({
            "error": "empty or invalid request body"
        }), 400

    alerts = score_flow_all(flow)

    for alert in alerts:
        alert_store.add_alert(alert)

    return jsonify({
        "alerts_fired": len(alerts),
        "alerts": alerts,
    })

