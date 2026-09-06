from flask import Blueprint, jsonify, request
from app.ml import alert_store
from app.ml.inference import score_flow_all
from app.ml import perf_stats

ingest_bp = Blueprint("ingest", __name__)

@ingest_bp.post("/flow")
def ingest_flow():
    """Passive one-flow ingest. The service only consumes metadata supplied by a mirror/data diode."""
    flow = request.get_json(silent=True)
    if not isinstance(flow, dict) or not flow:
        return jsonify({"error":"expected one flow metadata object"}), 400
    alerts = score_flow_all(flow)
    for alert in alerts: alert_store.add_alert(alert)
    perf_stats.record_flow(len(alerts))
    return jsonify({"accepted":True,"flow_id":flow.get("flow_id"),"alerts":alerts,"alert_count":len(alerts)})
