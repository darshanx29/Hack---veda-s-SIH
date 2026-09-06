from flask import Blueprint, abort, jsonify, request

from app.data import ALERTS
from app.ml import alert_store

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.get("")
def list_alerts():
    """
    Feeds AlertInvestigation.jsx's filterable table.
    Real alerts (from replay/inference) are shown newest-first, followed by
    the static demo seed alerts, so the table always has content even
    before any real detections have fired.
    Query params (all optional, mirroring the frontend's filter bar):
      severity        -> All | Critical | High | Medium
      vector          -> All | DDoS | Botnet | DNS | TLS | Reconnaissance | Exfiltration
      min_confidence  -> integer 0-100 (default 0)
    """
    severity = request.args.get("severity", "All")
    vector = request.args.get("vector", "All")
    min_confidence = float(request.args.get("min_confidence", 0))

    results = alert_store.real_alerts() + ALERTS
    # Newest alerts first so the console immediately answers what is happening now.
    results = sorted(
        results,
        key=lambda a: a.get("timestamp_iso", a.get("timestamp", "")),
        reverse=True,
    )
    if severity != "All":
        results = [a for a in results if a["severity"] == severity]
    if vector != "All":
        results = [a for a in results if vector.lower() in a["threatClass"].lower()]
    if min_confidence:
        results = [a for a in results if a["confidence"] >= min_confidence]

    return jsonify(results)


@alerts_bp.get("/<alert_id>")
def get_alert(alert_id):
    """Feeds the slide-over Forensics Inspector drawer (full rawJson payload)."""
    real = alert_store.find_real_alert(alert_id)
    if real:
        return jsonify(real)
    for alert in ALERTS:
        if alert["id"] == alert_id:
            return jsonify(alert)
    abort(404, description=f"Unknown alert '{alert_id}'")
