"""
app/routes/network.py
======================
Feeds NetworkVisualization.jsx. The original component hardcoded a
fixed set of 9 named machines ("SCADA Gateway Alpha", etc.) with
invented risk scores and a fixed edge list — pure fiction, never
touched by the models.

There's no real network inventory/CMDB in this project, so instead of
inventing one, /topology builds nodes/edges strictly from IPs that have
actually appeared in a real, model-fired alert (app.ml.alert_store):
each unique srcIp becomes a "Source" node (status/risk from the worst
alert seen for that IP), each unique dstIp becomes a "Destination"
node. If no model has fired yet, the list is empty — the frontend
should say "no detections yet" rather than show invented machines.
"""

from flask import Blueprint, jsonify

from app.ml import alert_store

network_bp = Blueprint("network", __name__)

_SEVERITY_RISK = {"Critical": 95, "High": 80, "Medium": 55, "Low": 20}
_SEVERITY_STATUS = {"Critical": "malicious", "High": "suspicious", "Medium": "suspicious", "Low": "safe"}


@network_bp.get("/topology")
def get_topology():
    alerts = alert_store.real_alerts()

    src_nodes = {}
    dst_nodes = {}
    edges = []
    seen_edges = set()

    for a in alerts:
        src_ip = a.get("srcIp", "unknown")
        dst_ip = a.get("dstIp", "unknown")
        severity = a.get("severity", "Low")
        risk = _SEVERITY_RISK.get(severity, 20)
        status = _SEVERITY_STATUS.get(severity, "safe")

        existing = src_nodes.get(src_ip)
        if existing is None or risk > existing["risk"]:
            src_nodes[src_ip] = {
                "id": f"src-{src_ip}",
                "name": src_ip,
                "ip": src_ip,
                "zone": "Source",
                "status": status,
                "risk": risk,
                "threatType": a.get("threatClass"),
            }

        if dst_ip not in dst_nodes:
            dst_nodes[dst_ip] = {
                "id": f"dst-{dst_ip}",
                "name": dst_ip,
                "ip": dst_ip,
                "zone": "Destination",
                "status": "safe",
                "risk": 0,
                "threatType": None,
            }

        edge_key = (src_ip, dst_ip)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({
                "from": f"src-{src_ip}",
                "to": f"dst-{dst_ip}",
                "malicious": status != "safe",
            })

    return jsonify({
        "hasData": len(alerts) > 0,
        "nodes": list(src_nodes.values()) + list(dst_nodes.values()),
        "edges": edges,
    })
