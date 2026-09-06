"""
app/routes/analytics.py
========================
Feeds AIAnalytics.jsx. The original component hardcoded a fake SHAP
feature list (invented names + invented importance scores) and a fake
per-timeslot trend chart. Neither was backed by anything real.

/features now reads each loaded model's own `feature_importances_`
(or, for sklearn Pipelines, its final estimator's) — genuinely computed
during training, not invented. This is feature importance, not SHAP
(no SHAP library is wired up), so the frontend should label it as such.

/performance and /trends are built from app.ml.alert_store — real
alerts fired by real models since process startup. There's no
historical time-series store, so /trends reports all-time per-category
totals rather than fabricating hourly/daily buckets.
"""

from flask import Blueprint, jsonify

from app.ml import alert_store
from app.ml.model_loader import get_model, get_feature_list, loaded_model_names

analytics_bp = Blueprint("analytics", __name__)

# modelKey -> (display category, threatClass string used in alert_store)
_MODEL_META = {
    "ddos": ("Volumetric", "DDoS & Volumetric"),
    "botnet_c2": ("Timing", "Botnet C2 Beaconing"),
    "dga_dns": ("DNS Protocol", "DGA & DNS Tunnelling"),
    "port_scan": ("Protocol Stack", "Reconnaissance & Scan"),
}


def _final_estimator(model):
    """Unwraps a sklearn Pipeline to its last step; passes plain estimators through."""
    if hasattr(model, "steps"):  # sklearn Pipeline
        return model.steps[-1][1]
    return model


@analytics_bp.get("/features")
def get_features():
    rows = []
    for model_key in loaded_model_names():
        if model_key not in _MODEL_META:
            continue
        category, _threat_class = _MODEL_META[model_key]
        try:
            model = get_model(model_key)
            feature_list = get_feature_list(model_key)
            estimator = _final_estimator(model)
            importances = getattr(estimator, "feature_importances_", None)
            if importances is None:
                continue
            for feat_name, score in zip(feature_list, importances):
                rows.append({
                    "name": feat_name,
                    "importance": round(float(score), 4),
                    "category": category,
                    "model": model_key,
                    "desc": f"Feature importance computed directly from the trained {model_key} classifier.",
                })
        except Exception:
            continue

    rows.sort(key=lambda r: r["importance"], reverse=True)
    top = rows[:8]
    max_importance = top[0]["importance"] if top else 1.0
    for r in top:
        r["relativePct"] = round((r["importance"] / max_importance) * 100, 1) if max_importance else 0
    return jsonify(top)


@analytics_bp.get("/performance")
def get_performance():
    alerts = alert_store.real_alerts()
    confidences = [a["confidence"] for a in alerts if "confidence" in a]
    return jsonify({
        "modelsActive": len(loaded_model_names()),
        "modelsTotal": 6,
        "totalRealAlerts": alert_store.real_alert_count(),
        "meanConfidence": round(sum(confidences) / len(confidences), 2) if confidences else None,
        "latestAlertAt": alerts[0]["timestamp"] if alerts else None,
    })


@analytics_bp.get("/trends")
def get_trends():
    alerts = alert_store.real_alerts()
    counts = {"ddos": 0, "botnet": 0, "dga_dns": 0, "recon": 0}
    class_to_id = {
        "DDoS & Volumetric": "ddos",
        "Botnet C2 Beaconing": "botnet",
        "DGA & DNS Tunnelling": "dga_dns",
        "Reconnaissance & Scan": "recon",
    }
    for a in alerts:
        cid = class_to_id.get(a.get("threatClass"))
        if cid:
            counts[cid] += 1
    return jsonify({
        "sinceStartup": True,
        "counts": counts,
        "totalRealAlerts": alert_store.real_alert_count(),
    })
