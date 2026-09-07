from flask import Flask, jsonify
from flask_cors import CORS

from app.ml.model_loader import load_all_models


def create_app():
    app = Flask(__name__)
    CORS(app)

    load_all_models()

    from app.routes.alerts import alerts_bp
    from app.routes.inference import inference_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.replay import replay_bp
    from app.routes.threats import threats_bp
    from app.routes.analytics import analytics_bp
    from app.routes.network import network_bp
    from app.routes.ingest import ingest_bp
    from app.routes.benchmark import benchmark_bp

    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
    app.register_blueprint(inference_bp, url_prefix="/api/inference")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(replay_bp, url_prefix="/api/replay")
    app.register_blueprint(threats_bp, url_prefix="/api/threats")
    app.register_blueprint(analytics_bp, url_prefix="/api/analytics")
    app.register_blueprint(network_bp, url_prefix="/api/network")
    app.register_blueprint(ingest_bp, url_prefix="/api/ingest")
    app.register_blueprint(benchmark_bp, url_prefix="/api/benchmark")

    @app.get("/")
    def health():
        from app.ml.model_loader import loaded_model_names
        return jsonify({
            "service": "RakshaNetra Backend",
            "status": "ok",
            "loaded_models": loaded_model_names(),
        })

    @app.get("/api/health")
    def api_health():
        from app.ml.model_loader import loaded_model_names
        return jsonify({"status":"ok", "loaded_models": loaded_model_names()})

    return app
