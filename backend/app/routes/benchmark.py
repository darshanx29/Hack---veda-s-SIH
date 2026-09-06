import time
from flask import Blueprint, jsonify, request
from app.ml import perf_stats
from app.ml.inference import score_flow_all

benchmark_bp=Blueprint("benchmark",__name__)

@benchmark_bp.post("/run")
def run_benchmark():
    body=request.get_json(silent=True) or {}
    flows=body.get("flows")
    if not isinstance(flows,list) or not flows:
        return jsonify({"error":"send {\"flows\":[...]} for a local replay benchmark"}),400
    t=time.perf_counter(); alerts=0
    for flow in flows:
        alerts += len(score_flow_all(flow))
    elapsed=time.perf_counter()-t
    return jsonify({"flows":len(flows),"alerts":alerts,"duration_sec":round(elapsed,6),"flows_per_sec":round(len(flows)/max(elapsed,1e-9),2),"mean_detection_latency_ms":round(elapsed*1000/len(flows),4),"inference_latency_ms":perf_stats.average_latency_ms(),"passive_only":True})

@benchmark_bp.get("/stats")
def benchmark_stats(): return jsonify(perf_stats.throughput_stats())
