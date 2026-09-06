Place these trained artifacts here for model inference:
cic_binary_xgb.joblib + cic_binary_features.json
ctu13_botnet_xgboost.joblib + ctu13_botnet_features.json
doh_tunneling_xgb.joblib + doh_tunneling_features.json
recon_xgb.joblib + recon_features.joblib

The backend now starts even if artifacts are absent, and /api/inference/models reports what is actually loaded.
hlw