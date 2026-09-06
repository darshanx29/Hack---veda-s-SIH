"""
app/ml/model_loader.py
=======================
Loads the trained model artifacts ONCE at Flask startup and exposes
them through get_model(). Every detector module pulls from here instead
of calling joblib.load() itself, so a model is never re-read from disk
per-request.

Currently wired models (4 of 6 threat categories):
  - "ddos"        -> cic_binary_xgb.joblib       (CIC-IDS flow features, general attack/normal binary classifier)
  - "botnet_c2"   -> ctu13_botnet_xgboost.joblib (CTU-13 flow features, botnet/normal binary classifier)
  - "dga_dns"     -> doh_tunneling_xgb.joblib    (CIRA-CIC-DoHBrw-2020 flow features, DoH/DNS-tunneling binary classifier)
  - "port_scan"   -> recon_xgb.joblib            (UNSW-NB15-style flow features, recon/port-scan binary classifier)

Still missing (no trained model, no dataset yet):
  - "encrypted_tls" (TLS/QUIC encrypted malware)
  - "exfiltration"  (data exfiltration)
Add them the same way once their .joblib file + a matching feature-list
file exist: drop both into app/models/, add one _load_one() line below.

Feature-list files come in three shapes depending on how the model was
trained/exported:
  - a plain JSON list                    (cic_binary_features.json)
  - a JSON object with a "features" key  (ctu13_botnet_features.json, doh_tunneling_features.json)
  - a joblib-pickled plain list          (recon_features.joblib)
_load_feature_list() below handles all three transparently.
"""

import json
import joblib
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent / "models"

_models = {}
_feature_lists = {}
_load_errors = {}  # name -> human-readable error string, for real diagnostics
                    # instead of a console warning easy to miss in scrollback


def _load_feature_list(features_file: str):
    path = MODELS_DIR / features_file
    if path.suffix == ".joblib":
        meta = joblib.load(path)
    else:
        with open(path) as f:
            meta = json.load(f)
    # plain list -> use as-is; dict -> pull out the "features" key
    return meta["features"] if isinstance(meta, dict) else meta


def _load_one(name: str, model_file: str, features_file: str):
    _models[name] = joblib.load(MODELS_DIR / model_file)
    _feature_lists[name] = _load_feature_list(features_file)


def load_all_models():
    """Load available model artifacts without preventing Flask from starting.
    Missing artifacts are reported clearly and simply remain unavailable."""
    specs = [
        ("ddos", "cic_binary_xgb.joblib", "cic_binary_features.json"),
        ("botnet_c2", "ctu13_botnet_xgboost.joblib", "ctu13_botnet_features.json"),
        ("dga_dns", "doh_tunneling_xgb.joblib", "doh_tunneling_features.json"),
        ("port_scan", "recon_xgb.joblib", "recon_features.joblib"),
    ]
    for name, model_file, features_file in specs:
        try:
            _load_one(name, model_file, features_file)
        except FileNotFoundError as exc:
            msg = f"missing artifact file: {exc.filename or (model_file + ' / ' + features_file)}"
            _load_errors[name] = msg
            print(f"[model_loader] WARNING: {name}: {msg}")
        except Exception as exc:
            # Most common real-world cause here: a version mismatch between
            # the pickled model (trained with one scikit-learn/xgboost
            # version) and whatever requirements.txt's loose ">=" pins
            # actually resolved to at install time — e.g. a Pipeline/
            # OneHotEncoder attribute renamed between sklearn minor versions,
            # or an XGBoost booster serialization format change.
            msg = f"{type(exc).__name__}: {exc}"
            _load_errors[name] = msg
            print(f"[model_loader] WARNING: could not load {name}: {msg}")

    print(f"[model_loader] Loaded models: {list(_models.keys())}")
    if _load_errors:
        print(f"[model_loader] Load errors (see /api/inference/models for this in-app): {_load_errors}")
    return _models


def get_model(name: str):
    if name not in _models:
        raise RuntimeError(f"Model '{name}' not loaded. Call load_all_models() at startup first.")
    return _models[name]


def get_feature_list(name: str):
    if name not in _feature_lists:
        raise RuntimeError(f"Feature list for '{name}' not loaded.")
    return _feature_lists[name]


def loaded_model_names():
    return list(_models.keys())


def get_load_errors():
    """The REAL reason any model failed to load, keyed by name — visible via
    GET /api/inference/models instead of only a backend console line."""
    return dict(_load_errors)

def detector_status():
    return {
        "ddos": {"type":"ml", "artifact":"cic_binary_xgb.joblib"},
        "botnet_c2": {"type":"ml", "artifact":"ctu13_botnet_xgboost.joblib"},
        "dga_dns": {"type":"ml", "artifact":"doh_tunneling_xgb.joblib"},
        "port_scan": {"type":"ml", "artifact":"recon_xgb.joblib"},
        "encrypted_tls": {"type":"rule_based", "artifact":None},
        "exfiltration": {"type":"rule_based", "artifact":None},
    }
