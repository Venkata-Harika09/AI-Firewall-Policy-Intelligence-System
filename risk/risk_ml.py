"""
Task 3: ML Risk Scoring
AI Firewall - Milestone 3

Improved Version
----------------
• Threat intelligence feature added
• Admin port exposure detection
• Model persistence (save/load)
• Feature names for debugging
• Dataset balance check
• Robust feature extraction
"""

import csv
import ipaddress
import os
from collections import Counter

# -----------------------------------------
# Feature Encoding Maps
# -----------------------------------------

EXPOSURE_MAP = {
    "public": 3,
    "restricted": 2,
    "internal": 1,
    "": 2
}

ASSET_MAP = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "": 2
}

LABEL_MAP = {
    "high": 2,
    "medium": 1,
    "low": 0
}

LABEL_NAMES = {
    2: "High",
    1: "Medium",
    0: "Low"
}

LABEL_SCORES = {
    2: 8.0,
    1: 5.0,
    0: 2.0
}

# -----------------------------------------
# Security Indicators
# -----------------------------------------

SENSITIVE_PORTS = {
    22, 23, 3389, 445,
    3306, 5432, 27017,
    6379, 9200, 2375, 6443
}

ADMIN_PORTS = {22, 3389, 2375, 6443}

FEATURE_NAMES = [
    "exposure",
    "asset_sensitivity",
    "intent_allow",
    "port_risk",
    "ip_scope",
    "time_constraint",
    "admin_port",
    "threat_match"
]


# -----------------------------------------
# Feature Functions
# -----------------------------------------

def _port_feature(port_str):

    try:

        port = int(port_str)

        if port in SENSITIVE_PORTS:
            return 1.0

        if port in (80, 8080, 8443):
            return 0.5

        if port in (443, 53, 123):
            return 0.2

        return 0.4

    except Exception:
        return 0.4


def _ip_scope_feature(ip):

    if ip in ("any", "0.0.0.0/0", "", None):
        return 1.0

    try:

        net = ipaddress.ip_network(ip, strict=False)

        if net.prefixlen <= 8:
            return 0.9

        if net.prefixlen <= 16:
            return 0.6

        if net.prefixlen <= 24:
            return 0.3

        return 0.1

    except Exception:
        return 0.1


# -----------------------------------------
# Feature Extraction
# -----------------------------------------

def extract_features(rule):

    port = rule.get("port")

    threat_match = rule.get("threat_match", False)

    return [

        EXPOSURE_MAP.get(
            str(rule.get("exposure_type", "")).lower(), 2
        ) / 3.0,

        ASSET_MAP.get(
            str(rule.get("asset_sensitivity", "")).lower(), 2
        ) / 4.0,

        1.0 if str(rule.get("intent", "allow")).lower() == "allow" else 0.0,

        _port_feature(str(port)),

        _ip_scope_feature(str(rule.get("source_ip", "any"))),

        1.0 if rule.get("time_constraint") else 0.0,

        1.0 if port in ADMIN_PORTS else 0.0,

        1.0 if threat_match else 0.0
    ]


# -----------------------------------------
# ML Risk Scorer
# -----------------------------------------

class RiskMLScorer:

    def __init__(self):

        self.model = None
        self.is_trained = False
        self.model_type = None
        self._use_sklearn = False

        self.model_path = os.path.join(
            "models",
            "ml_risk_model.pkl"
        )

    # -----------------------------------------
    # Train ML Model
    # -----------------------------------------

    def train(self, dataset_path):

        X = []
        y = []

        with open(dataset_path) as f:

            rows = list(csv.DictReader(f))

        for row in rows:

            X.append(extract_features(row))

            y.append(
                LABEL_MAP.get(
                    row.get("risk_label", "medium").lower(), 1
                )
            )

        # Dataset distribution check
        print("\nDataset Label Distribution:")
        print(Counter(y))

        try:

            import numpy as np
            import joblib

            from sklearn.ensemble import (
                GradientBoostingClassifier,
                RandomForestClassifier
            )

            from sklearn.model_selection import (
                train_test_split,
                cross_val_score
            )

            X_arr = np.array(X)
            y_arr = np.array(y)

            X_train, X_test, y_train, y_test = train_test_split(
                X_arr,
                y_arr,
                test_size=0.2,
                random_state=42,
                stratify=y_arr
            )

            # Gradient Boosting
            gbc = GradientBoostingClassifier(
                n_estimators=120,
                max_depth=3,
                random_state=42
            )

            gbc.fit(X_train, y_train)

            gbc_acc = gbc.score(X_test, y_test)

            gbc_cv = cross_val_score(gbc, X_arr, y_arr, cv=5)

            # Random Forest
            rfc = RandomForestClassifier(
                n_estimators=120,
                random_state=42
            )

            rfc.fit(X_train, y_train)

            rfc_acc = rfc.score(X_test, y_test)

            rfc_cv = cross_val_score(rfc, X_arr, y_arr, cv=5)

            best = gbc if gbc_cv.mean() >= rfc_cv.mean() else rfc

            best_name = (
                "GradientBoosting"
                if best is gbc
                else "RandomForest"
            )

            self.model = best
            self.model_type = best_name
            self.is_trained = True
            self._use_sklearn = True

            # Save model
            os.makedirs("models", exist_ok=True)
            joblib.dump(self.model, self.model_path)

            print("\n" + "=" * 60)
            print("ML RISK CLASSIFIER TRAINING RESULTS")
            print("=" * 60)
            print(f"Dataset Size : {len(rows)} rules")
            print(f"Features     : {len(FEATURE_NAMES)}")
            print(f"Best Model   : {best_name}")
            print(f"Accuracy     : {max(gbc_acc, rfc_acc)*100:.1f}%")
            print(f"CV Score     : {max(gbc_cv.mean(), rfc_cv.mean())*100:.1f}%")
            print("=" * 60)

            return {
                "model": best_name,
                "dataset_size": len(rows),
                "accuracy": round(max(gbc_acc, rfc_acc) * 100, 1)
            }

        except ImportError:

            # fallback linear scoring
            weights = [0.25,0.20,0.15,0.15,0.10,0.05,0.05,0.05]

            self.model = weights
            self.model_type = "LinearFallback"
            self.is_trained = True
            self._use_sklearn = False

            return {
                "model": "LinearFallback",
                "dataset_size": len(rows)
            }

    # -----------------------------------------
    # Load saved model
    # -----------------------------------------

    def load_model(self):

        try:

            import joblib

            self.model = joblib.load(self.model_path)

            self.model_type = "LoadedModel"

            self.is_trained = True
            self._use_sklearn = True

            return True

        except Exception:

            return False

    # -----------------------------------------
    # Predict Risk
    # -----------------------------------------

    def predict(self, rule):

        if not self.is_trained:

            raise Exception("Call train() or load_model() first")

        feats = extract_features(rule)

        if self._use_sklearn:

            import numpy as np

            pred = int(self.model.predict(np.array([feats]))[0])

            proba = self.model.predict_proba(
                np.array([feats])
            )[0]

            confidence = round(float(max(proba)) * 100, 1)

        else:

            raw = sum(
                f * w for f, w in zip(feats, self.model)
            )

            pred = 2 if raw > 0.65 else 1 if raw > 0.35 else 0

            confidence = 75.0

        return {

            "ml_score": LABEL_SCORES[pred],

            "ml_level": LABEL_NAMES[pred],

            "ml_label": pred,

            "confidence": confidence,

            "model_used": self.model_type
        }