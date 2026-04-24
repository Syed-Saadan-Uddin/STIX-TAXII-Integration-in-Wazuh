"""
Threat prediction model wrapper.

Uses a synthetic-data-trained RandomForest when scikit-learn is available and
falls back to a deterministic heuristic scorer otherwise.
"""

from __future__ import annotations

import math
import os
import pickle
import random
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_config
from app.utils.logger import get_logger

logger = get_logger(__name__)

FEATURE_ORDER = [
    "rule_level",
    "rule_severity",
    "frequency_1h",
    "frequency_24h",
    "same_rule_24h",
    "same_host_24h",
    "same_process_24h",
    "repeat_behavior_7d",
    "host_criticality",
    "login_failures",
    "suspicious_process_activity",
    "mitre_tactic_risk",
    "off_hours",
    "weekend",
    "public_source_ip",
    "candidate_indicator_count",
    "source_ip_reputation",
    "threat_intel_matches",
    "local_match_count",
    "host_internet_exposed",
    "host_crown_jewel",
]


class ThreatPredictionModel:
    def __init__(self):
        config = get_config()
        self.model_path = Path(config.ml.model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.model = None
        self.metadata = {
            "model_name": "heuristic-threat-predictor",
            "model_version": "2026.04.24",
            "trained_at": None,
        }
        self._load_or_train()

    def _load_or_train(self):
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as fh:
                    artifact = pickle.load(fh)
                self.model = artifact.get("model")
                self.metadata = artifact.get("metadata", self.metadata)
                return
            except Exception as exc:
                logger.warning(f"Failed to load ML model artifact, retraining: {exc}")

        self.retrain()

    def _build_synthetic_dataset(self, size: int = 3500):
        samples = []
        labels = []
        rng = random.Random(42)

        for _ in range(size):
            row = {
                "rule_level": rng.randint(0, 15),
                "rule_severity": rng.random(),
                "frequency_1h": rng.randint(0, 30),
                "frequency_24h": rng.randint(0, 120),
                "same_rule_24h": rng.randint(0, 80),
                "same_host_24h": rng.randint(0, 50),
                "same_process_24h": rng.randint(0, 20),
                "repeat_behavior_7d": rng.randint(0, 150),
                "host_criticality": rng.randint(1, 5),
                "login_failures": rng.randint(0, 1),
                "suspicious_process_activity": rng.randint(0, 1),
                "mitre_tactic_risk": round(rng.uniform(0.25, 0.99), 3),
                "off_hours": rng.randint(0, 1),
                "weekend": rng.randint(0, 1),
                "public_source_ip": rng.randint(0, 1),
                "candidate_indicator_count": rng.randint(0, 4),
                "source_ip_reputation": rng.randint(0, 100),
                "threat_intel_matches": rng.randint(0, 12),
                "local_match_count": rng.randint(0, 4),
                "host_internet_exposed": rng.randint(0, 1),
                "host_crown_jewel": rng.randint(0, 1),
            }

            latent = self._heuristic_probability(row)
            latent += rng.uniform(-0.08, 0.08)
            label = 1 if latent >= 0.55 else 0

            samples.append([row[name] for name in FEATURE_ORDER])
            labels.append(label)

        return samples, labels

    def retrain(self) -> dict:
        try:
            from sklearn.ensemble import RandomForestClassifier
        except Exception:
            self.model = None
            self.metadata = {
                "model_name": "heuristic-threat-predictor",
                "model_version": "2026.04.24",
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }
            return self.metadata

        samples, labels = self._build_synthetic_dataset()
        model = RandomForestClassifier(
            n_estimators=180,
            max_depth=10,
            min_samples_leaf=3,
            random_state=42,
        )
        model.fit(samples, labels)
        self.model = model
        self.metadata = {
            "model_name": "synthetic-random-forest",
            "model_version": "2026.04.24",
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(self.model_path, "wb") as fh:
            pickle.dump({"model": self.model, "metadata": self.metadata}, fh)

        return self.metadata

    def _heuristic_probability(self, features: dict) -> float:
        weighted = (
            min(features.get("rule_level", 0) / 15.0, 1.0) * 0.15
            + min(features.get("frequency_1h", 0) / 12.0, 1.0) * 0.10
            + min(features.get("frequency_24h", 0) / 60.0, 1.0) * 0.05
            + min(features.get("repeat_behavior_7d", 0) / 75.0, 1.0) * 0.10
            + min(features.get("source_ip_reputation", 0) / 100.0, 1.0) * 0.15
            + min(features.get("threat_intel_matches", 0) / 8.0, 1.0) * 0.13
            + min(features.get("local_match_count", 0) / 3.0, 1.0) * 0.12
            + min(features.get("host_criticality", 1) / 5.0, 1.0) * 0.08
            + features.get("mitre_tactic_risk", 0.35) * 0.08
            + min(features.get("login_failures", 0), 1) * 0.05
            + min(features.get("suspicious_process_activity", 0), 1) * 0.08
            + min(features.get("host_internet_exposed", 0), 1) * 0.03
            + min(features.get("host_crown_jewel", 0), 1) * 0.05
        )
        return max(0.01, min(0.99, weighted))

    def _priority_from_score(self, risk_score: int) -> str:
        if risk_score >= 85:
            return "Critical"
        if risk_score >= 65:
            return "High"
        if risk_score >= 40:
            return "Medium"
        return "Low"

    def _confidence_score(self, probability: float, features: dict) -> float:
        signal_count = sum(
            1 for key in [
                "source_ip_reputation",
                "threat_intel_matches",
                "local_match_count",
                "login_failures",
                "suspicious_process_activity",
            ]
            if features.get(key, 0) > 0
        )
        confidence = 55 + abs(probability - 0.5) * 60 + signal_count * 4
        return round(max(5.0, min(99.0, confidence)), 2)

    def predict(self, features: dict) -> dict:
        heuristic_probability = self._heuristic_probability(features)

        if self.model is not None:
            vector = [[features.get(name, 0.0) for name in FEATURE_ORDER]]
            try:
                probability = float(self.model.predict_proba(vector)[0][1])
                model_name = self.metadata["model_name"]
            except Exception as exc:
                logger.warning(f"RandomForest inference failed, falling back to heuristic: {exc}")
                probability = heuristic_probability
                model_name = "heuristic-threat-predictor"
        else:
            probability = heuristic_probability
            model_name = "heuristic-threat-predictor"

        composite = (probability * 0.7) + (heuristic_probability * 0.3)
        risk_score = round(
            max(
                1,
                min(
                    100,
                    composite * 100
                    + min(features.get("rule_level", 0), 15) * 1.2
                    + min(features.get("threat_intel_matches", 0), 8) * 2
                    + min(features.get("host_criticality", 1), 5) * 2,
                ),
            )
        )

        return {
            "model_name": model_name,
            "model_version": self.metadata["model_version"],
            "materialization_probability": round(probability * 100, 2),
            "risk_score": int(risk_score),
            "threat_priority": self._priority_from_score(risk_score),
            "confidence_score": self._confidence_score(probability, features),
        }


def recommended_action(priority: str, confidence_score: float) -> str:
    if priority == "Critical":
        return "Isolate"
    if priority == "High":
        return "Isolate" if confidence_score >= 80 else "Investigate"
    if priority == "Medium":
        return "Investigate" if confidence_score >= 70 else "Monitor"
    return "Monitor" if confidence_score >= 55 else "Ignore"


def predict_next_stage(current_tactic: str | None) -> str:
    mapping = {
        "reconnaissance": "Resource Development",
        "resource-development": "Initial Access",
        "initial-access": "Execution",
        "execution": "Persistence",
        "persistence": "Privilege Escalation",
        "privilege-escalation": "Credential Access",
        "credential-access": "Lateral Movement",
        "discovery": "Lateral Movement",
        "lateral-movement": "Collection",
        "collection": "Exfiltration",
        "command-and-control": "Impact",
        "exfiltration": "Impact",
        "impact": "Impact",
    }
    return mapping.get((current_tactic or "").lower(), "Execution")


def build_top_factors(features: dict) -> list[dict]:
    factors = [
        ("Rule severity", min(features.get("rule_level", 0) / 15.0, 1.0), f"Rule level {int(features.get('rule_level', 0))}"),
        ("Threat intel matches", min(features.get("threat_intel_matches", 0) / 8.0, 1.0), f"{int(features.get('threat_intel_matches', 0))} matches"),
        ("Source IP reputation", min(features.get("source_ip_reputation", 0) / 100.0, 1.0), f"Reputation {int(features.get('source_ip_reputation', 0))}/100"),
        ("Repeated behavior", min(features.get("repeat_behavior_7d", 0) / 75.0, 1.0), f"{int(features.get('repeat_behavior_7d', 0))} similar alerts in 7d"),
        ("Host criticality", min(features.get("host_criticality", 1) / 5.0, 1.0), f"Criticality {int(features.get('host_criticality', 1))}/5"),
        ("MITRE tactic risk", min(features.get("mitre_tactic_risk", 0.35), 1.0), f"Tactic risk {round(features.get('mitre_tactic_risk', 0.35), 2)}"),
        ("Suspicious process", min(features.get("suspicious_process_activity", 0), 1.0), "Known suspicious process activity"),
        ("Login failures", min(features.get("login_failures", 0), 1.0), "Authentication failures detected"),
    ]
    ranked = sorted(factors, key=lambda item: item[1], reverse=True)
    return [
        {"name": name, "weight": round(weight, 3), "detail": detail}
        for name, weight, detail in ranked[:5]
        if weight > 0
    ]
