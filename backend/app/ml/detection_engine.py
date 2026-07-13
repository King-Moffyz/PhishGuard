"""
Hierarchical multi-level detection engine:

  Level 1 (Supervised tabular)      -> RandomForest + XGBoost on header/URL features
  Level 2 (Semantic deep learning)  -> fine-tuned bert-base-uncased classification head
  Level 3 (Unsupervised anomaly)    -> IsolationForest + Stacked Denoising Autoencoder
  Level 4 (Ensemble meta-learner)   -> Logistic Regression over sub-model probabilities
  Explainability                    -> SHAP local attributions -> NL narrative
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression

from app.db.models import Severity, ThreatCategory
from app.ml.pipeline import FeatureBundle, TABULAR_FEATURE_NAMES

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "model_artifacts"
MODEL_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Level 1: Supervised tabular classifiers
# ---------------------------------------------------------------------------

def build_random_forest() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        n_jobs=-1,
        class_weight="balanced",
        random_state=42,
    )


def build_xgboost():
    from xgboost import XGBClassifier  # deferred: xgboost is a large optional dependency;
    # cold-start engines that never load a trained xgboost.joblib don't need it importable.
    return XGBClassifier(
        n_estimators=800,
        learning_rate=0.01,
        max_depth=8,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=len(list(ThreatCategory)),
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=42,
    )


# ---------------------------------------------------------------------------
# Level 2: Semantic deep learning (BERT classification head)
# ---------------------------------------------------------------------------

class BertPhishingClassifierHead(nn.Module):
    """Custom classification head on top of a frozen/fine-tuned BERT CLS embedding (768-dim)."""

    def __init__(self, embedding_dim: int = 768, num_classes: int = len(list(ThreatCategory))):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(embedding_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, embedding: torch.Tensor) -> torch.Tensor:
        return self.net(embedding)

    def predict_proba(self, embedding: np.ndarray) -> np.ndarray:
        self.eval()
        with torch.no_grad():
            x = torch.tensor(embedding, dtype=torch.float32).unsqueeze(0)
            logits = self.forward(x)
            return torch.softmax(logits, dim=-1).squeeze(0).numpy()


# ---------------------------------------------------------------------------
# Level 3: Unsupervised anomaly trackers
# ---------------------------------------------------------------------------

def build_isolation_forest() -> IsolationForest:
    return IsolationForest(
        n_estimators=200,
        contamination=0.05,
        n_jobs=-1,
        random_state=42,
    )


class StackedDenoisingAutoencoder(nn.Module):
    """4-layer stacked denoising autoencoder with 64-dim bottleneck for reconstruction-error anomaly scoring."""

    def __init__(self, input_dim: int, encoding_dim: int = 64, noise_factor: float = 0.1):
        super().__init__()
        self.noise_factor = noise_factor
        h1, h2 = max(input_dim // 2, encoding_dim * 2), max(input_dim // 4, encoding_dim)

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1), nn.ReLU(),
            nn.Linear(h1, h2), nn.ReLU(),
        )
        self.bottleneck = nn.Linear(h2, encoding_dim)
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, h2), nn.ReLU(),
            nn.Linear(h2, h1), nn.ReLU(),
            nn.Linear(h1, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.training:
            x = x + self.noise_factor * torch.randn_like(x)
        z = self.bottleneck(self.encoder(x))
        return self.decoder(z)

    def reconstruction_error(self, x: np.ndarray) -> float:
        self.eval()
        with torch.no_grad():
            t = torch.tensor(x, dtype=torch.float32).unsqueeze(0)
            recon = self.forward(t)
            return float(torch.mean((t - recon) ** 2).item())


# ---------------------------------------------------------------------------
# Level 4: Ensemble meta-learner
# ---------------------------------------------------------------------------

SUB_MODEL_NAMES = ["random_forest", "xgboost", "bert_semantic", "isolation_forest", "autoencoder"]

SEVERITY_THRESHOLDS = [
    (0.90, Severity.CRITICAL),
    (0.70, Severity.HIGH),
    (0.40, Severity.MEDIUM),
    (0.0, Severity.LOW),
]


class MetaLearnerEnsemble:
    """Logistic Regression meta-learner stacking sub-model probability outputs."""

    def __init__(self):
        self.model = LogisticRegression(max_iter=1000, class_weight="balanced")
        self._fitted = False

    def fit(self, sub_model_probs: np.ndarray, y: np.ndarray):
        self.model.fit(sub_model_probs, y)
        self._fitted = True

    def predict(self, sub_model_probs: np.ndarray) -> tuple[float, Severity]:
        if not self._fitted:
            score = float(np.clip(sub_model_probs.mean(), 0.0, 1.0))
        else:
            score = float(self.model.predict_proba(sub_model_probs.reshape(1, -1))[0, 1])
        severity = next(sev for threshold, sev in SEVERITY_THRESHOLDS if score >= threshold)
        return score, severity

    def save(self, path: Path = MODEL_DIR / "meta_learner.joblib"):
        joblib.dump(self.model, path)

    def load(self, path: Path = MODEL_DIR / "meta_learner.joblib"):
        self.model = joblib.load(path)
        self._fitted = True


# ---------------------------------------------------------------------------
# Full engine orchestrator
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    category: ThreatCategory
    severity: Severity
    meta_confidence: float
    sub_model_scores: dict[str, float]
    latencies_ms: dict[str, float]
    shap_explanation: dict[str, Any] = field(default_factory=dict)
    nl_summary: str = ""


class DetectionEngine:
    def __init__(self):
        self.random_forest = build_random_forest()
        self.xgboost = build_xgboost()
        self.bert_head = BertPhishingClassifierHead()
        self.isolation_forest = build_isolation_forest()
        self.autoencoder: StackedDenoisingAutoencoder | None = None
        self.meta_learner = MetaLearnerEnsemble()
        self._tabular_fitted = False  # gates RandomForest (the primary, always-attempted tabular signal)
        self._xgb_fitted = False
        self._iso_fitted = False
        self._bert_fitted = False
        self._ae_fitted = False
        self._shap_explainer = None

    def load_pretrained(self):
        """Load persisted model weights from MODEL_DIR if present. Each artifact is loaded
        independently — a missing file (e.g. one model still training, or a slow/partial
        download) only disables that specific sub-model's trained path rather than
        discarding every other artifact that DID load successfully."""
        try:
            self.random_forest = joblib.load(MODEL_DIR / "random_forest.joblib")
            self._tabular_fitted = True
        except FileNotFoundError:
            pass

        try:
            self.xgboost = joblib.load(MODEL_DIR / "xgboost.joblib")
            self._xgb_fitted = True
        except FileNotFoundError:
            pass

        try:
            self.isolation_forest = joblib.load(MODEL_DIR / "isolation_forest.joblib")
            self._iso_fitted = True
        except FileNotFoundError:
            pass

        try:
            self.meta_learner.load()
        except FileNotFoundError:
            pass

        try:
            self.bert_head.load_state_dict(torch.load(MODEL_DIR / "bert_head.pt", map_location="cpu"))
            self.bert_head.eval()
            self._bert_fitted = True
        except FileNotFoundError:
            pass

        try:
            input_dim = 768
            meta_path = MODEL_DIR / "bert_head_meta.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    input_dim = json.load(f).get("input_dim", 768)
            autoencoder = StackedDenoisingAutoencoder(input_dim=input_dim)
            autoencoder.load_state_dict(torch.load(MODEL_DIR / "autoencoder.pt", map_location="cpu"))
            autoencoder.eval()
            self.autoencoder = autoencoder
            self._ae_fitted = True
        except FileNotFoundError:
            pass

    def _tabular_probs(self, tabular_vector: np.ndarray) -> tuple[float, float]:
        x = tabular_vector.reshape(1, -1)
        if self._tabular_fitted:
            # index 1 = probability of the "phishing" class (models are trained binary:
            # 0 = legitimate, 1 = phishing) — NOT the max-confidence class, which would
            # spike for confidently-legitimate emails too and invert the signal.
            rf_prob = float(self.random_forest.predict_proba(x)[0, 1])
        else:
            # Deterministic heuristic fallback for a cold-started model (pre-training).
            rf_prob = float(np.clip(tabular_vector.mean() / 3.0, 0.0, 1.0))

        if self._xgb_fitted:
            xgb_prob = float(self.xgboost.predict_proba(x)[0, 1])
        else:
            # XGBoost artifact unavailable (e.g. not yet trained) — reuse RF's signal
            # rather than an unfitted, randomly-initialized XGBoost model.
            xgb_prob = rf_prob
        return rf_prob, xgb_prob

    def _isolation_score(self, tabular_vector: np.ndarray) -> float:
        x = tabular_vector.reshape(1, -1)
        if self._iso_fitted:
            raw = self.isolation_forest.decision_function(x)[0]
            return float(np.clip(0.5 - raw, 0.0, 1.0))
        return float(np.clip(np.abs(tabular_vector).std() / 5.0, 0.0, 1.0))

    def _autoencoder_score(self, bert_embedding: np.ndarray, iso_score: float) -> float:
        if not self._ae_fitted:
            # Untrained autoencoder — reuse the IsolationForest's anomaly signal (the
            # other unsupervised detector) rather than a randomly-initialized network's
            # reconstruction error, which is meaningless noise.
            return iso_score
        error = self.autoencoder.reconstruction_error(bert_embedding)
        return float(np.clip(error / 2.0, 0.0, 1.0))

    def _bert_probs(self, bundle: FeatureBundle, rf_prob: float) -> np.ndarray:
        """Returns a 14-way category distribution. When the classification head is
        trained, this is a real softmax over the frozen BERT embedding. Otherwise an
        unfitted, randomly-initialized network forward pass is not a meaningful signal —
        fall back to a distribution that reuses rf_prob as P(phishing), spread uniformly
        over the non-legitimate categories, so bert_phishing_prob and category inference
        both degrade to the RandomForest signal instead of noise."""
        if self._bert_fitted:
            return self.bert_head.predict_proba(bundle.bert_embedding)

        categories = list(ThreatCategory)
        legit_idx = categories.index(ThreatCategory.LEGITIMATE)
        probs = np.full(len(categories), rf_prob / (len(categories) - 1), dtype=np.float32)
        probs[legit_idx] = 1.0 - rf_prob
        return probs

    def infer(self, bundle: FeatureBundle) -> DetectionResult:
        latencies: dict[str, float] = {}

        t0 = time.perf_counter()
        rf_prob, xgb_prob = self._tabular_probs(bundle.tabular_vector)
        latencies["random_forest"] = latencies["xgboost"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        bert_probs = self._bert_probs(bundle, rf_prob)
        bert_phishing_prob = float(1.0 - bert_probs[list(ThreatCategory).index(ThreatCategory.LEGITIMATE)])
        latencies["bert_semantic"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        iso_score = self._isolation_score(bundle.tabular_vector)
        latencies["isolation_forest"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        ae_score = self._autoencoder_score(bundle.bert_embedding, iso_score)
        latencies["autoencoder"] = (time.perf_counter() - t0) * 1000

        sub_model_scores = {
            "random_forest": rf_prob,
            "xgboost": xgb_prob,
            "bert_semantic": bert_phishing_prob,
            "isolation_forest": iso_score,
            "autoencoder": ae_score,
        }

        t0 = time.perf_counter()
        probs_vector = np.array([sub_model_scores[n] for n in SUB_MODEL_NAMES])
        meta_confidence, severity = self.meta_learner.predict(probs_vector)
        latencies["meta_learner"] = (time.perf_counter() - t0) * 1000

        # Heuristic override for authenticated emails with zero phishing indicators
        is_authenticated = bundle.header_features.get("auth_all_pass", 0.0) > 0
        has_no_phish_signals = (
            bundle.lexical_features.get("num_urgent_phrases", 0.0) == 0.0 and
            bundle.lexical_features.get("contains_credential_request", 0.0) == 0.0 and
            bundle.lexical_features.get("contains_financial_request", 0.0) == 0.0 and
            bundle.lexical_features.get("num_links_in_text", 0.0) == 0.0 and
            bundle.header_features.get("sender_display_name_mismatch", 0.0) == 0.0
        )
        if is_authenticated and has_no_phish_signals:
            meta_confidence = 0.05
            severity = Severity.LOW

        category = self._infer_category(bundle, bert_probs, meta_confidence)

        result = DetectionResult(
            category=category,
            severity=severity,
            meta_confidence=meta_confidence,
            sub_model_scores=sub_model_scores,
            latencies_ms=latencies,
        )

        shap_expl, nl_summary = compute_shap_explanations(bundle, self, result)
        result.shap_explanation = shap_expl
        result.nl_summary = nl_summary
        return result

    def _infer_category(self, bundle: FeatureBundle, bert_probs: np.ndarray, meta_confidence: float) -> ThreatCategory:
        categories = list(ThreatCategory)
        if meta_confidence < 0.4:
            return ThreatCategory.LEGITIMATE

        top_idx = int(np.argmax(bert_probs))
        candidate = categories[top_idx]
        if candidate == ThreatCategory.LEGITIMATE:
            # BERT's semantic model says legitimate. Only override when the
            # meta-learner is *convincingly* phishing (>= 0.6). At borderline
            # confidence (0.4–0.6) the ensemble signal is too weak to outweigh
            # BERT's category-level verdict — return LEGITIMATE rather than
            # generating a false-positive UNKNOWN_ANOMALY.
            if meta_confidence < 0.6:
                return ThreatCategory.LEGITIMATE
            has_credential_terms = bundle.lexical_features.get("contains_credential_request", 0.0) > 0
            has_financial_terms = bundle.lexical_features.get("contains_financial_request", 0.0) > 0
            if has_financial_terms and bundle.header_features.get("reply_to_mismatch", 0.0) > 0:
                return ThreatCategory.BEC
            if has_credential_terms:
                return ThreatCategory.CREDENTIAL_PHISHING
            return ThreatCategory.UNKNOWN_ANOMALY
        return candidate


# ---------------------------------------------------------------------------
# Explainability: SHAP local attributions -> NL narrative
# ---------------------------------------------------------------------------

FEATURE_NL_TEMPLATES = {
    "reply_to_mismatch": "the Reply-To address does not match the visible sender address",
    "sender_display_name_mismatch": "the display name impersonates a recognized brand not matching the sending domain",
    "spf_pass": "SPF authentication {state}",
    "dkim_pass": "DKIM authentication {state}",
    "dmarc_pass": "DMARC alignment {state}",
    "sender_domain_age_days": "the sending domain was registered only {value:.0f} days ago",
    "num_urgent_phrases": "the message uses {value:.0f} urgency-inducing phrases",
    "contains_credential_request": "the message solicits login credentials or personal identifiers",
    "contains_financial_request": "the message requests a financial or wire transfer action",
    "has_ip_host": "one or more links point directly to a raw IP address instead of a domain",
    "tld_is_suspicious": "linked URLs use a top-level domain frequently abused for phishing",
    "domain_age_days": "the linked domain(s) are newly registered",
    "levenshtein_dist_to_known_brand": "a linked domain is a near-lookalike of a known brand name",
}


def compute_shap_explanations(bundle: FeatureBundle, engine: DetectionEngine, result: DetectionResult) -> tuple[dict, str]:
    """Compute local Shapley feature attributions and render a human-readable narrative for the final prediction."""
    feature_names = TABULAR_FEATURE_NAMES
    x = bundle.tabular_vector.reshape(1, -1)

    if engine._tabular_fitted:
        try:
            import shap  # deferred: large optional dependency, only needed once a
            # RandomForest is actually fitted (cold-start engines fall back below).
            explainer = shap.TreeExplainer(engine.random_forest)
            shap_values = explainer.shap_values(x)
            if isinstance(shap_values, list):
                # Older shap: list of per-class (n_samples, n_features) arrays.
                shap_values = shap_values[-1]
            shap_values = np.asarray(shap_values)
            if shap_values.ndim == 3:
                # Newer shap: single (n_samples, n_features, n_classes) array —
                # take the positive/last class's per-feature attributions.
                shap_values = shap_values[..., -1]
            attributions = np.asarray(shap_values[0]).reshape(-1)
            if attributions.shape[0] != len(TABULAR_FEATURE_NAMES):
                raise ValueError(f"unexpected SHAP attribution shape {attributions.shape}")
        except Exception:
            logging.getLogger(__name__).warning(
                "compute_shap_explanations: SHAP TreeExplainer failed, using fallback "
                "attribution", exc_info=True,
            )
            attributions = _fallback_attribution(bundle.tabular_vector)
    else:
        attributions = _fallback_attribution(bundle.tabular_vector)

    ranked = sorted(
        zip(feature_names, attributions, bundle.tabular_vector.tolist()),
        key=lambda t: abs(t[1]),
        reverse=True,
    )[:8]

    structured = [
        {"feature": name, "shap_value": float(val), "raw_value": float(raw)}
        for name, val, raw in ranked
    ]

    narrative_clauses = []
    for name, val, raw in ranked[:5]:
        if val <= 0:
            continue
        template = FEATURE_NL_TEMPLATES.get(name)
        if not template:
            continue
        if "{state}" in template:
            clause = template.format(state="failed" if raw < 1.0 else "passed")
            if raw >= 1.0:
                continue
        elif "{value" in template:
            clause = template.format(value=raw)
        else:
            clause = template
        narrative_clauses.append(clause)

    if narrative_clauses:
        narrative = (
            f"This message was classified as {result.category.value.replace('_', ' ')} "
            f"with {result.meta_confidence:.0%} confidence ({result.severity.value} severity) because "
            + "; ".join(narrative_clauses) + "."
        )
    else:
        narrative = (
            f"This message was classified as {result.category.value.replace('_', ' ')} "
            f"with {result.meta_confidence:.0%} confidence ({result.severity.value} severity) "
            "based on a combination of low-magnitude structural and behavioral signals."
        )

    return {"top_features": structured, "sub_model_scores": result.sub_model_scores}, narrative


def _fallback_attribution(tabular_vector: np.ndarray) -> np.ndarray:
    """Deterministic pseudo-SHAP fallback (deviation from feature mean) used before the tree model is trained."""
    centered = tabular_vector - np.nanmean(tabular_vector)
    return centered / (np.abs(centered).sum() + 1e-6)
