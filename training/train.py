"""
Trains the ensemble levels of DetectionEngine on the cached features produced by
build_dataset.py, then fits the meta-learner by stacking each sub-model's held-out
predictions — mirroring the inference-time logic in
app/ml/detection_engine.py::DetectionEngine.infer().

Every component here is OPTIONAL and detected at runtime:
  - XGBoost: skipped if the `xgboost` package isn't installed. detection_engine.py
    already falls back to reusing RandomForest's probability when xgboost.joblib is
    absent (see DetectionEngine._tabular_probs), so this degrades consistently between
    training and inference.
  - BERT head / Autoencoder: skipped unless the cached features actually contain real
    BERT embeddings (`has_bert` all True — see build_dataset.py; requires torch +
    transformers to have been installed when features were extracted). detection_engine.py
    falls back to reusing rf_prob / iso_score for these when their artifacts are absent
    (see DetectionEngine._bert_probs / _autoencoder_score) — same consistency guarantee.

This means `python training/train.py` always produces a usable, evaluated model with
whatever subset of the ensemble was actually trainable in the current environment; run it
again later (after installing torch/transformers/xgboost and re-running build_dataset.py)
to upgrade artifacts incrementally — already-saved files for components you don't retrain
are left untouched.

Design choices (see training/README.md for full rationale):
  - RandomForest / XGBoost / meta-learner: trained as binary classifiers
    (phishing vs legitimate) since the source dataset has no fine-grained threat-category
    labels. Sub-category assignment at inference time still runs through the
    heuristic rules in DetectionEngine._infer_category().
  - IsolationForest + Autoencoder: trained on the LEGITIMATE class only, matching their
    role as unsupervised anomaly detectors (flagging deviation from "normal" mail).
  - BertPhishingClassifierHead: trained as a binary linear-probe MLP on FROZEN BERT
    embeddings (no fine-tuning of the encoder itself) — the only way to get a supervised
    semantic signal in a reasonable time on CPU-only hardware.

Usage:
    python training/train.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split

TRAINING_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TRAINING_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Mirrors app.ml.detection_engine.SUB_MODEL_NAMES — kept as a local constant (rather than
# `from app.ml.detection_engine import SUB_MODEL_NAMES`) so this script can run the
# tabular-only training path without importing torch at module level: detection_engine.py
# defines nn.Module subclasses at import time, which hard-requires torch even when this
# run only needs RandomForest/XGBoost/IsolationForest.
SUB_MODEL_NAMES = ["random_forest", "xgboost", "bert_semantic", "isolation_forest", "autoencoder"]

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

CACHE_FILE = TRAINING_DIR / "data" / "cache" / "features.npz"
MODEL_DIR = BACKEND_DIR / "model_artifacts"
MODEL_DIR.mkdir(exist_ok=True)
REPORTS_DIR = TRAINING_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

SEED = 42


def load_cache():
    data = np.load(CACHE_FILE)
    has_bert = data["has_bert"] if "has_bert" in data else np.zeros(len(data["labels"]), dtype=bool)
    return data["tabular"], data["bert"], data["labels"], has_bert


def train_bert_head(bert_train, y_train, bert_val, y_val, epochs: int = 15, lr: float = 1e-3):
    """Linear-probe: freeze BERT encoder, train only the small classification head on
    cached embeddings. Binary target broadcast onto the 14-way output via 2 active
    logits (LEGITIMATE vs a generic phishing bucket) so the module's shape stays
    compatible with DetectionEngine's existing 14-class architecture."""
    from app.db.models import ThreatCategory
    from app.ml.detection_engine import BertPhishingClassifierHead

    categories = list(ThreatCategory)
    legit_idx = categories.index(ThreatCategory.LEGITIMATE)
    phish_idx = categories.index(ThreatCategory.CREDENTIAL_PHISHING)  # generic phishing bucket

    head = BertPhishingClassifierHead()
    optimizer = torch.optim.Adam(head.parameters(), lr=lr, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss()

    x_train = torch.tensor(bert_train, dtype=torch.float32)
    targets = torch.tensor([phish_idx if y else legit_idx for y in y_train], dtype=torch.long)
    x_val = torch.tensor(bert_val, dtype=torch.float32)

    best_val_acc, best_state = 0.0, None
    for epoch in range(epochs):
        head.train()
        optimizer.zero_grad()
        logits = head(x_train)
        loss = loss_fn(logits, targets)
        loss.backward()
        optimizer.step()

        head.eval()
        with torch.no_grad():
            val_logits = head(x_val)
            val_pred_idx = val_logits.argmax(dim=-1).numpy()
            val_pred_bin = (val_pred_idx == phish_idx).astype(int)
            val_acc = (val_pred_bin == y_val).mean()
        if val_acc >= best_val_acc:
            best_val_acc = val_acc
            best_state = {k: v.clone() for k, v in head.state_dict().items()}
        print(f"  [bert_head] epoch {epoch + 1}/{epochs} loss={loss.item():.4f} val_acc={val_acc:.4f}")

    head.load_state_dict(best_state)
    return head, legit_idx, phish_idx, best_val_acc


def bert_phishing_prob(head, embeddings: np.ndarray, legit_idx: int) -> np.ndarray:
    head.eval()
    with torch.no_grad():
        x = torch.tensor(embeddings, dtype=torch.float32)
        probs = torch.softmax(head(x), dim=-1).numpy()
    return 1.0 - probs[:, legit_idx]


def train_autoencoder(bert_legit_train: np.ndarray, epochs: int = 30, lr: float = 1e-3):
    """Reconstruction-based anomaly detector trained ONLY on legitimate-email embeddings;
    phishing emails are expected to reconstruct poorly (higher error) at inference time."""
    from app.ml.detection_engine import StackedDenoisingAutoencoder

    ae = StackedDenoisingAutoencoder(input_dim=bert_legit_train.shape[1])
    optimizer = torch.optim.Adam(ae.parameters(), lr=lr, weight_decay=1e-5)
    loss_fn = nn.MSELoss()

    x = torch.tensor(bert_legit_train, dtype=torch.float32)
    ae.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        recon = ae(x)
        loss = loss_fn(recon, x)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 5 == 0:
            print(f"  [autoencoder] epoch {epoch + 1}/{epochs} recon_mse={loss.item():.4f}")
    ae.eval()
    return ae


def autoencoder_scores(ae, embeddings: np.ndarray) -> np.ndarray:
    ae.eval()
    scores = []
    with torch.no_grad():
        for emb in embeddings:
            t = torch.tensor(emb, dtype=torch.float32).unsqueeze(0)
            recon = ae(t)
            err = torch.mean((t - recon) ** 2).item()
            scores.append(np.clip(err / 2.0, 0.0, 1.0))
    return np.array(scores)


def main():
    print("Loading cached features...")
    tabular, bert, labels, has_bert = load_cache()
    bert_ready = TORCH_AVAILABLE and bool(has_bert.all()) and len(has_bert) > 0
    print(f"{len(labels)} rows | tabular_dim={tabular.shape[1]} bert_dim={bert.shape[1]} "
          f"| positive={labels.sum()} negative={(labels == 0).sum()}")
    print(f"XGBoost available: {XGBOOST_AVAILABLE} | BERT/autoencoder trainable: {bert_ready} "
          f"(torch_available={TORCH_AVAILABLE}, has_bert_in_cache={bool(has_bert.any())})")

    idx = np.arange(len(labels))
    idx_train, idx_temp = train_test_split(idx, test_size=0.30, random_state=SEED, stratify=labels)
    idx_val, idx_test = train_test_split(idx_temp, test_size=0.50, random_state=SEED, stratify=labels[idx_temp])
    print(f"split: train={len(idx_train)} val={len(idx_val)} test={len(idx_test)}")

    tab_train, tab_val, tab_test = tabular[idx_train], tabular[idx_val], tabular[idx_test]
    bert_train, bert_val, bert_test = bert[idx_train], bert[idx_val], bert[idx_test]
    y_train, y_val, y_test = labels[idx_train], labels[idx_val], labels[idx_test]

    # ---------------------------------------------------------------
    # Level 1: RandomForest (always) + XGBoost (if installed)
    # ---------------------------------------------------------------
    print("\nTraining RandomForest...")
    rf = RandomForestClassifier(n_estimators=500, max_depth=20, n_jobs=-1, class_weight="balanced", random_state=SEED)
    rf.fit(tab_train, y_train)

    xgb = None
    if XGBOOST_AVAILABLE:
        print("Training XGBoost...")
        xgb = XGBClassifier(
            n_estimators=400, learning_rate=0.05, max_depth=6, subsample=0.8, colsample_bytree=0.8,
            objective="binary:logistic", eval_metric="logloss", n_jobs=-1, random_state=SEED,
        )
        xgb.fit(tab_train, y_train)
    else:
        print("Skipping XGBoost (package not installed) — meta-learner will use RF's signal in its place.")

    # ---------------------------------------------------------------
    # Level 3: IsolationForest (always) + Autoencoder (if BERT embeddings are real)
    # ---------------------------------------------------------------
    print("\nTraining IsolationForest (legitimate-only)...")
    legit_mask_train = y_train == 0
    iso = IsolationForest(n_estimators=200, contamination=0.05, n_jobs=-1, random_state=SEED)
    iso.fit(tab_train[legit_mask_train])

    ae = None
    if bert_ready:
        print("Training Denoising Autoencoder (legitimate-only, frozen BERT embeddings)...")
        ae = train_autoencoder(bert_train[legit_mask_train])
    else:
        print("Skipping Autoencoder (no real BERT embeddings cached) — meta-learner will use IsolationForest's signal in its place.")

    # ---------------------------------------------------------------
    # Level 2: BERT classification head (if BERT embeddings are real)
    # ---------------------------------------------------------------
    bert_head, legit_idx, bert_val_acc = None, None, None
    if bert_ready:
        print("\nTraining BERT classification head...")
        bert_head, legit_idx, _, bert_val_acc = train_bert_head(bert_train, y_train, bert_val, y_val)
    else:
        print("\nSkipping BERT classification head (no real BERT embeddings cached) — "
              "meta-learner will use RF's signal in its place.")

    # ---------------------------------------------------------------
    # Level 4: Meta-learner — stack sub-model probabilities on the VALIDATION split
    # (never seen by RF/XGB/AE/BERT during their own fitting) to avoid leakage. Falls back
    # to reusing rf_prob / iso_score for any untrained component, exactly matching
    # DetectionEngine's runtime behavior when an artifact is absent.
    # ---------------------------------------------------------------
    print("\nBuilding stacked features for meta-learner...")

    def stack(tab, bert_emb):
        rf_p = rf.predict_proba(tab)[:, 1]
        xgb_p = xgb.predict_proba(tab)[:, 1] if xgb is not None else rf_p
        iso_raw = iso.decision_function(tab)
        iso_p = np.clip(0.5 - iso_raw, 0.0, 1.0)
        bert_p = bert_phishing_prob(bert_head, bert_emb, legit_idx) if bert_head is not None else rf_p
        ae_p = autoencoder_scores(ae, bert_emb) if ae is not None else iso_p
        return np.stack([rf_p, xgb_p, bert_p, iso_p, ae_p], axis=1)

    stacked_val = stack(tab_val, bert_val)
    meta = LogisticRegression(max_iter=1000, class_weight="balanced")
    meta.fit(stacked_val, y_val)

    # ---------------------------------------------------------------
    # Evaluation on the untouched TEST split
    # ---------------------------------------------------------------
    print("\nEvaluating on held-out test set...")
    stacked_test = stack(tab_test, bert_test)
    meta_prob = meta.predict_proba(stacked_test)[:, 1]
    meta_pred = (meta_prob >= 0.5).astype(int)

    metrics = {
        "sub_model_order": SUB_MODEL_NAMES,
        "components_trained": {
            "random_forest": True,
            "xgboost": xgb is not None,
            "isolation_forest": True,
            "autoencoder": ae is not None,
            "bert_head": bert_head is not None,
        },
        "bert_head_val_accuracy": float(bert_val_acc) if bert_val_acc is not None else None,
        "test_set_size": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, meta_pred)),
        "precision": float(precision_score(y_test, meta_pred)),
        "recall": float(recall_score(y_test, meta_pred)),
        "f1": float(f1_score(y_test, meta_pred)),
        "roc_auc": float(roc_auc_score(y_test, meta_prob)),
        "confusion_matrix": confusion_matrix(y_test, meta_pred).tolist(),
        "classification_report": classification_report(y_test, meta_pred, target_names=["legitimate", "phishing"], output_dict=True),
    }
    print(json.dumps({k: v for k, v in metrics.items() if k != "classification_report"}, indent=2))

    with open(REPORTS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # ---------------------------------------------------------------
    # Persist artifacts — picked up by DetectionEngine.load_pretrained() at runtime.
    # Only write files for components that were actually trained this run; artifacts
    # from a previous run for components skipped this time are left in place untouched.
    # ---------------------------------------------------------------
    print(f"\nSaving artifacts to {MODEL_DIR} ...")
    joblib.dump(rf, MODEL_DIR / "random_forest.joblib")
    joblib.dump(iso, MODEL_DIR / "isolation_forest.joblib")
    joblib.dump(meta, MODEL_DIR / "meta_learner.joblib")
    if xgb is not None:
        joblib.dump(xgb, MODEL_DIR / "xgboost.joblib")
    if bert_head is not None:
        torch.save(bert_head.state_dict(), MODEL_DIR / "bert_head.pt")
    if ae is not None:
        torch.save(ae.state_dict(), MODEL_DIR / "autoencoder.pt")
    if bert_head is not None or ae is not None:
        with open(MODEL_DIR / "bert_head_meta.json", "w") as f:
            json.dump({"legit_idx": legit_idx, "input_dim": int(bert.shape[1])}, f)

    print("Done. Restart/rebuild the backend + worker containers to load the new weights.")
    if xgb is None or bert_head is None or ae is None:
        print("\nNOTE: some components were skipped this run (see components_trained in "
              "reports/metrics.json). Install the missing package(s) and re-run "
              "build_dataset.py + train.py to upgrade them later — already-trained "
              "components are unaffected.")


if __name__ == "__main__":
    main()
