# Model Training

Trains the four-level detection ensemble (`backend/app/ml/detection_engine.py`) on a public,
labeled phishing/legitimate email dataset, and saves the fitted artifacts into
`backend/model_artifacts/` where `DetectionEngine.load_pretrained()` picks them up at
container startup.

## Dataset

**Source:** [`zefang-liu/phishing-email-dataset`](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset)
on Hugging Face — a public mirror (LGPL-3.0) of the Kaggle "Phishing Email Detection"
dataset. Two columns: `Email Text` (raw email body text) and `Email Type`
(`Safe Email` / `Phishing Email`).

This dataset has **no raw MIME headers** — no `From`, `Reply-To`, SPF/DKIM/DMARC results,
etc. Each row is wrapped in a minimal synthetic MIME message (`build_dataset.py`) so it can
run through the *exact* production feature pipeline (`app.ml.pipeline.run_pipeline`)
unmodified. This guarantees train/serve feature parity for every feature that depends only
on message text/URLs, but means:

- **Header-derived features (18 dims) are uniformly neutral/absent for every row in
  training** — the models will learn these are uninformative on this dataset. On real
  production email with real headers, these features become active and meaningful (the
  pipeline code is unchanged; only this training run lacks the data to exercise them).
- **Category labels are binary only** (phishing vs. legitimate) — the dataset does not
  distinguish BEC vs. credential phishing vs. invoice fraud, etc. `RandomForest`, `XGBoost`,
  and the BERT head are trained as **binary** classifiers. Fine-grained category assignment
  at inference time still runs through the heuristic rules in
  `DetectionEngine._infer_category()` (credential/financial term + reply-to-mismatch
  checks), which are unaffected by this training run.

## What gets trained vs. what stays heuristic

| Component | Trained on | Method |
|---|---|---|
| RandomForest | tabular features, binary label | supervised, full train split |
| XGBoost | tabular features, binary label | supervised, full train split |
| IsolationForest | tabular features, **legitimate-only** | unsupervised anomaly |
| Denoising Autoencoder | frozen BERT embeddings, **legitimate-only** | unsupervised reconstruction |
| BERT classification head | frozen BERT embeddings, binary label | supervised linear-probe (BERT encoder itself is NOT fine-tuned — no GPU, would take days on CPU) |
| Meta-learner (Logistic Regression) | stacked sub-model outputs on a held-out validation split | supervised stacking |
| SHAP explanations | — | becomes a real `TreeExplainer` over the trained RandomForest once `_tabular_fitted = True`; no separate training step needed |

**Not trained by this pipeline** (unchanged from the original scaffold): URL SSL/redirect
inspection fields remain hardcoded placeholders (`extract_url_features` in `pipeline.py`) —
that's a live network-probing feature, not a trainable model.

## Running it

```bash
# from the project root
python3 -m venv .venv-training  # optional but recommended
source .venv-training/bin/activate

pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r training/requirements-training.txt

# 1. Dataset is already at training/data/raw/Phishing_Email.csv (downloaded once).
#    To re-fetch: see download command in this file's history / re-run curl against the
#    Hugging Face resolve URL above.

# 2. Extract features for every email through the real production pipeline.
#    This is the slow step (BERT forward pass per email, CPU-only) — expect ~15-30 min
#    for a few thousand rows. Cached to training/data/cache/features.npz so it only
#    needs to run once.
python training/build_dataset.py --limit 6000

# 3. Train all four levels + meta-learner, evaluate, save artifacts.
python training/train.py
```

Artifacts land in `backend/model_artifacts/`:
`random_forest.joblib`, `xgboost.joblib`, `isolation_forest.joblib`, `meta_learner.joblib`,
`bert_head.pt`, `autoencoder.pt`, `bert_head_meta.json`.

Metrics (accuracy/precision/recall/F1/ROC-AUC/confusion matrix on a held-out test split)
are written to `training/reports/metrics.json`.

## Picking the weights up in the running system

`docker-compose.yml` mounts `./backend/model_artifacts` into both the `backend` and
`worker` containers at `/app/model_artifacts` — restart (no rebuild needed) after training:

```bash
docker compose restart backend worker
```

`DetectionEngine.load_pretrained()` loads whatever files it finds there; anything missing
silently falls back to the pre-training heuristic for that component, so partial artifacts
(e.g. if you skip the autoencoder) degrade gracefully rather than crashing.

## Known limitations of this training run — be upfront about these in your report

1. **No raw headers in the dataset** → header-authentication features (SPF/DKIM/DMARC,
   reply-to mismatch, etc.) are not empirically validated by this training run, even though
   the code path supports them.
2. **Binary labels only** → fine-grained threat-category classification (14 categories) is
   not learned from data; only phishing-vs-legitimate is.
3. **BERT encoder is frozen, not fine-tuned** → the semantic signal comes from a linear
   probe on general-purpose `bert-base-uncased` embeddings, not a phishing-specialized
   encoder. This is standard practice for CPU-only/time-constrained setups and still yields
   a meaningfully better-than-heuristic signal, but a fine-tuned encoder (GPU, hours of
   training) would likely score higher.
4. **Single public dataset** → no cross-dataset validation; real-world generalization
   (different email clients, languages, more recent phishing kits) is untested.
5. **URL network intelligence (SSL validity, redirect chains, WHOIS)** is disabled during
   training (`do_network_lookups=False`) for speed/determinism and was largely inert in the
   source dataset anyway (tokenized text rarely contains intact URLs matching the URL
   regex).

These are reasonable, defensible scope decisions for a CPU-only, deadline-constrained
project — document them as such rather than presenting the numbers as a production-grade
benchmark.
