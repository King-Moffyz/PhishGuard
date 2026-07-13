"""
Turns the raw labeled CSV (training/data/raw/Phishing_Email.csv) into cached feature
arrays by running every row through the production feature-extraction functions in
app.ml.pipeline (header, lexical, URL) — the same code path used at inference time in
app/workers/tasks.py. This guarantees train/serve feature parity for the tabular vector
that RandomForest/XGBoost/IsolationForest are trained on.

BERT embeddings are attempted opportunistically: if torch/transformers are importable,
real 768-dim CLS embeddings are computed and cached alongside `has_bert=True`. If not
(e.g. still downloading on a slow connection), a zero vector is stored and `has_bert=False`
is recorded per row — train.py skips BERT-head/autoencoder training for rows without real
embeddings, so the tabular models (RF/XGBoost/IsolationForest) are never blocked on the
torch/transformers install finishing.

The source dataset has no raw MIME headers (no SPF/DKIM/From/Reply-To) — only email text.
Each row is wrapped in a minimal synthetic MIME message; header-derived features are
therefore uniformly "absent" across both classes (documented in training/README.md).
`_domain_age_days` is monkeypatched to a fast no-network stub — the synthetic sender
domain is meaningless to WHOIS anyway, and unconditional network lookups per-row would be
extremely slow on a constrained connection.

Usage:
    python training/build_dataset.py --limit 6000
    python training/build_dataset.py --limit 6000 --no-bert   # force-skip even if torch is available
"""
from __future__ import annotations

import argparse
import sys
from email.message import EmailMessage
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm import tqdm

TRAINING_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TRAINING_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import app.ml.pipeline as pipeline  # noqa: E402
from app.ml.pipeline import (  # noqa: E402
    FeatureBundle, clean_email, extract_header_features, extract_lexical_features,
    extract_url_features, extract_urls_from_email,
)

# Fast, deterministic, no-network stand-in — see module docstring.
pipeline._domain_age_days = lambda domain: -1.0

RAW_CSV = TRAINING_DIR / "data" / "raw" / "Phishing_Email.csv"
CACHE_DIR = TRAINING_DIR / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

LABEL_MAP = {"Phishing Email": 1, "Safe Email": 0}
BERT_DIM = 768


def _to_synthetic_mime(text: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@unknown-origin.example"
    msg["To"] = "recipient@monitored-org.example"
    msg["Subject"] = ""
    msg.set_content(text)
    return msg.as_bytes()


def _bert_available() -> bool:
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        return True
    except ImportError:
        return False


def _featurize(text: str, compute_bert: bool) -> FeatureBundle:
    cleaned = clean_email(_to_synthetic_mime(text))
    header_features = extract_header_features(cleaned)
    lexical_features = extract_lexical_features(cleaned)
    urls = extract_urls_from_email(cleaned)
    url_features = [extract_url_features(u, do_network_lookups=False) for u in urls]

    if compute_bert:
        bert_embedding = pipeline.BertEmbedder.embed(cleaned.subject, cleaned.body_text)
    else:
        bert_embedding = np.zeros(BERT_DIM, dtype=np.float32)

    return FeatureBundle(
        cleaned=cleaned,
        header_features=header_features,
        lexical_features=lexical_features,
        bert_embedding=bert_embedding,
        url_features=url_features,
    )


def build(limit: int, seed: int = 42, force_no_bert: bool = False) -> None:
    if not RAW_CSV.exists():
        raise FileNotFoundError(f"{RAW_CSV} not found — run the dataset download step first.")

    bert_ready = _bert_available() and not force_no_bert
    print(f"BERT embeddings: {'ENABLED (torch/transformers available)' if bert_ready else 'DISABLED — tabular-only features cached, bert=zeros'}")

    df = pd.read_csv(RAW_CSV, engine="python", on_bad_lines="skip")
    df = df.rename(columns={"Email Text": "text", "Email Type": "email_type"})
    df = df.dropna(subset=["text", "email_type"])
    df = df[df["text"].str.strip().str.len() > 20]
    df["label"] = df["email_type"].map(LABEL_MAP)
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    per_class = limit // 2
    balanced = (
        df.groupby("label", group_keys=False)
        .apply(lambda g: g.sample(n=min(per_class, len(g)), random_state=seed))
        .sample(frac=1.0, random_state=seed)  # shuffle
        .reset_index(drop=True)
    )
    print(f"Building features for {len(balanced)} emails "
          f"({(balanced['label'] == 1).sum()} phishing / {(balanced['label'] == 0).sum()} legitimate)")

    tabular_rows, bert_rows, labels, has_bert_flags = [], [], [], []
    skipped = 0

    for i, row in enumerate(tqdm(balanced.itertuples(), total=len(balanced))):
        text = str(row.text)
        label = int(row.label)
        try:
            bundle = _featurize(text[:20000], compute_bert=bert_ready)  # cap pathological huge rows
        except Exception:  # noqa: BLE001
            skipped += 1
            continue

        tabular_rows.append(bundle.tabular_vector)
        bert_rows.append(bundle.bert_embedding)
        labels.append(label)
        has_bert_flags.append(bert_ready)

        if (i + 1) % 500 == 0:
            _checkpoint(tabular_rows, bert_rows, labels, has_bert_flags)

    _checkpoint(tabular_rows, bert_rows, labels, has_bert_flags, final=True)
    print(f"Done. {len(labels)} rows featurized, {skipped} skipped (parse failures).")


def _checkpoint(tabular_rows, bert_rows, labels, has_bert_flags, final: bool = False) -> None:
    if not labels:
        return
    np.savez_compressed(
        CACHE_DIR / "features.npz",
        tabular=np.stack(tabular_rows).astype(np.float32),
        bert=np.stack(bert_rows).astype(np.float32),
        labels=np.array(labels, dtype=np.int64),
        has_bert=np.array(has_bert_flags, dtype=bool),
    )
    if final:
        print(f"Saved {len(labels)} rows -> {CACHE_DIR / 'features.npz'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=6000, help="total emails to featurize (balanced across classes)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-bert", action="store_true", help="force-skip BERT embeddings even if torch/transformers are installed")
    args = parser.parse_args()
    build(limit=args.limit, seed=args.seed, force_no_bert=args.no_bert)
