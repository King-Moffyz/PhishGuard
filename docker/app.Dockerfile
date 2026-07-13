# Shared base: installs the (large) Python dependency set — torch, transformers, xgboost,
# scikit-learn, shap — exactly once. The "backend" and "worker" stages both build on top of
# this "deps" stage, so `docker compose build` reuses the same cached layers for both images
# instead of installing ~4GB of ML dependencies twice.
FROM python:3.11-slim AS deps

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
# torch is CPU-only for this project (no CUDA inference path in app code) — installing from
# the default PyPI index pulls ~2GB of unused nvidia-cuda-*/nvidia-cudnn-* wheels alongside it.
# The PyTorch CPU wheel index skips those entirely, cutting the image ~2GB and avoiding slow/
# flaky downloads of packages that are never imported.
RUN pip install --no-cache-dir --timeout 120 --retries 10 \
    --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

COPY backend/app ./app

# Pre-download the BERT model at build time so the first Celery task doesn't
# spend 30s+ downloading weights and hit the hard time limit (60s).
RUN python -c "from transformers import AutoTokenizer, AutoModel; \
    AutoTokenizer.from_pretrained('bert-base-uncased'); \
    AutoModel.from_pretrained('bert-base-uncased')"

ENV PYTHONUNBUFFERED=1

FROM deps AS backend
EXPOSE 8000
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM deps AS worker
CMD ["celery", "-A", "app.workers.celery_app", "worker", "--loglevel=INFO", "--concurrency=4"]
