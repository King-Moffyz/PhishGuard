# AI-Based Phishing Detection System (MVP)

Corporate email phishing detection platform: async FastAPI/Celery backend, a hierarchical ML ensemble
(RandomForest + XGBoost + fine-tuned BERT + IsolationForest + Denoising Autoencoder + Logistic Regression
meta-learner), SHAP-based explainability, a URL/domain intelligence microservice, and a React/TypeScript
SOC analyst dashboard.

## Run locally

```bash
cp .env.example .env
docker compose up --build
```

- Backend API: http://localhost:8000/docs
- Dashboard: http://localhost:3000
- Postgres schema is auto-applied from `migrations/0001_init.sql` on first boot.

## Layout

```
backend/app/db/models.py         SQLAlchemy schema (organisations -> alerts -> response_actions)
backend/app/ml/pipeline.py       Cleaning, header/lexical/URL feature extraction, BERT embeddings
backend/app/ml/detection_engine.py  Multi-level ensemble + SHAP explanations
backend/app/api/main.py          FastAPI routes (/api/v1/emails/analyze, /api/v1/alerts, ...)
backend/app/workers/tasks.py     Celery task: inference + automated critical-severity response
frontend/src/pages/Dashboard.tsx SOC analyst dashboard (alert queue, SHAP panel, telemetry)
migrations/0001_init.sql         Raw SQL schema (mirrors models.py) for direct psql apply
```

## Training

`DetectionEngine.load_pretrained()` loads `model_artifacts/*.joblib` if present; without pretrained
weights it runs on deterministic heuristic fallbacks so the pipeline is runnable end-to-end before a
labeled training set is available. Persist trained `RandomForestClassifier`, `XGBClassifier`,
`IsolationForest`, and the `MetaLearnerEnsemble` there via `joblib.dump` / `MetaLearnerEnsemble.save()`.
