# PhishGuard — Setup Guide

This package contains the full source code, a pre-trained detection model, and everything
needed to run the system locally via Docker. No Python/Node dependencies need to be
installed manually — Docker builds everything inside containers.

---

## 1. Prerequisites

Install **Docker Desktop** (includes Docker Compose):

- Windows / Mac: https://www.docker.com/products/docker-desktop/
- After installing, open Docker Desktop and make sure it says "Docker is running" before
  continuing.

No other software is required — you do **not** need to install Python, Node.js, or any
packages yourself.

---

## 2. Unzip the project

Extract `PhishGuard-Project.zip` anywhere on your machine, e.g. to your Desktop. You should
end up with a `Project/` folder containing `backend/`, `frontend/`, `docker/`,
`docker-compose.yml`, etc.

---

## 3. Configure environment variables

Inside the `Project/` folder:

1. Copy `.env.example` to a new file named `.env` (same folder).
   - Windows: right-click `.env.example` → Copy, then Paste, then rename the copy to `.env`.
   - Mac/Linux terminal: `cp .env.example .env`
2. You don't need to change anything inside `.env` for a local demo — the defaults are
   already wired to a seeded demo organisation/mailbox.

---

## 4. Build and start everything

Open a terminal (Command Prompt / PowerShell on Windows, Terminal on Mac) in the `Project/`
folder and run:

```bash
docker compose up --build
```

**The first run will take a while** (10–20+ minutes depending on your internet speed) —
it's downloading and installing Python/Node dependencies (including PyTorch and
Transformers for the ML models) inside the containers. You'll see a lot of scrolling text;
that's normal. Subsequent runs are much faster since Docker caches the build.

Wait until you see log lines like:

```
backend-1   | INFO:     Uvicorn running on http://0.0.0.0:8000
worker-1    | celery@... ready.
frontend-1  | ➜  Local:   http://localhost:3000/
```

That means everything is up.

---

## 5. Open the dashboard

Go to **http://localhost:3000** in your browser. You should see the "PhishGuard SOC
Dashboard."

To try it out:

1. In the **"Analyze an Email"** panel at the top, click **"Load phishing example"**, then
   click **"Analyze Email."**
2. Wait a few seconds (the first analysis after startup can take up to ~45 seconds, because
   the BERT language model loads into memory on its first use — after that, it's fast).
3. You'll see the classification result (category, severity, confidence) and a SHAP
   explanation showing which features drove the decision. The alert also appears in the
   **Alert Queue** below.
4. Try **"Load legitimate example"** too, to see a lower-severity/legitimate classification
   for comparison.

You can also write your own test email into the From/Subject/Body fields and analyze it.

The backend API docs (for developers) are available at **http://localhost:8000/docs**.

---

## 6. Stopping the system

In the terminal where `docker compose up` is running, press `Ctrl+C`. To fully stop and
remove the containers:

```bash
docker compose down
```

Your data (alerts, seeded demo account, etc.) persists in a Docker volume between restarts
— running `docker compose up` again later will pick up where you left off. To wipe the
database and start completely fresh:

```bash
docker compose down -v
```

---

## 7. What's included

| Item | Notes |
|---|---|
| `backend/` | FastAPI + Celery detection service |
| `backend/model_artifacts/` | **Pre-trained model weights** (RandomForest, XGBoost, IsolationForest, BERT head, autoencoder, meta-learner) — already trained, ready to use out of the box |
| `frontend/` | React/TypeScript SOC dashboard |
| `docker/`, `docker-compose.yml` | Container definitions — this is what `docker compose up` uses |
| `migrations/` | Database schema + seed data (auto-applied on first boot) |
| `training/` | Scripts used to train the model (`train.py`, `build_dataset.py`) — not needed to run the system, only if you want to retrain on new data |
| `docs/` | Architecture diagrams, full source code appendix, this setup guide |

**Note:** the raw training dataset and cached features were excluded from this package to
keep the file size down (see `training/README.md` for how to re-download/rebuild them if
you want to retrain the models yourself).

---

## Troubleshooting

- **"Port already in use" error on `docker compose up`** — something else on your machine
  is using port 3000, 8000, 5432, or 6379. Either stop that other program, or edit the
  `ports:` section in `docker-compose.yml` to use different host ports (e.g. `"3001:3000"`).
- **Dashboard loads but shows "Failed to load alerts"** — the backend may still be starting
  up. Wait 30 seconds and refresh. Check the terminal for errors from the `backend` or
  `postgres` service.
- **First analysis takes a long time / times out** — this is expected on the very first
  request (BERT model loading into memory, ~45s). If it's consistently failing, check the
  `worker` service logs in the terminal for errors.
- **Still stuck?** Copy the terminal output and send it back for help — the specific error
  message will point to the exact cause.
