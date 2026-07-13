from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "phishdetect",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    # NOTE: MAX_PROCESSING_LATENCY_MS (150ms) is the target/alerting budget logged by
    # analyze_email itself (see tasks.py) — it is NOT this hard kill switch. These limits
    # exist only to stop a truly hung task; they must stay well above worst-case latency,
    # which includes a one-time BERT model load (~10-30s on CPU) and XGBoost
    # deserialization on each worker's first task. After the first task, inference
    # is sub-second and never approaches these limits.
    task_time_limit=180,
    task_soft_time_limit=120,
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=200,
    task_acks_late=True,
)
