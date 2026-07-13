import os


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql+psycopg2://phishdetect:phishdetect@postgres:5432/phishdetect"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
    MAX_PROCESSING_LATENCY_MS: int = int(os.getenv("MAX_PROCESSING_LATENCY_MS", "150"))
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me-in-production")
    DO_NETWORK_LOOKUPS: bool = os.getenv("DO_NETWORK_LOOKUPS", "true").lower() == "true"


settings = Settings()
