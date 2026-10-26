"""Application settings — loaded from environment variables."""
import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "PaymentAPI"
    debug: bool = False

    # Database
    database_url: str = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/paydb")
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Auth
    secret_key: str = os.environ.get("SECRET_KEY", "change-me")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Stripe
    stripe_secret_key: str = os.environ.get("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

    # AWS S3 (for invoice storage)
    aws_access_key_id: str = os.environ.get("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    s3_bucket: str = os.environ.get("S3_BUCKET", "invoices-prod")

    # Redis
    redis_url: str = os.environ.get("REDIS_URL", "redis://localhost:6379")

    class Config:
        env_file = ".env"


settings = Settings()
