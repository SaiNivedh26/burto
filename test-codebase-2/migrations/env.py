"""Alembic env.py — runs migrations against DATABASE_URL."""
import os
from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

# Override with env var so same code works in all environments
config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])

from src.core.database import Base
from src.models import user  # noqa: F401 — registers all models

target_metadata = Base.metadata


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
