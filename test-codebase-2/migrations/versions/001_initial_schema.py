"""Initial schema: users, invoices, payments.

Revision ID: 001
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("is_superuser", sa.Boolean(), default=False),
        sa.Column("stripe_customer_id", sa.String(), unique=True),
        sa.Column("subscription_tier", sa.String(), default="free"),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_table(
        "invoices",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("amount", sa.Numeric(10, 2), nullable=False),
        sa.Column("currency", sa.String(), default="usd"),
        sa.Column("status", sa.String(), default="pending"),
        sa.Column("stripe_invoice_id", sa.String(), unique=True),
        sa.Column("s3_key", sa.String()),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_table(
        "payments",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("stripe_payment_intent_id", sa.String(), unique=True),
        sa.Column("amount", sa.Numeric(10, 2), nullable=False),
        sa.Column("currency", sa.String(), default="usd"),
        sa.Column("status", sa.String()),
        sa.Column("created_at", sa.DateTime()),
    )


def downgrade():
    op.drop_table("payments")
    op.drop_table("invoices")
    op.drop_table("users")
