"""Stripe payment processing service."""
import stripe
from sqlalchemy.orm import Session

from src.core.config import settings
from src.models.user import Payment, Invoice, User

stripe.api_key = settings.stripe_secret_key


def create_payment_intent(user: User, amount_cents: int, currency: str = "usd") -> dict:
    intent = stripe.PaymentIntent.create(
        amount=amount_cents,
        currency=currency,
        customer=user.stripe_customer_id,
        metadata={"user_id": user.id},
    )
    return {"client_secret": intent.client_secret, "payment_intent_id": intent.id}


def create_stripe_customer(email: str, name: str) -> str:
    customer = stripe.Customer.create(email=email, name=name)
    return customer.id


def cancel_subscription(subscription_id: str) -> bool:
    try:
        stripe.Subscription.cancel(subscription_id)
        return True
    except stripe.error.StripeError:
        return False


def refund_payment(payment_intent_id: str, amount_cents: int | None = None) -> dict:
    """Issue a full or partial refund."""
    kwargs: dict = {"payment_intent": payment_intent_id}
    if amount_cents:
        kwargs["amount"] = amount_cents
    refund = stripe.Refund.create(**kwargs)
    return {"refund_id": refund.id, "status": refund.status}


def handle_webhook(payload: bytes, sig_header: str) -> dict:
    event = stripe.Webhook.construct_event(
        payload, sig_header, settings.stripe_webhook_secret
    )
    return {"type": event["type"], "data": event["data"]}
