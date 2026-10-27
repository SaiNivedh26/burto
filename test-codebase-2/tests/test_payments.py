"""Unit tests for payment service (mocked Stripe)."""
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = "usr_001"
    user.stripe_customer_id = "cus_test123"
    return user


@patch("stripe.PaymentIntent.create")
def test_create_payment_intent(mock_create, mock_user):
    mock_create.return_value = MagicMock(
        client_secret="pi_test_secret",
        id="pi_test123",
    )
    from src.services.payments import create_payment_intent
    result = create_payment_intent(mock_user, 1000)
    assert result["client_secret"] == "pi_test_secret"
    assert result["payment_intent_id"] == "pi_test123"


@patch("stripe.Refund.create")
def test_refund_payment(mock_refund):
    mock_refund.return_value = MagicMock(id="re_test", status="succeeded")
    from src.services.payments import refund_payment
    result = refund_payment("pi_test123")
    assert result["status"] == "succeeded"
