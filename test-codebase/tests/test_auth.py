"""Auth unit tests."""
import pytest
from src.auth.jwt import create_access_token, verify_token


def test_create_and_verify():
    token = create_access_token("alice")
    payload = verify_token(token)
    assert payload["sub"] == "alice"


def test_expired_token_raises():
    from datetime import datetime, timedelta, timezone
    import jwt as pyjwt, os
    secret = os.getenv("JWT_SECRET", "dev-secret-change-in-prod")
    expired = pyjwt.encode(
        {"sub": "alice", "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
        secret, algorithm="HS256",
    )
    with pytest.raises(ValueError, match="expired"):
        verify_token(expired)


def test_invalid_token_raises():
    with pytest.raises(ValueError):
        verify_token("not-a-valid-token")
