from src.auth.jwt import create_access_token, verify_token, ALGORITHM

def test_create_token_returns_string():
    token = create_access_token({"sub": "42"})
    assert isinstance(token, str)

def test_verify_token_roundtrip():
    """A token issued by create_access_token must verify successfully."""
    token = create_access_token({"sub": "42", "email": "user@example.com"})
    payload = verify_token(token)
    assert payload["sub"] == "42"
    assert payload["email"] == "user@example.com"

def test_algorithm_mismatch():
    assert ALGORITHM == "HS256", f"Expected HS256 but got {ALGORITHM} — auth is broken"
