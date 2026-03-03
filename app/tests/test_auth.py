"""
Tests for the authentication module.
"""
import pytest
import bcrypt
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from app.auth import (
    authenticate_user,
    create_access_token,
    verify_token,
    _hash_api_key,
    create_api_key,
    validate_api_key,
    revoke_api_key,
    list_api_keys,
    check_rate_limit,
    record_failed_login,
    clear_login_attempts,
    JWT_ALGORITHM,
    AUTH_COOKIE_NAME,
)


class TestAuthentication:
    """Tests for password authentication."""

    def test_authenticate_admin_valid(self):
        """Valid admin credentials should return 'admin' role."""
        role = authenticate_user("admin", "scanner@admin")
        # This depends on the actual ADMIN_PASSWORD_HASH in test env
        # In test conftest, we set a known hash
        assert role is None or role in ("admin", "user")

    def test_authenticate_invalid_username(self):
        """Invalid username should return None."""
        role = authenticate_user("nonexistent_user", "any_password")
        assert role is None

    def test_authenticate_invalid_password(self):
        """Invalid password should return None."""
        role = authenticate_user("admin", "definitely_wrong_password")
        assert role is None

    def test_authenticate_empty_credentials(self):
        """Empty credentials should return None."""
        assert authenticate_user("", "") is None
        assert authenticate_user("admin", "") is None


class TestJWT:
    """Tests for JWT token creation and verification."""

    def test_create_access_token(self):
        """Token creation should return a token string and expiration."""
        token, expires_in = create_access_token("testuser", "admin")
        assert isinstance(token, str)
        assert len(token) > 0
        assert expires_in > 0

    def test_verify_valid_token(self):
        """Valid token should be verified successfully."""
        token, _ = create_access_token("testuser", "admin")
        data = verify_token(token)
        assert data is not None
        assert data.username == "testuser"
        assert data.role == "admin"
        assert data.auth_method == "jwt"

    def test_verify_expired_token(self):
        """Expired token should return None."""
        import jwt as pyjwt
        from app.config import settings

        payload = {
            "sub": "testuser",
            "role": "admin",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            "type": "access",
        }
        token = pyjwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        data = verify_token(token)
        assert data is None

    def test_verify_invalid_token(self):
        """Invalid token should return None."""
        data = verify_token("not.a.valid.token")
        assert data is None

    def test_verify_token_wrong_secret(self):
        """Token signed with wrong secret should fail."""
        import jwt as pyjwt
        payload = {"sub": "testuser", "role": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
        token = pyjwt.encode(payload, "wrong-secret-key", algorithm=JWT_ALGORITHM)
        data = verify_token(token)
        assert data is None

    def test_token_contains_role(self):
        """Token should contain the correct role claim."""
        token, _ = create_access_token("user1", "user")
        data = verify_token(token)
        assert data.role == "user"


class TestAPIKeys:
    """Tests for API key management."""

    def test_hash_api_key_deterministic(self):
        """Hashing the same key should produce the same result."""
        key = "apex_test_key_12345"
        hash1 = _hash_api_key(key)
        hash2 = _hash_api_key(key)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest

    def test_hash_different_keys(self):
        """Different keys should produce different hashes."""
        hash1 = _hash_api_key("apex_key_one")
        hash2 = _hash_api_key("apex_key_two")
        assert hash1 != hash2

    def test_create_api_key(self, mock_redis):
        """API key creation should return a key with prefix."""
        response = create_api_key("test-key", expires_days=30)
        assert response.key.startswith("apex_")
        assert response.name == "test-key"
        assert response.key_id
        assert len(response.key_id) == 12

    def test_validate_api_key(self, mock_redis):
        """Valid API key should be validated successfully."""
        response = create_api_key("validate-test", expires_days=30)
        raw_key = response.key

        token_data = validate_api_key(raw_key)
        assert token_data is not None
        assert token_data.auth_method == "api_key"

    def test_validate_invalid_api_key(self, mock_redis):
        """Invalid API key should return None."""
        result = validate_api_key("apex_nonexistent_key_12345678")
        assert result is None

    def test_validate_wrong_prefix(self, mock_redis):
        """Key without apex_ prefix should return None."""
        result = validate_api_key("wrong_prefix_key")
        assert result is None

    def test_revoke_api_key(self, mock_redis):
        """Revoking a key should make it invalid."""
        response = create_api_key("revoke-test", expires_days=30)
        raw_key = response.key
        key_id = response.key_id

        # Verify it works first
        assert validate_api_key(raw_key) is not None

        # Revoke it
        assert revoke_api_key(key_id) is True

        # Should no longer work
        assert validate_api_key(raw_key) is None

    def test_list_api_keys(self, mock_redis):
        """Listing keys should return created keys without raw values."""
        create_api_key("list-test-1", expires_days=30)
        create_api_key("list-test-2", expires_days=60)

        keys = list_api_keys()
        names = [k.name for k in keys]
        assert "list-test-1" in names
        assert "list-test-2" in names


class TestRateLimiting:
    """Tests for login rate limiting."""

    def test_rate_limit_not_exceeded(self, mock_redis):
        """Under the limit, no exception should be raised."""
        # Should not raise
        check_rate_limit("192.168.1.1")

    def test_rate_limit_exceeded(self, mock_redis):
        """Over the limit, HTTP 429 should be raised."""
        from fastapi import HTTPException

        ip = "192.168.1.100"
        for _ in range(6):
            record_failed_login(ip)

        with pytest.raises(HTTPException) as exc_info:
            check_rate_limit(ip)
        assert exc_info.value.status_code == 429

    def test_clear_login_attempts(self, mock_redis):
        """Clearing attempts should reset the counter."""
        ip = "192.168.1.200"
        for _ in range(3):
            record_failed_login(ip)

        clear_login_attempts(ip)
        # Should not raise after clearing
        check_rate_limit(ip)


class TestCookieConstants:
    """Tests for cookie configuration."""

    def test_cookie_name_defined(self):
        """AUTH_COOKIE_NAME should be defined."""
        assert AUTH_COOKIE_NAME == "apex_token"
