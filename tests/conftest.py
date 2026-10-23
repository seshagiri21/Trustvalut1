"""
Pytest Test Configuration & Security Mocks for TrustVault
"""
import pytest
from unittest.mock import MagicMock, patch
from jose import jwt
from backend.config import settings
from backend.auth import AuthenticatedUser

@pytest.fixture
def mock_admin_user():
    return AuthenticatedUser(
        id="usr-admin-001",
        email="admin@trustvault.internal",
        username="admin_secops",
        role="admin"
    )

@pytest.fixture
def mock_owner_user():
    return AuthenticatedUser(
        id="usr-owner-002",
        email="alice_owner@vault.io",
        username="alice_owner",
        role="owner"
    )

@pytest.fixture
def mock_unauthorized_user():
    return AuthenticatedUser(
        id="usr-unauth-999",
        email="eve_attacker@untrusted.com",
        username="eve_attacker",
        role="viewer"
    )

@pytest.fixture
def mock_viewer_user():
    return AuthenticatedUser(
        id="usr-viewer-003",
        email="bob_viewer@vault.io",
        username="bob_viewer",
        role="viewer"
    )

@pytest.fixture
def sample_document():
    return {
        "id": "doc-uuid-12345",
        "title": "Q3 Financial Audit.pdf",
        "description": "Confidential financial ledger",
        "category": "Finance",
        "file_path": "usr-owner-002/doc-uuid-12345/Q3_Audit.pdf",
        "file_size_bytes": 102400,
        "mime_type": "application/pdf",
        "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "owner_id": "usr-owner-002",
        "created_at": "2026-10-23T10:00:00Z"
    }

def create_test_jwt(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "user_metadata": {"role": role, "username": email.split("@")[0]}
    }
    return jwt.encode(payload, settings.SUPABASE_JWT_SECRET, algorithm="HS256")
