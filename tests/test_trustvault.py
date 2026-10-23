"""
TrustVault Security & Access Control Test Suite
Validates strict authorization, refused attempt logging, permission revocation, and tamper-evident hash chaining.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from backend.services.document_service import DocumentService
from backend.services.storage_service import StorageService
from backend.audit import AuditService, compute_record_hash
from backend.config import settings

# -----------------------------------------------------------------------------
# 1. Test: User Cannot Access Another User's Document
# -----------------------------------------------------------------------------
def test_unauthorized_user_cannot_access_document(mock_unauthorized_user, sample_document):
    """
    Proves that a user cannot access another user's document via direct ID / URL manipulation.
    Expects HTTP 403 Forbidden and refusal to be logged.
    """
    with patch("backend.services.document_service.get_supabase_admin") as mock_admin, \
         patch.object(AuditService, "log_denied_attempt") as mock_log_denied:
        
        # Setup mock db response for document
        mock_doc_table = MagicMock()
        mock_doc_table.select.return_value.eq.return_value.execute.return_value.data = [sample_document]
        
        # Setup mock db response for permissions: empty (no permission granted)
        mock_perm_table = MagicMock()
        mock_perm_table.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = []

        def table_router(table_name):
            if table_name == "documents":
                return mock_doc_table
            elif table_name == "document_permissions":
                return mock_perm_table
            return MagicMock()

        mock_admin.return_value.table.side_effect = table_router

        # Attempt to access document as unauthorized user
        with pytest.raises(HTTPException) as exc_info:
            DocumentService.get_document_with_auth(
                document_id=sample_document["id"],
                user=mock_unauthorized_user,
                required_level="read"
            )

        assert exc_info.value.status_code == 403
        assert "Access denied" in exc_info.value.detail

        # Verify refused attempt was explicitly recorded in audit log
        mock_log_denied.assert_called_once()
        call_kwargs = mock_log_denied.call_args.kwargs
        assert call_kwargs["action"] == "unauthorized_document_access"
        assert call_kwargs["actor_email"] == mock_unauthorized_user.email
        assert call_kwargs["resource_id"] == sample_document["id"]

# -----------------------------------------------------------------------------
# 2. Test: Refused Access Attempts Are Recorded in the Audit Log
# -----------------------------------------------------------------------------
def test_refused_access_logged_in_audit_chain(mock_unauthorized_user):
    """
    Proves that refusal events are formatted into the cryptographic hash chain with status='denied'.
    """
    with patch("backend.audit.get_supabase_admin") as mock_admin:
        mock_table = MagicMock()
        # Mock previous record in chain
        mock_table.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"record_hash": "a1b2c3d4e5f60000000000000000000000000000000000000000000000000000", "sequence_number": 42}
        ]
        mock_admin.return_value.table.return_value = mock_table

        entry = AuditService.log_denied_attempt(
            action="unauthorized_document_access",
            resource_type="document",
            actor_email=mock_unauthorized_user.email,
            reason="Forbidden document requested",
            actor_id=mock_unauthorized_user.id,
            resource_id="doc-999"
        )

        assert entry["status"] == "denied"
        assert entry["actor_email"] == mock_unauthorized_user.email
        assert entry["previous_hash"] == "a1b2c3d4e5f60000000000000000000000000000000000000000000000000000"
        assert len(entry["record_hash"]) == 64
        assert entry["sequence_number"] == 43

# -----------------------------------------------------------------------------
# 3. Test: Revoking Access Immediately Blocks User From Generating Signed URL
# -----------------------------------------------------------------------------
def test_revoking_access_blocks_signed_url_generation(mock_owner_user, mock_viewer_user, sample_document):
    """
    Proves that when an owner revokes permission, the viewer is immediately blocked
    from accessing the document or generating signed URLs.
    """
    with patch("backend.services.document_service.get_supabase_admin") as mock_admin, \
         patch.object(AuditService, "log_event") as mock_log_event, \
         patch.object(AuditService, "log_denied_attempt") as mock_log_denied:

        mock_doc_table = MagicMock()
        mock_doc_table.select.return_value.eq.return_value.execute.return_value.data = [sample_document]

        mock_perm_table = MagicMock()
        # Delete permission succeeds
        mock_perm_table.delete.return_value.eq.return_value.eq.return_value.execute.return_value.data = [{"document_id": sample_document["id"]}]
        
        def table_router(table_name):
            if table_name == "documents":
                return mock_doc_table
            elif table_name == "document_permissions":
                return mock_perm_table
            return MagicMock()

        mock_admin.return_value.table.side_effect = table_router

        # Step 1: Owner revokes access
        revoke_res = DocumentService.revoke_permission(
            document_id=sample_document["id"],
            target_user_id=mock_viewer_user.id,
            current_user=mock_owner_user
        )
        assert revoke_res["revoked"] is True
        mock_log_event.assert_called_with(
            action="revoke_permission",
            resource_type="permission",
            actor_email=mock_owner_user.email,
            actor_id=mock_owner_user.id,
            resource_id=sample_document["id"],
            details={"revoked_user_id": mock_viewer_user.id},
            ip_address="127.0.0.1"
        )

        # Step 2: Now simulate viewer trying to request document access
        mock_perm_table.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = []

        with pytest.raises(HTTPException) as exc_info:
            DocumentService.get_document_with_auth(
                document_id=sample_document["id"],
                user=mock_viewer_user,
                required_level="read"
            )

        assert exc_info.value.status_code == 403
        mock_log_denied.assert_called_once()

# -----------------------------------------------------------------------------
# 4. Test: Tamper-Evident Hash Chain Integrity Verification
# -----------------------------------------------------------------------------
def test_hash_chain_validates_correctly():
    """
    Proves that a valid chain of entries with matching SHA-256 links passes verification.
    """
    # Create 3 chained records
    rec1_prev = settings.GENESIS_HASH
    rec1_hash = compute_record_hash(
        previous_hash=rec1_prev,
        actor_email="admin@trustvault.internal",
        action="system_init",
        resource_type="auth",
        resource_id="init-1",
        status="success",
        timestamp="2026-10-23T10:00:00Z",
        ip_address="127.0.0.1",
        details={"init": True}
    )
    rec1 = {
        "sequence_number": 1,
        "previous_hash": rec1_prev,
        "record_hash": rec1_hash,
        "actor_email": "admin@trustvault.internal",
        "action": "system_init",
        "resource_type": "auth",
        "resource_id": "init-1",
        "status": "success",
        "timestamp": "2026-10-23T10:00:00Z",
        "ip_address": "127.0.0.1",
        "details": {"init": True}
    }

    rec2_hash = compute_record_hash(
        previous_hash=rec1_hash,
        actor_email="alice@vault.io",
        action="upload",
        resource_type="document",
        resource_id="doc-101",
        status="success",
        timestamp="2026-10-23T10:05:00Z",
        ip_address="127.0.0.1",
        details={"title": "Contract.pdf"}
    )
    rec2 = {
        "sequence_number": 2,
        "previous_hash": rec1_hash,
        "record_hash": rec2_hash,
        "actor_email": "alice@vault.io",
        "action": "upload",
        "resource_type": "document",
        "resource_id": "doc-101",
        "status": "success",
        "timestamp": "2026-10-23T10:05:00Z",
        "ip_address": "127.0.0.1",
        "details": {"title": "Contract.pdf"}
    }

    verification = AuditService.verify_chain_integrity([rec1, rec2])
    assert verification["is_valid"] is True
    assert verification["count"] == 2
    assert verification["head_hash"] == rec2_hash

# -----------------------------------------------------------------------------
# 5. Test: Tampering with Record Breaks the Cryptographic Chain
# -----------------------------------------------------------------------------
def test_tampered_audit_log_fails_verification():
    """
    Proves that an attacker modifying details or omitting a log immediately breaks the chain.
    """
    rec1_prev = settings.GENESIS_HASH
    rec1_hash = compute_record_hash(
        previous_hash=rec1_prev,
        actor_email="admin@trustvault.internal",
        action="system_init",
        resource_type="auth",
        resource_id="init-1",
        status="success",
        timestamp="2026-10-23T10:00:00Z",
        ip_address="127.0.0.1",
        details={"init": True}
    )
    rec1 = {
        "sequence_number": 1,
        "previous_hash": rec1_prev,
        "record_hash": rec1_hash,
        "actor_email": "admin@trustvault.internal",
        "action": "system_init",
        "resource_type": "auth",
        "resource_id": "init-1",
        "status": "success",
        "timestamp": "2026-10-23T10:00:00Z",
        "ip_address": "127.0.0.1",
        "details": {"init": True}
    }

    # Tampered rec2 where action was secretly changed from 'unauthorized_access' to 'view'
    rec2 = {
        "sequence_number": 2,
        "previous_hash": rec1_hash,
        "record_hash": "deadbeef" * 8, # forged hash
        "actor_email": "eve@attacker.com",
        "action": "view",
        "resource_type": "document",
        "resource_id": "doc-101",
        "status": "success",
        "timestamp": "2026-10-23T10:05:00Z",
        "ip_address": "127.0.0.1",
        "details": {}
    }

    verification = AuditService.verify_chain_integrity([rec1, rec2])
    assert verification["is_valid"] is False
    assert verification["broken_at_sequence"] == 2
    assert "Tampered record digest" in verification["reason"]
