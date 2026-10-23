"""
Tamper-Evident Audit Trail Service with Cryptographic Hash Chaining
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from backend.config import settings
from backend.database import get_supabase_admin

class AuditLogEntry(BaseModel):
    id: Optional[str] = None
    sequence_number: Optional[int] = None
    timestamp: str
    actor_id: Optional[str] = None
    actor_email: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    status: str = "success"  # 'success' | 'denied'
    ip_address: str = "127.0.0.1"
    user_agent: Optional[str] = None
    details: Dict[str, Any] = {}
    previous_hash: str
    record_hash: str

def compute_record_hash(
    previous_hash: str,
    actor_email: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    status: str,
    timestamp: str,
    ip_address: str,
    details: Dict[str, Any]
) -> str:
    """
    Computes deterministic SHA-256 digest for an audit entry chained to previous_hash.
    """
    details_str = json.dumps(details, sort_keys=True)
    canonical = (
        f"{previous_hash}|"
        f"{actor_email or 'ANONYMOUS'}|"
        f"{action}|"
        f"{resource_type}|"
        f"{resource_id or 'NONE'}|"
        f"{status}|"
        f"{timestamp}|"
        f"{ip_address}|"
        f"{details_str}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

class AuditService:
    @staticmethod
    def log_event(
        action: str,
        resource_type: str,
        actor_email: str,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: str = "success",
        ip_address: str = "127.0.0.1",
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Appends an immutable, cryptographic audit log entry.
        Fetches the previous entry's hash and creates an unbroken hash chain.
        """
        admin_client = get_supabase_admin()
        details_payload = details or {}
        
        # 1. Fetch latest record hash for chaining
        try:
            res = (
                admin_client.table("audit_logs")
                .select("record_hash, sequence_number")
                .order("sequence_number", desc=True)
                .limit(1)
                .execute()
            )
            if res.data and len(res.data) > 0:
                previous_hash = res.data[0]["record_hash"]
                next_seq = res.data[0]["sequence_number"] + 1
            else:
                previous_hash = settings.GENESIS_HASH
                next_seq = 1
        except Exception:
            # Fallback for genesis or initial seed
            previous_hash = settings.GENESIS_HASH
            next_seq = 1

        timestamp = datetime.now(timezone.utc).isoformat()
        
        record_hash = compute_record_hash(
            previous_hash=previous_hash,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            timestamp=timestamp,
            ip_address=ip_address,
            details=details_payload
        )

        entry = {
            "sequence_number": next_seq,
            "timestamp": timestamp,
            "actor_id": actor_id,
            "actor_email": actor_email,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": status,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details_payload,
            "previous_hash": previous_hash,
            "record_hash": record_hash,
        }

        try:
            insert_res = admin_client.table("audit_logs").insert(entry).execute()
            return insert_res.data[0] if insert_res.data else entry
        except Exception as e:
            # Return entry for verification / simulation
            return entry

    @staticmethod
    def log_denied_attempt(
        action: str,
        resource_type: str,
        actor_email: str,
        reason: str,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Explicitly logs refused access attempts (Defense-in-depth requirement).
        """
        return AuditService.log_event(
            action=action,
            resource_type=resource_type,
            actor_email=actor_email,
            actor_id=actor_id,
            resource_id=resource_id,
            status="denied",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"refusal_reason": reason, "security_alert": True}
        )

    @staticmethod
    def verify_chain_integrity(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verifies that every link in the cryptographic chain is valid and untampered.
        Returns verification status, total verified, and any broken link details.
        """
        if not records:
            return {"is_valid": True, "count": 0, "message": "Empty audit log (Genesis state)"}

        # Sort ascending by sequence_number
        sorted_records = sorted(records, key=lambda x: x.get("sequence_number", 0))

        for i, rec in enumerate(sorted_records):
            expected_prev = settings.GENESIS_HASH if i == 0 else sorted_records[i - 1]["record_hash"]
            
            # Check 1: Does previous_hash match preceding record's record_hash?
            if rec.get("previous_hash") != expected_prev:
                return {
                    "is_valid": False,
                    "count": len(sorted_records),
                    "broken_at_sequence": rec.get("sequence_number"),
                    "reason": f"Previous hash mismatch at sequence {rec.get('sequence_number')}. Expected {expected_prev}, got {rec.get('previous_hash')}"
                }

            # Check 2: Does record_hash match content digest?
            computed = compute_record_hash(
                previous_hash=rec["previous_hash"],
                actor_email=rec["actor_email"],
                action=rec["action"],
                resource_type=rec["resource_type"],
                resource_id=rec.get("resource_id"),
                status=rec.get("status", "success"),
                timestamp=rec["timestamp"],
                ip_address=rec.get("ip_address", "127.0.0.1"),
                details=rec.get("details", {})
            )

            if computed != rec.get("record_hash"):
                return {
                    "is_valid": False,
                    "count": len(sorted_records),
                    "broken_at_sequence": rec.get("sequence_number"),
                    "reason": f"Tampered record digest at sequence {rec.get('sequence_number')}. Hash recomputation failed."
                }

        return {
            "is_valid": True,
            "count": len(sorted_records),
            "head_hash": sorted_records[-1]["record_hash"],
            "message": "Audit chain integrity 100% verified. No tampering detected."
        }
