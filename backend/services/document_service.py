"""
Document Management & Granular Permission Enforcement Service
"""
import uuid
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status
from backend.database import get_supabase_admin
from backend.audit import AuditService
from backend.auth import AuthenticatedUser

class DocumentService:
    @staticmethod
    def get_document_with_auth(
        document_id: str,
        user: AuthenticatedUser,
        required_level: str = "read",  # 'read' | 'edit' | 'owner'
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        DEFENSE IN DEPTH: Strict server-side authorization check.
        Ensures user is Admin, Owner, or explicitly granted permissions.
        If unauthorized, automatically records a denied attempt in the audit hash chain.
        """
        admin = get_supabase_admin()

        # 1. Fetch document metadata
        doc_res = admin.table("documents").select("*").eq("id", document_id).execute()
        if not doc_res.data:
            AuditService.log_denied_attempt(
                action="document_access_attempt",
                resource_type="document",
                actor_email=user.email,
                actor_id=user.id,
                resource_id=document_id,
                reason="Document not found",
                ip_address=ip_address
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

        doc = doc_res.data[0]

        # 2. Admin has complete visibility
        if user.role == "admin":
            return doc

        # 3. Owner has complete visibility and control
        if doc["owner_id"] == user.id:
            return doc

        # If operation requires owner role and user is not owner
        if required_level == "owner":
            AuditService.log_denied_attempt(
                action="document_owner_escalation_attempt",
                resource_type="document",
                actor_email=user.email,
                actor_id=user.id,
                resource_id=document_id,
                reason="Non-owner attempted owner-restricted action",
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Only the document owner or an administrator can perform this action."
            )

        # 4. Check document_permissions table for explicit grant
        perm_res = (
            admin.table("document_permissions")
            .select("permission_level")
            .eq("document_id", document_id)
            .eq("user_id", user.id)
            .execute()
        )

        if not perm_res.data:
            # DEFENSE IN DEPTH: Log refused access attempt to audit trail!
            AuditService.log_denied_attempt(
                action="unauthorized_document_access",
                resource_type="document",
                actor_email=user.email,
                actor_id=user.id,
                resource_id=document_id,
                reason="User lacks permission record for this document",
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to access this document."
            )

        user_perm = perm_res.data[0]["permission_level"]

        # Check required level
        if required_level == "edit" and user_perm != "edit":
            AuditService.log_denied_attempt(
                action="unauthorized_edit_attempt",
                resource_type="document",
                actor_email=user.email,
                actor_id=user.id,
                resource_id=document_id,
                reason="User has read-only permission; attempted edit",
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Edit permissions required."
            )

        return doc

    @staticmethod
    def list_accessible_documents(
        user: AuthenticatedUser,
        category: Optional[str] = None,
        search_query: Optional[str] = None,
        owner_name: Optional[str] = None,
        created_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lists documents based on user role and granular permissions.
        """
        admin = get_supabase_admin()

        if user.role == "admin":
            query = admin.table("documents").select("*, users!owner_id(username, email)").order("created_at", desc=True)
        elif user.role == "owner":
            # Own documents + shared with me
            # First fetch shared doc ids
            shared = admin.table("document_permissions").select("document_id").eq("user_id", user.id).execute()
            shared_ids = [p["document_id"] for p in shared.data] if shared.data else []
            
            if shared_ids:
                query = admin.table("documents").select("*, users!owner_id(username, email)").or_(
                    f"owner_id.eq.{user.id},id.in.({','.join(shared_ids)})"
                ).order("created_at", desc=True)
            else:
                query = admin.table("documents").select("*, users!owner_id(username, email)").eq("owner_id", user.id).order("created_at", desc=True)
        else: # Viewer
            shared = admin.table("document_permissions").select("document_id").eq("user_id", user.id).execute()
            shared_ids = [p["document_id"] for p in shared.data] if shared.data else []
            if not shared_ids:
                return []
            query = admin.table("documents").select("*, users!owner_id(username, email)").in_("id", shared_ids).order("created_at", desc=True)

        if category:
            query = query.eq("category", category)
        if search_query:
            query = query.ilike("title", f"%{search_query}%")
        if created_date:
            query = query.gte("created_at", f"{created_date}T00:00:00Z").lte("created_at", f"{created_date}T23:59:59Z")

        res = query.execute()
        return res.data or []

    @staticmethod
    def grant_permission(
        document_id: str,
        target_user_email: str,
        permission_level: str,
        current_user: AuthenticatedUser,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Grants Read or Edit access to a specific user.
        Only document owner or admin can grant permissions.
        """
        # Verify caller has owner rights
        DocumentService.get_document_with_auth(document_id, current_user, required_level="owner", ip_address=ip_address)
        
        admin = get_supabase_admin()
        # Find target user
        target = admin.table("users").select("id, email, username").eq("email", target_user_email).execute()
        if not target.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with email '{target_user_email}' not found.")
        
        target_id = target.data[0]["id"]

        # Insert or update permission
        payload = {
            "document_id": document_id,
            "user_id": target_id,
            "permission_level": permission_level,
            "granted_by": current_user.id
        }
        res = admin.table("document_permissions").upsert(payload, on_conflict="document_id,user_id").execute()

        # Log to audit trail
        AuditService.log_event(
            action="grant_permission",
            resource_type="permission",
            actor_email=current_user.email,
            actor_id=current_user.id,
            resource_id=document_id,
            details={
                "target_email": target_user_email,
                "target_id": target_id,
                "level": permission_level
            },
            ip_address=ip_address
        )
        return res.data[0] if res.data else payload

    @staticmethod
    def revoke_permission(
        document_id: str,
        target_user_id: str,
        current_user: AuthenticatedUser,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Revokes a user's access by deleting the permission row.
        Immediately blocks subsequent signed URL requests.
        """
        DocumentService.get_document_with_auth(document_id, current_user, required_level="owner", ip_address=ip_address)
        
        admin = get_supabase_admin()
        res = (
            admin.table("document_permissions")
            .delete()
            .eq("document_id", document_id)
            .eq("user_id", target_user_id)
            .execute()
        )

        # Log revocation
        AuditService.log_event(
            action="revoke_permission",
            resource_type="permission",
            actor_email=current_user.email,
            actor_id=current_user.id,
            resource_id=document_id,
            details={"revoked_user_id": target_user_id},
            ip_address=ip_address
        )
        return {"revoked": True, "document_id": document_id, "user_id": target_user_id}
