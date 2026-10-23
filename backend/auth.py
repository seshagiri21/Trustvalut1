"""
Authentication & Role-Based Access Control (RBAC) Middleware
"""
from typing import Optional, List
from fastapi import Request, HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from backend.config import settings
from backend.database import get_supabase_admin
from backend.audit import AuditService

security_bearer = HTTPBearer(auto_error=False)

class AuthenticatedUser(BaseModel):
    id: str
    email: str
    username: str
    role: str  # 'admin' | 'owner' | 'viewer'

async def get_token_from_request(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> Optional[str]:
    # 1. Bearer header
    if creds and creds.credentials:
        return creds.credentials
    # 2. Check Cookie for web/Jinja templates
    token = request.cookies.get("access_token")
    if token:
        if token.startswith("Bearer "):
            return token.split(" ")[1]
        return token
    # 3. Check authorization header directly
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    return None

async def get_current_user(request: Request, token: Optional[str] = Depends(get_token_from_request)) -> AuthenticatedUser:
    if not token:
        # Log unauthorized attempt
        AuditService.log_denied_attempt(
            action="api_access",
            resource_type="auth",
            actor_email="anonymous",
            reason="Missing or empty JWT token",
            ip_address=request.client.host if request.client else "127.0.0.1"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        payload = jwt.decode(
            token,
            settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        user_id: str = payload.get("sub")
        email: str = payload.get("email", "")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    except JWTError as e:
        AuditService.log_denied_attempt(
            action="api_access",
            resource_type="auth",
            actor_email="invalid_token_user",
            reason=f"JWT verification failed: {str(e)}",
            ip_address=request.client.host if request.client else "127.0.0.1"
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Fetch role and profile from public.users table
    admin = get_supabase_admin()
    user_row = admin.table("users").select("id, username, email, role").eq("id", user_id).single().execute()

    if not user_row.data:
        # Fallback if user just registered but public.users not yet populated
        role = payload.get("user_metadata", {}).get("role", "viewer")
        username = payload.get("user_metadata", {}).get("username", email.split("@")[0])
    else:
        role = user_row.data.get("role", "viewer")
        username = user_row.data.get("username", email.split("@")[0])

    return AuthenticatedUser(
        id=user_id,
        email=email,
        username=username,
        role=role
    )

def require_role(allowed_roles: List[str]):
    """
    Factory for role-guard dependency.
    Raises strict 403 Forbidden and logs the refused attempt in the audit chain.
    """
    async def role_checker(request: Request, current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if current_user.role not in allowed_roles:
            # DEFENSE IN DEPTH: Log refused access attempt
            AuditService.log_denied_attempt(
                action="privilege_escalation_attempt",
                resource_type="rbac_route",
                actor_email=current_user.email,
                actor_id=current_user.id,
                reason=f"User role '{current_user.role}' is not in allowed roles: {allowed_roles}",
                resource_id=request.url.path,
                ip_address=request.client.host if request.client else "127.0.0.1"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: insufficient permissions. Role '{current_user.role}' is not authorized."
            )
        return current_user
    return role_checker
