"""
TrustVault FastAPI Application Entrypoint
Full REST API + Server-rendered Jinja2 Templates + Tamper-Evident Audit Trail
"""
import uuid
from typing import Optional
from fastapi import FastAPI, Depends, Request, Form, UploadFile, File, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr

from backend.config import settings
from backend.database import get_supabase_client, get_supabase_admin
from backend.auth import get_current_user, require_role, AuthenticatedUser, get_token_from_request
from backend.audit import AuditService
from backend.services.storage_service import StorageService
from backend.services.document_service import DocumentService

app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise Document Sharing Platform with Cryptographic Audit Trail",
    version="1.0.0"
)

templates = Jinja2Templates(directory="backend/templates")

# ---------------------------------------------------------
# Schemas
# ---------------------------------------------------------
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class PermissionGrantRequest(BaseModel):
    email: EmailStr
    permission_level: str  # 'read' | 'edit'

# ---------------------------------------------------------
# Web Page Routes (Jinja2 Templates)
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root_redirect(request: Request):
    token = await get_token_from_request(request)
    if token:
        return RedirectResponse(url="/documents", status_code=302)
    return RedirectResponse(url="/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "app_name": settings.APP_NAME})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "app_name": settings.APP_NAME})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    user: AuthenticatedUser = Depends(require_role(["admin"]))
):
    """
    Admin Only: Strict 403 Forbidden server-side enforcement for non-admins.
    """
    admin = get_supabase_admin()
    docs_count = admin.table("documents").select("id", count="exact").execute()
    users_count = admin.table("users").select("id", count="exact").execute()
    logs_res = admin.table("audit_logs").select("*").order("sequence_number", desc=True).limit(10).execute()
    
    # Calculate integrity
    all_logs = admin.table("audit_logs").select("*").order("sequence_number", desc=False).execute()
    integrity_status = AuditService.verify_chain_integrity(all_logs.data or [])

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "total_documents": docs_count.count or 0,
            "total_users": users_count.count or 0,
            "recent_logs": logs_res.data or [],
            "integrity": integrity_status
        }
    )

@app.get("/documents", response_class=HTMLResponse)
async def my_documents_page(
    request: Request,
    search: Optional[str] = None,
    category: Optional[str] = None,
    user: AuthenticatedUser = Depends(get_current_user)
):
    docs = DocumentService.list_accessible_documents(user=user, category=category, search_query=search)
    return templates.TemplateResponse(
        "my_documents.html",
        {"request": request, "user": user, "documents": docs, "search": search or "", "category": category or ""}
    )

@app.get("/search", response_class=HTMLResponse)
async def search_page(
    request: Request,
    title: Optional[str] = None,
    category: Optional[str] = None,
    owner: Optional[str] = None,
    date: Optional[str] = None,
    user: AuthenticatedUser = Depends(get_current_user)
):
    results = []
    has_searched = any([title, category, owner, date])
    if has_searched:
        results = DocumentService.list_accessible_documents(
            user=user,
            category=category,
            search_query=title,
            owner_name=owner,
            created_date=date
        )
    return templates.TemplateResponse(
        "search.html",
        {
            "request": request,
            "user": user,
            "results": results,
            "has_searched": has_searched,
            "filters": {"title": title or "", "category": category or "", "owner": owner or "", "date": date or ""}
        }
    )

@app.get("/categories", response_class=HTMLResponse)
async def categories_page(
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user)
):
    categories = ["Finance", "HR", "Legal", "IT", "Education", "Personal"]
    docs = DocumentService.list_accessible_documents(user=user)
    
    # Compute counts per category
    counts = {cat: 0 for cat in categories}
    for doc in docs:
        cat = doc.get("category")
        if cat in counts:
            counts[cat] += 1

    return templates.TemplateResponse(
        "categories.html",
        {"request": request, "user": user, "category_counts": counts}
    )

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(
    request: Request,
    user: AuthenticatedUser = Depends(require_role(["owner", "admin"]))
):
    return templates.TemplateResponse("upload.html", {"request": request, "user": user})

@app.get("/activity-logs", response_class=HTMLResponse)
async def activity_logs_page(
    request: Request,
    user: AuthenticatedUser = Depends(require_role(["admin"]))
):
    """
    Admin Only: Strict 403 Forbidden server-side enforcement.
    """
    admin = get_supabase_admin()
    logs_res = admin.table("audit_logs").select("*").order("sequence_number", desc=True).limit(50).execute()
    all_logs = admin.table("audit_logs").select("*").order("sequence_number", desc=False).execute()
    integrity = AuditService.verify_chain_integrity(all_logs.data or [])

    return templates.TemplateResponse(
        "audit_logs.html",
        {"request": request, "user": user, "logs": logs_res.data or [], "integrity": integrity}
    )

# ---------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------

@app.post("/api/auth/register")
async def api_register(payload: RegisterRequest):
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long.")
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    client = get_supabase_client()
    try:
        # Supabase Auth sign up
        auth_res = client.auth.sign_up({
            "email": payload.email,
            "password": payload.password,
            "options": {
                "data": {"username": payload.username, "role": "owner"}
            }
        })
        user_id = auth_res.user.id

        # Insert user profile in public.users
        admin = get_supabase_admin()
        admin.table("users").insert({
            "id": user_id,
            "username": payload.username,
            "email": payload.email,
            "role": "owner"
        }).execute()

        # Log to audit trail
        AuditService.log_event(
            action="user_registered",
            resource_type="auth",
            actor_email=payload.email,
            actor_id=user_id,
            resource_id=user_id,
            details={"username": payload.username}
        )

        return {"success": True, "message": "User registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login")
async def api_login(payload: LoginRequest, request: Request):
    client = get_supabase_client()
    try:
        res = client.auth.sign_in_with_password({
            "email": payload.email,
            "password": payload.password
        })
        token = res.session.access_token
        user_id = res.user.id

        AuditService.log_event(
            action="user_login",
            resource_type="auth",
            actor_email=payload.email,
            actor_id=user_id,
            resource_id=user_id,
            ip_address=request.client.host if request.client else "127.0.0.1"
        )

        response = JSONResponse(content={"success": True, "token": token, "user": {"id": user_id, "email": payload.email}})
        response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, secure=True, samesite="lax")
        return response
    except Exception as e:
        AuditService.log_denied_attempt(
            action="failed_login_attempt",
            resource_type="auth",
            actor_email=payload.email,
            reason=str(e),
            ip_address=request.client.host if request.client else "127.0.0.1"
        )
        raise HTTPException(status_code=401, detail="Invalid email or password.")

@app.post("/api/documents/upload")
async def api_upload_document(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(""),
    category: str = Form(...),
    file: UploadFile = File(...),
    user: AuthenticatedUser = Depends(require_role(["owner", "admin"]))
):
    if category not in ["Finance", "HR", "Legal", "IT", "Education", "Personal"]:
        raise HTTPException(status_code=400, detail="Invalid category selected.")

    doc_id = str(uuid.uuid4())
    
    # 1. Upload to private Supabase storage with validation
    storage_path, file_size, mime_type, file_sha256 = await StorageService.validate_and_upload(
        file=file,
        owner_id=user.id,
        document_id=doc_id
    )

    # 2. Insert metadata into PostgreSQL
    admin = get_supabase_admin()
    doc_payload = {
        "id": doc_id,
        "title": title,
        "description": description,
        "category": category,
        "file_path": storage_path,
        "file_size_bytes": file_size,
        "mime_type": mime_type,
        "file_sha256": file_sha256,
        "owner_id": user.id
    }
    admin.table("documents").insert(doc_payload).execute()

    # 3. Log to tamper-evident audit trail
    AuditService.log_event(
        action="upload",
        resource_type="document",
        actor_email=user.email,
        actor_id=user.id,
        resource_id=doc_id,
        details={
            "title": title,
            "category": category,
            "file_size_bytes": file_size,
            "file_sha256": file_sha256
        },
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return {"success": True, "document_id": doc_id, "title": title}

@app.get("/api/documents/{document_id}/signed-url")
async def api_get_signed_download_url(
    document_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Enforces authorization check. If authorized, creates short-lived signed URL.
    Logs successful download or records refusal in audit trail.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # Strict server authorization verification
    doc = DocumentService.get_document_with_auth(
        document_id=document_id,
        user=user,
        required_level="read",
        ip_address=client_ip
    )

    # Generate signed URL
    signed_url = StorageService.create_signed_download_url(doc["file_path"], expires_in=settings.SIGNED_URL_EXPIRY_SECONDS)

    # Log successful download authorization
    AuditService.log_event(
        action="download",
        resource_type="document",
        actor_email=user.email,
        actor_id=user.id,
        resource_id=document_id,
        details={"signed_url_ttl_seconds": settings.SIGNED_URL_EXPIRY_SECONDS, "title": doc["title"]},
        ip_address=client_ip
    )

    return {"signed_url": signed_url, "expires_in": settings.SIGNED_URL_EXPIRY_SECONDS}

@app.post("/api/documents/{document_id}/permissions")
async def api_grant_permission(
    document_id: str,
    payload: PermissionGrantRequest,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    res = DocumentService.grant_permission(
        document_id=document_id,
        target_user_email=payload.email,
        permission_level=payload.permission_level,
        current_user=user,
        ip_address=client_ip
    )
    return {"success": True, "permission": res}

@app.delete("/api/documents/{document_id}/permissions/{target_user_id}")
async def api_revoke_permission(
    document_id: str,
    target_user_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    res = DocumentService.revoke_permission(
        document_id=document_id,
        target_user_id=target_user_id,
        current_user=user,
        ip_address=client_ip
    )
    return {"success": True, "result": res}

@app.get("/api/audit-logs/verify")
async def api_verify_audit_chain(user: AuthenticatedUser = Depends(require_role(["admin"]))):
    """
    Admin Only: Verifies cryptographic hash chain integrity end-to-end.
    """
    admin = get_supabase_admin()
    logs = admin.table("audit_logs").select("*").order("sequence_number", desc=False).execute()
    result = AuditService.verify_chain_integrity(logs.data or [])
    return result
