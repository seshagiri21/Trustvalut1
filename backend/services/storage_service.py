"""
Supabase Storage Service: File Uploads & Signed URL Generation
"""
import hashlib
from typing import Tuple
from fastapi import UploadFile, HTTPException, status
from backend.config import settings
from backend.database import get_supabase_admin

class StorageService:
    @staticmethod
    async def validate_and_upload(
        file: UploadFile,
        owner_id: str,
        document_id: str
    ) -> Tuple[str, int, str, str]:
        """
        Validates size, MIME type, and extension, computes SHA-256,
        and uploads file to the private Supabase Storage bucket.
        Returns: (file_path, file_size_bytes, mime_type, file_sha256)
        """
        # 1. Validate file extension
        filename = file.filename or "unknown"
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        if ext not in settings.ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file extension '.{ext}'. Allowed types: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}"
            )

        # 2. Read contents and check size
        contents = await file.read()
        file_size = len(contents)
        if file_size > settings.MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_BYTES / (1024 * 1024):.0f}MB."
            )

        # 3. Validate MIME type
        mime_type = file.content_type or "application/octet-stream"
        if mime_type not in settings.ALLOWED_MIME_TYPES:
            # Check if text/plain or valid csv
            if ext == "csv" and "csv" in mime_type:
                pass
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid MIME type '{mime_type}' for security policy."
                )

        # 4. Compute SHA-256 for integrity verification
        file_sha256 = hashlib.sha256(contents).hexdigest()

        # 5. Build isolated storage path: {owner_id}/{document_id}/{filename}
        clean_filename = "".join(c for c in filename if c.isalnum() or c in "._-")
        storage_path = f"{owner_id}/{document_id}/{clean_filename}"

        # 6. Upload directly to private bucket using admin service client
        admin = get_supabase_admin()
        try:
            admin.storage.from_(settings.STORAGE_BUCKET_NAME).upload(
                path=storage_path,
                file=contents,
                file_options={"content-type": mime_type, "upsert": "false"}
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Storage upload failed: {str(e)}"
            )

        return storage_path, file_size, mime_type, file_sha256

    @staticmethod
    def create_signed_download_url(file_path: str, expires_in: int = None) -> str:
        """
        Creates a time-limited Signed URL to download a private file.
        Only called AFTER backend has explicitly verified user authorization.
        """
        admin = get_supabase_admin()
        duration = expires_in or settings.SIGNED_URL_EXPIRY_SECONDS
        try:
            res = admin.storage.from_(settings.STORAGE_BUCKET_NAME).create_signed_url(
                path=file_path,
                expires_in=duration
            )
            if isinstance(res, dict) and "signedURL" in res:
                return res["signedURL"]
            elif hasattr(res, "signed_url"):
                return res.signed_url
            elif isinstance(res, dict) and "signedUrl" in res:
                return res["signedUrl"]
            return str(res)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Could not generate secure signed URL: {str(e)}"
            )

    @staticmethod
    def delete_file(file_path: str):
        admin = get_supabase_admin()
        try:
            admin.storage.from_(settings.STORAGE_BUCKET_NAME).remove([file_path])
        except Exception:
            pass
