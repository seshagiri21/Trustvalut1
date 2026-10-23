"""
TrustVault Configuration Settings
"""
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "TrustVault"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Supabase credentials
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "https://your-supabase-project.supabase.co")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "your-anon-key")
    SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "your-service-role-key")
    SUPABASE_JWT_SECRET: str = os.getenv("SUPABASE_JWT_SECRET", "super-secret-jwt-token-with-minimum-32-chars")
    
    # Storage settings
    STORAGE_BUCKET_NAME: str = "trustvault_documents"
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB strict limit
    SIGNED_URL_EXPIRY_SECONDS: int = 60  # Short-lived token for defense-in-depth
    
    # Allowed MIME types
    ALLOWED_MIME_TYPES: set[str] = {
        "application/pdf",
        "text/plain",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "text/csv",
        "image/png",
        "image/jpeg",
    }
    
    ALLOWED_EXTENSIONS: set[str] = {
        "pdf", "txt", "docx", "xlsx", "csv", "png", "jpg", "jpeg"
    }

    GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
