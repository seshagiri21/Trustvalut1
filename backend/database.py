"""
Supabase Client & Database Connection Module
"""
from supabase import create_client, Client
from backend.config import settings

# Standard client using Anon Key (adheres to RLS)
def get_supabase_client() -> Client:
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

# Admin client using Service Role Key (bypasses RLS for secure audit logging & admin operations)
def get_supabase_admin() -> Client:
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
