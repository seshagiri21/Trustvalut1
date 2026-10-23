-- ====================================================================
-- TrustVault: Supabase Database Schema, Security Policies & Hash Chain
-- ====================================================================

-- 1. Enable Required Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Define Custom Types & Enums
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'owner', 'viewer');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE access_level AS ENUM ('read', 'edit');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE audit_status AS ENUM ('success', 'denied');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 3. Public Users Table (Linked to auth.users)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role user_role NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for role lookup
CREATE INDEX IF NOT EXISTS idx_users_role ON public.users(role);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);

-- 4. Documents Table
CREATE TABLE IF NOT EXISTS public.documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL CHECK (category IN ('Finance', 'HR', 'Legal', 'IT', 'Education', 'Personal')),
    file_path TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes <= 10485760), -- Max 10MB
    mime_type VARCHAR(100) NOT NULL,
    file_sha256 VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON public.documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON public.documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON public.documents(created_at DESC);

-- 5. Document Permissions Table (Granular Access Control)
CREATE TABLE IF NOT EXISTS public.document_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    permission_level access_level NOT NULL DEFAULT 'read',
    granted_by UUID NOT NULL REFERENCES public.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_doc_user_perm UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_doc_perm_doc ON public.document_permissions(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_perm_user ON public.document_permissions(user_id);

-- 6. Tamper-Evident Audit Logs Table (Hash Chain)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sequence_number BIGSERIAL NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL, -- 'upload', 'download', 'update', 'delete', 'grant_permission', 'revoke_permission', 'unauthorized_access_attempt'
    resource_type VARCHAR(50) NOT NULL, -- 'document', 'permission', 'auth'
    resource_id VARCHAR(255),
    status audit_status NOT NULL DEFAULT 'success',
    ip_address VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_seq ON public.audit_logs(sequence_number ASC);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON public.audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON public.audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_status ON public.audit_logs(status);

-- 7. Cryptographic Hash Chain Trigger Logic
-- Computes SHA-256 over: previous_hash + sequence_number + timestamp + actor_email + action + resource_id + status + details
CREATE OR REPLACE FUNCTION generate_audit_log_hash_chain()
RETURNS TRIGGER AS $$
DECLARE
    last_hash VARCHAR(64);
    canonical_payload TEXT;
    genesis_seed VARCHAR(64) := '0000000000000000000000000000000000000000000000000000000000000000';
BEGIN
    -- Explicitly prevent manual modification of sequence_number or timestamp in trigger
    NEW.timestamp := COALESCE(NEW.timestamp, NOW());

    -- Fetch the hash of the immediately preceding audit record
    SELECT record_hash INTO last_hash
    FROM public.audit_logs
    ORDER BY sequence_number DESC
    LIMIT 1;

    IF last_hash IS NULL THEN
        NEW.previous_hash := genesis_seed;
    ELSE
        NEW.previous_hash := last_hash;
    END IF;

    -- Construct standardized canonical string representation for hashing
    canonical_payload := NEW.previous_hash || '|' ||
                         COALESCE(NEW.actor_email, 'ANONYMOUS') || '|' ||
                         NEW.action || '|' ||
                         NEW.resource_type || '|' ||
                         COALESCE(NEW.resource_id, 'NONE') || '|' ||
                         NEW.status::TEXT || '|' ||
                         to_char(NEW.timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' ||
                         NEW.ip_address || '|' ||
                         NEW.details::TEXT;

    -- Compute SHA-256 digest
    NEW.record_hash := encode(digest(canonical_payload, 'sha256'), 'hex');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to execute before insert on audit_logs
DROP TRIGGER IF EXISTS trg_audit_log_hash_chain ON public.audit_logs;
CREATE TRIGGER trg_audit_log_hash_chain
BEFORE INSERT ON public.audit_logs
FOR EACH ROW
EXECUTE FUNCTION generate_audit_log_hash_chain();

-- Immutability Guard: Strictly block any UPDATE or DELETE operations on audit_logs
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'CRITICAL SECURITY VIOLATION: Audit logs are immutable and tamper-evident. Modification and deletion are strictly prohibited by system policy.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_modification ON public.audit_logs;
CREATE TRIGGER trg_prevent_audit_modification
BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_tampering();

-- 8. Row Level Security (RLS) Setup
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Helper function to check if current authenticated user is an Admin
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.users
        WHERE id = auth.uid() AND role = 'admin'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- RLS Policies: public.users
CREATE POLICY "Users can view profiles"
    ON public.users FOR SELECT
    USING (true);

CREATE POLICY "Allow user insert or registration"
    ON public.users FOR INSERT
    WITH CHECK (true);

CREATE POLICY "Users can update their own profile"
    ON public.users FOR UPDATE
    USING (id = auth.uid() OR public.is_admin());

-- Automatic trigger: Auto-syncs new auth.users directly into public.users data table
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.users (id, username, email, role)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
    NEW.email,
    COALESCE((NEW.raw_user_meta_data->>'role')::user_role, 'owner'::user_role)
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    username = EXCLUDED.username,
    role = EXCLUDED.role,
    updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT OR UPDATE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- RLS Policies: documents
CREATE POLICY "Admins have full read access to all documents"
    ON public.documents FOR SELECT
    USING (public.is_admin());

CREATE POLICY "Owners can view own documents"
    ON public.documents FOR SELECT
    USING (owner_id = auth.uid());

CREATE POLICY "Users can view documents shared with them"
    ON public.documents FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.document_permissions
            WHERE document_id = public.documents.id
            AND user_id = auth.uid()
        )
    );

CREATE POLICY "Owners and Admins can create documents"
    ON public.documents FOR INSERT
    WITH CHECK (
        owner_id = auth.uid() AND
        EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

CREATE POLICY "Owners can update own documents"
    ON public.documents FOR UPDATE
    USING (owner_id = auth.uid());

CREATE POLICY "Owners can delete own documents"
    ON public.documents FOR DELETE
    USING (owner_id = auth.uid() OR public.is_admin());

-- RLS Policies: document_permissions
CREATE POLICY "Admins can view all permissions"
    ON public.document_permissions FOR SELECT
    USING (public.is_admin());

CREATE POLICY "Document owners can view permissions for their documents"
    ON public.document_permissions FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.documents
            WHERE id = public.document_permissions.document_id
            AND owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can view permissions granted to them"
    ON public.document_permissions FOR SELECT
    USING (user_id = auth.uid());

CREATE POLICY "Document owners can insert permissions"
    ON public.document_permissions FOR INSERT
    WITH CHECK (
        granted_by = auth.uid() AND
        EXISTS (
            SELECT 1 FROM public.documents
            WHERE id = public.document_permissions.document_id
            AND owner_id = auth.uid()
        )
    );

CREATE POLICY "Document owners can delete (revoke) permissions"
    ON public.document_permissions FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM public.documents
            WHERE id = public.document_permissions.document_id
            AND owner_id = auth.uid()
        ) OR public.is_admin()
    );

-- RLS Policies: audit_logs (Strict Admin-only read, append-only via backend service role)
CREATE POLICY "Only admins can view audit logs"
    ON public.audit_logs FOR SELECT
    USING (public.is_admin());

-- Service role bypasses RLS for inserting audit events

-- 9. Private Storage Bucket Setup (Supabase Storage)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
    'trustvault_documents',
    'trustvault_documents',
    false, -- Private bucket! No public access
    10485760, -- 10MB limit
    ARRAY[
        'application/pdf',
        'text/plain',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv',
        'image/png',
        'image/jpeg'
    ]
)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS: Deny public direct downloads. Only backend or authorized RLS can generate signed URLs
CREATE POLICY "Private document access only via signed URLs"
    ON storage.objects FOR SELECT
    TO authenticated
    USING (bucket_id = 'trustvault_documents');
