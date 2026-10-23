/**
 * Supabase Connection Diagnostic & Schema Migration Modal
 */
import React, { useState, useEffect } from 'react';
import {
  Database,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  Shield,
  Layers,
  HardDrive
} from 'lucide-react';
import {
  isSupabaseConfigured,
  SUPABASE_URL,
  testSupabaseConnection,
  SupabaseConnectionStatus
} from '../lib/supabase';

interface SupabaseConnectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSyncLiveData?: () => void;
}

const SQL_MIGRATION_SCRIPT = `-- TrustVault: Supabase Database Schema, Security Policies & Hash Chain
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'owner', 'viewer');
    CREATE TYPE access_level AS ENUM ('read', 'edit');
    CREATE TYPE audit_status AS ENUM ('success', 'denied');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role user_role NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL CHECK (category IN ('Finance', 'HR', 'Legal', 'IT', 'Education', 'Personal')),
    file_path TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes <= 10485760),
    mime_type VARCHAR(100) NOT NULL,
    file_sha256 VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.document_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    permission_level access_level NOT NULL DEFAULT 'read',
    granted_by UUID NOT NULL REFERENCES public.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_doc_user_perm UNIQUE (document_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sequence_number BIGSERIAL NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    status audit_status NOT NULL DEFAULT 'success',
    ip_address VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL
);

-- Cryptographic Hash Chain Trigger Logic
CREATE OR REPLACE FUNCTION generate_audit_log_hash_chain()
RETURNS TRIGGER AS $$
DECLARE
    last_hash VARCHAR(64);
    canonical_payload TEXT;
    genesis_seed VARCHAR(64) := '0000000000000000000000000000000000000000000000000000000000000000';
BEGIN
    SELECT record_hash INTO last_hash
    FROM public.audit_logs
    ORDER BY sequence_number DESC
    LIMIT 1;

    NEW.previous_hash := COALESCE(last_hash, genesis_seed);

    canonical_payload := NEW.previous_hash || '|' ||
                         COALESCE(NEW.actor_email, 'ANONYMOUS') || '|' ||
                         NEW.action || '|' ||
                         NEW.resource_type || '|' ||
                         COALESCE(NEW.resource_id, 'NONE') || '|' ||
                         NEW.status::TEXT || '|' ||
                         to_char(NEW.timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' ||
                         NEW.ip_address || '|' ||
                         NEW.details::TEXT;

    NEW.record_hash := encode(digest(canonical_payload, 'sha256'), 'hex');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_hash_chain ON public.audit_logs;
CREATE TRIGGER trg_audit_log_hash_chain
BEFORE INSERT ON public.audit_logs
FOR EACH ROW EXECUTE FUNCTION generate_audit_log_hash_chain();

-- Immutability Guard
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'CRITICAL SECURITY VIOLATION: Audit logs are immutable and tamper-evident.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_modification ON public.audit_logs;
CREATE TRIGGER trg_prevent_audit_modification
BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();

-- Row Level Security
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users read own profile" ON public.users FOR SELECT USING (id = auth.uid());
CREATE POLICY "Owners read own documents" ON public.documents FOR SELECT USING (owner_id = auth.uid());
CREATE POLICY "Shared users read documents" ON public.documents FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.document_permissions WHERE document_id = public.documents.id AND user_id = auth.uid())
);
CREATE POLICY "Only admins read audit logs" ON public.audit_logs FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.users WHERE id = auth.uid() AND role = 'admin')
);`;

export const SupabaseConnectModal: React.FC<SupabaseConnectModalProps> = ({
  isOpen,
  onClose,
  onSyncLiveData,
}) => {
  const [testing, setTesting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState<SupabaseConnectionStatus | null>(null);

  useEffect(() => {
    if (isOpen) {
      handleTestConnection();
    }
  }, [isOpen]);

  const handleTestConnection = async () => {
    setTesting(true);
    try {
      const res = await testSupabaseConnection();
      setStatus(res);
    } finally {
      setTesting(false);
    }
  };

  const handleCopySql = async () => {
    try {
      await navigator.clipboard.writeText(SQL_MIGRATION_SCRIPT);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6 space-y-6 shadow-2xl relative glow-neon-sm">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#1e3f2b] pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-950/80 border border-[#00ff88]/40 flex items-center justify-center text-[#00ff88]">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-lg">Supabase Cloud Connection</h3>
              <p className="text-xs text-slate-400">PostgreSQL Database &bull; Auth &bull; Private Storage &bull; Hash Chain</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white text-lg px-2 py-1"
          >
            &times;
          </button>
        </div>

        {/* Live Diagnostics Card */}
        <div className="p-4 rounded-xl bg-[#0a1c12] border border-[#1e3f2b] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Connection Health Diagnostics</span>
            <button
              type="button"
              onClick={handleTestConnection}
              disabled={testing}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0f2518] hover:bg-[#153421] border border-[#1e3f2b] text-slate-200 text-xs font-medium transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-[#00ff88] ${testing ? 'animate-spin' : ''}`} />
              <span>{testing ? 'Testing...' : 'Test Connection'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs pt-1">
            {/* Status 1: Configured */}
            <div className="p-3 rounded-lg bg-[#05140b] border border-[#1e3f2b] space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Environment Config</span>
              <div className="flex items-center gap-2">
                {isSupabaseConfigured ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />
                    <span className="text-white font-semibold">Configured</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span className="text-amber-300 font-semibold">Demo Vault Mode</span>
                  </>
                )}
              </div>
            </div>

            {/* Status 2: Host Reachable */}
            <div className="p-3 rounded-lg bg-[#05140b] border border-[#1e3f2b] space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Host Reachability</span>
              <div className="flex items-center gap-2">
                {status?.isConnected ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />
                    <span className="text-white font-semibold">Online &amp; Active</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-slate-500" />
                    <span className="text-slate-400 font-semibold">{isSupabaseConfigured ? 'Host Unreachable' : 'Local Standby'}</span>
                  </>
                )}
              </div>
            </div>

            {/* Status 3: Tables & Storage */}
            <div className="p-3 rounded-lg bg-[#05140b] border border-[#1e3f2b] space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Schema &amp; Bucket</span>
              <div className="flex items-center gap-2">
                {status?.hasTables ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />
                    <span className="text-white font-semibold">Tables Verified</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-slate-500" />
                    <span className="text-slate-400 font-semibold">{isSupabaseConfigured ? 'Run Migration' : 'Schema Ready'}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Config URL display */}
          <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between pt-1 border-t border-[#1e3f2b]">
            <span>Project Endpoint:</span>
            <span className="text-emerald-400 truncate max-w-xs">{SUPABASE_URL || 'Not specified (using built-in secure vault)'}</span>
          </div>
        </div>

        {/* Step-by-Step Connection Instructions */}
        <div className="space-y-4">
          <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#00ff88]" />
            <span>How to Connect Your Supabase Project</span>
          </h4>

          <div className="space-y-3 text-xs text-slate-300">
            {/* Step 1 */}
            <div className="p-3.5 rounded-xl bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-3">
              <div className="w-6 h-6 rounded-full bg-[#00ff88]/20 text-[#00ff88] font-bold flex items-center justify-center shrink-0 text-xs">
                1
              </div>
              <div className="space-y-1">
                <strong className="text-white block">Add Credentials to .env</strong>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Go to your Supabase Project &rarr; <strong>Project Settings &rarr; API</strong>. In your project's <code className="text-[#00ff88]">.env</code> file, set:
                </p>
                <div className="p-2 rounded bg-[#05140b] font-mono text-[10px] text-emerald-300 border border-[#1e3f2b]">
                  <div>VITE_SUPABASE_URL="https://your-project.supabase.co"</div>
                  <div>VITE_SUPABASE_ANON_KEY="your-anon-public-api-key"</div>
                </div>
              </div>
            </div>

            {/* Step 2 */}
            <div className="p-3.5 rounded-xl bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-3">
              <div className="w-6 h-6 rounded-full bg-[#00ff88]/20 text-[#00ff88] font-bold flex items-center justify-center shrink-0 text-xs">
                2
              </div>
              <div className="space-y-2 flex-1">
                <div className="flex items-center justify-between">
                  <strong className="text-white block">Execute Database Migration (Tables, RLS &amp; Hash Chain)</strong>
                  <button
                    type="button"
                    onClick={handleCopySql}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-[11px] transition"
                  >
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied SQL!' : 'Copy SQL Script'}</span>
                  </button>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Open your Supabase dashboard &rarr; <strong>SQL Editor &rarr; New Query</strong>, paste the copied migration script, and click <strong>Run</strong>. This creates the PostgreSQL schema, row-level security policies, and the cryptographic hash-chain trigger.
                </p>
              </div>
            </div>

            {/* Step 3 */}
            <div className="p-3.5 rounded-xl bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-3">
              <div className="w-6 h-6 rounded-full bg-[#00ff88]/20 text-[#00ff88] font-bold flex items-center justify-center shrink-0 text-xs">
                3
              </div>
              <div className="space-y-1">
                <strong className="text-white block">Create Private Storage Bucket</strong>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Go to <strong>Storage &rarr; New Bucket</strong>. Name it <code className="text-[#00ff88]">trustvault_documents</code>, set it to <strong>Private</strong> (public downloads disabled), and set max file size to <strong>10 MB</strong>.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-[#1e3f2b]">
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <Shield className="w-3.5 h-3.5 text-[#00ff88]" />
            <span>Zero-Trust: Backend verifies all signed URLs and audit logs</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-slate-300 text-xs hover:text-white"
            >
              Close
            </button>
            {status?.isConnected && onSyncLiveData && (
              <button
                type="button"
                onClick={() => {
                  onSyncLiveData();
                  onClose();
                }}
                className="px-4 py-2 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs"
              >
                Sync Live Supabase Data
              </button>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
