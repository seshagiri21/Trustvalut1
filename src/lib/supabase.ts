/**
 * Supabase Client & Real-Time Service Integration for TrustVault
 */
import { createClient, SupabaseClient } from '@supabase/supabase-js';

// Helper to sanitize environment variables in case user pasted the variable name or quotes
function sanitizeUrl(raw?: string): string {
  if (!raw || typeof raw !== 'string') return '';
  let cleaned = raw.trim();
  if (cleaned.startsWith('VITE_SUPABASE_URL=')) {
    cleaned = cleaned.replace(/^VITE_SUPABASE_URL=/, '').trim();
  } else if (cleaned.startsWith('SUPABASE_URL=')) {
    cleaned = cleaned.replace(/^SUPABASE_URL=/, '').trim();
  }
  return cleaned.replace(/^['"]|['"]$/g, '').trim();
}

function sanitizeKey(raw?: string): string {
  if (!raw || typeof raw !== 'string') return '';
  let cleaned = raw.trim();
  if (cleaned.startsWith('VITE_SUPABASE_ANON_KEY=')) {
    cleaned = cleaned.replace(/^VITE_SUPABASE_ANON_KEY=/, '').trim();
  } else if (cleaned.startsWith('SUPABASE_ANON_KEY=')) {
    cleaned = cleaned.replace(/^SUPABASE_ANON_KEY=/, '').trim();
  }
  return cleaned.replace(/^['"]|['"]$/g, '').trim();
}

// Environment variables configured in .env / system secrets
export const SUPABASE_URL = sanitizeUrl(import.meta.env.VITE_SUPABASE_URL);
export const SUPABASE_ANON_KEY = sanitizeKey(import.meta.env.VITE_SUPABASE_ANON_KEY);

/**
 * Validates whether a string is a valid HTTP/HTTPS URL.
 */
export function isValidHttpUrl(urlString: string): boolean {
  if (!urlString || typeof urlString !== 'string') return false;
  const trimmed = urlString.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false;
  if (
    trimmed.includes('your-project-id') ||
    trimmed.includes('your-project') ||
    trimmed.includes('MY_APP_URL') ||
    trimmed.includes('MY_SUPABASE_URL') ||
    trimmed === 'https://' ||
    trimmed === 'http://'
  ) {
    return false;
  }
  try {
    const url = new URL(trimmed);
    return (url.protocol === 'http:' || url.protocol === 'https:') && Boolean(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Validates whether an anon key is not a placeholder.
 */
export function isValidKey(key: string): boolean {
  if (!key || typeof key !== 'string') return false;
  const trimmed = key.trim();
  if (
    trimmed.includes('your-anon-public-api-key') ||
    trimmed.includes('your-anon-key') ||
    trimmed.includes('MY_') ||
    trimmed.length < 10
  ) {
    return false;
  }
  return true;
}

export const isSupabaseConfigured = isValidHttpUrl(SUPABASE_URL) && isValidKey(SUPABASE_ANON_KEY);

/**
 * Safely instantiate Supabase client with zero risk of unhandled module-load errors.
 */
function createSafeSupabaseClient(url: string, key: string): SupabaseClient | null {
  if (!isValidHttpUrl(url) || !isValidKey(key)) {
    return null;
  }
  try {
    return createClient(url, key, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
    });
  } catch (err) {
    console.warn('Could not initialize Supabase client:', err);
    return null;
  }
}

// Global safe client instance
export const supabase: SupabaseClient | null = createSafeSupabaseClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export interface SupabaseConnectionStatus {
  isConfigured: boolean;
  isConnected: boolean;
  url: string;
  projectId?: string;
  hasTables: boolean;
  hasBucket: boolean;
  error?: string;
  details?: string;
}

/**
 * Validates connection to the Supabase backend and checks if tables exist.
 */
export async function testSupabaseConnection(customUrl?: string, customKey?: string): Promise<SupabaseConnectionStatus> {
  const targetUrl = sanitizeUrl(customUrl) || SUPABASE_URL;
  const targetKey = sanitizeKey(customKey) || SUPABASE_ANON_KEY;

  if (!isValidHttpUrl(targetUrl)) {
    return {
      isConfigured: false,
      isConnected: false,
      url: targetUrl || 'Not configured',
      hasTables: false,
      hasBucket: false,
      error: 'VITE_SUPABASE_URL in .env is not a valid HTTP/HTTPS URL. Format should be: https://[project-id].supabase.co',
    };
  }

  if (!isValidKey(targetKey)) {
    return {
      isConfigured: false,
      isConnected: false,
      url: targetUrl,
      hasTables: false,
      hasBucket: false,
      error: 'VITE_SUPABASE_ANON_KEY is missing or invalid.',
    };
  }

  let projectId = '';
  try {
    projectId = new URL(targetUrl).hostname.split('.')[0];
  } catch {
    projectId = '';
  }

  try {
    const client = customUrl && customKey
      ? createSafeSupabaseClient(targetUrl, targetKey)
      : (supabase || createSafeSupabaseClient(targetUrl, targetKey));

    if (!client) {
      return {
        isConfigured: false,
        isConnected: false,
        url: targetUrl,
        projectId,
        hasTables: false,
        hasBucket: false,
        error: 'Unable to instantiate Supabase client.',
      };
    }

    // 1. Verify host connectivity via auth settings
    const authCheck = await fetch(`${targetUrl}/auth/v1/settings`, {
      headers: { apikey: targetKey }
    }).then(r => r.ok).catch(() => false);

    // 2. Test database tables
    const { error: dbError } = await client
      .from('documents')
      .select('id', { count: 'exact', head: true })
      .limit(1);

    const hasTables = !dbError || !dbError.message?.toLowerCase().includes('does not exist');

    // 3. Test storage bucket
    let hasBucket = false;
    try {
      const { data: buckets } = await client.storage.listBuckets();
      hasBucket = Boolean(buckets?.some(b => b.name === 'trustvault_documents'));
    } catch {
      hasBucket = false;
    }

    const isConnected = authCheck || !dbError || hasTables;

    return {
      isConfigured: true,
      isConnected,
      url: targetUrl,
      projectId,
      hasTables,
      hasBucket,
      error: !hasTables ? 'Database tables (documents, audit_logs) not yet created. Run SQL migration in Supabase SQL editor.' : undefined,
      details: isConnected ? `Connected to Supabase project "${projectId}".` : 'Could not reach Supabase endpoint.'
    };
  } catch (err: any) {
    return {
      isConfigured: true,
      isConnected: false,
      url: targetUrl,
      projectId,
      hasTables: false,
      hasBucket: false,
      error: err?.message || 'Failed to connect to Supabase host',
    };
  }
}
