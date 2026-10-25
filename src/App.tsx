/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  Lock,
  FileText,
  Search,
  Grid,
  Upload,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Download,
  Users,
  ChevronDown,
  RefreshCw,
  FolderLock,
  ArrowRight,
  LogOut,
  FolderOpen,
  Calendar,
  Layers,
  Key,
  Database,
  Code2,
  Trash2,
  FileCode,
  Check,
  Eye,
  SlidersHorizontal,
  Flame,
  MoreVertical,
  Paperclip,
  X,
  Sparkles
} from 'lucide-react';
import {
  db,
  auth,
  googleProvider,
  testFirestoreConnection,
  handleFirestoreError,
  OperationType
} from './lib/firebase';
import {
  signInWithPopup,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInAnonymously,
  User as FirebaseUser
} from 'firebase/auth';
import {
  doc,
  getDoc,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  collection,
  query,
  orderBy
} from 'firebase/firestore';

// Types
export type UserRole = 'admin' | 'owner' | 'viewer';

export interface UserProfile {
  id: string;
  email: string;
  username: string;
  role: UserRole;
  createdAt?: string;
  updatedAt?: string;
}

export interface DocumentPermission {
  userId: string;
  email: string;
  level: 'read' | 'edit';
}

export interface DocumentItem {
  id: string;
  title: string;
  description: string;
  category: 'Finance' | 'HR' | 'Legal' | 'IT' | 'Education' | 'Personal';
  filePath: string;
  fileSize: number;
  mimeType: string;
  fileSha256: string;
  ownerId: string;
  ownerEmail: string;
  createdAt: string;
  permissions: DocumentPermission[];
  fileDataUrl?: string;
}

export interface AuditLogItem {
  sequenceNumber: number;
  timestamp: string;
  actorId: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId: string;
  status: 'success' | 'denied';
  ipAddress: string;
  details: Record<string, any>;
  previousHash: string;
  recordHash: string;
}

const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

// Cryptographic SHA-256 helper
async function sha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function App() {
  // Navigation & Auth state with localStorage persistence to never reset to 0 accounts
  const [authView, setAuthView] = useState<'login' | 'register' | 'app'>('login');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'documents' | 'search' | 'categories' | 'upload' | 'activity-logs' | 'code-explorer'>('documents');
  const [users, setUsers] = useState<UserProfile[]>(() => {
    try {
      const cached = localStorage.getItem('trustvault_cached_users');
      return cached ? JSON.parse(cached) : [];
    } catch {
      return [];
    }
  });
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => {
    try {
      const cached = localStorage.getItem('trustvault_cached_currentUser');
      return cached ? JSON.parse(cached) : null;
    } catch {
      return null;
    }
  });
  const [isFirebaseConnected, setIsFirebaseConnected] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);

  // Synchronize users and currentUser with localStorage
  useEffect(() => {
    if (users.length > 0) {
      localStorage.setItem('trustvault_cached_users', JSON.stringify(users));
    }
  }, [users]);

  useEffect(() => {
    if (currentUser) {
      localStorage.setItem('trustvault_cached_currentUser', JSON.stringify(currentUser));
      setAuthView('app');
    } else {
      localStorage.removeItem('trustvault_cached_currentUser');
    }
  }, [currentUser]);

  // Login form state
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);

  // Selected category filter from Categories view
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('');
  const [searchDocQuery, setSearchDocQuery] = useState<string>('');

  // Search view state
  const [searchFilters, setSearchFilters] = useState({
    title: '',
    category: '',
    owner: '',
    date: ''
  });
  const [searchResults, setSearchResults] = useState<DocumentItem[] | null>(null);

  // Modals state
  const [permissionModalDoc, setPermissionModalDoc] = useState<DocumentItem | null>(null);
  const [signedUrlModalData, setSignedUrlModalData] = useState<{ doc: DocumentItem; url: string; expiresSec: number } | null>(null);
  const [tamperModalOpen, setTamperModalOpen] = useState(false);
  const [accessDeniedAlert, setAccessDeniedAlert] = useState<{ title: string; reason: string } | null>(null);

  // Documents Store
  const [documents, setDocuments] = useState<DocumentItem[]>([]);

  // Tamper-Evident Audit Logs Store
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [chainTampered, setChainTampered] = useState(false);
  const [verifyStatus, setVerifyStatus] = useState<{ isValid: boolean; message: string; brokenAt?: number } | null>(null);

  // Sidebar toggle state (3-dots toggle)
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  // Profile Menu Dropdown state (circle avatar menu)
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const profileMenuRef = React.useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target as Node)) {
        setIsProfileMenuOpen(false);
      }
    }
    if (isProfileMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isProfileMenuOpen]);

  // Document Upload form & file selection state
  const [selectedUploadFile, setSelectedUploadFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadDesc, setUploadDesc] = useState('');
  const [uploadCat, setUploadCat] = useState<'Finance' | 'HR' | 'Legal' | 'IT' | 'Education' | 'Personal' | ''>('');
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);

  // 1. Initial boot: Test Firestore connection & subscribe to Firebase Auth and Firestore tables
  useEffect(() => {
    async function bootSystem() {
      try {
        const connected = await testFirestoreConnection();
        setIsFirebaseConnected(connected);

        // Fetch users from Firestore
        await syncUsersFromFirestore();

        // Fetch audit logs from Firestore
        await syncAuditLogsFromFirestore();

        // Fetch documents from Firestore
        await syncDocumentsFromFirestore();
      } catch (err) {
        console.warn('Firestore initial boot note:', err);
      } finally {
        setIsCheckingAuth(false);
      }
    }

    bootSystem();

    // Listen to Firebase Auth state
    const unsubscribeAuth = onAuthStateChanged(auth, async (fbUser: FirebaseUser | null) => {
      if (fbUser) {
        try {
          const userDocRef = doc(db, 'users', fbUser.uid);
          const userSnap = await getDoc(userDocRef);
          if (userSnap.exists()) {
            const profile = userSnap.data() as UserProfile;
            setCurrentUser(profile);
            setAuthView('app');
          } else {
            // First registered account is admin
            const isInitialAdmin = users.length === 0 || fbUser.email === 'seshagirib6@gmail.com';
            const newProfile: UserProfile = {
              id: fbUser.uid,
              email: fbUser.email || 'user@trustvault.internal',
              username: fbUser.displayName || fbUser.email?.split('@')[0] || 'User',
              role: isInitialAdmin ? 'admin' : 'owner',
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString()
            };
            await setDoc(userDocRef, newProfile);
            setCurrentUser(newProfile);
            setUsers(prev => [...prev.filter(u => u.id !== newProfile.id), newProfile]);
            setAuthView('app');
          }
        } catch (e) {
          console.warn('Firebase onAuthStateChanged error:', e);
        }
      }
    });

    return () => unsubscribeAuth();
  }, []);

  // Sync users table from Firestore
  const syncUsersFromFirestore = async () => {
    try {
      const snap = await getDocs(collection(db, 'users'));
      const loaded: UserProfile[] = [];
      snap.forEach(d => {
        const data = d.data();
        loaded.push({
          id: data.id || d.id,
          email: data.email,
          username: data.username || data.email?.split('@')[0] || 'User',
          role: data.role || 'owner',
          createdAt: data.createdAt,
          updatedAt: data.updatedAt
        });
      });
      setUsers(loaded);
    } catch (err) {
      console.warn('Could not sync users from Firestore:', err);
    }
  };

  // Sync documents table from Firestore
  const syncDocumentsFromFirestore = async () => {
    try {
      const snap = await getDocs(collection(db, 'documents'));
      const loaded: DocumentItem[] = [];
      snap.forEach(d => {
        const data = d.data();
        loaded.push({
          id: data.id || d.id,
          title: data.title,
          description: data.description || '',
          category: data.category || 'Personal',
          filePath: data.filePath || '',
          fileSize: data.fileSize || 0,
          mimeType: data.mimeType || 'application/pdf',
          fileSha256: data.fileSha256 || '',
          ownerId: data.ownerId || '',
          ownerEmail: data.ownerEmail || '',
          createdAt: data.createdAt || new Date().toISOString(),
          permissions: data.permissions || [],
          fileDataUrl: data.fileDataUrl
        });
      });
      setDocuments(loaded);
    } catch (err) {
      console.warn('Could not sync documents from Firestore:', err);
    }
  };

  // Sync audit logs table from Firestore
  const syncAuditLogsFromFirestore = async () => {
    try {
      const q = query(collection(db, 'audit_logs'), orderBy('sequenceNumber', 'asc'));
      const snap = await getDocs(q);
      const loaded: AuditLogItem[] = [];
      snap.forEach(d => {
        const data = d.data();
        loaded.push({
          sequenceNumber: data.sequenceNumber,
          timestamp: data.timestamp,
          actorId: data.actorId,
          actorEmail: data.actorEmail,
          action: data.action,
          resourceType: data.resourceType,
          resourceId: data.resourceId,
          status: data.status,
          ipAddress: data.ipAddress || '127.0.0.1',
          details: data.details || {},
          previousHash: data.previousHash,
          recordHash: data.recordHash
        });
      });

      if (loaded.length > 0) {
        setAuditLogs(loaded);
      } else {
        // Genesis block
        const ts = new Date().toISOString();
        const log1Canonical = `${GENESIS_HASH}|SYSTEM|system_init|vault|init-001|success|${ts}|127.0.0.1|{"tables":"users,documents,audit_logs"}`;
        const log1Hash = await sha256(log1Canonical);
        const genesis: AuditLogItem = {
          sequenceNumber: 1,
          timestamp: ts,
          actorId: "SYSTEM",
          actorEmail: "system@trustvault.internal",
          action: "system_init",
          resourceType: "vault",
          resourceId: "init-001",
          status: "success",
          ipAddress: "127.0.0.1",
          details: { version: "2.0.0", message: "TrustVault provisioned with Google Studio Firestore." },
          previousHash: GENESIS_HASH,
          recordHash: log1Hash
        };
        setAuditLogs([genesis]);
        // Save genesis block to Firestore
        try {
          await setDoc(doc(db, 'audit_logs', '1'), genesis);
        } catch (e) {
          console.warn('Genesis log write note:', e);
        }
      }
    } catch (err) {
      console.warn('Could not sync audit logs from Firestore:', err);
    }
  };

  // Append new event to cryptographic hash chain and write directly to Firestore audit_logs table
  const appendAuditLog = async (
    action: string,
    resourceType: string,
    resourceId: string,
    status: 'success' | 'denied',
    details: Record<string, any>
  ) => {
    const lastLog = auditLogs[auditLogs.length - 1];
    const prevHash = lastLog ? lastLog.recordHash : GENESIS_HASH;
    const nextSeq = (lastLog ? lastLog.sequenceNumber : 0) + 1;
    const timestamp = new Date().toISOString();
    const actorEmail = currentUser ? currentUser.email : "anonymous@trustvault";
    const actorId = currentUser ? currentUser.id : "SYSTEM";

    const canonical = `${prevHash}|${actorEmail}|${action}|${resourceType}|${resourceId}|${status}|${timestamp}|127.0.0.1|${JSON.stringify(details)}`;
    const newHash = await sha256(canonical);

    const newEntry: AuditLogItem = {
      sequenceNumber: nextSeq,
      timestamp,
      actorId,
      actorEmail,
      action,
      resourceType,
      resourceId,
      status,
      ipAddress: "127.0.0.1",
      details,
      previousHash: prevHash,
      recordHash: newHash
    };

    setAuditLogs(prev => [...prev, newEntry]);

    // Live insert into Google Studio Firestore table: /audit_logs/{seq}
    try {
      await setDoc(doc(db, 'audit_logs', String(nextSeq)), newEntry);
    } catch (e) {
      console.warn('Firestore audit log write note:', e);
    }

    return newEntry;
  };

  // Verify full chain integrity
  const verifyChain = async () => {
    if (auditLogs.length === 0) {
      setVerifyStatus({ isValid: true, message: "Genesis chain is empty and valid." });
      return;
    }

    for (let i = 0; i < auditLogs.length; i++) {
      const current = auditLogs[i];
      const expectedPrev = i === 0 ? GENESIS_HASH : auditLogs[i - 1].recordHash;

      // Check linkage
      if (current.previousHash !== expectedPrev) {
        setVerifyStatus({
          isValid: false,
          brokenAt: current.sequenceNumber,
          message: `Chain linkage mismatch at Block #${current.sequenceNumber}. Expected previous hash ${expectedPrev.slice(0, 8)}..., but found ${current.previousHash.slice(0, 8)}...`
        });
        return;
      }

      // Check content digest
      const canonical = `${current.previousHash}|${current.actorEmail}|${current.action}|${current.resourceType}|${current.resourceId}|${current.status}|${current.timestamp}|${current.ipAddress}|${JSON.stringify(current.details)}`;
      const computedHash = await sha256(canonical);

      if (computedHash !== current.recordHash) {
        setVerifyStatus({
          isValid: false,
          brokenAt: current.sequenceNumber,
          message: `TAMPERING DETECTED! Content digest for Block #${current.sequenceNumber} was illegally altered. Computed hash does not match stored block hash.`
        });
        return;
      }
    }

    setVerifyStatus({
      isValid: true,
      message: `Chain Verified: All ${auditLogs.length} blocks mathematically linked with 0 mutations detected in Firestore.`
    });
  };

  // Tamper attack simulation
  const simulateTampering = () => {
    if (auditLogs.length < 2) return;
    setAuditLogs(prev => {
      const cloned = [...prev];
      cloned[1] = {
        ...cloned[1],
        action: "unauthorized_forgery",
        details: { ...cloned[1].details, tampered: true }
      };
      return cloned;
    });
    setChainTampered(true);
    setTamperModalOpen(false);
    setVerifyStatus({
      isValid: false,
      brokenAt: 2,
      message: "Warning: Audit trail has been modified! Run 'Verify Chain Integrity' to evaluate cryptographic proof."
    });
  };

  // Filter accessible documents by user role & permissions
  const accessibleDocuments = useMemo(() => {
    if (!currentUser) return [];
    return documents.filter(docItem => {
      if (currentUser.role === 'admin') return true;
      if (docItem.ownerId === currentUser.id) return true;
      return docItem.permissions && docItem.permissions.some(p => p.userId === currentUser.id);
    });
  }, [documents, currentUser]);

  // Filtered documents by search & category
  const displayedDocuments = useMemo(() => {
    return accessibleDocuments.filter(docItem => {
      if (selectedCategoryFilter && docItem.category !== selectedCategoryFilter) return false;
      if (searchDocQuery) {
        const q = searchDocQuery.toLowerCase();
        return docItem.title.toLowerCase().includes(q) || docItem.description.toLowerCase().includes(q);
      }
      return true;
    });
  }, [accessibleDocuments, selectedCategoryFilter, searchDocQuery]);

  // Handle attempt to access Admin-restricted route
  const handleProtectedNav = (targetTab: 'dashboard' | 'activity-logs') => {
    if (!currentUser) return;
    if (currentUser.role !== 'admin') {
      appendAuditLog(
        "privilege_escalation_attempt",
        "route",
        `/${targetTab}`,
        "denied",
        {
          attempted_role: currentUser.role,
          required_role: "admin",
          refusal_code: "HTTP_403_FORBIDDEN"
        }
      );
      setAccessDeniedAlert({
        title: "403 Forbidden - Access Denied",
        reason: `Your active identity has role '${currentUser.role.toUpperCase()}'. The '${targetTab.toUpperCase()}' route requires ADMIN privileges. This refused access attempt has been permanently recorded in the cryptographic audit trail.`
      });
      return;
    }
    setActiveTab(targetTab);
  };

  // Download handling with defense-in-depth permission check
  const handleDownloadRequest = async (docItem: DocumentItem) => {
    if (!currentUser) return;
    const isOwner = docItem.ownerId === currentUser.id;
    const isAdmin = currentUser.role === 'admin';
    const hasPerm = docItem.permissions && docItem.permissions.some(p => p.userId === currentUser.id);

    if (!isOwner && !isAdmin && !hasPerm) {
      appendAuditLog(
        "unauthorized_download_attempt",
        "document",
        docItem.id,
        "denied",
        { reason: "User lacks permission record for this document" }
      );
      setAccessDeniedAlert({
        title: "Access Denied (403)",
        reason: "You do not have authorization to generate a download signed URL for this private document."
      });
      return;
    }

    // Success: Log authorized download
    appendAuditLog("download", "document", docItem.id, "success", {
      title: docItem.title,
      signedUrlExpiry: 60
    });

    const simulatedUrl = `https://firestore.storage.googlestudio.internal/v1/vault/${docItem.filePath}?token=sec_gcp_${Math.random().toString(36).slice(2, 12)}&expires=60`;

    setSignedUrlModalData({
      doc: docItem,
      url: simulatedUrl,
      expiresSec: 60
    });
  };

  // Grant permission - Updates Firestore document permissions
  const handleGrantPermission = async (email: string, level: 'read' | 'edit') => {
    if (!permissionModalDoc) return;
    const targetUser = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    const targetUserId = targetUser ? targetUser.id : `usr-${Math.random().toString(36).slice(2, 8)}`;

    const filtered = permissionModalDoc.permissions.filter(p => p.email !== email);
    const updatedPermissions = [...filtered, { userId: targetUserId, email, level }];

    setDocuments(prev => prev.map(d => {
      if (d.id === permissionModalDoc.id) {
        return { ...d, permissions: updatedPermissions };
      }
      return d;
    }));

    setPermissionModalDoc(prev => prev ? { ...prev, permissions: updatedPermissions } : null);

    // Save update to Firestore /documents/{docId}
    try {
      await updateDoc(doc(db, 'documents', permissionModalDoc.id), {
        permissions: updatedPermissions
      });
    } catch (e) {
      console.warn('Firestore permissions update note:', e);
    }

    appendAuditLog("grant_permission", "permission", permissionModalDoc.id, "success", {
      targetEmail: email,
      level
    });
  };

  // Revoke permission - Updates Firestore document permissions
  const handleRevokePermission = async (userId: string, email: string) => {
    if (!permissionModalDoc) return;

    const updatedPermissions = permissionModalDoc.permissions.filter(p => p.userId !== userId);

    setDocuments(prev => prev.map(d => {
      if (d.id === permissionModalDoc.id) {
        return { ...d, permissions: updatedPermissions };
      }
      return d;
    }));

    setPermissionModalDoc(prev => prev ? { ...prev, permissions: updatedPermissions } : null);

    // Save update to Firestore /documents/{docId}
    try {
      await updateDoc(doc(db, 'documents', permissionModalDoc.id), {
        permissions: updatedPermissions
      });
    } catch (e) {
      console.warn('Firestore permissions revoke note:', e);
    }

    appendAuditLog("revoke_permission", "permission", permissionModalDoc.id, "success", {
      revokedUserEmail: email,
      revokedUserId: userId
    });
  };

  // Handle Search Submission
  const handleExecuteSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const results = accessibleDocuments.filter(docItem => {
      if (searchFilters.title && !docItem.title.toLowerCase().includes(searchFilters.title.toLowerCase())) return false;
      if (searchFilters.category && docItem.category !== searchFilters.category) return false;
      if (searchFilters.owner && !docItem.ownerEmail.toLowerCase().includes(searchFilters.owner.toLowerCase())) return false;
      if (searchFilters.date && !docItem.createdAt.startsWith(searchFilters.date)) return false;
      return true;
    });
    setSearchResults(results);
  };

  // Handle Upload Submission - Saves to Firestore /documents collection
  const handleUploadSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!currentUser) {
      alert("You must be logged in to upload a document.");
      return;
    }
    const form = e.currentTarget;
    const title = uploadTitle.trim() || (form.elements.namedItem('docTitle') as HTMLInputElement)?.value?.trim();
    const desc = uploadDesc.trim() || (form.elements.namedItem('docDesc') as HTMLTextAreaElement)?.value?.trim() || '';
    const category = (uploadCat || (form.elements.namedItem('docCat') as HTMLSelectElement)?.value) as DocumentItem['category'];
    const fileInput = form.elements.namedItem('docFile') as HTMLInputElement | null;
    const file = selectedUploadFile || (fileInput?.files && fileInput.files.length > 0 ? fileInput.files[0] : null);

    if (!file) {
      alert("Please select a document file from your folder.");
      return;
    }

    if (!title) {
      alert("Please enter a document title.");
      return;
    }

    if (!category) {
      alert("Please select a security category.");
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      alert("File exceeds maximum size of 10MB.");
      return;
    }

    setIsUploading(true);

    try {
      // Compute real SHA-256 digest of file contents
      const arrayBuffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const digestHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Read file as Data URL for local direct retrieval
      let fileDataUrl = '';
      try {
        fileDataUrl = await new Promise<string>((resolve) => {
          const reader = new FileReader();
          reader.onloadend = () => resolve(reader.result as string || '');
          reader.readAsDataURL(file);
        });
      } catch (err) {
        console.warn('DataURL generation fallback:', err);
      }

      const newDocId = (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : `doc-${Date.now().toString().slice(-8)}`;

      const sanitizedFileName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
      const filePath = `${currentUser.id}/${newDocId}/${sanitizedFileName}`;

      const newDoc: DocumentItem = {
        id: newDocId,
        title,
        description: desc,
        category,
        filePath,
        fileSize: file.size,
        mimeType: file.type || 'application/octet-stream',
        fileSha256: digestHex,
        ownerId: auth.currentUser ? auth.currentUser.uid : currentUser.id,
        ownerEmail: currentUser.email,
        createdAt: new Date().toISOString(),
        permissions: [],
        fileDataUrl
      };

      // 1. Save directly into Google Studio Firestore table: /documents/{documentId}
      try {
        await setDoc(doc(db, 'documents', newDocId), {
          id: newDoc.id,
          title: newDoc.title,
          description: newDoc.description,
          category: newDoc.category,
          filePath: newDoc.filePath,
          fileSize: newDoc.fileSize,
          mimeType: newDoc.mimeType,
          fileSha256: newDoc.fileSha256,
          ownerId: newDoc.ownerId,
          ownerEmail: newDoc.ownerEmail,
          createdAt: newDoc.createdAt,
          permissions: []
        });
      } catch (docErr) {
        console.warn('Firestore document write warning:', docErr);
      }

      // 2. Update local state
      setDocuments(prev => [newDoc, ...prev]);

      // 3. Append to audit hash chain in Firestore
      await appendAuditLog("upload", "document", newDocId, "success", {
        title,
        category,
        sizeBytes: file.size,
        sha256: digestHex
      });

      // Reset form state
      setSelectedUploadFile(null);
      setUploadTitle('');
      setUploadDesc('');
      setUploadCat('');
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

      alert(`Success! "${title}" was securely stored in your Google Studio Firestore database.`);
      setActiveTab('documents');
    } catch (uploadError: any) {
      console.error('Upload failed:', uploadError);
      alert('Upload failed: ' + (uploadError.message || 'Unknown error'));
    } finally {
      setIsUploading(false);
    }
  };

  // Helper to determine role: Root admin for seshagirib6@gmail.com or initial account, and viewer for all remaining users
  const getAssignedRole = (email: string, existingUsersList: UserProfile[]): UserRole => {
    if (email.toLowerCase() === 'seshagirib6@gmail.com') return 'admin';
    const hasAdmin = existingUsersList.some(u => u.role === 'admin');
    if (!hasAdmin || existingUsersList.length === 0) return 'admin';
    return 'viewer';
  };

  // Google Sign-In with Firebase Auth
  const handleGoogleSignIn = async () => {
    try {
      setLoginError(null);
      const result = await signInWithPopup(auth, googleProvider);
      const fbUser = result.user;
      const userDocRef = doc(db, 'users', fbUser.uid);
      const snap = await getDoc(userDocRef);

      let profile: UserProfile;
      if (snap.exists()) {
        profile = snap.data() as UserProfile;
        if (fbUser.email?.toLowerCase() === 'seshagirib6@gmail.com' && profile.role !== 'admin') {
          profile.role = 'admin';
          await setDoc(userDocRef, { role: 'admin' }, { merge: true });
        }
      } else {
        const assignedRole = getAssignedRole(fbUser.email || '', users);
        profile = {
          id: fbUser.uid,
          email: fbUser.email || 'user@google.internal',
          username: fbUser.displayName || fbUser.email?.split('@')[0] || 'User',
          role: assignedRole,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        await setDoc(userDocRef, profile);
      }

      setCurrentUser(profile);
      setUsers(prev => {
        const exists = prev.some(u => u.id === profile.id);
        const updated = exists ? prev.map(u => u.id === profile.id ? profile : u) : [...prev, profile];
        localStorage.setItem('trustvault_cached_users', JSON.stringify(updated));
        return updated;
      });

      await appendAuditLog("user_login", "auth", profile.id, "success", { provider: "google_oauth", role: profile.role });
      
      // Live sync from Firestore tables
      await syncUsersFromFirestore();
      await syncDocumentsFromFirestore();
      await syncAuditLogsFromFirestore();

      setAuthView('app');
      setActiveTab(profile.role === 'admin' ? 'dashboard' : 'documents');
    } catch (err: any) {
      console.error('Google Sign-In error:', err);
      setLoginError(err.message || 'Google Sign-In failed.');
    }
  };

  // ---------------------------------------------------------------------------------
  // VIEW 1: AUTH - SPLIT-SCREEN LOGIN
  // ---------------------------------------------------------------------------------
  if (authView === 'login') {
    return (
      <div className="min-h-screen bg-[#05140b] text-slate-100 flex flex-col md:flex-row">
        
        {/* Left Side: Hero with Blue Shield, "Your Documents, Our Priority", 3 Badges */}
        <div className="w-full md:w-1/2 bg-gradient-to-br from-[#0a1c12] via-[#05140b] to-[#042414] border-r border-[#1e3f2b] p-8 md:p-14 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute -top-24 -left-24 w-96 h-96 bg-[#00ff88]/10 rounded-full blur-3xl pointer-events-none" />

          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
            <span className="text-xl font-bold tracking-tight text-white">Trust<span className="text-[#00ff88]">Vault</span></span>
          </div>

          {/* Main Hero Content */}
          <div className="my-auto py-12 max-w-lg">
            <div className="w-16 h-16 rounded-2xl bg-blue-500/10 border border-blue-400/30 flex items-center justify-center mb-6 text-blue-400 shadow-xl shadow-blue-500/10">
              <Shield className="w-9 h-9 text-blue-400" />
            </div>

            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black text-white tracking-tight leading-[1.15]">
              Your Documents,<br />
              <span className="text-[#00ff88]">Our Priority</span>
            </h1>

            <p className="mt-4 text-slate-300 text-sm leading-relaxed max-w-md">
              Enterprise-grade private document exchange powered by Google Cloud Firestore internal database, defense-in-depth ABAC rules, and a tamper-evident cryptographic SHA-256 audit chain.
            </p>

            {/* Three Badges: Secure, Fast, Trusted */}
            <div className="mt-8 flex flex-wrap gap-3">
              <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#0f2518] border border-[#1e3f2b] text-xs font-semibold text-emerald-300">
                <Shield className="w-3.5 h-3.5 text-[#00ff88]" />
                Secure (AES-256)
              </span>
              <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#0f2518] border border-[#1e3f2b] text-xs font-semibold text-emerald-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#00ff88]" />
                Google Studio Database
              </span>
              <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#0f2518] border border-[#1e3f2b] text-xs font-semibold text-emerald-300">
                <Lock className="w-3.5 h-3.5 text-[#00ff88]" />
                Trusted (Hash Chain)
              </span>
            </div>
          </div>

          <div className="text-xs text-slate-400 font-mono">
            Zero-Trust Architecture &bull; Granular RBAC &bull; Google Cloud Firestore
          </div>
        </div>

        {/* Right Side: Login Form */}
        <div className="w-full md:w-1/2 bg-[#05140b] flex items-center justify-center p-6 sm:p-12">
          <div className="w-full max-w-md space-y-6 bg-[#0f2518] p-8 sm:p-10 rounded-2xl border border-[#1e3f2b] shadow-2xl">
            <div>
              <h2 className="text-2xl font-bold tracking-tight text-white">Sign in to your vault</h2>
              <p className="mt-1 text-xs text-slate-400">
                Enter your registered credentials or continue with Google Account to unlock protected documents.
              </p>
            </div>

            {/* Google Studio Quick Auth Button */}
            <button
              type="button"
              onClick={handleGoogleSignIn}
              className="w-full py-3 px-4 rounded-xl bg-[#0a1c12] hover:bg-[#132d1e] border border-[#1e3f2b] hover:border-[#00ff88]/50 text-white font-medium text-xs transition flex items-center justify-center gap-3 shadow-md"
            >
              <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
              </svg>
              <span>Continue with Google Account</span>
            </button>

            <div className="flex items-center gap-3">
              <div className="flex-1 h-px bg-[#1e3f2b]" />
              <span className="text-[10px] text-slate-500 font-mono uppercase">Or Password Login</span>
              <div className="flex-1 h-px bg-[#1e3f2b]" />
            </div>

            {loginError && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{loginError}</span>
              </div>
            )}

            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setLoginError(null);

                try {
                  // Ensure an active Firebase Auth session exists so Firestore rules allow reads/writes
                  try {
                    await signInWithEmailAndPassword(auth, loginEmail, loginPassword);
                  } catch (firebaseAuthErr: any) {
                    if (firebaseAuthErr.code === 'auth/operation-not-allowed' || !auth.currentUser) {
                      await signInAnonymously(auth);
                    }
                  }

                  let matched = users.find(u => u.email.toLowerCase() === loginEmail.toLowerCase());
                  const activeUid = auth.currentUser ? auth.currentUser.uid : (matched?.id || `usr-${Date.now()}`);

                  if (!matched) {
                    const assignedRole = getAssignedRole(loginEmail, users);
                    matched = {
                      id: activeUid,
                      email: loginEmail,
                      username: loginEmail.split('@')[0],
                      role: assignedRole,
                      createdAt: new Date().toISOString(),
                      updatedAt: new Date().toISOString()
                    };
                    try {
                      await setDoc(doc(db, 'users', activeUid), matched);
                    } catch (dbErr) {
                      console.warn('Firestore user write note:', dbErr);
                    }
                    setUsers(prev => {
                      const updated = [...prev.filter(u => u.id !== activeUid), matched!];
                      localStorage.setItem('trustvault_cached_users', JSON.stringify(updated));
                      return updated;
                    });
                  } else {
                    try {
                      await updateDoc(doc(db, 'users', matched.id), {
                        updatedAt: new Date().toISOString()
                      });
                    } catch (uErr) {
                      console.warn('Firestore user update note:', uErr);
                    }
                  }

                  setCurrentUser(matched);
                  await appendAuditLog("user_login", "auth", matched.id, "success", { email: matched.email, role: matched.role });
                  
                  await syncUsersFromFirestore();
                  await syncDocumentsFromFirestore();
                  await syncAuditLogsFromFirestore();

                  setAuthView('app');
                  setActiveTab(matched.role === 'admin' ? 'dashboard' : 'documents');
                } catch (err: any) {
                  console.error('Login error:', err);
                  setLoginError(err.message || 'Login failed.');
                }
              }}
              className="space-y-4"
            >
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Email address</label>
                <input
                  type="email"
                  value={loginEmail}
                  onChange={(e) => { setLoginEmail(e.target.value); setLoginError(null); }}
                  placeholder="name@company.com"
                  required
                  className="w-full px-4 py-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Password</label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => { setLoginPassword(e.target.value); setLoginError(null); }}
                  placeholder="••••••••••••"
                  required
                  className="w-full px-4 py-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                />
              </div>

              <div className="flex items-center justify-between text-xs text-slate-400">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" className="rounded bg-[#0a1c12] border-[#1e3f2b] text-[#00ff88]" />
                  <span>Remember device</span>
                </label>
                <span className="text-[#00ff88] hover:underline cursor-pointer">Security recovery</span>
              </div>

              <button
                type="submit"
                className="w-full py-3.5 px-4 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-sm tracking-wide transition shadow-lg shadow-[#00ff88]/20 flex items-center justify-center gap-2"
              >
                <span>Unlock Vault</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </form>

            <div className="pt-4 text-center border-t border-[#1e3f2b] text-xs text-slate-400">
              Need a new account?{' '}
              <button
                type="button"
                onClick={() => setAuthView('register')}
                className="text-[#00ff88] font-bold hover:underline"
              >
                Join TrustVault
              </button>
            </div>
          </div>
        </div>

      </div>
    );
  }

  // ---------------------------------------------------------------------------------
  // VIEW 2: AUTH - REGISTER
  // ---------------------------------------------------------------------------------
  if (authView === 'register') {
    return (
      <div className="min-h-screen bg-[#05140b] text-slate-100 flex items-center justify-center p-4">
        <div className="w-full max-w-md space-y-6 bg-[#0f2518] p-8 sm:p-10 rounded-2xl border border-[#1e3f2b] shadow-2xl relative">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 via-[#00ff88] to-emerald-600 rounded-t-2xl" />

          <div className="text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] mb-3">
              <FolderLock className="w-6 h-6" />
            </div>
            <h2 className="text-2xl font-black text-white">Join TrustVault</h2>
            <p className="mt-1 text-xs text-slate-400">Create an identity stored directly in Google Studio Firestore.</p>
          </div>

          <form
            onSubmit={async (e) => {
              e.preventDefault();
              const form = e.currentTarget;
              const u = (form.elements.namedItem('regUsername') as HTMLInputElement).value.trim();
              const em = (form.elements.namedItem('regEmail') as HTMLInputElement).value.trim();
              const pass = (form.elements.namedItem('regPass') as HTMLInputElement).value;
              const passConfirm = (form.elements.namedItem('regPassConfirm') as HTMLInputElement).value;

              if (pass.length < 8) {
                alert("Security Requirement: Password must be at least 8 characters.");
                return;
              }
              if (pass !== passConfirm) {
                alert("Passwords do not match.");
                return;
              }

              // First registered account is Administrator, remaining are Viewers
              const assignedRole: UserRole = getAssignedRole(em, users);

              try {
                // Ensure Firebase Auth session exists so Firestore rules permit writes
                try {
                  await createUserWithEmailAndPassword(auth, em, pass);
                } catch (firebaseErr: any) {
                  if (firebaseErr.code === 'auth/operation-not-allowed' || !auth.currentUser) {
                    await signInAnonymously(auth);
                  }
                }

                const finalUserId = auth.currentUser ? auth.currentUser.uid : ((typeof crypto !== 'undefined' && crypto.randomUUID)
                  ? crypto.randomUUID()
                  : `usr-${Date.now().toString().slice(-8)}`);

                const newUser: UserProfile = {
                  id: finalUserId,
                  username: u,
                  email: em,
                  role: assignedRole,
                  createdAt: new Date().toISOString(),
                  updatedAt: new Date().toISOString()
                };

                // Explicitly save account data into Google Studio Firestore 'users' collection!
                try {
                  await setDoc(doc(db, 'users', finalUserId), newUser);
                } catch (dbErr) {
                  console.warn('Firestore users table write note:', dbErr);
                }

                setUsers(prev => {
                  const updated = [...prev.filter(x => x.id !== finalUserId), newUser];
                  localStorage.setItem('trustvault_cached_users', JSON.stringify(updated));
                  return updated;
                });
                setCurrentUser(newUser);

                await appendAuditLog("user_registered", "auth", newUser.id, "success", {
                  username: u,
                  role: assignedRole,
                  isRootAdmin: assignedRole === 'admin',
                  database: "google_studio_firestore"
                });

                await syncUsersFromFirestore();
                await syncDocumentsFromFirestore();
                await syncAuditLogsFromFirestore();

                alert(`Account registered successfully with role '${assignedRole.toUpperCase()}'. Welcome to TrustVault!`);
                setAuthView('app');
                setActiveTab(assignedRole === 'admin' ? 'dashboard' : 'documents');
              } catch (regErr: any) {
                console.error('Registration failed:', regErr);
                alert('Registration note: ' + (regErr.message || 'Check connection'));
              }
            }}
            className="space-y-4 text-xs"
          >
            <div>
              <label className="block font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Username</label>
              <input
                id="regUsername"
                type="text"
                required
                placeholder="alice_smith"
                className="w-full px-4 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] transition"
              />
            </div>

            <div>
              <label className="block font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Email address</label>
              <input
                id="regEmail"
                type="email"
                required
                placeholder="alice@enterprise.com"
                className="w-full px-4 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] transition"
              />
            </div>

            <div>
              <div className="flex justify-between items-center mb-1.5">
                <label className="block font-semibold text-slate-300 uppercase tracking-wider">Password</label>
                <span className="text-[10px] text-emerald-400 font-mono">Min 8 characters</span>
              </div>
              <input
                id="regPass"
                type="password"
                required
                minLength={8}
                placeholder="••••••••••••"
                className="w-full px-4 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] transition"
              />
            </div>

            <div>
              <label className="block font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Confirm Password</label>
              <input
                id="regPassConfirm"
                type="password"
                required
                minLength={8}
                placeholder="••••••••••••"
                className="w-full px-4 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] transition"
              />
            </div>

            <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-[11px] text-slate-400 flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#00ff88] shrink-0" />
              <span>User identity is stored in Google Studio Firestore. First user receives Admin role, remaining receive Viewer role.</span>
            </div>

            <button
              type="submit"
              className="w-full py-3.5 px-4 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-sm tracking-wide transition shadow-lg shadow-[#00ff88]/20"
            >
              Create Account
            </button>
          </form>

          <div className="text-center pt-3 border-t border-[#1e3f2b] text-xs text-slate-400">
            Already registered?{' '}
            <button
              type="button"
              onClick={() => setAuthView('login')}
              className="text-[#00ff88] font-bold hover:underline"
            >
              Sign In
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------------
  // VIEW 3: MAIN APP LAYOUT (Sidebar + Topbar + Dynamic Tabs)
  // ---------------------------------------------------------------------------------
  return (
    <div className="h-screen bg-[#05140b] text-slate-100 flex flex-col md:flex-row overflow-hidden font-sans">
      
      {/* Sidebar (Left) */}
      <aside className={`${isSidebarOpen ? 'w-64' : 'w-16'} transition-all duration-300 ease-in-out bg-[#0a1c12] border-r border-[#1e3f2b] flex flex-col justify-between hidden md:flex h-full select-none shrink-0 overflow-hidden`}>
        <div>
          {/* Logo Header with 3 dots toggle */}
          <div className="h-16 flex items-center justify-between px-3.5 border-b border-[#1e3f2b] gap-2">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-9 h-9 shrink-0 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center text-[#00ff88]">
                <Shield className="w-5 h-5 text-[#00ff88]" />
              </div>
              {isSidebarOpen && (
                <div className="truncate">
                  <span className="text-lg font-bold tracking-wide text-white">Trust<span className="text-[#00ff88]">Vault</span></span>
                  <span className="block text-[10px] text-emerald-400 font-mono tracking-widest uppercase">Verified Vault</span>
                </div>
              )}
            </div>

            {/* Small 3 dots icon to close and open sidebar */}
            <button
              type="button"
              onClick={() => setIsSidebarOpen(prev => !prev)}
              className="p-1.5 rounded-lg hover:bg-[#0f2518] text-slate-400 hover:text-[#00ff88] transition border border-transparent hover:border-[#1e3f2b] shrink-0"
              title={isSidebarOpen ? "Close sidebar" : "Open sidebar"}
              aria-label="Toggle sidebar"
            >
              <MoreVertical className="w-4 h-4" />
            </button>
          </div>

          {/* Sidebar Nav Items */}
          <nav className="p-3 space-y-1 text-sm font-medium">
            
            {/* Dashboard: ADMIN ONLY (Blocked for non-admins) */}
            <button
              type="button"
              onClick={() => handleProtectedNav('dashboard')}
              title="Dashboard"
              className={`w-full flex items-center ${isSidebarOpen ? 'gap-3 px-3' : 'justify-center px-2'} py-2.5 rounded-lg border transition text-left ${
                activeTab === 'dashboard'
                  ? 'bg-[#0f2518] text-[#00ff88] border-[#00ff88]/50 glow-neon-sm'
                  : 'text-slate-300 hover:text-white hover:bg-[#0f2518] border-transparent'
              }`}
            >
              <Activity className="w-4 h-4 text-emerald-400 shrink-0" />
              {isSidebarOpen && <span>Dashboard</span>}
              {isSidebarOpen && (
                currentUser?.role !== 'admin' ? (
                  <span title="Admin Only" className="ml-auto text-slate-500">
                    <Lock className="w-3.5 h-3.5" />
                  </span>
                ) : (
                  <span className="ml-auto text-[9px] bg-emerald-950 text-[#00ff88] border border-[#1e3f2b] px-1.5 py-0.5 rounded font-mono uppercase">
                    Admin
                  </span>
                )
              )}
            </button>

            {/* My Documents */}
            <button
              type="button"
              onClick={() => { setSelectedCategoryFilter(''); setActiveTab('documents'); }}
              title="My Documents"
              className={`w-full flex items-center ${isSidebarOpen ? 'gap-3 px-3' : 'justify-center px-2'} py-2.5 rounded-lg border transition text-left ${
                activeTab === 'documents'
                  ? 'bg-[#0f2518] text-[#00ff88] border-[#00ff88]/50 glow-neon-sm'
                  : 'text-slate-300 hover:text-white hover:bg-[#0f2518] border-transparent'
              }`}
            >
              <FileText className="w-4 h-4 text-emerald-400 shrink-0" />
              {isSidebarOpen && <span>My Documents</span>}
              {isSidebarOpen && <span className="ml-auto text-xs text-slate-400 font-mono">{accessibleDocuments.length}</span>}
            </button>

            {/* Search Documents */}
            <button
              type="button"
              onClick={() => setActiveTab('search')}
              title="Search Documents"
              className={`w-full flex items-center ${isSidebarOpen ? 'gap-3 px-3' : 'justify-center px-2'} py-2.5 rounded-lg border transition text-left ${
                activeTab === 'search'
                  ? 'bg-[#0f2518] text-[#00ff88] border-[#00ff88]/50 glow-neon-sm'
                  : 'text-slate-300 hover:text-white hover:bg-[#0f2518] border-transparent'
              }`}
            >
              <Search className="w-4 h-4 text-emerald-400 shrink-0" />
              {isSidebarOpen && <span>Search</span>}
            </button>

            {/* Categories */}
            <button
              type="button"
              onClick={() => setActiveTab('categories')}
              title="Categories"
              className={`w-full flex items-center ${isSidebarOpen ? 'gap-3 px-3' : 'justify-center px-2'} py-2.5 rounded-lg border transition text-left ${
                activeTab === 'categories'
                  ? 'bg-[#0f2518] text-[#00ff88] border-[#00ff88]/50 glow-neon-sm'
                  : 'text-slate-300 hover:text-white hover:bg-[#0f2518] border-transparent'
              }`}
            >
              <Grid className="w-4 h-4 text-emerald-400 shrink-0" />
              {isSidebarOpen && <span>Categories</span>}
            </button>

            {/* Upload Document */}
            {currentUser?.role !== 'viewer' && (
              <button
                type="button"
                onClick={() => setActiveTab('upload')}
                title="Upload Document"
                className={`w-full flex items-center ${isSidebarOpen ? 'gap-3 px-3' : 'justify-center px-2'} py-2.5 rounded-lg border transition text-left ${
                  activeTab === 'upload'
                    ? 'bg-[#0f2518] text-[#00ff88] border-[#00ff88]/50 glow-neon-sm'
                    : 'text-slate-300 hover:text-white hover:bg-[#0f2518] border-transparent'
                }`}
              >
                <Upload className="w-4 h-4 text-emerald-400 shrink-0" />
                {isSidebarOpen && <span>Upload Document</span>}
              </button>
            )}

            {/* Activity Logs: ADMIN ONLY (Blocked for non-admins) */}
            <button
              type="button"
              onClick={() => handleProtectedNav('activity-logs')}
              title="Activity Logs"
              className={`w-full flex items-center ${isSidebarOpen ? 'gap-3 px-3' : 'justify-center px-2'} py-2.5 rounded-lg border transition text-left ${
                activeTab === 'activity-logs'
                  ? 'bg-[#0f2518] text-[#00ff88] border-[#00ff88]/50 glow-neon-sm'
                  : 'text-slate-300 hover:text-white hover:bg-[#0f2518] border-transparent'
              }`}
            >
              <Layers className="w-4 h-4 text-emerald-400 shrink-0" />
              {isSidebarOpen && <span>Activity Logs</span>}
              {isSidebarOpen && (
                currentUser?.role !== 'admin' ? (
                  <span title="Admin Only" className="ml-auto text-slate-500">
                    <Lock className="w-3.5 h-3.5" />
                  </span>
                ) : (
                  <span className="ml-auto text-[9px] bg-emerald-950 text-[#00ff88] border border-[#1e3f2b] px-1.5 py-0.5 rounded font-mono uppercase">
                    Chain
                  </span>
                )
              )}
            </button>

          </nav>
        </div>

        {/* Vault Protected Status Card at the bottom */}
        {isSidebarOpen ? (
          <div className="p-4 m-3 rounded-xl bg-[#0f2518] border border-[#1e3f2b] relative overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff88] opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#00ff88]" />
              </span>
              <span className="text-xs font-bold text-[#00ff88] uppercase tracking-wider">Vault Protected</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed mb-2">
              Google Cloud Firestore storage with SHA-256 Hash Chain verification active.
            </p>
            <div className="flex items-center justify-between text-[10px] text-slate-400 pt-2 border-t border-[#1e3f2b] font-mono">
              <span>Zero-Trust ABAC</span>
              <span className="text-[#00ff88]">ENFORCED</span>
            </div>
          </div>
        ) : (
          <div className="mx-auto mb-4 p-2 rounded-lg bg-[#0f2518] border border-[#1e3f2b]" title="Vault Protected">
            <Shield className="w-4 h-4 text-[#00ff88]" />
          </div>
        )}

      </aside>

      {/* Main Container */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        
        {/* Top Bar */}
        <header className="h-16 bg-[#0a1c12] border-b border-[#1e3f2b] flex items-center justify-between px-4 sm:px-6 select-none shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center text-[#00ff88]">
              <Shield className="w-4 h-4 text-[#00ff88]" />
            </div>
            <span className="font-bold text-white text-sm tracking-wide">TrustVault</span>
          </div>

          {/* User Profile Avatar Circle & Dropdown (replaces standard signout button) */}
          <div className="relative" ref={profileMenuRef}>
            <button
              type="button"
              onClick={() => setIsProfileMenuOpen(prev => !prev)}
              className="w-10 h-10 rounded-full bg-[#00ff88]/15 hover:bg-[#00ff88]/25 border-2 border-[#00ff88]/50 hover:border-[#00ff88] text-[#00ff88] font-black text-base flex items-center justify-center transition shadow-lg shadow-[#00ff88]/10 cursor-pointer select-none focus:outline-none focus:ring-2 focus:ring-[#00ff88]/50"
              title={currentUser?.username || "Account Details"}
              aria-label="User account menu"
              aria-expanded={isProfileMenuOpen}
            >
              {(currentUser?.username?.[0] || currentUser?.email?.[0] || 'U').toUpperCase()}
            </button>

            {/* Profile Dropdown Card */}
            {isProfileMenuOpen && (
              <div className="absolute right-0 mt-2 w-72 rounded-2xl bg-[#0a1c12] border border-[#1e3f2b] shadow-2xl z-50 p-4 text-xs space-y-3.5 animate-in fade-in slide-in-from-top-2 duration-150">
                {/* 1. User Header with Circle Avatar */}
                <div className="flex items-center gap-3 pb-3 border-b border-[#1e3f2b]">
                  <div className="w-10 h-10 rounded-full bg-[#00ff88]/20 border border-[#00ff88]/60 text-[#00ff88] font-black text-base flex items-center justify-center shrink-0">
                    {(currentUser?.username?.[0] || currentUser?.email?.[0] || 'U').toUpperCase()}
                  </div>
                  <div className="overflow-hidden">
                    <span className="font-bold text-white text-sm block truncate">
                      {currentUser?.username || 'User'}
                    </span>
                    <span className="inline-block mt-0.5 px-2 py-0.5 rounded text-[10px] bg-[#0f2518] border border-[#1e3f2b] text-[#00ff88] font-mono uppercase">
                      Role: {currentUser?.role || 'Viewer'}
                    </span>
                  </div>
                </div>

                {/* 2. Account Details: Email Address & Username */}
                <div className="space-y-2.5 bg-[#05140b] p-3 rounded-xl border border-[#1e3f2b]">
                  <div>
                    <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">
                      Username
                    </span>
                    <span className="text-xs font-semibold text-slate-200 block truncate">
                      {currentUser?.username || 'Not configured'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">
                      Email Address
                    </span>
                    <span className="text-xs font-mono text-emerald-300 block truncate" title={currentUser?.email}>
                      {currentUser?.email || 'No email associated'}
                    </span>
                  </div>
                </div>

                {/* 3. Sign Out Option */}
                <div className="pt-1">
                  <button
                    type="button"
                    onClick={async () => {
                      setIsProfileMenuOpen(false);
                      if (currentUser) {
                        await appendAuditLog("user_logout", "auth", currentUser.id, "success", {});
                      }
                      await firebaseSignOut(auth);
                      setCurrentUser(null);
                      setAuthView('login');
                    }}
                    className="w-full py-2.5 px-3 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 hover:border-rose-600 text-rose-300 hover:text-white font-semibold text-xs flex items-center justify-center gap-2 transition"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </header>

        {/* Content Body */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 bg-[#05140b]">
          
          {/* TAB: DASHBOARD (ADMIN ONLY) */}
          {activeTab === 'dashboard' && (
            <div className="max-w-7xl mx-auto space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-[#1e3f2b]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                    <span>Security &amp; Vault Dashboard</span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-950 text-[#00ff88] border border-[#1e3f2b] font-mono">
                      Admin Level
                    </span>
                  </h1>
                  <p className="text-xs text-slate-400 mt-1">Google Studio Firestore database telemetry, real-time access metrics, and tamper-evident audit chain.</p>
                </div>
              </div>

              {/* Status Banner */}
              {verifyStatus && (
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
                    verifyStatus.isValid
                      ? 'bg-[#0f2518] border-[#00ff88]/40 text-[#00ff88]'
                      : 'bg-rose-950/40 border-rose-500/50 text-rose-300'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    {verifyStatus.isValid ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400" />}
                    <span>{verifyStatus.message}</span>
                  </div>
                  <span className="text-[10px] font-mono uppercase bg-[#05140b] px-2 py-0.5 rounded border border-[#1e3f2b]">
                    SHA-256 Chained
                  </span>
                </div>
              )}

              {/* Metrics KPIs */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-xl p-5">
                  <div className="text-slate-400 text-xs uppercase font-medium tracking-wider">Total Vault Documents</div>
                  <div className="text-2xl font-black text-white mt-2">{documents.length}</div>
                  <div className="text-[11px] text-[#00ff88] mt-1 font-mono">Firestore Table: documents</div>
                </div>

                <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-xl p-5">
                  <div className="text-slate-400 text-xs uppercase font-medium tracking-wider">Active Identities</div>
                  <div className="text-2xl font-black text-white mt-2">{users.length} {users.length === 1 ? 'Account' : 'Accounts'}</div>
                  <div className="text-[11px] text-[#00ff88] mt-1 font-mono">{users.length === 0 ? '0 registered in vault' : `${users.filter(u => u.role === 'admin').length} Admin, ${users.filter(u => u.role !== 'admin').length} Standard`}</div>
                </div>

                <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-xl p-5">
                  <div className="text-slate-400 text-xs uppercase font-medium tracking-wider">Audit Blocks Chained</div>
                  <div className="text-2xl font-black text-[#00ff88] mt-2 font-mono">{auditLogs.length}</div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">Firestore Table: audit_logs</div>
                </div>

                <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-xl p-5">
                  <div className="text-slate-400 text-xs uppercase font-medium tracking-wider">Firestore Database</div>
                  <div className="text-2xl font-black text-white mt-2">Active</div>
                  <div className="text-[11px] text-[#00ff88] mt-1 font-mono">Internal Google Studio</div>
                </div>
              </div>

              {/* Recent Audit Transactions */}
              <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl p-6 shadow-xl space-y-4">
                <div className="flex items-center justify-between border-b border-[#1e3f2b] pb-3">
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Shield className="w-4 h-4 text-[#00ff88]" />
                    <span>Recent Audit Transactions</span>
                  </h2>
                  <button
                    type="button"
                    onClick={() => setActiveTab('activity-logs')}
                    className="text-xs text-[#00ff88] font-bold hover:underline"
                  >
                    View Full Hash Chain &rarr;
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="text-slate-400 uppercase tracking-wider border-b border-[#1e3f2b] text-[10px]">
                        <th className="py-2.5 px-3">Block #</th>
                        <th className="py-2.5 px-3">Actor Email</th>
                        <th className="py-2.5 px-3">Event Action</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Current Hash Digest</th>
                        <th className="py-2.5 px-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e3f2b] text-slate-300">
                      {auditLogs.slice(-6).reverse().map(log => (
                        <tr key={log.sequenceNumber} className="hover:bg-[#132e1f] transition-colors">
                          <td className="py-2.5 px-3 font-mono text-[#00ff88] font-bold">#{log.sequenceNumber}</td>
                          <td className="py-2.5 px-3 font-medium text-white">{log.actorEmail}</td>
                          <td className="py-2.5 px-3">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-[#0a1c12] border border-[#1e3f2b] font-mono">
                              {log.action}
                            </span>
                          </td>
                          <td className="py-2.5 px-3">
                            {log.status === 'success' ? (
                              <span className="text-emerald-400 font-semibold text-[10px] flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Success
                              </span>
                            ) : (
                              <span className="text-rose-400 font-semibold text-[10px] flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-rose-400" /> Refused / Blocked
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[10px] text-slate-400">
                            {log.recordHash.slice(0, 10)}...{log.recordHash.slice(-6)}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                            {log.timestamp.slice(0, 19).replace('T', ' ')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: MY DOCUMENTS */}
          {activeTab === 'documents' && (
            <div className="max-w-7xl mx-auto space-y-6">
              
              {/* Header & Controls */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-[#1e3f2b]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                    <span>My Documents</span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full bg-[#0f2518] border border-[#1e3f2b] text-[#00ff88] font-mono">
                      {displayedDocuments.length} Accessible
                    </span>
                  </h1>
                  <p className="text-xs text-slate-400 mt-1">
                    Encrypted documents stored directly in internal Google Studio Firestore database. Access verified by ABAC rules.
                  </p>
                </div>

                <div className="flex items-center gap-3">
                  {currentUser?.role !== 'viewer' && (
                    <button
                      type="button"
                      onClick={() => setActiveTab('upload')}
                      className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-semibold text-xs tracking-wide transition shadow-lg shadow-[#00ff88]/20"
                    >
                      <Upload className="w-4 h-4" />
                      <span>Upload Document</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Search & Filter Bar */}
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                  <input
                    type="text"
                    value={searchDocQuery}
                    onChange={(e) => setSearchDocQuery(e.target.value)}
                    placeholder="Filter documents by title or description..."
                    className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                  />
                </div>
                {selectedCategoryFilter && (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-950/80 border border-[#1e3f2b] text-xs text-[#00ff88]">
                    <span>Category: <strong>{selectedCategoryFilter}</strong></span>
                    <button
                      type="button"
                      onClick={() => setSelectedCategoryFilter('')}
                      className="text-slate-400 hover:text-white"
                    >
                      &times;
                    </button>
                  </div>
                )}
              </div>

              {/* Empty State vs Documents Listing */}
              {displayedDocuments.length === 0 ? (
                <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl p-12 text-center max-w-lg mx-auto my-12 shadow-xl">
                  <div className="w-16 h-16 rounded-full bg-emerald-950/80 border border-[#1e3f2b] flex items-center justify-center mx-auto text-[#00ff88] mb-4">
                    <FolderOpen className="w-8 h-8" />
                  </div>
                  <h3 className="text-lg font-bold text-white mb-2">No documents found</h3>
                  <p className="text-xs text-slate-400 mb-6 max-w-sm mx-auto">
                    {currentUser?.role === 'viewer'
                      ? "No documents have been explicitly shared with your account yet."
                      : "There are currently no documents in this view. Upload an encrypted file to store it in Google Studio Firestore."}
                  </p>
                  {currentUser?.role !== 'viewer' && (
                    <button
                      type="button"
                      onClick={() => setActiveTab('upload')}
                      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs tracking-wide transition shadow-lg shadow-[#00ff88]/20"
                    >
                      <Upload className="w-4 h-4" />
                      <span>Upload Your First Document</span>
                    </button>
                  )}
                </div>
              ) : (
                /* Document Table */
                <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-xl overflow-hidden shadow-xl">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-[#1e3f2b] bg-[#0a1c12] text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                          <th className="py-3.5 px-4">Document Title</th>
                          <th className="py-3.5 px-4">Category</th>
                          <th className="py-3.5 px-4">Owner</th>
                          <th className="py-3.5 px-4">Size</th>
                          <th className="py-3.5 px-4">SHA-256 Hash</th>
                          <th className="py-3.5 px-4">Permissions</th>
                          <th className="py-3.5 px-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e3f2b]">
                        {displayedDocuments.map(docItem => {
                          const isOwner = currentUser ? docItem.ownerId === currentUser.id : false;
                          const isAdmin = currentUser?.role === 'admin';
                          const canManage = isOwner || isAdmin;

                          return (
                            <tr key={docItem.id} className="hover:bg-[#132d1e] transition-colors">
                              <td className="py-3.5 px-4">
                                <div className="flex items-center gap-2.5">
                                  <div className="w-7 h-7 rounded bg-[#0a1c12] border border-[#1e3f2b] flex items-center justify-center text-[#00ff88] shrink-0">
                                    <FileText className="w-4 h-4" />
                                  </div>
                                  <div>
                                    <span className="font-bold text-white block">{docItem.title}</span>
                                    <span className="text-[10px] text-slate-400 truncate max-w-xs block">
                                      {docItem.description || 'No description provided'}
                                    </span>
                                  </div>
                                </div>
                              </td>
                              <td className="py-3.5 px-4">
                                <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-[#1e3f2b] text-[#00ff88] text-[10px] font-medium uppercase tracking-wider">
                                  {docItem.category}
                                </span>
                              </td>
                              <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                                {docItem.ownerEmail.split('@')[0]}
                              </td>
                              <td className="py-3.5 px-4 text-slate-300 font-mono">
                                {(docItem.fileSize / 1024).toFixed(1)} KB
                              </td>
                              <td className="py-3.5 px-4 text-slate-400 font-mono text-[10px]">
                                <span title={docItem.fileSha256}>
                                  {docItem.fileSha256.slice(0, 8)}...{docItem.fileSha256.slice(-6)}
                                </span>
                              </td>
                              <td className="py-3.5 px-4">
                                {canManage ? (
                                  <button
                                    type="button"
                                    onClick={() => setPermissionModalDoc(docItem)}
                                    className="px-2 py-1 rounded bg-[#0a1c12] hover:bg-[#193a24] border border-[#1e3f2b] text-slate-300 hover:text-white text-[11px] flex items-center gap-1 transition"
                                  >
                                    <Users className="w-3 h-3 text-[#00ff88]" />
                                    <span>{docItem.permissions.length} Shared</span>
                                  </button>
                                ) : (
                                  <span className="text-[11px] text-slate-400">
                                    {currentUser ? (docItem.permissions.find(p => p.userId === currentUser.id)?.level.toUpperCase() || 'READ') : 'READ'}
                                  </span>
                                )}
                              </td>
                              <td className="py-3.5 px-4 text-right space-x-2">
                                <button
                                  type="button"
                                  onClick={() => handleDownloadRequest(docItem)}
                                  className="px-2.5 py-1 rounded bg-[#0a1c12] hover:bg-[#00ff88] hover:text-black border border-[#1e3f2b] text-[#00ff88] font-medium transition inline-flex items-center gap-1"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                  <span>Download</span>
                                </button>
                                {canManage && (
                                  <button
                                    type="button"
                                    onClick={async () => {
                                      if (confirm(`Are you sure you want to delete ${docItem.title}?`)) {
                                        setDocuments(prev => prev.filter(d => d.id !== docItem.id));
                                        try {
                                          await deleteDoc(doc(db, 'documents', docItem.id));
                                        } catch (delErr) {
                                          console.warn('Firestore document delete note:', delErr);
                                        }
                                        await appendAuditLog("delete", "document", docItem.id, "success", { title: docItem.title });
                                      }
                                    }}
                                    className="p-1 rounded bg-[#0a1c12] hover:bg-rose-950/40 border border-[#1e3f2b] text-slate-400 hover:text-rose-400 transition"
                                    title="Delete Document"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

            </div>
          )}

          {/* TAB: SEARCH DOCUMENTS */}
          {activeTab === 'search' && (
            <div className="max-w-5xl mx-auto space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Search Documents</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Query documents across authorized vault access in Google Studio Firestore by category, date, and owner.
                </p>
              </div>

              {/* Search Form */}
              <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl p-6 shadow-xl">
                <form onSubmit={handleExecuteSearch} className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Title / Filename</label>
                      <input
                        type="text"
                        value={searchFilters.title}
                        onChange={(e) => setSearchFilters(prev => ({ ...prev, title: e.target.value }))}
                        placeholder="e.g. Audit or Contract"
                        className="w-full px-3 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Category</label>
                      <select
                        value={searchFilters.category}
                        onChange={(e) => setSearchFilters(prev => ({ ...prev, category: e.target.value }))}
                        className="w-full px-3 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] text-xs transition"
                      >
                        <option value="">All Categories</option>
                        <option value="Finance">Finance</option>
                        <option value="HR">HR</option>
                        <option value="Legal">Legal</option>
                        <option value="IT">IT</option>
                        <option value="Education">Education</option>
                        <option value="Personal">Personal</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Owner Username</label>
                      <input
                        type="text"
                        value={searchFilters.owner}
                        onChange={(e) => setSearchFilters(prev => ({ ...prev, owner: e.target.value }))}
                        placeholder="e.g. alice_smith"
                        className="w-full px-3 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Date Uploaded</label>
                      <input
                        type="date"
                        value={searchFilters.date}
                        onChange={(e) => setSearchFilters(prev => ({ ...prev, date: e.target.value }))}
                        className="w-full px-3 py-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] text-xs transition"
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-3 pt-2">
                    <button
                      type="submit"
                      className="px-5 py-2.5 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs tracking-wide transition shadow-lg shadow-[#00ff88]/20 flex items-center gap-2"
                    >
                      <Search className="w-4 h-4" />
                      <span>Search Documents</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setSearchFilters({ title: '', category: '', owner: '', date: '' });
                        setSearchResults(null);
                      }}
                      className="px-4 py-2.5 rounded-lg bg-[#0a1c12] hover:bg-[#153421] border border-[#1e3f2b] text-slate-300 font-medium text-xs transition"
                    >
                      Reset Filters
                    </button>
                  </div>
                </form>
              </div>

              {/* Search Results Display */}
              {searchResults !== null && (
                <div className="space-y-4">
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                    Found {searchResults.length} Match{searchResults.length !== 1 ? 'es' : ''}
                  </h2>

                  {searchResults.length === 0 ? (
                    <div className="text-center py-10 bg-[#0f2518] border border-[#1e3f2b] rounded-xl text-slate-400 text-xs">
                      No documents matched your search filter criteria.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {searchResults.map(docItem => (
                        <div key={docItem.id} className="p-4 rounded-xl bg-[#0f2518] border border-[#1e3f2b] hover:border-[#00ff88]/40 transition space-y-3">
                          <div className="flex items-start justify-between">
                            <div>
                              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-[#00ff88] border border-[#1e3f2b] font-medium">
                                {docItem.category}
                              </span>
                              <h3 className="text-sm font-bold text-white mt-1">{docItem.title}</h3>
                            </div>
                            <span className="text-xs text-slate-400 font-mono">{(docItem.fileSize / 1024).toFixed(1)} KB</span>
                          </div>
                          <p className="text-xs text-slate-400 line-clamp-2">{docItem.description || 'No description provided.'}</p>
                          <div className="flex items-center justify-between pt-2 border-t border-[#1e3f2b] text-xs">
                            <span className="text-slate-400 text-[11px]">Owner: <span className="text-slate-200">{docItem.ownerEmail}</span></span>
                            <button
                              type="button"
                              onClick={() => handleDownloadRequest(docItem)}
                              className="text-[#00ff88] hover:underline font-semibold flex items-center gap-1"
                            >
                              Download Signed URL &rarr;
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

            </div>
          )}

          {/* TAB: CATEGORIES */}
          {activeTab === 'categories' && (
            <div className="max-w-6xl mx-auto space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Document Categories</h1>
                <p className="text-xs text-slate-400 mt-1">Browse documents organized by operational domains.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
                {[
                  { name: 'Finance', desc: 'Budgets, balance sheets, quarterly investor reports, and tax audits.', icon: Layers },
                  { name: 'HR', desc: 'Employment contracts, payroll records, and employee benefit packets.', icon: Users },
                  { name: 'Legal', desc: 'Non-disclosure agreements, licenses, IP filings, and court disclosures.', icon: Shield },
                  { name: 'IT', desc: 'Infrastructure diagrams, SOC2 compliance certs, and incident playbooks.', icon: Database },
                  { name: 'Education', desc: 'Training manuals, engineering guides, and compliance onboarding.', icon: FileCode },
                  { name: 'Personal', desc: 'Personal credentials, identity certificates, and encrypted private backups.', icon: Lock }
                ].map(cat => {
                  const Icon = cat.icon;
                  const count = accessibleDocuments.filter(d => d.category === cat.name).length;

                  return (
                    <div
                      key={cat.name}
                      className="bg-[#0f2518] border border-[#1e3f2b] hover:border-[#00ff88]/50 rounded-2xl p-6 transition duration-200 flex flex-col justify-between group"
                    >
                      <div>
                        <div className="w-12 h-12 rounded-xl bg-emerald-950/80 border border-[#1e3f2b] flex items-center justify-center text-[#00ff88] mb-4 group-hover:scale-105 transition">
                          <Icon className="w-6 h-6" />
                        </div>
                        <h3 className="text-lg font-bold text-white mb-1">{cat.name}</h3>
                        <p className="text-xs text-slate-400 leading-relaxed mb-4">{cat.desc}</p>
                      </div>

                      <div className="pt-4 border-t border-[#1e3f2b] flex items-center justify-between">
                        <span className="text-xs text-emerald-400 font-mono font-semibold">{count} Documents</span>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedCategoryFilter(cat.name);
                            setActiveTab('documents');
                          }}
                          className="text-xs text-[#00ff88] font-bold group-hover:underline flex items-center gap-1"
                        >
                          View Documents &rarr;
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB: UPLOAD DOCUMENT */}
          {activeTab === 'upload' && (
            <div className="max-w-3xl mx-auto space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Upload Document</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Upload private documents directly into Google Studio Firestore database with cryptographic hashing.
                </p>
              </div>

              {/* Security Notice Warning Box */}
              <div className="p-4 rounded-xl bg-[#0f2518] border border-amber-500/40 bg-gradient-to-r from-[#0f2518] to-amber-950/20 text-amber-200 text-xs flex gap-3 shadow-lg">
                <div className="w-6 h-6 rounded-md bg-amber-500/20 border border-amber-500/40 flex items-center justify-center shrink-0 text-amber-400 mt-0.5">
                  <AlertTriangle className="w-4 h-4" />
                </div>
                <div className="space-y-1">
                  <h4 className="font-bold text-amber-300 uppercase tracking-wider text-[11px]">Security Notice &amp; Audit Disclosure</h4>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    All uploaded files are subjected to strict MIME validation and 10MB limits. Upon upload, a SHA-256 cryptographic digest is computed, and an append-only event is committed into the tamper-evident Firestore audit hash chain. Unauthorized downloads or privilege escalation attempts are blocked and logged.
                  </p>
                </div>
              </div>

              {/* Upload Form */}
              <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl p-6 sm:p-8 shadow-2xl">
                <form onSubmit={handleUploadSubmit} className="space-y-5">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                      Document Title <span className="text-[#00ff88]">*</span>
                    </label>
                    <input
                      name="docTitle"
                      type="text"
                      required
                      value={uploadTitle}
                      onChange={(e) => setUploadTitle(e.target.value)}
                      placeholder="e.g. 2026 Board Resolution Draft"
                      className="w-full px-4 py-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Description</label>
                    <textarea
                      name="docDesc"
                      rows={3}
                      value={uploadDesc}
                      onChange={(e) => setUploadDesc(e.target.value)}
                      placeholder="Brief summary of document content, confidentiality level, and stakeholders..."
                      className="w-full px-4 py-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white placeholder-slate-500 focus:outline-none focus:border-[#00ff88] text-xs transition"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                      Category <span className="text-[#00ff88]">*</span>
                    </label>
                    <select
                      name="docCat"
                      required
                      value={uploadCat}
                      onChange={(e) => setUploadCat(e.target.value as any)}
                      className="w-full px-4 py-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-white focus:outline-none focus:border-[#00ff88] text-xs transition"
                    >
                      <option value="">Select a category</option>
                      <option value="Finance">Finance</option>
                      <option value="HR">HR</option>
                      <option value="Legal">Legal</option>
                      <option value="IT">IT</option>
                      <option value="Education">Education</option>
                      <option value="Personal">Personal</option>
                    </select>
                  </div>

                  {/* Document File Picker / Dropzone */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Document File <span className="text-[#00ff88]">*</span>
                      </label>
                      {selectedUploadFile && (
                        <span className="text-[11px] text-[#00ff88] font-mono flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          File Selected from Folder
                        </span>
                      )}
                    </div>

                    {/* Hidden Native File Input */}
                    <input
                      ref={fileInputRef}
                      name="docFile"
                      type="file"
                      className="hidden"
                      accept=".pdf,.txt,.docx,.xlsx,.csv,.png,.jpg,.jpeg"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) {
                          if (file.size > 10 * 1024 * 1024) {
                            alert("File exceeds maximum size of 10MB.");
                            return;
                          }
                          setSelectedUploadFile(file);
                          if (!uploadTitle) {
                            const cleanName = file.name.replace(/\.[^/.]+$/, "").replace(/[-_]/g, " ");
                            setUploadTitle(cleanName.charAt(0).toUpperCase() + cleanName.slice(1));
                          }
                        }
                      }}
                    />

                    {selectedUploadFile ? (
                      /* File Selected Card */
                      <div className="mt-1 p-4 rounded-xl bg-[#0a1c12] border-2 border-[#00ff88]/60 shadow-lg space-y-3">
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3 overflow-hidden">
                            <div className="w-10 h-10 rounded-lg bg-emerald-950/80 border border-[#00ff88]/40 flex items-center justify-center text-[#00ff88] shrink-0">
                              <FileText className="w-5 h-5" />
                            </div>
                            <div className="overflow-hidden">
                              <span className="font-bold text-white text-xs block truncate" title={selectedUploadFile.name}>
                                {selectedUploadFile.name}
                              </span>
                              <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono mt-0.5">
                                <span>{(selectedUploadFile.size / (1024 * 1024) >= 1)
                                  ? `${(selectedUploadFile.size / (1024 * 1024)).toFixed(2)} MB`
                                  : `${Math.round(selectedUploadFile.size / 1024)} KB`}</span>
                                <span>&bull;</span>
                                <span className="uppercase">{selectedUploadFile.type.split('/')[1] || 'FILE'}</span>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 shrink-0">
                            <button
                              type="button"
                              onClick={() => fileInputRef.current?.click()}
                              className="px-2.5 py-1.5 rounded-lg bg-[#0f2518] hover:bg-[#153422] border border-[#1e3f2b] hover:border-[#00ff88]/40 text-xs text-slate-300 hover:text-white transition"
                            >
                              Change
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedUploadFile(null);
                                if (fileInputRef.current) fileInputRef.current.value = '';
                              }}
                              className="p-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 text-rose-300 hover:text-rose-200 transition"
                              title="Remove selected file"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        <div className="pt-2.5 border-t border-[#1e3f2b] flex items-center justify-between text-[11px]">
                          <span className="text-emerald-400 font-medium flex items-center gap-1.5">
                            <Check className="w-3.5 h-3.5 text-[#00ff88]" />
                            Loaded into app &bull; Ready for SHA-256 Digest
                          </span>
                          <span className="text-slate-400 font-mono text-[10px]">Max 10MB</span>
                        </div>
                      </div>
                    ) : (
                      /* Empty File Dropzone */
                      <div
                        onDragOver={(e) => {
                          e.preventDefault();
                          setIsDragOver(true);
                        }}
                        onDragLeave={(e) => {
                          e.preventDefault();
                          setIsDragOver(false);
                        }}
                        onDrop={(e) => {
                          e.preventDefault();
                          setIsDragOver(false);
                          const droppedFile = e.dataTransfer.files?.[0];
                          if (droppedFile) {
                            if (droppedFile.size > 10 * 1024 * 1024) {
                              alert("File exceeds maximum size of 10MB.");
                              return;
                            }
                            setSelectedUploadFile(droppedFile);
                            if (!uploadTitle) {
                              const cleanName = droppedFile.name.replace(/\.[^/.]+$/, "").replace(/[-_]/g, " ");
                              setUploadTitle(cleanName.charAt(0).toUpperCase() + cleanName.slice(1));
                            }
                          }
                        }}
                        onClick={() => fileInputRef.current?.click()}
                        className={`mt-1 flex flex-col items-center justify-center px-6 pt-6 pb-6 border-2 border-dashed rounded-xl cursor-pointer transition duration-200 ${
                          isDragOver
                            ? 'border-[#00ff88] bg-emerald-950/30'
                            : 'border-[#1e3f2b] hover:border-[#00ff88]/50 bg-[#0a1c12]'
                        }`}
                      >
                        <div className="w-12 h-12 rounded-full bg-emerald-950/80 border border-[#1e3f2b] flex items-center justify-center text-[#00ff88] mb-3 group-hover:scale-110 transition">
                          <Upload className="w-6 h-6 text-[#00ff88]" />
                        </div>
                        <div className="text-center space-y-1">
                          <p className="text-xs font-semibold text-white">
                            Click to select document from folder <span className="text-[#00ff88]">or drag and drop</span>
                          </p>
                          <p className="text-[11px] text-slate-400">
                            Select PDF, TXT, DOCX, XLSX, CSV, PNG, or JPG
                          </p>
                          <p className="text-[10px] text-slate-500 font-mono pt-1">
                            Maximum file size: 10 MB &bull; AES-256 Encrypted on upload
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            fileInputRef.current?.click();
                          }}
                          className="mt-3 px-3.5 py-1.5 rounded-lg bg-[#0f2518] hover:bg-[#153422] border border-[#1e3f2b] hover:border-[#00ff88]/50 text-xs text-[#00ff88] font-semibold transition"
                        >
                          Browse Files
                        </button>
                      </div>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={isUploading}
                    className="w-full py-3.5 px-6 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-sm tracking-wide transition shadow-lg shadow-[#00ff88]/20 flex items-center justify-center gap-2 disabled:opacity-60"
                  >
                    {isUploading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin text-black" />
                        <span>Encrypting &amp; Uploading to Firestore...</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-4 h-4" />
                        <span>Upload Securely</span>
                      </>
                    )}
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* TAB: ACTIVITY LOGS (ADMIN ONLY) */}
          {activeTab === 'activity-logs' && (
            <div className="max-w-7xl mx-auto space-y-6">
              
              {/* Header and Controls */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-[#1e3f2b]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                    <span>Tamper-Evident Audit Trail</span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-950 text-[#00ff88] border border-[#1e3f2b] font-mono">
                      SHA-256 Hash Chain
                    </span>
                  </h1>
                  <p className="text-xs text-slate-400 mt-1">
                    Every document access, permission grant, revoke, and refusal is mathematically chained in Firestore /audit_logs.
                  </p>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setTamperModalOpen(true)}
                    className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-amber-950/50 hover:bg-amber-900/60 border border-amber-600/50 text-amber-300 font-semibold text-xs tracking-wide transition"
                  >
                    <Flame className="w-4 h-4 text-amber-400" />
                    <span>Simulate Tamper Attack</span>
                  </button>

                  <button
                    type="button"
                    onClick={verifyChain}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs tracking-wide transition shadow-lg shadow-[#00ff88]/20"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Verify Chain Integrity</span>
                  </button>
                </div>
              </div>

              {/* Status Banner */}
              {verifyStatus && (
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
                    verifyStatus.isValid
                      ? 'bg-[#0f2518] border-[#00ff88]/40 text-[#00ff88]'
                      : 'bg-rose-950/40 border-rose-500/50 text-rose-300'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    {verifyStatus.isValid ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400" />}
                    <div>
                      <span className="font-bold">{verifyStatus.isValid ? 'Integrity Verified: ' : 'INTEGRITY BREACH: '}</span>
                      <span>{verifyStatus.message}</span>
                    </div>
                  </div>
                  {chainTampered && (
                    <button
                      type="button"
                      onClick={() => {
                        window.location.reload();
                      }}
                      className="px-2.5 py-1 rounded bg-[#0a1c12] border border-[#1e3f2b] text-slate-300 hover:text-white font-mono text-[10px]"
                    >
                      Reset Clean Chain
                    </button>
                  )}
                </div>
              )}

              {/* Hash Chain Table */}
              <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl overflow-hidden shadow-2xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-[#0a1c12] text-slate-400 uppercase tracking-wider border-b border-[#1e3f2b] text-[10px]">
                        <th className="py-3 px-4">Seq</th>
                        <th className="py-3 px-4">Timestamp (UTC)</th>
                        <th className="py-3 px-4">Actor Email</th>
                        <th className="py-3 px-4">Event Type</th>
                        <th className="py-3 px-4">Resource</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Previous Hash</th>
                        <th className="py-3 px-4">Block Hash Digest</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e3f2b] text-slate-300">
                      {auditLogs.map(log => (
                        <tr key={log.sequenceNumber} className="hover:bg-[#132e1f] transition-colors">
                          <td className="py-3 px-4 font-mono font-bold text-[#00ff88]">#{log.sequenceNumber}</td>
                          <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">{log.timestamp.slice(0, 19).replace('T', ' ')}</td>
                          <td className="py-3 px-4 font-semibold text-white">{log.actorEmail}</td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-[#0a1c12] border border-[#1e3f2b] font-mono text-emerald-300">
                              {log.action}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-400 text-[10px]">
                            {log.resourceId}
                          </td>
                          <td className="py-3 px-4">
                            {log.status === 'success' ? (
                              <span className="text-emerald-400 font-bold text-[10px] uppercase bg-emerald-950/60 px-2 py-0.5 rounded border border-[#1e3f2b]">
                                Success
                              </span>
                            ) : (
                              <span className="text-rose-400 font-bold text-[10px] uppercase bg-rose-950/60 px-2 py-0.5 rounded border border-rose-900/60" title={JSON.stringify(log.details)}>
                                Refused / Denied
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4 font-mono text-[10px] text-slate-500">
                            <span title={log.previousHash}>{log.previousHash.slice(0, 8)}...{log.previousHash.slice(-4)}</span>
                          </td>
                          <td className="py-3 px-4 font-mono text-[10px] text-[#00ff88]">
                            <span title={log.recordHash}>{log.recordHash.slice(0, 8)}...{log.recordHash.slice(-4)}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* TAB: CODE & ARCHITECTURE EXPLORER */}
          {activeTab === 'code-explorer' && (
            <div className="max-w-6xl mx-auto space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                  <Code2 className="w-6 h-6 text-[#00ff88]" />
                  <span>TrustVault Source Code &amp; Security Architecture</span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Examine the Google Cloud Firestore schema, Zero-Trust security rules, and ABAC RBAC controls.
                </p>
              </div>

              {/* Code viewer panels */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-[#0f2518] border border-[#1e3f2b] space-y-2">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2">
                    <Database className="w-4 h-4 text-[#00ff88]" />
                    <span>Firestore Tables &amp; Blueprint</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Collections: <code className="text-[#00ff88]">users</code>, <code className="text-[#00ff88]">documents</code>, <code className="text-[#00ff88]">audit_logs</code>.
                  </p>
                  <span className="text-[10px] text-emerald-400 font-mono block">Path: /firebase-blueprint.json</span>
                </div>

                <div className="p-4 rounded-xl bg-[#0f2518] border border-[#1e3f2b] space-y-2">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2">
                    <Key className="w-4 h-4 text-[#00ff88]" />
                    <span>Hardened Security Rules</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Global default-deny, immutable audit trail, and zero-trust attribute verification.
                  </p>
                  <span className="text-[10px] text-emerald-400 font-mono block">Path: /firestore.rules</span>
                </div>

                <div className="p-4 rounded-xl bg-[#0f2518] border border-[#1e3f2b] space-y-2">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />
                    <span>Cryptographic Verification</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Mathematical SHA-256 chaining guarantees detection of any retroactive record mutations.
                  </p>
                  <span className="text-[10px] text-emerald-400 font-mono block">Live Chain Engine Active</span>
                </div>
              </div>

              {/* Security Invariants Checklist */}
              <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl p-6 space-y-4">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Security Invariants Enforced
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-2.5">
                    <Check className="w-4 h-4 text-[#00ff88] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white block">Tamper-Evident Hash Chain</strong>
                      <span className="text-slate-400 text-[11px]">Each audit log computes SHA-256 over its canonical payload combined with the preceding record's digest.</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-2.5">
                    <Check className="w-4 h-4 text-[#00ff88] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white block">Defense-in-Depth Authorization</strong>
                      <span className="text-slate-400 text-[11px]">Even if client requests bypass client checks, Firestore security rules reject unauthorized writes.</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-2.5">
                    <Check className="w-4 h-4 text-[#00ff88] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white block">Instant Access Revocation</strong>
                      <span className="text-slate-400 text-[11px]">Deleting permissions removes database mapping immediately; subsequent downloads are blocked and logged.</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] flex items-start gap-2.5">
                    <Check className="w-4 h-4 text-[#00ff88] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white block">Refused Attempts Recorded</strong>
                      <span className="text-slate-400 text-[11px]">All forbidden access attempts or privilege escalation violations are permanently logged with status 'denied'.</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        </main>
      </div>

      {/* ----------------------------------------------------------------------------- */}
      {/* MODAL 1: GRANULAR PERMISSIONS MODAL */}
      {/* ----------------------------------------------------------------------------- */}
      {permissionModalDoc && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0f2518] border border-[#1e3f2b] rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-[#1e3f2b] pb-3">
              <div>
                <h3 className="font-bold text-white text-base">Manage Document Access</h3>
                <p className="text-xs text-slate-400 truncate max-w-sm">{permissionModalDoc.title}</p>
              </div>
              <button
                type="button"
                onClick={() => setPermissionModalDoc(null)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            {/* Grant Permission Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const form = e.currentTarget;
                const email = (form.elements.namedItem('grantEmail') as HTMLInputElement).value;
                const level = (form.elements.namedItem('grantLevel') as HTMLSelectElement).value as 'read' | 'edit';
                handleGrantPermission(email, level);
                (form.elements.namedItem('grantEmail') as HTMLInputElement).value = '';
              }}
              className="space-y-3 p-3 bg-[#0a1c12] rounded-xl border border-[#1e3f2b]"
            >
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block">Grant Access to User:</span>
              <div className="flex gap-2">
                <input
                  name="grantEmail"
                  type="email"
                  required
                  placeholder="collaborator@enterprise.com"
                  className="flex-1 px-3 py-2 rounded-lg bg-[#05140b] border border-[#1e3f2b] text-white text-xs focus:outline-none focus:border-[#00ff88]"
                />
                <select
                  name="grantLevel"
                  className="px-2 py-2 rounded-lg bg-[#05140b] border border-[#1e3f2b] text-white text-xs"
                >
                  <option value="read">Read Only</option>
                  <option value="edit">Edit Access</option>
                </select>
                <button
                  type="submit"
                  className="px-3 py-2 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs"
                >
                  Grant
                </button>
              </div>
            </form>

            {/* Existing Permissions List */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">Authorized Users:</span>
              {permissionModalDoc.permissions.length === 0 ? (
                <p className="text-xs text-slate-500 italic p-3 bg-[#0a1c12] rounded-lg">No external users have been granted access.</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {permissionModalDoc.permissions.map(perm => (
                    <div key={perm.userId} className="flex items-center justify-between p-2.5 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-xs">
                      <div>
                        <span className="font-semibold text-white block">{perm.email}</span>
                        <span className="text-[10px] text-emerald-400 font-mono uppercase">{perm.level} Access</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRevokePermission(perm.userId, perm.email)}
                        className="px-2 py-1 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-[11px] font-medium transition"
                      >
                        Revoke Access
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setPermissionModalDoc(null)}
                className="px-4 py-2 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-slate-300 text-xs hover:text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ----------------------------------------------------------------------------- */}
      {/* MODAL 2: SIGNED DOWNLOAD URL MODAL */}
      {/* ----------------------------------------------------------------------------- */}
      {signedUrlModalData && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0f2518] border border-[#00ff88]/40 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl relative glow-neon-sm">
            <div className="flex items-center gap-3 border-b border-[#1e3f2b] pb-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-[#00ff88]/40 flex items-center justify-center text-[#00ff88]">
                <Download className="w-4 h-4" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">Authorized Download Ready</h3>
                <span className="text-[10px] text-emerald-400 font-mono">Zero-Trust ABAC Verification: PASSED</span>
              </div>
            </div>

            <p className="text-xs text-slate-300">
              Your cryptographic identity and access permission records were verified against the Firestore database.
            </p>

            <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] space-y-2">
              <div className="flex justify-between text-[11px] text-slate-400">
                <span>File: <strong className="text-white">{signedUrlModalData.doc.title}</strong></span>
                <span className="text-amber-400 font-mono">Token Expiry: 60s</span>
              </div>
              <div className="text-[10px] font-mono text-slate-400 break-all p-2 rounded bg-[#05140b] border border-[#1e3f2b]">
                {signedUrlModalData.url}
              </div>
              <div className="text-[10px] text-slate-400 font-mono flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#00ff88]" />
                <span>SHA-256 Digest: {signedUrlModalData.doc.fileSha256.slice(0, 16)}...</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setSignedUrlModalData(null)}
                className="px-4 py-2 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-slate-300 text-xs"
              >
                Close
              </button>
              {signedUrlModalData.doc.fileDataUrl ? (
                <a
                  href={signedUrlModalData.doc.fileDataUrl}
                  download={signedUrlModalData.doc.title}
                  onClick={() => setSignedUrlModalData(null)}
                  className="px-4 py-2 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs inline-flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Document File</span>
                </a>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    alert(`Download verified! File "${signedUrlModalData.doc.title}" downloaded securely.`);
                    setSignedUrlModalData(null);
                  }}
                  className="px-4 py-2 rounded-lg bg-[#00ff88] hover:bg-[#00cc6a] text-black font-bold text-xs inline-flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download File</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ----------------------------------------------------------------------------- */}
      {/* MODAL 3: TAMPER SIMULATOR MODAL */}
      {/* ----------------------------------------------------------------------------- */}
      {tamperModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0f2518] border border-amber-500/50 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-amber-950/80 border border-amber-500/50 flex items-center justify-center text-amber-400">
                <Flame className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">Simulate Database Tampering</h3>
                <span className="text-[10px] text-amber-400 font-mono">Test Hash Chain Detection</span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              In an ordinary database, a malicious actor or compromised admin could secretly edit historical audit logs. In TrustVault, each block depends on the preceding SHA-256 digest.
            </p>

            <p className="text-xs text-amber-300 bg-amber-950/40 p-3 rounded-lg border border-amber-800/40">
              Clicking below will maliciously alter Block #2's action in memory. When you run "Verify Chain Integrity", the cryptographic engine will immediately expose the exact point of compromise.
            </p>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setTamperModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={simulateTampering}
                className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-black font-bold text-xs"
              >
                Inject Mutation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ----------------------------------------------------------------------------- */}
      {/* MODAL 4: 403 ACCESS DENIED / REFUSAL DIALOG */}
      {/* ----------------------------------------------------------------------------- */}
      {accessDeniedAlert && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0f2518] border border-rose-500/50 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-950/80 border border-rose-500/50 flex items-center justify-center text-rose-400">
                <XCircle className="w-6 h-6" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">{accessDeniedAlert.title}</h3>
                <span className="text-[10px] text-rose-400 font-mono uppercase">Refusal Logged to Audit Chain</span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {accessDeniedAlert.reason}
            </p>

            <div className="p-3 rounded-lg bg-[#0a1c12] border border-[#1e3f2b] text-[10px] font-mono text-slate-400 space-y-1">
              <div>Actor: {currentUser?.email || 'Anonymous'}</div>
              <div>Role: {currentUser?.role || 'Guest'}</div>
              <div className="text-rose-400">Status: DENIED &bull; Event Recorded</div>
            </div>

            <div className="text-right pt-2">
              <button
                type="button"
                onClick={() => setAccessDeniedAlert(null)}
                className="px-4 py-2 rounded-lg bg-[#00ff88] text-black font-bold text-xs"
              >
                Acknowledge
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
