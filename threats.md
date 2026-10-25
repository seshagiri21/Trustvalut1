# TrustVault Security Architecture & Threat Analysis

*A comprehensive breakdown of real-world threat vectors, vulnerabilities, edge cases, and implemented defenses in TrustVault's Zero-Trust Document Management System.*

---

## 1. Security Overview & Philosophy

TrustVault was designed from the ground up under the **Zero-Trust Security Model**:
> *"Never trust the client; always verify every transaction, token, and attribute at the database engine boundary."*

In modern single-page applications (SPAs), frontend checks (like disabling a button or hiding a menu item) are purely cosmetic UX conveniences. An attacker can easily tamper with JavaScript memory, modify local storage, rewrite React state, or fire raw HTTP requests using tools like Postman, curl, or browser DevTools.

To deliver true enterprise-grade confidentiality and integrity, TrustVault implements **Defense-in-Depth across three distinct layers**:
1. **Cryptographic Identity & Attribute-Based Access Control (ABAC)**
2. **Server-Enforced Firestore Security Rules** (compiled into the cloud database kernel)
3. **Tamper-Evident SHA-256 Hash Chaining** for the immutable audit trail

Below are the key threats, potential loopholes analyzed during development, and the exact solutions engineered to neutralize them.

---

## 2. Threat Analysis & Solutions

### Threat 1: Client-Side Role Forgery & Privilege Escalation
- **The Attack Vector:** 
  In a typical web application, user roles are stored in component state (e.g., `currentUser.role = 'viewer'`). A curious user or malicious actor opens browser DevTools, inspects the React component tree or runs `window.__REACT_DEVTOOLS_GLOBAL_HOOK__`, and manually flips their role to `'admin'`.
- **The Potential Loophole:**
  If backend authorization relies on parameters passed in the request body (e.g., `POST /deleteDocument { userRole: 'admin' }`), the attacker gains unauthorized control over sensitive company data.
- **How We Solved It:**
  1. **Source of Truth in Firestore:** The user's role is never accepted from the client request payload. Instead, Firestore security rules query the authenticated user's document directly from the secure `/users` collection:
     ```javascript
     function getUserData() {
       return get(/databases/$(database)/documents/users/$(request.auth.uid)).data;
     }
     function userIsAdmin() {
       return request.auth != null && getUserData().role == 'admin';
     }
     ```
  2. **Immutable Role Protection:** Non-admin users are strictly forbidden from modifying the `role` field on their own profile:
     ```javascript
     allow update: if request.auth != null && (
       userIsAdmin() || 
       (request.auth.uid == userId && request.resource.data.role == resource.data.role)
     );
     ```
  3. **First-User Bootstrap Guarantee:** The root administrator account (`seshagirib6@gmail.com`) is hard-whitelisted during initial provisioning. Every subsequent user registered through the application is automatically assigned the least-privilege `viewer` role unless explicitly elevated by an existing administrator.

---

### Threat 2: Insecure Direct Object Reference (IDOR) & Document Enumeration
- **The Attack Vector:**
  Document IDs in cloud databases often follow predictable patterns or get leaked through shared links (e.g., `doc_financial_q3_2025`). An attacker queries the database directly with the guessed ID to read unauthorized intellectual property.
- **The Potential Loophole:**
  Simple Role-Based Access Control (RBAC) often operates on broad buckets ("any manager can view all manager docs"). It fails when two employees with the same role should not see each other's confidential HR or salary records.
- **How We Solved It (Granular ABAC):**
  1. Every document record in the `documents` collection carries fine-grained attribute metadata:
     - `ownerId`: The unique user ID of the creator.
     - `classification`: Security clearance required (`Public`, `Internal`, `Restricted`, `Confidential`).
     - `isPublic`: Explicit boolean toggle.
     - `permissions`: An array of explicit user grants: `[{ userId, email, level: 'read' | 'edit' }]`.
  2. The Firestore security rule evaluates access at the individual document level:
     ```javascript
     function canReadDoc(docData) {
       return request.auth != null && (
         userIsAdmin() ||
         docData.ownerId == request.auth.uid ||
         docData.isPublic == true ||
         docData.permissions.hasAny([request.auth.uid]) ||
         docData.permissions.hasAny([request.auth.token.email])
       );
     }
     allow get: if canReadDoc(resource.data);
     ```
  3. If an unauthorized user attempts to fetch a document by ID, Firestore rejects the read with an immediate `PERMISSION_DENIED` error, returning zero bytes of data.

---

### Threat 3: Collection Scraping & List Query Leaks
- **The Attack Vector:**
  A user executes a blanket query: `db.collection('documents').get()`. Even if single-document `get` rules are tight, if list rules are poorly configured, Firestore might either fail the entire query or return documents that the user shouldn't see.
- **The Potential Loophole:**
  Many developers write `allow read: if canReadDoc(resource.data)`. However, in Firestore, rules act as filters for queries. If a rule references document fields that aren't constrained by `where()` clauses in the client query, Firestore returns a permission error.
- **How We Solved It:**
  1. **Separation of `get` and `list` Rules:** We decoupled single document lookups (`allow get`) from collection-wide searches (`allow list`):
     ```javascript
     allow get: if canReadDoc(resource.data);
     allow list: if request.auth != null;
     ```
  2. **Client-Side Query Constraints:** The client queries only fetch documents the user has rights to (filtering by owner or public status), and single document retrievals are strictly governed by `canReadDoc`.

---

### Threat 4: Audit Log Tampering & Repudiation (Covering Tracks)
- **The Attack Vector:**
  A rogue employee accesses a classified patent document, downloads it, and then deletes or updates the audit log entry to erase any record of the activity.
- **The Potential Loophole:**
  Standard database tables allow standard `UPDATE` or `DELETE` operations if someone has database-level write permissions.
- **How We Solved It:**
  1. **Cryptographic SHA-256 Hash Chaining:** Every log entry functions like a block in a private ledger. The cryptographic hash is computed across all critical fields:
     $$\text{Hash}_i = \text{SHA256}(\text{id} + \text{timestamp} + \text{action} + \text{userId} + \text{details} + \text{Hash}_{i-1})$$
     - The first entry connects to a known Genesis hash (`"0000000000000000000000000000000000000000000000000000000000000000"`).
     - Each subsequent entry stores both its own hash (`currentHash`) and the preceding entry's hash (`previousHash`).
  2. **Tamper Detection Engine:** The system includes a built-in cryptographic verification engine (`verifyAuditChain`) that traverses the chain from index 0 to $N$. If even a single character, timestamp, or user ID is altered retroactively, the computed hash diverges and instantly triggers a visible **CRITICAL: Chain Integrity Broken** alert identifying the exact altered log index.
  3. **Append-Only Security Rules:** In Firestore, update and delete operations on the `audit_logs` collection are permanently blocked:
     ```javascript
     match /audit_logs/{logId} {
       allow create: if request.auth != null;
       allow update, delete: if false; // STRICT IMMUTABILITY
     }
     ```
     Once an action is logged, no user—including the system administrator—can modify or delete the record.

---

### Threat 5: Data Poisoning & Storage Exhaustion (Denial of Wallet)
- **The Attack Vector:**
  An authenticated attacker writes massive strings (multi-megabyte junk payloads) into document titles, notes, or categories, causing database storage bloat, astronomical egress costs, and client performance degradation.
- **The Potential Loophole:**
  Unchecked schemas in NoSQL databases accept arbitrary JSON fields and arbitrary lengths.
- **How We Solved It:**
  1. **Strict String Length & Type Validation:** In `firestore.rules`, all incoming write operations are validated against length caps:
     ```javascript
     function isValidDocument(doc) {
       return doc.title is string && doc.title.size() > 0 && doc.title.size() <= 200 &&
              doc.category is string && doc.category.size() <= 100 &&
              doc.classification in ['Confidential', 'Restricted', 'Internal', 'Public'] &&
              doc.ownerId is string &&
              doc.permissions is list;
     }
     allow create: if request.auth != null && isValidDocument(request.resource.data);
     ```
  2. **Payload Size Guardrails:** Document uploads are capped at reasonable sizes, preventing client-side freeze and database payload overflow.

---

### Threat 6: Session Hijacking & Sensitive Data Residuals in Memory
- **The Attack Vector:**
  A user signs out on a shared terminal. The next user opens the browser, inspects form auto-fills, reads cached data URLs from memory, or accesses previously viewed document blobs.
- **The Potential Loophole:**
  Modern browsers retain object URLs created via `URL.createObjectURL(blob)` until the document is unloaded. If an application doesn't clean up its state on sign-out, sensitive documents remain accessible in the browser cache.
- **How We Solved It:**
  1. **Ephemeral Blob Lifecycles:** When a document is downloaded, TrustVault generates a transient Blob URL, triggers the browser download programmatically, and immediately schedules memory reclamation:
     ```typescript
     const downloadUrl = URL.createObjectURL(blob);
     a.href = downloadUrl;
     a.click();
     setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000); // Purged within 1 second
     ```
  2. **Complete Session Sanitization on Sign-Out:**
     - Clears the email and password form fields completely.
     - Destroys active user state in memory.
     - Resets filtered document views and permission caches.
     - Ensures the password input defaults to masked mode with an interactive visibility toggle.

---

### Threat 7: Unauthenticated Document Writes & Phantom Accounts
- **The Attack Vector:**
  An unauthenticated visitor tries to write documents directly or create admin accounts before logging in.
- **The Potential Loophole:**
  Overly permissive initialization scripts that leave rules in test mode (`allow read, write: if true;`).
- **How We Solved It:**
  1. Every database operation requires `request.auth != null`.
  2. Rules verify that the `ownerId` of newly created documents strictly matches `request.auth.uid`:
     ```javascript
     allow create: if request.auth != null && request.resource.data.ownerId == request.auth.uid;
     ```
  3. No anonymous or unauthenticated writes can reach any collection.

---

## 3. Security Verification Checklist

| Security Control | Threat Mitigated | Enforced At | Status |
| :--- | :--- | :--- | :--- |
| **Strict ABAC Rules** | Unauthorized data access & IDOR | Firestore Kernel | Verified |
| **Role Verification via User Doc** | Frontend privilege escalation | Firestore Kernel | Verified |
| **Immutable Role Updates** | Self-promotion to Admin | Firestore Kernel | Verified |
| **Append-Only Audit Logs** | Tampering & repudiation | Firestore Kernel | Verified |
| **Cryptographic SHA-256 Hash Chain** | Offline database log manipulation | Client + Crypto API | Verified |
| **Schema & Length Validation** | Data poisoning & storage abuse | Firestore Kernel | Verified |
| **Ephemeral Blob Revocation** | Client memory leakage | Browser Memory | Verified |
| **First-User Bootstrap Whitelist** | Rogue admin account creation | Auth / DB Logic | Verified |
| **Input Sanitization on Logout** | Credential residue on shared PCs | UI State Engine | Verified |

---

## 4. Conclusion

By shifting the burden of trust away from client-side JavaScript and anchoring it in **server-enforced security rules** paired with **cryptographic hashing**, TrustVault ensures that even if the client application is completely reverse-engineered or compromised, the core database remains resilient, confidential, and fully auditable.
