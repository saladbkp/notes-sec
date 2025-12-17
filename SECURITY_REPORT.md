# Security Investigation & Zero Trust Architecture Report

This document addresses **Objective 1**: *"To investigate the security vulnerabilities in current educational note-taking software and study the principles of Multi-Layer Encryption and Zero Trust Architecture."*

## 1. Investigation of Vulnerabilities in Current Educational Software

Current popular educational and note-taking platforms (e.g., Notion, Evernote, Google Docs) primarily rely on **perimeter security** and **server-side encryption**. This creates several critical vulnerabilities in an educational context where sensitive research data or personal information is stored:

### A. Centralized Trust Model (The "Insider Threat")
*   **Vulnerability:** Service providers manage the encryption keys. Database administrators or compromised server processes can decrypt and read user data.
*   **Educational Impact:** Research data, grades, or counseling notes are accessible to the platform provider.
*   **Our Solution:** **Zero Knowledge Architecture**. Keys are generated and stored only on the client (browser). The server never receives the decryption keys.

### B. Lack of Granular Access Control
*   **Vulnerability:** Once a user is authenticated, they often have broad access. Session hijacking allows full account compromise.
*   **Our Solution:** **Continuous Verification**. Every API request is independently authenticated via JWT. Critical actions (unlocking the vault) require a second layer of decryption (Data Encryption Key unwrapping) that cannot be performed even with a stolen session token alone (requires the Master Key derived from the password).

### C. Data Persistence Risks
*   **Vulnerability:** Deleted notes often remain in backups or server logs in plaintext.
*   **Our Solution:** **Crypto-Shredding**. Deleting a note's key effectively destroys the data forever, even if the encrypted blob remains in backups, as it is mathematically undecryptable without the key.

## 2. Multi-Layer Encryption Implementation

We have studied and implemented a **Multi-Layer Encryption** strategy to ensure defense-in-depth:

*   **Layer 1: Content Encryption (Data Layer)**
    *   **Algorithm:** AES-GCM (256-bit).
    *   **Mechanism:** Each note is encrypted with a unique random key (Note Key). This ensures that compromising one note does not compromise the entire vault.
    *   **Integrity:** GCM mode provides authenticated encryption, preventing tampering with the ciphertext.

*   **Layer 2: Key Encryption (Envelope Encryption)**
    *   **Algorithm:** AES-KW (Key Wrap) or AES-GCM.
    *   **Mechanism:** The Note Keys are encrypted using the user's Master Key (Vault Key). The Server stores only the *wrapped* keys.
    *   **Benefit:** Allows key rotation and efficient sharing without re-encrypting the entire content.

*   **Layer 3: Transport Security (Network Layer)**
    *   **Mechanism:** TLS/HTTPS (enforced in production).
    *   **Benefit:** Protects against Man-in-the-Middle (MitM) attacks during data transmission.

## 3. Zero Trust Architecture Principles

Our application adheres to the core tenets of Zero Trust:

### A. "Never Trust, Always Verify"
*   **Implementation:** The API treats the internal network and the client as untrusted.
*   **Evidence:** All API endpoints (except login/register) require a valid, signed JWT. The server validates the signature and expiration on *every* request, rather than relying on session cookies alone.

### B. "Assume Breach"
*   **Implementation:** We assume the database *will* be compromised.
*   **Evidence:** If an attacker dumps the `notes` and `note_blobs` tables, they see only high-entropy random strings (`alg: "AES-GCM", data: "..."`). There is no plaintext to mine.

### C. "Least Privilege" Access
*   **Implementation:** Sharing is explicit and granular.
*   **Evidence:** The `shares` table defines specific permissions (`read-only` vs `read-write`). A user cannot access a note unless an explicit record exists linking their User ID to the Note ID.

## 4. Conclusion

The project successfully meets Objective 1 by:
1.  Identifying the weakness of server-side trust in existing apps.
2.  Implementing a **Zero Trust** backend where the server is a blind storage provider.
3.  Deploying **Multi-Layer Encryption** (Client-side AES + Envelope) to guarantee data sovereignty.
