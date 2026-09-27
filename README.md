#  FIV — File Integrity Verifier

https://file-integrity-verifier.onrender.com

FIV is a lightweight web tool built with Python and Streamlit to verify file authenticity and detect tampering using cryptographic checksums (MD5 and SHA-256).

It processes files entirely on the client side using streaming buffers, meaning large files won't crash your system memory and no data ever leaves your machine. It also includes an authentication layer, PDF audit report generation, verification history, and an interactive breakdown comparing MD5 vs. SHA-256.

---

## ✨ Features

- **⚡ Instant Checksum Generation:** Upload any file to calculate its MD5 (128-bit) and SHA-256 (256-bit) hashes simultaneously.
- **🛡️ Dual Verification Modes:**
  - *Hash Match:* Paste an expected checksum. FIV auto-detects whether it's MD5 or SHA-256, cleans whitespace, and checks for an exact match.
  - *Direct File Comparison:* Upload two files directly to check if their contents are byte-for-byte identical.
- **📊 MD5 vs. SHA-256 Technical Comparison:** A side-by-side reference explaining digest size, speed benchmarks, security levels, collision resistance, and where each algorithm is still used today.
- **📄 Downloadable PDF Audit Reports:** Generates an official, stamped audit certificate with timestamps, file specs, and verification verdicts using `fpdf2` directly in memory (no disk clutter).
- **🔒 In-Memory & Memory-Safe:** Uses 64 KB binary chunking so you can safely hash files of any size without running out of RAM.
- **👤 User Accounts & History:** Built-in authentication backed by a local SQLite database (`fiv_database.db`). Passwords are protected using salted PBKDF2-HMAC-SHA256, and past verification runs are logged for later review.
- **🌙 Theme Switcher:** Clean dark mode by default with a quick light mode toggle.

---

## 🔬 MD5 vs. SHA-256 at a Glance

| Feature | MD5 | SHA-256 |
| :--- | :--- | :--- |
| **Output Length** | 128 bits (32 hex chars) | 256 bits (64 hex chars) |
| **Speed** | Very fast | Moderate |
| **Collision Resistance** | Vulnerable (broken for crypto security) | High (cryptographically secure) |
| **Primary Use Cases** | Quick error checking, legacy checksums | Digital signatures, blockchain, forensics |

---

## 🛠️ Tech Stack

- **Frontend / Dashboard:** [Streamlit](https://streamlit.io/)
- **Hashing Engine:** Python standard library (`hashlib`)
- **PDF Generation:** `fpdf2`
- **Database:** SQLite (`sqlite3`)

---

## 🚀 Getting Started
### 1. Prerequisites
Ensure you have Python 3.10 or newer installed:
```bash
python --version
