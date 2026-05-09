SCRY — Encryption Container for Text & Files

SCRY is a Python encryption utility designed for secure local storage of files and text data. It uses AES-256-GCM for authenticated encryption and Argon2id for secure key derivation from user passwords.

Features: Encrypt and decrypt both files and text - Password-based encryption with confirmation prompts - Self-identifying encrypted payloads (magic header + versioning) - Embedded filename support for accurate file restoration - Safe output path handling to avoid overwriting existing files - Integrity protection using AES-GCM authentication tags - Input validation and corruption detection

Security Design: AES-256-GCM ensures confidentiality + tamper detection - Argon2id strengthens passwords against brute-force attacks - Versioned headers allow forward compatibility - Strict filename and path sanitization prevents unsafe restores

Usage Overview: SCRY runs in an interactive CLI menu: Encrypt text or files - Decrypt text or SCRY-encrypted files - View tool information and version details

Dependencies Installation: pip install -r requirements.txt OR python -m pip install -r requirements.txt

Disclaimer: This tool is provided as-is without warranty. It has not been independently security audited and should not be treated as guaranteed protection against all threats. Users should always keep backups of important data.

License: MIT License (see LICENSE file for full terms)
