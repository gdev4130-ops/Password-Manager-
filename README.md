# Password-Manager-
A simple and secure password manager written in Python.


Features:
- Master password protected (uses PBKDF2HMAC to derive an encryption key)
- AES-256 (Fernet) symmetric encryption for stored credentials
- SQLite backend for local storage (`vault.db`)
- CLI to add, get, list, delete credentials
- Export to CSV (encrypted values decrypted on export)


## Quick start


1. Create a virtual environment and activate it:


```bash
python -m venv venv
source venv/bin/activate # on Windows: venv\Scripts\activate
