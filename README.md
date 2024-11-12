# Secure File Guard

Python application that provides secure storage with strong encryption and brute-force protection.

✅ This app has been tested thouroughly to make sure it's fully secure

## Features

- AES-256 encryption with PBKDF2 key derivation for maximum security
- Strong password requirements with brute-force protection
- Protected file permissions and vault integrity verification
- Configurable security settings and storage locations
- Add, extract, and list files with encrypted metadata
- Comprehensive error handling and logging

## How It Works

- Creates an encrypted vault secured by your password and a unique salt
- Files are encrypted using AES-256 and stored in a secure container
- Password verification and key derivation ensure vault security
- Files can be safely added to or extracted from the vault
- All operations maintain file integrity and metadata security
- Files can be safely added to or extracted from the vault

## Requirements

- Python 3.8+
- `requirements.txt` includes all the required packages

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/vpakarinen/secure-file-guard.git
   cd secure-file-guard
   ```

2. **Create a Virtual Environment** (Optional but Recommended)

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```
