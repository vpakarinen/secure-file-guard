# Secure File Guard

A robust Python-based file encryption application that provides secure storage with strong encryption and password protection.

## Features

- AES-256 encryption with PBKDF2 key derivation for maximum security
- Strong password requirements with brute-force protection
- Secure vault system for consolidated file storage
- Add, extract, and list files with encrypted metadata
- Protected file permissions and vault integrity verification
- Configurable security settings and storage locations
- Comprehensive error handling and logging

## How It Works

- Creates an encrypted vault secured by your password and a unique salt
- Files are encrypted using AES-256 and stored in a secure container
- Password verification and key derivation ensure vault security
- Files can be safely added to or extracted from the vault
- All operations maintain file integrity and metadata security

## Requirements

- Python 3.8+
- Required packages:
  - cryptography
  - PyYAML
  - watchdog
  - pytest
  - sphinx

## Installation

1. Clone the repository