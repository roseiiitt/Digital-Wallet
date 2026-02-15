<div align="center">

<img width="350" height="90" alt="image" src="https://github.com/user-attachments/assets/b80f3aca-0e36-4cb2-b289-058014e62cbc" alt="Softwartica College of IT & E-Commerce in collaboration with Coventry University" width="700"/>

<br><br>

<h1>Secure Digital Wallet System</h1>
<h3>ST6051CEM Practical Cryptography Coursework</h3>

<p><strong>A PKI-based Digital Wallet with Zero-Trust Architecture</strong></p>

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM-red.svg)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-Academic-yellow.svg)](LICENSE)

---

</div>

## 📋 Table of Contents

- [Abstract](#-abstract)
- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
- [Security Implementation](#-security-implementation)
- [Project Structure](#-project-structure)
- [Installation Guide](#-installation-guide)
- [Usage Documentation](#-usage-documentation)
- [Cryptographic Stack](#-cryptographic-stack)
- [Testing Framework](#-testing-framework)
- [Technical Specifications](#-technical-specifications)
- [References](#-references)

---

## 📄 Abstract

This project presents a comprehensive implementation of a secure digital wallet system leveraging Public Key Infrastructure (PKI) for authentication and transaction authorization. The system employs a zero-trust security model where every sensitive operation requires cryptographic proof through X.509 digital certificates. The implementation demonstrates practical applications of cryptographic primitives including asymmetric encryption (RSA-2048), symmetric encryption (AES-256-GCM), digital signatures (RSA-PSS with SHA-256), and secure key derivation (PBKDF2-HMAC-SHA256).

The digital wallet provides core financial functionalities such as secure money transfers, balance management, and payment gateway integration, while maintaining strict security guarantees of confidentiality, integrity, authentication, and non-repudiation through cryptographic mechanisms.

---

## 🏗️ System Architecture

<div align="center">
  <img src="https://raw.githubusercontent.com/roseiiitt/Digital-Wallet/main/Architecture_new.jpg" 
       alt="System Architecture Diagram" width="900"/>
</div>

The system architecture follows a three-tier design pattern with enhanced security layers:

**Presentation Layer**: Flask-based web interface with responsive HTML templates and client-side validation.

**Application Layer**: Python backend implementing business logic, cryptographic operations, and zero-trust authentication mechanisms.

**Data Layer**: SQLite database with field-level AES-256-GCM encryption for sensitive data protection.

**Security Layer**: PKI infrastructure with certificate authority, digital signature verification, and encrypted key storage.

---

## ✨ Key Features

### 🔐 Authentication & Authorization
- **PKI-based Authentication**: X.509 certificate verification for every login attempt
- **Zero-Trust Architecture**: Certificate-based authorization for all sensitive operations
- **Multi-Factor Security**: Username + Password + Digital Certificate requirement
- **Account Recovery**: Master key-based certificate regeneration mechanism

### 🔏 Cryptographic Operations
- **Digital Signatures**: RSA-PSS with SHA-256 for transaction non-repudiation
- **Document Signing**: Cryptographically signed transaction receipts
- **Certificate Validation**: Server-side verification against trusted Certificate Authority
- **Encrypted Storage**: AES-256-GCM encryption for all sensitive database fields

### 💰 Financial Operations
- **Secure Transfers**: Atomic database transactions with rollback capabilities
- **Balance Management**: Real-time balance tracking with encryption
- **Payment Integration**: Stripe API integration for fund deposits (sandbox mode)
- **Transaction History**: Complete audit trail with cryptographic signatures

### 🛡️ Security Guarantees
- **Confidentiality**: AES-256-GCM encryption with unique per-user keys
- **Integrity**: SHA-256 hashing and digital signatures for tamper detection
- **Authentication**: Certificate-based identity verification
- **Non-repudiation**: RSA-PSS digital signatures on all transactions

---

## 🔒 Security Implementation

### Database Encryption Model

The system implements field-level encryption with the following security properties:

**Encrypted Fields**:
- User passwords (bcrypt + AES-256-GCM double encryption)
- RSA private keys (PEM format, AES-256-GCM encrypted)
- X.509 certificates (PEM format, AES-256-GCM encrypted)
- Master recovery keys (AES-256-GCM encrypted)

**Unencrypted Fields** (for operational efficiency):
- Username (required for login queries)
- Balance (required for transaction validation)
- Transaction metadata (timestamps, transaction IDs)

### Key Derivation Scheme

Each user has a unique encryption key derived using PBKDF2-HMAC-SHA256:

```
User Encryption Key = PBKDF2(
    password = username,
    salt = 16-byte cryptographic random salt,
    iterations = 100,000,
    hash = SHA-256,
    key_length = 32 bytes
)
```

### Zero-Trust Security Model

Every sensitive operation follows the zero-trust principle:

1. **Login**: Username + Password + Certificate verification
2. **Transfer**: Certificate verification before transaction processing
3. **Password Reset**: Certificate verification before password update
4. **Account Recovery**: Master key verification before certificate regeneration

---

## 📁 Project Structure

```
.
├── Architecture.jpg
├── README.md
├── __pycache__
│   ├── app.cpython-312.pyc
│   └── models.cpython-312.pyc
├── app.py
├── favicon.ico
├── instance
│   └── wallet.db
├── models.py
├── requirements.txt
├── templates
│   ├── base.html
│   ├── dashboard.html
│   ├── download_cert.html
│   ├── fund.html
│   ├── login.html
│   ├── password_reset.html
│   ├── recover.html
│   ├── recovery_info.html
│   ├── register.html
│   └── transfer.html
└── unit_test
    ├── __pycache__
    │   ├── conftest.cpython-312-pytest-9.0.2.pyc
    │   ├── test_auth.cpython-312-pytest-9.0.2.pyc
    │   ├── test_registration.cpython-312-pytest-9.0.2.pyc
    │   ├── test_routes.cpython-312-pytest-9.0.2.pyc
    │   ├── test_transfer_requires_login.cpython-312-pytest-9.0.2.pyc
    │   └── test_wallet.cpython-312-pytest-9.0.2.pyc
    ├── conftest.py
    ├── test_auth.py
    ├── test_registration.py
    ├── test_routes.py
    ├── test_transfer_requires_login.py
    └── test_wallet.py

6 directories, 31 files
```

### Component Descriptions

| Component | Purpose |
|-----------|---------|
| `app.py` | Main Flask application with routing and request handling |
| `models.py` | Database models and cryptographic utility functions |
| `templates/` | Jinja2 HTML templates for web interface |
| `unit_test/` | Comprehensive pytest test suite |
| `instance/wallet.db` | SQLite database with encrypted user data |
| `requirements.txt` | Python package dependencies |
| `Architecture.jpg` | System architecture diagram |

---

## 🚀 Installation Guide

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git version control system
- OpenSSL (for cryptographic operations)

### Step 1: Clone Repository

```bash
git clone https://github.com/roseiiitt/Digital-Wallet.git
cd Digital-Wallet
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- Flask (web framework)
- Flask-SQLAlchemy (ORM)
- cryptography (cryptographic operations)
- bcrypt (password hashing)
- stripe (payment processing)
- pytest (testing framework)

### Step 4: Configure Environment Variables

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key-here
STRIPE_PUBLIC_KEY=your-stripe-public-key
STRIPE_SECRET_KEY=your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=your-webhook-secret
```

### Step 5: Initialize Database

```bash
# The database will be created automatically on first run
python app.py
```

### Step 6: Run Application

```bash
python app.py
```

Access the application at: `http://localhost:5000`

---

## 📖 Usage Documentation

### User Registration

1. Navigate to the registration page
2. Enter username (minimum 5 characters)
3. Enter password (minimum 8 characters)
4. Click "Register"
5. **CRITICAL**: Save your Master Key securely
6. Download your digital certificate (.pem file)
7. Store both securely for account recovery

### User Login

1. Enter username and password
2. Paste your digital certificate in PEM format
3. Click "Login"
4. Certificate is verified against stored certificate
5. Access granted upon successful verification

### Money Transfer

1. Navigate to "Transfer" page
2. Enter recipient username
3. Enter transfer amount
4. Paste your digital certificate for authorization
5. Transaction is processed and signed
6. Both parties receive cryptographically signed receipts

### Account Recovery

If you lose your digital certificate:

1. Navigate to "Recover Account"
2. Enter your username
3. Enter your Master Key (saved during registration)
4. New certificate is generated
5. Download new certificate
6. Update stored certificate for future logins

### Password Reset

1. Navigate to "Forgot Password"
2. Enter username and new password
3. Paste your digital certificate for verification
4. Password is reset upon certificate validation

### Adding Funds

1. Click "Add Funds" on dashboard
2. Redirected to Stripe payment page (sandbox mode)
3. Use test card: `4242 4242 4242 4242`
4. Enter any future expiry date and CVC
5. Complete payment
6. Funds credited to wallet balance

---

## 🔐 Cryptographic Stack

### Asymmetric Encryption
- **Algorithm**: RSA with 2048-bit key size
- **Key Generation**: cryptography.io's RSA key generation
- **Serialization**: PEM format with no encryption (encrypted separately with AES-256-GCM)

### Symmetric Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits
- **Nonce**: 96-bit random nonce per encryption
- **Authentication**: Built-in AEAD authentication tag

### Digital Signatures
- **Algorithm**: RSA-PSS (Probabilistic Signature Scheme)
- **Hash Function**: SHA-256
- **Salt Length**: PSS.MAX_LENGTH
- **Padding**: PSS padding with MGF1

### Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000
- **Salt**: 16-byte cryptographic random salt per user
- **Output**: 256-bit encryption key

### Password Hashing
- **Algorithm**: bcrypt
- **Work Factor**: 12 rounds
- **Salt**: Automatically generated per password

### X.509 Certificates
- **Subject**: Username as Common Name (CN)
- **Validity**: 365 days
- **Serial Number**: Cryptographic random
- **Signature Algorithm**: SHA-256 with RSA

---

## 🧪 Testing Framework

The project includes comprehensive unit tests using pytest:

### Test Coverage

| Test Module | Coverage |
|-------------|----------|
| `test_registration.py` | User registration, certificate generation |
| `test_auth.py` | Login, certificate verification, zero-trust |
| `test_wallet.py` | Money transfers, balance management |
| `test_routes.py` | Flask route testing, HTTP responses |
| `test_transfer_requires_login.py` | Authorization checks |

### Running Tests

```bash
# Run all tests
pytest unit_test/

# Run specific test file
pytest unit_test/test_auth.py

# Run with verbose output
pytest unit_test/ -v

# Run with coverage report
pytest unit_test/ --cov=.
```

### Test Scenarios

**Security Tests**:
- Certificate tampering detection
- Invalid certificate rejection
- Master key validation
- Password strength enforcement

**Functional Tests**:
- User registration workflow
- Login with certificate
- Money transfer with insufficient balance
- Payment gateway integration (sandbox)
- Account recovery mechanism

**Edge Cases**:
- Duplicate username registration
- Transfer to non-existent user
- Negative amount transfers
- Database transaction rollback

---

## 📊 Technical Specifications

### System Requirements

| Component | Specification |
|-----------|---------------|
| **Python Version** | 3.8+ (tested on 3.12) |
| **Database** | SQLite 3.x |
| **Web Server** | Flask development server |
| **Cryptography Library** | cryptography 42.x+ |
| **Memory** | Minimum 512 MB RAM |
| **Storage** | 50 MB for application + database |

### Performance Characteristics

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| User Registration | O(1) + Key Generation | ~200ms including RSA key generation |
| Login Verification | O(1) + Certificate Verification | ~50ms for database + cryptography |
| Money Transfer | O(1) + Signature Generation | ~100ms including digital signature |
| Database Encryption | O(n) per field | AES-256-GCM encryption overhead |

### Security Parameters

| Parameter | Value | Standard |
|-----------|-------|----------|
| RSA Key Size | 2048 bits | NIST SP 800-57 |
| AES Key Size | 256 bits | FIPS 197 |
| PBKDF2 Iterations | 100,000 | OWASP recommendation |
| bcrypt Work Factor | 12 rounds | OWASP recommendation |
| Certificate Validity | 365 days | Configurable |

---

## 📚 References

### Academic Standards
- NIST Special Publication 800-57: Recommendation for Key Management
- FIPS 197: Advanced Encryption Standard (AES)
- RFC 5280: Internet X.509 Public Key Infrastructure Certificate
- RFC 8017: PKCS #1 RSA Cryptography Specifications

### Libraries & Frameworks
- [Python Cryptography Library](https://cryptography.io/)
- [Flask Web Framework](https://flask.palletsprojects.com/)
- [SQLAlchemy ORM](https://www.sqlalchemy.org/)
- [Stripe Payment API](https://stripe.com/docs/api)

### Security Best Practices
- OWASP Top 10 Security Risks
- Zero Trust Security Model (NIST SP 800-207)
- PKI Best Practices (CA/Browser Forum)

---

<div align="center">

## 👨‍🎓 Course Information

**Module**: ST6051CEM Practical Cryptography  
**Institution**: Softwartica College of IT & E-Commerce  
**In Collaboration With**: Coventry University  

© 2026 Softwartica College of IT & E-Commerce in collaboration with Coventry University. All rights reserved.

</div>
