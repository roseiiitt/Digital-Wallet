🔐 Secure Digital Wallet with PKI & Zero-Trust Security
=======================================================

A fully functional digital wallet implementation that uses Public Key Infrastructure (PKI) for user authentication and secure document signing. The system ensures confidentiality, integrity, and authentication through cryptographic primitives including digital certificates, digital signatures, and asymmetric encryption.

🎯 Features
-----------

### ✅ **User Authentication**

*   **PKI-based authentication** using X.509 certificates
    
*   **Username requirements**: Minimum 5 characters
    
*   **Password requirements**: Minimum 8 characters
    
*   **Zero-trust login**: Requires username + password + certificate
    
*   **Master key recovery**: Account recovery if certificate is lost
    

### ✅ **Document Signing & Verification**

*   **Digital signatures** using RSA-PSS with SHA-256
    
*   **Transaction receipts** with non-repudiable signatures
    
*   **Certificate validation** against trusted Certificate Authority
    

### ✅ **Security Features**

*   **AES-256-GCM encryption** for all sensitive database fields
    
*   **Zero-trust architecture**: Every sensitive operation requires certificate verification
    
*   **Encrypted storage**: Passwords, private keys, certificates, and master keys encrypted at rest
    
*   **Unique per-user encryption keys** derived from username + salt
    

### ✅ **Financial Operations**

*   **Secure money transfers** between users
    
*   **Balance management** with atomic database transactions
    
*   **Transaction history** with complete audit trail
    
*   **Stripe integration** for adding funds via payment processing
    

### ✅ **Web Interface**

*   **Responsive web application** using Flask
    
*   **Complete user workflow**: Registration → Login → Transfer → Recovery
    
*   **Professional UI** with proper error handling and security warnings
    

🛠️ Technology Stack
--------------------

ComponentTechnology**Backend**Python 3.12, Flask**Database**SQLite with AES-256-GCM encryption**Cryptography**cryptography.io library**Frontend**HTML5, CSS3, Jinja2 templates**Payment**Stripe API (sandbox mode)**Security**PKI, X.509 certificates, RSA-2048, AES-256-GCM

📁 Project Structure
--------------------

secure-digital-wallet/
├── app.py                 # Main Flask application
├── models.py              # Database models and cryptographic functions
├── requirements.txt       # Dependencies
├── .env                   # Environment variables (gitignored)
├── .gitignore             # Git ignore file
└── templates/             # HTML templates
    ├── base.html
    ├── register.html
    ├── login.html
    ├── dashboard.html
    ├── transfer.html
    ├── recovery_info.html
    ├── recover.html
    ├── password_reset.html
    └── fund.html

🚀 Installation & Setup
-----------------------

### Prerequisites

*   Python 3.8+
    
*   pip package manager
    

### Step 1: Clone the Repository
git clone <repository-url>
cd <directory>

### Step 2: Install Dependencies
pip install -r requirements.txt

### Step 3: Configure Stripe (Optional)

1.  Create a [Stripe account](https://stripe.com/)
    
2.  Get your test API keys from the [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
    
3.  Create a .env file in the project root:

### Step 4: Run the Application
python gui/app.py

### Step 5: Access the Application

Open your browser and navigate to:
http://localhost:5000


🧪 Usage Guide
--------------

### 1\. User Registration

1.  Click "Register"
    
2.  Enter username (min 5 chars) and password (min 8 chars)
    
3.  **Save your Master Key and Certificate** - these are critical for account recovery!
    
4.  Download your certificate (.pem file)
    

### 2\. User Login

1.  Enter username and password
    
2.  **Paste your certificate** in PEM format (required for zero-trust authentication)
    
3.  Access your dashboard
    

### 3\. Money Transfer

1.  Go to "Transfer" page
    
2.  Enter recipient username and amount
    
3.  **Paste your certificate** for transaction authorization
    
4.  Transaction is processed with dual receipt generation
    

### 4\. Account Recovery

1.  If you lose your certificate, go to "Recover Account"
    
2.  Enter your username and **Master Key**
    
3.  New certificate is generated and available for download
    

### 5\. Password Reset

1.  Go to "Forgot Password"
    
2.  Enter username, new password, and **certificate**
    
3.  Password is reset with certificate verification
    

### 6\. Add Funds

1.  Click "Add Funds"
    
2.  You'll be redirected to Stripe sandbox
    
3.  Use test card: 4242 4242 4242 4242
    
4.  Funds are added to your wallet upon successful payment
    

🔒 Security Architecture
------------------------

### Database Encryption

All sensitive data is encrypted using AES-256-GCM:

*   **Encrypted fields**: Password hashes, private keys, certificates, master keys
    
*   **Unencrypted fields**: Username (for login queries), balance (for efficient operations)
    
*   **Key derivation**: PBKDF2-HMAC-SHA256 with unique salt per user
    

### Zero-Trust Principles

*   **Never trust, always verify**: Every sensitive operation requires certificate proof
    
*   **Minimal session data**: Only user ID stored in session
    
*   **Certificate validation**: Byte-by-byte comparison with stored certificates
    

📊 Testing
----------

The application includes comprehensive testing scenarios:

### Security Tests

*   Certificate validation and tampering detection
    
*   Password strength enforcement
    
*   Username uniqueness validation
    
*   Master key recovery functionality
    

### Functional Tests

*   User registration and certificate generation
    
*   Zero-trust login with certificate verification
    
*   Money transfer with balance validation
    
*   Stripe payment integration (sandbox mode)
    
*   Password reset with certificate authentication
    

### Error Handling

*   Proper error messages for invalid certificates
    
*   Graceful handling of database errors
    
*   User-friendly validation messages
    

📝 Documentation
----------------

### Technical Documentation

*   **Architecture diagram**: JSON format for Nano Banana import
    
*   **Gantt chart**: Complete project timeline with milestones
    
*   **Cryptographic stack**: Detailed algorithm explanations
    
*   **API endpoints**: All Flask routes documented
    

### User Documentation

*   **Registration guide**: Step-by-step account creation
    
*   **Certificate management**: How to save and use certificates
    
*   **Security best practices**: Master key storage recommendations
    
*   **Troubleshooting**: Common issues and solutions
    
