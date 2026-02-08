from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import datetime
import secrets
import os

db = SQLAlchemy()

class CertificateAuthority:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureWallet Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureWallet PKI")
        ])
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )

    def issue_certificate(self, user_public_key, user_id):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureWallet User")
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(user_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )
        return cert

# Global CA instance
ca = CertificateAuthority()

def derive_encryption_key(master_password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from master password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def encrypt_data(plaintext: str, key: bytes) -> bytes:
    """Encrypt data with AES-256-GCM"""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data with AES-256-GCM"""
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Encrypted fields
    encrypted_password_hash = db.Column(db.LargeBinary, nullable=False)
    encrypted_private_key_pem = db.Column(db.LargeBinary, nullable=False)
    encrypted_certificate_pem = db.Column(db.LargeBinary, nullable=False)
    encrypted_master_key = db.Column(db.LargeBinary, nullable=False)
    # Salt for key derivation
    encryption_salt = db.Column(db.LargeBinary, nullable=False)
    # Balance remains unencrypted for queries
    balance = db.Column(db.Float, default=0.0)
    
    def __init__(self, username):
        super().__init__()
        self.username = username
        # Generate unique salt for this user
        self.encryption_salt = os.urandom(16)
    
    def _get_encryption_key(self) -> bytes:
        """Get encryption key derived from username (in production, use user password)"""
        # In production, this should be derived from user's password + salt
        # For demo, we use username as the "master password"
        return derive_encryption_key(self.username, self.encryption_salt)
    
    def set_password(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        password_hash = generate_password_hash(password)
        key = self._get_encryption_key()
        self.encrypted_password_hash = encrypt_data(password_hash, key)
    
    def check_password(self, password):
        key = self._get_encryption_key()
        try:
            stored_hash = decrypt_data(self.encrypted_password_hash, key)
            return check_password_hash(stored_hash, password)
        except Exception:
            return False
    
    def get_private_key_pem(self) -> str:
        """Get decrypted private key PEM"""
        key = self._get_encryption_key()
        return decrypt_data(self.encrypted_private_key_pem, key)
    
    def get_certificate_pem(self) -> str:
        """Get decrypted certificate PEM"""
        key = self._get_encryption_key()
        return decrypt_data(self.encrypted_certificate_pem, key)
    
    def get_master_key(self) -> str:
        """Get decrypted master key"""
        key = self._get_encryption_key()
        return decrypt_data(self.encrypted_master_key, key)
    
    def generate_keys_and_cert(self):
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Issue certificate
        cert = ca.issue_certificate(public_key, self.username)
        
        # Store PEM formats (encrypted)
        key = self._get_encryption_key()
        self.encrypted_private_key_pem = encrypt_data(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            key
        )
        
        self.encrypted_certificate_pem = encrypt_data(
            cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            key
        )
        
        # Generate and store master key (encrypted)
        master_key = secrets.token_hex(32)
        self.encrypted_master_key = encrypt_data(master_key, key)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    transaction_id = db.Column(db.String(50), unique=True, nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])