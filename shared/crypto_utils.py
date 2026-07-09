from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key, load_pem_private_key
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
import os
import base64
import hmac
import hashlib


def aes_encrypt(key, plaintext: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return base64.b64encode(nonce).decode(), base64.b64encode(ciphertext).decode()

def aes_decrypt(key, nonce_b64, ciphertext_b64, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

def encrypt_for_cert(cert_pem, data):
    cert = load_pem_x509_certificate(cert_pem.encode())
    public_key = cert.public_key()

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted).decode()


def decrypt_with_private_key(private_key_path, encrypted_b64, password=None):
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=password)

    encrypted = base64.b64decode(encrypted_b64)
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign_nonce(private_key_path, nonce, password=None):
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=password)

    signature = private_key.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()



def extract_common_name(cert_pem):
    cert = load_pem_x509_certificate(cert_pem.encode())
    subject = cert.subject
    cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return cn
def generate_nonce():
    return os.urandom(16)



def verify_signature(cert_pem, nonce, signature_b64):
    cert = load_pem_x509_certificate(cert_pem.encode())
    public_key = cert.public_key()

    signature = base64.b64decode(signature_b64)

    public_key.verify(
        signature,
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_certificate(cert_pem, ca_path):
    import datetime
    try:
        cert = load_pem_x509_certificate(cert_pem.encode())
        with open(ca_path, "rb") as f:
            ca_cert = load_pem_x509_certificate(f.read())

        # 1. Verify validity period (supports tz-aware and naive datetimes)
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Fallback to naive if properties are naive (older cryptography versions)
        cert_not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        cert_not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        
        if cert_not_before.tzinfo is None:
            now = datetime.datetime.utcnow()

        if now < cert_not_before or now > cert_not_after:
            print("[SECURITY WARNING] Certificate is expired or not yet valid.")
            return False

        # 2. Check issuer name matches CA subject name
        if cert.issuer != ca_cert.subject:
            print("[SECURITY WARNING] Certificate issuer does not match CA subject.")
            return False

        # 3. Verify signature using CA's public key
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception as e:
        print(f"[SECURITY WARNING] Certificate validation error: {e}")
        return False

def generate_mac(key: bytes, message: bytes) -> str:
    """Generates an HMAC-SHA256 signature for the message using the session key."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_mac(key: bytes, message: bytes, expected_mac: str) -> bool:
    """Safely compares the generated MAC against the expected MAC."""
    return hmac.compare_digest(generate_mac(key, message), expected_mac)


def generate_ephemeral_keypair():
    """Generates a temporary Elliptic Curve keypair (SECP256R1) and returns (private_key, public_key_b64)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Serialize public key to PEM format
    public_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_bytes).decode()
    return private_key, public_key_b64

def derive_pfs_session_key(my_private_key, peer_public_key_b64: str) -> bytes:
    """Combines my private ephemeral key with peer's public ephemeral key to derive AES key."""
    peer_public_bytes = base64.b64decode(peer_public_key_b64)
    peer_public_key = load_pem_public_key(peer_public_bytes)
    
    # 1. Perform ECDH to get the shared secret
    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)
    
    # 2. Use HKDF to cleanly expand the secret into a 32-byte AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure_chat_pfs_key_exchange',
    ).derive(shared_secret)
    
    return derived_key

def get_interval_key(root_key: bytes, interval_index: int) -> bytes:
    """
    Derives a specific AES key for a given message interval. 
    Tying the KDF to the interval_index makes it immune to dropped packets.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"chat_interval_{interval_index}".encode()
    )
    return hkdf.derive(root_key)

