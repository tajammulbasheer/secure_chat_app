import pytest
import os
import datetime
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption, load_pem_public_key
)
from cryptography.exceptions import InvalidSignature, InvalidTag
from shared.crypto_utils import (
    aes_encrypt, aes_decrypt,
    encrypt_for_cert, decrypt_with_private_key,
    sign_nonce, verify_signature,
    verify_certificate, extract_common_name,
    generate_nonce,
    generate_mac, verify_mac,
    generate_ephemeral_keypair, derive_pfs_session_key,
    get_interval_key
)

@pytest.fixture
def temp_keys_and_certs(tmp_path):
    """Generates a temporary self-signed Root CA, and a client key and certificate signed by it."""
    # 1. Generate Root CA key and self-signed certificate
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .sign(ca_key, hashes.SHA256())
    )
    
    ca_path = tmp_path / "ca.pem"
    with open(ca_path, "wb") as f:
        f.write(ca_cert.public_bytes(Encoding.PEM))
        
    # 2. Generate client key and sign certificate with Root CA
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key_path = tmp_path / "client.key"
    with open(client_key_path, "wb") as f:
        f.write(client_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
        
    # Client key with password
    client_key_pw_path = tmp_path / "client_pw.key"
    with open(client_key_pw_path, "wb") as f:
        f.write(client_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(b"testpass")
        ))
        
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
    ])
    
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=5))
        .sign(ca_key, hashes.SHA256())
    )
    
    client_pem = client_cert.public_bytes(Encoding.PEM).decode()
    
    return {
        "ca_path": ca_path,
        "ca_cert": ca_cert,
        "ca_key": ca_key,
        "client_key_path": client_key_path,
        "client_key_pw_path": client_key_pw_path,
        "client_cert_pem": client_pem,
        "client_key": client_key,
        "client_cert": client_cert
    }

def test_aes_gcm():
    """Verify AES-GCM encryption and decryption with and without Associated Data."""
    key = os.urandom(32)
    plaintext = b"Hello, this is a secret message!"
    associated_data = b"metadata-alice-to-bob"
    
    # Test encryption/decryption with Associated Data
    nonce_b64, ciphertext_b64 = aes_encrypt(key, plaintext, associated_data)
    decrypted = aes_decrypt(key, nonce_b64, ciphertext_b64, associated_data)
    assert decrypted == plaintext
    
    # Test encryption/decryption without Associated Data
    nonce_b64_no_ad, ciphertext_b64_no_ad = aes_encrypt(key, plaintext)
    decrypted_no_ad = aes_decrypt(key, nonce_b64_no_ad, ciphertext_b64_no_ad)
    assert decrypted_no_ad == plaintext
    
    # Test failure on decryption with wrong key
    wrong_key = os.urandom(32)
    with pytest.raises(InvalidTag):
        aes_decrypt(wrong_key, nonce_b64, ciphertext_b64, associated_data)
        
    # Test failure on decryption with wrong Associated Data
    with pytest.raises(InvalidTag):
        aes_decrypt(key, nonce_b64, ciphertext_b64, b"wrong-metadata")
        
    # Test failure on decryption with modified ciphertext
    ciphertext = base64.b64decode(ciphertext_b64)
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 1 # flip one bit
    modified_ciphertext_b64 = base64.b64encode(modified_ciphertext).decode()
    with pytest.raises(InvalidTag):
        aes_decrypt(key, nonce_b64, modified_ciphertext_b64, associated_data)

def test_rsa_operations(temp_keys_and_certs):
    """Verify RSA sign/verify and encrypt/decrypt functions."""
    data = temp_keys_and_certs
    nonce = b"challenge_nonce_12345"
    
    # 1. Sign and Verify Nonce
    # Without passphrase
    sig_b64 = sign_nonce(data["client_key_path"], nonce)
    verify_signature(data["client_cert_pem"], nonce, sig_b64)
    
    # With passphrase
    sig_pw_b64 = sign_nonce(data["client_key_pw_path"], nonce, password=b"testpass")
    verify_signature(data["client_cert_pem"], nonce, sig_pw_b64)
    
    # Verify signature failure with modified signature
    sig = base64.b64decode(sig_b64)
    modified_sig = bytearray(sig)
    modified_sig[0] ^= 1
    modified_sig_b64 = base64.b64encode(modified_sig).decode()
    with pytest.raises(InvalidSignature):
        verify_signature(data["client_cert_pem"], nonce, modified_sig_b64)
        
    # Verify signature failure with modified nonce
    with pytest.raises(InvalidSignature):
        verify_signature(data["client_cert_pem"], b"tampered_nonce_12345", sig_b64)

    # 2. Encrypt for Cert and Decrypt with Private Key
    plaintext = b"Confidential payload"
    encrypted_b64 = encrypt_for_cert(data["client_cert_pem"], plaintext)
    decrypted = decrypt_with_private_key(data["client_key_path"], encrypted_b64)
    assert decrypted == plaintext
    
    # Decrypt with key password
    encrypted_pw_b64 = encrypt_for_cert(data["client_cert_pem"], plaintext)
    decrypted_pw = decrypt_with_private_key(data["client_key_pw_path"], encrypted_pw_b64, password=b"testpass")
    assert decrypted_pw == plaintext

def test_certificate_validation(temp_keys_and_certs, tmp_path):
    """Verify verify_certificate returns True for valid chain, False for expired/invalid/tampered."""
    data = temp_keys_and_certs
    
    # Valid certificate signed by CA
    assert verify_certificate(data["client_cert_pem"], data["ca_path"]) is True
    
    # Extract common name verification
    assert extract_common_name(data["client_cert_pem"]) == "Alice"
    
    # 1. Verification fails: Certificate is expired (validity range in the past)
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(data["client_cert"].subject)
        .issuer_name(data["ca_cert"].subject)
        .public_key(data["client_key"].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=5)) # Expired
        .sign(data["ca_key"], hashes.SHA256())
    )
    expired_pem = expired_cert.public_bytes(Encoding.PEM).decode()
    assert verify_certificate(expired_pem, data["ca_path"]) is False
    
    # 2. Verification fails: Certificate is not yet valid (validity in future)
    future_cert = (
        x509.CertificateBuilder()
        .subject_name(data["client_cert"].subject)
        .issuer_name(data["ca_cert"].subject)
        .public_key(data["client_key"].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=5)) # Future
        .not_valid_after(now + datetime.timedelta(days=10))
        .sign(data["ca_key"], hashes.SHA256())
    )
    future_pem = future_cert.public_bytes(Encoding.PEM).decode()
    assert verify_certificate(future_pem, data["ca_path"]) is False

    # 3. Verification fails: Issuer name mismatch
    wrong_issuer_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Mismatched CA name"),
    ])
    mismatched_issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(data["client_cert"].subject)
        .issuer_name(wrong_issuer_subject) # Issuer != CA subject
        .public_key(data["client_key"].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=5))
        .sign(data["ca_key"], hashes.SHA256())
    )
    mismatched_issuer_pem = mismatched_issuer_cert.public_bytes(Encoding.PEM).decode()
    assert verify_certificate(mismatched_issuer_pem, data["ca_path"]) is False

    # 4. Verification fails: Signed by untrusted/different CA
    rogue_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(data["client_cert"].subject)
        .issuer_name(data["ca_cert"].subject)
        .public_key(data["client_key"].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=5))
        .sign(rogue_ca_key, hashes.SHA256()) # Signed by rogue_ca_key, but verify_certificate expects signature signed by root CA key
    )
    rogue_pem = rogue_cert.public_bytes(Encoding.PEM).decode()
    assert verify_certificate(rogue_pem, data["ca_path"]) is False

def test_ecdhe_key_derivation():
    """Verify ephemeral keypair generation and shared session key derivation via ECDH."""
    # Generate A's keypair
    priv_a, pub_a_b64 = generate_ephemeral_keypair()
    assert isinstance(priv_a, ec.EllipticCurvePrivateKey)
    assert isinstance(pub_a_b64, str)
    
    # Decode pub_a to verify it's valid PEM
    pub_a_bytes = base64.b64decode(pub_a_b64)
    pub_a = load_pem_public_key(pub_a_bytes)
    assert isinstance(pub_a, ec.EllipticCurvePublicKey)
    
    # Generate B's keypair
    priv_b, pub_b_b64 = generate_ephemeral_keypair()
    assert isinstance(priv_b, ec.EllipticCurvePrivateKey)
    assert isinstance(pub_b_b64, str)
    
    # Derive PFS keys on both ends
    key_a = derive_pfs_session_key(priv_a, pub_b_b64)
    key_b = derive_pfs_session_key(priv_b, pub_a_b64)
    
    # Assert keys match and are 32 bytes
    assert len(key_a) == 32
    assert len(key_b) == 32
    assert key_a == key_b
    
    # Verification with invalid/malformed public key
    with pytest.raises(Exception):
        derive_pfs_session_key(priv_a, "invalid_base64_string")

def test_hmac_and_helpers():
    """Verify HMAC generation/verification, nonces, and interval key ratcheting."""
    # 1. Nonces
    nonce = generate_nonce()
    assert isinstance(nonce, bytes)
    assert len(nonce) == 16
    assert nonce != generate_nonce() # Should be random
    
    # 2. HMAC MAC verification
    key = os.urandom(32)
    message = b"Important payload structure"
    mac = generate_mac(key, message)
    assert isinstance(mac, str)
    
    assert verify_mac(key, message, mac) is True
    assert verify_mac(key, message + b"modified", mac) is False
    assert verify_mac(key, message, mac[:-1] + ("0" if mac[-1] != "0" else "1")) is False
    assert verify_mac(os.urandom(32), message, mac) is False
    
    # 3. Interval key ratcheting
    root_key = os.urandom(32)
    key_int_0 = get_interval_key(root_key, 0)
    key_int_1 = get_interval_key(root_key, 1)
    
    assert len(key_int_0) == 32
    assert len(key_int_1) == 32
    assert key_int_0 != key_int_1
    assert key_int_0 == get_interval_key(root_key, 0) # Deterministic
