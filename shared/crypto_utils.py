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

# Maximum number of skipped message keys to cache (DoS protection)
MAX_SKIP = 100

# ================================================================
# DOUBLE RATCHET — Symmetric KDF Chain
# ================================================================

def _kdf_chain_step(chain_key: bytes):
    """
    Single KDF chain step (Signal-style symmetric ratchet).

    Returns:
        (next_chain_key, message_key)

    The chain key is advanced via HMAC-SHA256(chain_key, 0x01).
    The message key is derived via HMAC-SHA256(chain_key, 0x02).
    The message key is used exactly once and then discarded.
    """
    next_chain_key = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
    message_key    = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
    return next_chain_key, message_key


class RatchetState:
    """
    Symmetric-chain Double Ratchet state machine.

    After ECDH key agreement, both peers seed an identical pair of KDF chains
    (send and recv) from the shared secret. Each message advances the send
    chain on the sender side and the recv chain on the receiver side.

    Forward secrecy is achieved because HMAC-SHA256 is a one-way function:
    a compromised chain key cannot recover any prior message key.
    """

    def __init__(self, send_chain: bytes, recv_chain: bytes, root_key: bytes):
        self.root_key   = root_key
        self.send_chain = send_chain
        self.recv_chain = recv_chain
        self.send_n     = 0          # next send counter
        self.recv_n     = 0          # next expected recv counter
        self.skipped    = {}         # counter → message_key (for out-of-order)

    @classmethod
    def from_shared_secret(cls, shared_secret: bytes, initiator: bool):
        """
        Derive two independent chain keys from the ECDH shared secret.

        The initiator (Alice) and responder (Bob) swap send/recv roles
        so that Alice.send_chain == Bob.recv_chain and vice versa.
        """
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_chat_ratchet_root',
        ).derive(shared_secret)

        chain_a = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_chat_ratchet_chain_a',
        ).derive(root_key)

        chain_b = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_chat_ratchet_chain_b',
        ).derive(root_key)

        if initiator:
            return cls(send_chain=chain_a, recv_chain=chain_b, root_key=root_key)
        else:
            return cls(send_chain=chain_b, recv_chain=chain_a, root_key=root_key)

    # ---- SEND ----

    def next_encrypt_key(self):
        """
        Advance the send chain by one step.

        Returns:
            (message_key, counter) — the one-time AES key and its sequence number.

        The previous chain key is irreversibly replaced.
        """
        self.send_chain, msg_key = _kdf_chain_step(self.send_chain)
        counter = self.send_n
        self.send_n += 1
        return msg_key, counter

    # ---- RECEIVE ----

    def next_decrypt_key(self, counter: int):
        """
        Derive the message key for `counter`.

        Handles three cases:
        1. counter == recv_n → normal in-order message
        2. counter > recv_n  → out-of-order; cache skipped keys up to MAX_SKIP
        3. counter < recv_n  → check the skipped-key cache

        Returns:
            message_key (bytes)

        Raises:
            ValueError on replay (already consumed) or excessive skip gap.
        """
        # Case 3: Already-skipped key that was cached
        if counter in self.skipped:
            msg_key = self.skipped.pop(counter)
            return msg_key

        # Case 3b: Old message we already processed (replay)
        if counter < self.recv_n:
            raise ValueError(
                f"Replay or duplicate: counter {counter} < recv_n {self.recv_n} "
                f"and not in skipped cache."
            )

        # Case 2: Future message — skip ahead (cache intermediate keys)
        skip_count = counter - self.recv_n
        if skip_count > MAX_SKIP:
            raise ValueError(
                f"Refusing to skip {skip_count} messages (max {MAX_SKIP}). "
                f"Possible DoS attempt."
            )

        while self.recv_n < counter:
            self.recv_chain, skipped_key = _kdf_chain_step(self.recv_chain)
            self.skipped[self.recv_n] = skipped_key
            self.recv_n += 1

        # Case 1: Now recv_n == counter — consume normally
        self.recv_chain, msg_key = _kdf_chain_step(self.recv_chain)
        self.recv_n += 1
        return msg_key

    # ---- CLEANUP ----

    def clear(self):
        """Zeroize all sensitive key material."""
        self.root_key   = b'\x00' * 32
        self.send_chain = b'\x00' * 32
        self.recv_chain = b'\x00' * 32
        self.skipped.clear()
        self.send_n = 0
        self.recv_n = 0


# ================================================================
# SAFETY NUMBERS — Signal-style 60-digit fingerprint
# ================================================================

def _iterative_hash(pub_key_bytes: bytes, identifier: str, iterations: int = 5200) -> bytes:
    """
    Compute an iterated SHA-512 fingerprint for one party.

    Signal spec: hash = SHA-512(pub_key + UTF-8(identifier))  repeated `iterations` times,
    using the output of each round as input to the next. Returns the first 30 bytes.
    """
    data = pub_key_bytes + identifier.encode('utf-8')
    for _ in range(iterations):
        data = hashlib.sha512(data).digest()
    return data[:30]


def _encode_fingerprint(raw_bytes: bytes) -> str:
    """
    Encode 30 bytes as 12 groups of 5 decimal digits (60 digits total).

    Each group is derived from 5 consecutive bytes: int.from_bytes(chunk, 'big') % 100000.
    """
    digits = []
    for i in range(0, 30, 5):
        chunk = raw_bytes[i:i + 5]
        # Interpret 5 bytes as a big-endian integer, mod 100000 → 5 decimal digits
        value = int.from_bytes(chunk, 'big') % 100000
        digits.append(f"{value:05d}")
    return " ".join(digits)


def compute_safety_number(my_cert_pem: str, my_username: str,
                          peer_cert_pem: str, peer_username: str) -> str:
    """
    Compute a deterministic 60-digit Safety Number from both peers' certificate
    public keys, following the Signal fingerprint specification.

    The result is identical regardless of which peer calls this function,
    because the two per-party fingerprints are combined in sorted order.

    Returns:
        A string of 60 decimal digits in 12 groups of 5, e.g.:
        "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
    """
    my_cert   = load_pem_x509_certificate(my_cert_pem.encode())
    peer_cert = load_pem_x509_certificate(peer_cert_pem.encode())

    my_pub_bytes   = my_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    peer_pub_bytes = peer_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    my_fp   = _iterative_hash(my_pub_bytes, my_username)
    peer_fp = _iterative_hash(peer_pub_bytes, peer_username)

    # Deterministic ordering: lexicographically sort so both peers get the same result
    if (my_username, my_fp) <= (peer_username, peer_fp):
        combined = my_fp + peer_fp
    else:
        combined = peer_fp + my_fp

    # Encode each 30-byte half separately, then join
    first_half  = _encode_fingerprint(combined[:30])
    second_half = _encode_fingerprint(combined[30:])
    return first_half + " " + second_half


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

def derive_shared_secret(my_private_key, peer_public_key_b64: str) -> bytes:
    """Performs ECDH key exchange and returns the raw shared secret.
    
    The caller should feed this into RatchetState.from_shared_secret() for
    direct sessions, or derive a static key for group sessions.
    """
    peer_public_bytes = base64.b64decode(peer_public_key_b64)
    peer_public_key = load_pem_public_key(peer_public_bytes)
    return my_private_key.exchange(ec.ECDH(), peer_public_key)


def derive_pfs_session_key(my_private_key, peer_public_key_b64: str) -> bytes:
    """DEPRECATED — kept for group session backward compatibility.
    Use derive_shared_secret() + RatchetState.from_shared_secret() for direct sessions.
    """
    shared_secret = derive_shared_secret(my_private_key, peer_public_key_b64)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure_chat_pfs_key_exchange',
    ).derive(shared_secret)
    return derived_key

def get_interval_key(root_key: bytes, interval_index: int) -> bytes:
    """DEPRECATED — kept for group session backward compatibility.
    Direct sessions now use RatchetState for per-message key derivation.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"chat_interval_{interval_index}".encode()
    )
    return hkdf.derive(root_key)
