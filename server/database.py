"""
database.py — SQLite backend with AES-256-GCM column encryption for the STS server.

Schema (sts.db):
    users           — registered usernames
    banned_users    — banned / revoked usernames
    certificates    — username → (serial_hex, encrypted cert_pem)
    revoked_serials — CRL entries (certificate revocation list)

Encryption:
    The ``cert_pem`` column is encrypted with AES-256-GCM.
    The 32-byte column key is derived from MASTER_PASSWORD_HASH via HKDF-SHA256
    using the domain-separation label ``sts-db-v1 / column-encryption``.
    Each value gets a fresh 12-byte random nonce; the stored blob is:
        nonce (12 B) ‖ ciphertext+tag (N + 16 B)

Thread safety:
    A single shared ``sqlite3.Connection`` is used with ``check_same_thread=False``
    and WAL journal mode.  Every public function acquires ``_lock`` (threading.RLock)
    before touching the connection, so concurrent server threads are safe.
"""

import os
import sqlite3
import threading
import time
import logging
from typing import Dict, Optional, Set

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("STS.database")

# ── Module-level state ────────────────────────────────────────────────────────
_conn: Optional[sqlite3.Connection] = None
_db_key: Optional[bytes] = None
_lock = threading.RLock()

# ── Schema DDL ────────────────────────────────────────────────────────────────
_DDL = """
CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,   -- lowercase; plain text (identity / index key)
    created_at REAL NOT NULL       -- Unix timestamp
);

CREATE TABLE IF NOT EXISTS banned_users (
    username   TEXT PRIMARY KEY,   -- lowercase; plain text
    banned_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    username   TEXT PRIMARY KEY,
    serial_hex TEXT NOT NULL,      -- hex serial; public info, plain text
    cert_pem   BLOB,               -- AES-256-GCM encrypted PEM blob
    issued_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_serials (
    serial_hex TEXT PRIMARY KEY,   -- hex serial; public info, plain text
    revoked_at REAL NOT NULL
);
"""

# =============================================================================
# KEY DERIVATION
# =============================================================================

def _derive_db_key(master_hash_hex: str) -> bytes:
    """Derive a 32-byte AES-256 key from MASTER_PASSWORD_HASH via HKDF-SHA256.

    Uses fixed domain-separation labels so the derived key is cryptographically
    independent from any other key derived from the same master secret.
    """
    raw = bytes.fromhex(master_hash_hex)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sts-db-v1",
        info=b"column-encryption",
    )
    return hkdf.derive(raw)


# =============================================================================
# AES-256-GCM HELPERS
# =============================================================================

def _encrypt(plaintext: str) -> bytes:
    """Encrypt a UTF-8 string with AES-256-GCM.

    Returns: nonce(12) ‖ ciphertext+tag  stored as a BLOB.
    A fresh 12-byte nonce is generated for every call.
    """
    if _db_key is None:
        raise RuntimeError("Database key not initialised. Call init_db() first.")
    nonce = os.urandom(12)
    ct = AESGCM(_db_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def _decrypt(blob: bytes) -> str:
    """Decrypt a BLOB produced by ``_encrypt``."""
    if _db_key is None:
        raise RuntimeError("Database key not initialised. Call init_db() first.")
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(_db_key).decrypt(nonce, ct, None).decode("utf-8")


# =============================================================================
# CONNECTION HELPERS
# =============================================================================

def _get_conn() -> sqlite3.Connection:
    if _conn is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _conn


# =============================================================================
# INITIALISATION
# =============================================================================

def init_db(db_path: str, master_hash: str) -> None:
    """Initialise (or re-initialise) the SQLite database.

    Creates the database file and all tables if they do not exist.
    If a connection is already open (e.g. from a previous ``init_db`` call
    during test reloads), it is closed cleanly before the new one is opened.

    Args:
        db_path:     Absolute path to the ``sts.db`` file.
        master_hash: Hex string of MASTER_PASSWORD_HASH from ``.env``.
    """
    global _conn, _db_key

    with _lock:
        # Close any existing connection safely (handles module reloads in tests)
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None

        _db_key = _derive_db_key(master_hash)

        _conn = sqlite3.connect(db_path, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.executescript(_DDL)
        _conn.commit()

    logger.info(f"Database initialised at {db_path!r}")


def close_db() -> None:
    """Close the database connection gracefully (called on server shutdown)."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
    logger.info("Database connection closed.")


# =============================================================================
# USERS
# =============================================================================

def add_user(username: str) -> None:
    """Register a username. No-op if the username already exists (INSERT OR IGNORE)."""
    with _lock:
        _get_conn().execute(
            "INSERT OR IGNORE INTO users (username, created_at) VALUES (?, ?)",
            (username.lower(), time.time()),
        )
        _get_conn().commit()


def get_all_users() -> Set[str]:
    """Return the set of all registered usernames."""
    with _lock:
        rows = _get_conn().execute("SELECT username FROM users").fetchall()
        return {r[0] for r in rows}


def user_exists(username: str) -> bool:
    """Return True if the username is registered."""
    with _lock:
        row = _get_conn().execute(
            "SELECT 1 FROM users WHERE username = ?", (username.lower(),)
        ).fetchone()
        return row is not None


# =============================================================================
# BANNED USERS
# =============================================================================

def ban_user(username: str) -> None:
    """Add a username to the ban list. No-op if already banned."""
    with _lock:
        _get_conn().execute(
            "INSERT OR IGNORE INTO banned_users (username, banned_at) VALUES (?, ?)",
            (username.lower(), time.time()),
        )
        _get_conn().commit()


def get_banned_users() -> Set[str]:
    """Return the set of all banned usernames."""
    with _lock:
        rows = _get_conn().execute("SELECT username FROM banned_users").fetchall()
        return {r[0] for r in rows}


def is_banned(username: str) -> bool:
    """Return True if the username is on the ban list."""
    with _lock:
        row = _get_conn().execute(
            "SELECT 1 FROM banned_users WHERE username = ?", (username.lower(),)
        ).fetchone()
        return row is not None


# =============================================================================
# CERTIFICATES
# =============================================================================

def add_certificate(username: str, serial_hex: str, cert_pem: str) -> None:
    """Insert or update a certificate record.

    ``cert_pem`` is encrypted with AES-256-GCM before storage.
    If ``cert_pem`` is empty/None the existing encrypted blob is preserved
    (useful during migration when the PEM is not available on disk).
    """
    with _lock:
        encrypted_pem: Optional[bytes] = _encrypt(cert_pem) if cert_pem else None
        _get_conn().execute(
            """
            INSERT INTO certificates (username, serial_hex, cert_pem, issued_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                serial_hex = excluded.serial_hex,
                cert_pem   = CASE
                                 WHEN excluded.cert_pem IS NOT NULL
                                 THEN excluded.cert_pem
                                 ELSE certificates.cert_pem
                             END,
                issued_at  = excluded.issued_at
            """,
            (username.lower(), serial_hex, encrypted_pem, time.time()),
        )
        _get_conn().commit()


def get_serial(username: str) -> Optional[str]:
    """Return the certificate serial hex for a username, or None if not found."""
    with _lock:
        row = _get_conn().execute(
            "SELECT serial_hex FROM certificates WHERE username = ?",
            (username.lower(),),
        ).fetchone()
        return row[0] if row else None


def get_cert_pem(username: str) -> Optional[str]:
    """Return the decrypted certificate PEM for a username, or None if not found."""
    with _lock:
        row = _get_conn().execute(
            "SELECT cert_pem FROM certificates WHERE username = ?",
            (username.lower(),),
        ).fetchone()
        if not row or row[0] is None:
            return None
        try:
            return _decrypt(bytes(row[0]))
        except Exception as exc:
            logger.error(f"Failed to decrypt cert_pem for {username!r}: {exc}")
            return None


def get_all_cert_serials() -> Dict[str, str]:
    """Return a ``{username: serial_hex}`` mapping for all certificate records."""
    with _lock:
        rows = _get_conn().execute(
            "SELECT username, serial_hex FROM certificates"
        ).fetchall()
        return {r[0]: r[1] for r in rows}


# =============================================================================
# REVOKED SERIALS  (Certificate Revocation List)
# =============================================================================

def revoke_serial(serial_hex: str) -> None:
    """Add a serial number to the CRL. No-op if already revoked."""
    with _lock:
        _get_conn().execute(
            "INSERT OR IGNORE INTO revoked_serials (serial_hex, revoked_at) VALUES (?, ?)",
            (serial_hex, time.time()),
        )
        _get_conn().commit()


def get_revoked_serials() -> Set[str]:
    """Return the set of all revoked serial hex strings."""
    with _lock:
        rows = _get_conn().execute(
            "SELECT serial_hex FROM revoked_serials"
        ).fetchall()
        return {r[0] for r in rows}


def is_revoked(serial_hex: str) -> bool:
    """Return True if the given serial is on the CRL."""
    with _lock:
        row = _get_conn().execute(
            "SELECT 1 FROM revoked_serials WHERE serial_hex = ?", (serial_hex,)
        ).fetchone()
        return row is not None
