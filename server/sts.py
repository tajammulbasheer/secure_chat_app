import socket
import threading
import os
import base64
import json
import re
import hashlib
import hmac
import uuid
import time

from shared.transport import send_packet, receive_packet
from shared.crypto_utils import (
    verify_signature,
    verify_certificate,
    extract_common_name
)
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import datetime

from shared.logger import setup_logger
from server.config import (
    HOST,
    PORT,
    DB_DIR,
    DB_PATH,
    CA_CERT,
    CA_KEY,
    KDC_CERT,
    KDC_KEY,
    USER_DB,
    BANNED_DB,
    CERT_DB,
    CRL_DB,
    MASTER_PASSWORD_HASH,
    MASTER_PASSWORD_SALT,
    LOG_FILE,
    LOG_LEVEL
)
import server.database as database

logger = setup_logger("STS", log_file=LOG_FILE, level=LOG_LEVEL)


groups = {}  # room_name -> list of usernames
group_keys = {}  # room_name -> {username: {"encrypted_key": ..., "signature": ...}}
group_creators = {}  # room_name -> creator_username
clients = {}  # username -> {conn, cert, ip, port}
lock = threading.RLock()



# =========================
# RATE LIMITING CONFIG
# =========================
RATE_LIMIT_WINDOW = 60         # Rolling window in seconds
MAX_REQUESTS_PER_WINDOW = 50   # Max packets an IP can send per minute
MAX_FAILED_LOGINS = 5          # Max authentication failures
LOCKOUT_DURATION = 300         # Lockout time in seconds (5 minutes)

ip_request_history = {}        # ip -> [list of timestamps]
failed_auth_attempts = {}      # ip -> {"count": int, "lockout_until": float}
# =========================
# DATABASE MANAGEMENT
# =========================

import ipaddress

def ensure_kdc_credentials():
    cert_path = KDC_CERT
    key_path = KDC_KEY
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
        
    logger.info("Generating new dedicated KDC server certificate and key...")
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = load_pem_private_key(f.read(), password=None)
        
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
    ])
    
    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
    ]
    
    if HOST != "0.0.0.0" and HOST != "127.0.0.1":
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(HOST)))
        except ValueError:
            san_list.append(x509.DNSName(HOST))
            
    try:
        from datetime import UTC
        now = datetime.datetime.now(UTC)
    except ImportError:
        now = datetime.datetime.utcnow()
        
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
    )
    
    cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )
    
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    logger.info(f"KDC server credentials saved to {cert_path} and {key_path}")


def keepalive_loop():
    while True:
        time.sleep(10)
        with lock:
            active_clients = list(clients.items())
            
        now = time.time()
        for user, info in active_clients:
            if now - info.get("last_seen", now) > 30:
                logger.info(f"Keep-alive timeout for {user}. Disconnecting.")
                with lock:
                    if user in clients and clients[user]["conn"] == info["conn"]:
                        try:
                            info["conn"].close()
                        except:
                            pass
                        del clients[user]
                broadcast_online_users()
                continue
                
            try:
                send_packet(info["conn"], {"type": "PING", "payload": {}})
            except Exception as e:
                logger.info(f"Failed to send heartbeat to {user}: {e}. Disconnecting.")
                with lock:
                    if user in clients and clients[user]["conn"] == info["conn"]:
                        try:
                            info["conn"].close()
                        except:
                            pass
                        del clients[user]
                broadcast_online_users()


def broadcast_online_users():
    online = list(clients.keys())
    for user in online:
        try:
            send_packet(clients[user]["conn"], {
                "type": "ONLINE_USERS",
                "payload": {"users": online}
            })
        except:
            pass

def _migrate_json_to_sql():
    """One-time migration from legacy JSON files to SQLite.

    If any of the four JSON registry files exist, their entries are imported
    into the SQLite database and the files are renamed to ``.json.bak``.
    This function is a no-op if all JSON files are absent (normal operation).
    """
    # users.json ─ list of registered usernames
    if os.path.exists(USER_DB):
        try:
            with open(USER_DB) as f:
                users = json.load(f)
            for u in users:
                database.add_user(u)
            os.rename(USER_DB, USER_DB + ".bak")
            logger.info(f"Migrated {len(users)} users from users.json → SQLite")
        except Exception as e:
            logger.error(f"Migration error (users.json): {e}")

    # banned.json ─ list of banned usernames
    if os.path.exists(BANNED_DB):
        try:
            with open(BANNED_DB) as f:
                banned = json.load(f)
            for u in banned:
                database.ban_user(u)
            os.rename(BANNED_DB, BANNED_DB + ".bak")
            logger.info(f"Migrated {len(banned)} banned users → SQLite")
        except Exception as e:
            logger.error(f"Migration error (banned.json): {e}")

    # cert_db.json ─ {username: serial_hex}; pull cert PEM from adjacent .crt files
    if os.path.exists(CERT_DB):
        try:
            with open(CERT_DB) as f:
                cert_data = json.load(f)
            for username, serial in cert_data.items():
                cert_pem = ""
                crt_path = os.path.join(DB_DIR, f"{username}.crt")
                if os.path.exists(crt_path):
                    try:
                        with open(crt_path) as cf:
                            cert_pem = cf.read()
                    except Exception:
                        pass
                database.add_certificate(username, serial, cert_pem)
            os.rename(CERT_DB, CERT_DB + ".bak")
            logger.info(f"Migrated {len(cert_data)} certificates → SQLite")
        except Exception as e:
            logger.error(f"Migration error (cert_db.json): {e}")

    # revoked_serials.json ─ list of hex serial strings
    if os.path.exists(CRL_DB):
        try:
            with open(CRL_DB) as f:
                serials = json.load(f)
            for s in serials:
                database.revoke_serial(s)
            os.rename(CRL_DB, CRL_DB + ".bak")
            logger.info(f"Migrated {len(serials)} revoked serials → SQLite")
        except Exception as e:
            logger.error(f"Migration error (revoked_serials.json): {e}")


# Initialise SQLite database and run one-time JSON migration check
database.init_db(DB_PATH, MASTER_PASSWORD_HASH)
_migrate_json_to_sql()

# =========================
# UTILITY FUNCTIONS
# =========================

def is_valid_username(username):
    return re.match(r"^[A-Za-z0-9_]{3,20}$", username) is not None

def extract_cn_from_csr_pem(csr_pem):
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names:
            return common_names[0].value
    except Exception as e:
        logger.error(f"Error parsing CSR: {e}")
    return None

def sign_csr_in_memory(csr_pem, ca_cert_path, ca_key_path, days=365):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = load_pem_private_key(f.read(), password=None)
        
    serial_number = x509.random_serial_number()
    now = datetime.datetime.utcnow()
    expiry = now + datetime.timedelta(days=days)
    
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(expiry)
    )
    
    cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex = f"{serial_number:X}"
    return cert_pem, serial_hex

def revoke_user(username):
    username = username.strip().lower()
    database.ban_user(username)
    with lock:
        # Kick if online (case-insensitive check)
        target = next((u for u in clients if u.lower() == username), None)
        if target:
            try:
                send_packet(clients[target]["conn"], {
                    "type": "AUTH_FAILED",
                    "payload": {"message": "You have been banned by the administrator."}
                })
                clients[target]["conn"].close()
                del clients[target]
            except:
                pass

    logger.info(f"User {username} revoked successfully.")

def revoke_certificate(username):
    username = username.strip().lower()
    serial = database.get_serial(username)
    if not serial:
        logger.warning(f"No certificate found for user: {username}")
        return

    database.revoke_serial(serial)

    with lock:
        # Kick if online
        if username in clients:
            try:
                send_packet(clients[username]["conn"], {
                    "type": "AUTH_FAILED",
                    "payload": {"message": "Your certificate was just revoked."}
                })
                clients[username]["conn"].close()
                del clients[username]
            except:
                pass

    logger.info(f"Certificate for {username} revoked (serial {serial})")

def get_user_cert_from_anywhere(username):
    """Retrieve a user's certificate PEM from the SQL database."""
    return database.get_cert_pem(username.strip().lower())

def record_auth_failure(client_ip):
    """Increments failure count and applies a lockout penalty if threshold is hit."""
    current_time = time.time()
    with lock:
        record = failed_auth_attempts.get(client_ip, {"count": 0, "lockout_until": 0})
        record["count"] += 1
        
        if record["count"] >= MAX_FAILED_LOGINS:
            record["lockout_until"] = current_time + LOCKOUT_DURATION
            record["count"] = 0 # Reset counter, but lockout is active
            
        failed_auth_attempts[client_ip] = record
# =========================
# CLIENT HANDLER
# =========================

def handle_client(conn, addr):
    client_ip = addr[0]
    logger.info(f"Connected: {addr}")

    username = None
    expected_nonce = None  # Tracks the challenge puzzle for this specific connection

    while True:
        try:
            packet = receive_packet(conn)
        except Exception:
            break
            
        if not packet:
            break
        
        current_time = time.time()
        
        # ==========================================================
        # SECURITY: 1. FLOODING & SPAM PROTECTION
        # ==========================================================
        with lock:
            if client_ip not in ip_request_history:
                ip_request_history[client_ip] = []
                
            # Filter out requests older than the rolling window
            ip_request_history[client_ip] = [t for t in ip_request_history[client_ip] if current_time - t < RATE_LIMIT_WINDOW]
            
            if len(ip_request_history[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
                send_packet(conn, {
                    "type": "ERROR",
                    "payload": {"message": "Rate limit exceeded. You are sending too many requests."}
                })
                continue 
                
            ip_request_history[client_ip].append(current_time)

        # ==========================================================
        # SECURITY: 2. BRUTE FORCE LOCKOUT CHECK
        # ==========================================================
        ptype = packet.get("type")
        
        if ptype in ["AUTH_VERIFY", "REGISTER_USER"]:
            with lock:
                record = failed_auth_attempts.get(client_ip, {"count": 0, "lockout_until": 0})
                if current_time < record["lockout_until"]:
                    remaining = int(record["lockout_until"] - current_time)
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": f"IP locked out due to failed attempts. Try again in {remaining}s."}
                    })
                    continue

        ptype = packet.get("type")

        # ================= REGISTER USER =================
        if ptype == "REGISTER_USER":
            csr_pem = packet["payload"].get("csr")
            provided_master = packet["payload"].get("master_password")

            if not provided_master or not csr_pem:
                send_packet(conn, {
                    "type": "ERROR",
                    "payload": {"message": "Invalid request parameters."}
                })
                continue

            provided_hash = hashlib.pbkdf2_hmac(
                "sha256",
                provided_master.encode(),
                MASTER_PASSWORD_SALT.encode(),
                100000
            ).hex()
            if not hmac.compare_digest(provided_hash, MASTER_PASSWORD_HASH):
                record_auth_failure(client_ip)
                send_packet(conn, {
                    "type": "ERROR",
                    "payload": {"message": "Invalid master password."}
                })
                continue

            new_username = extract_cn_from_csr_pem(csr_pem)

            if not new_username or not is_valid_username(new_username):
                send_packet(conn, {
                    "type": "ERROR",
                    "payload": {"message": "Invalid username format."}
                })
                continue
            new_username = new_username.lower()

            with lock:
                if database.is_banned(new_username):
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": "User is banned."}
                    })
                    continue

                if database.user_exists(new_username):
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": "Username already exists."}
                    })
                    continue

                try:
                    signed_cert, serial = sign_csr_in_memory(csr_pem, CA_CERT, CA_KEY)
                except Exception as e:
                    logger.error(f"Signing failed: {e}")
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": "Certificate signing failed."}
                    })
                    continue

                # Persist certificate and user record to SQLite (cert_pem encrypted)
                database.add_certificate(new_username, serial, signed_cert)
                database.add_user(new_username)

            send_packet(conn, {
                "type": "REGISTER_SUCCESS",
                "payload": {"certificate": signed_cert}
            })
            logger.info(f"New user registered: {new_username}")

        # ================= AUTH STEP 1: CHALLENGE =================
        elif ptype == "AUTH_INIT":
            expected_nonce = os.urandom(16)
            send_packet(conn, {
                "type": "AUTH_CHALLENGE",
                "payload": {
                    "nonce": base64.b64encode(expected_nonce).decode()
                }
            })

        # ================= AUTH STEP 2: VERIFY =================
        elif ptype == "AUTH_VERIFY":
            if not expected_nonce:
                send_packet(conn, {
                    "type": "AUTH_FAILED",
                    "payload": {"message": "No authentication challenge initiated."}
                })
                break

            payload = packet["payload"]
            cert_pem = payload["certificate"]
            signature = payload["signature"]

            # 1. Verify CA signature
            if not verify_certificate(cert_pem, CA_CERT):
                record_auth_failure(client_ip) 
                break

            # 2. Verify nonce signature (Replay Attack Prevention)
            try:
                verify_signature(cert_pem, expected_nonce, signature)
            except Exception:
                record_auth_failure(client_ip)

            expected_nonce = None # Invalidate challenge

            # 3. Extract Identity
            try:
                username = extract_common_name(cert_pem).lower()
            except Exception:
                record_auth_failure(client_ip)
                break
            
            if not username:
                record_auth_failure(client_ip)
                break

            with lock:
                # 4. Check CRL
                serial = database.get_serial(username)
                if serial and database.is_revoked(serial):
                    record_auth_failure(client_ip)
                    send_packet(conn, {
                        "type": "AUTH_FAILED",
                        "payload": {"message": "Your certificate has been revoked."}
                    })
                    break

                # 5. Check Ban List
                if database.is_banned(username):
                    record_auth_failure(client_ip)
                    send_packet(conn, {
                        "type": "AUTH_FAILED",
                        "payload": {"message": "User is banned."}
                    })
                    break

                # 6. Success
                clients[username] = {
                    "conn": conn,
                    "cert": cert_pem,
                    "ip": None,
                    "port": None,
                    "last_seen": time.time()
                }
            with lock:
                if client_ip in failed_auth_attempts:
                    del failed_auth_attempts[client_ip]

            # Refresh the stored certificate PEM in the database (encrypted at rest)
            if serial:
                database.add_certificate(username, serial, cert_pem)

            send_packet(conn, {
                "type": "AUTH_SUCCESS",
                "payload": {"username": username}
            })

            # Send group sync packets to the newly authenticated user
            with lock:
                for room, members in groups.items():
                    if username in members:
                        keys = group_keys.get(room, {})
                        member_key_info = keys.get(username, {})
                        creator = group_creators.get(room, "")
                        creator_cert = get_user_cert_from_anywhere(creator)
                        if member_key_info and creator_cert:
                            try:
                                send_packet(conn, {
                                    "type": "GROUP_CREATED",
                                    "payload": {
                                        "session_id": room,
                                        "creator": creator,
                                        "creator_cert": creator_cert,
                                        "encrypted_key": member_key_info.get("encrypted_key"),
                                        "signature": member_key_info.get("signature")
                                    }
                                })
                            except Exception as e:
                                logger.error(f"Failed to sync group {room} to {username}: {e}")

            broadcast_online_users()
            logger.info(f"{username} authenticated")

        # ================= REGISTER PEER INFO =================
        elif ptype == "REGISTER_PEER_INFO":
            if not username: continue
            ip = packet["payload"]["ip"]
            port = packet["payload"]["port"]
            with lock:
                if username in clients:
                    clients[username]["ip"] = ip
                    clients[username]["port"] = port

        # ================= PONG =================
        elif ptype == "PONG":
            if username:
                with lock:
                    if username in clients:
                        clients[username]["last_seen"] = time.time()
            continue

        # ================= FETCH CERTIFICATE (E2EE) =================
        elif ptype == "FETCH_CERT":
            if not username: continue
            target = packet["payload"]["target"]
            
            with lock:
                if target not in clients:
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": f"User {target} is not online."}
                    })
                    continue
                
                send_packet(conn, {
                    "type": "PEER_CERT_RESPONSE",
                    "payload": {
                        "target": target,
                        "cert": clients[target]["cert"],
                        "ip": clients[target]["ip"],
                        "port": clients[target]["port"]
                    }
                })

        # ================= RELAY SECURE SESSION KEY =================
        elif ptype == "RELAY_SESSION_KEY":
            if not username: continue
            target = packet["payload"]["target"]
            
            with lock:
                if target in clients:
                    send_packet(clients[target]["conn"], {
                        "type": "SESSION_INFO",
                        "payload": packet["payload"] 
                    })

        # ================= GET MEMBER CERTS =================
        elif ptype == "GET_MEMBER_CERTS":
            if not username: continue
            room = packet["payload"].get("room")
            targets = packet["payload"].get("members", [])
            
            certs = {}
            with lock:
                for target in targets:
                    target = target.lower()
                    if target in clients:
                        certs[target] = clients[target]["cert"]
                    else:
                        cert_pem = get_user_cert_from_anywhere(target)
                        if cert_pem:
                            certs[target] = cert_pem
                            
            send_packet(conn, {
                "type": "MEMBER_CERTS_RESPONSE",
                "payload": {
                    "room": room,
                    "certs": certs
                }
            })

        # ================= CREATE GROUP =================
        # Inside kdc.py -> handle_client
        elif ptype == "CREATE_GROUP":
            if not username: continue
            room = packet["payload"].get("room")
            members = list(set(packet["payload"].get("members", [])))
            keys = packet["payload"].get("keys", {})

            if not room or not members:
                send_packet(conn, {
                    "type": "ERROR",
                    "payload": {"message": "Invalid group creation parameters."}
                })
                continue

            # Ensure all members have their encrypted group keys and signatures
            missing_keys = [m for m in members if m not in keys or "encrypted_key" not in keys[m] or "signature" not in keys[m]]
            if missing_keys:
                send_packet(conn, {
                    "type": "ERROR",
                    "payload": {"message": f"Missing encrypted group keys or signatures for members: {', '.join(missing_keys)}"}
                })
                continue

            with lock:
                # Check if room already exists
                if room in groups:
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": f"Group '{room}' already exists!"}
                    })
                    continue # Stop here so it doesn't overwrite
                groups[room] = members
                group_keys[room] = keys
                group_creators[room] = username
            
            creator_cert = get_user_cert_from_anywhere(username)
            
            # Notify all online members that the group is ready
            for member in members:
                if member in clients:
                    member_key_info = keys.get(member, {})
                    try:
                        send_packet(clients[member]["conn"], {
                            "type": "GROUP_CREATED",
                            "payload": {
                                "session_id": room,
                                "creator": username,
                                "creator_cert": creator_cert,
                                "encrypted_key": member_key_info.get("encrypted_key"),
                                "signature": member_key_info.get("signature")
                            }
                        })
                    except:
                        pass
            logger.info(f"Group {room} created by {username}")
        # ================= RELAY GROUP MESSAGE =================
        elif ptype == "GROUP_MESSAGE":
            if not username: continue
            room = packet["payload"]["session_id"]
            
            with lock:
                # 1. Is it a Group Chat?
                if room in groups:
                    for member in groups[room]:
                        if member in clients and member != username:
                            try:
                                send_packet(clients[member]["conn"], packet)
                            except:
                                pass
                
                # 2. Is it a Direct Chat fallback relay?
                elif room.startswith("direct_"):
                    parts = room.split("_")
                    if len(parts) == 3:
                        target = parts[2] if parts[1] == username else parts[1]
                        if target in clients:
                            try:
                                send_packet(clients[target]["conn"], packet)
                            except:
                                pass

    # ================= CLEANUP =================
    if username:
        with lock:
            if username in clients:
                del clients[username]
        logger.info(f"{username} disconnected")
        broadcast_online_users()
    conn.close()


# =========================
# MAIN & SHUTDOWN
# =========================

server_socket = None

import ssl

def accept_loop(server, ssl_context):
    while True:
        try:
            conn, addr = server.accept()
        except Exception:
            break
        try:
            secure_conn = ssl_context.wrap_socket(conn, server_side=True)
        except Exception as e:
            logger.error(f"SSL handshake failed with {addr}: {e}")
            try:
                conn.close()
            except:
                pass
            continue
        threading.Thread(
            target=handle_client,
            args=(secure_conn, addr),
            daemon=True
        ).start()

def shutdown():
    global server_socket
    with lock:
        for user_info in list(clients.values()):
            try:
                user_info["conn"].close()
            except Exception:
                pass
        clients.clear()
    if server_socket:
        try:
            server_socket.close()
        except Exception:
            pass
    database.close_db()

def main():
    global server_socket
    ensure_kdc_credentials()
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=KDC_CERT, keyfile=KDC_KEY)
    
    threading.Thread(target=keepalive_loop, daemon=True).start()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    logger.info(f"STS running on port {PORT} (TLS Enabled)")

    threading.Thread(
        target=accept_loop,
        args=(server_socket, context),
        daemon=True
    ).start()

    # Admin console
    while True:
        try:
            cmd = input("STS Admin > ").strip()
        except KeyboardInterrupt:
            break

        if cmd.startswith("revoke "):
            user = cmd.split(" ", 1)[1]
            revoke_user(user)

        elif cmd == "list":
            print("Registered users:", database.get_all_users())
            print("Banned users:    ", database.get_banned_users())
            
        elif cmd.startswith("revoke_cert "):
            user = cmd.split(" ", 1)[1]
            revoke_certificate(user)

        elif cmd.startswith("ban "):
            user = cmd.split(" ", 1)[1]
            revoke_user(user)


if __name__ == "__main__":
    main()