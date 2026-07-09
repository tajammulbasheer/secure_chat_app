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
    CA_CERT,
    CA_KEY,
    USER_DB,
    BANNED_DB,
    CERT_DB,
    CRL_DB,
    MASTER_PASSWORD_HASH,
    MASTER_PASSWORD_SALT,
    LOG_FILE,
    LOG_LEVEL
)

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

def load_db(filename, default_type):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            return set(data) if isinstance(default_type, set) else data
    except:
        return default_type

def save_db(filename, data):
    with open(filename, "w") as f:
        # Convert sets to lists for JSON serialization
        json.dump(list(data) if isinstance(data, set) else data, f)

registered_users = load_db(USER_DB, set())
banned_users = load_db(BANNED_DB, set())
cert_db = load_db(CERT_DB, {})
revoked_serials = load_db(CRL_DB, set())

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
    with lock:
        banned_users.add(username)
        save_db(BANNED_DB, banned_users)
        
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
    with lock:
        target_user = next((u for u in cert_db if u.lower() == username), None)
        if not target_user:
            logger.warning(f"No certificate found for user: {username}")
            return

        serial = cert_db.get(target_user)
        revoked_serials.add(serial)
        save_db(CRL_DB, revoked_serials)

        # Kick if online
        if target_user in clients:
            try:
                send_packet(clients[target_user]["conn"], {
                    "type": "AUTH_FAILED",
                    "payload": {"message": "Your certificate was just revoked."}
                })
                clients[target_user]["conn"].close()
                del clients[target_user]
            except:
                pass

    logger.info(f"Certificate for {target_user} revoked (serial {serial})")

def get_user_cert_from_anywhere(username):
    username = username.strip().lower()
    # 1. Check in server data
    cert_path = os.path.join(DB_DIR, f"{username}.crt")
    if os.path.exists(cert_path):
        try:
            with open(cert_path, "r") as f:
                return f.read()
        except:
            pass
            
    # 2. Check in client directories (local dev environment fallback)
    try:
        client_cert_path = os.path.abspath(os.path.join(os.path.dirname(DB_DIR), "..", "client", "data", f"client_{username}", "client.crt"))
        if os.path.exists(client_cert_path):
            with open(client_cert_path, "r") as f:
                cert_pem = f.read()
            # Cache it in server data
            try:
                with open(cert_path, "w") as f_out:
                    f_out.write(cert_pem)
            except:
                pass
            return cert_pem
    except:
        pass
    return None

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
            logger.debug(f"provided_master={repr(provided_master)}, hash={provided_hash}, expected={MASTER_PASSWORD_HASH}")
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
                banned_lower = [u.lower() for u in banned_users]
                if new_username.lower() in banned_lower:
                    send_packet(conn, {
                        "type": "ERROR",
                        "payload": {"message": "User is banned."}
                    })
                    continue

                if new_username in registered_users:
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

                cert_db[new_username] = serial
                save_db(CERT_DB, cert_db)

                registered_users.add(new_username)
                save_db(USER_DB, registered_users)

                # Save certificate to disk for offline fetching
                cert_path = os.path.join(DB_DIR, f"{new_username}.crt")
                try:
                    with open(cert_path, "w") as f:
                        f.write(signed_cert)
                except Exception as e:
                    logger.error(f"Error saving registered certificate for {new_username}: {e}")

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
                serial = cert_db.get(username)
                if serial and serial in revoked_serials:
                    record_auth_failure(client_ip)
                    send_packet(conn, {
                        "type": "AUTH_FAILED",
                        "payload": {"message": "Your certificate has been revoked."}
                    })
                    break

                # 5. Check Ban List
                banned_lower = [u.lower() for u in banned_users]
                if username.lower() in banned_lower:
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
                    "port": None
                }
            with lock:
                if client_ip in failed_auth_attempts:
                    del failed_auth_attempts[client_ip]

            # Save certificate to disk for offline fetching
            cert_path = os.path.join(DB_DIR, f"{username}.crt")
            try:
                with open(cert_path, "w") as f:
                    f.write(cert_pem)
            except Exception as e:
                logger.error(f"Error saving certificate for {username}: {e}")

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

def accept_loop(server):
    while True:
        try:
            conn, addr = server.accept()
        except Exception:
            break
        threading.Thread(
            target=handle_client,
            args=(conn, addr),
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

def main():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    logger.info(f"STS running on port {PORT}")

    threading.Thread(
        target=accept_loop,
        args=(server_socket,),
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
            print("Registered users:", registered_users)
            print("Revoked users:", banned_users)
            
        elif cmd.startswith("revoke_cert "):
            user = cmd.split(" ", 1)[1]
            revoke_certificate(user)

        elif cmd.startswith("ban "):
            user = cmd.split(" ", 1)[1]
            revoke_user(user)


if __name__ == "__main__":
    main()