from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.x509.oid import NameOID
import socket
import threading
import base64
import os
import time
import json
import hashlib
import logging

from shared.logger import setup_logger
from shared.transport import send_packet, receive_packet
from shared.crypto_utils import (
    generate_nonce,
    sign_nonce,
    decrypt_with_private_key,
    encrypt_for_cert,
    aes_encrypt,
    aes_decrypt,
    generate_mac,
    verify_mac,
    verify_signature,
    verify_certificate,
    get_interval_key,
    generate_ephemeral_keypair,
    derive_shared_secret,
    derive_pfs_session_key,
    RatchetState,
    compute_safety_number
)
from client.config import KDC_IP, KDC_PORT, PEER_PORT, CA_CERT_PATH

ROTATION_INTERVAL = 10

class ClientEngine:

    # ==========================================================
    # INIT
    # ==========================================================

    def __init__(self, kdc_ip=None, kdc_port=None, peer_port=None):

        self.kdc_ip = kdc_ip if kdc_ip is not None else KDC_IP
        self.kdc_port = kdc_port if kdc_port is not None else KDC_PORT
        self.peer_port = peer_port if peer_port is not None else PEER_PORT

        self.sock = None
        self.peer_listener_sock = None
        self.username = None
        self.key_path = None
        self.passphrase = None

        self.sessions = {}        # session_id -> {key, send_counter, recv_counters, peer_cert}
        self.peer_sockets = {}    # session_id -> socket
        self.file_buffers = {}    # (session_id, filename) -> chunks
        self.pending_groups = {}  # room -> {"members": [...]}

        # GUI callbacks
        self.message_callback = None
        self.file_callback = None
        self.session_callback = None
        
        # Graceful shutdown flag
        self.is_running = True
        self._reconnecting = False
        self._reconnect_lock = threading.Lock()

        # Initialize default logger
        from client.config import LOG_LEVEL
        self.logger = setup_logger("Client", level=LOG_LEVEL, console_level=logging.ERROR)


    # ==========================================================
    # CALLBACK REGISTRATION (REQUIRED FOR GUI)
    # ==========================================================

    def register_message_callback(self, callback):
        self.message_callback = callback

    def register_file_callback(self, callback):
        self.file_callback = callback

    def register_session_callback(self, callback):
        self.session_callback = callback

    # ==========================================================
    # SHUTDOWN
    # ==========================================================
    
    def shutdown(self):
        """Silently close all connections without triggering UI errors."""
        self.is_running = False
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
                
        for peer_sock in list(self.peer_sockets.values()):
            try:
                peer_sock.close()
            except:
                pass

        if self.peer_listener_sock:
            try:
                self.peer_listener_sock.close()
            except:
                pass

    # ==========================================================
    # CONNECT TO KDC
    # ==========================================================

    def connect(self, cert_path, key_path, passphrase=None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.passphrase = passphrase

        # Verify password/key correctness
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
            password_bytes = passphrase.encode() if passphrase is not None else None
            serialization.load_pem_private_key(key_data, password=password_bytes)
        except Exception as e:
            if not os.path.exists(key_path):
                raise FileNotFoundError(f"Private key file not found at {key_path}")
            raise Exception("Incorrect Passphrase") from e

        # Connect and authenticate
        self._establish_socket_and_authenticate()

        # Setup user-specific file logging
        log_dir = os.path.dirname(self.key_path)
        log_file = os.path.join(log_dir, "client.log")
        from client.config import LOG_LEVEL
        self.logger = setup_logger("Client", log_file=log_file, level=LOG_LEVEL, console_level=logging.ERROR)
        self.logger.info(f"Client connected and authenticated as '{self.username}'")

        self._start_peer_server()
        self._register_peer_info()
        self._start_receive_loop()

    def _establish_socket_and_authenticate(self):
        import ssl
        ca_path = self._get_ca_path()
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        context.check_hostname = True
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            # Temporary workaround: disable strict X509 validation because the self-signed dev CA
            # is missing strict RFC-5280 extensions. 
            # TODO: Regenerate the CA with correct extensions.
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = context.wrap_socket(raw_sock, server_hostname=self.kdc_ip)
        self.sock.connect((self.kdc_ip, self.kdc_port))

        with open(self.cert_path, "r") as f:
            cert_pem = f.read()

        # STEP 1: Request Challenge
        send_packet(self.sock, {
            "type": "AUTH_INIT",
            "payload": {}
        })

        challenge_resp = receive_packet(self.sock)
        if not challenge_resp or challenge_resp.get("type") != "AUTH_CHALLENGE":
            raise Exception("Failed to receive authentication challenge from server.")

        # STEP 2: Sign Challenge
        nonce_b64 = challenge_resp["payload"]["nonce"]
        server_nonce_bytes = base64.b64decode(nonce_b64)
        signature = sign_nonce(self.key_path, server_nonce_bytes, password=self.passphrase.encode() if self.passphrase is not None else None)

        send_packet(self.sock, {
            "type": "AUTH_VERIFY",
            "payload": {
                "certificate": cert_pem,
                "signature": signature
            }
        })

        # STEP 3: Wait for Decision
        response = receive_packet(self.sock)

        if not response:
            raise Exception("Authentication failed. No response from server.")
        if response.get("type") == "AUTH_FAILED":
            raise Exception(response["payload"].get("message", "Authentication failed"))
        
        if response.get("type") == "ERROR":
            raise Exception(response["payload"].get("message", "Server Error"))
            
        if response.get("type") != "AUTH_SUCCESS":
            raise Exception("Authentication failed")

        self.username = response["payload"]["username"]

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def create_direct(self, target):
        target = target.lower()
        # E2EE STEP 1: Ask KDC for the public certificate, NOT a session key
        send_packet(self.sock, {
            "type": "FETCH_CERT",
            "payload": {"to": target, "target": target} 
        })
        self.logger.info(f"Requested certificate for {target} to establish E2EE...")

    def create_group(self, room, members):
        members = [m.lower() for m in members]
        self.pending_groups[room] = {
            "members": members
        }
        send_packet(self.sock, {
            "type": "GET_MEMBER_CERTS",
            "payload": {
                "room": room,
                "members": members
            }
        })

    def send_message(self, session_id, message):
        if session_id not in self.sessions:
            raise Exception("Session not found")

        session = self.sessions[session_id]
        current_time = int(time.time())

        # --- DOUBLE RATCHET for direct sessions ---
        if "ratchet" in session:
            ratchet = session["ratchet"]
            msg_key, counter = ratchet.next_encrypt_key()
            ad = f"{session_id}:{self.username}:{counter}:{current_time}".encode()
            nonce, ciphertext = aes_encrypt(msg_key, message.encode(), ad)
            del msg_key  # forward secrecy: discard after use
        else:
            # Legacy path for group sessions (static key + interval HKDF)
            session["send_counter"] += 1
            counter = session["send_counter"]
            interval_index = (counter - 1) // ROTATION_INTERVAL
            active_interval_key = get_interval_key(session["key"], interval_index)
            ad = f"{session_id}:{self.username}:{counter}:{current_time}".encode()
            nonce, ciphertext = aes_encrypt(active_interval_key, message.encode(), ad)

        packet = {
            "type": "SESSION_MESSAGE", 
            "payload": {
                "session_id": session_id,
                "sender": self.username,
                "counter": counter,
                "timestamp": current_time, 
                "nonce": nonce,
                "ciphertext": ciphertext
            }
        }

        peer_sock = self.peer_sockets.get(session_id)

        if peer_sock:
            try:
                send_packet(peer_sock, packet)
                return 
            except Exception:
                pass 
                
        packet["type"] = "GROUP_MESSAGE" 
        send_packet(self.sock, packet)

    def send_file(self, session_id, filepath):
        if session_id not in self.sessions:
            raise Exception("Session not found")
        if not os.path.exists(filepath):
            raise Exception("File not found")

        peer_sock = self.peer_sockets.get(session_id)
        if not peer_sock:
            raise Exception("Peer not connected")

        session = self.sessions[session_id]
        has_ratchet = "ratchet" in session

        CHUNK_SIZE = 32 * 1024
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE

        with open(filepath, "rb") as f:
            for chunk_index in range(total_chunks):
                chunk = f.read(CHUNK_SIZE)
                chunk_timestamp = int(time.time())

                if has_ratchet:
                    msg_key, counter = session["ratchet"].next_encrypt_key()
                    ad = f"{session_id}:{self.username}:{counter}:{chunk_timestamp}".encode()
                    nonce, ciphertext = aes_encrypt(msg_key, chunk, ad)
                    del msg_key
                else:
                    session["send_counter"] += 1
                    counter = session["send_counter"]
                    interval_index = (counter - 1) // ROTATION_INTERVAL
                    active_interval_key = get_interval_key(session["key"], interval_index)
                    ad = f"{session_id}:{self.username}:{counter}:{chunk_timestamp}".encode()
                    nonce, ciphertext = aes_encrypt(active_interval_key, chunk, ad)

                send_packet(peer_sock, {
                    "type": "FILE_CHUNK",
                    "payload": {
                        "session_id": session_id,
                        "sender": self.username,
                        "filename": filename,
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks,
                        "counter": counter,
                        "timestamp": chunk_timestamp,
                        "nonce": nonce,
                        "ciphertext": ciphertext
                    }
                })

        self.logger.info(f"File {filename} sent successfully.")

    def end_session(self, session_id):
        peer_sock = self.peer_sockets.get(session_id)
        if peer_sock:
            send_packet(peer_sock, {
                "type": "SESSION_END",
                "payload": {"session_id": session_id}
            })
        self._destroy_session(session_id)

    # ==========================================================
    # SECURITY PROTOCOLS (MITM & PINNING)
    # ==========================================================

    def _get_ca_path(self, key_path=None):
        """Locate rootCA.pem dynamically from standard locations."""
        # 0. Check from config override
        if CA_CERT_PATH:
            # Resolve relative to project root if needed
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            resolved_ca = CA_CERT_PATH if os.path.isabs(CA_CERT_PATH) else os.path.normpath(os.path.join(project_root, CA_CERT_PATH))
            if os.path.exists(resolved_ca):
                return resolved_ca

        # 1. Project-wide standard location (relative to this file)
        project_ca = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "server", "data", "rootCA.pem"))
        if os.path.exists(project_ca):
            return project_ca
        
        # 2. Check relative to key_path or self.key_path if available
        target_key = key_path or self.key_path
        if target_key:
            # Same directory as client key
            local_ca = os.path.abspath(os.path.join(os.path.dirname(target_key), "rootCA.pem"))
            if os.path.exists(local_ca):
                return local_ca
            # Parent directory of client key directory (e.g. client/data/rootCA.pem)
            parent_ca = os.path.abspath(os.path.join(os.path.dirname(target_key), "..", "rootCA.pem"))
            if os.path.exists(parent_ca):
                return parent_ca

        # 3. Current working directory
        cwd_ca = os.path.abspath("rootCA.pem")
        if os.path.exists(cwd_ca):
            return cwd_ca
            
        return None

    def _verify_and_pin_cert(self, target_username, cert_pem):
        """Verify peer certificate against Root CA, then apply Trust On First Use (TOFU) Pinning"""
        ca_path = self._get_ca_path()
        if not ca_path:
            raise Exception("CRITICAL SECURITY ERROR: Root CA certificate (rootCA.pem) not found. Cannot verify peer certificate.")

        if not verify_certificate(cert_pem, ca_path):
            raise Exception(f"CRITICAL SECURITY ERROR: {target_username}'s certificate verification failed! The certificate is expired or not signed by the Root CA.")

        pin_file = os.path.join(os.path.dirname(self.key_path), "known_peers.json")
        cert_hash = hashlib.sha256(cert_pem.encode()).hexdigest()

        known_peers = {}
        if os.path.exists(pin_file):
            with open(pin_file, "r") as f:
                known_peers = json.load(f)

        if target_username in known_peers:
            if known_peers[target_username] != cert_hash:
                raise Exception(f"CRITICAL SECURITY ALERT: {target_username}'s certificate has changed! MITM attack detected.")
        else:
            known_peers[target_username] = cert_hash
            with open(pin_file, "w") as f:
                json.dump(known_peers, f)

    def _handle_peer_cert_response(self, packet):
        payload = packet["payload"]
        target = payload["target"]
        target_cert = payload["cert"]
        target_ip = payload.get("ip")
        target_port = payload.get("port")

        # 1. MITM PROTECTION: Pin the certificate
        try:
            self._verify_and_pin_cert(target, target_cert)
        except Exception as e:
            if self.message_callback:
                self.message_callback("__SYSTEM__", str(e))
            return

        # 2. TRUE E2EE: Generate Ephemeral EC Key Pair
        alice_private_key, alice_public_key_b64 = generate_ephemeral_keypair()
        challenge_nonce = os.urandom(16)

        users = sorted([self.username, target])
        session_id = f"direct_{users[0]}_{users[1]}"

        # 3. Sign Alice's ephemeral public key with her long-term RSA private key using RSA-PSS
        signature = sign_nonce(self.key_path, alice_public_key_b64.encode(), password=self.passphrase.encode() if self.passphrase is not None else None)

        # 4. Save session locally (ratchet will be initialized in _handle_session_confirm)
        self.sessions[session_id] = {
            "ephemeral_private_key": alice_private_key,
            "peer_cert": target_cert,
            "challenge": challenge_nonce, 
            "confirmed": False            
        }
        
        with open(self.key_path.replace(".key", ".crt"), "r") as f:
            my_cert = f.read()
            
        try:
            temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp.connect(("8.8.8.8", 80))
            my_ip = temp.getsockname()[0]
            temp.close()
        except:
            my_ip = "127.0.0.1"

        if self.session_callback:
            self.session_callback(session_id)

        # 5. Tell the KDC to securely forward the package
        send_packet(self.sock, {
            "type": "RELAY_SESSION_KEY",
            "payload": {
                "target": target,
                "session_id": session_id,
                "ephemeral_key": alice_public_key_b64,
                "signature": signature,
                "challenge": base64.b64encode(challenge_nonce).decode(),
                "peer_ip": my_ip,
                "peer_port": self.peer_port,
                "peer_cert": my_cert
            }
        })

    # ==========================================================
    # INTERNAL NETWORK LOOPS
    # ==========================================================

    def _start_peer_server(self):
        if self.peer_listener_sock:
            return
        def peer_server():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind(("0.0.0.0", self.peer_port))
                server.listen(5)
                self.peer_listener_sock = server
            except Exception as e:
                self.logger.error(f"Failed to bind peer server socket on port {self.peer_port}: {e}")
                return

            while self.is_running:
                try:
                    conn, _ = server.accept()
                except Exception:
                    break
                threading.Thread(
                    target=self._handle_peer_connection,
                    args=(conn,),
                    daemon=True
                ).start()

        threading.Thread(target=peer_server, daemon=True).start()

    def _handle_peer_connection(self, conn):
        session_id_registered = None  

        while True:
            try:
                packet = receive_packet(conn)
            except:
                break

            if not packet:
                break

            ptype = packet.get("type")
            payload = packet.get("payload", {})
            session_id = payload.get("session_id")

            if session_id and session_id not in self.peer_sockets:
                self.peer_sockets[session_id] = conn
                session_id_registered = session_id

            if ptype == "SESSION_MESSAGE":
                self._handle_encrypted_message(packet)
            elif ptype == "FILE_CHUNK":
                self._handle_file_chunk(packet)
            elif ptype == "SESSION_END":
                self._handle_session_end(packet)
            elif ptype == "SESSION_END_ACK":
                self._handle_session_end_ack(packet)
            elif ptype == "SESSION_CONFIRM": 
                self._handle_session_confirm(packet)
                
        if session_id_registered and session_id_registered in self.peer_sockets:
            del self.peer_sockets[session_id_registered]

    def _start_receive_loop(self):
        def receive_loop():
            while True:
                try:
                    packet = receive_packet(self.sock)
                except Exception:
                    packet = None

                if not packet:
                    if self.is_running:
                        self.logger.warning("Connection to KDC lost. Initiating auto-reconnect...")
                        if self.message_callback:
                            self.message_callback("__SYSTEM__", "Connection to the server was lost. Reconnecting...")
                        self._reconnect()
                    break

                ptype = packet.get("type")

                if ptype == "SESSION_INFO":
                    self._handle_session_info(packet)
                elif ptype == "GROUP_MESSAGE":
                    self._handle_encrypted_message(packet)
                elif ptype == "GROUP_CREATED":
                    self._handle_group_created(packet)
                elif ptype == "MEMBER_CERTS_RESPONSE":
                    self._handle_member_certs_response(packet)
                elif ptype == "ONLINE_USERS":
                    users_list = packet["payload"]["users"]
                    if self.message_callback:
                        self.message_callback("__ONLINE__", users_list)
                elif ptype == "PEER_CERT_RESPONSE":
                    self._handle_peer_cert_response(packet)
                elif ptype == "PING":
                    try:
                        send_packet(self.sock, {"type": "PONG", "payload": {}})
                    except Exception as e:
                        self.logger.error(f"Failed to send PONG response: {e}")
                elif ptype == "AUTH_FAILED":
                    err_msg = packet.get("payload", {}).get("message", "Forced disconnect")
                    if self.message_callback:
                        self.message_callback("__SYSTEM__", err_msg)
                    self.shutdown()
                    break
                elif ptype == "ERROR":
                    err_msg = packet.get("payload", {}).get("message", "Server Error")
                    if self.message_callback:
                        self.message_callback("__ERROR__", err_msg)
                

        threading.Thread(target=receive_loop, daemon=True).start()

    def _reconnect(self):
        with self._reconnect_lock:
            if self._reconnecting:
                self.logger.debug("Reconnection already in progress.")
                return
            self._reconnecting = True

        def reconnect_thread():
            backoff = 1.0
            max_backoff = 32.0
            
            while self.is_running:
                self.logger.info(f"Attempting to reconnect to KDC in {backoff} seconds...")
                time.sleep(backoff)
                
                if not self.is_running:
                    break
                
                try:
                    self.logger.info("Attempting KDC connection & authentication...")
                    if self.sock:
                        try:
                            self.sock.close()
                        except:
                            pass
                    
                    self._establish_socket_and_authenticate()
                    self._register_peer_info()
                    self._start_receive_loop()
                    
                    self.logger.info("Reconnection successful.")
                    if self.message_callback:
                        self.message_callback("__SYSTEM__", "Reconnected to the server successfully.")
                    
                    with self._reconnect_lock:
                        self._reconnecting = False
                    break
                except Exception as e:
                    self.logger.error(f"Reconnection attempt failed: {e}")
                    backoff = min(backoff * 2, max_backoff)
            
            if not self.is_running:
                with self._reconnect_lock:
                    self._reconnecting = False

        threading.Thread(target=reconnect_thread, daemon=True).start()

    # ==========================================================
    # DATA HANDLERS
    # ==========================================================

    def _handle_session_info(self, packet):
        payload = packet["payload"]
        peer_cert = payload.get("peer_cert")
        session_id = payload["session_id"]
        
        # Identify the sender if it's a direct chat
        if session_id.startswith("direct_"):
            parts = session_id.split("_")
            sender = parts[1] if parts[2] == self.username else parts[2]
            
            # 1. MITM PROTECTION: Pin Certificate
            try:
                self._verify_and_pin_cert(sender, peer_cert)
            except Exception as e:
                if self.message_callback:
                    self.message_callback("__SYSTEM__", str(e))
                return
        
        alice_public_key_b64 = payload["ephemeral_key"]

        # 2. MITM PROTECTION: Verify Alice's signature on her ephemeral key (Direct Chats)
        if session_id.startswith("direct_") and "signature" in payload:
            try:
                verify_signature(peer_cert, alice_public_key_b64.encode(), payload["signature"])
            except Exception:
                err = f"CRITICAL: Fake ephemeral key signature detected from {sender}! Dropping connection."
                self.logger.critical(err)
                if self.message_callback:
                    self.message_callback("__SYSTEM__", err)
                return

        # 3. Generate Bob's ephemeral EC key pair, sign it, and derive ratchet
        bob_private_key, bob_public_key_b64 = generate_ephemeral_keypair()
        bob_signature = sign_nonce(self.key_path, bob_public_key_b64.encode(), password=self.passphrase.encode() if self.passphrase is not None else None)
        shared_secret = derive_shared_secret(bob_private_key, alice_public_key_b64)
        ratchet = RatchetState.from_shared_secret(shared_secret, initiator=False)

        self.sessions[session_id] = {
            "ratchet": ratchet,
            "peer_cert": peer_cert,
            "confirmed": True 
        }

        peer_ip = payload.get("peer_ip")
        peer_port = payload.get("peer_port")

        if self.session_callback:
            self.session_callback(session_id)

        if peer_ip and peer_port:
            try:
                peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_sock.settimeout(3.0) 
                peer_sock.connect((peer_ip, peer_port))
                peer_sock.settimeout(None)
                self.peer_sockets[session_id] = peer_sock
                
                self.logger.info(f"Established E2EE connection to {peer_ip}:{peer_port}")

                import threading
                threading.Thread(
                    target=self._handle_peer_connection,
                    args=(peer_sock,),
                    daemon=True
                ).start()

                if "challenge" in payload:
                    challenge_bytes = base64.b64decode(payload["challenge"])
                    # Derive temporary MAC key matching Alice's verification path
                    temp_mac_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'secure_chat_pfs_key_exchange',
                    ).derive(shared_secret)
                    mac = generate_mac(temp_mac_key, challenge_bytes)
                    
                    send_packet(peer_sock, {
                        "type": "SESSION_CONFIRM",
                        "payload": {
                            "session_id": session_id,
                            "ephemeral_key": bob_public_key_b64,
                            "signature": bob_signature,
                            "mac": mac
                        }
                    })
                    self.logger.info("Sent MAC confirmation to peer.")
                    
            except Exception as e:
                self.logger.error(f"Failed to connect to peer {peer_ip}:{peer_port} - {e}")
        else:
            self.logger.info(f"Established session relay: {session_id}")

    def _handle_encrypted_message(self, packet):
        payload = packet["payload"]
        session_id = payload["session_id"]
        sender = payload.get("sender", "unknown") 

        if session_id not in self.sessions:
            retries = 0
            while session_id not in self.sessions and retries < 10:
                time.sleep(0.1)
                retries += 1

        session = self.sessions.get(session_id)
        if not session:
            return

        counter = payload["counter"]
        packet_time = payload.get("timestamp", 0)

        current_time = int(time.time())
        if abs(current_time - packet_time) > 60:
            self.logger.warning(f"Blocked replay attack: Packet from {sender} outside time window.")
            return

        ad = f"{session_id}:{sender}:{counter}:{packet_time}".encode()

        # --- DOUBLE RATCHET for direct sessions ---
        if "ratchet" in session:
            try:
                msg_key = session["ratchet"].next_decrypt_key(counter)
            except ValueError as e:
                self.logger.warning(f"Ratchet rejected message from {sender} (counter {counter}): {e}")
                return
            try:
                plaintext = aes_decrypt(msg_key, payload["nonce"], payload["ciphertext"], ad)
            except Exception:
                warn_msg = f"[SECURITY WARNING] Decryption failed for message from {sender} (counter {counter}). Possible header modification or integrity failure!"
                self.logger.warning(warn_msg)
                if self.message_callback:
                    self.message_callback("__SYSTEM__", warn_msg)
                return
            finally:
                del msg_key
        else:
            # Legacy path for group sessions
            last_counter = session["recv_counters"].get(sender, 0)
            if counter <= last_counter:
                self.logger.warning(f"Blocked replay attack: Dropped old message from {sender}")
                return
            interval_index = (counter - 1) // ROTATION_INTERVAL
            active_interval_key = get_interval_key(session["key"], interval_index)
            try:
                plaintext = aes_decrypt(
                    active_interval_key,
                    payload["nonce"],
                    payload["ciphertext"],
                    ad
                )
            except Exception:
                warn_msg = f"[SECURITY WARNING] Decryption failed for message from {sender} (counter {counter}). Possible header modification or integrity failure!"
                self.logger.warning(warn_msg)
                if self.message_callback:
                    self.message_callback("__SYSTEM__", warn_msg)
                return
            session["recv_counters"][sender] = counter

        display_text = f"{sender}: {plaintext.decode()}" if sender != "unknown" else plaintext.decode()

        if self.message_callback:
            self.message_callback(session_id, display_text)

    def _handle_file_chunk(self, packet):
        payload = packet["payload"]

        session_id = payload["session_id"]
        sender = payload.get("sender", "unknown")
        filename = payload["filename"]
        chunk_index = payload["chunk_index"]
        total_chunks = payload["total_chunks"]
        counter = payload["counter"]

        session = self.sessions.get(session_id)
        if not session:
            return

        timestamp = payload.get("timestamp", 0)
        ad = f"{session_id}:{sender}:{counter}:{timestamp}".encode()

        # --- DOUBLE RATCHET for direct sessions ---
        if "ratchet" in session:
            try:
                msg_key = session["ratchet"].next_decrypt_key(counter)
            except ValueError as e:
                self.logger.warning(f"Ratchet rejected file chunk from {sender} (counter {counter}): {e}")
                return
            try:
                chunk_data = aes_decrypt(msg_key, payload["nonce"], payload["ciphertext"], ad)
            except Exception:
                warn_msg = f"[SECURITY WARNING] Decryption failed for file chunk from {sender} (counter {counter}, file {filename}). Possible header modification or integrity failure!"
                self.logger.warning(warn_msg)
                if self.message_callback:
                    self.message_callback("__SYSTEM__", warn_msg)
                return
            finally:
                del msg_key
        else:
            # Legacy path for group sessions
            last_counter = session["recv_counters"].get(sender, 0)
            if counter <= last_counter:
                return
            interval_index = (counter - 1) // ROTATION_INTERVAL
            active_interval_key = get_interval_key(session["key"], interval_index)
            try:
                chunk_data = aes_decrypt(
                    active_interval_key,
                    payload["nonce"],
                    payload["ciphertext"],
                    ad
                )
            except Exception:
                warn_msg = f"[SECURITY WARNING] Decryption failed for file chunk from {sender} (counter {counter}, file {filename}). Possible header modification or integrity failure!"
                self.logger.warning(warn_msg)
                if self.message_callback:
                    self.message_callback("__SYSTEM__", warn_msg)
                return
            session["recv_counters"][sender] = counter

        # WRITE DIRECTLY TO DISK (Prevents RAM exhaustion)
        output_path = f"received_{filename}"
        with open(output_path, "ab") as f:
            f.write(chunk_data)

        key_tuple = (session_id, filename)
        if key_tuple not in self.file_buffers:
            self.file_buffers[key_tuple] = {"received_chunks": 0, "total": total_chunks}
            
        self.file_buffers[key_tuple]["received_chunks"] += 1

        if self.file_buffers[key_tuple]["received_chunks"] == total_chunks:
            if self.file_callback:
                self.file_callback(output_path)
            del self.file_buffers[key_tuple]

    def _handle_session_end(self, packet):
        session_id = packet["payload"]["session_id"]
        peer_sock = self.peer_sockets.get(session_id)

        if peer_sock:
            send_packet(peer_sock, {
                "type": "SESSION_END_ACK",
                "payload": {"session_id": session_id}
            })

        self._destroy_session(session_id)

        if self.message_callback:
            self.message_callback(session_id, "[Session Ended by Peer]")

    def _handle_session_end_ack(self, packet):
        self._destroy_session(packet["payload"]["session_id"])

    def _destroy_session(self, session_id):
        if session_id in self.peer_sockets:
            try:
                self.peer_sockets[session_id].close()
            except:
                pass
            del self.peer_sockets[session_id]

        if session_id in self.sessions:
            # Zeroize ratchet key material before discarding
            ratchet = self.sessions[session_id].get("ratchet")
            if ratchet:
                ratchet.clear()
            del self.sessions[session_id]

    def _register_peer_info(self):
        try:
            temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp.connect(("8.8.8.8", 80))
            local_ip = temp.getsockname()[0]
            temp.close()
        except:
            local_ip = "127.0.0.1"

        send_packet(self.sock, {
            "type": "REGISTER_PEER_INFO",
            "payload": {
                "ip": local_ip,
                "port": self.peer_port
            }
        })

    def _handle_member_certs_response(self, packet):
        payload = packet["payload"]
        room = payload["room"]
        certs = payload["certs"]  # username -> cert_pem
        
        pending = self.pending_groups.pop(room, None)
        if not pending:
            return
            
        members = pending["members"]
        
        # Verify that all requested members are online or their certificates are retrieved
        missing = [m for m in members if m not in certs]
        if missing:
            err_msg = f"Failed to create group '{room}': Users {', '.join(missing)} are offline or their certificates are unavailable."
            self.logger.error(err_msg)
            if self.message_callback:
                self.message_callback("__ERROR__", err_msg)
            return
            
        # Verify and pin all member certificates
        for member, cert_pem in certs.items():
            try:
                self._verify_and_pin_cert(member, cert_pem)
            except Exception as e:
                err_msg = f"Security Error verifying certificate for {member}: {e}"
                self.logger.error(err_msg)
                if self.message_callback:
                    self.message_callback("__ERROR__", err_msg)
                return

        # Generate a random 32-byte group key
        group_key = os.urandom(32)
        
        # Build the keys dictionary
        keys_payload = {}
        
        # Load own certificate
        try:
            cert_path = self.key_path.replace(".key", ".crt")
            if not os.path.exists(cert_path):
                cert_path = self.key_path.replace(".key", ".pem")
            with open(cert_path, "r") as f:
                my_cert = f.read()
        except Exception as e:
            err_msg = f"Failed to load own certificate: {e}"
            self.logger.error(err_msg)
            if self.message_callback:
                self.message_callback("__ERROR__", err_msg)
            return

        all_certs = certs.copy()
        all_certs[self.username] = my_cert
        
        # Encrypt and sign for each member
        for member, cert_pem in all_certs.items():
            try:
                # Encrypt the group key with the member's public key (RSA-OAEP-SHA256)
                encrypted_key = encrypt_for_cert(cert_pem, group_key)
                
                # Sign the encrypted payload with Alice's long-term private key
                signature = sign_nonce(self.key_path, encrypted_key.encode(), password=self.passphrase.encode() if self.passphrase is not None else None)
                
                keys_payload[member] = {
                    "encrypted_key": encrypted_key,
                    "signature": signature
                }
            except Exception as e:
                err_msg = f"Failed to encrypt/sign key for {member}: {e}"
                self.logger.error(err_msg)
                if self.message_callback:
                    self.message_callback("__ERROR__", err_msg)
                return

        # Send CREATE_GROUP to KDC
        send_packet(self.sock, {
            "type": "CREATE_GROUP",
            "payload": {
                "room": room,
                "members": [self.username] + members,
                "keys": keys_payload
            }
        })

    def _handle_group_created(self, packet):
        payload = packet["payload"]
        session_id = payload["session_id"]
        creator = payload.get("creator")
        creator_cert = payload.get("creator_cert")
        encrypted_key = payload.get("encrypted_key")
        signature = payload.get("signature")
        
        if not creator or not creator_cert or not encrypted_key or not signature:
            self.logger.error(f"Malformed GROUP_CREATED packet for room {session_id}")
            return

        if session_id not in self.sessions:
            try:
                # 1. Verify creator's certificate against Root CA & apply TOFU pinning
                # If the creator is ourselves, we can bypass PIN check (we already trust ourselves)
                if creator != self.username:
                    self._verify_and_pin_cert(creator, creator_cert)
                
                # 2. Verify signature on encrypted key using creator's verified public key
                verify_signature(creator_cert, encrypted_key.encode(), signature)
                
                # 3. Decrypt the group key using our private RSA key
                group_key = decrypt_with_private_key(self.key_path, encrypted_key, password=self.passphrase.encode() if self.passphrase is not None else None)
                
                # 4. Initialize session with decrypted group key
                self.sessions[session_id] = {
                    "key": group_key,
                    "send_counter": 0,
                    "recv_counters": {},
                    "peer_cert": creator_cert
                }
                self.logger.info(f"Successfully joined secure group {session_id} created by {creator}")
            except Exception as e:
                err_msg = f"CRITICAL: Failed to join secure group '{session_id}': {e}"
                self.logger.error(err_msg)
                if self.message_callback:
                    self.message_callback("__ERROR__", err_msg)
                return

        # Trigger the UI to add the room
        if self.session_callback:
            self.session_callback(session_id)

    def register_new_user(self, username, cert_path, key_path, master_password, passphrase=None):
        username = username.lower()

        import ssl
        ca_path = self._get_ca_path(key_path)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        context.check_hostname = True
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            # Temporary workaround: disable strict X509 validation because the self-signed dev CA
            # is missing strict RFC-5280 extensions. 
            # TODO: Regenerate the CA with correct extensions.
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = context.wrap_socket(raw_sock, server_hostname=self.kdc_ip)
        sock.connect((self.kdc_ip, self.kdc_port))

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, username),
                ])
            )
            .sign(private_key, hashes.SHA256())
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        send_packet(sock, {
            "type": "REGISTER_USER",
            "payload": {
                "csr": csr_pem,
                "master_password": master_password
            }
        })

        response = receive_packet(sock)
        sock.close()

        if not response:
            raise Exception("No response from KDC. Is the server running?")
            
        if response.get("type") == "ERROR":
            error_msg = response.get("payload", {}).get("message", "Unknown KDC Error")
            raise Exception(f"Server rejected registration: {error_msg}")

        if response.get("type") != "REGISTER_SUCCESS":
            raise Exception("Registration failed for an unknown reason.")

        cert_pem = response["payload"]["certificate"]

        with open(key_path, "wb") as f:
            if not passphrase:
                raise ValueError("Passphrase cannot be empty. Private keys must be encrypted.")
            f.write(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(passphrase.encode())
                )
            )

        with open(cert_path, "w") as f:
            f.write(cert_pem)

        # Setup user-specific file logging
        log_dir = os.path.dirname(key_path)
        log_file = os.path.join(log_dir, "client.log")
        from client.config import LOG_LEVEL
        self.logger = setup_logger("Client", log_file=log_file, level=LOG_LEVEL, console_level=logging.ERROR)
        self.logger.info(f"Client registered successfully as '{username}'")



    def _handle_session_confirm(self, packet):
        payload = packet["payload"]
        session_id = payload["session_id"]
        received_mac = payload["mac"]
        
        session = self.sessions.get(session_id)
        if not session or "challenge" not in session:
            return
            
        bob_public_key_b64 = payload["ephemeral_key"]
        bob_signature = payload["signature"]
        peer_cert = session["peer_cert"]

        # 1. Verify Bob's signature on his ephemeral public key using RSA-PSS
        try:
            verify_signature(peer_cert, bob_public_key_b64.encode(), bob_signature)
        except Exception:
            err = "[System: CRITICAL - Peer failed ephemeral key signature verification!]"
            self.logger.critical(err)
            if self.message_callback:
                self.message_callback(session_id, err)
            self._destroy_session(session_id)
            return

        # 2. Derive the shared secret and initialize the Double Ratchet (Alice is initiator)
        alice_private_key = session["ephemeral_private_key"]
        shared_secret = derive_shared_secret(alice_private_key, bob_public_key_b64)

        # 3. Verify the MAC using a temporary session key derived from the shared secret
        #    (Bob computed the MAC with the same shared secret during SESSION_CONFIRM)
        temp_session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_chat_pfs_key_exchange',
        ).derive(shared_secret)

        if verify_mac(temp_session_key, session["challenge"], received_mac):
            # 4. Initialize the Double Ratchet (Alice = initiator)
            ratchet = RatchetState.from_shared_secret(shared_secret, initiator=True)
            session["ratchet"] = ratchet
            session["confirmed"] = True
            # Clean up ephemeral key — no longer needed
            session.pop("ephemeral_private_key", None)
            session.pop("challenge", None)
            self.logger.info(f"Session {session_id} confirmed with Double Ratchet!")
            if self.message_callback:
                self.message_callback(session_id, "[System: Secure connection confirmed by peer]")
        else:
            err = "[System: CRITICAL - Peer failed key confirmation! Session compromised.]"
            self.logger.critical(err)
            if self.message_callback:
                self.message_callback(session_id, err)
            self._destroy_session(session_id)

    # ==========================================================
    # SAFETY NUMBERS (Identity Verification)
    # ==========================================================

    def get_safety_number(self, session_id):
        """Compute the 60-digit Safety Number fingerprint for a direct session."""
        session = self.sessions.get(session_id)
        if not session:
            raise Exception("Session not found")
        peer_cert = session.get("peer_cert")
        if not peer_cert:
            raise Exception("Peer certificate not available for this session")

        my_cert = self.get_my_cert()

        # Determine peer username from session_id
        parts = session_id.split("_")
        if len(parts) >= 3 and parts[0] == "direct":
            peer_username = parts[1] if parts[2] == self.username else parts[2]
        else:
            raise Exception("Safety Numbers are only available for direct sessions")

        return compute_safety_number(my_cert, self.username, peer_cert, peer_username)

    def get_my_cert(self):
        """Load and return this client's certificate PEM string."""
        cert_path = self.key_path.replace(".key", ".crt")
        if not os.path.exists(cert_path):
            cert_path = self.key_path.replace(".key", ".pem")
        with open(cert_path, "r") as f:
            return f.read()