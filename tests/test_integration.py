import socket
import threading
import time
import pytest
import os
import importlib
import server
import server.config
import server.database
import server.sts
import client.config
import client.client_engine
from client.client_engine import ClientEngine

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def wait_until(condition, timeout=5.0, interval=0.1):
    start = time.time()
    while time.time() - start < timeout:
        if condition():
            return True
        time.sleep(interval)
    return False

@pytest.fixture
def sts_server(tmp_path, monkeypatch):
    """
    Spawns the STS server on a dynamic port in a background thread
    and stops it cleanly on teardown.

    A fresh self-signed Root CA is generated per-test so the integration
    suite never requires the real `rootCA.key` to be committed to the repo.
    """
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # 1. Generate ephemeral Root CA for this test run
    db_dir = tmp_path / "server_data"
    os.makedirs(db_dir, exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    try:
        from datetime import UTC
        now = datetime.datetime.now(UTC)
    except ImportError:
        now = datetime.datetime.utcnow()

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = str(db_dir / "rootCA.pem")
    ca_key_path = str(db_dir / "rootCA.key")

    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))


    # 2. Get a free port for the test STS server
    port = get_free_port()

    # 3. Set environment overrides to force STS and Client to use our test settings
    monkeypatch.setenv("STS_HOST", "127.0.0.1")
    monkeypatch.setenv("STS_PORT", str(port))
    monkeypatch.setenv("DB_DIR", str(db_dir))
    monkeypatch.setenv("CA_CERT_PATH", str(db_dir / "rootCA.pem"))
    monkeypatch.setenv("CA_KEY_PATH", str(db_dir / "rootCA.key"))
    monkeypatch.setenv("DB_PATH", str(db_dir / "sts.db"))
    monkeypatch.setenv("USER_DB_PATH", str(db_dir / "users.json"))
    monkeypatch.setenv("BANNED_DB_PATH", str(db_dir / "banned.json"))
    monkeypatch.setenv("CERT_DB_PATH", str(db_dir / "cert_db.json"))
    monkeypatch.setenv("CRL_DB_PATH", str(db_dir / "revoked_serials.json"))
    
    monkeypatch.setenv("KDC_IP", "127.0.0.1")
    monkeypatch.setenv("KDC_PORT", str(port))

    # Reload configuration modules and sts server to apply overrides
    # database must be reloaded first to reset module-level _conn / _db_key
    importlib.reload(server.config)
    importlib.reload(server.database)
    importlib.reload(client.config)
    importlib.reload(server.sts)

    # Patch CA_CERT_PATH directly on the already-imported client_engine module
    # (importlib.reload of client.config alone won't update the bound name in client_engine)
    monkeypatch.setattr(client.client_engine, "CA_CERT_PATH", ca_cert_path)

    # 4. Mock the STS Admin command console input to terminate immediately
    def mock_input(prompt=""):
        raise KeyboardInterrupt
    monkeypatch.setattr('builtins.input', mock_input)

    # 5. Run the STS server in a daemon thread
    server_thread = threading.Thread(target=server.sts.main, daemon=True)
    server_thread.start()
    
    # Allow the server socket bind & listen loop to initialize
    time.sleep(0.5)

    yield port

    # 6. Teardown: Shutdown the server cleanly
    server.sts.shutdown()


@pytest.fixture
def client_factory(tmp_path, sts_server):
    """
    Factory fixture to register and connect client engines,
    ensuring they are cleanly shut down and logs are closed on teardown.
    """
    engines = []

    def _create_client(username, password="admin", passphrase="localpassphrase"):
        client_dir = tmp_path / f"client_{username}"
        os.makedirs(client_dir, exist_ok=True)
        
        cert_path = str(client_dir / f"{username}.crt")
        key_path = str(client_dir / f"{username}.key")
        
        peer_port = get_free_port()
        
        engine = ClientEngine(
            kdc_ip="127.0.0.1",
            kdc_port=sts_server,
            peer_port=peer_port
        )
        engines.append(engine)

        # Register the user
        engine.register_new_user(
            username=username,
            cert_path=cert_path,
            key_path=key_path,
            master_password=password,
            passphrase=passphrase
        )

        # Connect the user
        engine.connect(
            cert_path=cert_path,
            key_path=key_path,
            passphrase=passphrase
        )

        return engine

    yield _create_client

    # Teardown: Shutdown all clients
    for engine in engines:
        try:
            engine.shutdown()
        except Exception:
            pass
        if hasattr(engine, 'logger') and engine.logger:
            for handler in list(engine.logger.handlers):
                try:
                    handler.close()
                except Exception:
                    pass
            engine.logger.handlers.clear()


def test_client_registration_and_login(client_factory):
    """
    Verify client registration, certificate storage, and challenge-response authentication.
    """
    # Create client Alice
    alice = client_factory("testalice")

    # Assert Alice is registered and authenticated
    assert alice.username == "testalice"
    assert os.path.exists(alice.key_path)
    assert os.path.exists(alice.key_path.replace(".key", ".crt"))

    # Assert client log exists
    log_file = os.path.join(os.path.dirname(alice.key_path), "client.log")
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        content = f.read()
        assert "connected and authenticated" in content or "registered successfully" in content


def test_direct_e2ee_chat_handshake(client_factory):
    """
    Verify the E2EE Direct Chat handshake and transmission of encrypted direct messages.
    """
    # 1. Spawn two client engines: Alice and Bob
    alice = client_factory("alice")
    bob = client_factory("bob")

    # Setup message callback lists to collect received messages
    alice_messages = []
    bob_messages = []

    alice.register_message_callback(lambda sid, msg: alice_messages.append((sid, msg)) if not sid.startswith("__") else None)
    bob.register_message_callback(lambda sid, msg: bob_messages.append((sid, msg)) if not sid.startswith("__") else None)

    # 2. Alice requests a direct E2EE session with Bob
    alice.create_direct("bob")

    # 3. Wait until the E2EE direct session is established on both Alice and Bob's ends
    session_id = "direct_alice_bob"
    
    def is_session_established():
        alice_ok = session_id in alice.sessions and alice.sessions[session_id].get("confirmed") is True
        bob_ok = session_id in bob.sessions and bob.sessions[session_id].get("confirmed") is True
        return alice_ok and bob_ok

    assert wait_until(is_session_established, timeout=5.0)

    # 4. Alice sends an E2EE direct message to Bob
    alice.send_message(session_id, "Hello Bob, this is a secure direct message!")

    # Verify Bob receives the decrypted message
    assert wait_until(lambda: any("Hello Bob" in msg for sid, msg in bob_messages), timeout=3.0)
    assert any("Hello Bob" in msg for sid, msg in bob_messages)

    # 5. Bob responds to Alice with an E2EE direct message
    bob.send_message(session_id, "Hi Alice! Our direct session is completely secure.")

    # Verify Alice receives the decrypted message
    assert wait_until(lambda: any("completely secure" in msg for sid, msg in alice_messages), timeout=3.0)
    assert any("completely secure" in msg for sid, msg in alice_messages)


def test_group_chat_e2ee(client_factory):
    """
    Verify group chat creation, key distribution, and group message transmission.
    """
    # 1. Spawn three client engines: Alice, Bob, and Charlie
    alice = client_factory("alice")
    bob = client_factory("bob")
    charlie = client_factory("charlie")

    # Setup message callback lists
    alice_messages = []
    bob_messages = []
    charlie_messages = []

    alice.register_message_callback(lambda sid, msg: alice_messages.append((sid, msg)) if not sid.startswith("__") else None)
    bob.register_message_callback(lambda sid, msg: bob_messages.append((sid, msg)) if not sid.startswith("__") else None)
    charlie.register_message_callback(lambda sid, msg: charlie_messages.append((sid, msg)) if not sid.startswith("__") else None)

    # 2. Alice creates a group room "room1" containing Bob and Charlie
    room_id = "room1"
    alice.create_group(room_id, ["bob", "charlie"])

    # 3. Wait until the group session is established on all three clients
    def is_group_established():
        return (
            room_id in alice.sessions and
            room_id in bob.sessions and
            room_id in charlie.sessions
        )

    assert wait_until(is_group_established, timeout=5.0)

    # 4. Alice sends a group message
    alice.send_message(room_id, "Welcome to the secure team room!")

    # Verify Bob and Charlie receive the decrypted group message
    assert wait_until(lambda: any("Welcome to the secure team room!" in msg for sid, msg in bob_messages), timeout=3.0)
    assert wait_until(lambda: any("Welcome to the secure team room!" in msg for sid, msg in charlie_messages), timeout=3.0)

    # 5. Bob sends a group message
    bob.send_message(room_id, "Thanks Alice! Testing group reply.")

    # Verify Alice and Charlie receive Bob's message
    assert wait_until(lambda: any("Testing group reply." in msg for sid, msg in alice_messages), timeout=3.0)
    assert wait_until(lambda: any("Testing group reply." in msg for sid, msg in charlie_messages), timeout=3.0)


def test_client_auto_reconnect(client_factory):
    """
    Verify that the client auto-reconnects when the connection is dropped.
    """
    alice = client_factory("alice_reconnect")
    system_messages = []
    
    # Track system messages
    alice.register_message_callback(lambda sid, msg: system_messages.append(msg) if sid == "__SYSTEM__" else None)
    
    # Abruptly close the socket from the client side
    # On Linux, close() alone does not always unblock a pending recv() in another thread.
    # We must call shutdown() to force the receive loop to throw an exception immediately.
    try:
        alice.sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    alice.sock.close()
    
    # Wait for lost connection system message
    assert wait_until(lambda: any("lost" in msg for msg in system_messages), timeout=5.0)
    
    # Wait for successful reconnection system message
    assert wait_until(lambda: any("Reconnected" in msg for msg in system_messages), timeout=5.0)
