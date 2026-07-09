import struct
import json

HEADER_SIZE = 4
MAX_PACKET_SIZE = 10 * 1024 * 1024  # 10 Megabytes limit

def send_packet(sock, data: dict):
    raw = json.dumps(data).encode()
    length = struct.pack("!I", len(raw))
    sock.sendall(length + raw)

def receive_packet(sock):
    header = sock.recv(HEADER_SIZE)
    if not header:
        return None

    length = struct.unpack("!I", header)[0]
    
    # ---> ADD THIS PROTECTION <---
    if length > MAX_PACKET_SIZE:
        print(f"[SECURITY WARNING] Dropping massive packet of size {length} bytes")
        return None 
    # -----------------------------

    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk

    return json.loads(data.decode())