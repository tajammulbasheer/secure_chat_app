import sys
import os
import threading
from client.client_engine import ClientEngine
from client.config import KDC_IP, KDC_PORT

# Enable ANSI colors on Windows Command Prompt
if os.name == 'nt':
    os.system('')

# ==========================================
# COLOR DEFINITIONS
# ==========================================
class Colors:
    SYSTEM = '\033[93m'   # Yellow
    SUCCESS = '\033[92m'  # Green
    ERROR = '\033[91m'    # Red
    PEER = '\033[96m'     # Cyan
    YOU = '\033[95m'      # Magenta
    INFO = '\033[94m'     # Blue
    PROMPT = '\033[1;92m' # Bold Green
    RESET = '\033[0m'     # Reset to default

# ==========================================
# ASYNC PRINT HELPER
# ==========================================
def print_async(msg):
    """
    Clears the current input line, prints the message, 
    and redraws the colored input prompt so typing isn't interrupted.
    """
    print(f"\r\033[K{msg}\n{Colors.PROMPT}>{Colors.RESET} ", end="", flush=True)

# ==========================================
# MAIN CLI LOOP
# ==========================================
def main():
    if len(sys.argv) < 3:
        print(f"{Colors.ERROR}Usage: python3 cli_app.py <Username> <PeerPort>{Colors.RESET}")
        print(f"{Colors.ERROR}Example: python3 cli_app.py Alice 7000{Colors.RESET}")
        sys.exit(1)

    username = sys.argv[1].lower()
    peer_port = int(sys.argv[2])

    CLIENT_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(CLIENT_DIR, "data")
    user_folder = os.path.join(DATA_DIR, f"client_{username}")
    os.makedirs(user_folder, exist_ok=True)

    cert_path = os.path.join(user_folder, "client.crt")
    key_path = os.path.join(user_folder, "client.key")

    engine = ClientEngine(
        kdc_ip=KDC_IP,
        kdc_port=KDC_PORT,
        peer_port=peer_port
    )

    # ------------------------------------------
    # 1. REGISTER CALLBACKS
    # ------------------------------------------
    def on_message(session_id, message):
        if session_id == "__ONLINE__":
            print_async(f"{Colors.INFO}[Online Users]: {', '.join(message)}{Colors.RESET}")
        elif session_id == "__SYSTEM__":
            print_async(f"{Colors.SYSTEM} [SYSTEM ALERT]: {message}{Colors.RESET}")
            if "banned" in message.lower() or "revoked" in message.lower():
                os._exit(1) # Force quit if banned
        elif session_id == "__ERROR__":
            print_async(f"{Colors.ERROR} [SERVER ERROR]: {message}{Colors.RESET}")
        else:
            print_async(f"{Colors.PEER}[{session_id}] {message}{Colors.RESET}")

    def on_file(filepath):
        print_async(f"{Colors.SUCCESS} [System] File securely downloaded to: {filepath}{Colors.RESET}")

    def on_session(session_id):
        print_async(f"{Colors.SUCCESS} [System] Secure session established: {session_id}{Colors.RESET}")

    engine.register_message_callback(on_message)
    engine.register_file_callback(on_file)
    engine.register_session_callback(on_session)

    # ------------------------------------------
    # 2. REGISTRATION FLOW
    # ------------------------------------------
    passphrase = None
    if not os.path.exists(cert_path):
        print(f"{Colors.INFO}No certificate found for '{username}'. Initiating registration...{Colors.RESET}")
        master_password = input(f"{Colors.SYSTEM}Enter Master Password to authorize registration: {Colors.RESET}").strip()
        while True:
            passphrase = input(f"{Colors.SYSTEM}Create a passphrase to encrypt your private key: {Colors.RESET}").strip()
            if not passphrase:
                print(f"{Colors.ERROR}Passphrase cannot be empty.{Colors.RESET}")
                continue
            confirm = input(f"{Colors.SYSTEM}Confirm your private key passphrase: {Colors.RESET}").strip()
            if passphrase != confirm:
                print(f"{Colors.ERROR}Passphrases do not match. Try again.{Colors.RESET}")
                continue
            break
        try:
            engine.register_new_user(username, cert_path, key_path, master_password, passphrase)
            print(f"{Colors.SUCCESS} Registration successful!{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR} Registration failed: {e}{Colors.RESET}")
            sys.exit(1)
    else:
        # Prompt the user to enter their key passphrase on startup if a key already exists.
        passphrase = input(f"{Colors.SYSTEM}Enter your private key passphrase: {Colors.RESET}").strip()

    # ------------------------------------------
    # 3. CONNECTION FLOW
    # ------------------------------------------
    print(f"{Colors.INFO}Connecting to STS as '{username}'...{Colors.RESET}")
    try:
        engine.connect(cert_path, key_path, passphrase)
        print(f"{Colors.SUCCESS} Connected successfully!{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.ERROR}Connection failed: {e}{Colors.RESET}")
        sys.exit(1)

    # ------------------------------------------
    # 4. INTERACTIVE SHELL
    # ------------------------------------------
    print(f"\n{Colors.INFO}--- SECURE CHAT CLI ---{Colors.RESET}")
    print(f"{Colors.SYSTEM}Commands:{Colors.RESET}")
    print(f"  {Colors.PROMPT}direct{Colors.RESET} <username>              - Start an E2EE chat")
    print(f"  {Colors.PROMPT}group{Colors.RESET} <room> <user1> <user2>   - Create a group chat")
    print(f"  {Colors.PROMPT}msg{Colors.RESET} <session_id> <text>        - Send a message")
    print(f"  {Colors.PROMPT}file{Colors.RESET} <session_id> <filepath>   - Send a file")
    print(f"  {Colors.PROMPT}end{Colors.RESET} <session_id>               - End a session")
    print(f"  {Colors.PROMPT}exit{Colors.RESET}                           - Close application")
    print(f"{Colors.INFO}-----------------------{Colors.RESET}\n")

    while True:
        try:
            # Add color to the input prompt itself
            cmd_line = input(f"{Colors.PROMPT}>{Colors.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not cmd_line:
            continue

        parts = cmd_line.split()
        cmd = parts[0].lower()

        try:
            if cmd == "exit" or cmd == "quit":
                break

            elif cmd == "direct":
                if len(parts) < 2:
                    print_async(f"{Colors.SYSTEM}Usage: direct <username>{Colors.RESET}")
                else:
                    engine.create_direct(parts[1])

            elif cmd == "group":
                if len(parts) < 3:
                    print_async(f"{Colors.SYSTEM}Usage: group <room_name> <user1> <user2> ...{Colors.RESET}")
                else:
                    room = parts[1]
                    members = parts[2:]
                    engine.create_group(room, members)

            elif cmd == "msg":
                if len(parts) < 3:
                    print_async(f"{Colors.SYSTEM}Usage: msg <session_id> <message text>{Colors.RESET}")
                else:
                    session_id = parts[1]
                    text = " ".join(parts[2:])
                    engine.send_message(session_id, text)
                    print_async(f"{Colors.YOU}[{session_id}] You: {text}{Colors.RESET}") # Print locally

            elif cmd == "file":
                if len(parts) < 3:
                    print_async(f"{Colors.SYSTEM}Usage: file <session_id> <filepath>{Colors.RESET}")
                else:
                    session_id = parts[1]
                    filepath = parts[2]
                    engine.send_file(session_id, filepath)
                    print_async(f"{Colors.YOU}[{session_id}] You sent file: {os.path.basename(filepath)}{Colors.RESET}")

            elif cmd == "end":
                if len(parts) < 2:
                    print_async(f"{Colors.SYSTEM}Usage: end <session_id>{Colors.RESET}")
                else:
                    engine.end_session(parts[1])
                    print_async(f"{Colors.INFO}Ended session {parts[1]}{Colors.RESET}")

            else:
                print_async(f"{Colors.ERROR}Unknown command: {cmd}. Type 'help' for commands.{Colors.RESET}")

        except Exception as e:
            print_async(f"{Colors.ERROR}Error executing command: {e}{Colors.RESET}")

    # Cleanup
    print(f"\n{Colors.INFO}Shutting down...{Colors.RESET}")
    engine.shutdown()

if __name__ == "__main__":
    main()