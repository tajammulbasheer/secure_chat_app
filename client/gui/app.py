import sys
import os
from PyQt6.QtWidgets import QApplication, QMessageBox
from client.client_engine import ClientEngine
from client.config import KDC_IP, KDC_PORT
from client.gui.main_window import MainWindow


def main():

    if len(sys.argv) < 3:
        print("Usage: python3 -m gui.app <Username> <PeerPort>")
        print("Example: python3 -m gui.app Alice 7000")
        sys.exit(1)

    username = sys.argv[1].lower()
    peer_port = int(sys.argv[2])

    app = QApplication(sys.argv)

    CLIENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(CLIENT_DIR, "data")

    user_folder = os.path.join(DATA_DIR, f"client_{username}")

    cert_path = os.path.join(user_folder, "client.crt")
    key_path = os.path.join(user_folder, "client.key")

    if not os.path.exists(cert_path):
        from client.gui.register_window import RegisterWindow

        engine = ClientEngine(
            kdc_ip=KDC_IP,
            kdc_port=KDC_PORT,
            peer_port=peer_port
        )

        register_dialog = RegisterWindow(engine, DATA_DIR)
        register_dialog.exec()

        # After registration, check again
        if not os.path.exists(cert_path):
            QMessageBox.critical(None, "Error", "Registration failed.")
            sys.exit(1)

    engine = ClientEngine(
        kdc_ip=KDC_IP,
        kdc_port=KDC_PORT,
        peer_port=peer_port
    )

    # 1. CREATE GUI AND REGISTER CALLBACKS FIRST
    window = MainWindow(engine)

    # 2. NOW CONNECT TO THE NETWORK
    try:
        if not os.path.exists(cert_path):
            register_dialog.exec()

            # After registration, stop here
            # Do NOT auto-connect
            QMessageBox.information(None, "Info", "Registration complete. Please restart the application.")
            sys.exit(0)
        
        from PyQt6.QtWidgets import QInputDialog, QLineEdit
        passphrase, ok = QInputDialog.getText(
            None,
            "Enter Passphrase",
            "Enter your private key passphrase:",
            QLineEdit.EchoMode.Password
        )
        if not ok:
            sys.exit(0)

        engine.connect(cert_path, key_path, passphrase)
        window.setWindowTitle(f"Secure Chat - {engine.username}")
        window.identity_label.setText(f"Logged in as: {engine.username}")
    except Exception as e:
        QMessageBox.critical(None, "Connection Failed", str(e))
        sys.exit(1)

    # 3. SHOW THE WINDOW
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
