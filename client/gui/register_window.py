from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox
)
import os


class RegisterWindow(QDialog):

    def __init__(self, engine, project_root):
        super().__init__()

        self.engine = engine
        self.project_root = project_root

        self.setWindowTitle("Register New User")
        self.setMinimumWidth(300)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Enter Username:"))
        self.username_input = QLineEdit()
        layout.addWidget(self.username_input)

        layout.addWidget(QLabel("Master Password:"))
        self.master_input = QLineEdit()
        self.master_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.master_input)

        layout.addWidget(QLabel("Private Key Passphrase:"))
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.passphrase_input)

        self.register_button = QPushButton("Register")
        self.register_button.setObjectName("primaryButton")
        self.register_button.clicked.connect(self._register_user)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def _register_user(self):

        username = self.username_input.text().strip()
        master_password = self.master_input.text().strip()
        passphrase = self.passphrase_input.text().strip()

        if not username or not master_password or not passphrase:
            QMessageBox.warning(self, "Error", "All fields required.")
            return

        user_dir = os.path.join(self.project_root, f"client_{username}")
        os.makedirs(user_dir, exist_ok=True)

        cert_path = os.path.join(user_dir, "client.crt")
        key_path = os.path.join(user_dir, "client.key")

        try:
            self.engine.register_new_user(username, cert_path, key_path, master_password, passphrase)
            QMessageBox.information(self, "Success", "User registered successfully.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))