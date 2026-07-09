from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QTextEdit, QLineEdit,
    QPushButton, QLabel, QInputDialog, QFileDialog,
    QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal 
from client.gui.register_window import RegisterWindow
import os

class MainWindow(QMainWindow):
    
    # 1. Define ALL signals at the class level
    incoming_message_signal = pyqtSignal(str, str) 
    new_session_signal = pyqtSignal(str)
    online_users_signal = pyqtSignal(list)

    def __init__(self, engine):
        super().__init__()

        self.engine = engine
        self.setWindowTitle("Secure Chat")
        self.setMinimumSize(300, 100)

        self.current_session = None
        self.chat_history = {} 

        self._build_ui()
        
        # 2. Connect signals to safe UI update methods
        self.incoming_message_signal.connect(self._update_chat_area) 
        self.new_session_signal.connect(self.add_session)
        self.online_users_signal.connect(self._update_online_list)
        
        self._connect_engine()
    # ==========================================================
    # UI BUILD
    # ==========================================================


    def _send_file(self):

        if not self.current_session:
            return

        filepath, _ = QFileDialog.getOpenFileName(self, "Select File")

        if filepath:
            try:
                self.engine.send_file(self.current_session, filepath)
                self.chat_area.append("[File Sent]")
            except Exception as e:
                self.chat_area.append(f"File error: {str(e)}")
    def _build_ui(self):

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)

        # ================= LEFT PANEL =================
        left_layout = QVBoxLayout()
        self.identity_label = QLabel("Logged in as: ...")
        self.identity_label.setStyleSheet("font-weight: bold; color: #2E86C1;")
        left_layout.addWidget(self.identity_label)

        self.online_list = QListWidget()
        left_layout.addWidget(QLabel("Online Users"))
        left_layout.addWidget(self.online_list)

        # self.register_button = QPushButton("Register New User")
        # self.register_button.clicked.connect(self._open_register)
        # left_layout.addWidget(self.register_button)

        self.new_direct_button = QPushButton("New Direct")
        self.new_direct_button.clicked.connect(self._create_direct)
        left_layout.addWidget(self.new_direct_button)

        self.new_group_button = QPushButton("New Group")
        self.new_group_button.clicked.connect(self._create_group)
        left_layout.addWidget(self.new_group_button)

        self.session_list = QListWidget()
        self.session_list.itemClicked.connect(self._on_session_selected)
        left_layout.addWidget(self.session_list)

        main_layout.addLayout(left_layout)

        # ================= RIGHT PANEL =================
        right_panel = QVBoxLayout()

        self.chat_header = QLabel("No session selected")
        self.chat_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_panel.addWidget(self.chat_header)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        right_panel.addWidget(self.chat_area)

        # ---- INPUT AREA ----
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        input_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self._send_message)
        input_layout.addWidget(self.send_button)

        self.file_button = QPushButton("Send File")
        self.file_button.clicked.connect(self._send_file)
        input_layout.addWidget(self.file_button)

        self.end_button = QPushButton("End Session")
        self.end_button.clicked.connect(self._end_session)
        input_layout.addWidget(self.end_button)

        right_panel.addLayout(input_layout)

        main_layout.addLayout(right_panel)

    # ==========================================================
    # ENGINE CONNECTION
    # ==========================================================

    def _connect_engine(self):
            def on_message(session_id, message):
                if session_id == "__ONLINE__":
                    # Safely emit the list of users
                    self.online_users_signal.emit(message)
                    return
                
                # Safely emit the chat message
                self.incoming_message_signal.emit(session_id, message)

            def on_new_session(session_id):
                # Safely emit the new session string
                self.new_session_signal.emit(session_id)

            self.engine.register_message_callback(on_message)
            self.engine.register_session_callback(on_new_session)

        # ==========================================================
        # SAFE UI UPDATE METHODS (Correctly Indented!)
        # ==========================================================

    # def _update_chat_area(self, session_id, message):
    #     if session_id == self.current_session:
    #         self.chat_area.append(f"Peer: {message}")
    #     else:           ## here
    #         print(f"Background message from {session_id}: {message}")
    def _update_chat_area(self, session_id, message):
        # 1. Catch the real-time kick from the server
        if session_id == "__SYSTEM__":
            QMessageBox.critical(self, "System Alert", message)
            
            # Lock the entire UI so the banned user can't do anything else
            self.setEnabled(False) 
            return
        
        if session_id == "__ERROR__":
            QMessageBox.warning(self, "Notice", message)
            return
        
        display_text = message
        
        # --- ALWAYS SAVE TO HISTORY ---
        if session_id not in self.chat_history:
            self.chat_history[session_id] = []
        self.chat_history[session_id].append(display_text)

        # Only display it instantly if we are looking at this chat
        if session_id == self.current_session:
            self.chat_area.append(display_text)
        else:
            # You have an unread message waiting in another room!
            print(f"Unread message waiting in {session_id}")

    def _update_online_list(self, users):
        self.online_list.clear()
        for user in users:
            self.online_list.addItem(user)
    # ==========================================================
    # EVENTS
    # ==========================================================

    def _on_session_selected(self, item):
        from PyQt6.QtCore import Qt
        
        # 1. Retrieve the HIDDEN raw ID to use for the engine operations
        self.current_session = item.data(Qt.ItemDataRole.UserRole)
        
        # 2. Use the VISIBLE text just for the UI header
        self.chat_header.setText(f"Chatting with: {item.text()}")
        
        self.chat_area.clear()
        
        # 3. Load chat history using the raw ID
        if self.current_session in self.chat_history:
            for msg in self.chat_history[self.current_session]:
                self.chat_area.append(msg)

    def _send_message(self):

        if not self.current_session:
            return

        text = self.message_input.text().strip()
        if not text:
            return

        try:
            self.engine.send_message(self.current_session, text)
            # --- UPDATE THIS TO SAVE HISTORY ---
            display_text = f"You: {text}"
            self.chat_area.append(display_text)
            
            if self.current_session not in self.chat_history:
                self.chat_history[self.current_session] = []
            self.chat_history[self.current_session].append(display_text)
            # -----------------------------------
            self.message_input.clear()
        except Exception as e:
            self.chat_area.append(f"[Error] {str(e)}")

    # ==========================================================
    # PUBLIC METHODS
    # ==========================================================
    def _get_friendly_name(self, session_id):
        """Converts 'direct_Alice_Bob' into just 'Bob' (if you are Alice)."""
        if session_id.startswith("direct_"):
            parts = session_id.split("_")
            # parts[1] and parts[2] are the two usernames
            if parts[1] == self.engine.username:
                return parts[2]
            else:
                return parts[1]
        
        # If it's a group, just return the group name
        return session_id


    def add_session(self, session_id):
            from PyQt6.QtWidgets import QListWidgetItem
            from PyQt6.QtCore import Qt
            
            # 1. Prevent duplicate entries by checking the hidden data
            for i in range(self.session_list.count()):
                existing_item = self.session_list.item(i)
                if existing_item.data(Qt.ItemDataRole.UserRole) == session_id:
                    return # Room is already in the list
                    
            # 2. Get the clean name to show the user
            friendly_name = self._get_friendly_name(session_id)
            
            # 3. Create the list item
            item = QListWidgetItem(friendly_name)
            
            # 4. Hide the raw ID (direct_Alice_Bob) inside the item
            item.setData(Qt.ItemDataRole.UserRole, session_id)
            
            self.session_list.addItem(item)
    def _create_direct(self):
        username, ok = QInputDialog.getText(
            self,
            "New Direct Chat",
            "Enter username:"
        )
        if ok and username:
            self.engine.create_direct(username)


    def _create_group(self):
        text, ok = QInputDialog.getText(
            self,
            "New Group",
            "Enter group name and members (comma separated):\nExample: room1, Bob, Charlie"
        )
        if ok and text:
            parts = [p.strip() for p in text.split(",")]
            if len(parts) >= 2:
                room = parts[0]
                members = parts[1:]
                self.engine.create_group(room, members)
    def _open_register(self):

        dialog = RegisterWindow(self.engine, os.path.dirname(os.path.dirname(__file__)))
        dialog.exec()
    def _end_session(self):

        if not self.current_session:
            return

        self.engine.end_session(self.current_session)

        # Remove from list
        items = self.session_list.findItems(self.current_session, Qt.MatchFlag.MatchExactly)
        for item in items:
            row = self.session_list.row(item)
            self.session_list.takeItem(row)

        self.chat_area.clear()
        self.chat_header.setText("No session selected")
        self.current_session = None

    def closeEvent(self, event):
        """Triggered automatically when the user clicks the 'X' to close the app."""
        if hasattr(self, 'engine') and self.engine:
            self.engine.shutdown() # Tell the background threads to die quietly
            
        event.accept() # Allow the window to clos
