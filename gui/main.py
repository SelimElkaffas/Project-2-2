
import sys
import uuid
from datetime import datetime

from PyQt6.QtWidgets import QApplication, QMainWindow, QHBoxLayout, QWidget, QDialog
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from gui.chat_sidebar import ChatSidebar
from gui.chat_area import ChatArea
from network.client import ChatClient

class MainWindow(QMainWindow):
    user_found_signal = pyqtSignal(dict)
    gui_message_received = pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.pending_search_username = None
        self.username = None

        self.chat_client = ChatClient()

        # Signal for safely passing messages to the GUI thread
        self.gui_message_received.connect(self.handle_received_message)
        self.chat_client.on_message_received = lambda msg: self.gui_message_received.emit(msg)

        # Signal for when a searched user is found
        self.user_found_signal.connect(self.on_user_found)
        self.chat_client.on_user_found = lambda chat: self.user_found_signal.emit(chat)

        self.init_ui()

        # Sample chats
        self.sample_chats = []

        # Components
        self.sidebar = ChatSidebar(self.sample_chats)
        self.sidebar.user_searched.connect(self.on_user_searched)
        self.sidebar.chat_selected.connect(self.on_chat_selected)

        self.chat_area = ChatArea()

        # Main layout
        central_widget = QWidget()
        layout = QHBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.chat_area)
        self.setCentralWidget(central_widget)

        # Connect chat sending
        self.chat_area.message_sent.connect(self.on_message_sent)

        # Initial state
        self.current_chat_id = None

    def init_ui(self):
        self.setWindowTitle("Encrypted Chat App")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(800, 600)
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f9fafb;;
                color: #0f172a;
            }
        """)
        # Initialize your UI components here (e.g., ChatArea, ChatSidebar)

    def handle_received_message(self, full_message):
        from PyQt6.QtCore import QTimer

        def _handle():
            print(" ------------------------- Raw incoming message:", full_message)

            try:
                message_id, payload = full_message.split("|", 1)
            except ValueError:
                print("Invalid message format")
                return

            # Format: hadi: Hello!
            if ":" in payload:
                sender_username, actual_text = payload.split(":", 1)
                sender_username = sender_username.strip().lower()
                actual_text = actual_text.strip()
            else:
                print("Invalid payload (missing sender):", payload)
                return

            is_own = (message_id == self.chat_client.last_message_id)

            # ✅ Check if this chat already exists by sender username
            chat = next((c for c in self.sample_chats if c['id'] == sender_username), None)

            print()
            print(" ##### Chat is: ", chat)
            print()

            if not chat:
                # 👤 Create new chat if not found
                chat = {
                    'id': sender_username,
                    'name': sender_username.capitalize(),
                    'lastMessage': actual_text,
                    'timestamp': self.get_current_timestamp(),
                    'unread': 1,
                    'isOnline': True,
                    'lastSeen': None,
                    'messages': []
                }
                self.sample_chats.insert(0, chat)
                self.sidebar.update_chat_list(self.sample_chats)

            # 📩 Add message to chat
            chat['messages'].append({
                'id': message_id,
                'text': actual_text,
                'timestamp': self.get_current_timestamp(),
                'isSent': is_own,
                'isDelivered': not is_own,
                'isRead': not is_own,
                'isEncrypted': True
            })

            chat['lastMessage'] = actual_text
            chat['timestamp'] = self.get_current_timestamp()

            # ✅ Force refresh chat UI if this is the active chat
            if self.current_chat_id == sender_username:
                self.chat_area.set_chat(chat)
            elif self.current_chat_id is None:
                # Auto-open if no chat is open
                self.current_chat_id = sender_username
                self.chat_area.set_chat(chat)

        print("⏳ Passing message to handler: ", repr(full_message))
        _handle()


    def on_user_found(self, chat):
        chat_id = chat['name'].lower()
        chat['id'] = chat_id

        existing = next((c for c in self.sample_chats if c['id'] == chat_id), None)
        if not existing:
            self.sample_chats.insert(0, chat)
            self.sidebar.update_chat_list(self.sample_chats)

        self.sidebar.select_chat(chat_id)


    def get_username(self):
        # Create and open the dialog
        from gui.login_dialog import UsernameDialog

        dialog = UsernameDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.username = dialog.get_username()
            print(f"Username: {self.username}")
            # Connect to server
            if not self.chat_client.connect(self.username):
                print("Connection failed.")
                return False
            self.setWindowTitle(f"Encrypted Chat App - {self.username} (connected)")
            return True
        else:
            return False

    def on_chat_selected(self, chat_id):
        self.current_chat_id = chat_id
        selected_chat = next((chat for chat in self.sample_chats if chat['id'] == chat_id), None)
        if selected_chat:
            self.chat_area.set_chat(selected_chat)

    def on_user_searched(self, username):
        print("→ searching for:", username)
        self.chat_client.pending_search_username = username
        self.chat_client.send_message("__get_users__")  # Send raw command to request users

    def on_message_sent(self, message_text):
        if not self.current_chat_id:
            return

        for chat in self.sample_chats:
            if chat['id'] == self.current_chat_id:
                recipient_username = chat['name'].lower()

                new_message = {
                    'id': str(uuid.uuid4()),
                    'text': message_text,
                    'timestamp': self.get_current_timestamp(),
                    'isSent': True,
                    'isDelivered': True,
                    'isRead': False,
                    'isEncrypted': True,
                }
                chat['messages'].append(new_message)
                chat['lastMessage'] = f'🔒 {message_text}'
                chat['timestamp'] = new_message['timestamp']

                print("🕒 Timestamp test:", self.get_current_timestamp())

                self.chat_client.send_message(f"{recipient_username}|{self.username}: {message_text}")

                self.chat_area.set_chat(chat)
                self.sidebar.update_chat_list(self.sample_chats)
                break

    def get_current_timestamp(self):
        return datetime.now().strftime('%I:%M %p').lstrip('0')  # 2:35 PM (24-hour users: use %H:%M)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Set application font
    font = QFont("Inter", 10)
    app.setFont(font)

    window = MainWindow()
    if window.get_username():
        window.show()

    else:
        print("Username not provided")
        sys.exit(0)

    sys.exit(app.exec())
