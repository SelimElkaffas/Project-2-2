
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QScrollArea, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal
from chat_header import ChatHeader
from message_bubble import MessageBubble
from chat_input import ChatInput

class ChatArea(QWidget):
    message_sent = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.current_chat = None
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #f9fafb;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Create welcome screen
        self.welcome_widget = self.create_welcome_screen()
        layout.addWidget(self.welcome_widget)

        # Create chat widget (initially hidden)
        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_widget)
        self.chat_layout.setContentsMargins(0, 0, 0, 0)
        self.chat_layout.setSpacing(0)

        # Header
        self.header = ChatHeader()
        self.chat_layout.addWidget(self.header)

        # Line separator
        separator = QFrame()
        separator.setFixedHeight(1)
        separator.setStyleSheet("background-color: #e2e8f0;")
        self.chat_layout.addWidget(separator)

        # Messages area
        self.messages_area = self.create_messages_area()
        self.chat_layout.addWidget(self.messages_area)

        # Input area
        self.input_area = ChatInput()
        self.input_area.message_sent.connect(self.on_message_sent)
        self.chat_layout.addWidget(self.input_area)

        layout.addWidget(self.chat_widget)
        self.chat_widget.hide()

    def create_welcome_screen(self):
        welcome = QWidget()
        welcome.setStyleSheet("""
            QWidget {
                background-color: hsl(210, 40%, 96.1%);
            }
        """)

        layout = QVBoxLayout(welcome)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        # Icon container
        icon_container = QFrame()
        icon_container.setStyleSheet("""
            QFrame {
                background-color: hsl(222.2, 47.4%, 11.2%);
                border-radius: 40px;
            }
        """)
        icon_container.setFixedSize(80, 80)

        icon_layout = QVBoxLayout(icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)

        # Icon
        icon = QLabel("💬")
        icon.setStyleSheet("""
            QLabel {
                font-size: 40px;
                background-color: transparent;
            }
        """)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_layout.addWidget(icon)

        layout.addWidget(icon_container, 0, Qt.AlignmentFlag.AlignCenter)

        # Title
        title = QLabel("Welcome to Cipher Chat")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: 600;
                color: hsl(222.2, 84%, 4.9%);
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Select a chat to start messaging with end-to-end encryption")
        subtitle.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: hsl(215.4, 16.3%, 46.9%);
            }
        """)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        return welcome

    def create_messages_area(self):
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #f9fafb;
            }
            QScrollBar:vertical {
                background-color: hsl(210, 40%, 96.1%);
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background-color: hsl(214.3, 31.8%, 91.4%);
                border-radius: 4px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: hsl(215.4, 16.3%, 46.9%);
            }
        """)

        self.messages_widget = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_widget)
        self.messages_layout.setContentsMargins(16, 16, 16, 16)
        self.messages_layout.setSpacing(16)
        self.messages_layout.addStretch()

        scroll_area.setWidget(self.messages_widget)

        return scroll_area

    def set_chat(self, chat):
        self.current_chat = chat

        # Show chat widget, hide welcome
        self.welcome_widget.hide()
        self.chat_widget.show()

        # Update header
        self.header.set_contact(chat['name'], chat['isOnline'], chat.get('lastSeen'))

        # Clear existing messages
        for i in reversed(range(self.messages_layout.count() - 1)):  # -1 to keep the stretch
            self.messages_layout.itemAt(i).widget().setParent(None)

        # Add new messages
        for message in chat['messages']:
            message_bubble = MessageBubble(message)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, message_bubble)

        # Scroll to bottom
        self.messages_area.verticalScrollBar().setValue(
            self.messages_area.verticalScrollBar().maximum()
        )

    def on_message_sent(self, message_text):
        self.message_sent.emit(message_text)
