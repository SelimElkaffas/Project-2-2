
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QScrollArea, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

class ChatSidebar(QWidget):
    chat_selected = pyqtSignal(str)
    user_searched = pyqtSignal(str)

    def __init__(self, chats):
        super().__init__()
        self.chat_list = None
        self.chats = chats
        self.selected_chat_id = None
        self.search_input = None
        self.init_ui()

    def init_ui(self):
        self.setFixedWidth(320)
        self.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
                border-right: 1px solid #e2e8f0;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = self.create_header()
        layout.addWidget(header)

        # Search
        search = self.create_search()
        layout.addWidget(search)

        # Chat list
        self.chat_list = self.create_chat_list()
        layout.addWidget(self.chat_list)

    def create_header(self):
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                /* border-bottom: 1px solid #e2e8f0; */
            }
        """)
        header.setFixedHeight(64)

        layout = QHBoxLayout(header)
        layout.setContentsMargins(12, 12, 12, 12)

        # Title with icon
        title_layout = QHBoxLayout()
        title_layout.setSpacing(8)

        # Chat icon
        icon_label = QLabel("💬")
        icon_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                color: hsl(222.2, 47.4%, 11.2%);
                border: none;
            }
        """)
        title_layout.addWidget(icon_label)

        # Title text
        title = QLabel("Cipher Chat")
        title.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: 600;
                color: hsl(222.2, 84%, 4.9%);
                border: none;
            }
        """)
        title_layout.addWidget(title)
        title_layout.addStretch()

        layout.addLayout(title_layout)

        # Settings button
        settings_btn = QPushButton()
        settings_btn.setText("⚙️")
        settings_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                font-size: 20px;
                padding: 8px;
                border-radius: 16px;
                width: 40px;
                height: 40px;
            }
            QPushButton:hover {
                background-color: hsl(210, 40%, 96.1%);
            }
        """)
        layout.addWidget(settings_btn)

        return header

    def create_search(self):
        search_container = QFrame()
        search_container.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border-bottom: 1px solid #e2e8f0;
            }
        """)
        search_container.setFixedHeight(64)

        layout = QHBoxLayout(search_container)
        layout.setContentsMargins(16, 12, 16, 12)

        # Search input with icon
        search_frame = QFrame()
        search_frame.setStyleSheet("""
            QFrame {
                background-color: hsl(210, 40%, 96.1%);
                border: 1px solid hsl(214.3, 31.8%, 91.4%);
                border-radius: 6px;
            }
        """)

        search_layout = QHBoxLayout(search_frame)
        search_layout.setContentsMargins(12, 8, 12, 8)
        search_layout.setSpacing(8)

        # Search icon
        search_icon = QLabel("🔍")
        search_icon.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: hsl(215.4, 16.3%, 46.9%);
                border: none;
            }
        """)
        search_layout.addWidget(search_icon)

        # Search input
        self.search_input = QLineEdit()
        self.search_input.returnPressed.connect(self.emit_search)
        self.search_input.setPlaceholderText("Search chats...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: transparent;
                border: none;
                font-size: 14px;
                color: hsl(222.2, 84%, 4.9%);
                padding: 0;
            }
            QLineEdit::placeholder {
                color: hsl(215.4, 16.3%, 46.9%);
            }
        """)
        self.search_input.setFixedHeight(24)
        search_layout.addWidget(self.search_input)

        layout.addWidget(search_frame)

        return search_container

    def emit_search(self):
        username = self.search_input.text().strip()
        if username:
            self.user_searched.emit(username)

    def create_chat_list(self):
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #ffffff;
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

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.chat_items = []
        for chat in self.chats:
            chat_item = self.create_chat_item(chat)
            content_layout.addWidget(chat_item)
            self.chat_items.append(chat_item)

        content_layout.addStretch()
        scroll_area.setWidget(content_widget)

        return scroll_area

    def create_chat_item(self, chat):
        chat_item = QPushButton()
        chat_item.setStyleSheet("""
            QPushButton {
                background-color: #ffffff;
                border-bottom: 1px solid hsl(214.3, 31.8%, 91.4%);
                padding: 16px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: hsl(210, 40%, 96.1%);
            }
        """)
        chat_item.setFixedHeight(80)
        chat_item.clicked.connect(lambda: self.select_chat(chat['id']))

        # Create layout for chat item content
        layout = QHBoxLayout(chat_item)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # Avatar
        avatar_container = QFrame()
        avatar_container.setFixedSize(48, 48)
        avatar_container.setStyleSheet("""
            QFrame {
                background-color: hsl(222.2, 47.4%, 11.2%);
                border-radius: 24px;
                border: none;
            }
        """)

        avatar_layout = QVBoxLayout(avatar_container)
        avatar_layout.setContentsMargins(0, 0, 0, 0)

        avatar = QLabel()
        avatar.setText(chat['name'][0].upper())
        avatar.setStyleSheet("""
            QLabel {
                background-color: transparent;
                color: hsl(210, 40%, 98%);
                font-size: 18px;
                font-weight: 600;
            }
        """)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar_layout.addWidget(avatar)

        layout.addWidget(avatar_container)

        # Chat info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        # Name and timestamp
        name_time_layout = QHBoxLayout()
        name_time_layout.setSpacing(0)

        name = QLabel(chat['name'])
        name.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: 500;
                color: hsl(222.2, 84%, 4.9%);
                border: none;
            }
        """)
        name_time_layout.addWidget(name)
        name_time_layout.addStretch()

        timestamp = QLabel(chat['timestamp'])
        timestamp.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: hsl(215.4, 16.3%, 46.9%);
                border: none;
            }
        """)
        name_time_layout.addWidget(timestamp)

        info_layout.addLayout(name_time_layout)

        # Last message and unread count
        message_layout = QHBoxLayout()
        message_layout.setSpacing(8)

        last_message = QLabel(chat['lastMessage'])
        last_message.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: hsl(215.4, 16.3%, 46.9%);
                border: none;
            }
        """)
        last_message.setWordWrap(True)
        message_layout.addWidget(last_message)
        message_layout.addStretch()

        if chat['unread'] > 0:
            unread_badge = QLabel(str(chat['unread']))
            unread_badge.setStyleSheet("""
                QLabel {
                    background-color: hsl(222.2, 47.4%, 11.2%);
                    color: hsl(210, 40%, 98%);
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                    padding: 2px 6px;
                    min-width: 16px;
                    border: none;
                }
            """)
            unread_badge.setFixedSize(20, 20)
            unread_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            message_layout.addWidget(unread_badge)

        info_layout.addLayout(message_layout)
        layout.addLayout(info_layout)

        # Online indicator
        if chat['isOnline']:
            online_indicator = QLabel()
            online_indicator.setStyleSheet("""
                QLabel {
                    background-color: #10b981;
                    border: 2px solid #ffffff;
                    border-radius: 8px;
                }
            """)
            online_indicator.setFixedSize(16, 16)
            online_indicator.setParent(avatar_container)
            online_indicator.move(32, 32)

        return chat_item

    def select_chat(self, chat_id):
        self.selected_chat_id = chat_id
        self.update_selection()
        self.chat_selected.emit(chat_id)

    def update_selection(self):
        for i, chat_item in enumerate(self.chat_items):
            if self.chats[i]['id'] == self.selected_chat_id:
                chat_item.setStyleSheet("""
                    QPushButton {
                        background-color: hsl(210, 40%, 96.1%);
                        border: none;
                        border-bottom: 1px solid hsl(214.3, 31.8%, 91.4%);
                        padding: 16px;
                        text-align: left;
                    }
                    QPushButton:hover {
                        background-color: hsl(210, 40%, 96.1%);
                    }
                """)
            else:
                chat_item.setStyleSheet("""
                    QPushButton {
                        background-color: #ffffff;
                        border: none;
                        border-bottom: 1px solid hsl(214.3, 31.8%, 91.4%);
                        padding: 16px;
                        text-align: left;
                    }
                    QPushButton:hover {
                        background-color: hsl(210, 40%, 96.1%);
                    }
                """)

    def update_chat_list(self, chats):
        print("Updating chat list...")
        print(chats)
        print('-' * 50)

        self.chats = chats

        # Rebuild the chat list UI
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.chat_items = []
        for chat in self.chats:
            chat_item = self.create_chat_item(chat)
            content_layout.addWidget(chat_item)
            self.chat_items.append(chat_item)

        content_layout.addStretch()
        self.chat_list.setWidget(content_widget)
