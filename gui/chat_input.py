
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QTextEdit,
                             QPushButton, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal

class ChatInput(QWidget):
    message_sent = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
                border-top: 1px solid hsl(214.3, 31.8%, 91.4%);
            }
        """)
        self.setFixedHeight(80)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # File button
        file_btn = QPushButton("📎")
        file_btn.setStyleSheet(self.get_icon_button_style())
        file_btn.setFixedSize(44, 44)
        layout.addWidget(file_btn)

        # Input container
        input_container = QFrame()
        input_container.setStyleSheet("""
            QFrame {
                background-color: hsl(210, 40%, 96.1%);
                border: 1px solid hsl(214.3, 31.8%, 91.4%);
                border-radius: 24px;
            }
        """)

        input_layout = QHBoxLayout(input_container)
        input_layout.setContentsMargins(16, 8, 16, 8)
        input_layout.setSpacing(8)

        # Text input
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Type a message...")
        self.text_input.setStyleSheet("""
            QTextEdit {
                background-color: transparent;
                border: none;
                font-size: 14px;
                color: hsl(222.2, 84%, 4.9%);
                padding: 0;
            }
            QTextEdit:focus {
                outline: none;
            }
        """)
        self.text_input.setFixedHeight(28)
        self.text_input.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.text_input.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        input_layout.addWidget(self.text_input)

        # Emoji button
        emoji_btn = QPushButton("😊")
        emoji_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                font-size: 16px;
                padding: 4px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: hsl(214.3, 31.8%, 91.4%);
            }
        """)
        emoji_btn.setFixedSize(32, 32)
        input_layout.addWidget(emoji_btn)

        layout.addWidget(input_container)

        # Send button
        self.send_btn = QPushButton("🚀")
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: hsl(222.2, 47.4%, 11.2%);
                color: hsl(210, 40%, 98%);
                border: none;
                font-size: 16px;
                padding: 8px;
                border-radius: 22px;
            }
            QPushButton:hover {
                background-color: hsl(222.2, 47.4%, 8%);
            }
            QPushButton:pressed {
                background-color: hsl(222.2, 47.4%, 6%);
            }
            QPushButton:disabled {
                background-color: hsl(214.3, 31.8%, 91.4%);
                color: hsl(215.4, 16.3%, 46.9%);
            }
        """)
        self.send_btn.setFixedSize(44, 44)
        self.send_btn.clicked.connect(self.send_message)
        layout.addWidget(self.send_btn)

        # Connect text change to update send button
        self.text_input.textChanged.connect(self.on_text_changed)
        self.text_input.installEventFilter(self)

        self.update_send_button()

    def get_icon_button_style(self):
        return """
            QPushButton {
                background-color: transparent;
                border: none;
                font-size: 20px;
                padding: 8px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: hsl(210, 40%, 96.1%);
            }
            QPushButton:pressed {
                background-color: hsl(214.3, 31.8%, 91.4%);
            }
        """

    def eventFilter(self, obj, event):
        if obj == self.text_input and event.type() == event.Type.KeyPress:
            if event.key() == Qt.Key.Key_Return and not event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                self.send_message()
                return True
        return super().eventFilter(obj, event)

    def on_text_changed(self):
        self.update_send_button()

    def update_send_button(self):
        has_text = bool(self.text_input.toPlainText().strip())
        self.send_btn.setEnabled(has_text)

    def send_message(self):
        text = self.text_input.toPlainText().strip()
        if text:
            self.message_sent.emit(text)
            self.text_input.clear()
