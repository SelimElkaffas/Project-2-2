from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QFrame
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

class UsernameDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cipher Chat - Login")
        self.setFixedSize(400, 300)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowCloseButtonHint)

        # Modern styling
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                border-radius: 12px;
            }
        """)

        # Main layout with proper spacing
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)

        # Title
        title_label = QLabel("Welcome to Cipher Chat")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: 600;
                color: hsl(222.2, 84%, 4.9%);
                margin-bottom: 8px;
            }
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        # Subtitle
        subtitle_label = QLabel("Enter your username to start chatting")
        subtitle_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: hsl(215.4, 16.3%, 46.9%);
                margin-bottom: 16px;
            }
        """)
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle_label)

        # Wrapper layout to bind label + input tightly
        input_wrapper = QVBoxLayout()
        input_wrapper.setSpacing(2)  # Tight spacing between label and input
        input_wrapper.setContentsMargins(0, 0, 0, 0)

        # Username label
        self.label = QLabel("Username")
        self.label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: 500;
                color: hsl(222.2, 84%, 4.9%);
            }
        """)
        input_wrapper.addWidget(self.label)

        # Username input with simplified styling that works properly
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username...")
        self.username_input.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 5px;
                padding: 6px 10px;
                font-size: 12px;
                color: #1e293b;
                min-height: 28px;
            }
            QLineEdit:focus {
                border: 1px solid #334155;
                outline: none;
            }
            QLineEdit::placeholder {
                color: #94a3b8;
            }
        """)
        input_wrapper.addWidget(self.username_input)
        layout.addLayout(input_wrapper)

        # Add some space
        layout.addSpacing(20)

        # Login button with modern styling
        self.login_button = QPushButton("Start Chatting")
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #f8fafc;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                min-height: 32px;
                margin-bottom: 10px;
            }
            QPushButton:hover {
                background-color: #0f172a;
            }
            QPushButton:pressed {
                background-color: #020617;
            }
            QPushButton:disabled {
                background-color: #e2e8f0;
                color: #64748b;
            }
        """)
        self.login_button.clicked.connect(self.accept)
        layout.addWidget(self.login_button)
        layout.addSpacing(10)

        # Connect Enter key to login
        self.username_input.returnPressed.connect(self.accept)

        # Focus on input field
        self.username_input.setFocus()

    def get_username(self):
        return self.username_input.text().strip()
