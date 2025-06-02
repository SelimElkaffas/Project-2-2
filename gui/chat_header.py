
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt

class ChatHeader(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #f9fafb;
                border-bottom: 1px solid hsl(214.3, 31.8%, 91.4%);
            }
        """)
        self.setFixedHeight(64)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Contact info
        contact_layout = QHBoxLayout()
        contact_layout.setSpacing(12)

        # Avatar
        self.avatar = QLabel()
        self.avatar.setStyleSheet("""
            QLabel {
                background-color: hsl(222.2, 47.4%, 11.2%);
                color: hsl(210, 40%, 98%);
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
                border: none;
            }
        """)
        self.avatar.setFixedSize(40, 40)
        self.avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        contact_layout.addWidget(self.avatar)

        # Name and status
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        self.name_label = QLabel()
        self.name_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: 600;
                color: hsl(222.2, 84%, 4.9%);
                border: none;
            }
        """)
        info_layout.addWidget(self.name_label)

        self.status_label = QLabel()
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: hsl(215.4, 16.3%, 46.9%);
                border: none;
            }
        """)
        info_layout.addWidget(self.status_label)

        contact_layout.addLayout(info_layout)
        contact_layout.addStretch()

        layout.addLayout(contact_layout)

        # Action buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(8)

        # Phone button
        phone_btn = QPushButton("📞")
        phone_btn.setStyleSheet(self.get_button_style())
        phone_btn.setFixedSize(40, 40)
        buttons_layout.addWidget(phone_btn)

        # Video button
        video_btn = QPushButton("📹")
        video_btn.setStyleSheet(self.get_button_style())
        video_btn.setFixedSize(40, 40)
        buttons_layout.addWidget(video_btn)

        # Settings button
        settings_btn = QPushButton("⚙️")
        settings_btn.setStyleSheet(self.get_button_style())
        settings_btn.setFixedSize(40, 40)
        buttons_layout.addWidget(settings_btn)

        layout.addLayout(buttons_layout)

    def get_button_style(self):
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

    def set_contact(self, name, is_online, last_seen):
        self.name_label.setText(name)
        self.avatar.setText(name[0].upper())

        if is_online:
            self.status_label.setText("Online")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    color: #10b981;
                    border: none;
                }
            """)
        elif last_seen:
            self.status_label.setText(f"Last seen {last_seen}")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    color: hsl(215.4, 16.3%, 46.9%);
                    border: none;
                }
            """)
        else:
            self.status_label.setText("Offline")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    color: hsl(215.4, 16.3%, 46.9%);
                    border: none;
                }
            """)
