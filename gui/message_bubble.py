
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame
from PyQt6.QtCore import Qt

class MessageBubble(QWidget):
    def __init__(self, message):
        super().__init__()
        self.message = message
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if self.message['isSent']:
            layout.addStretch()
            bubble = self.create_sent_bubble()
            layout.addWidget(bubble)
        else:
            bubble = self.create_received_bubble()
            layout.addWidget(bubble)
            layout.addStretch()

    def create_sent_bubble(self):
        bubble = QFrame()
        bubble.setStyleSheet("""
            QFrame {
                background-color: hsl(222.2, 47.4%, 11.2%);
                border-radius: 16px;
                max-width: 400px;
            }
        """)

        layout = QVBoxLayout(bubble)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Message text
        text_label = QLabel(self.message['text'])
        text_label.setStyleSheet("""
            QLabel {
                color: hsl(210, 40%, 98%);
                font-size: 14px;
                background-color: transparent;
                border: none;
                padding: 0;
            }
        """)
        text_label.setWordWrap(True)
        layout.addWidget(text_label)

        # Footer with timestamp and status
        footer_layout = QHBoxLayout()
        footer_layout.setContentsMargins(0, 0, 0, 0)
        footer_layout.setSpacing(4)

        if self.message.get('isEncrypted'):
            encryption_label = QLabel("🔒")
            encryption_label.setStyleSheet("""
                QLabel {
                    color: rgba(255, 255, 255, 0.7);
                    font-size: 12px;
                    background-color: transparent;
                    border: none;
                    padding: 0;
                }
            """)
            footer_layout.addWidget(encryption_label)

        timestamp_label = QLabel(self.message['timestamp'])
        timestamp_label.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.7);
                font-size: 12px;
                background-color: transparent;
                border: none;
                padding: 0;
            }
        """)
        footer_layout.addWidget(timestamp_label)
        footer_layout.addStretch()

        # Status indicators
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(0)

        # First check mark
        check1 = QLabel("✓")
        if self.message['isDelivered']:
            check1.setStyleSheet("color: rgba(255, 255, 255, 0.5); font-size: 12px;")
        else:
            check1.setStyleSheet("color: rgba(255, 255, 255, 0.5); font-size: 12px;")
        status_layout.addWidget(check1)

        # Second check mark (for read status)
        if self.message['isRead']:
            check2 = QLabel("✓✓")
            check2.setStyleSheet("color: #60a5fa; font-size: 12px; font-weight: bold;")
            status_layout.addWidget(check2)

        footer_layout.addLayout(status_layout)
        layout.addLayout(footer_layout)

        return bubble

    def create_received_bubble(self):
        bubble = QFrame()
        bubble.setStyleSheet("""
            QFrame {
                background-color: hsl(210, 40%, 96.1%);
                border-radius: 16px;
                max-width: 400px;
            }
        """)

        layout = QVBoxLayout(bubble)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Message text
        text_label = QLabel(self.message['text'])
        text_label.setStyleSheet("""
            QLabel {
                color: hsl(222.2, 84%, 4.9%);
                font-size: 14px;
                background-color: transparent;
                border: none;
                padding: 0;
            }
        """)
        text_label.setWordWrap(True)
        layout.addWidget(text_label)

        # Footer with timestamp and encryption
        footer_layout = QHBoxLayout()
        footer_layout.setContentsMargins(0, 0, 0, 0)
        footer_layout.setSpacing(4)
        footer_layout.addStretch()

        if self.message.get('isEncrypted'):
            encryption_label = QLabel("🔒")
            encryption_label.setStyleSheet("""
                QLabel {
                    color: hsl(215.4, 16.3%, 46.9%);
                    font-size: 12px;
                    background-color: transparent;
                    border: none;
                    padding: 0;
                }
            """)
            footer_layout.addWidget(encryption_label)

        timestamp_label = QLabel(self.message['timestamp'])
        timestamp_label.setStyleSheet("""
            QLabel {
                color: hsl(215.4, 16.3%, 46.9%);
                font-size: 12px;
                background-color: transparent;
                border: none;
                padding: 0;
            }
        """)
        footer_layout.addWidget(timestamp_label)

        layout.addLayout(footer_layout)

        return bubble
