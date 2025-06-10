# network_client.py
import socket
import threading
import uuid
from datetime import datetime

from key_exchange.key_exchange_protocol import KeyExchangeProtocol
from cipher.custom_cipher import CustomCipher
from utils.block_conversion import text_to_blocks, blocks_to_text
from utils.hmac_utils import compute_hmac, verify_hmac

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.pending_search_username = None
        self.host = host
        self.port = port
        self.socket = None
        self.key_exchange = KeyExchangeProtocol()
        self.cipher = None
        self.username = None
        self.last_message_id = None
        self.on_message_received = None

    def connect(self, username):
        try:
            self.username = username
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

            # Key exchange: send & receive public keys
            server_public_key = self.socket.recv(4096)
            client_public_key = self.key_exchange.get_public_key()
            self.socket.send(client_public_key)

            # Derive session key & init cipher
            session_key = self.key_exchange.derive_session_key(server_public_key)
            self.session_key = session_key
            self.cipher = CustomCipher(key=session_key[:16], num_rounds=8)

            # Encrypt username and send
            username_padded = username.ljust(16, ' ')
            username_blocks = text_to_blocks(username_padded)
            encrypted_username = self.cipher.encrypt_block(username_blocks[0])
            self.socket.send(encrypted_username.to_bytes(16, 'big'))

            # Start receiving thread
            thread = threading.Thread(target=self.receive_messages, daemon=True)
            thread.start()

            print(f"[CLIENT]: Connected to {self.host}:{self.port} as {username}")
            return True

        except Exception as e:
            print(f"[Connect Error] {e}")
            return False
    
    def receive_messages(self):
        while True:
            try:
                data = self.socket.recv(1024)
                if not data:
                    print("[CLIENT]: No data received, disconnecting.")
                    break

                # Handle rekey challenge
                if data.startswith(b"REKEY_CHALLENGE"):
                    tag_len = 32 # SHA256 output size
                    challenge = data[:15]
                    tag = data[15:15 + tag_len]
                    key = self.session_key
                    print(f"[REKEY]: Received rekey challenge: {challenge}, tag: {tag.hex()}")

                    if verify_hmac(key, challenge, tag):
                        print("[REKEY]: HMAC verified successfully, triggering rekey...")
                        self.handle_rekey_process()
                    else:
                        print("[ERROR]: HMAC verification failed, cannot rekey.")
                    continue

                # Handle rekey server public key
                if data.startswith(b"REKEY_SERVER_KEY"):
                    server_public_key = data[len("REKEY_SERVER_KEY"):]
                    self.complete_rekey(server_public_key)
                    continue


                # Process and decrypt received blocks properly as 16 bytes
                blocks = [int.from_bytes(data[i:i + 16], 'big') for i in range(0, len(data), 16)]
                decrypted = [self.cipher.decrypt_block(b) for b in blocks]
                full_message = blocks_to_text(decrypted)

                print(f"[DEBUG]: Decrypted received: {full_message}")

                # Handle control message for user list
                if full_message.startswith("__users__|"):
                    users = full_message[len("__users__|"):].split(",")
                    print("→ Online users:", users)

                    # Check if user search was pending
                    if self.pending_search_username:
                        search_username = self.pending_search_username
                        if search_username in users:
                            print(f"✔️ User '{search_username}' is online.")

                            # Build chat data and trigger UI update if connected
                            chat = {
                                "id": search_username,
                                "name": search_username.capitalize(),
                                "lastMessage": "Start chatting securely...",
                                "timestamp": self.get_current_timestamp(),
                                "unread": 0,
                                "isOnline": True,
                                "messages": []
                            }

                            if hasattr(self, "on_user_found"):
                                self.on_user_found(chat)
                        else:
                            print(f"❌ User '{search_username}' is not online.")
                        self.pending_search_username = None
                    continue

                print("Received from server:", full_message)

                if self.on_message_received:
                    # print("✅ Calling on_message_received...")
                    # print(f"🟢 Decrypted received: {full_message}")
                    self.on_message_received(full_message)
            except Exception as e:
                print(f"[Receive Error] {e}")
                break

    def get_current_timestamp(self):
        return datetime.now().strftime('%I:%M %p').lstrip('0')  # 2:35 PM (24-hour users: use %H:%M)

    def send_message(self, message):
        try:
            if message.strip() == "__get_users__":
                full_message = message  # NO message_id for control messages
            else:
                message_id = str(uuid.uuid4())
                self.last_message_id = message_id
                full_message = f"{message_id}|{message}"

            print(f"* Sending: {full_message}")  # Debug output

            # Properly pad messages and handle 16-byte blocks
            full_message_padded = full_message.ljust((len(full_message) + 15) // 16 * 16, ' ')  # Pad to multiple of 16 bytes
            blocks = text_to_blocks(full_message_padded)
            encrypted = [self.cipher.encrypt_block(b) for b in blocks]
            data = b''.join(b.to_bytes(16, 'big') for b in encrypted)
            self.socket.send(data)
        except Exception as e:
            print(f"[Send Error] {e}")

    def request_online_users(self):
        print("→ requesting users...")
        try:
            blocks = text_to_blocks("__get_users__".ljust(16, ' '))  # Pad to 16 bytes
            encrypted_blocks = [self.cipher.encrypt_block(b) for b in blocks]
            data = b''.join(block.to_bytes(16, 'big') for block in encrypted_blocks)
            self.socket.send(data)
        except Exception as e:
            print("Failed to request online users:", e)

    def send_raw(self, raw_text):
        print("-> Sending raw text: ", raw_text, "\n")
        try:
            if raw_text == "__get_users__":
                blocks = text_to_blocks(raw_text.ljust(16, ' '))  # Pad if needed
            else:
                message_id = str(uuid.uuid4())
                self.last_message_id = message_id
                padded_message = f"{message_id}|{raw_text}".ljust(16, ' ')  # Pad to 16 bytes
                blocks = text_to_blocks(padded_message)

            encrypted = [self.cipher.encrypt_block(b) for b in blocks]
            message_bytes = b''.join(b.to_bytes(16, 'big') for b in encrypted)
            self.socket.send(message_bytes)
        except Exception as e:
            print(f"[Send Raw Error] {e}")

    def handle_rekey_process(self):
        """Handle the client side of the rekey process"""
        try:      
            # Create new key exchange protocol
            self.key_exchange = KeyExchangeProtocol()
            client_public_key = self.key_exchange.get_public_key()
            
            # Send rekey response with new public key
            self.socket.send(b"REKEY_RESPONSE" + client_public_key)
            # print("📤 Sent rekey response with new public key")
            
        except Exception as e:
            print(f"[Rekey Process Error] {e}")

    def complete_rekey(self, server_public_key):
        """Complete the rekey process with server's new public key"""
        try:
            print("[REKEY]: Completing rekey with server's new public key...")
            
            # Derive new session key
            session_key = self.key_exchange.derive_session_key(server_public_key)
            self.session_key = session_key
            # print("🔐 New session key (hex):", session_key.hex())
            
            # Update cipher with new session key
            self.cipher = CustomCipher(key=session_key[:16], num_rounds=8)
            # print("🔐 New cipher key used:", session_key.hex()[:16])
            
            # Re-send encrypted username with new cipher
            username_blocks = text_to_blocks(self.username)
            encrypted_username = self.cipher.encrypt_block(username_blocks[0])
            self.socket.send(encrypted_username.to_bytes(16, 'big'))
            
            print("[REKEY]: Rekey completed successfully on client side")
            
        except Exception as e:
            print(f"[Complete Rekey Error] {e}")       
