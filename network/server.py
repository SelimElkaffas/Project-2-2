import socket
import threading
from key_exchange.key_exchange_protocol import KeyExchangeProtocol
from cipher.custom_cipher import CustomCipher
from utils.block_conversion import text_to_blocks, blocks_to_text
from session.session_key_manager import SessionKeyManager

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # client_socket -> username
        self.key_exchange = KeyExchangeProtocol()
        self.session_manager = SessionKeyManager()
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"Connection from {address} established")
                
                # Start a new thread for each client
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
            except KeyboardInterrupt:
                print("\nShutting down server...")
                break
            except Exception as e:
                print(f"Error accepting connection: {e}")
        
        self.server_socket.close()

    def get_online_usernames(self):
        return list(self.clients.values())

    def handle_client(self, client_socket, address):
        print("handling client ...")
        try:
            server_public_key = self.key_exchange.get_public_key()
            client_socket.send(server_public_key)

            client_public_key = client_socket.recv(4096)
            session_key = self.key_exchange.derive_session_key(client_public_key)

            print(f"🔑 [SERVER] Session key for {address}:", session_key.hex())

            cipher = CustomCipher(key=session_key[:16], num_rounds=8)

            encrypted_username_bytes = client_socket.recv(16)
            encrypted_username = int.from_bytes(encrypted_username_bytes, 'big')
            decrypted_username_blocks = [cipher.decrypt_block(encrypted_username)]
            username = blocks_to_text(decrypted_username_blocks)

            self.session_manager.add_key(username, session_key)
            self.clients[client_socket] = username
            self.broadcast(f"{username} joined the chat!")

            while True:
                try:
                    encrypted_message_bytes = client_socket.recv(1024)
                    if not encrypted_message_bytes:
                        break

                    encrypted_blocks = [
                        int.from_bytes(encrypted_message_bytes[i:i+16], 'big')
                        for i in range(0, len(encrypted_message_bytes), 16)
                    ]
                    decrypted_blocks = [cipher.decrypt_block(block) for block in encrypted_blocks]
                    full_message = blocks_to_text(decrypted_blocks).strip()

                    print(f"[Decrypted] {full_message}")

                    if full_message == "__get_users__":
                        online_users = ",".join(self.get_online_usernames())
                        self.send_direct(f"__users__|{online_users}", client_socket, cipher)
                        continue

                    if "|" in full_message:
                        message_id, message = full_message.split("|", 1)

                        if message.strip() == "__get_users__":
                            online_users = ",".join(self.get_online_usernames())
                            self.send_direct(f"__users__|{online_users}", client_socket, cipher)
                            continue

                        if "|" in message:
                            recipient, real_msg = message.split("|", 1)
                            self.send_to_user(recipient.strip(), f"{message_id}|{real_msg}")
                        else:
                            self.broadcast(f"{message_id}|{username}: {message}")
                    else:
                        self.broadcast(f"{username}: {full_message}")

                except Exception as e:
                    print(f"Error handling message from {username}: {e}")
                    break

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            if client_socket in self.clients:
                username = self.clients[client_socket]
                del self.clients[client_socket]
                self.session_manager.remove_key(username)
                self.broadcast(f"{username} left the chat!")
            client_socket.close()


    def broadcast(self, message, message_id=None):
        """Broadcast a message to all connected clients."""
        print(f"Broadcasting: {message}")
        
        # If the message is a system message (join/leave), don't add message ID
        if message.endswith(" joined the chat!") or message.endswith(" left the chat!"):
            message_blocks = text_to_blocks(message)
        else:
            # For chat messages, include the message ID if provided
            if message_id:
                message_blocks = text_to_blocks(f"{message_id}|{message}")
            else:
                message_blocks = text_to_blocks(message)
        
        for client_socket in list(self.clients.keys()):
            try:
                username = self.clients[client_socket]
                session_key = self.session_manager.get_key(username)
                cipher = CustomCipher(key=session_key[:16], num_rounds=8)
                
                encrypted_blocks = [cipher.encrypt_block(block) for block in message_blocks]
                message_bytes = b''
                for block in encrypted_blocks:
                    message_bytes += block.to_bytes(16, 'big')
                
                client_socket.send(message_bytes)
            except Exception as e:
                print(f"Error broadcasting to {username}: {e}")
                # Remove the client if there's an error
                if client_socket in self.clients:
                    del self.clients[client_socket]
                    client_socket.close()

    def send_to_user(self, target_username, message):
        for client_socket, username in self.clients.items():
            if username == target_username:
                print(f"Sending to {target_username}: {message}")  # ✅ Debug
                session_key = self.session_manager.get_key(username)
                cipher = CustomCipher(key=session_key[:16], num_rounds=8)
                blocks = text_to_blocks(message)
                encrypted = [cipher.encrypt_block(b) for b in blocks]
                message_bytes = b''.join(b.to_bytes(16, 'big') for b in encrypted)
                client_socket.send(message_bytes)
                break


    def send_direct(self, message, client_socket, cipher):
        try:
            message_blocks = text_to_blocks(message)
            encrypted_blocks = [cipher.encrypt_block(b) for b in message_blocks]
            message_bytes = b''.join(b.to_bytes(16, 'big') for b in encrypted_blocks)
            client_socket.send(message_bytes)
        except Exception as e:
            print(f"Error sending direct message: {e}")
            client_socket.close()
            if client_socket in self.clients:
                del self.clients[client_socket]


if __name__ == "__main__":
    server = ChatServer()
    server.start()
