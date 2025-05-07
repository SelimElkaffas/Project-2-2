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
    
    def handle_client(self, client_socket, address):
        try:
            # Step 1: Send server's public key
            server_public_key = self.key_exchange.get_public_key()
            client_socket.send(server_public_key)
            
            # Step 2: Receive client's public key
            client_public_key = client_socket.recv(4096)
            
            # Step 3: Derive shared session key
            session_key = self.key_exchange.derive_session_key(client_public_key)
            
            # Step 4: Create cipher with session key
            cipher = CustomCipher(key=session_key.hex()[:16], num_rounds=8)
            
            # Step 5: Receive encrypted username
            encrypted_username_bytes = client_socket.recv(8)
            encrypted_username = int.from_bytes(encrypted_username_bytes, 'big')
            decrypted_username_blocks = [cipher.decrypt_block(encrypted_username)]
            username = blocks_to_text(decrypted_username_blocks)
            
            # Store the session key
            self.session_manager.add_key(username, session_key)
            
            # Add client to the list
            self.clients[client_socket] = username
            
            # Broadcast that the user joined
            self.broadcast(f"{username} joined the chat!")
            
            # Handle messages from this client
            while True:
                try:
                    encrypted_message_bytes = client_socket.recv(1024)
                    if not encrypted_message_bytes:
                        break
                    
                    # Decrypt message
                    encrypted_blocks = []
                    for i in range(0, len(encrypted_message_bytes), 8):
                        block = int.from_bytes(encrypted_message_bytes[i:i+8], 'big')
                        encrypted_blocks.append(block)
                    
                    decrypted_blocks = [cipher.decrypt_block(block) for block in encrypted_blocks]
                    full_message = blocks_to_text(decrypted_blocks)
                    
                    # Split message ID and content
                    try:
                        message_id, message = full_message.split('|', 1)
                        # Broadcast the message with the ID
                        self.broadcast(f"{username}: {message}", message_id)
                    except ValueError:
                        # If message doesn't contain ID, broadcast as is
                        self.broadcast(f"{username}: {full_message}")
                    
                except Exception as e:
                    print(f"Error handling message from {username}: {e}")
                    break
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            # Clean up
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
                cipher = CustomCipher(key=session_key.hex()[:16], num_rounds=8)
                
                encrypted_blocks = [cipher.encrypt_block(block) for block in message_blocks]
                message_bytes = b''
                for block in encrypted_blocks:
                    message_bytes += block.to_bytes(8, 'big')
                
                client_socket.send(message_bytes)
            except Exception as e:
                print(f"Error broadcasting to {username}: {e}")
                # Remove the client if there's an error
                if client_socket in self.clients:
                    del self.clients[client_socket]
                    client_socket.close()

if __name__ == "__main__":
    server = ChatServer()
    server.start()