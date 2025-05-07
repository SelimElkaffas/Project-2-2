import socket
import threading
from key_exchange.key_exchange_protocol import KeyExchangeProtocol
from cipher.custom_cipher import CustomCipher
from utils.block_conversion import text_to_blocks, blocks_to_text

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # {client_socket: (username, key_exchange, cipher)}
        self.key_exchange = KeyExchangeProtocol()
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            print(f"Connection from {address} established")
            
            # Start a new thread for each client
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()
    
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
            
            # Step 5: Get username
            encrypted_username = int.from_bytes(client_socket.recv(1024), 'big')
            username_block = cipher.decrypt_block(encrypted_username)
            username = blocks_to_text([username_block]).strip()
            
            # Store client information
            self.clients[client_socket] = (username, self.key_exchange, cipher)
            
            # Broadcast new user joined
            self.broadcast(f"{username} joined the chat!", client_socket)
            
            # Handle messages
            while True:
                encrypted_message_bytes = client_socket.recv(1024)
                if not encrypted_message_bytes:
                    break
                
                # Decrypt message
                encrypted_blocks = []
                for i in range(0, len(encrypted_message_bytes), 8):
                    block = int.from_bytes(encrypted_message_bytes[i:i+8], 'big')
                    encrypted_blocks.append(block)
                
                decrypted_blocks = [cipher.decrypt_block(block) for block in encrypted_blocks]
                message = blocks_to_text(decrypted_blocks)
                
                # Broadcast message
                self.broadcast(f"{username}: {message}", client_socket)
                
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            # Remove client and close connection
            if client_socket in self.clients:
                username = self.clients[client_socket][0]
                del self.clients[client_socket]
                self.broadcast(f"{username} left the chat!", None)
            client_socket.close()
    
    def broadcast(self, message, sender_socket):
        print(f"Broadcasting: {message}")
        for client_socket, (username, _, cipher) in self.clients.items():
            if client_socket != sender_socket:
                # Encrypt message for this client
                blocks = text_to_blocks(message)
                encrypted_blocks = [cipher.encrypt_block(block) for block in blocks]
                
                # Convert to bytes and send
                message_bytes = b''
                for block in encrypted_blocks:
                    message_bytes += block.to_bytes(8, 'big')
                
                try:
                    client_socket.send(message_bytes)
                except:
                    client_socket.close()
                    del self.clients[client_socket]

if __name__ == "__main__":
    server = ChatServer()
    server.start()