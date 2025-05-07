import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from key_exchange.key_exchange_protocol import KeyExchangeProtocol
from cipher.custom_cipher import CustomCipher
from utils.block_conversion import text_to_blocks, blocks_to_text

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key_exchange = KeyExchangeProtocol()
        self.cipher = None
        self.username = None
        
        # Setup GUI
        self.root = tk.Tk()
        self.root.title("Encrypted Chat")
        self.root.geometry("600x500")
        
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(self.root, width=70, height=20)
        self.chat_display.pack(padx=10, pady=10)
        self.chat_display.config(state=tk.DISABLED)
        
        # Message input area
        self.message_frame = tk.Frame(self.root)
        self.message_frame.pack(padx=10, pady=10, fill=tk.X)
        
        self.message_input = tk.Entry(self.message_frame, width=50)
        self.message_input.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.message_input.bind("<Return>", self.send_message)
        
        self.send_button = tk.Button(self.message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        
    def connect(self, username):
        self.username = username
        try:
            self.socket.connect((self.host, self.port))
            
            # Step 1: Receive server's public key
            server_public_key = self.socket.recv(4096)
            
            # Step 2: Send client's public key
            client_public_key = self.key_exchange.get_public_key()
            self.socket.send(client_public_key)
            
            # Step 3: Derive shared session key
            session_key = self.key_exchange.derive_session_key(server_public_key)
            
            # Step 4: Create cipher with session key
            self.cipher = CustomCipher(key=session_key.hex()[:16], num_rounds=8)
            
            # Step 5: Send encrypted username
            username_blocks = text_to_blocks(username)
            encrypted_username = self.cipher.encrypt_block(username_blocks[0])
            self.socket.send(encrypted_username.to_bytes(8, 'big'))
            
            # Start receiving messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def receive_messages(self):
        while True:
            try:
                encrypted_message_bytes = self.socket.recv(1024)
                if not encrypted_message_bytes:
                    break
                
                # Decrypt message
                encrypted_blocks = []
                for i in range(0, len(encrypted_message_bytes), 8):
                    block = int.from_bytes(encrypted_message_bytes[i:i+8], 'big')
                    encrypted_blocks.append(block)
                
                decrypted_blocks = [self.cipher.decrypt_block(block) for block in encrypted_blocks]
                message = blocks_to_text(decrypted_blocks)
                
                # Display message
                self.display_message(message)
                
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.socket.close()
                break
    
    def send_message(self, event=None):
        message = self.message_input.get()
        if message:
            self.message_input.delete(0, tk.END)
            
            # Encrypt message
            blocks = text_to_blocks(message)
            encrypted_blocks = [self.cipher.encrypt_block(block) for block in blocks]
            
            # Convert to bytes and send
            message_bytes = b''
            for block in encrypted_blocks:
                message_bytes += block.to_bytes(8, 'big')
            
            try:
                self.socket.send(message_bytes)
                self.display_message(f"You: {message}")
            except Exception as e:
                print(f"Error sending message: {e}")
                self.display_message("Error sending message. Connection may be lost.")
    
    def display_message(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def start(self):
        # Login window
        login_window = tk.Toplevel(self.root)
        login_window.title("Login")
        login_window.geometry("300x150")
        
        tk.Label(login_window, text="Enter your username:").pack(pady=10)
        username_entry = tk.Entry(login_window, width=30)
        username_entry.pack(pady=10)
        username_entry.focus()
        
        def login():
            username = username_entry.get()
            if username:
                if self.connect(username):
                    login_window.destroy()
                    self.root.title(f"Encrypted Chat - {username}")
                else:
                    tk.Label(login_window, text="Connection failed!", fg="red").pack()
        
        tk.Button(login_window, text="Connect", command=login).pack(pady=10)
        username_entry.bind("<Return>", lambda event: login())
        
        self.root.withdraw()  # Hide main window until login
        login_window.protocol("WM_DELETE_WINDOW", self.root.destroy)
        
        login_window.transient(self.root)
        login_window.grab_set()
        
        self.root.wait_window(login_window)
        self.root.deiconify()  # Show main window after login
        
        self.root.mainloop()

if __name__ == "__main__":
    client = ChatClient()
    client.start()