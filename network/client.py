import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from key_exchange.key_exchange_protocol import KeyExchangeProtocol
from cipher.custom_cipher import CustomCipher
from utils.block_conversion import text_to_blocks, blocks_to_text
import uuid
import time

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        try:
            self.host = host
            self.port = port
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.key_exchange = KeyExchangeProtocol()
            self.cipher = None
            self.username = None
            self.last_message_id = None
            
            # Setup GUI
            self.root = tk.Tk()
            self.root.title("Encrypted Chat")
            self.root.geometry("800x600")  # Larger window
            self.root.configure(bg='#f0f0f0')
            
            # Create main frame
            main_frame = tk.Frame(self.root, bg='#f0f0f0')
            main_frame.pack(expand=True, fill='both', padx=10, pady=10)
            
            # Chat display area with custom styling
            self.chat_display = scrolledtext.ScrolledText(
                main_frame,
                width=70,
                height=20,
                font=('Arial', 10),
                bg='white',
                fg='#333333',
                relief=tk.GROOVE,
                bd=2
            )
            self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            self.chat_display.config(state=tk.DISABLED)
            
            # Message input area with improved styling
            self.message_frame = tk.Frame(main_frame, bg='#f0f0f0')
            self.message_frame.pack(padx=10, pady=10, fill=tk.X)
            
            self.message_input = tk.Entry(
                self.message_frame,
                width=50,
                font=('Arial', 11),
                relief=tk.GROOVE,
                bd=2
            )
            self.message_input.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            self.message_input.bind("<Return>", self.send_message)
            
            # Send button with improved styling
            self.send_button = tk.Button(
                self.message_frame,
                text="Send",
                command=self.send_message,
                font=('Arial', 11, 'bold'),
                bg='#4CAF50',
                fg='white',
                padx=15,
                pady=5,
                relief=tk.RAISED,
                bd=3,
                cursor='hand2'
            )
            self.send_button.pack(side=tk.RIGHT, padx=5)
            
            # Add hover effect for send button
            def on_enter(e):
                self.send_button['bg'] = '#45a049'
            
            def on_leave(e):
                self.send_button['bg'] = '#4CAF50'
            
            self.send_button.bind("<Enter>", on_enter)
            self.send_button.bind("<Leave>", on_leave)
            
            # Status bar
            self.status_bar = tk.Label(
                main_frame,
                text="Disconnected",
                bd=1,
                relief=tk.SUNKEN,
                anchor=tk.W,
                bg='#e0e0e0',
                fg='#333333',
                font=('Arial', 9)
            )
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            
        except Exception as e:
            print(f"Error initializing client: {e}")
            raise
        
    def connect(self, username):
        self.username = username
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Update status bar
            self.status_bar.config(text=f"Connected as {username}")
            
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
            self.status_bar.config(text="Connection failed")
            if hasattr(self, 'socket'):
                try:
                    self.socket.close()
                except:
                    pass
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
                full_message = blocks_to_text(decrypted_blocks)
                
                # Split message ID and content
                try:
                    message_id, message = full_message.split('|', 1)
                    
                    # If it's our own message, display with "You: "
                    if message_id == self.last_message_id:
                        self.root.after(0, lambda m=message: self.display_message(f"You: {m}"))
                    else:
                        # Otherwise display the message as received
                        self.root.after(0, lambda m=message: self.display_message(m))
                except ValueError:
                    # If message doesn't contain ID, display as is
                    self.root.after(0, lambda m=full_message: self.display_message(m))
                
            except Exception as e:
                print(f"Error receiving message: {e}")
                if hasattr(self, 'socket'):
                    try:
                        self.socket.close()
                    except:
                        pass
                break
    
    def send_message(self, event=None):
        message = self.message_input.get()
        if message:
            self.message_input.delete(0, tk.END)
            
            try:
                # Generate a unique message ID
                message_id = str(uuid.uuid4())
                self.last_message_id = message_id
                
                # Add message ID to the message
                full_message = f"{message_id}|{message}"
                
                # Encrypt message
                blocks = text_to_blocks(full_message)
                encrypted_blocks = [self.cipher.encrypt_block(block) for block in blocks]
                
                # Convert to bytes and send
                message_bytes = b''
                for block in encrypted_blocks:
                    message_bytes += block.to_bytes(8, 'big')
                
                self.socket.send(message_bytes)
                # Don't display the message here - wait for the broadcast
            except Exception as e:
                print(f"Error sending message: {e}")
                self.display_message("Error sending message. Connection may be lost.")
                if hasattr(self, 'socket'):
                    try:
                        self.socket.close()
                    except:
                        pass
    
    def display_message(self, message):
        self.chat_display.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        
        # Different styling for different message types
        if message.startswith("You: "):
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.chat_display.insert(tk.END, message + "\n", 'self_message')
        elif message.endswith(" joined the chat!"):
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.chat_display.insert(tk.END, message + "\n", 'system_message')
        elif message.endswith(" left the chat!"):
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.chat_display.insert(tk.END, message + "\n", 'system_message')
        else:
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.chat_display.insert(tk.END, message + "\n", 'other_message')
        
        # Configure tags for different message types
        self.chat_display.tag_config('timestamp', foreground='gray')
        self.chat_display.tag_config('self_message', foreground='#0066cc')
        self.chat_display.tag_config('system_message', foreground='#666666', font=('Arial', 9, 'italic'))
        self.chat_display.tag_config('other_message', foreground='#333333')
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def start(self):
        try:
            print("Creating login window...")
            # Create a new window instead of Toplevel
            login_window = tk.Tk()
            login_window.title("Chat Login")
            login_window.geometry("400x250+300+300")  # Made window slightly larger
            login_window.configure(bg='#f0f0f0')  # Light gray background
            login_window.attributes('-topmost', True)
            print("Login window created")
            
            # Add a frame with padding and styling
            frame = tk.Frame(login_window, bg='#f0f0f0', padx=30, pady=30)
            frame.pack(expand=True, fill='both')
            
            # Title label
            title_label = tk.Label(
                frame,
                text="Welcome to Encrypted Chat",
                font=('Arial', 16, 'bold'),
                bg='#f0f0f0',
                fg='#333333'
            )
            title_label.pack(pady=(0, 20))
            
            # Username label and entry
            username_label = tk.Label(
                frame,
                text="Enter your username:",
                font=('Arial', 12),
                bg='#f0f0f0',
                fg='#333333'
            )
            username_label.pack(pady=(0, 10))
            
            username_entry = tk.Entry(
                frame,
                width=30,
                font=('Arial', 12),
                bd=2,
                relief=tk.GROOVE
            )
            username_entry.pack(pady=(0, 20))
            username_entry.focus()
            
            def login():
                try:
                    username = username_entry.get()
                    if username:
                        if self.connect(username):
                            login_window.destroy()
                            self.root.title(f"Encrypted Chat - {username}")
                            self.root.deiconify()
                            self.root.mainloop()
                        else:
                            tk.messagebox.showerror("Error", "Connection failed!")
                except Exception as e:
                    print(f"Login error: {e}")
                    tk.messagebox.showerror("Error", f"Login failed: {str(e)}")
            
            # Connect button with improved styling
            connect_btn = tk.Button(
                frame,
                text="Connect to Chat",
                command=login,
                font=('Arial', 12, 'bold'),
                bg='#4CAF50',  # Green color
                fg='white',
                padx=20,
                pady=10,
                relief=tk.RAISED,
                bd=3,
                cursor='hand2'  # Hand cursor on hover
            )
            connect_btn.pack(pady=10)
            
            # Add hover effect
            def on_enter(e):
                connect_btn['bg'] = '#45a049'  # Darker green
            
            def on_leave(e):
                connect_btn['bg'] = '#4CAF50'  # Original green
            
            connect_btn.bind("<Enter>", on_enter)
            connect_btn.bind("<Leave>", on_leave)
            
            username_entry.bind("<Return>", lambda e: login())
            
            # Force the window to the foreground
            login_window.lift()
            login_window.focus_force()
            
            print("Starting login window mainloop...")
            login_window.mainloop()
            print("Login window mainloop ended")
            
        except Exception as e:
            print(f"Error in start method: {e}")
            if 'login_window' in locals():
                login_window.destroy()
            raise

if __name__ == "__main__":
    try:
        client = ChatClient()
        print("Starting encrypted chat client...")
        client.start()
    except Exception as e:
        print(f"Fatal error: {e}")
        input("Press Enter to exit...")