import sys
import os
from network.client import ChatClient

if __name__ == "__main__":
    try:
        print("Python version:", sys.version)
        print("Current directory:", os.getcwd())
        print("Starting encrypted chat client...")
        client = ChatClient()
        print("Client instance created successfully")
        print("Starting client...")
        client.start()
    except Exception as e:
        print(f"Error starting client: {e}")
        input("Press Enter to exit...")
