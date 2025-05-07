from network.client import ChatClient

if __name__ == "__main__":
    client = ChatClient()
    print("Starting encrypted chat client...")
    client.start()