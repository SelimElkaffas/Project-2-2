from network.server import ChatServer

if __name__ == "__main__":
    server = ChatServer()
    print("Starting encrypted chat server...")
    server.start()