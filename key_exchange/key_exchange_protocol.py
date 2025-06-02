import hashlib
from key_exchange.ecdh_exchanger import ECDHExchanger

class KeyExchangeProtocol:
    def __init__(self):
        self.exchanger = ECDHExchanger()

    def get_public_key(self):
        return self.exchanger.get_public_bytes()
    
    def derive_session_key(self, peer_public_bytes):
        shared_secret = self.exchanger.compute_shared_secret(peer_public_bytes)
        print(f"Shared Secret (hex): {shared_secret}")

        # Convert the shared secret from hex to bytes
        shared_secret = bytes.fromhex(shared_secret)

        # Derive a session key from the shared secret using SHA-256
        session_key = hashlib.sha256(shared_secret).digest()
        return session_key[:8]  # Truncate to 64 bits for the cipher