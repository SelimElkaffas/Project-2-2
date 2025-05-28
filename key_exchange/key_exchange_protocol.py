import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from key_exchange.ecdh_exchanger import ECDHExchanger

class key_exchange_protocol:
    def __init__(self):
        self.exchanger = ECDHExchanger()

    def get_public_bundle(self):
        return self.exchanger.get_public_bundle()

    def derive_session_key(self, peer_bundle):
        peer_public_bytes = peer_bundle["public_key"]
        signature = peer_bundle["signature"]
        verification_key_bytes = peer_bundle["verification_key"]

        # Deserialize verification key
        verification_key = serialization.load_pem_public_key(verification_key_bytes)

        # Verify signature on received public key
        try:
            verification_key.verify(
                signature,
                peer_public_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            raise ValueError("Signature verification failed: possible MITM attack")

        # Compute shared secret
        shared_secret = self.exchanger.compute_shared_secret(peer_public_bytes)
        print(f"Shared Secret (hex): {shared_secret}")

        # Convert the shared secret from hex to bytes
        shared_secret = bytes.fromhex(shared_secret)

        # Derive a session key from the shared secret using SHA-256
        session_key = hashlib.sha256(shared_secret).digest()
        return session_key[:8]  # Truncate to 64 bits
