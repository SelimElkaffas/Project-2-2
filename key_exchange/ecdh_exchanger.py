from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ECDHExchanger:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def compute_shared_secret(self, peer_pubic_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_pubic_bytes)
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_key.hex()
