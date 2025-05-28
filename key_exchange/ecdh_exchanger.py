from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

class ecdh_exchanger:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # Signing key for identity
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.verification_key = self.signing_key.public_key()

    def get_public_bundle(self):
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Sign the ECDH public key
        signature = self.signing_key.sign(
            public_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        verification_key_bytes = self.verification_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "public_key": public_bytes,
            "signature": signature,
            "verification_key": verification_key_bytes
        }

    def compute_shared_secret(self, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_key.hex()
