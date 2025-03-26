import socket
import sys
import os

# We will use PyCryptodome for RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair(key_size=2048):
    """
    Generate an RSA public/private key pair.
    """
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext_bytes):
    """
    Encrypt data with an RSA public key.
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext_bytes)

def rsa_decrypt(private_key, ciphertext_bytes):
    """
    Decrypt data with an RSA private key.
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext_bytes)

def xor_encrypt_decrypt(data, key):
    """
    Very simple XOR "encryption/decryption".
    data: bytes
    key:  bytes (same length or repeated)
    """
    # If key is shorter than data, we repeat it (not secure, just for demo).
    expanded_key = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, expanded_key))


def main():
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keypair()
    print("Generated RSA Key Pair:")
    print("Public Key:", public_key.export_key().decode())
    print("Private Key:", private_key.export_key().decode())

    # Test RSA encryption and decryption
    message = b"This is a test for RSA encryption."
    encrypted_message = rsa_encrypt(public_key, message)
    print("\nEncrypted Message (RSA):", encrypted_message)

    decrypted_message = rsa_decrypt(private_key, encrypted_message)
    print("Decrypted Message (RSA):", decrypted_message.decode())

    # Test XOR encryption and decryption
    xor_key = b"key"
    xor_message = b"This is a test for XOR encryption."
    xor_encrypted = xor_encrypt_decrypt(xor_message, xor_key)
    print("\nEncrypted Message (XOR):", xor_encrypted)

    xor_decrypted = xor_encrypt_decrypt(xor_encrypted, xor_key)
    print("Decrypted Message (XOR):", xor_decrypted.decode())

if __name__ == "__main__":
    main()
