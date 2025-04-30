from key_exchange.key_exchange_protocol import KeyExchangeProtocol
from cipher.custom_cipher import CustomCipher

def simulate_encryption_exchange(message: int):
    # Simulate Alice and Bob key exchange
    alice_kep = KeyExchangeProtocol()
    bob_kep = KeyExchangeProtocol()

    alice_pub = alice_kep.get_public_key()
    bob_pub = bob_kep.get_public_key()

    alice_session_key = alice_kep.derive_session_key(bob_pub)
    bob_session_key = bob_kep.derive_session_key(alice_pub)

    keys_match = alice_session_key == bob_session_key
    cipher_key = alice_session_key.hex()

    alice_cipher = CustomCipher(key=cipher_key)
    bob_cipher = CustomCipher(key=cipher_key)

    encrypted_message = alice_cipher.encrypt_block(message)
    decrypted_message = bob_cipher.decrypt_block(encrypted_message)
    print({
        "original_message": message,
        "encrypted_message": encrypted_message,
        "decrypted_message": decrypted_message,
        "keys_match": keys_match,
        "encryption_valid": message == decrypted_message
    })
    return {
        "original_message": message,
        "encrypted_message": encrypted_message,
        "decrypted_message": decrypted_message,
        "keys_match": keys_match,
        "encryption_valid": message == decrypted_message
    }

# Example usage with a sample message
simulate_encryption_exchange(0x0123456789ABCDEF)
