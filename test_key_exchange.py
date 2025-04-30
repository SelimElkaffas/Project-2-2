from key_exchange.key_exchange_protocol import KeyExchangeProtocol

def test_ecdh_key_exchange():
    # Simulate Alice
    alice = KeyExchangeProtocol()
    alice_public = alice.get_public_key()

    # Simulate Bob
    bob = KeyExchangeProtocol()
    bob_public = bob.get_public_key()

    # Exchange public keys and derive shared session keys
    alice_session_key = alice.derive_session_key(bob_public)
    bob_session_key = bob.derive_session_key(alice_public)

    print("Alice's Session Key:", alice_session_key.hex())
    print("Bob's Session Key:  ", bob_session_key.hex())

    assert alice_session_key == bob_session_key, "Session keys do not match!"
    print("✅ Key exchange successful! Shared session key established.")

if __name__ == "__main__":
    test_ecdh_key_exchange()
