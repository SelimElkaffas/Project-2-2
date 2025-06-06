from key_exchange.key_exchange_protocol import KeyExchangeProtocol
import unittest

class TestKeyExchangeProtocol(unittest.TestCase):

    def test_session_key_derivation(self):
        alice = KeyExchangeProtocol()
        bob = KeyExchangeProtocol()
        alice_key = alice.derive_session_key(bob.get_public_key())
        bob_key = bob.derive_session_key(alice.get_public_key())
        self.assertEqual(alice_key, bob_key)
        self.assertEqual(len(alice_key), 16)  # 🔧 First 16 bytes used by CustomCipher

    def test_public_key_format(self):
        protocol = KeyExchangeProtocol()
        public_key = protocol.get_public_key()
        self.assertTrue(public_key.startswith(b"-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(public_key.endswith(b"-----END PUBLIC KEY-----\n"))

    def test_session_key_length(self):
        alice = KeyExchangeProtocol()
        bob = KeyExchangeProtocol()
        session_key = alice.derive_session_key(bob.get_public_key())
        self.assertEqual(len(session_key), 16)  # 🔧 match cipher use

    def test_session_key_consistency(self):
        alice = KeyExchangeProtocol()
        bob = KeyExchangeProtocol()
        key1 = alice.derive_session_key(bob.get_public_key())
        key2 = alice.derive_session_key(bob.get_public_key())
        self.assertEqual(key1, key2)

    def test_key_exchange_multiple_parties(self):
        alice = KeyExchangeProtocol()
        bob = KeyExchangeProtocol()
        charlie = KeyExchangeProtocol()

        alice_bob_key = alice.derive_session_key(bob.get_public_key())
        bob_alice_key = bob.derive_session_key(alice.get_public_key())

        alice_charlie_key = alice.derive_session_key(charlie.get_public_key())
        charlie_alice_key = charlie.derive_session_key(alice.get_public_key())

        self.assertEqual(alice_bob_key, bob_alice_key)
        self.assertEqual(alice_charlie_key, charlie_alice_key)
        self.assertNotEqual(alice_bob_key, alice_charlie_key)

    def test_invalid_public_key(self):
        alice = KeyExchangeProtocol()
        invalid_key = b"invalid public key data"
        with self.assertRaises(ValueError):
            alice.derive_session_key(invalid_key)

    def test_shared_secret_conversion(self):
        alice = KeyExchangeProtocol()
        bob = KeyExchangeProtocol()
        shared_secret = alice.exchanger.compute_shared_secret(bob.get_public_key())
        self.assertIsInstance(shared_secret, bytes)
        self.assertEqual(len(shared_secret), 32)  # ✅ 256 bits

if __name__ == "__main__":
    unittest.main()
