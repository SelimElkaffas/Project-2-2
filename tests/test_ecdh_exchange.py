import unittest
from key_exchange.ecdh_exchanger import ECDHExchanger

class TestECDHExchanger(unittest.TestCase):

    def test_key_pair_generation(self):
        exchanger = ECDHExchanger()
        public_key = exchanger.get_public_bytes()
        self.assertIsInstance(public_key, bytes)
        self.assertIn(b'BEGIN PUBLIC KEY', public_key)

    def test_shared_secret_agreement(self):
        alice = ECDHExchanger()
        bob = ECDHExchanger()
        alice_secret = alice.compute_shared_secret(bob.get_public_bytes())
        bob_secret = bob.compute_shared_secret(alice.get_public_bytes())
        self.assertEqual(alice_secret, bob_secret)

    def test_invalid_public_key(self):
        exchanger = ECDHExchanger()
        invalid_key = b"invalid public key data"
        with self.assertRaises(ValueError):
            exchanger.compute_shared_secret(invalid_key)

    def test_key_pair_uniqueness(self):
        exchanger1 = ECDHExchanger()
        exchanger2 = ECDHExchanger()
        self.assertNotEqual(exchanger1.get_public_bytes(), exchanger2.get_public_bytes())

    def test_shared_secret_length(self):
        alice = ECDHExchanger()
        bob = ECDHExchanger()
        shared_secret = alice.compute_shared_secret(bob.get_public_bytes())
        self.assertEqual(len(shared_secret), 32)  # ✅ raw bytes, not hex

    def test_public_key_format(self):
        exchanger = ECDHExchanger()
        public_key = exchanger.get_public_bytes()
        self.assertTrue(public_key.startswith(b"-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(public_key.endswith(b"-----END PUBLIC KEY-----\n"))

    def test_shared_secret_consistency(self):
        alice = ECDHExchanger()
        bob = ECDHExchanger()
        secret1 = alice.compute_shared_secret(bob.get_public_bytes())
        secret2 = alice.compute_shared_secret(bob.get_public_bytes())
        self.assertEqual(secret1, secret2)

if __name__ == "__main__":
    unittest.main()
