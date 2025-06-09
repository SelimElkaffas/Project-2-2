import unittest
import random
from cipher.custom_cipher import CustomCipher

class TestCustomCipher(unittest.TestCase):

    def setUp(self):
        self.valid_key = b"thisis16bytekey!"  # 16 bytes = 128 bits
        self.cipher = CustomCipher(key=self.valid_key, num_rounds=8)

    def test_encrypt_decrypt_symmetry(self):
        for block in [
            0x0123456789ABCDEF0123456789ABCDEF,
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            0x00000000000000000000000000000000,
            0x1234567890ABCDEF1234567890ABCDEF
        ]:
            encrypted = self.cipher.encrypt_block(block)
            decrypted = self.cipher.decrypt_block(encrypted)
            self.assertEqual(block, decrypted)

    def test_different_keys_produce_different_ciphertext(self):
        block = 0xDEADBEEFCAFEBABE1122334455667788
        cipher1 = CustomCipher(key=b"alphaalphaalphaaa")
        cipher2 = CustomCipher(key=b"betabetabetabeta")
        encrypted1 = cipher1.encrypt_block(block)
        encrypted2 = cipher2.encrypt_block(block)
        self.assertNotEqual(encrypted1, encrypted2)

    def test_deterministic_encryption(self):
        block = 0xFACEB00CDEADC0DEFACEB00CDEADC0DE
        cipher1 = CustomCipher(key=b"consistent__key")
        cipher2 = CustomCipher(key=b"consistent__key")
        encrypted1 = cipher1.encrypt_block(block)
        encrypted2 = cipher2.encrypt_block(block)
        self.assertEqual(encrypted1, encrypted2)

    def test_ciphertext_differs_from_plaintext(self):
        block = 0x11223344556677881122334455667788
        ciphertext = self.cipher.encrypt_block(block)
        self.assertNotEqual(ciphertext, block)

    def test_encrypt_decrypt_random_blocks(self):
        for _ in range(1000):
            block = random.getrandbits(128)  # 128-bit random block
            encrypted = self.cipher.encrypt_block(block)
            decrypted = self.cipher.decrypt_block(encrypted)
            self.assertEqual(block, decrypted)

if __name__ == '__main__':
    unittest.main()
