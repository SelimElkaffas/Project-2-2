import unittest
from cipher.custom_cipher import CustomCipher

class TestCustomCipher(unittest.TestCase):

    def test_encrypt_decrypt_symmetry(self):
        # Tests that encrypting and then decrypting a block returns the original block.
        cipher = CustomCipher(key="testkey123", num_rounds=8)
        for block in [0x0123456789ABCDEF, 0xFFFFFFFFFFFFFFFF, 0x0000000000000000, 0x1234567890ABCDEF]:
            encrypted = cipher.encrypt_block(block)
            decrypted = cipher.decrypt_block(encrypted)
            print(f"Block: {hex(block)}, Encrypted: {hex(encrypted)}, Decrypted: {hex(decrypted)}")
            self.assertEqual(block, decrypted)

    def test_different_keys_produce_different_ciphertext(self):
        # Tests that using different keys produces different ciphertext for the same plaintext block.
        block = 0xDEADBEEFCAFEBABE
        cipher1 = CustomCipher(key="alpha")
        cipher2 = CustomCipher(key="beta")
        encrypted1 = cipher1.encrypt_block(block)
        encrypted2 = cipher2.encrypt_block(block)
        print(f"Block: {hex(block)}, Encrypted with 'alpha': {hex(encrypted1)}, Encrypted with 'beta': {hex(encrypted2)}")
        self.assertNotEqual(encrypted1, encrypted2)

    def test_deterministic_encryption(self):
        # Tests that using the same key produces the same ciphertext for the same plaintext block.
        block = 0xFACEB00CDEADC0DE
        cipher1 = CustomCipher(key="consistent")
        cipher2 = CustomCipher(key="consistent")
        encrypted1 = cipher1.encrypt_block(block)
        encrypted2 = cipher2.encrypt_block(block)
        print(f"Block: {hex(block)}, Encrypted with 'consistent' (cipher1): {hex(encrypted1)}, Encrypted with 'consistent' (cipher2): {hex(encrypted2)}")
        self.assertEqual(encrypted1, encrypted2)

    def test_ciphertext_differs_from_plaintext(self):
        # Tests that the ciphertext is different from the plaintext block.
        block = 0x1122334455667788
        cipher = CustomCipher(key="testkey")
        ciphertext = cipher.encrypt_block(block)
        print(f"Block: {hex(block)}, Ciphertext: {hex(ciphertext)}")
        self.assertNotEqual(ciphertext, block)

    def test_encrypt_decrypt_random_blocks(self):
        # Tests that encrypting and then decrypting random blocks returns the original block.
        import random
        cipher = CustomCipher(key="stressTestKey")
        for _ in range(1000):
            block = random.getrandbits(64)  # Generate a random 64-bit block
            encrypted = cipher.encrypt_block(block)
            decrypted = cipher.decrypt_block(encrypted)
            # print(f"Random Block: {hex(block)}, Encrypted: {hex(encrypted)}, Decrypted: {hex(decrypted)}")
            self.assertEqual(block, decrypted)

if __name__ == '__main__':
    unittest.main()

