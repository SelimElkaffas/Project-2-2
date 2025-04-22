import unittest
from cipher.pbox import PBox

class TestPBox(unittest.TestCase):

    def test_identity_permutation(self):
        # Tests the default identity permutation (no changes to the input)
        # Ensures that the permutation and inverse permutation return the same value
        
        pbox = PBox(block_size=8)
        for i in range(256):
            self.assertEqual(pbox.permute(i), i)
            self.assertEqual(pbox.inverse_permute(i), i)

    def test_custom_permutation(self):
        # Tests a custom permutation where the bits are reversed
        # For example, if the input is 0b11010010, the output should be 0b01001011

        perm = [7, 6, 5, 4, 3, 2, 1, 0]  # reverse bits
        pbox = PBox(block_size=8, permutation=perm)
        block = 0b11010010
        # print(f"Inversed block: {bin(pbox.inverse_permute(block))}")
        expected = int('{:08b}'.format(block)[::-1], 2)  # reverse the bits
        permuted = pbox.permute(block)
        self.assertEqual(permuted, expected)
        self.assertEqual(pbox.inverse_permute(permuted), block)

    def test_permutation_and_inverse(self):
        # Tests that permuting and then inverse permuting returns the original value
        # Ensures that the permutation and inverse permutation are correct for all possible 8bit inputs (from 0 to 255)
        
        import random
        perm = list(range(8))
        random.shuffle(perm)
        pbox = PBox(block_size=8, permutation=perm)
        for i in range(256):
            permuted = pbox.permute(i)
            restored = pbox.inverse_permute(permuted)
            self.assertEqual(i, restored)

    def test_invalid_permutation_length(self):
        with self.assertRaises(ValueError):
            PBox(block_size=8, permutation=[0, 1, 2])  # Too short

if __name__ == '__main__':
    unittest.main()
