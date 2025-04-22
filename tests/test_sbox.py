import unittest
from cipher.sbox import SBox  # Adjusted import to use relative path

class TestSBox(unittest.TestCase):
    def test_substitution_reversibility(self):
        """
        Test that substituting a byte and then reversing it
        returns the original byte.
        """
        sbox = SBox(size=256, seed=42)
        print("S-Box:", sbox.sbox)  # Print the generated S-Box
        for byte in range(256):
            substituted = sbox.substitute(byte)
            reversed_byte = sbox.reverse_substitute(substituted)
            print(f"Byte: {byte}, Substituted: {substituted}, Reversed: {reversed_byte}")
            self.assertEqual(byte, reversed_byte, f"Failed for byte {byte}: {reversed_byte} != {byte}")

    def test_unique_substitution(self):
        """
        Test that all substituted values are unique.
        """
        sbox = SBox(seed=42)
        print("S-Box:", sbox.sbox)  # Print the generated S-Box
        substituted_values = set()
        for i in range(sbox.size):
            val = sbox.substitute(i)
            print(f"Original: {i}, Substituted: {val}")
            self.assertNotIn(val, substituted_values)
            substituted_values.add(val)
        self.assertEqual(len(substituted_values), sbox.size)

    def test_deterministic_with_seed(self):
        """
        Test that using the same seed produces the same S-Box.
        """
        sbox1 = SBox(seed=123)
        sbox2 = SBox(seed=123)
        print("S-Box 1:", sbox1.sbox)
        print("S-Box 2:", sbox2.sbox)
        for i in range(sbox1.size):
            self.assertEqual(sbox1.substitute(i), sbox2.substitute(i))

    def test_random_without_seed(self):
        """
        Test that S-Boxes generated without a seed are different.
        """
        sbox1 = SBox()
        sbox2 = SBox()
        print("S-Box 1 (no seed):", sbox1.sbox)
        print("S-Box 2 (no seed):", sbox2.sbox)
        # There is a very small chance they could be the same, but it's unlikely.
        # We will just check that they are not equal
        self.assertNotEqual(sbox1.sbox, sbox2.sbox)

    def test_invalid_index_substitution(self):
        """
        Test that substituting an out-of-bounds index raises an error.
        """
        sbox = SBox()
        with self.assertRaises(IndexError):
            print("Attempting to substitute an invalid index...")
            sbox.substitute(256)  # Out of bounds

    def test_invalid_index_reverse_substitution(self):
        """
        Test that reversing a substitution for a value not in the S-Box raises an error.
        """
        sbox = SBox()
        with self.assertRaises(ValueError):
            print("Attempting to reverse substitute an invalid value...")
            sbox.reverse_substitute(300)  # Value not in S-Box

if __name__ == '__main__':
    unittest.main()