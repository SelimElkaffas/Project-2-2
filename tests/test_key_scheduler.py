import unittest
from cipher.key_scheduler import KeyScheduler

class TestKeyScheduler(unittest.TestCase):

    def test_round_keys_length(self):
        # Tests that the correct number of round keys are generated
        # Ensures that the length of the 'round_keys' list matches the number of rounds specified

        ks = KeyScheduler(base_key="testkey", num_rounds=10, round_key_size=64)
        self.assertEqual(len(ks.round_keys), 10)

    def test_get_specific_round_key(self):
        # Tests retrieving a specific round key by index
        # Ensures that the returned key is of the correct type and size
        # Also checks that the key is less than 2^round_key_size

        ks = KeyScheduler(base_key="secure", num_rounds=5, round_key_size=64)
        key = ks.get_round_key(2)
        self.assertIsInstance(key, int)
        self.assertLess(key, 2**64)

    def test_round_key_size(self):
        # Tests that all generated round keys are within the specified size
        # Ensures that no key exceeds the maximum value allowed by `round_key_size`

        ks = KeyScheduler(base_key="sizecheck", num_rounds=3, round_key_size=32)
        for key in ks.round_keys:
            self.assertLess(key, 2**32)

    def test_invalid_round_index(self):
        ks = KeyScheduler(base_key="invalid", num_rounds=4, round_key_size=64)
        with self.assertRaises(IndexError):
            ks.get_round_key(-1)
        with self.assertRaises(IndexError):
            ks.get_round_key(4)

    def test_different_keys_for_different_rounds(self):
        # Tests that all round keys are unique
        # Ensures that the keys generated for different rounds are not repeated

        ks = KeyScheduler(base_key="diffrounds", num_rounds=4, round_key_size=64)
        keys = ks.round_keys
        self.assertEqual(len(set(keys)), len(keys))  # all keys should be unique

    def test_same_input_same_keys(self):
        # Tests that using the same base key, number of rounds, and key size produces the same sequence of round keys.
        # Ensures deterministic behavior of the key scheduler.

        ks1 = KeyScheduler(base_key="repeatable", num_rounds=5, round_key_size=64)
        ks2 = KeyScheduler(base_key="repeatable", num_rounds=5, round_key_size=64)
        self.assertEqual(ks1.round_keys, ks2.round_keys)

if __name__ == '__main__':
    unittest.main()
