import random
import numpy as np

class SBox:
    def __init__(self, size=256, seed=None):
        self.size = size
        self.sbox = list(range(size))
        if seed is not None:
            random.seed(seed)
        random.shuffle(self.sbox)
        self.inverse_sbox = [0] * size
        for i, val in enumerate(self.sbox):
            self.inverse_sbox[val] = i

    def substitute(self, byte):
        # Substitutes a byte using the S-Box
        return self.sbox[byte]
    
    def reverse_substitute(self, byte):
        if byte < 0 or byte >= self.size:
            raise ValueError("Byte not found in inverse S-Box")

        # Reverses the substitution using the inverse S-Box
        return self.inverse_sbox[byte]
    
    def substitute_array(self, arr):
        """Vectorized SBox substitution for numpy arrays"""
        return np.take(self.sbox, arr)
    
    def reverse_substitute_array(self, arr):
        """Vectorized inverse SBox substitution for numpy arrays"""
        return np.take(self.inverse_sbox, arr)
    
    def get_substitution_array(self):
        """Returns the S-Box as a numpy array."""
        return np.array(self.sbox, dtype=np.uint8)
    
    def get_inverse_substitution_array(self):
        """Returns the inverse S-Box as a numpy array."""
        return np.array(self.inverse_sbox, dtype=np.uint8)