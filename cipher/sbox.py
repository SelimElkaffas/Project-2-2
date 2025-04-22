import random

class SBox:
    def __init__(self, size=256, seed=None):
        self.size = size
        self.sbox = list(range(size))
        if seed is not None:
            random.seed(seed)
        random.shuffle(self.sbox)

    def substitute(self, byte):
        # Substitutes a byte using the S-Box
        return self.sbox[byte]
    
    def reverse_substitute(self, byte):
        # Reverses the substitution using the inverse S-Box
        return self.sbox.index(byte)
    
    