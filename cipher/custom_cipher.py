from cipher.sbox import SBox
from cipher.pbox import PBox
from cipher.key_scheduler import KeyScheduler
import numpy as np
from utils.numba_utils import (
    split_block_128, combine_block_128,
    substitute_block_128, reverse_substitute_block_128,
    apply_permutation_128_fast, inverse_permutation_128_fast
)


class CustomCipher:
    def __init__(self, key: bytes, num_rounds: int = 8):
        self.num_rounds = num_rounds
        self.block_size = 128  # 128-bit block size

        # Ensure the key is of type bytes
        if not isinstance(key, bytes):
            raise TypeError("Key must be a bytes object.")

        self.sbox = SBox(size=256, seed=42)
        self.pbox = PBox(block_size=self.block_size)
        self.key_scheduler = KeyScheduler(
            base_key=key,
            num_rounds=num_rounds,
            round_key_size=self.block_size
        )

        # Convert to numpy arrays with correct dtypes for Numba
        self.sbox_array = np.array(self.sbox.get_substitution_array(), dtype=np.uint8)
        self.inv_sbox_array = np.array(self.sbox.get_inverse_substitution_array(), dtype=np.uint8)
        self.permutation = np.array(self.pbox.get_permutation(), dtype=np.int32)  # Changed to int32
        self.inverse_permutation = np.array(self.pbox.get_inverse_permutation(), dtype=np.int32)  # Changed to int32

    def encrypt_block(self, block: int) -> int:
        self._validate_block_size(block)
        
        # Split the 128-bit block into two 64-bit halves
        hi, lo = split_block_128(block)
        
        for round_index in range(self.num_rounds):
            # Apply S-box substitution
            hi, lo = substitute_block_128(hi, lo, self.sbox_array)
            
            # Apply permutation
            hi, lo = apply_permutation_128_fast(np.uint64(hi), np.uint64(lo), self.permutation)
            
            # Add round key - convert to Python int for XOR operations
            round_key = self.key_scheduler.get_round_key(round_index)
            round_key_hi, round_key_lo = split_block_128(round_key)
            
            # Convert to Python int for XOR, then back to numpy uint64
            hi = np.uint64(hi) ^ np.uint64(round_key_hi)
            lo = np.uint64(lo) ^ np.uint64(round_key_lo)

        return combine_block_128(hi, lo)

    def decrypt_block(self, block: int) -> int:
        self._validate_block_size(block)
        
        # Split the 128-bit block into two 64-bit halves
        hi, lo = split_block_128(block)
        
        for round_index in reversed(range(self.num_rounds)):
            # Remove round key - convert to Python int for XOR operations
            round_key = self.key_scheduler.get_round_key(round_index)
            round_key_hi, round_key_lo = split_block_128(round_key)
            
            hi = np.uint64(hi) ^ np.uint64(round_key_hi)
            lo = np.uint64(lo) ^ np.uint64(round_key_lo)
            
            # Apply inverse permutation
            hi, lo = inverse_permutation_128_fast(np.uint64(hi), np.uint64(lo), self.inverse_permutation)
            
            # Apply inverse S-box substitution
            hi, lo = reverse_substitute_block_128(hi, lo, self.inv_sbox_array)

        return combine_block_128(hi, lo)
    
    def _validate_block_size(self, block: int):
        if block < 0 or block >= (1 << self.block_size):
            raise ValueError(f"Block must be {self.block_size}-bit. Got {block.bit_length()} bits.")

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt bytes data by converting to 128-bit blocks"""
        if len(data) % 16 != 0:
            raise ValueError("Data must be padded to 16-byte (128-bit) blocks")
        
        encrypted_blocks = []
        for i in range(0, len(data), 16):
            block_bytes = data[i:i+16]
            block_int = int.from_bytes(block_bytes, byteorder='big')
            encrypted_block = self.encrypt_block(block_int)
            encrypted_blocks.append(encrypted_block.to_bytes(16, byteorder='big'))
        
        return b''.join(encrypted_blocks)

    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt bytes data by converting from 128-bit blocks"""
        if len(data) % 16 != 0:
            raise ValueError("Encrypted data must be in 16-byte (128-bit) blocks")
        
        decrypted_blocks = []
        for i in range(0, len(data), 16):
            block_bytes = data[i:i+16]
            block_int = int.from_bytes(block_bytes, byteorder='big')
            decrypted_block = self.decrypt_block(block_int)
            decrypted_blocks.append(decrypted_block.to_bytes(16, byteorder='big'))
        
        return b''.join(decrypted_blocks)