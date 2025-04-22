from cipher.sbox import SBox
from cipher.pbox import PBox
from cipher.key_scheduler import KeyScheduler

class CustomCipher:
    def __init__(self, key: str, num_rounds: int = 8):
        self.num_rounds = num_rounds
        self.sbox = SBox(size=256, seed=42)  # Example S-Box with a fixed seed for reproducibility
        self.pbox = PBox(block_size=64) # Example P-Box with default permutation
        self.key_scheduler = KeyScheduler(base_key=key, num_rounds=num_rounds, round_key_size=64)

    def encrypt_block(self, block: int) -> int:
        """
        Encrypt a 64-bit block using the custom cipher.
        """
        state = block
        for round_index in range(self.num_rounds):
            state = self._substitute(state)
            state = self.pbox.permute(state)
            state ^= self.key_scheduler.get_round_key(round_index)
        return state
    
    def decrypt_block(self, block: int) -> int:
        """
        Decrypt a 64-bit block using the custom cipher.
        """
        state = block
        for round_index in reversed(range(self.num_rounds)):
            state ^= self.key_scheduler.get_round_key(round_index)
            state = self.pbox.inverse_permute(state)
            state = self._reverse_substitute(state)
        return state
    
    def _substitute(self, block: int) -> int:
        """
        Apply SBox to each byte of a 64-bit block.
        """
        result = 0
        for i in range(8): # 8 bytes in a 64-bit block
            byte = (block >> (8 * i)) & 0xFF
            substituted_byte = self.sbox.substitute(byte)
            result |= (substituted_byte << (8 * i))
        return result
    
    def _reverse_substitute(self, block: int) -> int:
        """
        Apply inverse SBox to each byte of a 64-bit block.
        """
        result = 0
        for i in range(8):
            byte = (block >> (8 * i)) & 0xFF
            reversed_byte = self.sbox.reverse_substitute(byte)
            result |= (reversed_byte << (8 * i))
        return result