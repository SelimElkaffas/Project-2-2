from cipher.sbox import SBox
from cipher.pbox import PBox
from cipher.key_scheduler import KeyScheduler


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
            base_key=key,  # Now using bytes key directly
            num_rounds=num_rounds,
            round_key_size=self.block_size
        )

    def encrypt_block(self, block: int) -> int:
        self._validate_block_size(block)
        state = block
        for round_index in range(self.num_rounds):
            state = self._substitute(state)
            state = self.pbox.permute(state)
            round_key = self.key_scheduler.get_round_key(round_index)
            state ^= round_key
            state &= (1 << self.block_size) - 1  # Ensure state is within 128 bits
        return state

    def decrypt_block(self, block: int) -> int:
        self._validate_block_size(block)
        state = block
        for round_index in reversed(range(self.num_rounds)):
            round_key = self.key_scheduler.get_round_key(round_index)
            state ^= round_key
            state &= (1 << self.block_size) - 1  # Ensure state is within 128 bits
            state = self.pbox.inverse_permute(state)
            state = self._reverse_substitute(state)
        return state

    def _substitute(self, block: int) -> int:
        """
        Apply SBox to each byte of a 128-bit block.
        """
        result = 0
        for i in range(16):  # 16 bytes in 128 bits
            byte = (block >> (8 * i)) & 0xFF
            substituted = self.sbox.substitute(byte)
            result |= (substituted << (8 * i))
        return result

    def _reverse_substitute(self, block: int) -> int:
        """
        Apply inverse SBox to each byte of a 128-bit block.
        """
        result = 0
        for i in range(16):  # 16 bytes in 128 bits
            byte = (block >> (8 * i)) & 0xFF
            reversed_substituted = self.sbox.reverse_substitute(byte)
            result |= (reversed_substituted << (8 * i))
        return result

    def _validate_block_size(self, block: int):
        """
        Validate that the block is exactly 128 bits (16 bytes).
        """
        if block < 0 or block >= (1 << self.block_size):
            raise ValueError(f"Block must be {self.block_size}-bit (16 bytes). "
                             f"Received block of size {block.bit_length()} bits.")
