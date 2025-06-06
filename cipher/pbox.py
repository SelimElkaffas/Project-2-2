class PBox:
    def __init__(self, block_size=128, permutation=None):
        self.block_size = block_size  # Ensure this matches 128 bits
        if permutation:
            if len(permutation) != block_size:
                raise ValueError("Permutation length must match block size.")
            self.permutation = permutation
        else:
            # Default permutation for 128 bits (identity map)
            self.permutation = list(range(block_size))

        # Create the inverse permutation
        self.inverse_permutation = [0] * block_size
        for i, p in enumerate(self.permutation):
            self.inverse_permutation[p] = i

    def permute(self, block):
        """Apply the permutation to a block (bit-level)."""
        return self._apply_permutation(block, self.permutation)

    def inverse_permute(self, block):
        """Reverse the permutation on a block."""
        return self._apply_permutation(block, self.inverse_permutation)

    def _apply_permutation(self, block, permutation):
        """Apply a permutation to the block."""
        block = int(block)  # Ensure block is an integer
        result = 0
        for dest, src in enumerate(permutation):
            bit = (block >> src) & 1
            result |= (bit << dest)
        return result
