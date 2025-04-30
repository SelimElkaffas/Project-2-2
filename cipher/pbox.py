class PBox:
    def __init__(self, block_size=64, permutation=None):
        self.block_size = block_size
        if permutation:
            if len(permutation) != block_size:
                raise ValueError("Permutation length must match block size.")
            self.permutation = permutation
        else:
            self.permutation = list(range(block_size))
            
        # Create the inverse permutation
        self.inverse_permutation = [0] * block_size
        for i, p in enumerate(self.permutation):
            self.inverse_permutation[p] = i

        # Create the bitmask lookup table for the permutation
        # self.bitmask_lookup = [(1 << p) for p in self.permutation]
        # self.inverse_bitmask_lookup = [(1 << p) for p in self.inverse_permutation]

    def permute(self, block):
        """Apply the permutation to a block (bit-level)."""
        return self._apply_permutation(block, self.permutation)
        
    def inverse_permute(self, block):
        """Reverese the permutation on a block."""
        return self._apply_permutation(block, self.inverse_permutation)
        
    def _apply_permutation(self, block, permutation):
        block = int(block)  # Ensure block is an integer
        result = 0
        for i, p in enumerate(permutation):
            bit = (block >> p) & 1
            result |= (bit << i)
        return result
