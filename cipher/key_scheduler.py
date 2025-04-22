import hashlib

class KeyScheduler:
    def __init__(self, base_key: str, num_rounds: int = 8, round_key_size: int = 64):
        self.base_key = base_key
        self.num_rounds = num_rounds
        self.round_key_size = round_key_size
        self.round_keys = self._generate_round_keys()

    def _generate_round_keys(self) -> list:
        """
        Generate round keys from the base key using SHA-256.
        """
        keys = []
        seed = self.base_key.encode('utf-8')
        for i in range(self.num_rounds):
            # Mix the seed with the round index
            data = seed + i.to_bytes(1, 'big')
            # Generate a hash of the data
            hash_object = hashlib.sha256(data)
            hash_digest = hash_object.digest()

            # Take the first N bits as round key
            key_int = int.from_bytes(hash_digest, byteorder='big') & ((1 << self.round_key_size) -1)
            keys.append(key_int)
        return keys
    
    def get_round_key(self, round_index):
        """
        Retrieve a specific round key by index
        """
        if 0 <= round_index < self.num_rounds:
            return self.round_keys[round_index]
        else:
            raise IndexError("Round index out of range")
        