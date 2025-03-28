# For simplicity, let’s define a small block size: 16 bytes (128 bits).
BLOCK_SIZE = 16  # 128 bits

# Example S-Box (16-byte block toy S-Box, not cryptographically strong)
S_BOX = bytes([
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
])

def simple_sub_bytes(block):
    """
    Substitute each nibble (4 bits) in the block based on S_BOX (toy example).
    block: 16 bytes
    """
    out_block = bytearray(len(block))
    for i in range(len(block)):
        # split byte into high nibble, low nibble
        high_nibble = (block[i] >> 4) & 0xF
        low_nibble = block[i] & 0xF

        # substitute each nibble
        new_high = S_BOX[high_nibble]
        new_low  = S_BOX[low_nibble]

        # recombine
        out_block[i] = ((new_high & 0xF) << 4) | (new_low & 0xF)
    return bytes(out_block)

def simple_permute_bytes(block):
    """
    Permute bytes by a fixed pattern (toy example):
    e.g., rotate all bytes to the left by 1.
    """
    return block[1:] + block[:1]

def xor_bytes(a, b):
    """ XOR two byte strings of equal length. """
    return bytes(x ^ y for x, y in zip(a, b))

def key_schedule(master_key, rounds=4):
    """
    Generate 'rounds' subkeys from master key.
    For a 16-byte master key, we’ll rotate and scramble it for each round.
    """
    subkeys = []
    current_key = master_key
    for r in range(rounds):
        # A trivial rotation for demonstration
        current_key = current_key[1:] + current_key[:1]
        subkeys.append(current_key)
    return subkeys

def encrypt_block(plaintext_block, subkeys):
    """
    Encrypt a 16-byte block with subkeys in multiple rounds of SP transformations.
    """
    state = plaintext_block
    for rnd, sk in enumerate(subkeys):
        # XOR with round key
        state = xor_bytes(state, sk)
        # SubBytes
        state = simple_sub_bytes(state)
        # Permute
        state = simple_permute_bytes(state)

    # Final round key XOR
    state = xor_bytes(state, subkeys[-1])
    return state

def decrypt_block(ciphertext_block, subkeys):
    """
    Reverse the operations: 
    - (Inverse) final round key XOR
    - Inverse of permute
    - Inverse of sub bytes
    - ...
    """
    state = xor_bytes(ciphertext_block, subkeys[-1])

    # We have to reverse each round in reverse order
    for rnd in reversed(range(len(subkeys))):
        # inverse of permute
        state = simple_permute_bytes(state[-1:] + state[:-1])  # rotate right
        # inverse of sub bytes
        state = inverse_sub_bytes(state)
        # XOR with round key
        state = xor_bytes(state, subkeys[rnd])

    return state

def inverse_sub_bytes(block):
    """
    Inverse of the simple_sub_bytes.
    We need an inverse S-Box for the nibble-based transform.
    """
    # Build inverse of S_BOX
    # S_BOX maps index -> value, so we invert value -> index
    inv_sbox = [0]*16
    for i, val in enumerate(S_BOX):
        inv_sbox[val] = i

    out_block = bytearray(len(block))
    for i in range(len(block)):
        high_nibble = (block[i] >> 4) & 0xF
        low_nibble  = block[i] & 0xF

        new_high = inv_sbox[high_nibble]
        new_low  = inv_sbox[low_nibble]

        out_block[i] = ((new_high & 0xF) << 4) | (new_low & 0xF)
    return bytes(out_block)

def pad(plaintext):
    """
    Pad plaintext to a multiple of BLOCK_SIZE using PKCS#7 style padding.
    """
    padding_len = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + bytes([padding_len]*padding_len)

def unpad(padded_data):
    """
    Remove PKCS#7 style padding.
    """
    padding_len = padded_data[-1]
    return padded_data[:-padding_len]

def custom_cipher_encrypt(plaintext, key):
    """
    Encrypt the entire plaintext (which may be multiple blocks).
    """
    subkeys = key_schedule(key, rounds=4)
    # Pad
    padded_data = pad(plaintext)
    ciphertext = b""
    # Process block by block
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i+BLOCK_SIZE]
        enc_block = encrypt_block(block, subkeys)
        ciphertext += enc_block
    return ciphertext

def custom_cipher_decrypt(ciphertext, key):
    """
    Decrypt the entire ciphertext (multiple blocks).
    """
    subkeys = key_schedule(key, rounds=4)
    plaintext_padded = b""
    # Process block by block
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        dec_block = decrypt_block(block, subkeys)
        plaintext_padded += dec_block
    # Unpad
    return unpad(plaintext_padded)