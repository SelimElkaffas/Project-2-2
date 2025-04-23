from cipher.custom_cipher import CustomCipher
from utils.block_conversion import text_to_blocks, blocks_to_text

def simulate_block(cipher: CustomCipher, block: int):
    print("\n🔒 Encrypting Block:")
    print(f"  Text:     {block.to_bytes(8, 'big')}")
    print(f"  Binary:   {bin(block)[2:].zfill(64)}")

    state = block
    encrypted_jumble = []

    for round_index in range(cipher.num_rounds):
        print(f"\n-- Round {round_index + 1} --")
        
        # Substitution
        state = cipher._substitute(state)
        print(f"  After SBox: {bin(state)[2:].zfill(64)}")
        
        # Permutation
        state = cipher.pbox.permute(state)
        print(f"  After PBox: {bin(state)[2:].zfill(64)}")
        
        # Key Mixing
        round_key = cipher.key_scheduler.get_round_key(round_index)
        state ^= round_key
        print(f"  Round Key: {bin(round_key)[2:].zfill(64)}")
        print(f"  XORed:     {bin(state)[2:].zfill(64)}")
        print(f"  State HEX: {hex(state)}")
        # Convert state to text (if possible)
        try:
            text_representation = state.to_bytes(8, 'big').decode('utf-8', errors='ignore')
            print(f"  State Text: {text_representation}")
            encrypted_jumble.append(text_representation)
        except Exception as e:
            print(f"  State Text: [Non-decodable]")
            encrypted_jumble.append("[Non-decodable]")

    print("\n Encrypted Text Representation:")
    print("".join(encrypted_jumble))

    return state


def run():
    message = (
        "hello guys welcome to my youtube channel :)"
    )
    print(f"📨 Original Message:\n{message}")

    cipher = CustomCipher(key="testKey1", num_rounds=8) # You can change the key and rounds here

    # Encrypt
    blocks = text_to_blocks(message)
    encrypted_blocks = []
    for i, block in enumerate(blocks):
        print(f"\n=== BLOCK {i + 1} ===")
        encrypted = simulate_block(cipher, block)
        encrypted_blocks.append(encrypted)

    # Decrypt
    decrypted_blocks = [cipher.decrypt_block(b) for b in encrypted_blocks]
    decrypted_message = blocks_to_text(decrypted_blocks)

    print("\n✅ Final Decrypted Message:")
    print(decrypted_message)


def main():
    key = "SuperSecretKey"
    plaintext_block = 0x0123456789ABCDEF  # 64-bit test block

    cipher = CustomCipher(key=key)

    encrypted = cipher.encrypt_block(plaintext_block)
    decrypted = cipher.decrypt_block(encrypted)

    print(f"Plaintext block:  0x{plaintext_block:016X}")
    print(f"Encrypted block:  0x{encrypted:016X}")
    print(f"Decrypted block:  0x{decrypted:016X}")

    assert decrypted == plaintext_block, "Decryption failed! Something is broken."

if __name__ == "__main__":
    # main()
    
    run()
