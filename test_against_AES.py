import time
from cipher.custom_cipher import CustomCipher 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import matplotlib.pyplot as plt
import numpy as np

# Setup for AES
def aes_encrypt_decrypt_block(key: bytes, data: bytes):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return encrypted, decrypted

# Setup for CustomCipher (reuse earlier implementation)
def custom_cipher_encrypt_decrypt_block(cipher: CustomCipher, block: int):
    encrypted = cipher.encrypt_block(block)
    decrypted = cipher.decrypt_block(encrypted)
    return encrypted, decrypted

# Setup for ChaCha20
def chacha20_encrypt_decrypt_block(key: bytes, nonce: bytes, data: bytes):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return encrypted, decrypted

# Setup for Triple DES
def triple_des_encrypt_decrypt_block(key: bytes, data: bytes):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return encrypted, decrypted

# Setup for Blowfish
def blowfish_encrypt_decrypt_block(key: bytes, data: bytes):
    cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return encrypted, decrypted

# Measure performance
def benchmark_encryption(cycles=10000):
    results = {}

    # AES-128 Setup
    aes_key = os.urandom(16)  # 128-bit key
    aes_data = os.urandom(16)  # 128-bit block

    # AES-256 Setup
    aes_key_256 = os.urandom(32)  # 256-bit key

    # ChaCha20 Setup
    chacha_key = os.urandom(32)  # 256-bit key
    chacha_nonce = os.urandom(16)  # 128-bit nonce

    # Triple DES Setup
    triple_des_key = os.urandom(24)  # 192-bit key

    # Blowfish Setup
    blowfish_key = os.urandom(16)  # 128-bit key

    # CustomCipher Setup
    session_key = "deadbeef"  # 64-bit hex str for simplicity
    cipher = CustomCipher(key=session_key)
    block = int.from_bytes(aes_data[:8], 'big')  # Convert 64-bit block for CustomCipher

    # Benchmark AES-128
    start = time.time()
    for _ in range(cycles):
        aes_encrypt_decrypt_block(aes_key, aes_data)
    end = time.time()
    total_time = end - start
    results['AES-128'] = total_time
    print(f"AES-128: Total Time = {total_time:.6f}s, Average Time per Cycle = {total_time / cycles:.6f}s")

    # Benchmark AES-256
    start = time.time()
    for _ in range(cycles):
        aes_encrypt_decrypt_block(aes_key_256, aes_data)
    end = time.time()
    total_time = end - start
    results['AES-256'] = total_time
    print(f"AES-256: Total Time = {total_time:.6f}s, Average Time per Cycle = {total_time / cycles:.6f}s")

    # Benchmark ChaCha20
    start = time.time()
    for _ in range(cycles):
        chacha20_encrypt_decrypt_block(chacha_key, chacha_nonce, aes_data)
    end = time.time()
    total_time = end - start
    results['ChaCha20'] = total_time
    print(f"ChaCha20: Total Time = {total_time:.6f}s, Average Time per Cycle = {total_time / cycles:.6f}s")

    # Benchmark Triple DES
    start = time.time()
    for _ in range(cycles):
        triple_des_encrypt_decrypt_block(triple_des_key, aes_data)
    end = time.time()
    total_time = end - start
    results['Triple DES'] = total_time
    print(f"Triple DES: Total Time = {total_time:.6f}s, Average Time per Cycle = {total_time / cycles:.6f}s")

    # Benchmark Blowfish
    start = time.time()
    for _ in range(cycles):
        blowfish_encrypt_decrypt_block(blowfish_key, aes_data)
    end = time.time()
    total_time = end - start
    results['Blowfish'] = total_time
    print(f"Blowfish: Total Time = {total_time:.6f}s, Average Time per Cycle = {total_time / cycles:.6f}s")

    # Benchmark CustomCipher
    start = time.time()
    for _ in range(cycles):
        custom_cipher_encrypt_decrypt_block(cipher, block)
    end = time.time()
    total_time = end - start
    results['CustomCipher'] = total_time
    print(f"CustomCipher: Total Time = {total_time:.6f}s, Average Time per Cycle = {total_time / cycles:.6f}s")

    return results

# Run benchmark
benchmark_results = benchmark_encryption()

# Plotting the results
labels = list(benchmark_results.keys())
times = [benchmark_results[label] for label in labels]

plt.figure(figsize=(8, 5))
plt.bar(labels, times, edgecolor='black')
plt.title("Encryption/Decryption Performance Comparison (10000 Cycles)")
plt.ylabel("Time (seconds)")
plt.xlabel("Cipher Type")
plt.grid(axis='y')
plt.tight_layout()
plt.show()
