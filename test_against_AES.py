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

# Setup for CustomCipher - now using proper 128-bit blocks
def custom_cipher_encrypt_decrypt_block(cipher: CustomCipher, block: int):
    encrypted = cipher.encrypt_block(block)
    decrypted = cipher.decrypt_block(encrypted)
    return encrypted, decrypted

def custom_cipher_encrypt_decrypt_bytes(cipher: CustomCipher, data: bytes):
    encrypted = cipher.encrypt_bytes(data)
    decrypted = cipher.decrypt_bytes(encrypted)
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

    # Common test data - 16 bytes (128 bits)
    test_data = os.urandom(16)

    # AES-128 Setup
    aes_key_128 = os.urandom(16)  # 128-bit key

    # AES-256 Setup
    aes_key_256 = os.urandom(32)  # 256-bit key

    # ChaCha20 Setup
    chacha_key = os.urandom(32)  # 256-bit key
    chacha_nonce = os.urandom(16)  # 128-bit nonce

    # Triple DES Setup
    triple_des_key = os.urandom(24)  # 192-bit key

    # Blowfish Setup
    blowfish_key = os.urandom(16)  # 128-bit key

    # CustomCipher Setup - now using proper 128-bit blocks
    session_key = os.urandom(32)  # Use a proper 256-bit key
    cipher = CustomCipher(key=session_key)
    
    # Convert test data to 128-bit integer for block-level testing
    block_int = int.from_bytes(test_data, 'big')

    print(f"Running {cycles} cycles of encryption/decryption...")
    print(f"Test data size: {len(test_data)} bytes ({len(test_data) * 8} bits)")
    print("-" * 60)

    # Benchmark AES-128
    start = time.time()
    for _ in range(cycles):
        aes_encrypt_decrypt_block(aes_key_128, test_data)
    end = time.time()
    total_time = end - start
    results['AES-128'] = total_time
    print(f"AES-128: Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    # Benchmark AES-256
    start = time.time()
    for _ in range(cycles):
        aes_encrypt_decrypt_block(aes_key_256, test_data)
    end = time.time()
    total_time = end - start
    results['AES-256'] = total_time
    print(f"AES-256: Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    # Benchmark ChaCha20
    start = time.time()
    for _ in range(cycles):
        chacha20_encrypt_decrypt_block(chacha_key, chacha_nonce, test_data)
    end = time.time()
    total_time = end - start
    results['ChaCha20'] = total_time
    print(f"ChaCha20: Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    # Benchmark Triple DES
    start = time.time()
    for _ in range(cycles):
        triple_des_encrypt_decrypt_block(triple_des_key, test_data)
    end = time.time()
    total_time = end - start
    results['Triple DES'] = total_time
    print(f"Triple DES: Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    # Benchmark Blowfish
    start = time.time()
    for _ in range(cycles):
        blowfish_encrypt_decrypt_block(blowfish_key, test_data)
    end = time.time()
    total_time = end - start
    results['Blowfish'] = total_time
    print(f"Blowfish: Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    # Benchmark CustomCipher (block-level)
    start = time.time()
    for _ in range(cycles):
        custom_cipher_encrypt_decrypt_block(cipher, block_int)
    end = time.time()
    total_time = end - start
    results['CustomCipher (Numba)'] = total_time
    print(f"CustomCipher: Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    # Benchmark CustomCipher (bytes-level for comparison)
    start = time.time()
    for _ in range(cycles):
        custom_cipher_encrypt_decrypt_bytes(cipher, test_data)
    end = time.time()
    total_time = end - start
    results['CustomCipher (Bytes)'] = total_time
    print(f"CustomCipher (Bytes): Total Time = {total_time:.6f}s, Average = {total_time / cycles * 1000:.3f}ms per cycle")

    return results

def test_correctness():
    """Test that encryption/decryption works correctly"""
    print("Testing correctness...")
    
    # Test data
    test_data = b"Hello, World!123"  # Exactly 16 bytes
    key = os.urandom(32)
    
    cipher = CustomCipher(key=key)
    
    # Test block-level operations
    block_int = int.from_bytes(test_data, 'big')
    encrypted_block = cipher.encrypt_block(block_int)
    decrypted_block = cipher.decrypt_block(encrypted_block)
    
    print(f"Original block:  {block_int}")
    print(f"Encrypted block: {encrypted_block}")
    print(f"Decrypted block: {decrypted_block}")
    print(f"Block test passed: {block_int == decrypted_block}")
    
    # Test bytes-level operations
    encrypted_bytes = cipher.encrypt_bytes(test_data)
    decrypted_bytes = cipher.decrypt_bytes(encrypted_bytes)
    
    print(f"Original bytes:  {test_data}")
    print(f"Decrypted bytes: {decrypted_bytes}")
    print(f"Bytes test passed: {test_data == decrypted_bytes}")
    
    return test_data == decrypted_bytes and block_int == decrypted_block

def plot_results(results):
    """Create a performance comparison chart"""
    labels = list(results.keys())
    times = [results[label] for label in labels]
    
    # Calculate throughput (blocks per second)
    cycles = 10000
    throughput = [cycles / t for t in times]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Time comparison
    bars1 = ax1.bar(labels, times, color=['#ff7f0e', '#1f77b4', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2'])
    ax1.set_title(f"Encryption/Decryption Time Comparison ({cycles} cycles)")
    ax1.set_ylabel("Time (seconds)")
    ax1.set_xlabel("Cipher Type")
    ax1.tick_params(axis='x', rotation=45)
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar, time_val in zip(bars1, times):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                f'{time_val:.3f}s', ha='center', va='bottom', fontsize=8)
    
    # Throughput comparison
    bars2 = ax2.bar(labels, throughput, color=['#ff7f0e', '#1f77b4', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2'])
    ax2.set_title("Throughput Comparison")
    ax2.set_ylabel("Operations per Second")
    ax2.set_xlabel("Cipher Type")
    ax2.tick_params(axis='x', rotation=45)
    ax2.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar, throughput_val in zip(bars2, throughput):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                f'{throughput_val:.0f}', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    # Test correctness first
    if test_correctness():
        print("\n✅ Correctness tests passed!")
        print("\n" + "="*60)
        
        # Run performance benchmark
        benchmark_results = benchmark_encryption(cycles=10000)
        
        print("\n" + "="*60)
        print("Performance Summary:")
        for cipher, time_val in sorted(benchmark_results.items(), key=lambda x: x[1]):
            ops_per_sec = 10000 / time_val
            print(f"{cipher:20}: {time_val:.6f}s ({ops_per_sec:.0f} ops/sec)")
        
        # Plot results
        plot_results(benchmark_results)
    
    else:
        print("❌ Correctness tests failed! Fix the implementation before benchmarking.")