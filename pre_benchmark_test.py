#!/usr/bin/env python3
"""
Simple test to verify the cipher works before running full benchmarks
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cipher.custom_cipher import CustomCipher

def test_basic_functionality():
    """Test basic encrypt/decrypt functionality"""
    print("Testing basic functionality...")
    
    # Create cipher with a simple key
    key = b"test_key_123456789012345678901234"  # 32 bytes
    cipher = CustomCipher(key=key, num_rounds=4)  # Fewer rounds for testing
    
    # Test with a simple 128-bit block
    test_block = 0x123456789ABCDEF0FEDCBA9876543210
    print(f"Original block: 0x{test_block:032X}")
    
    try:
        # Encrypt
        encrypted = cipher.encrypt_block(test_block)
        print(f"Encrypted:      0x{encrypted:032X}")
        
        # Decrypt
        decrypted = cipher.decrypt_block(encrypted)
        print(f"Decrypted:      0x{decrypted:032X}")
        
        # Check if they match
        success = test_block == decrypted
        print(f"Test passed: {success}")
        
        if not success:
            print(f"ERROR: Original and decrypted blocks don't match!")
            print(f"Difference: 0x{test_block ^ decrypted:032X}")
        
        return success
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_bytes_functionality():
    """Test bytes-level encrypt/decrypt functionality"""
    print("\nTesting bytes functionality...")
    
    # Create cipher
    key = b"test_key_123456789012345678901234"  # 32 bytes
    cipher = CustomCipher(key=key, num_rounds=4)
    
    # Test data (must be 16 bytes for 128-bit blocks)
    test_data = b"Hello, World!123"
    print(f"Original data: {test_data}")
    
    try:
        # Encrypt
        encrypted = cipher.encrypt_bytes(test_data)
        print(f"Encrypted: {encrypted.hex()}")
        
        # Decrypt
        decrypted = cipher.decrypt_bytes(encrypted)
        print(f"Decrypted: {decrypted}")
        
        # Check if they match
        success = test_data == decrypted
        print(f"Test passed: {success}")
        
        return success
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_multiple_blocks():
    """Test with multiple different blocks"""
    print("\nTesting multiple blocks...")
    
    key = b"test_key_123456789012345678901234"
    cipher = CustomCipher(key=key, num_rounds=4)
    
    test_blocks = [
        0x0,
        0x1,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        0x123456789ABCDEF0FEDCBA9876543210,
        0xAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB,
    ]
    
    all_passed = True
    
    for i, block in enumerate(test_blocks):
        try:
            encrypted = cipher.encrypt_block(block)
            decrypted = cipher.decrypt_block(encrypted)
            passed = block == decrypted
            
            print(f"Block {i+1}: {'PASS' if passed else 'FAIL'}")
            if not passed:
                print(f"  Original:  0x{block:032X}")
                print(f"  Decrypted: 0x{decrypted:032X}")
                all_passed = False
                
        except Exception as e:
            print(f"Block {i+1}: ERROR - {e}")
            all_passed = False
    
    return all_passed

if __name__ == "__main__":
    print("Running simple tests...")
    print("=" * 50)
    
    test1 = test_basic_functionality()
    test2 = test_bytes_functionality()
    test3 = test_multiple_blocks()
    
    print("\n" + "=" * 50)
    print("Test Results:")
    print(f"Basic functionality: {'PASS' if test1 else 'FAIL'}")
    print(f"Bytes functionality: {'PASS' if test2 else 'FAIL'}")
    print(f"Multiple blocks:     {'PASS' if test3 else 'FAIL'}")
    
    overall_success = test1 and test2 and test3
    print(f"\nOverall: {'ALL TESTS PASSED' if overall_success else 'SOME TESTS FAILED'}")
    
    if overall_success:
        print("\n✅ Ready to run full benchmarks!")
    else:
        print("\n❌ Fix issues before running benchmarks!")
    
    sys.exit(0 if overall_success else 1)