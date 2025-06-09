from numba import njit, uint64, uint8
import numpy as np

# Non-Numba functions for 128-bit operations (Python handles large ints better)
def split_block_128(block):
    """Split a 128-bit block into two 64-bit halves"""
    hi = (block >> 64) & 0xFFFFFFFFFFFFFFFF
    lo = block & 0xFFFFFFFFFFFFFFFF
    return np.uint64(hi), np.uint64(lo)

def combine_block_128(hi, lo):
    """Combine two 64-bit halves into a 128-bit block"""
    return (int(hi) << 64) | int(lo)

# Numba-optimized functions for 64-bit operations
@njit
def substitute_block_64(block, sbox):
    """Apply S-box substitution to a 64-bit block (8 bytes) - Numba optimized"""
    result = uint64(0)
    for i in range(8):  # 8 bytes in 64 bits
        byte_val = (block >> (8 * i)) & 0xFF
        substituted = sbox[byte_val]
        result |= uint64(substituted) << (8 * i)
    return result

@njit
def reverse_substitute_block_64(block, inv_sbox):
    """Apply inverse S-box substitution to a 64-bit block - Numba optimized"""
    result = uint64(0)
    for i in range(8):  # 8 bytes in 64 bits
        byte_val = (block >> (8 * i)) & 0xFF
        substituted = inv_sbox[byte_val]
        result |= uint64(substituted) << (8 * i)
    return result

@njit
def apply_permutation_64(block, permutation):
    """Apply permutation to a 64-bit block - Numba optimized"""
    result = uint64(0)
    for dest in range(64):
        src = permutation[dest]
        bit = (block >> src) & 1
        result |= uint64(bit) << dest
    return result

@njit  
def inverse_permutation_64(block, inverse_permutation):
    """Apply inverse permutation to a 64-bit block - Numba optimized"""
    result = uint64(0)
    for dest in range(64):
        src = inverse_permutation[dest]
        bit = (block >> src) & 1
        result |= uint64(bit) << dest
    return result

# Python functions for 128-bit operations (calling Numba functions for 64-bit parts)
def substitute_block_128(hi, lo, sbox):
    """Apply S-box substitution to a 128-bit block split into two 64-bit parts"""
    new_hi = substitute_block_64(np.uint64(hi), sbox)
    new_lo = substitute_block_64(np.uint64(lo), sbox)

    return new_hi, new_lo

def reverse_substitute_block_128(hi, lo, inv_sbox):
    """Apply inverse S-box substitution to a 128-bit block split into two 64-bit parts"""
    new_hi = reverse_substitute_block_64(np.uint64(hi), inv_sbox)
    new_lo = reverse_substitute_block_64(np.uint64(lo), inv_sbox)

    return new_hi, new_lo

def apply_permutation_128(hi, lo, permutation):
    """Apply permutation to a 128-bit block represented as two 64-bit parts"""
    # Convert to int for bit operations, then back to numpy types
    hi_int = int(hi)
    lo_int = int(lo)
    
    result_hi = 0
    result_lo = 0
    
    for dest in range(128):
        src = permutation[dest]
        
        # Extract bit from source position
        if src < 64:
            bit = (lo_int >> src) & 1
        else:
            bit = (hi_int >> (src - 64)) & 1
        
        # Place bit in destination position
        if dest < 64:
            result_lo |= bit << dest
        else:
            result_hi |= bit << (dest - 64)
    
    return np.uint64(result_hi), np.uint64(result_lo)

def inverse_permutation_128(hi, lo, inverse_permutation):
    """Apply inverse permutation to a 128-bit block represented as two 64-bit parts"""
    # Convert to int for bit operations, then back to numpy types
    hi_int = int(hi)
    lo_int = int(lo)
    
    result_hi = 0
    result_lo = 0
    
    for dest in range(128):
        src = inverse_permutation[dest]
        
        # Extract bit from source position
        if src < 64:
            bit = (lo_int >> src) & 1
        else:
            bit = (hi_int >> (src - 64)) & 1
        
        # Place bit in destination position
        if dest < 64:
            result_lo |= bit << dest
        else:
            result_hi |= bit << (dest - 64)
    
    return np.uint64(result_hi), np.uint64(result_lo)

# Optimized permutation functions using pure Python int operations
def apply_permutation_128_optimized(hi, lo, permutation):
    """Optimized 128-bit permutation using pure Python integers"""
    # Combine into a single 128-bit value for bit extraction
    full_block = (int(hi) << 64) | int(lo)
    
    result_hi = 0
    result_lo = 0
    
    # Process in chunks for better performance
    for dest in range(128):
        src = permutation[dest]
        bit = (full_block >> src) & 1
        
        if dest < 64:
            result_lo |= bit << dest
        else:
            result_hi |= bit << (dest - 64)
    
    return np.uint64(result_hi), np.uint64(result_lo)

def inverse_permutation_128_optimized(hi, lo, inverse_permutation):
    """Optimized 128-bit inverse permutation using pure Python integers"""
    # Combine into a single 128-bit value for bit extraction
    full_block = (int(hi) << 64) | int(lo)
    
    result_hi = 0
    result_lo = 0
    
    # Process in chunks for better performance
    for dest in range(128):
        src = inverse_permutation[dest]
        bit = (full_block >> src) & 1
        
        if dest < 64:
            result_lo |= bit << dest
        else:
            result_hi |= bit << (dest - 64)
    
    return np.uint64(result_hi), np.uint64(result_lo)

@njit
def apply_permutation_128_fast(hi, lo, permutation):    
    result_hi = uint64(0)
    result_lo = uint64(0)

    for dest in range(128):
        src = permutation[dest]
        if src < 64:
            bit = (lo >> src) & 1
        else:
            bit = (hi >> (src - 64)) & 1

        if dest < 64:
            result_lo |= uint64(bit) << dest
        else:
            result_hi |= uint64(bit) << (dest - 64)

    return result_hi, result_lo

@njit
def inverse_permutation_128_fast(hi, lo, inverse_permutation):
    result_hi = uint64(0)
    result_lo = uint64(0)

    for dest in range(128):
        src = inverse_permutation[dest]
        if src < 64:
            bit = (lo >> src) & 1
        else:
            bit = (hi >> (src - 64)) & 1

        if dest < 64:
            result_lo |= uint64(bit) << dest
        else:
            result_hi |= uint64(bit) << (dest - 64)

    return result_hi, result_lo