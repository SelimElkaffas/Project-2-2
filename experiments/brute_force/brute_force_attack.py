import sys
import os

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import time
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import os
from concurrent.futures import ProcessPoolExecutor
import itertools
from typing import Tuple, List, Dict
import json
from cipher.custom_cipher import CustomCipher
from cipher.key_scheduler import KeyScheduler
import hashlib

class BruteForceAnalyzer:
    def __init__(self, max_key_size: int = 32, num_rounds: int = 8):
        self.max_key_size = max_key_size  # in bits
        self.num_rounds = num_rounds
        self.results_dir = "experiment_results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Test data
        self.known_plaintext = b"Hello, World!123"  # 16 bytes (128 bits)
        self.known_ciphertext = None
        self.target_key = None
        
    def generate_test_key(self, key_size: int) -> bytes:
        """Generate a random key of specified size in bits"""
        return os.urandom(key_size // 8)
    
    def encrypt_with_key(self, key: bytes) -> bytes:
        """Encrypt known plaintext with given key"""
        cipher = CustomCipher(key=key, num_rounds=self.num_rounds)
        return cipher.encrypt_bytes(self.known_plaintext)
    
    def setup_test(self, key_size: int) -> None:
        """Setup a test case with a random key"""
        self.target_key = self.generate_test_key(key_size)
        self.known_ciphertext = self.encrypt_with_key(self.target_key)
        print(f"Test setup complete - Key size: {key_size} bits")
        print(f"Target key (hex): {self.target_key.hex()}")
    
    def try_key(self, key: bytes) -> bool:
        """Try a single key and return True if it matches"""
        try:
            result = self.encrypt_with_key(key)
            return result == self.known_ciphertext
        except Exception as e:
            print(f"Error trying key: {e}")
            return False
    
    def brute_force_worker(self, key_size: int, start_range: int, end_range: int) -> Tuple[int, float, bool]:
        """Worker function for parallel brute force attempts"""
        start_time = time.time()
        attempts = 0
        found = False
        
        # Generate keys in the assigned range
        for i in range(start_range, end_range):
            # Convert number to bytes of appropriate length
            key_bytes = i.to_bytes(key_size // 8, 'big')
            attempts += 1
            
            if self.try_key(key_bytes):
                found = True
                break
                
            # Print progress every 1000 attempts
            if attempts % 1000 == 0:
                print(f"Worker tried {attempts} keys...")
        
        end_time = time.time()
        return attempts, end_time - start_time, found
    
    def run_brute_force_test(self, key_size: int, max_attempts: int = 1000000) -> Dict:
        """Run brute force attack with specified key size"""
        print(f"\nStarting brute force test for {key_size}-bit key...")
        self.setup_test(key_size)
        
        start_time = time.time()
        total_attempts = 0
        found = False
        
        # Calculate number of workers based on CPU cores
        num_workers = os.cpu_count() or 4
        chunk_size = max_attempts // num_workers
        
        # Run parallel brute force attempts
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(num_workers)]
            futures = [executor.submit(self.brute_force_worker, key_size, start, end) 
                      for start, end in ranges]
            
            for future in futures:
                attempts, duration, key_found = future.result()
                total_attempts += attempts
                if key_found:
                    found = True
                    break
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate statistics
        attempts_per_second = total_attempts / total_time if total_time > 0 else 0
        estimated_total_time = (2 ** key_size) / attempts_per_second if attempts_per_second > 0 else float('inf')
        
        result = {
            "key_size": key_size,
            "total_attempts": total_attempts,
            "total_time": total_time,
            "attempts_per_second": attempts_per_second,
            "estimated_total_time": estimated_total_time,
            "found": found,
            "timestamp": datetime.now().isoformat()
        }
        
        print(f"\nBrute force test results for {key_size}-bit key:")
        print(f"Total attempts: {total_attempts:,}")
        print(f"Total time: {total_time:.2f} seconds")
        print(f"Attempts per second: {attempts_per_second:,.2f}")
        print(f"Estimated time for full keyspace: {self.format_time(estimated_total_time)}")
        print(f"Key found: {found}")
        
        return result
    
    def format_time(self, seconds: float) -> str:
        """Format time in a human-readable way"""
        if seconds == float('inf'):
            return "Infinite"
        
        intervals = (
            ('years', 31536000),
            ('months', 2592000),
            ('days', 86400),
            ('hours', 3600),
            ('minutes', 60),
            ('seconds', 1)
        )
        
        result = []
        for name, count in intervals:
            value = seconds // count
            if value:
                seconds -= value * count
                result.append(f"{int(value)} {name}")
        
        return ', '.join(result) if result else "0 seconds"
    
    def run_comprehensive_test(self, key_sizes: List[int] = None) -> None:
        """Run brute force tests for multiple key sizes"""
        if key_sizes is None:
            key_sizes = [8, 16, 24, 32]  # Test with smaller key sizes first
        
        results = []
        for key_size in key_sizes:
            result = self.run_brute_force_test(key_size)
            results.append(result)
            
            # Save intermediate results
            self.save_results(results)
            
            # Generate and save plot
            self.plot_results(results)
    
    def save_results(self, results: List[Dict]) -> None:
        """Save test results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.results_dir, f"brute_force_results_{timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nResults saved to {filename}")
    
    def plot_results(self, results: List[Dict]) -> None:
        """Generate and save plots of the results"""
        # Prepare data
        key_sizes = [r['key_size'] for r in results]
        times = [r['total_time'] for r in results]
        attempts = [r['total_attempts'] for r in results]
        rates = [r['attempts_per_second'] for r in results]
        
        # Create figure with subplots
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12))
        
        # Plot 1: Time vs Key Size
        ax1.plot(key_sizes, times, 'b-o', label='Actual Time')
        ax1.set_xlabel('Key Size (bits)')
        ax1.set_ylabel('Time (seconds)')
        ax1.set_title('Brute Force Attack Time vs Key Size')
        ax1.grid(True)
        ax1.legend()
        
        # Plot 2: Attempts per Second vs Key Size
        ax2.plot(key_sizes, rates, 'r-o', label='Attempts per Second')
        ax2.set_xlabel('Key Size (bits)')
        ax2.set_ylabel('Attempts per Second')
        ax2.set_title('Brute Force Attack Rate vs Key Size')
        ax2.grid(True)
        ax2.legend()
        
        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_file = os.path.join(self.results_dir, f"brute_force_analysis_{timestamp}.png")
        plt.tight_layout()
        plt.savefig(plot_file)
        plt.close()
        
        print(f"Plot saved to {plot_file}")

if __name__ == "__main__":
    # Create analyzer instance
    analyzer = BruteForceAnalyzer(max_key_size=32, num_rounds=8)
    
    # Run comprehensive test with different key sizes
    # Starting with smaller key sizes to establish baseline
    key_sizes = [8, 16, 24, 32]  # Test with 8-bit, 16-bit, 24-bit, and 32-bit keys
    analyzer.run_comprehensive_test(key_sizes) 