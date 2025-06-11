import sys
import os

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import time
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from typing import Tuple, List, Dict
import json
from cipher.custom_cipher import CustomCipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Cipher128BitAnalyzer:
    def __init__(self, num_rounds: int = 8):
        self.num_rounds = num_rounds
        self.results_dir = "128bit_results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Test data - 16 bytes for AES compatibility
        self.known_plaintext = b"Hello, World!123"  # 16 bytes exactly
        
    def generate_test_key_128(self) -> bytes:
        """Generate a random 128-bit (16 bytes) key"""
        return os.urandom(16)
    
    def encrypt_with_custom_cipher(self, key: bytes) -> bytes:
        """Encrypt plaintext with our custom cipher"""
        cipher = CustomCipher(key=key, num_rounds=self.num_rounds)
        return cipher.encrypt_bytes(self.known_plaintext)
    
    def encrypt_with_aes(self, key: bytes) -> bytes:
        """Encrypt plaintext with AES-128"""
        # Use exactly 16 bytes for AES-128
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(self.known_plaintext) + encryptor.finalize()
    
    def try_key_custom(self, key: bytes, target_ciphertext: bytes) -> bool:
        """Try a key against our custom cipher"""
        try:
            result = self.encrypt_with_custom_cipher(key)
            return result == target_ciphertext
        except Exception:
            return False
    
    def try_key_aes(self, key: bytes, target_ciphertext: bytes) -> bool:
        """Try a key against AES"""
        try:
            result = self.encrypt_with_aes(key)
            return result == target_ciphertext
        except Exception:
            return False
    
    def brute_force_worker_custom(self, start_range: int, end_range: int, target_ciphertext: bytes) -> Tuple[int, float, bool]:
        """Worker function for custom cipher brute force with 128-bit keys"""
        start_time = time.time()
        attempts = 0
        found = False
        
        for i in range(start_range, end_range):
            # Generate semi-random 128-bit key based on counter
            # This won't find the actual key, but tests performance
            key_base = i.to_bytes(8, 'big')  # 8 bytes from counter
            key_pad = b'\x00' * 8  # 8 bytes padding
            key_bytes = key_base + key_pad
            attempts += 1
            
            if self.try_key_custom(key_bytes, target_ciphertext):
                found = True
                break
                
            if attempts % 10000 == 0:
                print(f"Custom cipher worker: {attempts} keys tried...")
        
        end_time = time.time()
        return attempts, end_time - start_time, found
    
    def brute_force_worker_aes(self, start_range: int, end_range: int, target_ciphertext: bytes) -> Tuple[int, float, bool]:
        """Worker function for AES brute force with 128-bit keys"""
        start_time = time.time()
        attempts = 0
        found = False
        
        for i in range(start_range, end_range):
            # Generate semi-random 128-bit key based on counter
            key_base = i.to_bytes(8, 'big')  # 8 bytes from counter
            key_pad = b'\x00' * 8  # 8 bytes padding
            key_bytes = key_base + key_pad
            attempts += 1
            
            if self.try_key_aes(key_bytes, target_ciphertext):
                found = True
                break
                
            if attempts % 10000 == 0:
                print(f"AES worker: {attempts} keys tried...")
        
        end_time = time.time()
        return attempts, end_time - start_time, found
    
    def run_128bit_comparison_test(self, max_attempts: int = 10000000) -> Dict:
        """Run comparative brute force test with 128-bit keys"""
        print(f"\n{'='*70}")
        print(f"128-BIT KEY COMPARISON TEST")
        print(f"{'='*70}")
        print(f"Max attempts per cipher: {max_attempts:,}")
        print(f"Keyspace size: 2^128 = {2**128:,}")
        
        # Generate test key and encrypt with both ciphers
        target_key = self.generate_test_key_128()
        print(f"Target key (hex): {target_key.hex()}")
        
        custom_ciphertext = self.encrypt_with_custom_cipher(target_key)
        aes_ciphertext = self.encrypt_with_aes(target_key)
        
        print(f"Custom cipher ciphertext: {custom_ciphertext.hex()}")
        print(f"AES ciphertext: {aes_ciphertext.hex()}")
        
        # Test both ciphers
        results = {}
        
        for cipher_name, worker_func, target_ciphertext in [
            ('custom_cipher', self.brute_force_worker_custom, custom_ciphertext),
            ('aes', self.brute_force_worker_aes, aes_ciphertext)
        ]:
            print(f"\nTesting {cipher_name.upper()} with 128-bit keys...")
            start_time = time.time()
            
            # Setup parallel workers
            num_workers = os.cpu_count() or 4
            chunk_size = max_attempts // num_workers
            
            total_attempts = 0
            found = False
            
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(num_workers)]
                futures = [executor.submit(worker_func, start, end, target_ciphertext) 
                          for start, end in ranges]
                
                for future in futures:
                    attempts, duration, key_found = future.result()
                    total_attempts += attempts
                    if key_found:
                        found = True
                        break
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Calculate metrics
            attempts_per_second = total_attempts / total_time if total_time > 0 else 0
            keyspace_coverage = (total_attempts / (2**128)) * 100
            
            # Theoretical time calculations
            if attempts_per_second > 0:
                # Time to exhaust 1% of keyspace
                one_percent_time = (2**128 * 0.01) / attempts_per_second
                # Time to exhaust full keyspace  
                full_keyspace_time = (2**128) / attempts_per_second
            else:
                one_percent_time = float('inf')
                full_keyspace_time = float('inf')
            
            results[cipher_name] = {
                "key_size": 128,
                "total_attempts": total_attempts,
                "total_time": total_time,
                "attempts_per_second": attempts_per_second,
                "keyspace_coverage": keyspace_coverage,
                "one_percent_keyspace_time": one_percent_time,
                "full_keyspace_time": full_keyspace_time,
                "found": found,
                "target_key": target_key.hex(),
                "ciphertext": target_ciphertext.hex(),
                "timestamp": datetime.now().isoformat()
            }
            
            print(f"{cipher_name.upper()} Results:")
            print(f"  Attempts: {total_attempts:,}")
            print(f"  Time: {total_time:.2f}s")
            print(f"  Rate: {attempts_per_second:,.2f} keys/sec")
            print(f"  Keyspace coverage: {keyspace_coverage:.2e}%")
            print(f"  Found: {'YES' if found else 'NO'}")
            print(f"  Time for 1% keyspace: {self.format_time(one_percent_time)}")
        
        # Compare performance
        self.compare_128bit_performance(results)
        
        return results
    
    def compare_128bit_performance(self, results: Dict):
        """Compare performance between the two ciphers for 128-bit keys"""
        custom = results['custom_cipher']
        aes = results['aes']
        
        print(f"\n{'-'*50}")
        print(f"128-BIT KEY PERFORMANCE COMPARISON")
        print(f"{'-'*50}")
        
        # Speed comparison
        custom_rate = custom['attempts_per_second']
        aes_rate = aes['attempts_per_second']
        
        if aes_rate > 0 and custom_rate > 0:
            speed_ratio = aes_rate / custom_rate  # AES advantage
            print(f"AES Advantage: {speed_ratio:.2f}x faster")
        
        print(f"Custom Cipher Rate: {custom_rate:,.2f} keys/second")
        print(f"AES Rate:          {aes_rate:,.2f} keys/second")
        
        # Keyspace coverage
        print(f"\nKeyspace Coverage:")
        print(f"Custom Cipher: {custom['keyspace_coverage']:.2e}%")
        print(f"AES:          {aes['keyspace_coverage']:.2e}%")
        
        # Real-world attack scenarios
        print(f"\nReal-world Attack Time Estimates:")
        print(f"(Time to exhaust 1% of keyspace)")
        print(f"Custom Cipher: {self.format_time(custom['one_percent_keyspace_time'])}")
        print(f"AES:          {self.format_time(aes['one_percent_keyspace_time'])}")
        
        # Security assessment
        print(f"\n128-bit Key Security Assessment:")
        if custom_rate > 0:
            years_for_one_percent = custom['one_percent_keyspace_time'] / (365.25 * 24 * 3600)
            if years_for_one_percent > 1000:
                security_level = "EXTREMELY SECURE"
            elif years_for_one_percent > 100:
                security_level = "VERY SECURE"
            elif years_for_one_percent > 10:
                security_level = "SECURE"
            else:
                security_level = "MODERATE"
            
            print(f"Security Level: {security_level}")
            print(f"Years for 1% keyspace: {years_for_one_percent:.2e}")
    
    def format_time(self, seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds == float('inf') or seconds > 1e20:
            return "Practically infinite"
        
        if seconds > 1e15:  # More than ~31 million years
            years = seconds / (365.25 * 24 * 3600)
            if years > 1e9:
                return f"{years:.2e} years"
            else:
                return f"{years:,.0f} years"
        
        intervals = [
            ('years', 31557600),  # 365.25 days
            ('months', 2629800),  # 30.44 days
            ('days', 86400),
            ('hours', 3600),
            ('minutes', 60),
            ('seconds', 1)
        ]
        
        result = []
        for name, count in intervals:
            value = int(seconds // count)
            if value:
                seconds -= value * count
                result.append(f"{value} {name}")
                if len(result) >= 2:
                    break
        
        return ', '.join(result) if result else "< 1 second"
    
    def run_multiple_tests(self, num_tests: int = 3, attempts_per_test: int = 5000000):
        """Run multiple 128-bit tests for statistical accuracy"""
        print("STARTING 128-BIT CIPHER COMPARISON")
        print("="*60)
        print(f"Number of tests: {num_tests}")
        print(f"Attempts per test: {attempts_per_test:,}")
        print(f"Test date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        all_results = []
        
        for test_num in range(1, num_tests + 1):
            print(f"\n*** TEST {test_num} of {num_tests} ***")
            results = self.run_128bit_comparison_test(attempts_per_test)
            all_results.append(results)
            
            # Save intermediate results
            self.save_128bit_results(all_results, test_num)
        
        # Generate final analysis
        self.generate_128bit_analysis(all_results)
    
    def save_128bit_results(self, results: List[Dict], test_number: int):
        """Save 128-bit test results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.results_dir, f"128bit_comparison_test{test_number}_{timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nTest {test_number} results saved to: {filename}")
    
    def generate_128bit_analysis(self, all_results: List[Dict]):
        """Generate comprehensive analysis of 128-bit tests"""
        print("\n" + "="*80)
        print("COMPREHENSIVE 128-BIT ANALYSIS REPORT")
        print("="*80)
        
        # Calculate averages across all tests
        custom_rates = []
        aes_rates = []
        
        for result in all_results:
            custom_rates.append(result['custom_cipher']['attempts_per_second'])
            aes_rates.append(result['aes']['attempts_per_second'])
        
        avg_custom_rate = sum(custom_rates) / len(custom_rates)
        avg_aes_rate = sum(aes_rates) / len(aes_rates)
        
        print(f"\nAVERAGE PERFORMANCE ACROSS {len(all_results)} TESTS:")
        print(f"Custom Cipher Average: {avg_custom_rate:,.2f} keys/second")
        print(f"AES Average:          {avg_aes_rate:,.2f} keys/second")
        
        if avg_aes_rate > 0:
            performance_ratio = avg_aes_rate / avg_custom_rate
            print(f"AES Performance Advantage: {performance_ratio:.2f}x")
        
        # Calculate theoretical attack times with average performance
        keyspace_128 = 2**128
        
        custom_full_time = keyspace_128 / avg_custom_rate if avg_custom_rate > 0 else float('inf')
        aes_full_time = keyspace_128 / avg_aes_rate if avg_aes_rate > 0 else float('inf')
        
        print(f"\nTHEORETICAL FULL KEYSPACE ATTACK TIMES:")
        print(f"Custom Cipher: {self.format_time(custom_full_time)}")
        print(f"AES:          {self.format_time(aes_full_time)}")
        
        # Real-world scenarios
        print(f"\nREAL-WORLD ATTACK SCENARIOS (128-bit keys):")
        
        scenarios = [
            ("Single PC", 1),
            ("Small Botnet", 1000),
            ("Large Botnet", 1000000),
            ("Supercomputer", 1000000000),
            ("Global Network", 1000000000000)
        ]
        
        for scenario_name, multiplier in scenarios:
            boosted_custom = avg_custom_rate * multiplier
            boosted_aes = avg_aes_rate * multiplier
            
            # Time for 50% probability (half keyspace)
            custom_50_time = (keyspace_128 / 2) / boosted_custom if boosted_custom > 0 else float('inf')
            aes_50_time = (keyspace_128 / 2) / boosted_aes if boosted_aes > 0 else float('inf')
            
            print(f"\n{scenario_name}:")
            print(f"  Custom Cipher (50% probability): {self.format_time(custom_50_time)}")
            print(f"  AES (50% probability):          {self.format_time(aes_50_time)}")
        
        # Security recommendations
        print(f"\nSECURITY ASSESSMENT:")
        print("128-bit keys provide EXCELLENT security for both algorithms")
        print("Even with nation-state resources, brute force attacks are impractical")
        print("Performance differences become irrelevant at this security level")
        
        # Generate visualization
        self.generate_128bit_plots(all_results)
    
    def generate_128bit_plots(self, all_results: List[Dict]):
        """Generate plots for 128-bit analysis"""
        # Extract data
        test_numbers = list(range(1, len(all_results) + 1))
        custom_rates = [r['custom_cipher']['attempts_per_second'] for r in all_results]
        aes_rates = [r['aes']['attempts_per_second'] for r in all_results]
        
        # Create plots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Plot 1: Performance comparison across tests
        x = np.arange(len(test_numbers))
        width = 0.35
        
        ax1.bar(x - width/2, custom_rates, width, label='Custom Cipher', alpha=0.8, color='blue')
        ax1.bar(x + width/2, aes_rates, width, label='AES', alpha=0.8, color='red')
        ax1.set_xlabel('Test Number')
        ax1.set_ylabel('Attack Rate (keys/second)')
        ax1.set_title('128-bit Key Attack Rate Comparison')
        ax1.set_xticks(x)
        ax1.set_xticklabels(test_numbers)
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Performance ratio
        ratios = [aes / custom if custom > 0 else 0 for aes, custom in zip(aes_rates, custom_rates)]
        avg_ratio = sum(ratios) / len(ratios) if ratios else 0
        
        ax2.bar(test_numbers, ratios, alpha=0.7, color='green')
        ax2.axhline(y=avg_ratio, color='red', linestyle='--', 
                   label=f'Average: {avg_ratio:.2f}x')
        ax2.set_xlabel('Test Number')
        ax2.set_ylabel('AES/Custom Speed Ratio')
        ax2.set_title('AES Performance Advantage (128-bit)')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_file = os.path.join(self.results_dir, f"128bit_analysis_{timestamp}.png")
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"\n128-bit analysis plot saved to: {plot_file}")

if __name__ == "__main__":
    # Create analyzer and run 128-bit comparison
    analyzer = Cipher128BitAnalyzer(num_rounds=8)
    
    # Run multiple tests for statistical accuracy
    analyzer.run_multiple_tests(num_tests=3, attempts_per_test=5000000) 