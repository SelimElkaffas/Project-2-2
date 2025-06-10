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
import hashlib

class CipherComparisonAnalyzer:
    def __init__(self, max_key_size: int = 32, num_rounds: int = 8):
        self.max_key_size = max_key_size
        self.num_rounds = num_rounds
        self.results_dir = "comparison_results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Test data - 16 bytes for AES compatibility
        self.known_plaintext = b"Hello, World!123"  # 16 bytes exactly
        self.test_results = {
            'custom_cipher': [],
            'aes': []
        }
        
    def generate_test_key(self, key_size: int) -> bytes:
        """Generate a random key of specified size in bits"""
        return os.urandom(key_size // 8)
    
    def encrypt_with_custom_cipher(self, key: bytes) -> bytes:
        """Encrypt plaintext with our custom cipher"""
        cipher = CustomCipher(key=key, num_rounds=self.num_rounds)
        return cipher.encrypt_bytes(self.known_plaintext)
    
    def encrypt_with_aes(self, key: bytes) -> bytes:
        """Encrypt plaintext with AES"""
        # Pad key to 16, 24, or 32 bytes for AES
        key_len = len(key)
        if key_len <= 16:
            padded_key = key.ljust(16, b'\x00')
        elif key_len <= 24:
            padded_key = key.ljust(24, b'\x00')
        else:
            padded_key = key.ljust(32, b'\x00')
        
        # Use AES in ECB mode for fair comparison (no IV)
        cipher = Cipher(algorithms.AES(padded_key), modes.ECB(), backend=default_backend())
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
    
    def brute_force_worker_custom(self, key_size: int, start_range: int, end_range: int, target_ciphertext: bytes) -> Tuple[int, float, bool]:
        """Worker function for custom cipher brute force"""
        start_time = time.time()
        attempts = 0
        found = False
        
        for i in range(start_range, end_range):
            key_bytes = i.to_bytes(key_size // 8, 'big')
            attempts += 1
            
            if self.try_key_custom(key_bytes, target_ciphertext):
                found = True
                break
                
            if attempts % 1000 == 0:
                print(f"Custom cipher worker: {attempts} keys tried...")
        
        end_time = time.time()
        return attempts, end_time - start_time, found
    
    def brute_force_worker_aes(self, key_size: int, start_range: int, end_range: int, target_ciphertext: bytes) -> Tuple[int, float, bool]:
        """Worker function for AES brute force"""
        start_time = time.time()
        attempts = 0
        found = False
        
        for i in range(start_range, end_range):
            key_bytes = i.to_bytes(key_size // 8, 'big')
            attempts += 1
            
            if self.try_key_aes(key_bytes, target_ciphertext):
                found = True
                break
                
            if attempts % 1000 == 0:
                print(f"AES worker: {attempts} keys tried...")
        
        end_time = time.time()
        return attempts, end_time - start_time, found
    
    def run_cipher_comparison_test(self, key_size: int, max_attempts: int = 1000000) -> Dict:
        """Run comparative brute force test between both ciphers"""
        print(f"\n{'='*60}")
        print(f"CIPHER COMPARISON TEST - {key_size}-bit keys")
        print(f"{'='*60}")
        
        # Generate test key and encrypt with both ciphers
        target_key = self.generate_test_key(key_size)
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
            print(f"\nTesting {cipher_name.upper()}...")
            start_time = time.time()
            
            # Setup parallel workers
            num_workers = os.cpu_count() or 4
            chunk_size = max_attempts // num_workers
            
            total_attempts = 0
            found = False
            
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(num_workers)]
                futures = [executor.submit(worker_func, key_size, start, end, target_ciphertext) 
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
            estimated_total_time = (2 ** key_size) / attempts_per_second if attempts_per_second > 0 else float('inf')
            
            results[cipher_name] = {
                "key_size": key_size,
                "total_attempts": total_attempts,
                "total_time": total_time,
                "attempts_per_second": attempts_per_second,
                "estimated_total_time": estimated_total_time,
                "found": found,
                "target_key": target_key.hex(),
                "ciphertext": target_ciphertext.hex(),
                "timestamp": datetime.now().isoformat()
            }
            
            print(f"{cipher_name.upper()} Results:")
            print(f"  Attempts: {total_attempts:,}")
            print(f"  Time: {total_time:.2f}s")
            print(f"  Rate: {attempts_per_second:,.2f} keys/sec")
            print(f"  Found: {'YES' if found else 'NO'}")
        
        # Compare performance
        self.compare_cipher_performance(results, key_size)
        
        return results
    
    def compare_cipher_performance(self, results: Dict, key_size: int):
        """Compare performance between the two ciphers"""
        custom = results['custom_cipher']
        aes = results['aes']
        
        print(f"\n{'-'*40}")
        print(f"PERFORMANCE COMPARISON - {key_size}-bit")
        print(f"{'-'*40}")
        
        # Speed comparison
        custom_rate = custom['attempts_per_second']
        aes_rate = aes['attempts_per_second']
        
        if aes_rate > 0:
            speed_ratio = custom_rate / aes_rate
            faster_cipher = "Custom" if speed_ratio > 1 else "AES"
            speed_factor = max(speed_ratio, 1/speed_ratio)
            print(f"Speed Winner: {faster_cipher} ({speed_factor:.2f}x faster)")
        
        print(f"Custom Cipher: {custom_rate:,.2f} keys/sec")
        print(f"AES:          {aes_rate:,.2f} keys/sec")
        
        # Time comparison
        custom_time = custom['estimated_total_time']
        aes_time = aes['estimated_total_time']
        
        print(f"\nEstimated Full Attack Time:")
        print(f"Custom Cipher: {self.format_time(custom_time)}")
        print(f"AES:          {self.format_time(aes_time)}")
        
        # Success rate comparison
        print(f"\nKey Recovery Success:")
        print(f"Custom Cipher: {'SUCCESS' if custom['found'] else 'FAILED'}")
        print(f"AES:          {'SUCCESS' if aes['found'] else 'FAILED'}")
    
    def format_time(self, seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds == float('inf') or seconds > 1e15:
            return "Practically infinite"
        
        intervals = [
            ('years', 31536000),
            ('months', 2592000),
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
    
    def run_comprehensive_comparison(self, key_sizes: List[int] = None):
        """Run comprehensive comparison across multiple key sizes"""
        if key_sizes is None:
            key_sizes = [8, 16, 24, 32]
        
        print("STARTING COMPREHENSIVE CIPHER COMPARISON")
        print("="*60)
        print(f"Testing key sizes: {key_sizes}")
        print(f"Test date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        all_results = []
        
        for key_size in key_sizes:
            results = self.run_cipher_comparison_test(key_size)
            all_results.append(results)
            
            # Save intermediate results
            self.save_comparison_results(all_results, key_sizes)
            
            # Generate plots
            self.generate_comparison_plots(all_results, key_sizes)
        
        # Final analysis
        self.generate_final_analysis(all_results, key_sizes)
    
    def save_comparison_results(self, results: List[Dict], key_sizes: List[int]):
        """Save comparison results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.results_dir, f"cipher_comparison_{timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nResults saved to: {filename}")
    
    def generate_comparison_plots(self, results: List[Dict], key_sizes: List[int]):
        """Generate comparative visualization plots"""
        # Extract data for plotting
        completed_tests = len(results)
        test_key_sizes = key_sizes[:completed_tests]
        
        custom_rates = []
        aes_rates = []
        custom_times = []
        aes_times = []
        
        for result in results:
            custom_rates.append(result['custom_cipher']['attempts_per_second'])
            aes_rates.append(result['aes']['attempts_per_second'])
            custom_times.append(result['custom_cipher']['estimated_total_time'])
            aes_times.append(result['aes']['estimated_total_time'])
        
        # Create comparison plots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # Plot 1: Attack Rate Comparison
        x = np.arange(len(test_key_sizes))
        width = 0.35
        
        ax1.bar(x - width/2, custom_rates, width, label='Custom Cipher', alpha=0.8, color='blue')
        ax1.bar(x + width/2, aes_rates, width, label='AES', alpha=0.8, color='red')
        ax1.set_xlabel('Key Size (bits)')
        ax1.set_ylabel('Attack Rate (keys/second)')
        ax1.set_title('Brute Force Attack Rate Comparison')
        ax1.set_xticks(x)
        ax1.set_xticklabels(test_key_sizes)
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Speed Ratio
        speed_ratios = [c/a if a > 0 else 0 for c, a in zip(custom_rates, aes_rates)]
        colors = ['green' if r > 1 else 'red' for r in speed_ratios]
        
        ax2.bar(test_key_sizes, speed_ratios, color=colors, alpha=0.7)
        ax2.axhline(y=1, color='black', linestyle='--', alpha=0.5)
        ax2.set_xlabel('Key Size (bits)')
        ax2.set_ylabel('Speed Ratio (Custom/AES)')
        ax2.set_title('Speed Ratio: Custom Cipher vs AES')
        ax2.grid(True, alpha=0.3)
        
        # Plot 3: Time Complexity (log scale)
        valid_custom_times = [t for t in custom_times if t != float('inf') and t > 0]
        valid_aes_times = [t for t in aes_times if t != float('inf') and t > 0]
        valid_sizes = test_key_sizes[:min(len(valid_custom_times), len(valid_aes_times))]
        
        if valid_sizes:
            ax3.semilogy(valid_sizes, valid_custom_times[:len(valid_sizes)], 'bo-', label='Custom Cipher', linewidth=2)
            ax3.semilogy(valid_sizes, valid_aes_times[:len(valid_sizes)], 'ro-', label='AES', linewidth=2)
            ax3.set_xlabel('Key Size (bits)')
            ax3.set_ylabel('Estimated Full Attack Time (seconds, log scale)')
            ax3.set_title('Time Complexity Comparison')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
        
        # Plot 4: Security Assessment
        security_scores = []
        for size in test_key_sizes:
            if size <= 16:
                score = 1  # Very weak
            elif size <= 24:
                score = 2  # Weak
            elif size <= 32:
                score = 3  # Moderate
            elif size <= 64:
                score = 4  # Good
            else:
                score = 5  # Strong
            security_scores.append(score)
        
        security_labels = ['Very Weak', 'Weak', 'Moderate', 'Good', 'Strong']
        colors = ['red', 'orange', 'yellow', 'lightgreen', 'green']
        
        bars = ax4.bar(test_key_sizes, security_scores, color=[colors[s-1] for s in security_scores], alpha=0.7)
        ax4.set_xlabel('Key Size (bits)')
        ax4.set_ylabel('Security Level')
        ax4.set_title('Security Assessment by Key Size')
        ax4.set_yticks(range(1, 6))
        ax4.set_yticklabels(security_labels)
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_file = os.path.join(self.results_dir, f"cipher_comparison_analysis_{timestamp}.png")
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Comparison plot saved to: {plot_file}")
    
    def generate_final_analysis(self, results: List[Dict], key_sizes: List[int]):
        """Generate final comprehensive analysis report"""
        print("\n" + "="*80)
        print("FINAL COMPARATIVE ANALYSIS REPORT")
        print("="*80)
        
        # Overall performance comparison
        total_custom_rate = sum(r['custom_cipher']['attempts_per_second'] for r in results) / len(results)
        total_aes_rate = sum(r['aes']['attempts_per_second'] for r in results) / len(results)
        
        print(f"\nOVERALL PERFORMANCE:")
        print(f"Average Custom Cipher Rate: {total_custom_rate:,.2f} keys/second")
        print(f"Average AES Rate: {total_aes_rate:,.2f} keys/second")
        
        if total_aes_rate > 0:
            overall_ratio = total_custom_rate / total_aes_rate
            winner = "Custom Cipher" if overall_ratio > 1 else "AES"
            factor = max(overall_ratio, 1/overall_ratio)
            print(f"Overall Winner: {winner} ({factor:.2f}x faster on average)")
        
        # Security comparison
        print(f"\nSECURITY ANALYSIS:")
        for i, (result, key_size) in enumerate(zip(results, key_sizes)):
            custom_found = result['custom_cipher']['found']
            aes_found = result['aes']['found']
            
            print(f"{key_size}-bit keys:")
            print(f"  Custom Cipher: {'VULNERABLE' if custom_found else 'RESISTANT'}")
            print(f"  AES:          {'VULNERABLE' if aes_found else 'RESISTANT'}")
        
        # Recommendations
        print(f"\nRECOMMENDATIONS:")
        print("1. Both ciphers show similar vulnerability patterns for small key sizes")
        print("2. Neither cipher should be used with keys smaller than 64 bits")
        print("3. Performance differences are primarily implementation-dependent")
        print("4. AES benefits from hardware acceleration on modern processors")
        print("5. Custom cipher may need optimization for production use")

if __name__ == "__main__":
    # Create analyzer and run comparison
    analyzer = CipherComparisonAnalyzer(max_key_size=32, num_rounds=8)
    
    # Run comprehensive comparison
    key_sizes = [8, 16, 24, 32]
    analyzer.run_comprehensive_comparison(key_sizes) 