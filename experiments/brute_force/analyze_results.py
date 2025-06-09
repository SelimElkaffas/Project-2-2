import json
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import os

class BruteForceResultsAnalyzer:
    def __init__(self, results_file):
        with open(results_file, 'r') as f:
            self.results = json.load(f)
    
    def analyze_results(self):
        """Comprehensive analysis of brute force results"""
        print("=" * 80)
        print("BRUTE FORCE ATTACK ANALYSIS REPORT")
        print("=" * 80)
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Test Cases: {len(self.results)}")
        print()
        
        # Individual test analysis
        for i, result in enumerate(self.results):
            self.analyze_single_test(result, i + 1)
        
        # Comparative analysis
        self.comparative_analysis()
        
        # Security implications
        self.security_implications()
        
        # Generate comprehensive plots
        self.generate_comprehensive_plots()
    
    def analyze_single_test(self, result, test_num):
        """Analyze a single test result"""
        print(f"TEST {test_num}: {result['key_size']}-bit Key Analysis")
        print("-" * 50)
        print(f"Key Size: {result['key_size']} bits")
        print(f"Total Keyspace: 2^{result['key_size']} = {2**result['key_size']:,} possible keys")
        print(f"Attempts Made: {result['total_attempts']:,}")
        print(f"Time Taken: {result['total_time']:.2f} seconds")
        print(f"Attack Rate: {result['attempts_per_second']:,.2f} keys/second")
        print(f"Key Found: {'YES' if result['found'] else 'NO'}")
        
        if result['found']:
            success_rate = (result['total_attempts'] / (2**result['key_size'])) * 100
            print(f"Success Rate: {success_rate:.4f}% of keyspace searched")
            print(f"Lucky Factor: Found key after {result['total_attempts']} attempts out of {2**result['key_size']} possible")
        else:
            coverage = (result['total_attempts'] / (2**result['key_size'])) * 100
            print(f"Keyspace Coverage: {coverage:.6f}%")
        
        # Time estimates
        full_time = self.format_time(result['estimated_total_time'])
        print(f"Estimated Full Keyspace Time: {full_time}")
        
        # Security assessment
        if result['key_size'] <= 16:
            security_level = "WEAK - Easily breakable"
        elif result['key_size'] <= 24:
            security_level = "MODERATE - Breakable with resources"
        elif result['key_size'] <= 32:
            security_level = "GOOD - Requires significant resources"
        else:
            security_level = "STRONG - Computationally infeasible"
        
        print(f"Security Assessment: {security_level}")
        print()
    
    def comparative_analysis(self):
        """Compare results across different key sizes"""
        print("COMPARATIVE ANALYSIS")
        print("=" * 50)
        
        key_sizes = [r['key_size'] for r in self.results]
        rates = [r['attempts_per_second'] for r in self.results]
        times = [r['estimated_total_time'] for r in self.results]
        
        print("Key Size vs Attack Rate:")
        for i, (size, rate) in enumerate(zip(key_sizes, rates)):
            print(f"  {size:2d} bits: {rate:10,.2f} keys/second")
        
        print("\nComplexity Growth Analysis:")
        for i in range(1, len(key_sizes)):
            prev_time = times[i-1]
            curr_time = times[i]
            growth_factor = curr_time / prev_time if prev_time > 0 else float('inf')
            key_diff = key_sizes[i] - key_sizes[i-1]
            theoretical_growth = 2 ** key_diff
            
            print(f"  {key_sizes[i-1]} → {key_sizes[i]} bits:")
            print(f"    Theoretical growth: {theoretical_growth:,}x")
            print(f"    Actual growth: {growth_factor:,.2f}x")
            print(f"    Efficiency: {(theoretical_growth/growth_factor)*100:.1f}%")
        
        print()
    
    def security_implications(self):
        """Analyze security implications"""
        print("SECURITY IMPLICATIONS")
        print("=" * 50)
        
        # Real-world attack scenarios
        print("Real-world Attack Scenarios:")
        print()
        
        scenarios = [
            ("Single Computer", 1, "Personal laptop/desktop"),
            ("Small Botnet", 100, "100 compromised machines"),
            ("Large Botnet", 10000, "10,000 compromised machines"),
            ("Cloud Computing", 100000, "Massive cloud resources"),
            ("Nation-State", 1000000, "Government-level resources")
        ]
        
        for scenario_name, multiplier, description in scenarios:
            print(f"{scenario_name} ({description}):")
            for result in self.results:
                if result['attempts_per_second'] > 0:
                    boosted_rate = result['attempts_per_second'] * multiplier
                    full_keyspace_time = (2 ** result['key_size']) / boosted_rate
                    formatted_time = self.format_time(full_keyspace_time)
                    
                    print(f"  {result['key_size']:2d}-bit key: {formatted_time}")
            print()
        
        # Recommendations
        print("SECURITY RECOMMENDATIONS:")
        print("-" * 30)
        print("• 8-bit keys: NEVER USE - Breakable in seconds")
        print("• 16-bit keys: NEVER USE - Breakable in minutes")
        print("• 24-bit keys: AVOID - Breakable with moderate resources")
        print("• 32-bit keys: MINIMUM for low-security applications")
        print("• 64-bit keys: RECOMMENDED for moderate security")
        print("• 128-bit keys: RECOMMENDED for high security")
        print("• 256-bit keys: RECOMMENDED for maximum security")
        print()
    
    def format_time(self, seconds):
        """Format time in human-readable format"""
        if seconds == float('inf') or seconds > 1e15:
            return "Practically infinite"
        
        intervals = [
            ('millennia', 31536000000),
            ('centuries', 3153600000),
            ('decades', 315360000),
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
                if len(result) >= 2:  # Limit to 2 most significant units
                    break
        
        return ', '.join(result) if result else "< 1 second"
    
    def generate_comprehensive_plots(self):
        """Generate comprehensive visualization plots"""
        key_sizes = [r['key_size'] for r in self.results]
        rates = [r['attempts_per_second'] for r in self.results]
        times = [r['estimated_total_time'] for r in self.results]
        found = [r['found'] for r in self.results]
        
        # Create comprehensive plot
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # Plot 1: Attack Rate vs Key Size
        colors = ['green' if f else 'red' for f in found]
        ax1.bar(key_sizes, rates, color=colors, alpha=0.7)
        ax1.set_xlabel('Key Size (bits)')
        ax1.set_ylabel('Attack Rate (keys/second)')
        ax1.set_title('Brute Force Attack Rate by Key Size')
        ax1.grid(True, alpha=0.3)
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor='green', alpha=0.7, label='Key Found'),
                          Patch(facecolor='red', alpha=0.7, label='Key Not Found')]
        ax1.legend(handles=legend_elements)
        
        # Plot 2: Time Complexity (log scale)
        valid_times = [t for t in times if t != float('inf') and t > 0]
        valid_keys = [key_sizes[i] for i, t in enumerate(times) if t != float('inf') and t > 0]
        
        ax2.semilogy(valid_keys, valid_times, 'bo-', linewidth=2, markersize=8)
        ax2.set_xlabel('Key Size (bits)')
        ax2.set_ylabel('Estimated Full Attack Time (seconds, log scale)')
        ax2.set_title('Time Complexity Growth')
        ax2.grid(True, alpha=0.3)
        
        # Plot 3: Keyspace Coverage
        coverage = []
        for result in self.results:
            if result['found']:
                coverage.append((result['total_attempts'] / (2**result['key_size'])) * 100)
            else:
                coverage.append((result['total_attempts'] / (2**result['key_size'])) * 100)
        
        ax3.bar(key_sizes, coverage, color='orange', alpha=0.7)
        ax3.set_xlabel('Key Size (bits)')
        ax3.set_ylabel('Keyspace Coverage (%)')
        ax3.set_title('Percentage of Keyspace Searched')
        ax3.set_yscale('log')
        ax3.grid(True, alpha=0.3)
        
        # Plot 4: Security Timeline
        scenarios = ['Personal PC', 'Small Botnet', 'Large Botnet', 'Cloud Resources']
        multipliers = [1, 100, 10000, 100000]
        
        for i, (scenario, mult) in enumerate(zip(scenarios, multipliers)):
            scenario_times = []
            for result in self.results:
                if result['attempts_per_second'] > 0:
                    boosted_rate = result['attempts_per_second'] * mult
                    full_time = (2 ** result['key_size']) / boosted_rate
                    scenario_times.append(full_time / 31536000)  # Convert to years
                else:
                    scenario_times.append(float('inf'))
            
            # Only plot finite values
            finite_times = [t for t in scenario_times if t != float('inf') and t > 0]
            finite_keys = [key_sizes[j] for j, t in enumerate(scenario_times) if t != float('inf') and t > 0]
            
            if finite_times:
                ax4.semilogy(finite_keys, finite_times, 'o-', label=scenario, linewidth=2, markersize=6)
        
        ax4.set_xlabel('Key Size (bits)')
        ax4.set_ylabel('Attack Time (years, log scale)')
        ax4.set_title('Attack Time by Scenario')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_file = f"experiment_results/comprehensive_analysis_{timestamp}.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Comprehensive analysis plot saved to: {plot_file}")

if __name__ == "__main__":
    # Find the latest results file
    results_dir = "experiment_results"
    json_files = [f for f in os.listdir(results_dir) if f.startswith("brute_force_results_") and f.endswith(".json")]
    
    if not json_files:
        print("No results files found!")
        exit(1)
    
    # Get the latest file
    latest_file = max(json_files, key=lambda x: os.path.getctime(os.path.join(results_dir, x)))
    results_path = os.path.join(results_dir, latest_file)
    
    print(f"Analyzing results from: {results_path}")
    print()
    
    # Analyze results
    analyzer = BruteForceResultsAnalyzer(results_path)
    analyzer.analyze_results() 