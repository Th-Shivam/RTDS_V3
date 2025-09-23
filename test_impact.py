#!/usr/bin/env python3

import time
from impact_calculator import ImpactCalculator

def test_log_callback(message, category):
    print(f"[{category}] {message}")

def main():
    print("🧪 RTDS Impact Calculator Test")
    print("=" * 40)
    
    # Initialize impact calculator
    calculator = ImpactCalculator(log_callback=test_log_callback)
    
    print("\n1. System baseline established")
    print(f"Baseline CPU: {calculator.baseline_metrics['cpu_percent']:.1f}%")
    print(f"Baseline Memory: {calculator.baseline_metrics['memory_percent']:.1f}%")
    
    print("\n2. Testing current impact calculation...")
    impact = calculator.get_current_impact()
    print(f"Current Impact Score: {impact.get('impact_score', 0)}")
    print(f"Severity: {impact.get('severity', 'UNKNOWN')}")
    
    print("\n3. Testing attack tracking...")
    attack_id = calculator.start_attack_tracking("test_attack", "DDoS")
    
    # Simulate attack duration
    for i in range(5):
        calculator.update_attack_impact(attack_id)
        time.sleep(1)
        print(f"   Attack sample {i+1} recorded")
    
    # End attack tracking
    final_impact = calculator.end_attack_tracking(attack_id)
    print(f"\n4. Attack Summary:")
    print(f"Duration: {final_impact.get('duration', 0):.1f}s")
    print(f"Peak Impact Score: {final_impact.get('total_impact', {}).get('peak_impact_score', 0)}")
    
    print("\n5. System health check...")
    health = calculator.get_system_health()
    print(f"Health Status: {health['status']}")
    if health['issues']:
        print("Issues found:")
        for issue in health['issues']:
            print(f"  - {issue}")
    
    print("\n6. Impact statistics:")
    stats = calculator.get_impact_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            continue
        print(f"   {key}: {value}")
    
    print("\n🏁 Impact calculator test completed!")

if __name__ == "__main__":
    main()
