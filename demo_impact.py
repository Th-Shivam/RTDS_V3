#!/usr/bin/env python3

import time
import requests
import json
from datetime import datetime

def demo_impact_calculation():
    """
    Demo script to show impact calculation functionality
    """
    print("🎯 RTDS Impact Calculation Demo")
    print("=" * 50)
    
    base_url = "http://localhost:5000/api"
    
    print("1. Checking system health...")
    try:
        response = requests.get(f"{base_url}/system-health")
        if response.status_code == 200:
            health = response.json()
            print(f"   Status: {health['status']}")
            print(f"   CPU: {health['metrics']['cpu_percent']:.1f}%")
            print(f"   Memory: {health['metrics']['memory_percent']:.1f}%")
            print(f"   Connections: {health['metrics']['connections']}")
        else:
            print("   ❌ Failed to get system health")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n2. Getting current system impact...")
    try:
        response = requests.get(f"{base_url}/system-impact")
        if response.status_code == 200:
            impact = response.json()
            print(f"   Impact Score: {impact.get('impact_score', 0)}")
            print(f"   Severity: {impact.get('severity', 'UNKNOWN')}")
            print(f"   CPU Impact: {impact.get('cpu_impact', 0):.1f}%")
            print(f"   Memory Impact: {impact.get('memory_impact', 0):.1f}%")
        else:
            print("   ❌ Failed to get impact data")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n3. Getting impact statistics...")
    try:
        response = requests.get(f"{base_url}/impact-stats")
        if response.status_code == 200:
            stats = response.json()
            print(f"   Average CPU Impact: {stats.get('avg_cpu_impact', 0):.1f}%")
            print(f"   Average Memory Impact: {stats.get('avg_memory_impact', 0):.1f}%")
            print(f"   Peak Impact Score: {stats.get('peak_impact_score', 0):.1f}")
            print(f"   Active Attacks: {stats.get('active_attacks', 0)}")
        else:
            print("   ❌ Failed to get impact stats")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n4. Getting impact history (last 5 minutes)...")
    try:
        response = requests.get(f"{base_url}/impact-history?minutes=5")
        if response.status_code == 200:
            history = response.json()
            print(f"   History entries: {len(history)}")
            if history:
                latest = history[-1]
                timestamp = datetime.fromtimestamp(latest['timestamp'])
                print(f"   Latest entry: {timestamp.strftime('%H:%M:%S')}")
                print(f"   Latest score: {latest.get('impact_score', 0):.1f}")
        else:
            print("   ❌ Failed to get impact history")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n🎉 Impact calculation demo completed!")
    print("\n💡 To see real-time impact:")
    print("   1. Open dashboard: http://localhost:5000")
    print("   2. Look for 'System Impact Analysis' section")
    print("   3. Monitor during attacks for live impact data")

if __name__ == "__main__":
    demo_impact_calculation()
