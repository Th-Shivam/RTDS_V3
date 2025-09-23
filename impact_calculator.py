#!/usr/bin/env python3

import psutil
import time
import json
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Dict, List, Optional

class ImpactCalculator:
    """
    System Impact Calculator for RTDS
    Calculates and tracks system performance impact during attacks
    """
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        
        # Baseline metrics (normal system state)
        self.baseline_metrics = {
            'cpu_percent': 0.0,
            'memory_percent': 0.0,
            'network_io': {'bytes_sent': 0, 'bytes_recv': 0},
            'disk_io': {'read_bytes': 0, 'write_bytes': 0},
            'connections': 0,
            'load_avg': 0.0
        }
        
        # Current metrics
        self.current_metrics = {}
        
        # Impact history (last 100 measurements)
        self.impact_history = deque(maxlen=100)
        
        # Attack impact tracking
        self.attack_impacts = {}  # {attack_id: impact_data}
        
        # Performance thresholds
        self.thresholds = {
            'cpu_critical': 80.0,
            'memory_critical': 85.0,
            'network_critical': 100 * 1024 * 1024,  # 100MB/s
            'connections_critical': 1000
        }
        
        # Initialize baseline
        self._establish_baseline()
    
    def _establish_baseline(self):
        """Establish baseline system metrics"""
        try:
            # Take multiple samples for accurate baseline
            samples = []
            for _ in range(5):
                sample = self._get_system_metrics()
                samples.append(sample)
                time.sleep(1)
            
            # Calculate average baseline
            self.baseline_metrics = {
                'cpu_percent': sum(s['cpu_percent'] for s in samples) / len(samples),
                'memory_percent': sum(s['memory_percent'] for s in samples) / len(samples),
                'network_io': {
                    'bytes_sent': sum(s['network_io']['bytes_sent'] for s in samples) / len(samples),
                    'bytes_recv': sum(s['network_io']['bytes_recv'] for s in samples) / len(samples)
                },
                'disk_io': {
                    'read_bytes': sum(s['disk_io']['read_bytes'] for s in samples) / len(samples),
                    'write_bytes': sum(s['disk_io']['write_bytes'] for s in samples) / len(samples)
                },
                'connections': sum(s['connections'] for s in samples) / len(samples),
                'load_avg': sum(s['load_avg'] for s in samples) / len(samples)
            }
            
            if self.log_callback:
                self.log_callback("✅ Baseline metrics established", "IMPACT_CALC")
                
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Failed to establish baseline: {e}", "IMPACT_CALC")
    
    def _get_system_metrics(self) -> Dict:
        """Get current system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Network I/O
            network_io = psutil.net_io_counters()
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            
            # Network connections
            connections = len(psutil.net_connections())
            
            # Load average
            load_avg = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
            
            return {
                'timestamp': time.time(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'network_io': {
                    'bytes_sent': network_io.bytes_sent,
                    'bytes_recv': network_io.bytes_recv
                },
                'disk_io': {
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0
                },
                'connections': connections,
                'load_avg': load_avg
            }
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error getting system metrics: {e}", "IMPACT_CALC")
            return {}
    
    def calculate_impact(self, attack_type: str = "Unknown") -> Dict:
        """Calculate current system impact"""
        self.current_metrics = self._get_system_metrics()
        
        if not self.current_metrics:
            return {}
        
        # Calculate impact percentages
        impact = {
            'timestamp': self.current_metrics['timestamp'],
            'attack_type': attack_type,
            'cpu_impact': max(0, self.current_metrics['cpu_percent'] - self.baseline_metrics['cpu_percent']),
            'memory_impact': max(0, self.current_metrics['memory_percent'] - self.baseline_metrics['memory_percent']),
            'network_impact': {
                'sent_increase': max(0, self.current_metrics['network_io']['bytes_sent'] - self.baseline_metrics['network_io']['bytes_sent']),
                'recv_increase': max(0, self.current_metrics['network_io']['bytes_recv'] - self.baseline_metrics['network_io']['bytes_recv'])
            },
            'connections_impact': max(0, self.current_metrics['connections'] - self.baseline_metrics['connections']),
            'load_impact': max(0, self.current_metrics['load_avg'] - self.baseline_metrics['load_avg']),
            'severity': 'LOW'
        }
        
        # Calculate overall severity
        impact['severity'] = self._calculate_severity(impact)
        
        # Calculate impact score (0-100)
        impact['impact_score'] = self._calculate_impact_score(impact)
        
        # Add to history
        self.impact_history.append(impact)
        
        return impact
    
    def _calculate_severity(self, impact: Dict) -> str:
        """Calculate impact severity level"""
        cpu_impact = impact['cpu_impact']
        memory_impact = impact['memory_impact']
        connections_impact = impact['connections_impact']
        
        # Critical thresholds
        if (cpu_impact > 50 or memory_impact > 40 or connections_impact > 500):
            return 'CRITICAL'
        elif (cpu_impact > 30 or memory_impact > 25 or connections_impact > 200):
            return 'HIGH'
        elif (cpu_impact > 15 or memory_impact > 15 or connections_impact > 50):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_impact_score(self, impact: Dict) -> float:
        """Calculate overall impact score (0-100)"""
        # Weighted scoring
        cpu_score = min(100, (impact['cpu_impact'] / 50) * 40)  # 40% weight
        memory_score = min(100, (impact['memory_impact'] / 40) * 30)  # 30% weight
        connections_score = min(100, (impact['connections_impact'] / 500) * 20)  # 20% weight
        load_score = min(100, (impact['load_impact'] / 5) * 10)  # 10% weight
        
        total_score = cpu_score + memory_score + connections_score + load_score
        return round(total_score, 2)
    
    def start_attack_tracking(self, attack_id: str, attack_type: str) -> str:
        """Start tracking impact for a specific attack"""
        self.attack_impacts[attack_id] = {
            'attack_type': attack_type,
            'start_time': time.time(),
            'start_metrics': self.current_metrics.copy(),
            'peak_impact': {},
            'total_impact': {},
            'duration': 0,
            'samples': []
        }
        
        if self.log_callback:
            self.log_callback(f"📊 Started impact tracking for {attack_type} attack: {attack_id}", "IMPACT_TRACKING")
        
        return attack_id
    
    def update_attack_impact(self, attack_id: str):
        """Update impact metrics for ongoing attack"""
        if attack_id not in self.attack_impacts:
            return
        
        current_impact = self.calculate_impact(self.attack_impacts[attack_id]['attack_type'])
        self.attack_impacts[attack_id]['samples'].append(current_impact)
        
        # Update peak impact
        if not self.attack_impacts[attack_id]['peak_impact'] or current_impact['impact_score'] > self.attack_impacts[attack_id]['peak_impact'].get('impact_score', 0):
            self.attack_impacts[attack_id]['peak_impact'] = current_impact.copy()
    
    def end_attack_tracking(self, attack_id: str) -> Dict:
        """End attack tracking and calculate final impact"""
        if attack_id not in self.attack_impacts:
            return {}
        
        attack_data = self.attack_impacts[attack_id]
        attack_data['end_time'] = time.time()
        attack_data['duration'] = attack_data['end_time'] - attack_data['start_time']
        
        # Calculate total impact
        if attack_data['samples']:
            samples = attack_data['samples']
            attack_data['total_impact'] = {
                'avg_cpu_impact': sum(s['cpu_impact'] for s in samples) / len(samples),
                'avg_memory_impact': sum(s['memory_impact'] for s in samples) / len(samples),
                'avg_connections_impact': sum(s['connections_impact'] for s in samples) / len(samples),
                'avg_impact_score': sum(s['impact_score'] for s in samples) / len(samples),
                'peak_impact_score': attack_data['peak_impact'].get('impact_score', 0),
                'severity': attack_data['peak_impact'].get('severity', 'LOW')
            }
        
        if self.log_callback:
            duration_str = f"{attack_data['duration']:.1f}s"
            peak_score = attack_data['total_impact'].get('peak_impact_score', 0)
            self.log_callback(f"📈 Attack impact summary - Duration: {duration_str}, Peak Score: {peak_score}", "IMPACT_SUMMARY")
        
        return attack_data
    
    def get_current_impact(self) -> Dict:
        """Get current system impact"""
        return self.calculate_impact()
    
    def get_impact_history(self, minutes: int = 10) -> List[Dict]:
        """Get impact history for specified minutes"""
        cutoff_time = time.time() - (minutes * 60)
        return [impact for impact in self.impact_history if impact['timestamp'] > cutoff_time]
    
    def get_impact_stats(self) -> Dict:
        """Get impact statistics"""
        if not self.impact_history:
            return {}
        
        recent_impacts = list(self.impact_history)[-20:]  # Last 20 samples
        
        return {
            'current_metrics': self.current_metrics,
            'baseline_metrics': self.baseline_metrics,
            'avg_cpu_impact': sum(i['cpu_impact'] for i in recent_impacts) / len(recent_impacts),
            'avg_memory_impact': sum(i['memory_impact'] for i in recent_impacts) / len(recent_impacts),
            'avg_impact_score': sum(i['impact_score'] for i in recent_impacts) / len(recent_impacts),
            'peak_impact_score': max(i['impact_score'] for i in recent_impacts),
            'active_attacks': len(self.attack_impacts),
            'total_samples': len(self.impact_history)
        }
    
    def get_system_health(self) -> Dict:
        """Get overall system health status"""
        current = self._get_system_metrics()
        
        health_status = "HEALTHY"
        issues = []
        
        if current['cpu_percent'] > self.thresholds['cpu_critical']:
            health_status = "CRITICAL"
            issues.append(f"High CPU usage: {current['cpu_percent']:.1f}%")
        
        if current['memory_percent'] > self.thresholds['memory_critical']:
            health_status = "CRITICAL"
            issues.append(f"High memory usage: {current['memory_percent']:.1f}%")
        
        if current['connections'] > self.thresholds['connections_critical']:
            health_status = "WARNING"
            issues.append(f"High connection count: {current['connections']}")
        
        return {
            'status': health_status,
            'issues': issues,
            'metrics': current,
            'timestamp': time.time()
        }
