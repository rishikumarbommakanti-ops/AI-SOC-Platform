#!/usr/bin/env python3
"""
Windows Network Anomaly Detector & Auto-Remediator
Real-time detection and automatic remediation of network/system anomalies
No tickets - just auto-fixes
"""

import subprocess
import psutil
import os
from datetime import datetime

class WindowsAnomalyDetector:
    def __init__(self):
        self.remediated = []
        print("\n" + "="*70)
        print("\u2764\ufe0f WINDOWS NETWORK ANOMALY DETECTOR & AUTO-REMEDIATOR")
        print("="*70)
        print(f"\u23f0 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
    
    # ==================== SYSTEM MONITORING ====================
    
    def get_running_processes(self):
        """Get all running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                process_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'memory_mb': proc.memory_info().rss / (1024 * 1024),
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                }
                processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes
    
    def detect_suspicious_processes(self, processes):
        """Detect suspicious process behavior"""
        suspicious = []
        
        for proc in processes:
            flags = []
            
            if proc['memory_mb'] > 500:
                flags.append(f"High Memory: {proc['memory_mb']:.1f}MB")
            
            if proc['cpu_percent'] > 50:
                flags.append(f"High CPU: {proc['cpu_percent']:.1f}%")
            
            if flags:
                suspicious.append({
                    'pid': proc['pid'],
                    'name': proc['name'],
                    'anomalies': flags,
                    'severity': 'HIGH' if len(flags) > 1 else 'MEDIUM'
                })
        
        return suspicious
    
    # ==================== NETWORK MONITORING ====================
    
    def scan_network_connections(self):
        """Scan all network connections"""
        connections = []
        try:
            for conn in psutil.net_connections():
                try:
                    conn_info = {
                        'local_addr': conn.laddr.ip if conn.laddr else 'Unknown',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_addr': conn.raddr.ip if conn.raddr else 'Unknown',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                    }
                    connections.append(conn_info)
                except:
                    pass
        except PermissionError:
            print("⚠️ Need admin privileges for full network scanning")
        
        return connections
    
    def detect_suspicious_connections(self, connections):
        """Detect suspicious network connections"""
        suspicious = []
        suspicious_ports = [4444, 5555, 6666, 8888, 9999, 31337, 6129]
        
        for conn in connections:
            flags = []
            
            if conn['remote_port'] in suspicious_ports:
                flags.append(f"Suspicious Port: {conn['remote_port']}")
            
            if flags:
                suspicious.append({
                    'local': f"{conn['local_addr']}:{conn['local_port']}",
                    'remote': f"{conn['remote_addr']}:{conn['remote_port']}",
                    'status': conn['status'],
                    'anomalies': flags,
                    'severity': 'HIGH'
                })
        
        return suspicious
    
    # ==================== WIFI MONITORING ====================
    
    def scan_wifi_networks(self):
        """Scan WiFi networks and connected devices"""
        wifi_info = {'networks': [], 'devices': []}
        
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                shell=True
            )
            wifi_info['networks'] = result.stdout
            
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                shell=True
            )
            wifi_info['devices'] = result.stdout
            
        except Exception as e:
            print(f"⚠️ WiFi scanning error: {e}")
        
        return wifi_info
    
    # ==================== AUTO-REMEDIATION ====================
    
    def remediate_suspicious_process(self, proc_info):
        """Auto-kill suspicious processes"""
        try:
            result = subprocess.run(
                ['taskkill', '/PID', str(proc_info['pid']), '/F'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.remediated.append({
                    'type': 'Process Termination',
                    'target': proc_info['name'],
                    'status': '✓ TERMINATED',
                })
                return True
        except Exception as e:
            print(f"⚠️ Could not terminate process: {e}")
        return False
    
    def remediate_suspicious_connection(self, conn_info):
        """Block suspicious network connections via firewall"""
        try:
            remote_ip = conn_info['remote'].split(':')[0]
            cmd = f'netsh advfirewall firewall add rule name="Block {remote_ip}" dir=out action=block remoteip={remote_ip}'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0 or 'already exists' in result.stderr:
                self.remediated.append({
                    'type': 'Network Blocking',
                    'target': remote_ip,
                    'status': '✓ BLOCKED',
                })
                return True
        except Exception as e:
            print(f"⚠️ Could not block connection: {e}")
        return False
    
    # ==================== SCANNING & ANALYSIS ====================
    
    def run_full_scan(self):
        """Run complete system and network scan"""
        print("\n🔍 STARTING COMPREHENSIVE SCAN...")
        print("-" * 70)
        
        # 1. SYSTEM PROCESSES
        print("\n[1/3] Analyzing System Processes...")
        processes = self.get_running_processes()
        suspicious_processes = self.detect_suspicious_processes(processes)
        
        if suspicious_processes:
            print(f"🚨 Found {len(suspicious_processes)} suspicious processes:")
            for proc in suspicious_processes:
                print(f"\n  PID: {proc['pid']} | Process: {proc['name']} | Severity: {proc['severity']}")
                for anomaly in proc['anomalies']:
                    print(f"    └─ {anomaly}")
                
                if proc['severity'] == 'HIGH':
                    print(f"    🔧 Auto-remediating...")
                    if self.remediate_suspicious_process(proc):
                        print(f"    ✓ Process terminated successfully")
        else:
            print("✅ No suspicious processes detected")
        
        # 2. NETWORK CONNECTIONS
        print("\n[2/3] Analyzing Network Connections...")
        connections = self.scan_network_connections()
        suspicious_connections = self.detect_suspicious_connections(connections)
        
        if suspicious_connections:
            print(f"🚨 Found {len(suspicious_connections)} suspicious connections:")
            for conn in suspicious_connections:
                print(f"\n  Local: {conn['local']} → Remote: {conn['remote']}")
                for anomaly in conn['anomalies']:
                    print(f"    └─ {anomaly}")
                
                print(f"    🔧 Auto-remediating...")
                if self.remediate_suspicious_connection(conn):
                    print(f"    ✓ Connection blocked successfully")
        else:
            print("✅ No suspicious network connections detected")
        
        # 3. SYSTEM HEALTH
        print("\n[3/3] System Health Check...")
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        
        print(f"  CPU Usage: {cpu_percent}%")
        print(f"  Memory: {memory_info.percent}% ({memory_info.available / (1024**3):.1f}GB free)")
        
        if cpu_percent > 80:
            print(f"  ⚠️ High CPU usage detected")
        if memory_info.percent > 85:
            print(f"  ⚠️ High memory usage detected")
    
    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*70)
        print("📊 SCAN REPORT")
        print("="*70)
        
        print(f"\n✅ Anomalies Remediated: {len(self.remediated)}")
        if self.remediated:
            for remediation in self.remediated:
                print(f"\n  Type: {remediation['type']}")
                print(f"  Target: {remediation['target']}")
                print(f"  Status: {remediation['status']}")
        
        print(f"\n✨ Scan Complete!\n")


if __name__ == "__main__":
    detector = WindowsAnomalyDetector()
    detector.run_full_scan()
    detector.generate_report()
