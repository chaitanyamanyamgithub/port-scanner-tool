#!/usr/bin/env python3
"""
Advanced Port Scanner Web Application
Professional network security tool for port scanning and service discovery
"""

import os
import socket
import json
import datetime
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# Configuration
MAX_THREADS = 50
SCAN_TIMEOUT = 3
MAX_PORT_RANGE = 1000  # Limit port range for performance

# Common services mapping
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 
    995: "POP3S", 3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 1433: "MSSQL", 1521: "Oracle",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"
}

def validate_target(target):
    """Validate if target is a valid IP or hostname"""
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(target)
        return True
    except:
        # Check if it's a valid hostname
        if re.match(r'^[a-zA-Z0-9.-]+$', target) and len(target) <= 255:
            return True
        return False

def validate_port_range(start_port, end_port):
    """Validate port range"""
    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        return False
    if start_port > end_port:
        return False
    if (end_port - start_port + 1) > MAX_PORT_RANGE:
        return False
    return True

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_service():
    """Port scanning endpoint"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        port = int(data.get('port', 80))
        
        # Validate inputs
        if not validate_target(target):
            return jsonify({
                'error': 'Invalid target. Please provide a valid IP address or hostname.'
            }), 400
        
        if not (1 <= port <= 65535):
            return jsonify({
                'error': 'Port must be between 1 and 65535.'
            }), 400
        
        # Perform port scan
        result = scan_port(target, port)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/api/range-scan', methods=['POST'])
def range_scan():
    """Port range scanning endpoint"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        start_port = int(data.get('start_port', 1))
        end_port = int(data.get('end_port', 100))
        
        # Validate inputs
        if not validate_target(target):
            return jsonify({
                'error': 'Invalid target. Please provide a valid IP address or hostname.'
            }), 400
        
        if not validate_port_range(start_port, end_port):
            return jsonify({
                'error': f'Invalid port range. Must be 1-65535 and max range of {MAX_PORT_RANGE} ports.'
            }), 400
        
        # Perform range scan
        results = scan_port_range(target, start_port, end_port)
        return jsonify({
            'target': target,
            'start_port': start_port,
            'end_port': end_port,
            'timestamp': datetime.datetime.now().isoformat(),
            'results': results,
            'summary': {
                'total_scanned': len(results),
                'open_ports': sum(1 for r in results if r['status'] == 'Open'),
                'closed_ports': sum(1 for r in results if r['status'] == 'Closed'),
                'filtered_ports': sum(1 for r in results if r['status'] == 'Filtered')
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Range scan failed: {str(e)}'}), 500

@app.route('/api/quick-scan', methods=['POST'])
def quick_scan():
    """Quick scan of common ports"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not validate_target(target):
            return jsonify({
                'error': 'Invalid target. Please provide a valid IP address or hostname.'
            }), 400
        
        # Scan common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080]
        results = scan_port_range_threaded(target, common_ports)
        
        return jsonify({
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'results': results,
            'summary': {
                'total_checked': len(results),
                'open_ports': sum(1 for r in results if r['status'] == 'Open'),
                'closed_ports': sum(1 for r in results if r['status'] == 'Closed')
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Quick scan failed: {str(e)}'}), 500

def scan_port(target, port, timeout=SCAN_TIMEOUT):
    """Scan a single port"""
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((target, port))
        sock.close()
        
        response_time = (time.time() - start_time) * 1000
        
        if result == 0:
            status = "Open"
            service = SERVICES.get(port, "Unknown")
        else:
            status = "Closed"
            service = "N/A"
        
        return {
            'port': port,
            'status': status,
            'service': service,
            'response_time': f"{response_time:.1f}ms",
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
        }
        
    except socket.timeout:
        return {
            'port': port,
            'status': 'Filtered',
            'service': 'N/A',
            'response_time': 'Timeout',
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        return {
            'port': port,
            'status': 'Error',
            'service': 'N/A',
            'response_time': 'N/A',
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'error': str(e)
        }

def scan_port_range(target, start_port, end_port):
    """Scan a range of ports sequentially"""
    results = []
    for port in range(start_port, end_port + 1):
        result = scan_port(target, port)
        results.append(result)
        time.sleep(0.01)  # Small delay to prevent overwhelming
    return results

def scan_port_range_threaded(target, ports):
    """Scan multiple ports using threading"""
    results = []
    
    def scan_worker(port):
        return scan_port(target, port)
    
    with ThreadPoolExecutor(max_workers=min(MAX_THREADS, len(ports))) as executor:
        future_results = executor.map(scan_worker, ports)
        results = list(future_results)
    
    return results

def check_port(target, port, timeout=SCAN_TIMEOUT):
    """Legacy function for backward compatibility"""
    return scan_port(target, port, timeout)

@app.route('/api/info')
def app_info():
    """Application information"""
    return jsonify({
        'name': 'Advanced Port Scanner',
        'version': '2.0.0',
        'description': 'Professional network security tool for port scanning and service discovery',
        'features': [
            'Single port scanning',
            'Port range scanning', 
            'Quick common port scan',
            'Service identification',
            'Response time measurement',
            'Multi-threaded scanning',
            'Professional reporting'
        ],
        'capabilities': [
            'Scan any valid IP or hostname',
            'Full port range (1-65535)',
            'Configurable timeouts',
            'Concurrent scanning',
            'Real-time results'
        ],
        'max_port_range': MAX_PORT_RANGE,
        'max_threads': MAX_THREADS,
        'default_timeout': SCAN_TIMEOUT
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
