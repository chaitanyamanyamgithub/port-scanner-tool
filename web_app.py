#!/usr/bin/env python3
"""
Port Scanner Web Demo - Safe for Cloud Deployment
A limited web version for demonstration purposes
"""

import os
import socket
import json
import datetime
from flask import Flask, render_template, request, jsonify
import threading
import time

app = Flask(__name__)

# Safe configuration for cloud deployment
ALLOWED_TARGETS = [
    '127.0.0.1', 
    'localhost',
    'httpbin.org',
    'google.com',
    'github.com',
    'stackoverflow.com',
    'python.org'
]

SAFE_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443]

# Common services mapping
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html', 
                         allowed_targets=ALLOWED_TARGETS,
                         safe_ports=SAFE_PORTS)

@app.route('/api/scan', methods=['POST'])
def scan_service():
    """Safe port checking endpoint"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        port = int(data.get('port', 80))
        
        # Security validations
        if target not in ALLOWED_TARGETS:
            return jsonify({
                'error': f'Target "{target}" not allowed. Only demo targets permitted.',
                'allowed_targets': ALLOWED_TARGETS
            }), 400
        
        if port not in SAFE_PORTS:
            return jsonify({
                'error': f'Port {port} not allowed. Only common service ports permitted.',
                'allowed_ports': SAFE_PORTS
            }), 400
        
        # Perform safe port check
        result = check_port(target, port)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/api/quick-scan', methods=['POST'])
def quick_scan():
    """Quick scan of common ports"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if target not in ALLOWED_TARGETS:
            return jsonify({
                'error': f'Target "{target}" not allowed.',
                'allowed_targets': ALLOWED_TARGETS
            }), 400
        
        # Scan common ports
        common_ports = [80, 443, 22, 21, 25, 53]
        results = []
        
        for port in common_ports:
            result = check_port(target, port)
            results.append(result)
            time.sleep(0.1)  # Rate limiting
        
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

def check_port(target, port, timeout=3):
    """Safe port checking function"""
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
        
    except Exception as e:
        return {
            'port': port,
            'status': 'Error',
            'service': 'N/A',
            'response_time': 'N/A',
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'error': str(e)
        }

@app.route('/api/info')
def app_info():
    """Application information"""
    return jsonify({
        'name': 'Port Scanner Demo',
        'version': '1.0.0',
        'description': 'Safe demonstration of port scanning capabilities',
        'features': [
            'Limited target scanning',
            'Common port checking',
            'Service identification',
            'Response time measurement'
        ],
        'limitations': [
            'Only predefined targets allowed',
            'Limited to common service ports',
            'Rate limited for security',
            'No raw socket operations'
        ],
        'allowed_targets': ALLOWED_TARGETS,
        'allowed_ports': SAFE_PORTS
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
