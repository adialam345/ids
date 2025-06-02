from flask import Flask, render_template, jsonify, request
from datetime import datetime
import threading
import psutil
import logging
import json
from scapy.all import sniff
from collections import defaultdict
import time

app = Flask(__name__)

# Global variables to store IDS data
network_stats = defaultdict(int)
suspicious_ips = set()
alerts = []
MAX_ALERTS = 1000

# Configure logging
logging.basicConfig(
    filename='ids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def analyze_packet(packet):
    """Analyze network packets for suspicious activity"""
    try:
        if packet.haslayer('IP'):
            # Count packets per IP
            src_ip = packet['IP'].src
            network_stats[src_ip] += 1
            
            # Simple threshold-based detection
            if network_stats[src_ip] > 100:  # Threshold for suspicious activity
                if src_ip not in suspicious_ips:
                    suspicious_ips.add(src_ip)
                    alert = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'type': 'Suspicious Traffic',
                        'details': f'High traffic from IP: {src_ip}',
                        'severity': 'High'
                    }
                    alerts.append(alert)
                    logging.warning(f'Suspicious traffic detected from {src_ip}')
                    
                    # Maintain max alerts
                    if len(alerts) > MAX_ALERTS:
                        alerts.pop(0)
    except Exception as e:
        logging.error(f'Error analyzing packet: {str(e)}')

def start_packet_capture():
    """Start capturing network packets"""
    try:
        sniff(prn=analyze_packet, store=0)
    except Exception as e:
        logging.error(f'Error in packet capture: {str(e)}')

@app.route('/')
def index():
    """Render the main dashboard"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Get current IDS statistics"""
    return jsonify({
        'network_stats': dict(network_stats),
        'suspicious_ips': list(suspicious_ips),
        'alerts': alerts[-50:],  # Return last 50 alerts
        'system_stats': {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent
        }
    })

if __name__ == '__main__':
    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    capture_thread.start()
    
    # Start Flask application
    app.run(host='0.0.0.0', port=5000, debug=True) 