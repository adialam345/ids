from flask import Flask, render_template, jsonify, request, flash
from datetime import datetime
import threading
import psutil
import logging
import json
from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw, conf, get_if_addr, get_if_list
from collections import defaultdict
import time
import subprocess
import re
import socket
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for flash messages

# Get all server IP addresses
def get_server_ips():
    server_ips = set()
    try:
        # Get hostname and primary IP
        hostname = socket.gethostname()
        server_ips.add(socket.gethostbyname(hostname))
        
        # Get all network interfaces IPs
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith('127.'):  # Skip localhost
                server_ips.add(ip)
                print(f"Found server IP: {ip}")
        
        # Try to get additional IPs using socket connections
        try:
            # Create a dummy socket to get default IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))  # Connect to Google DNS
            server_ips.add(s.getsockname()[0])
            s.close()
        except:
            pass
            
        # Use ifconfig/ip addr command as backup
        try:
            if subprocess.call("which ip > /dev/null", shell=True) == 0:
                # Linux with ip command
                result = subprocess.check_output("ip -4 addr show | grep inet", shell=True).decode()
                ips = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', result)
                for ip in ips:
                    if not ip.startswith('127.'):
                        server_ips.add(ip)
            elif subprocess.call("which ifconfig > /dev/null", shell=True) == 0:
                # Linux/Unix with ifconfig
                result = subprocess.check_output("ifconfig | grep 'inet '", shell=True).decode()
                ips = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', result)
                for ip in ips:
                    if not ip.startswith('127.'):
                        server_ips.add(ip)
        except:
            pass
            
    except Exception as e:
        logging.error(f"Error getting server IPs: {str(e)}")
    
    return server_ips

# Get server IPs and store them
SERVER_IPS = get_server_ips()
print(f"\nServer IPs detected: {SERVER_IPS}")

# Global variables to store IDS data
network_stats = defaultdict(int)
suspicious_ips = set()
alerts = []
firewall_rules = []
MAX_ALERTS = 1000

# Enhanced sensitivity thresholds
PING_FLOOD_THRESHOLD = 3     # Detect after 3 pings per minute
PORT_SCAN_THRESHOLD = 5      # Detect after 5 different ports
SYN_FLOOD_THRESHOLD = 10     # Detect after 10 SYN packets
TRAFFIC_THRESHOLD = 50       # Packets per minute
ICMP_SIZE_THRESHOLD = 1000   # Detect large ICMP packets

# Common ports used in scanning
COMMON_SCAN_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
}

# Tracking dictionaries
ping_counts = defaultdict(lambda: {'count': 0, 'last_reset': datetime.now(), 'types': set()})
port_scan_counts = defaultdict(lambda: {'ports': set(), 'last_reset': datetime.now(), 'scan_type': ''})
syn_flood_counts = defaultdict(lambda: {'count': 0, 'last_reset': datetime.now()})
packet_sizes = defaultdict(list)

# Known scanning tools signatures
SCAN_SIGNATURES = {
    'nmap': [b'Nmap', b'MSSP', b'SCHEDULED_SCAN'],
    'powershell': [b'Windows PowerShell', b'Test-NetConnection'],
    'ping': [b'abcdefghijklmnopqrstuvwabcdefghi'],  # Windows default ping pattern
    'zenmap': [b'ZENMAP'],
    'angry_ip': [b'AngryIP'],
    'advanced_port_scanner': [b'Advanced Port Scanner']
}

def reset_counters(ip):
    """Reset counters for an IP if a minute has passed"""
    current_time = datetime.now()
    
    # Reset ping flood counter
    if (current_time - ping_counts[ip]['last_reset']).total_seconds() >= 60:
        ping_counts[ip] = {'count': 0, 'last_reset': current_time, 'types': set()}
    
    # Reset port scan counter
    if (current_time - port_scan_counts[ip]['last_reset']).total_seconds() >= 60:
        port_scan_counts[ip] = {'ports': set(), 'last_reset': current_time, 'scan_type': ''}
    
    # Reset SYN flood counter
    if (current_time - syn_flood_counts[ip]['last_reset']).total_seconds() >= 60:
        syn_flood_counts[ip] = {'count': 0, 'last_reset': current_time}

def detect_scan_tool(packet):
    """Detect which tool is being used for scanning"""
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        
        for tool, signatures in SCAN_SIGNATURES.items():
            for sig in signatures:
                if sig in payload:
                    return tool
    
    return None

def analyze_icmp_type(packet):
    """Analyze ICMP packet types and sizes"""
    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        
        type_descriptions = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request (Ping)',
            13: 'Timestamp Request',
            14: 'Timestamp Reply'
        }
        
        return type_descriptions.get(icmp_type, f'Type {icmp_type}/{icmp_code}')
    return None

def detect_os_from_ttl(packet):
    """Detect OS based on TTL value"""
    if packet.haslayer(IP):
        ttl = packet[IP].ttl
        if ttl >= 250:
            return 'Solaris/AIX'
        elif ttl >= 128:
            return 'Windows'
        elif ttl >= 64:
            return 'Linux/Unix'
        else:
            return 'Unknown'
    return None

def add_alert(ip, alert_type, details, severity, tool=None, os=None):
    """Enhanced alert system with tool and OS detection"""
    alert = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': alert_type,
        'details': details,
        'severity': severity,
        'source_ip': ip,
        'detected_tool': tool if tool else 'Unknown',
        'source_os': os if os else 'Unknown'
    }
    alerts.append(alert)
    
    log_msg = (f'{alert_type} detected from {ip} | Tool: {alert["detected_tool"]} | '
               f'OS: {alert["source_os"]} | Details: {details}')
    logging.warning(log_msg)
    
    if len(alerts) > MAX_ALERTS:
        alerts.pop(0)

def detect_attacks(packet):
    """Enhanced attack detection with detailed analysis"""
    try:
        if not packet.haslayer(IP):
            return

        ip = packet[IP].src
        
        # Skip if the packet is from our own server
        if ip in SERVER_IPS:
            return
            
        reset_counters(ip)
        
        # Tool and OS Detection
        scan_tool = detect_scan_tool(packet)
        source_os = detect_os_from_ttl(packet)

        # ICMP Analysis (Including Ping Detection)
        if packet.haslayer(ICMP):
            icmp_type = analyze_icmp_type(packet)
            ping_counts[ip]['count'] += 1
            ping_counts[ip]['types'].add(icmp_type)
            
            # Detect ping activity (very sensitive)
            if ping_counts[ip]['count'] >= PING_FLOOD_THRESHOLD:
                details = (f"ICMP Activity: {ping_counts[ip]['count']} packets/min | "
                         f"Types: {', '.join(ping_counts[ip]['types'])}")
                add_alert(ip, 'ICMP Activity', details, 'Medium', scan_tool, source_os)
                suspicious_ips.add(ip)
            
            # Large ICMP packet detection
            if len(packet) > ICMP_SIZE_THRESHOLD:
                add_alert(ip, 'Large ICMP Packet', 
                         f'Size: {len(packet)} bytes', 'High', 
                         scan_tool, source_os)

        # Enhanced Port Scan Detection
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            proto = 'TCP' if packet.haslayer(TCP) else 'UDP'
            dst_port = packet[TCP].dport if proto == 'TCP' else packet[UDP].dport
            port_scan_counts[ip]['ports'].add(dst_port)
            
            # Check if scanning common service ports
            if dst_port in COMMON_SCAN_PORTS:
                service = COMMON_SCAN_PORTS[dst_port]
                add_alert(ip, 'Service Probe', 
                         f'{proto} scan on {service} port ({dst_port})', 
                         'High', scan_tool, source_os)

            # Detect port scanning (very sensitive)
            if len(port_scan_counts[ip]['ports']) >= PORT_SCAN_THRESHOLD:
                ports_str = ', '.join(map(str, sorted(port_scan_counts[ip]['ports'])))
                add_alert(ip, 'Port Scan', 
                         f'{proto} scan on ports: {ports_str}', 
                         'High', scan_tool, source_os)
                suspicious_ips.add(ip)

        # Enhanced SYN Scan Detection
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN flag
                syn_flood_counts[ip]['count'] += 1
                if syn_flood_counts[ip]['count'] >= SYN_FLOOD_THRESHOLD:
                    add_alert(ip, 'SYN Scan', 
                             f'SYN packets: {syn_flood_counts[ip]["count"]}/min', 
                             'High', scan_tool, source_os)
                    suspicious_ips.add(ip)

            # Detect other TCP scan types
            if flags & 0x01:  # FIN
                add_alert(ip, 'FIN Scan', 'FIN packet detected', 'High', scan_tool, source_os)
            elif flags & 0x3F == 0:  # NULL
                add_alert(ip, 'NULL Scan', 'NULL packet detected', 'High', scan_tool, source_os)
            elif flags & 0x3F == 0x3F:  # XMAS
                add_alert(ip, 'XMAS Scan', 'XMAS packet detected', 'High', scan_tool, source_os)

        # Traffic Analysis
        network_stats[ip] += 1
        if network_stats[ip] > TRAFFIC_THRESHOLD:
            add_alert(ip, 'High Traffic', 
                     f'Traffic rate: {network_stats[ip]} packets/min', 
                     'Medium', scan_tool, source_os)

    except Exception as e:
        logging.error(f'Error in attack detection: {str(e)}')

def analyze_packet(packet):
    """Main packet analysis function"""
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip not in SERVER_IPS:  # Only analyze if not from server
                detect_attacks(packet)
    except Exception as e:
        logging.error(f'Error analyzing packet: {str(e)}')

def start_packet_capture():
    """Start capturing network packets"""
    try:
        print("\n[*] Starting packet capture...")
        print(f"[*] Server IPs (traffic from these IPs will be ignored): {SERVER_IPS}")
        sniff(prn=analyze_packet, store=0)
    except Exception as e:
        logging.error(f'Error in packet capture: {str(e)}')
        print(f"\n[!] Error in packet capture: {str(e)}")

def execute_command(command):
    """Execute a system command and return the output"""
    try:
        # Add sudo if command is iptables
        if command.startswith('iptables'):
            command = f'sudo {command}'
            
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Check if command not found
        if 'command not found' in result.stderr or 'not found' in result.stderr:
            if 'iptables' in command:
                return {
                    'success': False,
                    'output': 'Firewall command failed. Please ensure iptables is installed: sudo apt-get install iptables'
                }
            return {
                'success': False,
                'output': f'Command not found: {result.stderr}'
            }
            
        return {
            'success': result.returncode == 0,
            'output': result.stdout if result.returncode == 0 else result.stderr
        }
    except Exception as e:
        return {'success': False, 'output': str(e)}

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
        },
        'firewall_rules': firewall_rules
    })

@app.route('/api/firewall/add', methods=['POST'])
def add_firewall_rule():
    """Add a new firewall rule"""
    try:
        data = request.json
        rule_type = data.get('type', '')
        ip = data.get('ip', '')
        port = data.get('port', '')
        
        if not ip or not rule_type:
            return jsonify({'success': False, 'message': 'Missing required parameters'})
            
        # Validate IP address format
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            return jsonify({'success': False, 'message': 'Invalid IP address format'})
            
        # Test iptables availability first
        test_result = execute_command('sudo iptables --version')
        if not test_result['success']:
            return jsonify({
                'success': False, 
                'message': 'Firewall system (iptables) is not available. Please install it first: sudo apt-get install iptables'
            })
            
        # Construct iptables command
        if rule_type == 'block':
            cmd = f'iptables -A INPUT -s {ip} -j DROP'
        elif rule_type == 'allow':
            cmd = f'iptables -A INPUT -s {ip} -j ACCEPT'
        else:
            return jsonify({'success': False, 'message': 'Invalid rule type'})
            
        # Add port if specified
        if port:
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                return jsonify({'success': False, 'message': 'Invalid port number'})
            cmd = f'{cmd} -p tcp --dport {port}'
            
        # Execute the command
        result = execute_command(cmd)
        
        if result['success']:
            firewall_rules.append({
                'type': rule_type,
                'ip': ip,
                'port': port,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            return jsonify({'success': True, 'message': 'Firewall rule added successfully'})
        else:
            return jsonify({
                'success': False, 
                'message': f'Error adding firewall rule: {result["output"]}. Make sure you have sudo privileges.'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/firewall/remove', methods=['POST'])
def remove_firewall_rule():
    """Remove a firewall rule"""
    try:
        data = request.json
        rule_type = data.get('type', '')
        ip = data.get('ip', '')
        port = data.get('port', '')
        
        if not ip or not rule_type:
            return jsonify({'success': False, 'message': 'Missing required parameters'})
            
        # Test iptables availability first
        test_result = execute_command('sudo iptables --version')
        if not test_result['success']:
            return jsonify({
                'success': False, 
                'message': 'Firewall system (iptables) is not available. Please install it first: sudo apt-get install iptables'
            })
            
        # Construct iptables command
        if rule_type == 'block':
            cmd = f'iptables -D INPUT -s {ip} -j DROP'
        elif rule_type == 'allow':
            cmd = f'iptables -D INPUT -s {ip} -j ACCEPT'
        else:
            return jsonify({'success': False, 'message': 'Invalid rule type'})
            
        # Add port if specified
        if port:
            cmd = f'{cmd} -p tcp --dport {port}'
            
        # Execute the command
        result = execute_command(cmd)
        
        if result['success']:
            # Remove rule from our list
            firewall_rules[:] = [rule for rule in firewall_rules 
                               if not (rule['ip'] == ip and rule['type'] == rule_type 
                                     and rule['port'] == port)]
            return jsonify({'success': True, 'message': 'Firewall rule removed successfully'})
        else:
            return jsonify({
                'success': False, 
                'message': f'Error removing firewall rule: {result["output"]}. Make sure you have sudo privileges.'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/command', methods=['POST'])
def execute_custom_command():
    """Execute a custom command"""
    try:
        data = request.json
        command = data.get('command', '').strip()
        
        if not command:
            return jsonify({'success': False, 'message': 'No command provided'})
            
        # Validate command (add your security checks here)
        allowed_commands = ['iptables', 'netstat', 'ps', 'who']
        if not any(command.startswith(cmd) for cmd in allowed_commands):
            return jsonify({'success': False, 'message': 'Command not allowed'})
            
        result = execute_command(command)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    print("\n[*] Starting IDS Web Interface...")
    print("[*] Please open your web browser and navigate to: http://127.0.0.1:5000")
    print("[*] Press Ctrl+C to stop the application\n")
    
    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    capture_thread.start()
    
    # Start Flask application
    app.run(host='0.0.0.0', port=5000, debug=True) 