# Network Intrusion Detection System (IDS)

A real-time network intrusion detection system with web interface built using Python Flask and Scapy. This system monitors network traffic, detects potential threats, and provides firewall management capabilities.

## Features

- Real-time network traffic monitoring
- Detection of various attack types:
  - Port scanning
  - Ping floods
  - SYN floods
  - Tool detection (Nmap, PowerShell, etc.)
  - OS fingerprinting
- Web-based dashboard
- Firewall management interface
- System resource monitoring
- Command terminal interface

## Prerequisites

### For Linux:
- Python 3.11 or higher
- pip (Python package manager)
- iptables (for firewall management)
- Root/sudo privileges

### For Windows:
- Python 3.11 or higher
- pip (Python package manager)
- Administrator privileges
- Npcap or Winpcap installed

## Installation

1. Clone the repository or download the source code:
   ```bash
   git clone <repository-url>
   cd ids
   ```

2. Create and activate a virtual environment:

   For Linux:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

   For Windows:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up firewall permissions:

   For Linux:
   ```bash
   # Install iptables if not already installed
   sudo apt-get update
   sudo apt-get install -y iptables

   # Add sudo privileges for iptables (optional but recommended)
   sudo visudo -f /etc/sudoers.d/iptables
   # Add the following line (replace 'yourusername'):
   # yourusername ALL=(ALL) NOPASSWD: /sbin/iptables
   ```

   For Windows:
   - Run the application with Administrator privileges

## Running the IDS

1. Activate the virtual environment (if not already activated):

   For Linux:
   ```bash
   source venv/bin/activate
   ```

   For Windows:
   ```powershell
   .\venv\Scripts\activate
   ```

2. Run the application:

   For Linux:
   ```bash
   sudo python app.py
   ```

   For Windows (run PowerShell as Administrator):
   ```powershell
   python app.py
   ```

3. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

## Using the Web Interface

1. **Dashboard**
   - View real-time network statistics
   - Monitor system resources
   - See active alerts and suspicious IPs

2. **Firewall Management**
   - Add/remove firewall rules
   - Block/allow specific IPs
   - Configure port-specific rules

3. **Command Terminal**
   - Execute allowed network commands
   - View system status
   - Monitor network connections

## Security Considerations

1. **Access Control**
   - The web interface binds to all interfaces (0.0.0.0)
   - Implement proper access controls in production
   - Consider adding authentication

2. **Privileges**
   - The application requires elevated privileges
   - Run with minimal necessary permissions
   - Use sudo rules instead of running entire app as root

3. **Network Access**
   - Default port is 5000
   - Configure firewall to restrict access
   - Use HTTPS in production

## Troubleshooting

1. **Permission Issues**
   - Ensure proper sudo/Administrator privileges
   - Check firewall permissions
   - Verify network interface access

2. **Installation Problems**
   - Ensure Python version compatibility
   - Install system dependencies
   - Check virtual environment activation

3. **Network Capture Issues**
   - Verify Npcap/Winpcap installation (Windows)
   - Check network interface permissions
   - Ensure no conflicts with other capture tools

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

[Your License Here]

## Acknowledgments

- Flask for the web framework
- Scapy for packet capture
- Python community for various packages 