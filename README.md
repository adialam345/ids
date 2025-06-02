# Python Web-based IDS (Intrusion Detection System)

A simple web-based Intrusion Detection System built with Python and Flask. This system monitors network traffic and system resources, providing real-time alerts and visualization through a web interface.

## Features

- Real-time network traffic monitoring
- Suspicious IP detection
- System resource monitoring (CPU and Memory usage)
- Interactive dashboard with charts and alerts
- Log management

## Requirements

- Python 3.8 or higher
- Required Python packages (listed in requirements.txt)
- Root/Administrator privileges (for packet capture)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd ids
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# OR
venv\Scripts\activate  # On Windows
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the IDS application:
```bash
sudo python app.py  # On Linux/Mac
# OR
# Run as Administrator on Windows
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Dashboard Features

- Real-time network traffic visualization
- System resource monitoring
- Suspicious IP detection and alerting
- Interactive charts and graphs
- Alert history

## Security Considerations

- Run this application in a controlled environment
- Monitor the logs regularly
- Adjust the detection thresholds in app.py as needed
- Keep all dependencies updated

## Logs

The application generates logs in `ids.log` file. Monitor this file for detailed system events and alerts.

## License

MIT License

## Note

This is a basic IDS implementation for educational purposes. For production environments, consider using established security tools and implementing additional security measures. 