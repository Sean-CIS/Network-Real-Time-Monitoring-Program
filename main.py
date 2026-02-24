#!/usr/bin/env python3
"""Network Real-Time Monitoring Program

A full-suite network monitoring desktop application that provides:
- Real-time bandwidth monitoring per interface
- Latency/ping monitoring to configured targets
- Device discovery via ARP scanning
- Port scanning
- Live packet capture and analysis
- Threshold-based alerting with desktop notifications

Usage:
    python main.py

Requirements:
    pip install -r requirements.txt

    On Windows, install Npcap (https://npcap.com/) for packet capture.
    Some features (ARP scan, packet capture) require administrator privileges.
"""

import sys

from src.app import NetworkMonitorApp


def main():
    app = NetworkMonitorApp()
    sys.exit(app.run())


if __name__ == "__main__":
    main()
