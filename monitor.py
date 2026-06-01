#!/usr/bin/env python3
"""
Network Monitor Module for SpySentry

This module monitors network traffic for signs of spyware/stalkerware
communication, such as connections to known C2 servers or suspicious domains.

Usage:
    monitor = NetworkMonitor(interface="eth0")
    results = monitor.monitor()

Author: Transparency-X
License: MIT
"""

import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.utils.logger import setup_logger
from src.utils.helpers import load_config


class NetworkMonitor:
    """
    A network monitor to detect spyware/stalkerware C2 traffic.
    """

    def __init__(self, interface: str = "eth0", output_dir: str = "reports", logger=None):
        """
        Initialize the Network Monitor.

        Args:
            interface (str): Network interface to monitor (e.g., "eth0", "wlan0").
            output_dir (str): Directory to save output files.
            logger: Logger instance for logging messages.
        """
        self.interface = interface
        self.output_dir = output_dir
        self.logger = logger or setup_logger("NetworkMonitor")
        self.running = False
        self.thread = None
        self.c2_indicators = self._load_c2_indicators()

    def _load_c2_indicators(self) -> Dict:
        """
        Load known C2 indicators (IPs, domains) from configuration.

        Returns:
            Dict: Dictionary of C2 indicators (IPs and domains).
        """
        # Load from a dedicated config file or use defaults
        c2_config_path = "configs/c2_indicators.yaml"
        if os.path.exists(c2_config_path):
            try:
                config = load_config(c2_config_path)
                return {
                    "ips": config.get("ips", []),
                    "domains": config.get("domains", [])
                }
            except Exception as e:
                self.logger.warning(f"Failed to load C2 indicators from {c2_config_path}: {str(e)}")

        # Default C2 indicators (example - replace with real data)
        return {
            "ips": [
                "1.2.3.4",       # Example malicious IP
                "5.6.7.8",       # Example malicious IP
                "192.168.1.100"  # Example local test IP
            ],
            "domains": [
                "malicious-domain.com",
                "c2-server.net",
                "spyware-control.org"
            ]
        }

    def _is_suspicious_ip(self, ip: str) -> bool:
        """
        Check if an IP address is in the C2 indicators list.

        Args:
            ip (str): IP address to check.

        Returns:
            bool: True if the IP is suspicious, False otherwise.
        """
        return ip in self.c2_indicators.get("ips", [])

    def _is_suspicious_domain(self, domain: str) -> bool:
        """
        Check if a domain is in the C2 indicators list.

        Args:
            domain (str): Domain to check.

        Returns:
            bool: True if the domain is suspicious, False otherwise.
        """
        return domain in self.c2_indicators.get("domains", [])

    def _resolve_domain(self, domain: str) -> Optional[str]:
        """
        Resolve a domain to its IP address.

        Args:
            domain (str): Domain to resolve.

        Returns:
            Optional[str]: Resolved IP address, or None if resolution fails.
        """
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _get_active_connections(self) -> List[Dict]:
        """
        Get a list of active network connections.

        Returns:
            List[Dict]: List of active connections with details.
        """
        connections = []
        try:
            # Use netstat or ss to get active connections
            if os.name == "nt":  # Windows
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.split("\n")
                # Skip header lines
                for line in lines[4:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            connections.append({
                                "proto": parts[0],
                                "local_addr": parts[1],
                                "local_port": parts[2],
                                "remote_addr": parts[3],
                                "remote_port": parts[4],
                                "state": parts[5] if len(parts) > 5 else "UNKNOWN",
                                "pid": parts[-1] if len(parts) > 5 else "UNKNOWN"
                            })
            else:  # Linux/macOS
                result = subprocess.run(
                    ["ss", "-tulnp"],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.split("\n")
                # Skip header line
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            connections.append({
                                "proto": parts[0],
                                "local_addr": parts[4].split(":")[0] if ":" in parts[4] else parts[4],
                                "local_port": parts[4].split(":")[1] if ":" in parts[4] else "UNKNOWN",
                                "remote_addr": parts[5].split(":")[0] if len(parts) > 5 and ":" in parts[5] else (parts[5] if len(parts) > 5 else "UNKNOWN"),
                                "remote_port": parts[5].split(":")[1] if len(parts) > 5 and ":" in parts[5] else "UNKNOWN",
                                "state": parts[1] if len(parts) > 1 else "UNKNOWN",
                                "pid": parts[-1] if "pid=" in line else "UNKNOWN"
                            })
        except Exception as e:
            self.logger.error(f"Failed to get active connections: {str(e)}")

        return connections

    def _check_connection(self, conn: Dict) -> Optional[Dict]:
        """
        Check if a connection is suspicious (matches C2 indicators).

        Args:
            conn (Dict): Connection details.

        Returns:
            Optional[Dict]: Suspicious connection details if detected, None otherwise.
        """
        remote_addr = conn.get("remote_addr", "")
        
        # Check if IP is suspicious
        if self._is_suspicious_ip(remote_addr):
            return {
                **conn,
                "type": "c2_ip",
                "indicator": remote_addr,
                "severity": "high",
                "description": f"Connection to known C2 IP: {remote_addr}"
            }

        # Resolve domain if remote_addr is a domain
        if not any(c.isdigit() for c in remote_addr):  # Likely a domain
            resolved_ip = self._resolve_domain(remote_addr)
            if resolved_ip and self._is_suspicious_ip(resolved_ip):
                return {
                    **conn,
                    "type": "c2_domain",
                    "indicator": remote_addr,
                    "resolved_ip": resolved_ip,
                    "severity": "high",
                    "description": f"Connection to known C2 domain: {remote_addr} (resolved to {resolved_ip})"
                }
            if self._is_suspicious_domain(remote_addr):
                return {
                    **conn,
                    "type": "c2_domain",
                    "indicator": remote_addr,
                    "severity": "high",
                    "description": f"Connection to known C2 domain: {remote_addr}"
                }

        return None

    def monitor(self, duration: int = 60, output: Optional[str] = None) -> Dict:
        """
        Monitor network traffic for a specified duration.

        Args:
            duration (int): Duration to monitor in seconds (default: 60).
            output (Optional[str]): Output file path to save results.

        Returns:
            Dict: Monitoring results with detections and metadata.
        """
        self.running = True
        results = {
            "scan_type": "network",
            "interface": self.interface,
            "start_time": datetime.now().isoformat(),
            "end_time": "",
            "detections": [],
            "errors": [],
            "metadata": {
                "duration": duration,
                "c2_indicators_loaded": len(self.c2_indicators.get("ips", [])) + len(self.c2_indicators.get("domains", []))
            }
        }

        try:
            self.logger.info(f"Starting network monitoring on {self.interface} for {duration} seconds")

            # Initial scan of active connections
            self.logger.debug("Scanning active connections...")
            connections = self._get_active_connections()
            for conn in connections:
                detection = self._check_connection(conn)
                if detection:
                    results["detections"].append(detection)
                    self.logger.warning(f"Detected suspicious connection: {detection['description']}")

            # Continuous monitoring (if duration > 0)
            if duration > 0:
                start_time = time.time()
                while self.running and (time.time() - start_time) < duration:
                    time.sleep(5)  # Check every 5 seconds
                    connections = self._get_active_connections()
                    for conn in connections:
                        detection = self._check_connection(conn)
                        if detection:
                            # Avoid duplicates
                            if detection not in results["detections"]:
                                results["detections"].append(detection)
                                self.logger.warning(f"Detected suspicious connection: {detection['description']}")

            results["end_time"] = datetime.now().isoformat()

        except Exception as e:
            results["errors"].append(f"Network monitoring error: {str(e)}")
            self.logger.error(f"Network monitoring error: {str(e)}")
        finally:
            self.running = False

        # Save results to file
        if output:
            try:
                os.makedirs(os.path.dirname(output), exist_ok=True)
                with open(output, "w") as f:
                    json.dump(results, f, indent=4)
                self.logger.info(f"Network monitoring results saved to {output}")
            except Exception as e:
                results["errors"].append(f"Failed to save results: {str(e)}")
                self.logger.error(f"Failed to save results: {str(e)}")

        return results

    def start_continuous_monitor(self, output: Optional[str] = None, interval: int = 60) -> None:
        """
        Start continuous network monitoring in a background thread.

        Args:
            output (Optional[str]): Output file path to save results.
            interval (int): Monitoring interval in seconds (default: 60).
        """
        if self.thread and self.thread.is_alive():
            self.logger.warning("Continuous monitoring is already running")
            return

        self.running = True
        self.thread = threading.Thread(
            target=self._continuous_monitor_loop,
            args=(output, interval),
            daemon=True
        )
        self.thread.start()
        self.logger.info(f"Started continuous network monitoring (interval: {interval}s)")

    def _continuous_monitor_loop(self, output: Optional[str] = None, interval: int = 60) -> None:
        """
        Continuous monitoring loop.

        Args:
            output (Optional[str]): Output file path to save results.
            interval (int): Monitoring interval in seconds.
        """
        while self.running:
            self.monitor(duration=interval, output=output)
            time.sleep(interval)

    def stop_continuous_monitor(self) -> None:
        """Stop continuous network monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.logger.info("Stopped continuous network monitoring")

    def update_c2_indicators(self, ips: List[str] = None, domains: List[str] = None) -> None:
        """
        Update the C2 indicators list.

        Args:
            ips (List[str]): List of malicious IPs to add.
            domains (List[str]): List of malicious domains to add.
        """
        if ips:
            self.c2_indicators["ips"] = list(set(self.c2_indicators.get("ips", []) + ips))
        if domains:
            self.c2_indicators["domains"] = list(set(self.c2_indicators.get("domains", []) + domains))
        self.logger.info(f"Updated C2 indicators: {len(self.c2_indicators.get('ips', []))} IPs, {len(self.c2_indicators.get('domains', []))} domains")

    def save_c2_indicators(self, output_path: str = "configs/c2_indicators.yaml") -> None:
        """
        Save C2 indicators to a YAML file.

        Args:
            output_path (str): Path to save the C2 indicators.
        """
        try:
            import yaml
            with open(output_path, "w") as f:
                yaml.dump(self.c2_indicators, f)
            self.logger.info(f"C2 indicators saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to save C2 indicators: {str(e)}")
