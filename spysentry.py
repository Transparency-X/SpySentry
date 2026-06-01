#!/usr/bin/env python3
"""
SpySentry: Core CLI Tool for Spyware/Stalkerware Detection & Mitigation

This script serves as the main entry point for SpySentry, providing a unified interface
to scan for spyware/stalkerware using YARA rules, behavioral analysis, and network monitoring.

Usage:
    python spysentry.py --scan --path /target/directory --output reports/results.json

Author: Transparency-X
License: MIT
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanners.yara_scanner.scanner import YARAScanner
from src.scanners.network_monitor.monitor import NetworkMonitor
from src.scanners.behavioral_analysis.ossec_integration import OSSECIntegration
from src.scanners.memory_forensics.volatility_integration import VolatilityIntegration
from src.utils.logger import setup_logger
from src.utils.helpers import load_config, validate_path


class SpySentry:
    """
    Core SpySentry class to orchestrate detection, analysis, and mitigation.
    """

    def __init__(self, config_path: str = "configs/spysentry_config.yaml"):
        """
        Initialize SpySentry with configuration.

        Args:
            config_path (str): Path to the SpySentry configuration file.
        """
        self.config = load_config(config_path)
        self.logger = setup_logger("SpySentry", self.config.get("logging_level", "INFO"))
        self.yara_scanner = None
        self.network_monitor = None
        self.ossec_integration = None
        self.volatility_integration = None
        self._initialize_modules()

    def _initialize_modules(self):
        """Initialize all detection modules based on config."""
        # Initialize YARA Scanner
        if self.config.get("yara", {}).get("enabled", False):
            yara_config = self.config.get("yara", {})
            self.yara_scanner = YARAScanner(
                rules_dir=yara_config.get("rules_dir", "rules/yara"),
                logger=self.logger
            )
            self.logger.info("YARA Scanner initialized")

        # Initialize Network Monitor
        if self.config.get("network_monitor", {}).get("enabled", False):
            network_config = self.config.get("network_monitor", {})
            self.network_monitor = NetworkMonitor(
                interface=network_config.get("interface", "eth0"),
                output_dir=network_config.get("output_dir", "reports"),
                logger=self.logger
            )
            self.logger.info("Network Monitor initialized")

        # Initialize OSSEC Integration
        if self.config.get("behavioral_analysis", {}).get("ossec_enabled", False):
            ossec_config = self.config.get("behavioral_analysis", {})
            self.ossec_integration = OSSECIntegration(
                config_path=ossec_config.get("config_path", "configs/ossec_config.xml"),
                logger=self.logger
            )
            self.logger.info("OSSEC Integration initialized")

        # Initialize Volatility Integration
        if self.config.get("memory_forensics", {}).get("enabled", False):
            volatility_config = self.config.get("memory_forensics", {})
            self.volatility_integration = VolatilityIntegration(
                logger=self.logger
            )
            self.logger.info("Volatility Integration initialized")

    def scan(self, path: Union[str, List[str]], output: Optional[str] = None, recursive: bool = True) -> Dict:
        """
        Run a comprehensive scan for spyware/stalkerware.

        Args:
            path (Union[str, List[str]]): File or directory path(s) to scan.
            output (Optional[str]): Output file path (JSON).
            recursive (bool): Whether to scan subdirectories recursively.

        Returns:
            Dict: Scan results with detections, errors, and metadata.
        """
        results = {
            "scan_type": "comprehensive",
            "targets": path if isinstance(path, list) else [path],
            "detections": [],
            "errors": [],
            "metadata": {
                "timestamp": "",
                "config": self.config
            }
        }

        # Validate paths
        if isinstance(path, str):
            path = [path]
        for p in path:
            if not validate_path(p, self.logger):
                results["errors"].append(f"Invalid path: {p}")
                continue

        # Run YARA scan
        if self.yara_scanner:
            self.logger.info(f"Running YARA scan on {path}")
            yara_results = self.yara_scanner.scan(path, recursive=recursive)
            results["detections"].extend(yara_results.get("detections", []))
            results["errors"].extend(yara_results.get("errors", []))

        # Run Network Monitor (if enabled and path is a directory)
        if self.network_monitor and all(os.path.isdir(p) for p in path):
            self.logger.info("Running Network Monitor")
            network_results = self.network_monitor.monitor()
            results["detections"].extend(network_results.get("detections", []))
            results["errors"].extend(network_results.get("errors", []))

        # Run OSSEC Behavioral Analysis
        if self.ossec_integration:
            self.logger.info("Running OSSEC Behavioral Analysis")
            ossec_results = self.ossec_integration.analyze()
            results["detections"].extend(ossec_results.get("detections", []))
            results["errors"].extend(ossec_results.get("errors", []))

        # Run Volatility Memory Forensics (if memory dump is provided)
        if self.volatility_integration:
            for p in path:
                if p.endswith(".raw") or p.endswith(".mem"):
                    self.logger.info(f"Running Volatility on memory dump: {p}")
                    volatility_results = self.volatility_integration.analyze(p)
                    results["detections"].extend(volatility_results.get("detections", []))
                    results["errors"].extend(volatility_results.get("errors", []))

        # Save results to file
        if output:
            try:
                os.makedirs(os.path.dirname(output), exist_ok=True)
                with open(output, "w") as f:
                    json.dump(results, f, indent=4)
                self.logger.info(f"Scan results saved to {output}")
            except Exception as e:
                results["errors"].append(f"Failed to save results: {str(e)}")

        return results

    def monitor_network(self, interface: str = None, output: Optional[str] = None) -> Dict:
        """
        Monitor network traffic for spyware C2 communication.

        Args:
            interface (str): Network interface to monitor.
            output (Optional[str]): Output file path (JSON).

        Returns:
            Dict: Network monitoring results.
        """
        if not self.network_monitor:
            return {"error": "Network Monitor is not enabled in config."}

        if interface:
            self.network_monitor.interface = interface

        results = self.network_monitor.monitor()

        if output:
            try:
                os.makedirs(os.path.dirname(output), exist_ok=True)
                with open(output, "w") as f:
                    json.dump(results, f, indent=4)
                self.logger.info(f"Network monitor results saved to {output}")
            except Exception as e:
                results["errors"] = [f"Failed to save results: {str(e)}"]

        return results

    def analyze_behavior(self, output: Optional[str] = None) -> Dict:
        """
        Run behavioral analysis using OSSEC.

        Args:
            output (Optional[str]): Output file path (JSON).

        Returns:
            Dict: Behavioral analysis results.
        """
        if not self.ossec_integration:
            return {"error": "OSSEC Integration is not enabled in config."}

        results = self.ossec_integration.analyze()

        if output:
            try:
                os.makedirs(os.path.dirname(output), exist_ok=True)
                with open(output, "w") as f:
                    json.dump(results, f, indent=4)
                self.logger.info(f"Behavioral analysis results saved to {output}")
            except Exception as e:
                results["errors"] = [f"Failed to save results: {str(e)}"]

        return results

    def analyze_memory(self, memory_dump: str, output: Optional[str] = None) -> Dict:
        """
        Analyze a memory dump for fileless spyware.

        Args:
            memory_dump (str): Path to the memory dump file.
            output (Optional[str]): Output file path (JSON).

        Returns:
            Dict: Memory forensics results.
        """
        if not self.volatility_integration:
            return {"error": "Volatility Integration is not enabled in config."}

        results = self.volatility_integration.analyze(memory_dump)

        if output:
            try:
                os.makedirs(os.path.dirname(output), exist_ok=True)
                with open(output, "w") as f:
                    json.dump(results, f, indent=4)
                self.logger.info(f"Memory analysis results saved to {output}")
            except Exception as e:
                results["errors"] = [f"Failed to save results: {str(e)}"]

        return results


def main():
    """Main entry point for SpySentry CLI."""
    parser = argparse.ArgumentParser(
        description="SpySentry: Spyware & Stalkerware Detection & Mitigation Framework"
    )

    # Global arguments
    parser.add_argument(
        "--config",
        type=str,
        default="configs/spysentry_config.yaml",
        help="Path to SpySentry configuration file (default: configs/spysentry_config.yaml)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    # Subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a comprehensive scan")
    scan_parser.add_argument(
        "--path",
        type=str,
        nargs="+",
        required=True,
        help="File or directory path(s) to scan"
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        help="Output file path (JSON)"
    )
    scan_parser.add_argument(
        "--recursive",
        action="store_true",
        default=True,
        help="Scan subdirectories recursively (default: True)"
    )

    # Network monitor command
    network_parser = subparsers.add_parser("network", help="Monitor network traffic")
    network_parser.add_argument(
        "--interface",
        type=str,
        default="eth0",
        help="Network interface to monitor (default: eth0)"
    )
    network_parser.add_argument(
        "--output",
        type=str,
        help="Output file path (JSON)"
    )

    # Behavioral analysis command
    behavioral_parser = subparsers.add_parser("behavior", help="Run behavioral analysis")
    behavioral_parser.add_argument(
        "--output",
        type=str,
        help="Output file path (JSON)"
    )

    # Memory forensics command
    memory_parser = subparsers.add_parser("memory", help="Analyze memory dump")
    memory_parser.add_argument(
        "--memory-dump",
        type=str,
        required=True,
        help="Path to the memory dump file"
    )
    memory_parser.add_argument(
        "--output",
        type=str,
        help="Output file path (JSON)"
    )

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Set up logging
    logging_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger("SpySentry", logging_level)

    try:
        # Initialize SpySentry
        spysentry = SpySentry(config_path=args.config)

        # Execute command
        if args.command == "scan":
            results = spysentry.scan(
                path=args.path,
                output=args.output,
                recursive=args.recursive
            )
        elif args.command == "network":
            results = spysentry.monitor_network(
                interface=args.interface,
                output=args.output
            )
        elif args.command == "behavior":
            results = spysentry.analyze_behavior(output=args.output)
        elif args.command == "memory":
            results = spysentry.analyze_memory(
                memory_dump=args.memory_dump,
                output=args.output
            )
        else:
            parser.print_help()
            sys.exit(1)

        # Print results to console
        print(json.dumps(results, indent=4))

    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
