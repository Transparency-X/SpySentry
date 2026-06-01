#!/usr/bin/env python3
"""
YARA Scanner Module for SpySentry

This module provides functionality to scan files and directories using YARA rules
for detecting spyware, stalkerware, and other malicious artifacts.

Usage:
    scanner = YARAScanner(rules_dir="rules/yara")
    results = scanner.scan(path="/target/directory", recursive=True)

Author: Transparency-X
License: MIT
"""

import os
import yara
from pathlib import Path
from typing import Dict, List, Optional, Union
from src.utils.logger import setup_logger
from src.utils.helpers import validate_path, load_yara_rules


class YARAScanner:
    """
    A scanner class to detect spyware/stalkerware using YARA rules.
    """

    def __init__(self, rules_dir: str = "rules/yara", logger=None):
        """
        Initialize the YARA scanner with a directory of YARA rules.

        Args:
            rules_dir (str): Path to the directory containing YARA rules.
            logger: Logger instance for logging messages.
        """
        self.rules_dir = rules_dir
        self.logger = logger or setup_logger("YARAScanner")
        self.rules = self._load_rules()

    def _load_rules(self) -> Optional[yara.Rules]:
        """
        Load YARA rules from the specified directory.

        Returns:
            yara.Rules: Compiled YARA rules.
        """
        try:
            self.logger.info(f"Loading YARA rules from {self.rules_dir}")
            rules = load_yara_rules(self.rules_dir)
            self.logger.info(f"Loaded {len(rules)} YARA rules")
            return rules
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {str(e)}")
            return None

    def scan(self, path: Union[str, List[str]], recursive: bool = True) -> Dict:
        """
        Scan a file or directory for spyware/stalkerware using YARA rules.

        Args:
            path (Union[str, List[str]]): File or directory path(s) to scan.
            recursive (bool): Whether to scan subdirectories recursively.

        Returns:
            Dict: Scan results with detections and errors.
        """
        results = {
            "scan_type": "yara",
            "targets": path if isinstance(path, list) else [path],
            "detections": [],
            "errors": [],
            "metadata": {
                "rules_loaded": len(self.rules) if self.rules else 0,
                "recursive": recursive
            }
        }

        if not self.rules:
            results["errors"].append("No YARA rules loaded. Check rules directory.")
            return results

        # Convert single path to list
        if isinstance(path, str):
            path = [path]

        for target in path:
            if not validate_path(target, self.logger):
                results["errors"].append(f"Invalid path: {target}")
                continue

            if os.path.isfile(target):
                self._scan_file(target, results)
            elif os.path.isdir(target):
                self._scan_directory(target, results, recursive)

        return results

    def _scan_file(self, filepath: str, results: Dict) -> None:
        """
        Scan a single file with YARA rules.

        Args:
            filepath (str): Path to the file to scan.
            results (Dict): Results dictionary to update with detections/errors.
        """
        try:
            self.logger.debug(f"Scanning file: {filepath}")
            with open(filepath, "rb") as f:
                matches = self.rules.match(data=f.read())
                if matches:
                    for match in matches:
                        detection = {
                            "file": filepath,
                            "rule": match.rule,
                            "tags": list(match.tags),
                            "meta": dict(match.meta),
                            "strings": [{"identifier": s.identifier, "data": s.data} for s in match.strings]
                        }
                        results["detections"].append(detection)
                        self.logger.info(f"Detection in {filepath}: {match.rule}")
        except Exception as e:
            results["errors"].append(f"Error scanning {filepath}: {str(e)}")
            self.logger.error(f"Error scanning {filepath}: {str(e)}")

    def _scan_directory(self, dirpath: str, results: Dict, recursive: bool) -> None:
        """
        Scan a directory for files to analyze with YARA.

        Args:
            dirpath (str): Path to the directory to scan.
            results (Dict): Results dictionary to update with detections/errors.
            recursive (bool): Whether to scan subdirectories recursively.
        """
        try:
            for root, _, files in os.walk(dirpath):
                for file in files:
                    filepath = os.path.join(root, file)
                    self._scan_file(filepath, results)
                if not recursive:
                    break
        except Exception as e:
            results["errors"].append(f"Error scanning directory {dirpath}: {str(e)}")
            self.logger.error(f"Error scanning directory {dirpath}: {str(e)}")

    def scan_memory_dump(self, memdump_path: str) -> Dict:
        """
        Scan a memory dump file with YARA rules.

        Args:
            memdump_path (str): Path to the memory dump file.

        Returns:
            Dict: Scan results with detections and errors.
        """
        results = {
            "scan_type": "yara_memory",
            "target": memdump_path,
            "detections": [],
            "errors": []
        }

        if not self.rules:
            results["errors"].append("No YARA rules loaded. Check rules directory.")
            return results

        try:
            self.logger.info(f"Scanning memory dump: {memdump_path}")
            with open(memdump_path, "rb") as f:
                matches = self.rules.match(data=f.read())
                if matches:
                    for match in matches:
                        detection = {
                            "file": memdump_path,
                            "rule": match.rule,
                            "tags": list(match.tags),
                            "meta": dict(match.meta),
                            "strings": [{"identifier": s.identifier, "data": s.data} for s in match.strings]
                        }
                        results["detections"].append(detection)
                        self.logger.info(f"Detection in memory dump: {match.rule}")
        except Exception as e:
            results["errors"].append(f"Error scanning memory dump: {str(e)}")
            self.logger.error(f"Error scanning memory dump: {str(e)}")

        return results

    def validate_rule(self, rule_path: str) -> bool:
        """
        Validate a single YARA rule file.

        Args:
            rule_path (str): Path to the YARA rule file.

        Returns:
            bool: True if the rule is valid, False otherwise.
        """
        try:
            with open(rule_path, "r") as f:
                yara.compile(sources={"rule": f.read()})
            return True
        except Exception as e:
            self.logger.error(f"Invalid YARA rule {rule_path}: {str(e)}")
            return False

    def validate_rules(self) -> Dict:
        """
        Validate all YARA rules in the rules directory.

        Returns:
            Dict: Validation results with valid/invalid rules.
        """
        results = {
            "valid_rules": [],
            "invalid_rules": []
        }

        if not os.path.isdir(self.rules_dir):
            self.logger.error(f"Rules directory {self.rules_dir} does not exist")
            return results

        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar"):
                    rule_path = os.path.join(root, file)
                    if self.validate_rule(rule_path):
                        results["valid_rules"].append(rule_path)
                    else:
                        results["invalid_rules"].append(rule_path)

        return results
