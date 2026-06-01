# **SpySentry: Spyware & Stalkerware Detection & Mitigation Framework**

[License: MIT](LICENSE)  
[Python 3.8+](https://www.python.org/downloads/)  
[GitHub Stars](https://github.com/Transparency-X/spysentry/stargazers)  
[GitHub Issues](https://github.com/Transparency-X/spysentry/issues)  
[Last Commit](https://github.com/Transparency-X/spysentry/commits/main)

---

## **📌 About SpySentry**

**SpySentry** is an **open-source framework** designed to **detect, analyze, and mitigate spyware, stalkerware, and cyber crime tools** across **Android, iOS, macOS, Windows, Linux, IoT, and network devices**. It combines **signature-based detection (YARA), behavioral analysis, network monitoring, and memory forensics** to provide a **comprehensive defense** against digital surveillance threats.

### **🎯 Mission**

- **Educate** users and organizations on **spyware/stalkerware threats** and their **mechanisms, risks, and impacts**.
- **Detect** known and emerging threats using **YARA rules, behavioral analysis, and network monitoring**.
- **Mitigate** infections with **step-by-step removal guides** and **automated tools**.
- **Prevent** future infections through **best practices, hardening guides, and proactive monitoring**.

---

## **🚀 Features**

### **📚 Research & Documentation**

✅ **Comprehensive Threat Taxonomy**

- **Infection Levels**: Covers **17 layers** from **Physical/Hardware** to **Social Engineering** (see [Infection Levels Hierarchy](docs/assets/diagrams/Infection_Levels_Hierarchy.mmd)).
- **Platform-Specific Analysis**: Detailed breakdowns for **Android, iOS, macOS, Windows, Linux, IoT, and Network Routers**.
- **Real-World Examples**: Maps **spyware families** (e.g., Pegasus, LoJax, mSpy) to their **behaviors, targets, and countermeasures**.

✅ **Detection & Removal Guides**

- **Step-by-Step Instructions** for detecting and removing spyware/stalkerware at **every infection level**.
- **Tool Recommendations**: Lists **free and paid tools** (e.g., YARA, OSSEC, Zeek, Volatility) for each OS/device.
- **Prevention Strategies**: Proactive measures to **harden devices** against threats.

✅ **Comparison Tables**

- **Infection Levels vs. Countermeasures**: Detailed table mapping **infection levels** to **detection methods, removal steps, and prevention strategies** (see [tables/Infection_Levels_vs_Countermeasures.csv](docs/assets/tables/Infection_Levels_vs_Countermeasures.csv)).
- **Spyware/Stalkerware Examples**: Curated list of **known threats** with their **behavior, targets, and mitigation**.

✅ **Case Studies**

- Real-world **spyware/stalkerware attacks** (e.g., Pegasus, LoJax, Emotet) with **lessons learned** and **mitigation steps**.

---

### **🛠️ Tools & Scanners**

🔹 **SpySentry Scanner (Python)**

- **Cross-platform CLI tool** to scan for **spyware/stalkerware indicators** (e.g., suspicious processes, network connections, file modifications).
- **Modular Design**: Supports **Android (ADB), Windows (PowerShell), macOS (Bash), and Linux**.
- **YARA Rules Integration**: Uses **custom YARA rules** to detect **known malware signatures**.

🔹 **Network Traffic Analyzer**

- **Lightweight tool** to monitor and flag **suspicious outbound connections** (e.g., to known C2 servers in Russia/China).
- **Integration with Zeek/Suricata**: For **advanced network-level detection** and **file extraction**.

🔹 **Behavioral Analysis Module**

- **OSSEC/Wazuh Integration**: Monitors **file integrity, log anomalies, and system behavior** (e.g., new cron jobs, startup entries).
- **Sysmon Integration (Windows)**: Tracks **process creation, network connections, and registry changes**.

🔹 **Memory Forensics Module**

- **Volatility Integration**: Scans **memory dumps** for **fileless malware** (e.g., Pegasus, LoJax).
- **Kernel-Level Analysis**: Detects **rootkits** and **hidden processes** in RAM.

🔹 **Automated Rule Updates**

- **MISP Integration**: Automatically **pulls latest IoCs** (e.g., C2 IPs, hashes) to update **YARA rules** dynamically.
- **GitHub Actions Workflows**: For **scheduled rule updates** and **CI/CD testing**.

---

### **📊 Reports & Insights**

📄 **[SpySentry v1.0 Report: Comprehensive Analysis of Spyware & Stalkerware Threats](docs/reports/SpySentry_v1.0_Report.md)**

- **Installation Methods**: Physical vs. remote (phishing, exploits, supply chain).
- **Data Exfiltration**: C2 servers, cloud storage, SMS/email forwarding.
- **Infection Levels**: 17 layers from **Physical/Hardware** to **Social Engineering**.
- **Platform-Specific Countermeasures**: Detection, removal, and prevention for **Android, iOS, macOS, Windows, Linux, IoT**.
- **Threat Landscape Summary**: Key trends, high-risk threats, and recommendations.

📄 **[YARA Rules & Complementary Approaches Report](docs/reports/YARA_Rules_and_Complementary_Approaches.md)**

- **YARA Deep Dive**: How YARA works, benefits, and drawbacks.
- **Alternatives/Complements**: ClamAV, Snort, OSSEC, Volatility, Zeek, Cuckoo Sandbox, MISP, etc.
- **Comparison Tables**: YARA vs. alternatives for **detection, performance, and use cases**.
- **Recommended Integrations**: How to **combine tools** for **layered defense**.

---

## **📥 Installation**

### **Prerequisites**

- **Python 3.8+** (for core tools and scripts).
- **Git** (for cloning and contributing).
- **YARA** (for signature-based scanning).
- **Optional Dependencies**:
  - **OSSEC/Wazuh** (for behavioral analysis).
  - **Zeek/Suricata** (for network monitoring).
  - **Volatility** (for memory forensics).
  - **Docker** (for sandboxing with Cuckoo).

### **Quick Start**

1. **Clone the Repository**:
  ```bash
   git clone https://github.com/Transparency-X/spysentry.git
   cd spysentry
  ```
2. **Install Python Dependencies**:
  ```bash
   pip install -r requirements.txt
  ```
   *Requirements include: `yara-python`, `pyyaml`, `requests`, `pandas`.*
3. **Install Additional Tools** (Optional):
  - **YARA**:
  - **OSSEC/Wazuh**:
    ```bash
    bash scripts/setup/install_ossec.sh
    ```
  - **Zeek/Suricata**:
    ```bash
    bash scripts/setup/install_zeek.sh
    ```
4. **Verify Installation**:
  ```bash
   python src/core/spysentry.py --version
  ```

---

## **🛠️ Usage**

### **1. Run a YARA Scan**

Scan a directory for **known spyware/stalkerware signatures**:

```bash
python src/core/spysentry.py --scan --path /target/directory --output reports/scan_results.json
```

**Options**:


| **Option**    | **Description**                     | **Example**                     |
| ------------- | ----------------------------------- | ------------------------------- |
| `--scan`      | Run a scan for spyware/stalkerware. | `--scan`                        |
| `--path`      | Directory or file to scan.          | `--path /home/user/Downloads`   |
| `--output`    | Output file path (JSON/CSV).        | `--output reports/results.json` |
| `--rules`     | Custom YARA rules directory.        | `--rules rules/yara/custom/`    |
| `--recursive` | Scan subdirectories recursively.    | `--recursive`                   |
| `--verbose`   | Enable verbose logging.             | `--verbose`                     |


---

### **2. Monitor Network Traffic**

Monitor **inbound/outbound traffic** for spyware C2 communication:

```bash
python src/scanners/network_monitor/monitor.py --interface eth0 --output reports/network_traffic.json
```

**Options**:


| **Option**    | **Description**                                     | **Example**                     |
| ------------- | --------------------------------------------------- | ------------------------------- |
| `--interface` | Network interface to monitor.                       | `--interface eth0`              |
| `--output`    | Output file path.                                   | `--output reports/network.json` |
| `--zeek`      | Enable Zeek integration for deep packet inspection. | `--zeek`                        |
| `--suricata`  | Enable Suricata integration for NIDS.               | `--suricata`                    |


---

### **3. Behavioral Analysis**

Monitor **system behavior** for spyware persistence:

```bash
python src/scanners/behavioral_analysis/ossec_integration.py --config configs/ossec_config.xml --output reports/behavioral_analysis.json
```

---

### **4. Memory Forensics**

Analyze **memory dumps** for fileless spyware:

```bash
python src/scanners/memory_forensics/volatility_integration.py --memory-dump memdump.raw --output reports/memory_analysis.json
```

---

### **5. Update YARA Rules**

Automatically **pull latest IoCs** from MISP:

```bash
bash scripts/automation/update_yara_rules.sh --misp-url https://misp.example.com --api-key YOUR_API_KEY
```

---

### **6. Generate Reports**

Generate a **consolidated report** from scan results:

```bash
python scripts/automation/generate_report.py --input reports/scan_results.json --output reports/final_report.md
```

---

## **📂 Project Structure**

```
spysentry/
├── 📚 docs/
│   ├── 📄 reports/
│   │   ├── SpySentry_v1.0_Report.md                     # Comprehensive threat landscape report
│   │   ├── YARA_Rules_and_Complementary_Approaches.md   # YARA + alternatives/complements report
│   │   └── CASE_STUDIES.md                              # Real-world case studies
│   │
│   ├── 📖 user_guides/
│   │   ├── Installation_Guide.md                        # Setup instructions
│   │   ├── Detection_Guide.md                          # Detection workflows
│   │   ├── Removal_Guide.md                             # Removal steps
│   │   └── Prevention_Best_Practices.md                # Proactive security
│   │
│   ├── 📖 developer_guides/
│   │   ├── Contributing.md                             # Contribution guidelines
│   │   ├── API_Reference.md                            # API documentation
│   │   ├── YARA_Rule_Writing.md                         # Guide to writing YARA rules
│   │   └── Tool_Integration.md                          # Integration guides
│   │
│   └── 📊 assets/
│       ├── diagrams/                                   # Mermaid/PlantUML diagrams
│       ├── tables/                                     # CSV/Markdown tables
│       └── images/                                    # Screenshots and visuals
│
├── 💻 src/
│   ├── 🔍 scanners/
│   │   ├── yara_scanner/
│   │   │   ├── scanner.py                              # Core YARA scanning logic
│   │   │   ├── config.yaml                             # YARA scanner config
│   │   │   └── README.md                                # Usage instructions
│   │   │
│   │   ├── network_monitor/
│   │   │   ├── monitor.py                               # Network monitoring logic
│   │   │   └── README.md                                # Usage instructions
│   │   │
│   │   ├── behavioral_analysis/
│   │   │   ├── ossec_integration.py                     # OSSEC integration
│   │   │   └── README.md                                # Usage instructions
│   │   │
│   │   └── memory_forensics/
│   │       ├── volatility_integration.py               # Volatility integration
│   │       └── README.md                                # Usage instructions
│   │
│   ├── 🛠️ utils/
│   │   ├── logger.py                                   # Logging utility
│   │   ├── file_utils.py                                # File handling
│   │   └── helpers.py                                  # Helper functions
│   │
│   └── 🏗️ core/
│       ├── spysentry.py                                # Main CLI entry point
│       └── config.py                                   # Global configuration
│
├── 📦 rules/
│   ├── yara/
│   │   ├── spyware/                                    # YARA rules for spyware
│   │   │   ├── android.yar                             # Android spyware rules
│   │   │   ├── ios.yar                                 # iOS spyware rules
│   │   │   ├── windows.yar                             # Windows spyware rules
│   │   │   ├── macos.yar                               # macOS spyware rules
│   │   │   └── linux.yar                               # Linux spyware rules
│   │   │
│   │   ├── stalkerware/                                # YARA rules for stalkerware
│   │   │   ├── commercial.yar                          # Commercial stalkerware rules
│   │   │   └── custom.yar                              # Custom rules
│   │   │
│   │   └── ioc/                                        # YARA rules for IoCs
│   │       ├── c2_ips.yar                              # C2 server IP rules
│   │       ├── domains.yar                             # Malicious domain rules
│   │       └── hashes.yar                              # File hash rules
│   │
│   └── snort/
│       ├── spyware_rules.rules                        # Snort rules for spyware
│       └── README.md                                   # Snort integration guide
│
├── 📦 tools/
│   ├── detection/
│   │   ├── yara/                                       # YARA binaries
│   │   ├── volatility/                                 # Volatility binaries
│   │   └── suricata/                                   # Suricata binaries
│   │
│   └── mitigation/
│       ├── scripts/                                    # Mitigation scripts
│       └── templates/                                  # Rule/templates
│
├── 🧪 tests/
│   ├── unit/
│   │   ├── test_yara_scanner.py                       # Unit tests for YARA scanner
│   │   └── test_network_monitor.py                    # Unit tests for network monitor
│   │
│   ├── integration/
│   │   ├── test_full_scan.py                          # Integration tests
│   │   └── test_yara_ossec_integration.py              # YARA + OSSEC tests
│   │
│   └── fixtures/
│       ├── samples/                                   # Test files
│       └── logs/                                      # Test logs
│
├── 📦 examples/
│   ├── yara_rules/
│   │   ├── example_pegasus.yar                         # Example Pegasus rule
│   │   └── example_lojax.yar                           # Example LoJax rule
│   │
│   └── scripts/
│       ├── scan_with_yara.py                          # Example YARA scan script
│       └── generate_yara_from_cuckoo.py                # Example Cuckoo → YARA script
│
├── 📦 configs/
│   ├── spysentry_config.yaml                          # Main config
│   ├── yara_config.yaml                               # YARA config
│   └── network_monitor_config.yaml                   # Network monitor config
│
├── 📦 scripts/
│   ├── setup/
│   │   ├── install_dependencies.sh                     # Install dependencies
│   │   └── install_ossec.sh                            # Install OSSEC
│   │
│   ├── automation/
│   │   ├── update_yara_rules.sh                        # Update YARA rules from MISP
│   │   ├── scheduled_scan.sh                           # Scheduled scans
│   │   └── generate_report.py                          # Generate reports
│   │
│   └── utils/
│       ├── backup_rules.sh                            # Backup YARA rules
│       └── validate_rules.py                           # Validate YARA rules
│
├── 📦 .github/
│   └── workflows/
│       ├── ci.yml                                     # CI workflow
│       ├── test.yml                                   # Test workflow
│       └── update_rules.yml                            # Auto-update YARA rules
│
├── 📄 .gitignore
├── 📄 LICENSE
├── 📄 CONTRIBUTING.md
├── 📄 CHANGELOG.md
└── 📄 README.md
```

---

## **📚 Documentation**


| **Resource**              | **Description**                                                                                   | **Path**                                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **SpySentry v1.0 Report** | Comprehensive analysis of **spyware/stalkerware threats, infection levels, and countermeasures**. | `[docs/reports/SpySentry_v1.0_Report.md](docs/reports/SpySentry_v1.0_Report.md)`                                     |
| **YARA Rules Report**     | Deep dive into **YARA rules and complementary tools** (ClamAV, OSSEC, Zeek, etc.).                | `[docs/reports/YARA_Rules_and_Complementary_Approaches.md](docs/reports/YARA_Rules_and_Complementary_Approaches.md)` |
| **Case Studies**          | Real-world **spyware/stalkerware attacks** and mitigation strategies.                             | `[docs/reports/CASE_STUDIES.md](docs/reports/CASE_STUDIES.md)`                                                       |
| **Installation Guide**    | Step-by-step **setup instructions** for SpySentry.                                                | `[docs/user_guides/Installation_Guide.md](docs/user_guides/Installation_Guide.md)`                                   |
| **Detection Guide**       | How to **use SpySentry tools** to detect threats.                                                 | `[docs/user_guides/Detection_Guide.md](docs/user_guides/Detection_Guide.md)`                                         |
| **Removal Guide**         | Step-by-step **removal instructions** for infected devices.                                       | `[docs/user_guides/Removal_Guide.md](docs/user_guides/Removal_Guide.md)`                                             |
| **Prevention Guide**      | **Best practices** to prevent spyware/stalkerware infections.                                     | `[docs/user_guides/Prevention_Best_Practices.md](docs/user_guides/Prevention_Best_Practices.md)`                     |
| **Contributing Guide**    | How to **contribute** to SpySentry.                                                               | `[CONTRIBUTING.md](CONTRIBUTING.md)`                                                                                 |
| **YARA Rule Writing**     | Guide to **writing custom YARA rules** for SpySentry.                                             | `[docs/developer_guides/YARA_Rule_Writing.md](docs/developer_guides/YARA_Rule_Writing.md)`                           |
| **Tool Integration**      | How to **integrate YARA, OSSEC, Zeek, etc.** into SpySentry.                                      | `[docs/developer_guides/Tool_Integration.md](docs/developer_guides/Tool_Integration.md)`                             |


---

## **🤝 Contributing**

We welcome contributions from the **security community**! Here’s how you can help:

### **📌 Ways to Contribute**

1. **Report New Threats**: Submit **new spyware/stalkerware examples** or **infection techniques** via **GitHub Issues**.
2. **Improve Detection Rules**: Contribute **YARA rules, Snort rules, or IoCs** via **Pull Requests**.
3. **Test & Validate**: Help **test tools** on different platforms and **report bugs**.
4. **Enhance Documentation**: Improve **guides, tables, or reports** with new insights.
5. **Develop New Features**: Add **new scanners, integrations, or automation scripts**.

### **📌 Contribution Guidelines**

1. **Fork the Repository**:
  ```bash
   git fork https://github.com/Transparency-X/spysentry.git
   git clone https://github.com/your-username/spysentry.git
  ```
2. **Create a Branch**:
  - For **new features**: `git checkout -b feature/your-feature-name`
  - For **bug fixes**: `git checkout -b fix/your-bug-fix`
3. **Make Changes**:
  - Follow the **directory structure** and **naming conventions**.
  - Add **tests** for new features.
  - Update **documentation** (e.g., `README.md`, `docs/`).
4. **Submit a Pull Request**:
  - **Title**: Clear and concise (e.g., "Add YARA rule for Pegasus C2 IPs").
  - **Description**: Include:
    - What was changed?
    - Why was it changed?
    - How was it tested?
    - Screenshots/outputs (if applicable).
  - **Linked Issues**: Reference any **related issues**.

### **📌 Code of Conduct**

- Be **respectful** and **inclusive**.
- Follow **best practices** for security tools (e.g., **no malicious code** in PRs).
- **Credit sources** for third-party rules or data.

---

## **📜 License**

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## **🙏 Acknowledgments**

### **Research Sources**

- [Kaspersky](https://www.kaspersky.com/)
- [ESET](https://www.eset.com/)
- [Citizen Lab](https://citizenlab.ca/)
- [Malwarebytes](https://www.malwarebytes.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)

### **Tools & Frameworks**

- [YARA](https://virustotal.github.io/yara/)
- [OSSEC](https://www.ossec.net/)
- [Wazuh](https://wazuh.com/)
- [Zeek](https://zeek.org/)
- [Suricata](https://suricata.io/)
- [Volatility](https://www.volatilityfoundation.org/)
- [MISP](https://www.misp-project.org/)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)

### **Community**

Thanks to all **security researchers, ethical hackers, and contributors** who help fight spyware/stalkerware!

---

## **📩 Contact**

For questions, feedback, or collaborations:

- **GitHub**: [SpySentry Repository](https://github.com/Transparency-X/spysentry)
- **Email**: [spysentry@transparency-x.org](mailto:spysentry@transparency-x.org)
- **Twitter**: [@SpySentry](https://twitter.com/SpySentry)
- **Website**: [Transparency-X](https://transparency-x.org)

---

---

## **🔒 Stay Secure. Stay Informed.**

> *SpySentry – Your Guardian Against Digital Surveillance.*
