# **Contributing to SpySentry**

We welcome contributions from the **security community** to help improve **SpySentry**! Whether you're a **researcher, developer, tester, or security enthusiast**, there are many ways to get involved.

---

## **📌 Ways to Contribute**


| **Type**              | **Description**                                                              | **Examples**                                                                                  |
| --------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **🐛 Bug Reports**    | Report **bugs, issues, or unexpected behavior** in SpySentry tools.          | File a **GitHub Issue** with steps to reproduce the bug.                                      |
| **🔍 Threat Reports** | Report **new spyware/stalkerware threats** or **infection techniques**.      | Submit **IoCs, samples, or behaviors** via GitHub Issues.                                     |
| **📜 Documentation**  | Improve **guides, reports, or tables** with new insights or clarifications.  | Update `docs/`, `README.md`, or `CONTRIBUTING.md`.                                            |
| **🛠️ Code**          | Contribute **new features, bug fixes, or optimizations** to SpySentry tools. | Add a **new scanner module**, improve **YARA rule integration**, or optimize **performance**. |
| **🔧 YARA Rules**     | Add **new YARA rules** for detecting spyware/stalkerware.                    | Submit **custom rules** for Pegasus, LoJax, or other threats.                                 |
| **🧪 Testing**        | Test **SpySentry tools** on different platforms and **report issues**.       | Run **unit/integration tests** and provide feedback.                                          |
| **📊 Data**           | Contribute **IoCs, hashes, or threat intelligence** to improve detection.    | Submit **C2 IPs, domains, or file hashes** for known spyware.                                 |
| **💡 Ideas**          | Suggest **new features, integrations, or improvements**.                     | Open a **GitHub Discussion** or **Issue** with your ideas.                                    |


---

## **📌 Getting Started**

### **1. Fork the Repository**

1. **Fork** the [SpySentry repository](https://github.com/Transparency-X/spysentry) to your GitHub account.
2. **Clone** your fork locally:
  ```bash
   git clone https://github.com/your-username/spysentry.git
   cd spysentry
  ```

### **2. Set Up Your Environment**

1. **Install Python 3.8+**:
  - [Python Downloads](https://www.python.org/downloads/)
2. **Install Dependencies**:
  ```bash
   pip install -r requirements.txt
  ```
3. **Install Optional Tools**:
  - **YARA**: `sudo apt-get install yara` (Linux) / `brew install yara` (macOS) / `choco install yara` (Windows)
  - **OSSEC/Wazuh**: Follow the [installation guide](docs/user_guides/Installation_Guide.md#ossecwazuh).
  - **Zeek/Suricata**: Follow the [installation guide](docs/user_guides/Installation_Guide.md#zeeksuricata).

### **3. Create a Branch**

- For **new features**:
  ```bash
  git checkout -b feature/your-feature-name
  ```
- For **bug fixes**:
  ```bash
  git checkout -b fix/your-bug-fix
  ```
- For **documentation updates**:
  ```bash
  git checkout -b docs/your-update
  ```

---

## **📌 Contribution Guidelines**

### **1. Code Contributions**

#### **📂 Directory Structure**

Follow the **existing directory structure** when adding new files:

```
spysentry/
├── docs/               # Documentation (reports, guides)
├── src/               # Source code (scanners, utils)
├── rules/             # Detection rules (YARA, Snort)
├── tools/             # Pre-built binaries and utilities
├── tests/             # Unit and integration tests
└── scripts/           # Automation and utility scripts
```

#### **📜 Naming Conventions**


| **Type**            | **Naming Convention** | **Example**             |
| ------------------- | --------------------- | ----------------------- |
| Python Scripts      | `snake_case.py`       | `yara_scanner.py`       |
| YARA Rules          | `snake_case.yar`      | `pegasus_detection.yar` |
| Configuration Files | `snake_case.ext`      | `yara_config.yaml`      |
| Test Files          | `test_snake_case.py`  | `test_yara_scanner.py`  |
| Directories         | `kebab-case/`         | `yara-rules/`           |


#### **📝 Code Style**

- **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/) guidelines.
  - Use **4 spaces** for indentation.
  - **Snake case** for function/variable names (`scan_directory`).
  - **PascalCase** for class names (`YARAScanner`).
  - **UPPER_CASE** for constants (`MAX_FILE_SIZE`).
  - **Docstrings** for all functions and classes (Google style).
- **YARA Rules**: Follow the **SpySentry YARA Rule Style Guide** (see below).
- **Shell Scripts**: Use **Bash** and include **shebangs** (`#!/bin/bash`).

#### **🔍 YARA Rule Style Guide**

1. **Metadata**: Always include `**meta**` section with:
  - `description`: Clear description of the rule.
  - `author`: Your name or organization.
  - `date`: Rule creation date (YYYY-MM-DD).
  - `reference`: Source or reference (e.g., "SpySentry Project v1.0").
  - `severity`: `low`, `medium`, or `high`.
  - `category`: `spyware`, `stalkerware`, `c2_traffic`, `persistence`, etc.
  - `family`: Malware family (e.g., "Pegasus", "LoJax").
  - `os`: Target OS (e.g., "iOS", "Android", "Windows").
2. **Strings**: Use **descriptive identifiers** (e.g., `$pegasus_string_1`).
  - `**wide**`: For wide-character strings (Unicode).
  - `**nocase**`: For case-insensitive matching.
  - `**ascii**`: For ASCII-only strings.
3. **Condition**: Use **clear, logical conditions**.
  - Avoid **overly complex** conditions.
  - Use `**any of them**` or `**all of them**` for string groups.
4. **Example Rule**:
  ```yara
   rule Detect_Pegasus_Spyware {
       meta:
           description = "Detects Pegasus spyware by known strings"
           author = "Your Name"
           date = "2026-06-01"
           reference = "SpySentry Project v1.0"
           severity = "high"
           category = "spyware"
           family = "Pegasus"
           os = "iOS, Android"

       strings:
           $pegasus_string = "Pegasus" wide ascii
           $nso_group = "NSO Group" nocase wide

       condition:
           any of them
   }
  ```

#### **📦 Pull Request (PR) Guidelines**

1. **Title**: Clear and concise (e.g., "Add YARA rule for LoJax UEFI rootkit").
2. **Description**: Include:
  - **What was changed?** (e.g., "Added a new YARA rule for LoJax").
  - **Why was it changed?** (e.g., "To detect LoJax UEFI rootkit").
  - **How was it tested?** (e.g., "Tested on a sample LoJax binary").
  - **Screenshots/Outputs**: If applicable (e.g., scan results).
3. **Linked Issues**: Reference any **related issues** (e.g., "Fixes #123").
4. **Tests**: Include **unit tests** for new features (see [Testing](#-testing)).
5. **Documentation**: Update **relevant documentation** (e.g., `README.md`, `docs/`).

---

### **2. YARA Rule Contributions**

#### **📂 Where to Add Rules**

- **Spyware Rules**: Add to `rules/yara/spyware/` (e.g., `pegasus.yar`, `lojax.yar`).
- **Stalkerware Rules**: Add to `rules/yara/stalkerware/` (e.g., `mspy.yar`, `flexispy.yar`).
- **IoC Rules**: Add to `rules/yara/ioc/` (e.g., `c2_ips.yar`, `domains.yar`).

#### **🔍 Rule Validation**

- **Test your rules** before submitting:
  ```bash
  yara -C rules/yara/spyware/your_rule.yar
  ```
- **Avoid false positives**: Test against **benign files** (e.g., system files, common apps).
- **Use `scripts/utils/validate_rules.py**` to validate all rules:
  ```bash
  python scripts/utils/validate_rules.py
  ```

#### **📜 Example PR for YARA Rules**

```markdown
## Add YARA Rule for New Android Spyware

### Description
- **What**: Added a YARA rule to detect a new Android spyware variant (SpywareX).
- **Why**: SpywareX is a new threat targeting Android devices, with known strings and C2 IPs.
- **How Tested**: 
  - Tested against a sample SpywareX APK.
  - Verified no false positives on benign Android apps.

### Related Issues
- Closes #456 (Request for SpywareX detection)

### Files Changed
- `rules/yara/spyware/android_spywarex.yar` (new rule)
- `tests/fixtures/samples/malicious/spywarex.apk` (test sample)
```

---

### **3. Documentation Contributions**

#### **📚 Where to Add Documentation**


| **Type**         | **Directory**            | **Example Files**                         |
| ---------------- | ------------------------ | ----------------------------------------- |
| Reports          | `docs/reports/`          | `SpySentry_v1.0_Report.md`                |
| User Guides      | `docs/user_guides/`      | `Detection_Guide.md`                      |
| Developer Guides | `docs/developer_guides/` | `YARA_Rule_Writing.md`                    |
| Case Studies     | `docs/reports/`          | `CASE_STUDIES.md`                         |
| Diagrams         | `docs/assets/diagrams/`  | `Infection_Levels_Hierarchy.mmd`          |
| Tables           | `docs/assets/tables/`    | `Infection_Levels_vs_Countermeasures.csv` |


#### **📝 Documentation Style**

- Use **Markdown** for all documentation.
- **Headers**: Use **ATX-style headers** (`#`, `##`, `###`).
- **Lists**: Use **hyphens** (`-`) for bullet points.
- **Code Blocks**: Use **fenced code blocks** with language specification:
  ```markdown
  ```python
  def example():
      print("Hello, SpySentry!")
  ```
  ```
- **Tables**: Use **GitHub-flavored Markdown tables**:
  ```markdown
  | Column 1 | Column 2 |
  |----------|----------|
  | Row 1    | Data 1   |
  | Row 2    | Data 2   |
  ```
- **Links**: Use **relative paths** for internal links:
  ```markdown
  [Detection Guide](../user_guides/Detection_Guide.md)
  ```

---

### **4. Testing**

#### **🧪 Unit Tests**

- Add **unit tests** for new functionality in `tests/unit/`.
- Use `**pytest**` for testing:
  ```bash
  pip install pytest
  pytest tests/unit/test_yara_scanner.py -v
  ```
- **Example Test**:
  ```python
  # tests/unit/test_yara_scanner.py
  import pytest
  from src.scanners.yara_scanner.scanner import YARAScanner

  def test_yara_scanner_init():
      scanner = YARAScanner(rules_dir="rules/yara")
      assert scanner.rules is not None

  def test_yara_scanner_scan():
      scanner = YARAScanner(rules_dir="rules/yara")
      results = scanner.scan(path="tests/fixtures/samples/benign/test_file.exe")
      assert "detections" in results
  ```

#### **🧪 Integration Tests**

- Add **integration tests** in `tests/integration/`.
- Test **interactions between modules** (e.g., YARA + OSSEC).
- **Example Test**:
  ```python
  # tests/integration/test_yara_ossec_integration.py
  from src.scanners.yara_scanner.scanner import YARAScanner
  from src.scanners.behavioral_analysis.ossec_integration import OSSECIntegration

  def test_yara_ossec_integration():
      yara_scanner = YARAScanner(rules_dir="rules/yara")
      ossec = OSSECIntegration(config_path="configs/ossec_config.xml")
      # Test integration logic here
      assert True
  ```

#### **📦 Test Fixtures**

- Add **test files** (e.g., benign/malicious samples) to `tests/fixtures/samples/`.
- Add **test logs** to `tests/fixtures/logs/`.
- **Never commit real malware** to the repository. Use **synthetic samples** or **hashed placeholders**.

---

## **📌 Code of Conduct**

### **🤝 Be Respectful**

- **Inclusive Language**: Avoid **exclusionary language** (e.g., gendered, ableist).
- **Constructive Feedback**: Provide **actionable, respectful feedback** in PRs and issues.
- **No Harassment**: Harassment of any kind is **not tolerated**.

### **🔒 Security**

- **No Malicious Code**: Do **not** commit **malware, exploits, or malicious payloads** to the repository.
- **Responsible Disclosure**: If you discover a **vulnerability** in SpySentry, **report it privately** to [spysentry@transparency-x.org](mailto:spysentry@transparency-x.org) before disclosing publicly.
- **Ethical Use**: SpySentry is for **defensive security purposes only**. Do **not** use it for **malicious activities**.

### **📜 Licensing**

- **Your Contributions**: By contributing to SpySentry, you agree to license your contributions under the **MIT License** (see [LICENSE](LICENSE)).
- **Third-Party Code**: If you include **third-party code**, ensure it is **compatible with MIT** and **properly attributed**.

---

## **📌 Reporting Issues**

### **🐛 Bug Reports**

1. **Check Existing Issues**: Search [GitHub Issues](https://github.com/Transparency-X/spysentry/issues) to ensure the bug hasn't already been reported.
2. **Create a New Issue**:
  - **Title**: Clear and descriptive (e.g., "YARA Scanner Fails on Large Files").
  - **Description**: Include:
    - **Steps to Reproduce**: How can we reproduce the bug?
    - **Expected Behavior**: What should happen?
    - **Actual Behavior**: What happens instead?
    - **Environment**: OS, Python version, SpySentry version, etc.
    - **Logs/Errors**: Include **relevant logs or error messages**.
    - **Screenshots**: If applicable.
  - **Labels**: Add relevant labels (e.g., `bug`, `yara-scanner`, `high-priority`).

### **🔍 Threat Reports**

1. **Check Existing Reports**: Search the [SpySentry v1.0 Report](docs/reports/SpySentry_v1.0_Report.md) and [YARA Rules Report](docs/reports/YARA_Rules_and_Complementary_Approaches.md) to ensure the threat isn't already documented.
2. **Create a New Issue**:
  - **Title**: Clear and descriptive (e.g., "New Android Spyware: SpywareX").
  - **Description**: Include:
    - **Threat Name**: Name of the spyware/stalkerware.
    - **Threat Type**: Spyware, stalkerware, RAT, etc.
    - **Target Platforms**: Android, iOS, Windows, etc.
    - **Infection Vector**: How does it spread? (e.g., phishing, app sideloading).
    - **Persistence Mechanisms**: How does it maintain access? (e.g., cron jobs, startup entries).
    - **IoCs**: Indicators of Compromise (IPs, domains, hashes, strings).
    - **Behavior**: What does it do? (e.g., keylogging, data exfiltration).
    - **References**: Links to **articles, reports, or samples** (if public).
  - **Labels**: Add relevant labels (e.g., `threat-report`, `spyware`, `new-threat`).

---

## **📌 Recognition**

All contributions to SpySentry are **greatly appreciated**! Contributors will be recognized in:

- The `**CONTRIBUTORS.md**` file (coming soon).
- The **release notes** for each version.
- **GitHub Contributors** tab on the repository.

---

## **📌 Support**

If you have questions or need help:

1. **GitHub Discussions**: Start a [new discussion](https://github.com/Transparency-X/spysentry/discussions) for general questions.
2. **GitHub Issues**: Open an [issue](https://github.com/Transparency-X/spysentry/issues) for bugs or feature requests.
3. **Email**: Contact [spysentry@transparency-x.org](mailto:spysentry@transparency-x.org) for private matters.

---

---

## **🙏 Thank You!**

Your contributions help make **SpySentry** a **powerful, community-driven tool** for detecting and mitigating spyware/stalkerware threats. Together, we can **fight digital surveillance** and **protect privacy**.

---

> **🔒 Stay Secure. Stay Informed.**  
> *SpySentry – Your Guardian Against Digital Surveillance.*
