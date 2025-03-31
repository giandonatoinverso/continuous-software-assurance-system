**Software Assurance System** is a Python-based core module, developed as part of [my master's thesis](https://giandonatoinverso.dev/#portfolio), implementing an innovative methodology for software assurance.  It is designed to be integrated into DevSecOps environments within CI/CD pipelines.

The software aims to overcome the limitations of existing security check orchestrators by addressing more realistic and heterogeneous scenarios, where complex infrastructures span across diverse technology stacks and may include external or remote devices.

# Integrated Security Checks

This software performs a coordinated set of security checks on multiple targets by integrating four well-established tools:

- [Gosec](https://github.com/securego/gosec) is a static code analysis tool that scans Golang source code for common security issues. In this project, it is used to analyze Go projects that have been previously downloaded and stored locally.

- [Bandit](https://bandit.readthedocs.io/en/latest/) is a similar tool focused on Python. It inspects Python codebases for potential vulnerabilities and bad security practices. The software runs Bandit on local Python projects to detect weaknesses early in the development cycle.

- [Trivy](https://github.com/aquasecurity/trivy) is a powerful, all-in-one vulnerability scanner developed by Aqua Security. It supports scanning source code, container images, file systems, and even Git repositories. Within this software, Trivy is used in three modes: 
  - Local source code scanning
  - Container image scanning based on services defined in a `docker-compose` file
  - Remote filesystem scanning via SSH to identify known vulnerabilities.

- [Lynis](https://cisofy.com/lynis/) is a security auditing tool for Unix-based systems that focuses on system hardening. It is executed remotely over SSH to assess the security posture of external devices and provide actionable hardening recommendations.

These tools are orchestrated to run as part of a unified assurance process, allowing for a comprehensive assessment of software artifacts and infrastructure components across different stages of the DevSecOps lifecycle.

# Project Structure

Allora spieghiamo la struttura del progetto. Io ti dico in breve cosa c'è e tu estendi:

## `utils/` – Utility Scripts
  - Cartella contenente script di utility:
    - Python script defines a utility class for processing, merging, and visualizing CVE vulnerability data from security scanners, sorting entries by severity and enriching them with details such as CWE, CVSS V2/V3 scores, and affected targets.
    - Python script defines a utility class for extracting and normalizing Docker image names from `docker-compose.yml` files, optionally replacing environment variables defined in a `.env` file to return a clean list of service images. 
    - Python script implements a wrapper class based on `fabric` and `paramiko` to establish SSH connections using either password or private key authentication, allowing remote command execution with exit code handling, as well as file transfer to and from remote hosts.
    - Python script defines a utility class for common repository and file system operations, including cloning Git repositories (with optional access token support), downloading files from remote URLs with authentication headers, and recursively deleting the contents of local directories.

## `security_controls/` – Executable Security Modules

The `security_controls` directory contains a set of modular Python classes, each implementing an automated security control. These controls are designed to evaluate codebases, Docker environments, filesystems, and remote systems through static analysis or system audit tools.
All controls share a common structure and lifecycle:

- **Initialization (`__init__`)**  
  Each class receives configuration parameters like paths, credentials, thresholds, and authentication tokens.

- **Standard Workflow (`execute()` method)**  
  Every control follows this orchestration pattern:
  1. `download_resources()` – Fetches or prepares required resources (e.g. repositories, compose files, binaries).
  2. `*_execute()` – Runs the actual scanning or auditing tool.
  3. `generate_output()` – Parses, aggregates and optionally formats results (e.g., HTML, JSON).
  4. `evaluate_output()` – Applies evaluation logic based on severity levels, hardening score, or thresholds.
  5. `clean()` – Cleans up temporary or remote files.

- **Return Value**  
  All controls return `0` for **pass** and `1` for **fail**, enabling integration into larger CI/CD or compliance pipelines.

### Available Security Controls

- **bandit**
  - It clones the target repository, runs Bandit, parses vulnerabilities grouped by CWE and target, and evaluates the findings against a configurable severity threshold.
  
- **Gosec**
  - It clones the repository, runs the scanner, processes and evaluates the output based on severity levels to determine compliance.

- **Lynis**
  - It connects via SSH, installs and executes Lynis remotely, parses the report into structured sections, and evaluates the result based on the hardening index.

- **Trivy**
  - Wraps Trivy to run vulnerability scans in three different modes, it groups vulnerabilities by CVE, formats the output (HTML/JSON), and checks severity levels against a threshold:
    - `trivy_docker`: scans Docker images from a compose file
    - `trivy_fs`: scans a local filesystem (repository)
    - `trivy_remotefs`: scans a remote root filesystem over SSH

### Config folder
The `config/` directory contains the centralized configuration for running the security controls defined in the `security_controls/` module. It enables project-specific setup for both **which security checks to run** and **how to authenticate** against local, remote, or cloud resources.

#### `config/` – Execution Logic per Target

This file defines **which security controls are executed for each project**, along with their parameters, output paths, and evaluation policies.

Each top-level key (e.g. `Mainflux`, `HomeAssistant`, `ExternalDevice`) represents a distinct target system or codebase.

Each target system contains:

- `security_controls`: a set of tools to run (e.g. `bandit`, `gosec`, `trivy_docker`, `lynis`), each with:
  - `credential`: an optional key referencing the matching entry in `credential.json`
  - `name`: display name
  - `target`: URL (for code) or hostname/IP (for remote systems)
  - Optional parameters specific to the tool (e.g. `compose_file`, `env_file`, `version`, `skip_test`, etc.)
  - `raw_output`, `final_output`, `report_output`: output filenames (JSON/HTML)
  - `evaluation`: criteria for pass/fail (e.g., `severity` + `threshold`, or `hardening_index_threshold`)

- `threats`: a mapping of threat categories to CWE IDs, enabling post-processing and risk mapping of discovered vulnerabilities.

#### `credential.json` - Secure Access Config

This file contains the **authentication credentials** referenced in `config.json` under the `credential` field.

Each entry is a key-value map identified by a unique name (e.g. `mainflux`, `home_assistant`, `external_device`) and contains:
- For public repos: `oauth_token`
- For Docker: `username`, `password`
- For remote systems: `username`, `password`, `private_key`

### `parser/` – Output Post-Processing

The `parser/` directory contains modules responsible for transforming the raw output of external security tools into structured and normalized JSON formats. These parsers are designed to reduce, sanitize, and aggregate results for subsequent reporting, evaluation, and threat mapping.

All parsers share a consistent pattern across tools:

- **Initialization**
  Each parser is initialized with the path to a raw report. It may immediately clean or sanitize the content (e.g., remove metadata, escape characters, error blocks).

- **Content Access**
  Methods like `get_content()` or `print_json()` are provided to retrieve or inspect the loaded data.

- **Aggregation by CWE**
  Parsers group findings by CWE identifiers and affected targets (e.g., file paths, services), consolidating multiple occurrences of the same issue.

- **Reduced JSON Output**
  The resulting JSON is significantly reduced compared to the original tool output, keeping only relevant fields such as:
  - CWE
  - Affected targets (with line/column or logical path)
  - Severity and confidence levels
  - Descriptive details

- **HTML Generation**
  Most parsers include support to export the cleaned data as an HTML table for reporting purposes, with sorting and grouping based on severity and confidence.

### `data/` and `aggregation/` folders

The data/ folder contains all raw and post-processed JSON files from security tools, as well as comprehensive aggregation reports generated by the aggregation logic (aggregation/cwe.py). These reports summarize vulnerabilities and threats across multiple dimensions using several analytical techniques.

# Results aggregation and reporting

The aggregation process performs various computations over the processed security reports, based on the `config.json` file which defines the threat categories and the corresponding CWEs to track. The resulting metrics include:

1. **Unique CVEs and CWEs**
2. **Severity distributions**
3. **Threat analysis**
4. **Risk calculations**

Each metric is computed across all tools and components defined in the configuration.

## 1. **Unique CVEs and CWEs**
- Extracts and counts all distinct **CVEs** and **CWEs** found in the post-processed reports.
- Handles deduplication across tools that may report the same vulnerability multiple times.

## 2. **Severity Distribution**
- Calculates the distribution of vulnerabilities across five severity levels:
  - `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`
- Computed both globally and per tool/category.

## 3. **Threat Analysis**
- Maps each CWE to one or more **threat categories**, as defined in the configuration file.
- Aggregates CVEs/CWEs according to their threat associations.

### **Found CWEs**
- Computes the intersection between the expected CWEs (from config) and the ones actually found in reports.
- Outputs coverage metrics: how many relevant CWEs were actually detected.

### **CWE-to-Category Distribution**
- For each category, shows how many of the expected CWEs were matched in findings.
- Useful to identify which macro-components are more/less affected.

### **Filtered Severity Distribution**
- Like section 2, but filtered to only consider CVEs associated with a relevant CWE (according to the threat model).
- Provides severity insights specific to domain-relevant vulnerabilities.

## 4. Risk Score Calculations

Risk metrics are computed using both **severity level** and **CVSS v3 score (V3Score)**. When no V3Score is available, a fallback strategy is applied.

### **Overall Risk Score**

![overall risk formula](https://latex.codecogs.com/png.image?\dpi{120}&space;riskScore=\frac{\sum_{i=1}^{n}(s_i\cdot{v_i})}{(n_v\cdot{s_{max}}\cdot{v_{max}})+(n_{nv}\cdot{s_{max}}\cdot{1})}\cdot{100})

Where:
- *sᵢ*: severity score of vulnerability *i*
- *vᵢ*: V3Score of vulnerability *i*
- *nᵥ*: number of vulnerabilities with V3Score
- *nₙᵥ*: number of vulnerabilities without V3Score
- *sₘₐₓ*: max severity score (9)
- *vₘₐₓ*: max V3Score (10)

---

### **Risk Score per CWE**

![risk per cwe formula](https://latex.codecogs.com/png.image?\dpi{120}&space;riskScoreCWE_j=\left(\frac{\sum_{i=1}^{n_j}(s_{ij}\cdot{v_{ij}})}{(n_{vj}\cdot{s_{max}}\cdot{v_{max}})+(n_{nvj}\cdot{s_{max}}\cdot{1})}\right)\cdot\frac{n_j}{n_{max}}\cdot{100})

- Computed per CWE.
- Normalized by the number of findings to avoid overweighting less frequent but severe CWEs.

---

### **Risk Score per Threat**

![risk per threat formula](https://latex.codecogs.com/png.image?\dpi{120}&space;riskScoreThreat_k=\left(\frac{\sum_{j=1}^{m_k}\sum_{i=1}^{n_{jk}}(s_{ijk}\cdot{v_{ijk}})}{(n_{vjk}\cdot{s_{max}}\cdot{v_{max}})+(n_{nvjk}\cdot{s_{max}}\cdot{1})}\right)\cdot\frac{N_k}{N_{max}}\cdot{100})

- Computed per threat.
- Aggregates all CWEs under the same threat and applies normalization using the threat with the highest number of findings.

---

### **CVE Distribution per Tool**

- For each CWE and category, shows how many tools detected matching CVEs.
- Output is presented as a matrix of `CWE × Tool` with total counts.

---

### **Severity Distribution per Label**

- Severity-level distribution of CVEs per tool (label).
- Helps assess the detection quality and focus of each security control.
