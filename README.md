# vuln-scan — Automated Multi-Tool Vulnerability Scanner (Host + Docker)

`vuln-scan` is a **comprehensive, plug-and-play vulnerability scanning utility** that works seamlessly in **both host mode** and **containerized environments**. It bundles multiple leading open-source security scanners to scan application code, binaries, Dockerfiles, IaC, and SBOMs.

### Features

- Unified scanner wrapper with interactive and CLI modes
- Supports containerized execution with volume mounting
- Auto-generates a searchable, paginated HTML dashboard
- Extracts archives (`.zip`, `.tar.gz`, `.deb`, `.rpm`) before scanning
- Automatically installs tools in host-mode if not present

---

## Scanners Used

| Scanner                | Use Case                                  |
|------------------------|-------------------------------------------|
| OWASP Dependency-Check | 3rd-party CVEs in JARs, packages          |
| Trivy                  | CVE & misconfig scan (FS & containers)    |
| Grype                  | Advanced CVE scanner with SBOM support    |
| KICS                   | IaC misconfiguration detection (Terraform)|
| Hadolint               | Dockerfile best practice linter           |
| Syft                   | SBOM generator (CycloneDX JSON)           |

---

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/yash22091/vuln-scan-toolkit.git
cd vuln-scan-toolkit
chmod +x dynamic_scan.sh
docker build -t vuln-scan:latest . (For Container Build Locally)
```

## Usage Examples

### Docker Mode

> Run in **interactive mode** (`-it`) to allow format prompts or scanner selection.

#### Run All Scanners
```bash
docker run --rm -it \
  -v /tmp/test-deb/:/input \
  -v /root/automatedscanner/results:/results \
  vuln-scan:latest \
  -s all -p /input/ -o /results
````

#### Run a Specific Scanner (e.g., Trivy only)

```bash
docker run --rm -it \
  -v /tmp/test-deb/:/input \
  -v /root/automatedscanner/results:/results \
  vuln-scan:latest \
  -s trivy -p /input/ -o /results
```

---

### Host Mode (Without Docker)

> All tools will auto-install if missing.

#### Scan All Tools

```bash
./dynamic_scan.sh -s all -p /path/to/code -o ./results
```

#### Scan Only KICS (IaC)

```bash
./dynamic_scan.sh -s kics -p /path/to/terraform -o ./results
```

---

## Interactive Dashboard (HTML)

After a scan completes, an HTML dashboard is generated at:

```bash
./results/Dashboard.html
```

### Serve Dashboard via Python

```bash
cd ./results
python3 -m http.server 9000
```

Then open [http://localhost:9000](http://localhost:9000) in your browser.

The dashboard supports:

* Paginated, searchable tables for:

  * Trivy vulnerabilities
  * Grype matches
  * Hadolint lint findings
  * SBOM (Syft CycloneDX)
* Embedded HTML for:

  * Dependency-Check reports
  * KICS analysis

---

## Tools Integrated and How They're Leveraged

| Tool                 | Purpose                            | Targets                                |
| -------------------- | ---------------------------------- | -------------------------------------- |
| **Dependency-Check** | CVEs in 3rd-party dependencies     | JARs, NPM, NuGet, Python, etc.         |
| **Trivy**            | FS/image/IaC vulnerability scanner | Filesystem, Docker images, IaC configs |
| **Grype**            | Image/Dir/SBOM CVE scanner         | Linux packages and layers              |
| **KICS**             | IaC misconfiguration scanner       | Terraform files                        |
| **Hadolint**         | Dockerfile linter                  | Dockerfiles                            |
| **Syft**             | SBOM generator                     | Any directory or image                 |

---

## Use Cases

* Secure open-source project drops (JAR, ZIP, RPM, DEB)
* Pre-deployment validation in CI/CD pipelines
* Offline/air-gapped vulnerability analysis
* Infrastructure-as-Code (IaC) security hardening
* SBOM generation and CVE impact review

---

##  Notes

* **Dependency-Check takes \~15 minutes** on first run to populate the NVD database (in both Docker and Host).
* Subsequent scans reuse that data unless explicitly removed.
* You can pre-pull and reuse the Docker image without rebuilding.
* Hadolint results are now fixed and visualized correctly in the HTML dashboard.

---

## Docker Build (Optional)

If building manually:

```bash
docker build -t vuln-scan:latest .
```

---

## Folder Structure (Example)

```
.
├── Dockerfile
├── dynamic_scan.sh
├── scan-results/
│   ├── trivy-report.json
│   ├── grype-report.json
│   ├── hadolint-report.json
│   ├── sbom-syft.cyclonedx.json
│   └── Dashboard.html
```

---

## Requirements (Host Mode Only)

* bash, curl, unzip, tar, jq, git
* Java Runtime (`default-jre-headless`)
* .NET Runtime 8.0 (`dotnet-install.sh`)
* Internet access (for first-time installs)

> All binaries like Trivy, Grype, KICS, Hadolint, and Syft are auto-installed if missing.

---

## Tips

* You can scan `.jar`, `.zip`, `.deb`, `.rpm`, `.tf`, `Dockerfile`, etc.
* SBOM generated with Syft (CycloneDX JSON) is visualized in the HTML dashboard.
* All scanner outputs go to the `-o` folder (default `./scan-results`)

---
