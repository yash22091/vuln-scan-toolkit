# vuln-scan — Automated Multi-Tool Vulnerability Scanner (Host + Docker)

`vuln-scan` is a **comprehensive, plug-and-play vulnerability scanning utility** that works seamlessly in **both host mode** and **containerized environments**. It bundles multiple leading open-source security scanners to scan application code, binaries, Dockerfiles, IaC, and SBOMs.

### Features

- Unified scanner wrapper with interactive and CLI modes
- Supports containerized execution with volume mounting
- Auto-generates a searchable, paginated HTML dashboard
- Extracts archives (`.zip`, `.tar.gz`, `.deb`, `.rpm`) before scanning
- Automatically installs tools in host-mode if not present

---

## 🔧 Scanners Used

| Scanner                | Use Case                                  |
|------------------------|-------------------------------------------|
| OWASP Dependency-Check | 3rd-party CVEs in JARs, packages          |
| Trivy                  | CVE & misconfig scan (FS & containers)    |
| Grype                  | Advanced CVE scanner with SBOM support    |
| KICS                   | IaC misconfiguration detection (Terraform)|
| Hadolint               | Dockerfile best practice linter           |
| Syft                   | SBOM generator (CycloneDX JSON)           |

---

## Usage Examples

### Docker Mode (Run All Scanners)
```bash
docker run --rm -it \
  -v /tmp/test-deb/:/input \
  -v /root/automatedscanner/results:/results \
  vuln-scan:latest \
  -s all -p /input/ -o /results
````

### Docker Mode (Run a Single Scanner)

```bash
docker run --rm -it \
  -v /tmp/test-deb/:/input \
  -v /root/automatedscanner/results:/results \
  vuln-scan:latest \
  -s trivy -p /input/* -o /results
```

> **NOTE**: The `-it` flag is **required** for interactive format/API prompts.

---

### Host Mode (All Scanners)

```bash
./dynamic_scan.sh -s all -p /path/to/code -o ./results
```

### Host Mode (Single Scanner)

```bash
./dynamic_scan.sh -s kics -p /path/to/terraform -o ./results
```

---

## Interactive Dashboard (HTML)

After the scan completes, a **dashboard** is generated:

```bash
./results/Dashboard.html
```

To view it:

```bash
cd results
python3 -m http.server 9000
# Open http://localhost:9000 in your browser
```

> The dashboard includes **interactive tables** for Trivy, Grype, Hadolint, SBOM, and embeds Dependency-Check/KICS HTML output.

---

## Use Cases

* CI/CD pipeline security validation
* Manual security testing of code drops/packages
* Offline/air-gapped security assessments
* Quick SBOM + CVE mapping from `.deb`, `.rpm`, `.jar`, `.zip`
* IaC & Dockerfile misconfiguration detection

---

## Important Notes

* **Dependency-Check** will download the NVD database on first use (\~10–15 mins)
* Scans are fully offline after initial database population
* KICS and Hadolint are run against Terraform and Dockerfile paths respectively
* SBOM is generated using Syft (CycloneDX JSON) and visualized in the dashboard

---

## Requirements (for Host Mode)

* bash, curl, unzip, tar, jq, git
* Java Runtime (default-jre-headless)
* [.NET Runtime 8.0](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
* Internet access (initial DB/tool install)

> All tools are **auto-installed** in host mode if not found.

---

## Docker Image Build (Optional)

To build locally:

```bash
docker build -t vuln-scan:latest .
```

> The image includes all tools preinstalled, including Dependency-Check, Trivy, Grype, Hadolint, KICS, Syft, and .NET runtime.

---

MIT License · Maintained by Yash Patel

```
