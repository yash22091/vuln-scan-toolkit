# vuln-scan-toolkit

A versatile, plug-and-play **vulnerability scanning toolkit** that works seamlessly **on the host** or inside a **Docker container**. It bundles the best open-source security tools to perform comprehensive security checks and generates a **self-contained HTML dashboard** for visualizing results.

---

## Key Features

- **Dual Environment Support**: Run as a container or directly on your host system
- **Scans Code, Containers, IaC, Packages, Dockerfiles, SBOMs**
- **Interactive Dashboard**: Clean HTML report with tables, filters, and pagination
- **Supports Archives**: `.zip`, `.tar.gz`, `.deb`, `.rpm`
- **Auto-Detection**: Scanners auto-selected based on input contents
- **Self-Contained Script**: One `dynamic_scan.sh` does everything

---

## Tools Integrated and How They're Leveraged

| Tool | Use Case | What It Scans |
|------|----------|---------------|
| **Dependency-Check** | Detects known vulnerabilities (CVEs) in 3rd-party Java, JS, Python, etc. | `.jar`, `pom.xml`, `package.json`, `go.mod` |
| **Trivy** | Vulnerability and config scanner | Filesystem, Docker images, IaC |
| **Grype** | Vulnerability scanner using SBOM or direct directory/image scan | Linux packages, container layers |
| **KICS** | Infrastructure as Code misconfiguration scanner | `.tf` (Terraform files) |
| **Hadolint** | Dockerfile best practices and linting | `Dockerfile` |
| **Syft** | SBOM (CycloneDX JSON) generator | Any directory or image contents |

---

## Use Cases

- **CI/CD Security Gate**
- **DevSecOps Pipelines**
- **SBOM Audits & Compliance**
- **Pre-deployment Container Scans**
- **IaC Security Review**
- **Local Security Checks (Developers)**

---

## Usage
### Docker Mode (RECOMMENDED)

docker run -it --rm -v $(pwd):/input vuln-scan-toolkit -p /input -s all

    IMPORTANT: Run with -it (interactive) so the scanner can ask for API keys or format options.

    The results will be saved in /input/scan-results (mounted from your host).

* `-p /input`: Path to scan inside container
* `-s all`: Run all supported scanners

> The results will be in `/input/scan-results` on your host.

### Live Dashboard via Python HTTP Server

```bash
cd scan-results
python3 -m http.server 9000
# Open http://localhost:9000/Dashboard.html in browser
```

---

### Host Mode

Just clone the repo and run:

```bash
chmod +x dynamic_scan.sh
./dynamic_scan.sh -p ./your_project -s all
```

> Works on any modern Linux system. Installs missing tools automatically.

---

## ommand-Line Options

| Flag | Description                                                  |
| ---- | ------------------------------------------------------------ |
| `-p` | Path to scan (dir/archive/image)                             |
| `-s` | Comma-separated scanners to use (`trivy,grype,...`) or `all` |
| `-o` | Output folder (default: `./scan-results`)                    |
| `-a` | Auto-detect scanners based on file types                     |
| `-g` | Grype source (e.g. `dir:/path`, `docker:nginx`)              |
| `-h` | Show help                                                    |

---

## Sample Dashboard Screenshot

![Sample Dashboard](docs/sample-dashboard.png)

> Dashboard includes searchable, paginated tables for:
>
> * Trivy vulnerabilities
> * Grype scan results
> * SBOM components (from Syft)
> * Dockerfile issues (Hadolint)
> * And embedded HTML reports from Dependency-Check, KICS

---

##  Requirements

For host mode (auto-installed if missing):

* Bash
* curl, unzip, git
* Java 11+, Go 1.24 (for KICS)
* .NET 8 Runtime (for Dependency-Check)

For container mode:

* Just Docker. Everything is baked in.

---

## Example: Scan Dockerfile and Terraform

```bash
./dynamic_scan.sh -p ./project-dir -s hadolint,kics
```

* Hadolint will lint your Dockerfile
* KICS will scan Terraform configs

---

## Example: Use in CI

```yaml
- name: Run Vulnerability Scan
  run: |
    docker run --rm -v $PWD:/input vuln-scan-toolkit -p /input -s all
```

> Add artifact upload for `scan-results/Dashboard.html`

---

## License

MIT © 2024+

---

## Contribute

Pull requests are welcome. You can:

* Add support for more formats (SARIF, SPDX)
* Improve HTML dashboard UI
* Add auto-upload to S3/GitHub Pages

---

## Star This Repo If You Find It Useful!
