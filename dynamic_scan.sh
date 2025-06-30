#!/usr/bin/env bash
set -euo pipefail

#-----------------------------------------
# Dynamic Vulnerability Scan Script
# Supports: dependency-check, trivy, grype, kics, hadolint
#-----------------------------------------

# Defaults
OUTPUT_DIR="$(pwd)/scan-results"
TARGET_PATH=""
SCANNERS_ENV="${SCANNERS:-}"
SCANNERS=()
AUTO_DETECT=0

# allow overriding the Grype source via CLI or env
GRYPE_SOURCE_ENV="${GRYPE_SOURCE:-}"
GRYPE_SOURCE=""

# Supported output formats
DCO_OPTIONS=(CSV HTML JSON XML SARIF JUNIT JENKINS GITLAB ALL)
TRIVY_OPTIONS=(json table template)

#––– Usage/help –––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
usage() {
  cat <<EOF
Usage: $0 [-p path] [-s scanners] [-o output_dir] [-a] [-g grype_source] [-h]

  -p path       Directory/archive to scan (default: cwd)
  -s scanners   Comma-sep list: dependency-check,trivy,grype,kics,hadolint
                Overrides auto-detect; default = interactive prompt
  -o dir        Output directory (default: ./scan-results)
  -a, --auto    Auto-select scanners based on file types
  -g, --grype   Grype source scheme (e.g. dir:/path, docker:nginx:latest,
                docker-archive:/img.tar, oci-archive:/img.tar, sbom:/sbom.json,
                registry:alpine:3.18, singularity:/img.sif). Defaults to dir:\$SCAN_ROOT
  -h, --help    Show this help

Scanner Capabilities:
  • dependency-check  → 3rd-party CVE analysis (JARs, NPM, NuGet…)
  • trivy             → Filesystem/container CVE & misconfig scan
  • grype             → Anchore CVE scan (dir or image)
  • kics              → IaC misconfig check (Terraform only)
  • hadolint          → Dockerfile lint best practices

Examples:
  $0                               # interactive: prompts & scans cwd
  $0 -p ./app -s trivy,grype       # only Trivy & Grype on ./app
  $0 -p code.tar.gz -o results     # extract & scan archive
  $0 -a -p ./repo -o reports       # auto-pick based on ./repo
EOF
  exit 1
}

#––– Parse args (with long options) –––––––––––––––––––––––––––––––––––––––––
while getopts "p:s:o:ag:h-:" opt; do
  case "$opt" in
    p) TARGET_PATH="$OPTARG" ;;
    s)
      # if they said "-s all", immediately expand to the full scanner list
      if [[ "$OPTARG" == all ]]; then
        SCANNERS=(dependency-check trivy grype kics hadolint)
      else
        IFS=',' read -ra SCANNERS <<< "$OPTARG"
      fi
      ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    a) AUTO_DETECT=1 ;;
    g) GRYPE_SOURCE="$OPTARG" ;;
    h) usage ;;
    -)
      case "${OPTARG}" in
        grype)    GRYPE_SOURCE="${!OPTARG#grype=}" ;;
        auto)     AUTO_DETECT=1              ;;
        help)     usage                      ;;
        *)        echo "Unknown option --${OPTARG}" >&2; usage ;;
      esac
      ;;
    *) usage ;;
  esac
done

# fallback to env if no CLI
GRYPE_SOURCE="${GRYPE_SOURCE:-${GRYPE_SOURCE_ENV:-}}"

# If no -s but SCANNERS env var present, use that
if [[ ${#SCANNERS[@]} -eq 0 && -n "$SCANNERS_ENV" ]]; then
  IFS=',' read -ra SCANNERS <<< "$SCANNERS_ENV"
fi

# Expand “all” into the full list (so we never literally carry "all")
if [[ " ${SCANNERS[*]} " == *all* ]]; then
  SCANNERS=(dependency-check trivy grype kics hadolint)
fi

#––– Prompt for target path –––––––––––––––––––––––––––––––––––––––––––––––––
if [[ -z "$TARGET_PATH" ]]; then
  read -rp "Enter path to scan [$(pwd)]: " TARGET_PATH
  TARGET_PATH="${TARGET_PATH:-$(pwd)}"
fi

if [[ ! -e "$TARGET_PATH" ]]; then
  echo "Error: Path '$TARGET_PATH' does not exist." >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

#–––––– Auto-detect scanners if -a && none chosen –––––––––––––––––––––––––
declare -A want=()
if [[ $AUTO_DETECT -eq 1 && ${#SCANNERS[@]} -eq 0 ]]; then
  # dependency-check → JARs, pom.xml, package.json, go.mod
  if find "$TARGET_PATH" -maxdepth 7 -type f \
       \( -iname '*.jar' -o -iname 'pom.xml' -o -iname 'package.json' -o -iname 'go.mod' \) \
     | grep -q .; then
    want[dependency-check]=1
  fi
  # Dockerfile → hadolint, trivy, grype
  if find "$TARGET_PATH" -maxdepth 7 -type f -iname Dockerfile | grep -q .; then
    want[hadolint]=1
    want[trivy]=1
    want[grype]=1
  fi
  # Archives/packages → trivy, grype
  if find "$TARGET_PATH" -maxdepth 7 -type f \
       \( -iname '*.zip' -o -iname '*.tar*' -o -iname '*.deb' -o -iname '*.rpm' \) \
     | grep -q .; then
    want[trivy]=1
    want[grype]=1
  fi
  # IaC → kics (Terraform only)
  if find "$TARGET_PATH" -maxdepth 7 -type f -iname '*.tf' | grep -q .; then
    want[kics]=1
  fi
  # fallback = all
  if [[ ${#want[@]} -eq 0 ]]; then
    want=( [dependency-check]=1 [trivy]=1 [grype]=1 [kics]=1 [hadolint]=1 )
  fi

  SCANNERS=("${!want[@]}")
  echo "[*] Auto-detected scanners: ${SCANNERS[*]}"
fi

#––– Interactive prompt if still none –––––––––––––––––––––––––––––––––––––
if [[ ${#SCANNERS[@]} -eq 0 ]]; then
  echo "Available scanners: dependency-check, trivy, grype, kics, hadolint"
  read -rp "Enter scanners to run (comma-separated or 'all'): " scanner_input
  scanner_input="${scanner_input:-all}"
  if [[ "$scanner_input" == all ]]; then
    SCANNERS=(dependency-check trivy grype kics hadolint)
  else
    IFS=',' read -ra SCANNERS <<< "$scanner_input"
  fi
fi

#––– Prompt for optional API keys –––––––––––––––––––––––––––––––––––––––––––
for tool in dependency-check trivy grype; do
  name="${tool//-/_}"
  var="${name^^}_API_KEY"
  if [[ " ${SCANNERS[*]} " =~ " $tool " && -z "${!var:-}" ]]; then
    read -rp "Enter $tool API key (or leave empty to skip): " entry
    [[ -n "$entry" ]] && export "$var"="$entry"
  else
    echo "Using \$$var=${!var:-<none>}"
  fi
done

#––– Prompt & validate Dependency-Check formats –––––––––––––––––––––––––––––
if [[ " ${SCANNERS[*]} " =~ " dependency-check " ]]; then
  if [[ -n "${DCO_FORMATS:-}" && " ${DCO_OPTIONS[*]} " =~ " ${DCO_FORMATS} " ]]; then
    echo "Using DCO_FORMATS=$DCO_FORMATS"
  else
    while true; do
      read -rp "Dep-Check formats (${DCO_OPTIONS[*]}) [ALL]: " DCO_FORMATS
      DCO_FORMATS="${DCO_FORMATS:-ALL}"
      [[ " ${DCO_OPTIONS[*]} " =~ " ${DCO_FORMATS} " ]] && break
      echo "Invalid—choose from: ${DCO_OPTIONS[*]}"
    done
  fi
fi

#––– Prompt & validate Trivy format ––––––––––––––––––––––––––––––––––––––––––
if [[ " ${SCANNERS[*]} " =~ " trivy " ]]; then
  if [[ -n "${TRIVY_FORMAT:-}" && " ${TRIVY_OPTIONS[*]} " =~ " ${TRIVY_FORMAT} " ]]; then
    echo "Using TRIVY_FORMAT=$TRIVY_FORMAT"
  else
    while true; do
      read -rp "Trivy format (${TRIVY_OPTIONS[*]}) [json]: " TRIVY_FORMAT
      TRIVY_FORMAT="${TRIVY_FORMAT:-json}"
      [[ " ${TRIVY_OPTIONS[*]} " =~ " ${TRIVY_FORMAT} " ]] && break
      echo "Invalid—choose from: ${TRIVY_OPTIONS[*]}"
    done
  fi
fi



#───────────────────────────────────────────────────────────────────────────────
# Define host-mode installer commands (must come before usage below)
#───────────────────────────────────────────────────────────────────────────────

DCO_INSTALL='\
  VERSION=$(curl -s https://dependency-check.github.io/DependencyCheck/current.txt) && \
  curl -sL https://github.com/dependency-check/DependencyCheck/releases/download/v${VERSION}/dependency-check-${VERSION}-release.zip \
    -o /tmp/dc.zip && \
  rm -rf /opt/dependency-check && mkdir -p /opt/dependency-check && \
  unzip -qd /opt/dependency-check /tmp/dc.zip && rm /tmp/dc.zip && \
  ln -sf /opt/dependency-check/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh && \
  ln -sf /opt/dependency-check/dependency-check/bin/completion-for-dependency-check.sh /usr/local/bin/completion-for-dependency-check.sh'

GRYPE_INSTALL='curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin'

TRIVY_INSTALL='curl -sL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | bash -s -- -b /usr/local/bin && \
  rm -rf /root/.cache/trivy'

KICS_INSTALL='\
  rm -rf /tmp/kics && \
  git clone --depth 1 https://github.com/Checkmarx/kics.git /tmp/kics && \
  cd /tmp/kics && \
  # force go.mod to use “go 1.24” so any Go toolchain will accept it
  sed -i '\''s/^go .*/go 1.24/'\'' go.mod && \
  go mod download && \
  make build && \
  mv ./bin/kics /usr/local/bin/kics && \
  mkdir -p /usr/local/share/kics && \
  cp -r assets /usr/local/share/kics/ && \
  rm -rf /tmp/kics'

HADOLINT_INSTALL='curl -sL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
  -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint'

#───────────────────────────────────────────────────────────────────────────────
# Host-mode prerequisites & scanner installs (skipped in Docker)
#───────────────────────────────────────────────────────────────────────────────

install_go() {
  local version="${1:-1.24.1}"
  # only install if go missing or too old
  if ! command -v go &>/dev/null || [[ "$(go version)" != *"go${version}"* ]]; then
    echo "[*] Installing Go ${version} (host-mode)"
    # determine OS
    local os="$(uname | tr '[:upper:]' '[:lower:]')"
    # determine arch
    local arch="$(uname -m)"
    case "$arch" in
      x86_64) arch=amd64 ;;
      aarch64|arm64) arch=arm64 ;;
      *) echo "❌ Unsupported arch: $arch"; return 1 ;;
    esac
    # cleanup old install
    rm -rf /usr/local/go
    # fetch & extract
    curl -sSL "https://go.dev/dl/go${version}.${os}-${arch}.tar.gz" \
      | tar --no-same-owner -C /usr/local -xz
    # update PATH for rest of script
    export PATH="/usr/local/go/bin:$PATH"
  else
    echo "[*] Found Go: $(go version)"
  fi
}


if [[ -z "${CONTAINER_MODE:-}" ]]; then
  # 1) Detect package manager
  if   command -v apt-get &>/dev/null; then
    PM="apt-get update && apt-get install -y --no-install-recommends"
  elif command -v yum    &>/dev/null; then
    PM="yum install -y"
  elif command -v dnf    &>/dev/null; then
    PM="dnf install -y"
  elif command -v apk    &>/dev/null; then
    PM="apk add --no-cache"
  elif command -v brew   &>/dev/null; then
    PM="brew install"
  else
    echo "❌ No supported package manager. Install base tools manually." >&2
    exit 1
  fi

  # 2) Base tools everyone needs
  BASE_PKGS=(git curl unzip tar rpm2cpio cpio ca-certificates bash)

  # 3) Add scanner-specific prereqs
  if [[ " ${SCANNERS[*]} " =~ " dependency-check " ]]; then
    BASE_PKGS+=(default-jre-headless)    # Java for Dependency-Check
  fi
  if [[ " ${SCANNERS[*]} " =~ " kics " ]]; then
    BASE_PKGS+=(make binutils)
    install_go 1.24.1
  fi

  echo "[*] Installing prerequisites: ${BASE_PKGS[*]}"
  eval "$PM ${BASE_PKGS[*]}"

  # 4) For dependency-check, also install .NET 8.0 runtime
  if [[ " ${SCANNERS[*]} " =~ " dependency-check " ]]; then
    if ! command -v dotnet &>/dev/null; then
      echo "[*] Installing .NET 8.0 runtime (host-mode)"
      curl -sSL https://dot.net/v1/dotnet-install.sh \
        | bash /dev/stdin --runtime dotnet --channel 8.0 --install-dir /usr/share/dotnet
      export DOTNET_ROOT=/usr/share/dotnet
      export PATH="$PATH:/usr/share/dotnet"
    else
      echo "[*] dotnet already installed: $(dotnet --version)"
    fi
  fi

  # 5) Pull down only the selected scanner binaries
  install_if_missing() { command -v "$1" &>/dev/null || eval "$2"; }

  for tool in "${SCANNERS[@]}"; do
    case "$tool" in
      dependency-check)
        echo "[*] Installing OWASP Dependency-Check"
        install_if_missing dependency-check.sh "$DCO_INSTALL"
        ;;
      trivy)
        echo "[*] Installing Trivy"
        install_if_missing trivy "$TRIVY_INSTALL"
        ;;
      grype)
        echo "[*] Installing Grype"
        install_if_missing grype "$GRYPE_INSTALL"
        ;;
      kics)
        echo "[*] Installing KICS"
        install_if_missing kics "$KICS_INSTALL"
        ;;
      hadolint)
        echo "[*] Installing Hadolint"
        install_if_missing hadolint "$HADOLINT_INSTALL"
        ;;
      *)
        echo "⚠️  Skipping unknown scanner '$tool' in host-mode install"
        ;;
    esac
  done
fi

#––– Unpack archives/packages ––––––––––––––––––––––––––––––––––––––––––––––
TEMP_DIR="$(mktemp -d)"
case "$TARGET_PATH" in
  *.zip)   unzip -qq "$TARGET_PATH" -d "$TEMP_DIR" ;;
  *.tar.*) tar -xf "$TARGET_PATH" -C "$TEMP_DIR" ;;
  *.deb)
  ar x "$TARGET_PATH"
  if ls data.tar* &>/dev/null; then
    datafile=$(ls data.tar* | head -n1)
    tar -xf "$datafile" -C "$TEMP_DIR"
  else
    echo "[!] No data.tar found in .deb — skipping unpack."
  fi
  ;;
  *.rpm)
  rpm2cpio "$TARGET_PATH" | cpio -idm -D "$TEMP_DIR"
  rpm -qpi "$TARGET_PATH" > "$OUTPUT_DIR/rpm-info.txt" 2>/dev/null || echo "[!] RPM metadata not available"
  ;;
  *)        ;;
esac
SCAN_ROOT="$([[ -n "$(ls -A "$TEMP_DIR" 2>/dev/null)" ]] && echo "$TEMP_DIR" || echo "$TARGET_PATH")"

#––– Run each selected scanner –––––––––––––––––––––––––––––––––––––––––––––
for tool in "${SCANNERS[@]}"; do
  case "$tool" in
    dependency-check)
      echo "[*] OWASP Dependency-Check"
      #dependency-check.sh --project "scan-$(date +%s)" \
      #  --scan "$SCAN_ROOT" --format "$DCO_FORMATS" --out "$OUTPUT_DIR" \
      #  ${DEPENDENCY_CHECK_API_KEY:+--data "$DEPENDENCY_CHECK_API_KEY"}
      dependency-check.sh --project "scan-$(date +%s)" \
       --scan "$SCAN_ROOT" --format HTML --out "$OUTPUT_DIR"
      ;;
    trivy)
      echo "[*] Trivy"
      trivy fs --security-checks vuln,config \
        --format "$TRIVY_FORMAT" \
        --output "$OUTPUT_DIR/trivy-report.$TRIVY_FORMAT" \
        ${TRIVY_TOKEN:+--token "$TRIVY_TOKEN"} \
        "$SCAN_ROOT"
      ;;
    grype)
      echo "[*] Grype"
      export GRYPE_API_KEY=${GRYPE_API_KEY:-}
      src="${GRYPE_SOURCE:-dir:$SCAN_ROOT}"
      echo "-> Using Grype source: $src"
      grype "$src" -o json > "$OUTPUT_DIR/grype-report.json"
      ;;
    kics)
      echo "[*] KICS (IaC scan)"
     #kics scan -p "$SCAN_ROOT" \
     #   --queries-path /usr/local/share/kics/assets/queries \
     #   -o json --output-path "$OUTPUT_DIR/kics-report.json"
     kics scan -p "$SCAN_ROOT" --queries-path /usr/local/share/kics/assets/queries \
  --report-formats html --output-name kics-report.html -o "$OUTPUT_DIR" --no-color > "$OUTPUT_DIR/kics.log" 2>&1 || \
  echo "[!] KICS completed with findings (non-zero exit code ignored)"
      ;;
    hadolint)
      echo "[*] Hadolint (Dockerfile lint)"
      DOCKERFILES=$(find "$SCAN_ROOT" -type f -iname Dockerfile)

      if [[ -n "$DOCKERFILES" ]]; then
        echo "[*] Found Dockerfiles:"
        echo "$DOCKERFILES"

        hadolint_output_txt=""
        hadolint_output_json="[]"

        while IFS= read -r file; do
          result_txt=$(hadolint "$file" || true)
          result_json=$(hadolint -f json "$file" || echo "[]")

          if [[ -n "$result_txt" ]]; then
            hadolint_output_txt+=$'\n'"$file"$'\n'"$result_txt"$'\n'
          fi

          if [[ "$result_json" != "[]" ]]; then
            # Append JSON results into array
            hadolint_output_json=$(jq -s 'add' <(echo "$hadolint_output_json") <(echo "$result_json"))
          fi
        done <<< "$DOCKERFILES"

        if [[ -n "$hadolint_output_txt" ]]; then
          echo "$hadolint_output_txt" > "$OUTPUT_DIR/hadolint-report.txt"
          echo "$hadolint_output_json" > "$OUTPUT_DIR/hadolint-report.json"
          echo "[*] Hadolint issues written to report.txt and report.json"
        else
          echo "[*] Hadolint: no issues found."
          echo "[]" > "$OUTPUT_DIR/hadolint-report.json"
        fi
      else
        echo "[*] No Dockerfile found, skipping Hadolint."
        echo "[]" > "$OUTPUT_DIR/hadolint-report.json"
      fi
    ;;

    *)
      echo "⚠️  Warning: unknown scanner '$tool'"
      ;;
  esac
  echo
done

echo "[✓] Scans complete. Reports in $OUTPUT_DIR"

#───────────────────────────────────────────────────────────────────────────────
# 🧾 SBOM Generation (Host: Syft, Container: Trivy)
#───────────────────────────────────────────────────────────────────────────────

echo "[*] Generating SBOM..."

if [[ -z "${CONTAINER_MODE:-}" ]]; then
  # Host mode: Use Syft
  if ! command -v syft &>/dev/null; then
    echo "[*] Installing Syft (host-mode)"
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin
  fi
  syft dir:"$SCAN_ROOT" -o cyclonedx-json > "$OUTPUT_DIR/sbom-syft.cyclonedx.json" \
    && echo "[✓] SBOM generated with Syft → sbom-syft.cyclonedx.json"
else
  # Container mode: Also use Syft
  syft dir:"$SCAN_ROOT" -o cyclonedx-json > "$OUTPUT_DIR/sbom-syft.cyclonedx.json" \
    && echo "[✓] SBOM generated with Syft → sbom-syft.cyclonedx.json"
fi

# ── Build single‐page HTML dashboard ───────────────────────────────────────

DASH="$OUTPUT_DIR/Dashboard.html"
{
echo '<!doctype html>'
echo '<html lang="en">'
echo '<head>'
echo '  <meta charset="utf-8">'
echo '  <title>Vulnerability Scan Dashboard</title>'
echo '  <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">'
echo '  <style>'
echo '    body { font-family: sans-serif; margin: 1em; }'
echo '    section { margin-bottom: 3em; }'
echo '    h2 { border-bottom: 1px solid #ccc; padding-bottom: 5px; }'
echo '    pre, .embed-html { background: #f8f8f8; padding: 1em; border: 1px solid #ccc; overflow: auto; max-height: 600px; }'
echo '    table { border-collapse: collapse; width: 100%; margin-top: 1em; }'
echo '    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }'
echo '    th { background-color: #f2f2f2; }'
echo '  </style>'
echo '</head>'
echo '<body>'
echo "  <h1>Scan Results - $(date)</h1>"

# Dependency-Check
if [[ -f "$OUTPUT_DIR/dependency-check-report.html" ]]; then
  echo "  <section><h2>Dependency-Check</h2><div class='embed-html'>"
  sed 's/<script[^>]*>.*<\/script>//gI' "$OUTPUT_DIR/dependency-check-report.html"
  echo "</div></section>"
fi

# KICS
if [[ -f "$OUTPUT_DIR/kics-report.html" ]]; then
  echo "  <section><h2>KICS</h2><div class='embed-html'>"
  sed 's/<script[^>]*>.*<\/script>//gI' "$OUTPUT_DIR/kics-report.html"
  echo "</div></section>"
elif [[ -f "$OUTPUT_DIR/results.html" ]]; then
  echo "  <section><h2>KICS</h2><div class='embed-html'>"
  sed 's/<script[^>]*>.*<\/script>//gI' "$OUTPUT_DIR/results.html"
  echo "</div></section>"
fi

# Trivy
if [[ -f "$OUTPUT_DIR/trivy-report.json" ]]; then
  echo "  <section><h2>Trivy</h2><table id='trivy-table'><thead><tr><th>Package</th><th>Version</th><th>Severity</th><th>CVE</th><th>Title</th></tr></thead><tbody></tbody></table></section>"
fi

# Grype
if [[ -f "$OUTPUT_DIR/grype-report.json" ]]; then
  echo "  <section><h2>Grype</h2><table id='grype-table'><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>CVE</th><th>Severity</th></tr></thead><tbody></tbody></table></section>"
fi

# SBOM (Syft)
if [[ -f "$OUTPUT_DIR/sbom-syft.cyclonedx.json" ]]; then
  echo "  <section><h2>SBOM (Syft)</h2><table id='sbom-table'><thead><tr><th>Name</th><th>Version</th><th>Type</th><th>PURL</th><th>Path</th></tr></thead><tbody></tbody></table></section>"
fi

# Hadolint
if [[ -f "$OUTPUT_DIR/hadolint-report.json" ]]; then
  echo "  <section><h2>Hadolint</h2><table id='hadolint-table'><thead><tr><th>File</th><th>Line</th><th>Rule</th><th>Level</th><th>Message</th></tr></thead><tbody></tbody></table></section>"
fi

# JS
cat <<'EOF'
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>
function escapeHTML(str) {
  return typeof str === "string" ? str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[tag])) : str;
}

Promise.all([
  fetch('trivy-report.json').then(res => res.json()).catch(() => ({})),
  fetch('grype-report.json').then(res => res.json()).catch(() => ({})),
  fetch('sbom-syft.cyclonedx.json').then(res => res.json()).catch(() => ({})),
  fetch('hadolint-report.json').then(res => res.json()).catch(() => ([]))
]).then(([trivy, grype, sbom, hadolint]) => {
  // Trivy
  if (trivy.Results) {
    trivy.Results.forEach(r => {
      r.Vulnerabilities?.forEach(v => {
        $('#trivy-table tbody').append(`<tr>
          <td>${escapeHTML(v.PkgName)}</td><td>${escapeHTML(v.InstalledVersion)}</td><td>${escapeHTML(v.Severity)}</td>
          <td>${escapeHTML(v.VulnerabilityID)}</td><td>${escapeHTML(v.Title || v.Description || '-')}</td>
        </tr>`);
      });
    });
    $('#trivy-table').DataTable();
  }

  // Grype
  if (grype.matches) {
    grype.matches.forEach(m => {
      $('#grype-table tbody').append(`<tr>
        <td>${escapeHTML(m.artifact?.name)}</td><td>${escapeHTML(m.artifact?.version)}</td><td>${escapeHTML(m.artifact?.type)}</td>
        <td>${escapeHTML(m.vulnerability?.id)}</td><td>${escapeHTML(m.vulnerability?.severity)}</td>
      </tr>`);
    });
    $('#grype-table').DataTable();
  }

  // SBOM
  if (sbom.components) {
    sbom.components.forEach(c => {
      const path = (c.properties || []).find(p => p.name === 'syft:location:0:path')?.value || '';
      $('#sbom-table tbody').append(`<tr>
        <td>${escapeHTML(c.name)}</td><td>${escapeHTML(c.version)}</td><td>${escapeHTML(c.type)}</td>
        <td>${escapeHTML(c.purl || '')}</td><td>${escapeHTML(path)}</td>
      </tr>`);
    });
    $('#sbom-table').DataTable();
  }

  // ✅ Hadolint (corrected)
  if (Array.isArray(hadolint)) {
    if (!hadolint.length) {
      $('#hadolint-table tbody').append('<tr><td colspan="5" style="text-align:center;">No findings</td></tr>');
    } else {
      hadolint.forEach(item => {
        $('#hadolint-table tbody').append(`<tr>
          <td>${escapeHTML(item.file)}</td>
          <td>${escapeHTML(item.line)}</td>
          <td>${escapeHTML(item.code)}</td>
          <td>${escapeHTML(item.level)}</td>
          <td>${escapeHTML(item.message)}</td>
        </tr>`);
      });
    }
    $('#hadolint-table').DataTable();
  }
});
</script>

</body>
</html>
EOF

} > "$DASH"

echo "[✓] Self-contained Dashboard created at: $DASH"

#echo "[*] Serving dashboard on http://localhost:8000 (Ctrl+C to stop)"
#cd "$OUTPUT_DIR"
#python3 -m http.server 9000
