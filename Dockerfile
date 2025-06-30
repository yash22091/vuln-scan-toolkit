# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build a static KICS binary (and stage its assets)
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.24 AS kics-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 https://github.com/Checkmarx/kics.git

WORKDIR /build/kics
RUN go mod download

# Build fully static (no glibc dependency)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /usr/local/bin/kics ./cmd/console/main.go

# Stage out the entire assets folder so we can COPY it later
RUN mkdir -p /kics-assets && \
    cp -r assets /kics-assets/

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Final scanner image
# ─────────────────────────────────────────────────────────────────────────────
FROM openjdk:11-jre-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl binutils wget unzip jq tar rpm2cpio cpio ca-certificates default-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# OWASP Dependency-Check
RUN VERSION=$(curl -s https://dependency-check.github.io/DependencyCheck/current.txt) && \
    curl -sL https://github.com/dependency-check/DependencyCheck/releases/download/v${VERSION}/dependency-check-${VERSION}-release.zip \
      -o /tmp/dc.zip && \
    unzip -qd /opt /tmp/dc.zip && \
    ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh && \
    rm /tmp/dc.zip

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Trivy
RUN curl -sL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | bash -s -- -b /usr/local/bin && \
    rm -rf /root/.cache/trivy

# Hadolint
RUN curl -sL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
      -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Syft (for SBOM generation in container mode)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ─────────────────────────────────────────────────────────────────────────────
# Install .NET 8.0 runtime via Microsoft’s install script
# ─────────────────────────────────────────────────────────────────────────────
RUN wget -qO dotnet-install.sh https://dot.net/v1/dotnet-install.sh && \
    bash dotnet-install.sh --runtime dotnet --channel 8.0 --install-dir /usr/share/dotnet && \
    rm dotnet-install.sh

ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="$PATH:/usr/share/dotnet"

# Copy the static KICS binary
COPY --from=kics-builder /usr/local/bin/kics /usr/local/bin/kics

# Copy the staged assets so /usr/local/share/kics/assets/queries exists
COPY --from=kics-builder /kics-assets/assets /usr/local/share/kics/assets


# Copy your dynamic_scan.sh, etc.
COPY dynamic_scan.sh /usr/local/bin/dynamic_scan.sh
RUN chmod +x /usr/local/bin/dynamic_scan.sh
ENV CONTAINER_MODE=1

ENTRYPOINT ["bash","-c","if [ \"$#\" -eq 0 ]; then /usr/local/bin/dynamic_scan.sh -h; else exec /usr/local/bin/dynamic_scan.sh \"$@\"; fi","--"]
