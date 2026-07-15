# Ghidra-analysis worker: decompiles a device's uploaded filesystem with
# Ghidra 12.1.2 (analyzeHeadless -recursive + the Haruspex post-script) and
# writes the C output into a parallel tree on the shared /data volume.
FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    fontconfig \
    libfreetype6 \
    unzip \
 && rm -rf /var/lib/apt/lists/*

# JDK 25 via adaptogen / Adoptium Temurin (Ghidra 12.x requires JDK 25). The
# Adoptium download API redirects to the current GA Temurin 25 JDK tarball for
# the build arch; override JDK_URL to pin a specific build.
ARG JDK_URL=https://api.adoptium.net/v3/binary/latest/25/ga/linux/x64/jdk/hotspot/normal/eclipse
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64|amd64) jdk_arch="x64" ;; \
      aarch64|arm64) jdk_arch="aarch64" ;; \
      *) echo "unsupported build arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="$(printf '%s' "$JDK_URL" | sed "s#/x64/#/${jdk_arch}/#")"; \
    curl -fsSL "$url" -o /tmp/jdk.tar.gz; \
    mkdir -p /opt/jdk; \
    tar -xzf /tmp/jdk.tar.gz -C /opt/jdk --strip-components=1; \
    rm /tmp/jdk.tar.gz; \
    /opt/jdk/bin/java -version
ENV JAVA_HOME=/opt/jdk
ENV PATH="/opt/jdk/bin:${PATH}"

# Ghidra 12.1.2. The public release asset carries a build-date suffix that
# changes per release, so by default we resolve the exact asset URL from the
# GitHub release tag at build time. Set GHIDRA_URL to a direct URL (e.g. an
# internal mirror) to skip the API lookup.
ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_URL=
RUN set -eux; \
    url="$GHIDRA_URL"; \
    if [ -z "$url" ]; then \
      tag="Ghidra_${GHIDRA_VERSION}_build"; \
      url="$(curl -fsSL "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/${tag}" \
        | grep -o "https://[^\"]*ghidra_${GHIDRA_VERSION}_PUBLIC_[0-9]*\.zip" | head -n1)"; \
    fi; \
    test -n "$url"; \
    echo "downloading Ghidra from: $url"; \
    curl -fsSL "$url" -o /tmp/ghidra.zip; \
    unzip -q /tmp/ghidra.zip -d /opt; \
    rm /tmp/ghidra.zip; \
    mv /opt/ghidra_* /opt/ghidra; \
    chmod +x /opt/ghidra/support/analyzeHeadless
ENV GHIDRA_HOME=/opt/ghidra

WORKDIR /app

# Worker code (incl. api/ghidra/HaruspexHeadless.java, resolved via -scriptPath)
# plus its node deps; the binaries to analyze arrive on the /data volume at
# runtime, uploaded by the agent's remote-copy.
COPY api /app/api

WORKDIR /app/api
RUN npm install --omit=dev

ENV NODE_ENV=production \
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    ELA_AGENT_DATA_DIR=/data/agent \
    GHIDRA_HOME=/opt/ghidra

CMD ["node", "/app/api/ghidra/worker.js"]
