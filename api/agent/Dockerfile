FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Toolchain required to cross-compile the per-user agent binaries in-container
# (mirrors tests/release-builder.Dockerfile).  The GitHub download path has been
# removed; binaries are built when a user's API token is created.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bash \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    libltdl-dev \
    libtool-bin \
    llvm \
    perl \
    pkg-config \
    python3 \
    tar \
    wget \
    xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Pre-install Zig so token-creation builds do not need to download it at runtime.
ENV ZIG_VERSION=0.14.0
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64|amd64) zig_host="x86_64" ;; \
      aarch64|arm64) zig_host="aarch64" ;; \
      *) echo "unsupported build arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_host}-${ZIG_VERSION}.tar.xz"; \
    curl -fsSL "$url" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version

WORKDIR /app

# Copy the whole repo (including agent/ and the third_party/ submodules) so the
# token-create script can build agent binaries.  node_modules, data, .git, etc.
# are excluded via .dockerignore.  Submodules must be initialized on the host
# (git submodule update --init --recursive) before building this image.
COPY . /app

WORKDIR /app/api
RUN npm install --omit=dev

WORKDIR /app/api/agent
RUN npm install --omit=dev

ENV NODE_ENV=production \
    ELA_AGENT_HOST=0.0.0.0 \
    ELA_AGENT_PORT=5000

EXPOSE 5000

CMD ["node", "server.js", "--reuse-last-data-dir"]
