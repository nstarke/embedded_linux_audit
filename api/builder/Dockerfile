FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Cross-compile toolchain for the per-user agent binary builds (mirrors
# tests/release-builder.Dockerfile, plus flex/bison for libpcap).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bash \
    bison \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    flex \
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

# Kernel-module build support: Debian's packaged cross compilers for every ISA
# in api/builder/kernelTarget.js, plus the kernel build system's own deps
# (bc, cpio, kmod, libelf/openssl headers, rsync). Plain kernel headers
# (modules_prepare) — no buildroot; see api/builder/build-kernel-module.sh.
# gcc-x86-64/i686 are included so x86 targets also build on arm64 hosts.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    bc \
    cpio \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabi \
    gcc-i686-linux-gnu \
    gcc-mips-linux-gnu \
    gcc-mips64-linux-gnuabi64 \
    gcc-mips64el-linux-gnuabi64 \
    gcc-mipsel-linux-gnu \
    gcc-powerpc-linux-gnu \
    gcc-powerpc64-linux-gnu \
    gcc-powerpc64le-linux-gnu \
    gcc-riscv64-linux-gnu \
    gcc-x86-64-linux-gnu \
    kmod \
    libelf-dev \
    libssl-dev \
    rsync \
 && rm -rf /var/lib/apt/lists/*

# Kernel source tarball + prepared-tree cache. docker-compose mounts a named
# volume here so a device's second build (same version/arch/config) skips the
# slow modules_prepare step.
ENV ELA_KMOD_CACHE_DIR=/var/cache/ela-kmod
RUN mkdir -p /var/cache/ela-kmod

# The repo (incl. .git for tpm2-tss's `git describe`) is bind-mounted at /src and
# owned by a different uid than the container; trust it.
RUN git config --system --add safe.directory '*'

# Pre-install Zig so builds need no runtime download.
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

# Only the worker code + its node deps live in the image; the C sources to
# compile come from the /src bind-mount at runtime.
COPY api /app/api

WORKDIR /app/api
RUN npm install --omit=dev

ENV NODE_ENV=production \
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    ELA_BUILD_REPO_ROOT=/src

CMD ["node", "/app/api/builder/worker.js"]
