FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

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

WORKDIR /src

CMD ["/bin/bash"]
