FROM ubuntu:24.04

# Cài đặt các công cụ quản trị hệ thống & kiểm tra an ninh mà MCP Server sẽ gọi
RUN apt-get update && apt-get install -y \
    bash \
    procps \
    net-tools \
    iproute2 \
    iptables \
    ufw \
    curl \
    htop \
    lsof \
    sysstat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["/bin/bash"]
