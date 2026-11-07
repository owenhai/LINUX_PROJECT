FROM ubuntu:24.04

# Cài đặt các công cụ quản trị hệ thống & audit an ninh trên Linux
RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    findutils \
    grep \
    gawk \
    sed \
    procps \
    net-tools \
    iproute2 \
    iptables \
    ufw \
    curl \
    htop \
    lsof \
    sysstat \
    file \
    && rm -rf /var/lib/apt/lists/*

# Tạo người dùng hạn chế (sandboxuser) không thuộc nhóm root
RUN useradd -m -s /bin/bash sandboxuser

WORKDIR /home/sandboxuser
USER sandboxuser

CMD ["/bin/bash"]
