#!/usr/bin/env bash
# ==============================================================================
# Linux System Administration & Security Auditing Shell Toolkit (Thành viên 2)
# Hỗ trợ kiểm tra Process, Log Analysis, Service Status, Network & Anomaly Files
# ==============================================================================

set -u

ACTION="${1:-all}"

check_resources_sh() {
    echo "=== [SHELL] KIỂM TRA TÀI NGUYÊN HỆ THỐNG ==="
    echo "--- Uptime & Load Average ---"
    uptime || true
    echo "--- Memory (MB) ---"
    free -m 2>/dev/null || true
    echo "--- Disk Usage ---"
    df -hT 2>/dev/null | grep -v "tmpfs" || true
}

check_processes_sh() {
    echo "=== [SHELL] TOP 10 TIẾN TRÌNH NGỐN CPU/RAM ==="
    ps aux --sort=-%cpu 2>/dev/null | head -n 11 || ps -ef | head -n 11
}

check_services_sh() {
    echo "=== [SHELL] TRẠNG THÁI DỊCH VỤ HỆ THỐNG ==="
    for svc in ssh sshd ufw docker cron rsyslog nginx; do
        if command -v systemctl >/dev/null 2>&1; then
            status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            echo "Service [$svc]: $status"
        else
            echo "Service [$svc]: systemctl not available in container"
        fi
    done
}

analyze_logs_sh() {
    echo "=== [SHELL] PHÂN TÍCH NHẬT KÝ AN NINH (AUTH LOG) ==="
    LOG_FILE="/var/log/auth.log"
    if [ ! -f "$LOG_FILE" ] && [ -f "/var/log/audit_samples/auth.log" ]; then
        LOG_FILE="/var/log/audit_samples/auth.log"
    fi

    if [ -r "$LOG_FILE" ]; then
        echo "--- Failed SSH Logins ---"
        grep -i "Failed password" "$LOG_FILE" | tail -n 10 || echo "Không có"
        echo "--- Thống kê IP tấn công Brute-force ---"
        grep -i "Failed password" "$LOG_FILE" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -nr || true
    else
        echo "Không thể đọc file log ($LOG_FILE)"
    fi
}

check_network_sh() {
    echo "=== [SHELL] GIÁM SÁT MẠNG & CỔNG ĐANG MỞ ==="
    if command -v ss >/dev/null 2>&1; then
        ss -tulnp 2>/dev/null || ss -tuln
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null || netstat -tuln
    fi
}

scan_anomalous_files_sh() {
    TARGET_DIR="${2:-/tmp}"
    echo "=== [SHELL] QUÉT FILE BẤT THƯỜNG TẠI $TARGET_DIR ==="
    echo "--- File quyền 777 (World-Writable) ---"
    find "$TARGET_DIR" -maxdepth 2 -type f -perm -0002 -ls 2>/dev/null | head -n 10 || true
    echo "--- File ẩn hoặc Script thực thi (.sh, .py, .elf) ---"
    find "$TARGET_DIR" -maxdepth 2 -type f \( -name ".*" -o -name "*.sh" -o -name "*.elf" -o -name "*.py" \) 2>/dev/null | head -n 15 || true
}

case "$ACTION" in
    resources) check_resources_sh ;;
    processes) check_processes_sh ;;
    services)  check_services_sh ;;
    logs)      analyze_logs_sh ;;
    network)   check_network_sh ;;
    files)     scan_anomalous_files_sh "$@" ;;
    all)
        check_resources_sh
        echo ""
        check_processes_sh
        echo ""
        check_services_sh
        echo ""
        analyze_logs_sh
        echo ""
        check_network_sh
        echo ""
        scan_anomalous_files_sh "/tmp"
        ;;
    *)
        echo "Usage: $0 {resources|processes|services|logs|network|files|all}"
        exit 1
        ;;
esac

