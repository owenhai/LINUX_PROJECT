import os
import sys
import json
from fastmcp import FastMCP

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
for path_item in (CURRENT_DIR, PROJECT_ROOT):
    if path_item not in sys.path:
        sys.path.insert(0, path_item)

from system_tools import (
    collect_cpu_metrics,
    collect_ram_metrics,
    collect_disk_metrics,
    inspect_top_processes,
    inspect_service_status,
    analyze_logs,
    monitor_network,
    scan_anomalous_files,
    generate_firewall_recommendations,
)
from sandbox.sandbox_runner import run_command_in_sandbox

mcp = FastMCP("LinuxResourceAndSecurityMonitor")


@mcp.tool()
def get_cpu_usage() -> str:
    """Lấy thông tin phần trăm sử dụng CPU, số nhân và Load Average hiện tại của hệ thống Linux."""
    return collect_cpu_metrics()


@mcp.tool()
def get_ram_usage() -> str:
    """Lấy thông tin mức độ sử dụng RAM (Memory) và Swap hiện tại của máy chủ."""
    return collect_ram_metrics()


@mcp.tool()
def get_disk_usage() -> str:
    """Kiểm tra dung lượng ổ cứng các phân vùng trên máy chủ và cảnh báo nếu sắp đầy."""
    return collect_disk_metrics()


@mcp.tool()
def check_top_processes(limit: int = 10, sort_by: str = "cpu") -> str:
    """
    Kiểm tra danh sách tiến trình (processes) đang tiêu thụ nhiều CPU hoặc RAM nhất,
    đồng thời phát hiện các tiến trình đáng ngờ.
    """
    return inspect_top_processes(limit=limit, sort_by=sort_by)


@mcp.tool()
def check_service_status(service_name: str = "all") -> str:
    """
    Kiểm tra trạng thái hoạt động của các dịch vụ hệ thống Linux (ssh, ufw, docker, cron, nginx...).
    Truyền 'all' để kiểm tra toàn bộ các dịch vụ quan trọng.
    """
    return inspect_service_status(service_name=service_name)


@mcp.tool()
def analyze_system_logs(log_type: str = "auth", lines: int = 50) -> str:
    """
    Phân tích log hệ thống Linux (auth.log, syslog, journalctl) để phát hiện đăng nhập thất bại,
    tấn công Brute-force SSH hoặc lỗi thực thi đặc quyền (sudo).
    """
    return analyze_logs(log_type=log_type, lines_count=lines)


@mcp.tool()
def monitor_network_connections() -> str:
    """
    Giám sát các kết nối mạng hiện tại, liệt kê các cổng (ports) đang mở LISTEN,
    kết nối ESTABLISHED và cảnh báo các cổng dịch vụ nhạy cảm mở ra ngoài.
    """
    return monitor_network()


@mcp.tool()
def detect_anomalous_files(target_dir: str = "/tmp") -> str:
    """
    Quét và phát hiện các file bất thường trong thư mục hệ thống (mặc định: /tmp):
    bao gồm file ẩn (.hidden), file quyền 777 (world-writable), SUID/SGID và script khả nghi.
    """
    return scan_anomalous_files(target_dir=target_dir)


@mcp.tool()
def propose_firewall_rules(
    suspicious_ips: str = "",
    allowed_ports: str = "22,80,443",
) -> str:
    """
    Tự động phân tích các cổng đang mở thực tế trên máy chủ và IP bất thường từ log
    để đề xuất bộ quy tắc cấu hình tường lửa (UFW và iptables).
    """
    return generate_firewall_recommendations(
        suspicious_ips=suspicious_ips,
        allowed_ports=allowed_ports,
    )


@mcp.tool()
def execute_sandboxed_command(command: str) -> str:
    """
    Thực thi một câu lệnh Linux bên trong môi trường Zero-Trust Sandbox cô lập
    (Non-root user, Read-only FS, Cap-drop ALL, Network isolated, cgroups CPU/RAM limit).
    """
    result = run_command_in_sandbox(command)
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def run_full_security_audit() -> str:
    """
    Thực hiện kiểm toán toàn diện hệ thống Linux:
    Tài nguyên CPU/RAM/Disk, Tiến trình, File bất thường, Phân tích Log, Giám sát Mạng và Đề xuất Firewall.
    """
    sections = [
        "======================================================================",
        "   BÁO CÁO TỔNG HỢP QUẢN TRỊ HỆ THỐNG & KIỂM TOÁN AN NINH LINUX",
        "======================================================================",
        "\n[1] TÀI NGUYÊN MÁY CHỦ (CPU & RAM & DISK)",
        collect_cpu_metrics(),
        collect_ram_metrics(),
        collect_disk_metrics(),
        "\n[2] RÀ SOÁT TIẾN TRÌNH HỆ THỐNG",
        inspect_top_processes(limit=8, sort_by="cpu"),
        "\n[3] KIỂM TRA DỊCH VỤ TRỌNG YẾU",
        inspect_service_status("all"),
        "\n[4] PHÁT HIỆN FILE BẤT THƯỜNG",
        scan_anomalous_files("/tmp"),
        "\n[5] PHÂN TÍCH LOG AN NINH (AUTH/SYSLOG)",
        analyze_logs("auth", lines_count=50),
        "\n[6] GIÁM SÁT MẠNG & CỔNG MỞ",
        monitor_network(),
        "\n[7] ĐỀ XUẤT CẤU HÌNH FIREWALL TỰ ĐỘNG",
        generate_firewall_recommendations(),
    ]
    return "\n".join(sections)


if __name__ == "__main__":
    print("MCP Server (FastMCP - Linux Admin & Security Auditing) đang chạy... (Nhấn Ctrl+C để thoát)")
    mcp.run()
