from fastmcp import FastMCP
import psutil

mcp = FastMCP("LinuxResourceMonitor")

@mcp.tool()
def get_cpu_usage() -> str:
    """Lấy thông tin phần trăm sử dụng CPU hiện tại của hệ thống Linux."""
    return f"CPU Usage: {psutil.cpu_percent(interval=1)}%"

@mcp.tool()
def get_ram_usage() -> str:
    """Lấy thông tin mức độ sử dụng RAM (Memory) hiện tại."""
    ram = psutil.virtual_memory()
    used_gb = ram.used / (1024**3)
    total_gb = ram.total / (1024**3)
    return f"RAM Usage: {ram.percent}% (Đã dùng: {used_gb:.2f} GB / Tổng: {total_gb:.2f} GB)"

if __name__ == "__main__":
    print("MCP Server (FastMCP) đang chạy... (Nhấn Ctrl+C để thoát)")
    mcp.run()


