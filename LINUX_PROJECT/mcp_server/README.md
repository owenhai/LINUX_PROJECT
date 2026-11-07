# MCP Server & Linux Administration Tools (Thành viên 2)

Phân hệ **MCP Server (`FastMCP`)** cung cấp bộ 11 công cụ quản trị hệ thống và kiểm toán an ninh Linux bằng Python kết hợp Shell Script.

---

## 📂 Cấu trúc Thư mục `mcp_server/`

- `mcp_server.py`: Khởi tạo máy chủ `FastMCP("LinuxResourceAndSecurityMonitor")` và đăng ký 11 công cụ MCP.
- `system_tools.py`: Cài đặt chi tiết các hàm thu thập thông số tài nguyên (CPU, RAM, Disk), tiến trình, dịch vụ (`systemctl`), phân tích nhật ký (`auth.log`, `syslog`, `journalctl`), giám sát mạng, quét file bất thường và đề xuất tường lửa (`ufw`, `iptables`).
- `mcp_config.json`: Cấu hình khai báo lệnh khởi chạy MCP Server cho MCP Client / AI Agent.
- `requirements.txt`: Danh sách các gói thư viện Python cần thiết.
- `scripts/linux_audit_tools.sh`: Bộ Shell script thuần Linux dùng để kiểm tra nhanh từ Terminal.

---

## 📄 Giải thích cấu hình `mcp_config.json`

```json
{
  "mcpServers": {
    "linux_monitor": {
      "command": "conda",
      "args": [
        "run",
        "-n",
        "mcp_env",
        "python",
        "mcp_server/mcp_server.py"
      ]
    }
  }
}
```
File này định nghĩa điểm kết nối chuẩn theo giao thức MCP, giúp AI Agent biết cách gọi chạy `mcp_server/mcp_server.py` bên trong môi trường Conda `mcp_env`.

---

## 🐧 Cách chạy độc lập trên Linux Terminal

### 1. Chạy trực tiếp MCP Server
```bash
cd LINUX_PROJECT
python3 mcp_server/mcp_server.py
```

### 2. Chạy bộ Shell Script kiểm toán Linux (`linux_audit_tools.sh`)
```bash
cd LINUX_PROJECT
chmod +x mcp_server/scripts/linux_audit_tools.sh

# Chạy toàn bộ các mục kiểm tra
./mcp_server/scripts/linux_audit_tools.sh all

# Hoặc chạy từng mục riêng biệt:
./mcp_server/scripts/linux_audit_tools.sh resources
./mcp_server/scripts/linux_audit_tools.sh processes
./mcp_server/scripts/linux_audit_tools.sh services
./mcp_server/scripts/linux_audit_tools.sh logs
./mcp_server/scripts/linux_audit_tools.sh network
./mcp_server/scripts/linux_audit_tools.sh files /tmp
```
