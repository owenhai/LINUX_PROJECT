# Linux MCP Server & Agentic AI Sandbox Integration

Hệ thống giám sát tài nguyên hệ thống (CPU, RAM) tích hợp môi trường thực thi an toàn (Zero-Trust Sandbox) và kết nối với AI Agent thông qua Model Context Protocol (MCP).

---

## 🛠️ 1. Yêu cầu môi trường & Cài đặt

- **Python**: 3.10+
- **Quản lý môi trường**: Miniconda / Anaconda (`mcp_env`)
- **Containerization**: Docker (đã cài đặt và phân quyền user)

### Khởi tạo môi trường Conda:
```bash
conda activate mcp_env
## 🚀 3. Khai báo & Chạy MCP Server

MCP Server cung cấp 2 công cụ đo tài nguyên hệ thống chính:
- `get_cpu_usage`: Lấy % mức sử dụng CPU hiện tại.
- `get_ram_usage`: Lấy % mức sử dụng RAM và thông số dung lượng chi tiết.

### Cấu hình kết nối Agent (`mcp_config.json`):
File cấu hình định nghĩa cầu nối giữa AI Agent và MCP Server:
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
        "mcp_server.py"
      ]
    }
  }
}

