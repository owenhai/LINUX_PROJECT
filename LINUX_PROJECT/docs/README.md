# Kiến trúc Hệ thống: Agentic AI System with MCP for Automated Linux Administration & Security Auditing

## 1. Sơ đồ Kiến trúc Tổng thể

```mermaid
flowchart TD
    Admin["👤 Quản trị viên\n(Terminal CLI / Streamlit Dashboard)"] -->|"Câu lệnh tự nhiên"| GuardIn["🛡️ Input Guardrail\n(agent/guardrails.py)"]
    GuardIn -->|"Vi phạm chính sách\n(rm -rf /, fork bomb, /etc/shadow...)"| Reject["🛑 Chặn & Cảnh báo Bảo mật"]
    GuardIn -->|"Hợp lệ"| Planner["🤖 AI Agent & Planner\n(agent/agent_cli.py & dashboard.py)\nGemini 2.5 Flash / Intent Planner"]
    Planner -->|"Yêu cầu gọi Tool"| GuardTool["🔍 Tool Call Guardrail\n(agent/guardrails.py)"]
    GuardTool --> MCPServer["⚙️ FastMCP Server\n(mcp_server/mcp_server.py)"]

    subgraph Tools ["Bộ 11 Công cụ Quản trị & Bảo mật Linux (Thành viên 2)"]
        T1["Tài nguyên: get_cpu_usage, get_ram_usage, get_disk_usage"]
        T2["Tiến trình & Dịch vụ: check_top_processes, check_service_status"]
        T3["Nhật ký & File lạ: analyze_system_logs, detect_anomalous_files"]
        T4["Mạng & Tường lửa: monitor_network_connections, propose_firewall_rules"]
        T5["Kiểm toán tổng thể: run_full_security_audit"]
        T6["Thực thi cô lập: execute_sandboxed_command"]
    end

    MCPServer --> T1 & T2 & T3 & T4 & T5 & T6
    T6 --> Sandbox["📦 Zero-Trust Docker Sandbox (Thành viên 1)\n--read-only | --network=none | --cap-drop=ALL | cgroups"]
```

## 2. Luồng Hoạt động (Workflow)
1. **Tiếp nhận yêu cầu**: Quản trị viên nhập câu lệnh tự nhiên qua **Terminal CLI** (`python3 agent/agent_cli.py`) hoặc **Streamlit Web Dashboard** (`streamlit run agent/dashboard.py`).
2. **Kiểm duyệt đầu vào (`Input Guardrail`)**: Kiểm tra câu lệnh có chứa mã độc, lệnh xóa hệ thống hoặc tấn công Prompt Injection hay không.
3. **Lập kế hoạch & Gọi công cụ (`MCP Tool Calling`)**: Agent xác định danh sách các MCP Tools cần gọi trên `FastMCP Server`.
4. **Thực thi an toàn (`System Tools & Zero-Trust Sandbox`)**:
   - Các công cụ giám sát đọc thông số trực tiếp từ hệ điều hành Linux.
   - Các câu lệnh shell tùy chỉnh bắt buộc đi qua `execute_sandboxed_command` để chạy bên trong container cô lập của Thành viên 1.
5. **Tổng hợp báo cáo**: Kết quả từ các MCP Tools được tổng hợp thành báo cáo Markdown kèm khuyến nghị cấu hình `ufw` / `iptables`.
