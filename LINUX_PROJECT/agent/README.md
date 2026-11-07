# Agentic AI, Guardrails & Giao diện Tương tác (Thành viên 3)

Phân hệ **AI Agent** tích hợp mô hình ngôn ngữ lớn (**Google Gemini 2.5 Flash** kèm bộ lập kế hoạch nội bộ), cơ chế kiểm duyệt an toàn **Guardrails 2 lớp**, giao diện dòng lệnh **Terminal CLI** và **Streamlit Web Dashboard**.

---

## 📂 Cấu trúc Thư mục `agent/`

- `agent_cli.py`: Giao diện dòng lệnh (CLI) cho phép nhập trực tiếp câu lệnh tự nhiên trên Linux Terminal hoặc truyền câu lệnh trực tiếp qua tham số dòng lệnh.
- `dashboard.py`: Giao diện Web Dashboard bằng **Streamlit** hiển thị thông số hệ thống thời gian thực, bảng nút bấm gọi nhanh 11 MCP Tools, trình chạy lệnh Sandbox và khung Chat AI Agent.
- `guardrails.py`: Định nghĩa `SYSTEM_PROMPT` và 2 lớp kiểm duyệt an toàn (`check_user_input_guardrail`, `check_tool_call_guardrail`) chặn các lệnh nguy hiểm (`rm -rf /`, Fork Bomb, `mkfs`, đọc `/etc/shadow`, Reverse Shell, Prompt Injection).
- `mock_agent.py`: Script kiểm tra kết nối cơ bản từ Agent tới MCP Server.

---

## 🐧 Hướng dẫn Sử dụng trên Linux

### 1. Khởi chạy giao diện Web Dashboard (`dashboard.py`)
```bash
cd LINUX_PROJECT
streamlit run agent/dashboard.py
```
Truy cập `http://localhost:8501` trên trình duyệt để xem thông số CPU/RAM/Disk/Ports, bấm chạy từng MCP Tool hoặc chat trực tiếp với AI Agent.

### 2. Chạy lệnh tự nhiên trực tiếp từ dòng lệnh Terminal (`agent_cli.py`)
```bash
cd LINUX_PROJECT

# Kiểm tra tài nguyên, quét file bất thường và đề xuất firewall
python3 agent/agent_cli.py "Kiểm tra tài nguyên máy chủ, phát hiện file bất thường và tự động đề xuất cấu hình firewall"

# Xem danh sách toàn bộ 11 MCP Tools
python3 agent/agent_cli.py --list-tools
```

### 3. Chế độ Terminal tương tác liên tục (`LinuxAdmin@Agent:~$`)
```bash
cd LINUX_PROJECT
python3 agent/agent_cli.py
```
Nhập trực tiếp câu lệnh tự nhiên tại dấu nhắc `LinuxAdmin@Agent:~$ `. Gõ `tools` để xem danh sách công cụ, `exit` để thoát.
