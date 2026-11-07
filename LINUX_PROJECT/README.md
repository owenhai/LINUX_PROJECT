# Build & Deploy an Agentic AI System with MCP for Automated Linux System Administration & Security Auditing

Hệ thống **AI Agent tích hợp Model Context Protocol (MCP Server)** chạy trên môi trường **Linux**, cho phép quản trị viên điều khiển, giám sát tài nguyên, phân tích nhật ký, phát hiện tệp bất thường và tự động đề xuất cấu hình tường lửa thông qua **ngôn ngữ tự nhiên** (trên **Terminal CLI** hoặc **Streamlit Web Dashboard**), đảm bảo an toàn tuyệt đối nhờ cơ chế **Guardrails 2 lớp** và **Zero-Trust Docker Sandbox**.

---

## 👥 Phân công Công việc & Kiến trúc 3 Thành viên

| Thành viên | Vai trò | Thư mục phụ trách | Nội dung triển khai |
| :--- | :--- | :--- | :--- |
| **Thành viên 1** | **System & Sandbox** | `sandbox/` | Xây dựng môi trường Linux Container cô lập (`Dockerfile`), giới hạn tài nguyên bằng `cgroups` (`--cpus=0.5`, `-m=512m`, `--pids-limit=100`), cô lập `namespaces` (`--network=none`, `--read-only`), hạ quyền `sandboxuser` và khóa toàn bộ Linux Capabilities (`--cap-drop=ALL`). |
| **Thành viên 2** | **MCP Server & Tooling** | `mcp_server/` | Phát triển máy chủ `FastMCP` (`mcp_server.py`, `system_tools.py`) và bộ `linux_audit_tools.sh` cung cấp **11 công cụ hệ thống** (CPU, RAM, Disk, Process, Service, Log Analysis, Network Monitoring, Anomaly File Scan, Firewall Hardening, Sandbox Execution). |
| **Thành viên 3** | **Agentic AI & Integration** | `agent/` | Tích hợp LLM (`Google Gemini 2.5 Flash` + bộ lập kế hoạch nội bộ), thiết kế Prompt Engineering & bộ lọc **Guardrails** (`guardrails.py`), xây dựng giao diện **Terminal CLI** (`agent_cli.py`) và **Streamlit Web Dashboard** (`dashboard.py`). |

---

## 📂 Cấu trúc Thư mục Dự án

```text
LINUX_PROJECT/
├── .gitignore
├── README.md                            # Tài liệu hướng dẫn tổng thể dự án
├── sandbox/                             # [Thành viên 1] Zero-Trust Linux Sandbox
│   ├── Dockerfile                       # Image Ubuntu 24.04 hardened với user giới hạn (sandboxuser)
│   ├── sandbox_runner.py                # Module thực thi lệnh cô lập (--read-only, --cap-drop=ALL, --network=none)
│   ├── build_sandbox.sh                 # Script tự động build và kiểm tra Docker Sandbox
│   ├── INTEGRATION.md                   # Tài liệu kết nối Sandbox với MCP Server
│   └── README.md                        # Hướng dẫn chi tiết phần Thành viên 1
├── mcp_server/                          # [Thành viên 2] MCP Server & Bộ công cụ quản trị/bảo mật Linux
│   ├── mcp_server.py                    # Máy chủ FastMCP đăng ký 11 công cụ hệ thống
│   ├── system_tools.py                  # Cài đặt chi tiết các hàm đo tài nguyên, tiến trình, dịch vụ, log, mạng, firewall
│   ├── mcp_config.json                  # Cấu hình kết nối chuẩn giữa MCP Client và MCP Server
│   ├── requirements.txt                 # Danh sách thư viện Python của toàn dự án
│   ├── README.md                        # Hướng dẫn chi tiết phần Thành viên 2
│   └── scripts/
│       └── linux_audit_tools.sh         # Shell script kiểm toán trực tiếp trên Linux Terminal
├── agent/                               # [Thành viên 3] AI Agent CLI, Streamlit Dashboard & Guardrails
│   ├── agent_cli.py                     # Giao diện dòng lệnh (CLI) nhận câu lệnh tự nhiên trực tiếp trên Terminal
│   ├── dashboard.py                     # Giao diện Web Dashboard trực quan bằng Streamlit
│   ├── guardrails.py                    # Hệ thống Guardrails 2 lớp chặn lệnh độc hại & System Prompt
│   ├── mock_agent.py                    # Script kiểm tra kết nối MCP Server cơ bản
│   └── README.md                        # Hướng dẫn chi tiết phần Thành viên 3
└── docs/
    └── README.md                        # Sơ đồ kiến trúc và luồng hoạt động của hệ thống
```

---

## ⚙️ 1. Yêu cầu Hệ thống & Cài đặt trên Linux

- **Hệ điều hành**: Linux (Ubuntu 22.04 / 24.04, Debian, Kali, hoặc WSL2)
- **Python**: `3.10+` (khuyến nghị quản lý bằng Miniconda/Anaconda với môi trường `mcp_env`)
- **Container**: Docker Engine (để chạy Zero-Trust Sandbox của Thành viên 1)

### Bước 1: Kích hoạt môi trường và cài đặt thư viện Python
```bash
cd LINUX_PROJECT
conda activate mcp_env
pip install -r mcp_server/requirements.txt
```

### Bước 2: Build Docker Image cho Zero-Trust Sandbox (Thành viên 1)
```bash
chmod +x sandbox/build_sandbox.sh
./sandbox/build_sandbox.sh
```

### Bước 3: (Tùy chọn) Cấu hình Google Gemini API Key
Nếu muốn AI Agent sử dụng mô hình **Gemini 2.5 Flash** để viết phân tích chuyên sâu, khai báo biến môi trường:
```bash
export GEMINI_API_KEY="your_api_key_here"
```
*(Nếu không khai báo `GEMINI_API_KEY`, Agent vẫn hoạt động đầy đủ 100% nhờ bộ lập kế hoạch và tổng hợp báo cáo nội bộ).*

---

## 🚀 2. Hướng dẫn Sử dụng Hệ thống

### Cách 1: Sử dụng Web Dashboard trực quan bằng Streamlit (`dashboard.py`)
Khởi chạy giao diện Web từ Terminal:
```bash
streamlit run agent/dashboard.py
```
Sau khi chạy, mở trình duyệt tại địa chỉ `http://localhost:8501`:
- **Thanh trạng thái thời gian thực (Realtime Metrics)**: Hiển thị ngay `% CPU`, `% RAM`, `% Disk (/)` và tổng số cổng mạng đang lắng nghe (`LISTEN`).
- **Sidebar điều khiển nhanh**: Chọn và bấm chạy trực tiếp từng công cụ trong **11 MCP Tools**, hoặc gõ câu lệnh Linux bất kỳ để thực thi trong **Zero-Trust Sandbox**.
- **Khung Chat AI Agent**: Nhập câu lệnh tự nhiên trực tiếp vào ô chat để Agent tự động kiểm duyệt Guardrails, gọi các MCP Tools tương ứng và xuất báo cáo.

---

### Cách 2: Sử dụng trực tiếp trên Linux Terminal CLI (`agent_cli.py`)

#### A. Chế độ Terminal tương tác liên tục (Interactive Shell)
```bash
python3 agent/agent_cli.py
```
Tại dấu nhắc `LinuxAdmin@Agent:~$ `, bạn có thể nhập trực tiếp bất kỳ yêu cầu nào bằng tiếng Việt hoặc tiếng Anh:
- Gõ `tools`: Xem bảng danh sách 11 công cụ trên MCP Server.
- Gõ `exit` hoặc `quit`: Thoát chương trình.

#### B. Chế độ truyền lệnh trực tiếp từ Terminal (One-line Command)
Truyền thẳng yêu cầu tự nhiên vào sau lệnh `python3 agent/agent_cli.py`:
```bash
# Kiểm tra tài nguyên, quét file lạ và đề xuất cấu hình tường lửa
python3 agent/agent_cli.py "Kiểm tra tài nguyên máy chủ, phát hiện file bất thường và tự động đề xuất cấu hình firewall"

# Kiểm tra tiến trình tiêu thụ tài nguyên và trạng thái các dịch vụ hệ thống
python3 agent/agent_cli.py "Kiểm tra các tiến trình ngốn CPU và trạng thái dịch vụ hệ thống"

# Phân tích nhật ký xác thực và giám sát các kết nối mạng
python3 agent/agent_cli.py "Phân tích log hệ thống và kiểm tra các port mạng đang mở"

# Thực thi câu lệnh bash bên trong Zero-Trust Sandbox (đặt lệnh trong dấu backtick)
python3 agent/agent_cli.py "Chạy lệnh \`uname -a && id && df -h\` trong sandbox"

# Thực hiện kiểm toán an ninh toàn bộ hệ thống
python3 agent/agent_cli.py "Kiểm toán toàn bộ hệ thống"
```

---

### Cách 3: Chạy độc lập từng phân hệ (Phục vụ kiểm tra riêng từng thành viên)

1. **Kiểm tra riêng Sandbox của Thành viên 1**:
   ```bash
   python3 sandbox/sandbox_runner.py "whoami && id && uname -a"
   ```
2. **Chạy riêng MCP Server hoặc Shell Script của Thành viên 2**:
   ```bash
   # Khởi chạy MCP Server
   python3 mcp_server/mcp_server.py

   # Chạy Shell Script kiểm toán hệ thống Linux
   chmod +x mcp_server/scripts/linux_audit_tools.sh
   ./mcp_server/scripts/linux_audit_tools.sh all
   ```
3. **Kiểm tra kết nối MCP Client - Server cơ bản (`mock_agent.py`)**:
   ```bash
   python3 agent/mock_agent.py
   ```

---

## 🧰 3. Danh sách 11 Công cụ trên MCP Server (`mcp_server/mcp_server.py`)

| STT | Tên MCP Tool | Mô tả chức năng |
| :-: | :--- | :--- |
| 1 | `get_cpu_usage` | Lấy `% CPU`, số nhân vật lý/luồng, tần số xung nhịp và `Load Average (1m, 5m, 15m)`. |
| 2 | `get_ram_usage` | Lấy `% RAM`, dung lượng đã dùng/khả dụng/tổng (GB) và mức sử dụng `Swap`. |
| 3 | `get_disk_usage` | Kiểm tra dung lượng tất cả phân vùng ổ cứng và cảnh báo các phân vùng đạt ngưỡng `>85%`. |
| 4 | `check_top_processes` | Liệt kê các tiến trình tiêu thụ nhiều CPU/RAM nhất và rà soát tiến trình khả nghi. |
| 5 | `check_service_status` | Kiểm tra trạng thái hoạt động của các dịch vụ hệ thống (`ssh`, `ufw`, `docker`, `cron`, `rsyslog`, `nginx`...). |
| 6 | `analyze_system_logs` | Đọc `/var/log/auth.log`, `/var/log/syslog` hoặc `journalctl` để phát hiện đăng nhập SSH thất bại và sự kiện `sudo`. |
| 7 | `monitor_network_connections` | Liệt kê các cổng đang mở (`LISTEN`), kết nối `ESTABLISHED`, lưu lượng mạng và cảnh báo cổng nhạy cảm mở ra ngoài. |
| 8 | `detect_anomalous_files` | Quét thư mục hệ thống (mặc định `/tmp`) tìm file ẩn (`.hidden`), quyền `777` (`world-writable`), bit `SUID/SGID` và script thực thi. |
| 9 | `propose_firewall_rules` | Đối chiếu các cổng đang mở thực tế trên máy và IP đăng nhập thất bại từ log để sinh quy tắc `ufw` & `iptables`. |
| 10 | `execute_sandboxed_command` | Thực thi câu lệnh Linux bên trong container cô lập Zero-Trust Sandbox của Thành viên 1. |
| 11 | `run_full_security_audit` | Thực thi toàn bộ quy trình kiểm toán hệ thống và xuất báo cáo tổng hợp. |

---

## 🛡️ 4. Cơ chế An toàn & Bảo mật (Guardrails + Zero-Trust Sandbox)

1. **Input & Tool Call Guardrails (`agent/guardrails.py`)**:
   - Chặn ngay từ đầu các yêu cầu phá hoại hệ điều hành (`rm -rf /`, Fork Bomb `:(){ :|:& };:`, định dạng ổ đĩa `mkfs`, ghi đè `/dev/sda`, đọc trộm `/etc/shadow`, tạo Reverse Shell `/dev/tcp/`, hoặc tấn công Prompt Injection).
2. **Zero-Trust Container Isolation (`sandbox/sandbox_runner.py`)**:
   - Thực thi dưới quyền người dùng thường `sandboxuser` (`non-root`).
   - Hệ thống tệp gốc chỉ đọc (`--read-only`), thư mục `/tmp` gắn trên RAM với cờ cấm thực thi (`--tmpfs /tmp:rw,noexec,nosuid,size=64m`).
   - Gỡ bỏ toàn bộ quyền Kernel (`--cap-drop=ALL`, `--security-opt=no-new-privileges:true`).
   - Giới hạn phần cứng bằng `cgroups` (`--pids-limit=100`, `--cpus=0.5`, `-m=512m`) và ngắt kết nối mạng (`--network=none`).
