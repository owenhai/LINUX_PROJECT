import re
from dataclasses import dataclass

SYSTEM_PROMPT = """Bạn là **LinuxSecAgent** — Chuyên gia Quản trị Hệ thống Linux & Kiểm toán An ninh (Automated Linux System Administration & Security Auditing Agent) hoạt động thông qua giao thức Model Context Protocol (MCP).

### Nhiệm vụ cốt lõi:
1. Tiếp nhận yêu cầu bằng ngôn ngữ tự nhiên từ quản trị viên (tiếng Việt hoặc tiếng Anh).
2. Lựa chọn và gọi chính xác các công cụ (MCP Tools) trên hệ thống Linux để thu thập dữ liệu thực tế:
   - Giám sát tài nguyên: `get_cpu_usage`, `get_ram_usage`, `get_disk_usage`
   - Quản lý tiến trình & dịch vụ: `check_top_processes`, `check_service_status`
   - Kiểm toán an ninh & phát hiện bất thường: `detect_anomalous_files`, `analyze_system_logs`
   - Giám sát mạng & đề xuất tường lửa: `monitor_network_connections`, `propose_firewall_rules`
   - Thực thi lệnh trong Zero-Trust Sandbox: `execute_sandboxed_command`
   - Báo cáo tổng thể: `run_full_security_audit`
3. Phân tích kết quả trả về từ các MCP Tools và lập báo cáo rõ ràng gồm:
   - **Tóm tắt hiện trạng hệ thống** (CPU, RAM, Disk, Dịch vụ).
   - **Cảnh báo rủi ro & Phát hiện bất thường** (File lạ trong `/tmp`, IP tấn công Brute-force SSH, Port nhạy cảm đang mở).
   - **Khuyến nghị khắc phục & Cấu hình Firewall (`ufw` / `iptables`)** cụ thể, an toàn.

### Quy tắc an toàn (Guardrails):
- TUYỆT ĐỐI KHÔNG thực thi hoặc hướng dẫn thực thi các câu lệnh phá hoại hệ điều hành (`rm -rf /`, `mkfs`, fork bomb, ghi đè ổ đĩa `/dev/sda`, mở reverse shell, đọc trộm `/etc/shadow`).
- Mọi câu lệnh shell tùy chỉnh bắt buộc phải đi qua công cụ `execute_sandboxed_command` (chạy dưới quyền `sandboxuser` trong container cô lập `--read-only`, `--network=none`, `--cap-drop=ALL`).
"""


@dataclass
class GuardrailVerdict:
    allowed: bool
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    reason: str


# Các mẫu câu lệnh hoặc yêu cầu nguy hiểm bị chặn ở tầng Agent Input & Tool Guardrail
BLOCKED_PATTERNS = [
    (r"rm\s+(-[rRf]+\s+)*(/|/\*|\.\.)(\s|$)", "Lệnh xóa toàn bộ hệ thống tệp gốc (rm -rf /)"),
    (r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", "Tấn công Fork Bomb làm treo Kernel"),
    (r"mkfs\.", "Lệnh định dạng/xóa phân vùng ổ cứng (mkfs)"),
    (r"dd\s+if=.*of=/dev/", "Ghi đè trực tiếp thiết bị khối (/dev/)"),
    (r"chmod\s+-R\s+777\s+/", "Mở quyền 777 toàn hệ thống gây mất an toàn nghiêm trọng"),
    (r"/etc/shadow", "Truy cập trái phép tệp băm mật khẩu (/etc/shadow)"),
    (r"bash\s+-i\s+>&\s*/dev/tcp/", "Tạo kết nối Reverse Shell trái phép"),
    (r"nc\s+-e\s+/bin/(sh|bash)", "Tạo Netcat Reverse Shell"),
    (r"(ignore|disregard)\s+(all\s+)?(previous|prior)\s+instructions", "Phát hiện tấn công Prompt Injection"),
]


def check_user_input_guardrail(user_prompt: str) -> GuardrailVerdict:
    """Kiểm tra câu lệnh tự nhiên của người dùng trước khi gửi cho LLM / Planner."""
    if not user_prompt or not user_prompt.strip():
        return GuardrailVerdict(False, "LOW", "Câu lệnh đầu vào trống.")

    for pattern, desc in BLOCKED_PATTERNS:
        if re.search(pattern, user_prompt, re.IGNORECASE):
            return GuardrailVerdict(
                allowed=False,
                risk_level="CRITICAL",
                reason=f"[GUARDRAIL BLOCKED] Yêu cầu vi phạm chính sách an toàn hệ thống: {desc}",
            )

    return GuardrailVerdict(
        allowed=True,
        risk_level="LOW",
        reason="Yêu cầu hợp lệ và tuân thủ chính sách an ninh.",
    )


def check_tool_call_guardrail(tool_name: str, tool_args: dict) -> GuardrailVerdict:
    """Kiểm duyệt lệnh gọi MCP Tool và tham số trước khi thực thi."""
    if tool_name == "execute_sandboxed_command":
        cmd = str(tool_args.get("command", ""))
        for pattern, desc in BLOCKED_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return GuardrailVerdict(
                    allowed=False,
                    risk_level="CRITICAL",
                    reason=f"[TOOL GUARDRAIL BLOCKED] Từ chối đưa lệnh nguy hiểm vào Sandbox: {desc}",
                )
        return GuardrailVerdict(
            allowed=True,
            risk_level="MEDIUM",
            reason=f"Cho phép chạy lệnh `{cmd}` bên trong Zero-Trust Sandbox cô lập.",
        )

    return GuardrailVerdict(
        allowed=True,
        risk_level="LOW",
        reason=f"MCP Tool `{tool_name}` thuộc nhóm giám sát/kiểm toán an toàn (Read-only).",
    )

