import os
import sys
import json
import asyncio
import argparse
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(PROJECT_DIR, ".."))
MCP_DIR = os.path.abspath(os.path.join(PROJECT_DIR, "mcp_server"))

for p in (CURRENT_DIR, MCP_DIR, PROJECT_DIR, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from guardrails import SYSTEM_PROMPT, check_user_input_guardrail, check_tool_call_guardrail
from mcp_server import mcp

load_dotenv(os.path.join(PROJECT_DIR, ".env"))
load_dotenv()
console = Console()


def extract_tool_text(tool_result) -> str:
    """Trích xuất chuỗi văn bản từ kết quả trả về của FastMCP call_tool."""
    if hasattr(tool_result, "content") and tool_result.content:
        parts = []
        for item in tool_result.content:
            parts.append(item.text if hasattr(item, "text") else str(item))
        return "\n".join(parts)
    if isinstance(tool_result, list) and tool_result:
        first = tool_result[0]
        return first.text if hasattr(first, "text") else str(first)
    return str(tool_result)


def plan_tools_from_natural_language(prompt: str) -> list[tuple[str, dict]]:
    """
    Phân tích câu lệnh tự nhiên của người dùng trên Terminal và chọn các MCP Tools tương ứng.
    """
    q = prompt.lower()
    planned: list[tuple[str, dict]] = []

    if any(k in q for k in ["toàn diện", "full audit", "kiểm toán toàn bộ", "tổng thể"]):
        return [("run_full_security_audit", {})]

    # 1. Tài nguyên hệ thống (CPU, RAM, Disk)
    if any(k in q for k in ["tài nguyên", "cpu", "ram", "memory", "bộ nhớ", "máy chủ", "resource", "disk", "ổ cứng"]):
        planned.append(("get_cpu_usage", {}))
        planned.append(("get_ram_usage", {}))
        if any(k in q for k in ["disk", "ổ cứng", "dung lượng", "tài nguyên"]):
            planned.append(("get_disk_usage", {}))

    # 2. Tiến trình (Process)
    if any(k in q for k in ["tiến trình", "process", "ps", "top", "ngốn", "đào coin"]):
        sort_key = "ram" if ("ram" in q or "bộ nhớ" in q) else "cpu"
        planned.append(("check_top_processes", {"limit": 10, "sort_by": sort_key}))

    # 3. Dịch vụ (Services)
    if any(k in q for k in ["dịch vụ", "service", "systemctl", "daemon", "ssh", "docker", "nginx"]):
        planned.append(("check_service_status", {"service_name": "all"}))

    # 4. Phát hiện file bất thường (Anomalous files)
    if any(k in q for k in ["file", "tệp", "bất thường", "anomal", "suid", "777", "/tmp", "mã độc", "backdoor"]):
        target_dir = "/tmp"
        for token in prompt.split():
            if token.startswith("/") and len(token) > 1:
                target_dir = token.strip(",.;'\"")
                break
        planned.append(("detect_anomalous_files", {"target_dir": target_dir}))

    # 5. Phân tích Log (Log analysis)
    if any(k in q for k in ["log", "nhật ký", "brute", "đăng nhập", "auth", "syslog", "tấn công"]):
        log_type = "syslog" if "syslog" in q else "auth"
        planned.append(("analyze_system_logs", {"log_type": log_type, "lines": 50}))

    # 6. Giám sát mạng (Network / Ports)
    if any(k in q for k in ["mạng", "network", "port", "cổng", "kết nối", "listen", "socket"]):
        planned.append(("monitor_network_connections", {}))

    # 7. Đề xuất cấu hình Firewall (UFW / iptables)
    if any(k in q for k in ["firewall", "tường lửa", "ufw", "iptables", "chặn ip", "cấu hình bảo mật"]):
        tool_names = [t[0] for t in planned]
        if "monitor_network_connections" not in tool_names:
            planned.append(("monitor_network_connections", {}))
        if "analyze_system_logs" not in tool_names:
            planned.append(("analyze_system_logs", {"log_type": "auth", "lines": 50}))
        planned.append(("propose_firewall_rules", {"suspicious_ips": "", "allowed_ports": "22,80,443"}))

    # 8. Chạy lệnh trong Sandbox (khi đặt lệnh trong dấu backtick `...` hoặc yêu cầu chạy lệnh)
    if "`" in prompt:
        parts = prompt.split("`")
        if len(parts) >= 2 and parts[1].strip():
            planned.append(("execute_sandboxed_command", {"command": parts[1].strip()}))
    elif any(k in q for k in ["sandbox", "chạy lệnh", "thực thi lệnh"]):
        cmd = prompt.split(":", 1)[1].strip() if ":" in prompt else "whoami && id && uname -a"
        planned.append(("execute_sandboxed_command", {"command": cmd}))

    # Nếu câu lệnh chưa khớp từ khóa cụ thể nào, thực hiện kiểm tra tổng quát hệ thống
    if not planned:
        planned = [
            ("get_cpu_usage", {}),
            ("get_ram_usage", {}),
            ("check_top_processes", {"limit": 5, "sort_by": "cpu"}),
            ("monitor_network_connections", {}),
        ]

    return planned


async def execute_mcp_tool_with_guardrail(tool_name: str, tool_args: dict) -> str:
    """Kiểm tra Guardrail và thực thi công cụ trên MCP Server."""
    verdict = check_tool_call_guardrail(tool_name, tool_args)
    if not verdict.allowed:
        console.print(f"[bold red]✗ {verdict.reason}[/bold red]")
        return verdict.reason

    console.print(
        f"[cyan]⚙ [MCP Client -> Server][/cyan] Gọi tool [bold yellow]{tool_name}[/bold yellow] "
        f"tham số `{json.dumps(tool_args, ensure_ascii=False)}` "
        f"([green]Risk: {verdict.risk_level}[/green])"
    )
    raw_res = await mcp.call_tool(tool_name, tool_args)
    return extract_tool_text(raw_res)


async def synthesize_response(user_prompt: str, tool_outputs: list[tuple[str, str]]) -> str:
    """Tổng hợp kết quả qua Google Gemini (nếu có GEMINI_API_KEY) hoặc xuất báo cáo trực tiếp."""
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    combined_context = "\n\n".join([f"### Kết quả từ `{name}`:\n{out}" for name, out in tool_outputs])

    if api_key:
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=api_key)
            prompt_content = (
                f"Yêu cầu từ Terminal: \"{user_prompt}\"\n\n"
                f"Dữ liệu thu thập thực tế từ các MCP Tools trên hệ thống:\n{combined_context}\n\n"
                "Hãy phân tích ngắn gọn, chính xác và đưa ra khuyến nghị quản trị/bảo mật phù hợp."
            )
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt_content,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=0.2,
                ),
            )
            if response and response.text:
                return response.text
        except Exception as e:
            console.print(f"[yellow][!] Không thể gọi Gemini API ({e}), hiển thị báo cáo trực tiếp từ MCP Tools.[/yellow]")

    report_lines = [
        "## 📊 BÁO CÁO THỰC THI TỪ AI AGENT & MCP SERVER",
        f"**Câu lệnh yêu cầu:** `{user_prompt}`",
        f"**Các MCP Tools đã thực thi:** `{', '.join(t[0] for t in tool_outputs)}`",
        "---",
    ]
    for idx, (t_name, t_out) in enumerate(tool_outputs, 1):
        report_lines.append(f"### {idx}. `{t_name}`")
        report_lines.append(t_out)
        report_lines.append("")

    return "\n".join(report_lines)


async def process_user_query(user_prompt: str):
    """Xử lý câu lệnh tự nhiên của người dùng."""
    input_check = check_user_input_guardrail(user_prompt)
    if not input_check.allowed:
        console.print(Panel(f"[bold red]{input_check.reason}[/bold red]", title="🛑 Guardrail Blocked", border_style="red"))
        return

    planned_calls = plan_tools_from_natural_language(user_prompt)
    console.print(
        f"[magenta]🧠 [Agent Planner][/magenta] Kích hoạt [bold]{len(planned_calls)}[/bold] MCP Tools: "
        f"`{[name for name, _ in planned_calls]}`"
    )

    tool_outputs: list[tuple[str, str]] = []
    for tool_name, tool_args in planned_calls:
        output_text = await execute_mcp_tool_with_guardrail(tool_name, tool_args)
        tool_outputs.append((tool_name, output_text))

    final_report = await synthesize_response(user_prompt, tool_outputs)
    console.print(Panel(Markdown(final_report), title="📋 Kết quả Phân tích & Thực thi", border_style="green"))


async def show_registered_mcp_tools():
    """Hiển thị danh sách công cụ đang đăng ký trên MCP Server."""
    tools = await mcp.list_tools()
    table = Table(title="🔧 Danh sách MCP Tools hiện có", show_lines=True)
    table.add_column("STT", justify="center", style="cyan", width=5)
    table.add_column("Tên Tool", style="bold yellow", width=28)
    table.add_column("Mô tả", style="white")

    for i, t in enumerate(tools, 1):
        desc = (t.description or "").strip().replace("\n", " ")
        table.add_row(str(i), t.name, desc)

    console.print(table)


async def interactive_terminal():
    """Giao diện Terminal tương tác trực tiếp."""
    console.print(
        Panel.fit(
            "[bold cyan]LINUX MCP AI AGENT CLI[/bold cyan]\n"
            "Nhập trực tiếp yêu cầu bằng ngôn ngữ tự nhiên (hoặc gõ `tools` để xem công cụ, `exit` để thoát).\n"
            "Để chạy một câu lệnh bash trong Sandbox, đặt lệnh trong dấu backtick, ví dụ: `Chạy lệnh `uname -a && id` trong sandbox`",
            border_style="bright_blue",
        )
    )

    while True:
        try:
            user_input = console.input("\n[bold green]LinuxAdmin@Agent[/bold green][bold white]:~$ [/bold white]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Đã thoát Agent CLI.[/yellow]")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            break
        if user_input.lower() == "tools":
            await show_registered_mcp_tools()
            continue

        await process_user_query(user_input)


async def main():
    parser = argparse.ArgumentParser(
        description="Linux MCP AI Agent CLI - Nhập trực tiếp câu lệnh tự nhiên trên Terminal"
    )
    parser.add_argument(
        "prompt",
        nargs="*",
        help="Câu lệnh tự nhiên truyền thẳng từ Terminal (nếu bỏ trống sẽ vào chế độ tương tác)",
    )
    parser.add_argument("-q", "--query", type=str, help="Câu lệnh tự nhiên cần thực thi")
    parser.add_argument("--list-tools", action="store_true", help="Liệt kê danh sách các MCP Tools")
    args = parser.parse_args()

    if args.list_tools:
        await show_registered_mcp_tools()
        return

    direct_prompt = args.query or (" ".join(args.prompt).strip() if args.prompt else "")
    if direct_prompt:
        await process_user_query(direct_prompt)
        return

    await interactive_terminal()


if __name__ == "__main__":
    asyncio.run(main())
