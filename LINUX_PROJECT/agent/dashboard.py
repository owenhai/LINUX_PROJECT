import os
import sys
import asyncio
import psutil
import streamlit as st
from dotenv import load_dotenv

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
MCP_DIR = os.path.abspath(os.path.join(PROJECT_DIR, "mcp_server"))

load_dotenv(os.path.join(PROJECT_DIR, ".env"))
load_dotenv()

for p in (CURRENT_DIR, MCP_DIR, PROJECT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from guardrails import check_user_input_guardrail, check_tool_call_guardrail
from agent_cli import (
    plan_tools_from_natural_language,
    extract_tool_text,
    synthesize_response,
)
from mcp_server import mcp

st.set_page_config(
    page_title="Linux MCP AI Agent Dashboard",
    page_icon="🐧",
    layout="wide",
)

st.title("🐧 Linux System Administration & Security Auditing Dashboard")
st.caption("Model Context Protocol (FastMCP) • Zero-Trust Sandbox • Agentic AI & Guardrails")


def get_live_metrics():
    cpu = psutil.cpu_percent(interval=0.2)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    try:
        listen_ports = len(
            {
                c.laddr.port
                for c in psutil.net_connections(kind="inet")
                if c.status == psutil.CONN_LISTEN and c.laddr
            }
        )
    except Exception:
        listen_ports = 0
    return cpu, ram, disk, listen_ports


async def call_single_mcp_tool(tool_name: str, tool_args: dict) -> str:
    verdict = check_tool_call_guardrail(tool_name, tool_args)
    if not verdict.allowed:
        return verdict.reason
    res = await mcp.call_tool(tool_name, tool_args)
    return extract_tool_text(res)


async def run_agent_query(prompt: str) -> dict:
    verdict = check_user_input_guardrail(prompt)
    if not verdict.allowed:
        return {
            "blocked": True,
            "reason": verdict.reason,
            "planned_tools": [],
            "tool_outputs": [],
            "report": "",
        }

    planned = plan_tools_from_natural_language(prompt)
    outputs = []
    for t_name, t_args in planned:
        t_verdict = check_tool_call_guardrail(t_name, t_args)
        if not t_verdict.allowed:
            outputs.append((t_name, t_verdict.reason))
            continue
        res = await mcp.call_tool(t_name, t_args)
        outputs.append((t_name, extract_tool_text(res)))

    report = await synthesize_response(prompt, outputs)
    return {
        "blocked": False,
        "reason": verdict.reason,
        "planned_tools": [t[0] for t in planned],
        "tool_outputs": outputs,
        "report": report,
    }


# --- SIDEBAR: CẤU HÌNH & CÔNG CỤ NHANH ---
with st.sidebar:
    st.header("⚙️ Điều khiển & Cấu hình")
    if st.button("🔄 Làm mới thông số máy chủ", use_container_width=True):
        st.rerun()

    st.divider()
    api_key_val = st.text_input(
        "GEMINI_API_KEY (Tùy chọn)",
        value=os.environ.get("GEMINI_API_KEY", ""),
        type="password",
        help="Nhập khóa Gemini nếu muốn LLM viết nhận xét chuyên sâu.",
    )
    if api_key_val:
        os.environ["GEMINI_API_KEY"] = api_key_val

    st.divider()
    st.subheader("🧰 Chạy nhanh MCP Tool")
    tool_options = {
        "Kiểm tra CPU (get_cpu_usage)": ("get_cpu_usage", {}),
        "Kiểm tra RAM (get_ram_usage)": ("get_ram_usage", {}),
        "Kiểm tra Ổ cứng (get_disk_usage)": ("get_disk_usage", {}),
        "Top Tiến trình (check_top_processes)": ("check_top_processes", {"limit": 10, "sort_by": "cpu"}),
        "Trạng thái Dịch vụ (check_service_status)": ("check_service_status", {"service_name": "all"}),
        "Phân tích Log (analyze_system_logs)": ("analyze_system_logs", {"log_type": "auth", "lines": 50}),
        "Giám sát Mạng (monitor_network_connections)": ("monitor_network_connections", {}),
        "Quét File bất thường /tmp (detect_anomalous_files)": ("detect_anomalous_files", {"target_dir": "/tmp"}),
        "Đề xuất Firewall (propose_firewall_rules)": ("propose_firewall_rules", {"suspicious_ips": "", "allowed_ports": "22,80,443"}),
        "Kiểm toán Toàn diện (run_full_security_audit)": ("run_full_security_audit", {}),
    }
    selected_label = st.selectbox("Chọn công cụ MCP:", list(tool_options.keys()))
    run_tool_btn = st.button("▶️ Thực thi Tool", use_container_width=True)

    st.divider()
    st.subheader("📦 Chạy lệnh trong Sandbox")
    sandbox_cmd = st.text_input("Câu lệnh Linux:", placeholder="Ví dụ: whoami && id && uname -a")
    run_sandbox_btn = st.button("🛡️ Chạy trong Sandbox", use_container_width=True)


# --- HÀNG 1: THÔNG SỐ HỆ THỐNG REALTIME ---
cpu_val, ram_obj, disk_obj, port_count = get_live_metrics()
col1, col2, col3, col4 = st.columns(4)
col1.metric("CPU Usage", f"{cpu_val}%")
col2.metric("RAM Usage", f"{ram_obj.percent}%", f"{ram_obj.used / (1024**3):.1f} / {ram_obj.total / (1024**3):.1f} GB")
col3.metric("Disk Usage (/)", f"{disk_obj.percent}%", f"Trống {disk_obj.free / (1024**3):.1f} GB")
col4.metric("Listening Ports", f"{port_count} cổng")

st.divider()

# --- XỬ LÝ NÚT CHẠY NHANH TRÊN SIDEBAR ---
if run_tool_btn:
    t_name, t_args = tool_options[selected_label]
    with st.spinner(f"Đang gọi MCP Tool `{t_name}`..."):
        out = asyncio.run(call_single_mcp_tool(t_name, t_args))
    st.subheader(f"🔧 Kết quả từ MCP Tool: `{t_name}`")
    st.code(out)

if run_sandbox_btn and sandbox_cmd.strip():
    with st.spinner(f"Đang thực thi `{sandbox_cmd}` trong Zero-Trust Sandbox..."):
        out = asyncio.run(call_single_mcp_tool("execute_sandboxed_command", {"command": sandbox_cmd.strip()}))
    st.subheader(f"📦 Kết quả thực thi Sandbox: `{sandbox_cmd}`")
    if "BLOCKED" in out:
        st.error(out)
    else:
        st.code(out, language="json")

# --- LỊCH SỬ & KHUNG CHAT VỚI AI AGENT ---
st.subheader("💬 Giao tiếp Ngôn ngữ Tự nhiên với AI Agent")

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

for msg in st.session_state.chat_history:
    with st.chat_message(msg["role"]):
        if msg.get("blocked"):
            st.error(msg["content"])
        else:
            if msg.get("tools"):
                st.caption(f"⚙️ MCP Tools đã gọi: `{', '.join(msg['tools'])}`")
            st.markdown(msg["content"])

user_prompt = st.chat_input("Nhập câu lệnh tự nhiên cho AI Agent (VD: Kiểm tra tài nguyên, quét file /tmp và đề xuất firewall)...")

if user_prompt:
    st.session_state.chat_history.append({"role": "user", "content": user_prompt})
    with st.chat_message("user"):
        st.write(user_prompt)

    with st.chat_message("assistant"):
        with st.spinner("AI Agent đang kiểm tra Guardrails và gọi các MCP Tools..."):
            res = asyncio.run(run_agent_query(user_prompt))

        if res["blocked"]:
            st.error(res["reason"])
            st.session_state.chat_history.append({
                "role": "assistant",
                "content": res["reason"],
                "blocked": True,
            })
        else:
            st.success(f"✓ Guardrail: {res['reason']} | MCP Tools kích hoạt: `{res['planned_tools']}`")
            with st.expander("Xem dữ liệu thô trả về từ từng MCP Tool", expanded=False):
                for t_name, t_out in res["tool_outputs"]:
                    st.markdown(f"**`{t_name}`**")
                    st.code(t_out)
            st.markdown(res["report"])
            st.session_state.chat_history.append({
                "role": "assistant",
                "content": res["report"],
                "tools": res["planned_tools"],
                "blocked": False,
            })

