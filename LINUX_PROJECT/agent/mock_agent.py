import sys
import os
import asyncio
import json

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MCP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../mcp_server"))
for p in (MCP_DIR, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from mcp_server import mcp


def _extract_text(res) -> str:
    if hasattr(res, "content") and res.content:
        return res.content[0].text
    if isinstance(res, list) and res:
        return res[0].text if hasattr(res[0], "text") else str(res[0])
    return str(res)


async def run_agent():
    print("=== [AGENT] Bắt đầu kết nối tới MCP Server ===")

    config_path = os.path.join(MCP_DIR, "mcp_config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(REPO_ROOT, "mcp_config.json")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    print(f"[AGENT] Đã tải cấu hình ({config_path}): {list(config['mcpServers'].keys())}")

    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    print(f"[AGENT] Công cụ phát hiện được ({len(tool_names)} tools): {tool_names}")

    print("\n--- [AGENT] Thực thi giám sát hệ thống ---")
    cpu_data = await mcp.call_tool("get_cpu_usage", {})
    ram_data = await mcp.call_tool("get_ram_usage", {})

    print(f"[AGENT RESULT] Trạng thái CPU -> {_extract_text(cpu_data)}")
    print(f"[AGENT RESULT] Trạng thái RAM -> {_extract_text(ram_data)}")
    print("\n=== [AGENT] Tích hợp thành công! ===")


if __name__ == "__main__":
    asyncio.run(run_agent())
