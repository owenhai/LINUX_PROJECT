import sys
import os
import asyncio
import json

# Thêm thư mục gốc vào đường dẫn Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from mcp_server import mcp

async def run_agent():
    print("=== [AGENT] Bắt đầu kết nối tới MCP Server ===")
    
    # Đọc cấu hình MCP
    with open("mcp_config.json", "r") as f:
        config = json.load(f)
    print(f"[AGENT] Đã tải cấu hình: {list(config['mcpServers'].keys())}")

    # Lấy danh sách công cụ
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    print(f"[AGENT] Công cụ phát hiện được: {tool_names}")

    # Thực thi gọi công cụ
    print("\n--- [AGENT] Thực thi giám sát hệ thống ---")
    cpu_data = await mcp.call_tool("get_cpu_usage", {})
    ram_data = await mcp.call_tool("get_ram_usage", {})

    # Ép kiểu dữ liệu ToolResult ra văn bản
    print(f"[AGENT RESULT] Trạng thái CPU -> {cpu_data.content[0].text if hasattr(cpu_data, 'content') else cpu_data}")
    print(f"[AGENT RESULT] Trạng thái RAM -> {ram_data.content[0].text if hasattr(ram_data, 'content') else ram_data}")
    print("\n=== [AGENT] Tích hợp thành công! ===")

if __name__ == "__main__":
    asyncio.run(run_agent())
