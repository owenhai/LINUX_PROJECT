# Sandbox Integration Guide for Member 2 (MCP Server)

## Cách tích hợp với MCP Server (`mcp_server/mcp_server.py`)
Import hàm `run_command_in_sandbox` từ module `sandbox.sandbox_runner` để thực thi bất kỳ câu lệnh Linux nào bên trong môi trường Zero-Trust Sandbox:

```python
from sandbox.sandbox_runner import run_command_in_sandbox

# Ví dụ gọi kiểm tra tiến trình hệ thống trong Sandbox cô lập
result = run_command_in_sandbox("ps aux")

if result["success"]:
    print("Mode:", result["mode"])
    print("Output:", result["stdout"])
else:
    print("Error:", result["stderr"])
```
