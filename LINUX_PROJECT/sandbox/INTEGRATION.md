# Sandbox Integration Guide for Member 2 (MCP Server)

## How to Use
Import hàm `run_command_in_sandbox` từ file `sandbox_runner.py` để chạy bất kỳ câu lệnh Linux nào bên trong môi trường Zero-Trust Sandbox:

```python
from sandbox.sandbox_runner import run_command_in_sandbox

# Ví dụ gọi kiểm tra tiến trình hệ thống
result = run_command_in_sandbox("ps aux")

if result["success"]:
    print("Output:", result["stdout"])
else:
    print("Error:", result["stderr"])~
