import subprocess
import json
import sys

def run_command_in_sandbox(cmd: str, timeout: int = 15) -> dict:
    """
    Thực thi câu lệnh Linux trong Sandbox bảo mật cấp cao (Zero-Trust isolation):
    - Non-root user (sandboxuser)
    - Khóa hệ thống tệp chỉ đọc (--read-only)
    - RAM-based tmpfs cho /tmp (--tmpfs với flag cấm thực thi)
    - Drop toàn bộ Linux capabilities (--cap-drop=ALL)
    - Giới hạn tiến trình chống Fork Bomb (--pids-limit=100)
    - Giới hạn tài nguyên (0.5 CPU, 512MB RAM)
    - Cách ly mạng hoàn toàn (--network=none)
    """
    docker_cmd = [
        "docker", "run", "--rm",
        "--network=none",                        # Cách ly mạng hoàn toàn
        "--read-only",                           # Khóa hệ thống tệp chỉ đọc
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", # Cấp /tmp trên RAM, cấm chạy file thực thi
        "--cap-drop=ALL",                        # Loại bỏ toàn bộ quyền Linux Kernel
        "--pids-limit=100",                      # Chống Fork Bomb
        "--cpus=0.5",                            # Giới hạn 50% CPU
        "-m=512m",                               # Giới hạn 512MB RAM
        "--security-opt=no-new-privileges:true", # Chống leo leo quyền SUID
        "agent-sandbox",
        "bash", "-c", cmd
    ]
    
    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Error: Command execution timed out ({timeout}s)",
            "exit_code": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1
        }

if __name__ == "__main__":
    test_cmd = "whoami && id"
    if len(sys.argv) > 1:
        test_cmd = " ".join(sys.argv[1:])
        
    print(f"--- Running in Hardened Sandbox: '{test_cmd}' ---")
    output = run_command_in_sandbox(test_cmd)
    print(json.dumps(output, indent=2, ensure_ascii=False))
