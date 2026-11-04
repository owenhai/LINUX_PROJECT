import subprocess
import json
import sys

def run_command_in_sandbox(cmd: str, timeout: int = 15) -> dict:
    """
    Thực thi câu lệnh Linux bên trong Docker Sandbox cách ly.
    Trả về dict chứa stdout, stderr và returncode.
    """
    docker_cmd = [
        "docker", "run", "--rm",
        "--cpus=0.5",
        "-m=512m",
        "--security-opt=no-new-privileges:true",
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
    # Test chạy thử lệnh kiểm tra dung lượng ổ đĩa
    test_cmd = "df -h"
    if len(sys.argv) > 1:
        test_cmd = " ".join(sys.argv[1:])
        
    print(f"--- Running inside Sandbox: '{test_cmd}' ---")
    output = run_command_in_sandbox(test_cmd)
    print(json.dumps(output, indent=2, ensure_ascii=False))
