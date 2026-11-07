# Zero-Trust Linux Sandbox & Isolation (Thành viên 1)

Phân hệ cô lập môi trường thực thi câu lệnh trên Linux sử dụng **Docker Container, Linux Namespaces và Control Groups (`cgroups`)** nhằm đảm bảo mọi lệnh từ AI Agent không thể làm hỏng hệ điều hành máy chủ (Host OS).

---

## 📂 Cấu trúc Thư mục `sandbox/`

- `Dockerfile`: Định nghĩa môi trường Ubuntu 24.04 với các gói công cụ quản trị/kiểm toán (`procps`, `net-tools`, `iproute2`, `iptables`, `ufw`, `lsof`, `sysstat`, `findutils`) và tài khoản giới hạn `sandboxuser` (`non-root`).
- `sandbox_runner.py`: Cung cấp hàm `run_command_in_sandbox(cmd)` kết hợp bộ lọc Regex tiền thực thi (`validate_command_safety`) và các cờ cô lập Kernel của Docker.
- `build_sandbox.sh`: Script tự động build Docker image `agent-sandbox` và kiểm tra tính năng cô lập.
- `INTEGRATION.md`: Tài liệu hướng dẫn cách Thành viên 2 import và gọi hàm Sandbox.

---

## 🛡️ Các cơ chế cô lập được áp dụng

1. **Regex Safety Pre-check**: Chặn trước các mẫu lệnh nguy hiểm (`rm -rf /`, Fork Bomb, `mkfs`, `dd`, Reverse Shell).
2. **Non-root User (`sandboxuser`)**: Không cấp quyền `root` bên trong container.
3. **Read-Only Root Filesystem (`--read-only`)**: Khóa chỉ đọc toàn bộ hệ thống tệp gốc.
4. **RAM-based `/tmp` (`--tmpfs /tmp:rw,noexec,nosuid,size=64m`)**: Cấm thực thi file nhị phân/script trong `/tmp`.
5. **Drop Capabilities (`--cap-drop=ALL` & `--security-opt=no-new-privileges:true`)**: Loại bỏ mọi đặc quyền Linux Kernel và chống leo thang đặc quyền qua bit SUID.
6. **Giới hạn tài nguyên bằng `cgroups` (`--pids-limit=100`, `--cpus=0.5`, `-m=512m`)**: Chống tấn công làm cạn kiệt tài nguyên (Fork Bomb / DoS).
7. **Network Isolation (`--network=none`)**: Ngắt hoàn toàn kết nối mạng ra bên ngoài khi thực thi lệnh trong Sandbox.

---

## 🐧 Cách Build và Kiểm tra trên Linux Terminal

```bash
cd LINUX_PROJECT

# 1. Build image agent-sandbox và chạy kiểm tra tự động
chmod +x sandbox/build_sandbox.sh
./sandbox/build_sandbox.sh

# 2. Chạy thử một câu lệnh bất kỳ trong Sandbox
python3 sandbox/sandbox_runner.py "whoami && id && uname -a"
```
