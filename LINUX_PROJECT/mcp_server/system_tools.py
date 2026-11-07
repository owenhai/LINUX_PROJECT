import os
import sys
import stat
import shutil
import platform
import subprocess
from datetime import datetime
import psutil

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sandbox.sandbox_runner import run_command_in_sandbox


def collect_cpu_metrics() -> str:
    """Thu thập thông số CPU thực tế (%, số nhân, tần số, load average)."""
    cpu_percent = psutil.cpu_percent(interval=0.5)
    logical_cores = psutil.cpu_count(logical=True)
    physical_cores = psutil.cpu_count(logical=False) or logical_cores

    freq_info = ""
    try:
        freq = psutil.cpu_freq()
        if freq and freq.current:
            freq_info = f" | Xung nhịp: {freq.current:.0f} MHz"
    except Exception:
        pass

    load_str = ""
    if hasattr(os, "getloadavg"):
        try:
            l1, l5, l15 = os.getloadavg()
            load_str = f" | Load Average (1m/5m/15m): {l1:.2f}, {l5:.2f}, {l15:.2f}"
        except Exception:
            pass

    status = "BÌNH THƯỜNG"
    if cpu_percent >= 85:
        status = "CẢNH BÁO CAO (Overload)"
    elif cpu_percent >= 65:
        status = "TRUNG BÌNH - CAO"

    return (
        f"CPU Usage: {cpu_percent}% [{status}] "
        f"(Cores: {physical_cores} vật lý / {logical_cores} luồng{freq_info}{load_str})"
    )


def collect_ram_metrics() -> str:
    """Thu thập thông số bộ nhớ RAM và Swap thực tế."""
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()

    used_gb = ram.used / (1024 ** 3)
    avail_gb = ram.available / (1024 ** 3)
    total_gb = ram.total / (1024 ** 3)
    swap_used_gb = swap.used / (1024 ** 3)
    swap_total_gb = swap.total / (1024 ** 3)

    status = "BÌNH THƯỜNG"
    if ram.percent >= 85:
        status = "NGUY HIỂM (Sắp tràn RAM)"
    elif ram.percent >= 70:
        status = "CẢNH BÁO (Sử dụng cao)"

    return (
        f"RAM Usage: {ram.percent}% [{status}] "
        f"(Đã dùng: {used_gb:.2f} GB / Khả dụng: {avail_gb:.2f} GB / Tổng: {total_gb:.2f} GB) | "
        f"Swap: {swap.percent}% ({swap_used_gb:.2f} GB / {swap_total_gb:.2f} GB)"
    )


def collect_disk_metrics() -> str:
    """Kiểm tra dung lượng các phân vùng ổ cứng trên máy chủ."""
    lines = ["=== THÔNG TIN PHÂN VÙNG Ổ CỨNG (DISK USAGE) ==="]
    warnings = []

    partitions = psutil.disk_partitions(all=False)
    for part in partitions:
        if "cdrom" in part.opts or part.fstype == "":
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            total_gb = usage.total / (1024 ** 3)
            used_gb = usage.used / (1024 ** 3)
            free_gb = usage.free / (1024 ** 3)
            flag = " [CẢNH BÁO ĐẦY >85%]" if usage.percent >= 85 else ""
            if usage.percent >= 85:
                warnings.append(f"Phân vùng {part.mountpoint} đạt {usage.percent}%!")
            lines.append(
                f"- Mount `{part.mountpoint}` ({part.fstype}): {usage.percent}% "
                f"(Đã dùng: {used_gb:.2f} GB / Trống: {free_gb:.2f} GB / Tổng: {total_gb:.2f} GB){flag}"
            )
        except PermissionError:
            continue

    if warnings:
        lines.append("\n[!] CẢNH BÁO DUNG LƯỢNG: " + "; ".join(warnings))
    return "\n".join(lines)


def inspect_top_processes(limit: int = 10, sort_by: str = "cpu") -> str:
    """Liệt kê các tiến trình tiêu thụ nhiều CPU/RAM nhất và rà soát tiến trình khả nghi."""
    procs = []
    suspicious_keywords = ["xmrig", "minerd", "cryptonight", "ncat", "netcat", "/tmp/."]

    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "exe", "cmdline"]):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    key_field = "memory_percent" if sort_by.lower() in ("ram", "mem", "memory") else "cpu_percent"
    procs.sort(key=lambda x: x.get(key_field) or 0.0, reverse=True)

    top_list = procs[: max(1, min(limit, 30))]
    lines = [f"=== TOP {len(top_list)} TIẾN TRÌNH THEO {sort_by.upper()} ==="]
    suspicious_found = []

    for idx, p in enumerate(top_list, 1):
        pid = p.get("pid")
        name = p.get("name") or "unknown"
        user = p.get("username") or "system"
        cpu_p = p.get("cpu_percent") or 0.0
        mem_p = p.get("memory_percent") or 0.0
        cmdline_list = p.get("cmdline") or []
        cmd_str = " ".join(cmdline_list)[:80] if cmdline_list else name

        lines.append(
            f"{idx}. PID {pid:<6} | {name:<22} | CPU: {cpu_p:>5.1f}% | RAM: {mem_p:>5.1f}% | User: {user} | Cmd: `{cmd_str}`"
        )

    for p in procs:
        cmd_full = " ".join(p.get("cmdline") or []).lower()
        exe_full = (p.get("exe") or "").lower()
        name_full = (p.get("name") or "").lower()
        for kw in suspicious_keywords:
            if kw in cmd_full or kw in exe_full or kw in name_full:
                suspicious_found.append(
                    f"PID {p.get('pid')} ({p.get('name')}) chạy bởi {p.get('username')}: khớp dấu hiệu `{kw}`"
                )

    if suspicious_found:
        lines.append("\n[!] PHÁT HIỆN TIẾN TRÌNH ĐÁNG NGỜ:")
        for s in suspicious_found:
            lines.append(f"  - {s}")
    else:
        lines.append("\n[+] Đánh giá an ninh tiến trình: Không phát hiện tiến trình bất thường.")

    return "\n".join(lines)


def inspect_service_status(service_name: str = "all") -> str:
    """Kiểm tra trạng thái dịch vụ hệ thống qua systemctl hoặc bảng tiến trình."""
    core_services = ["ssh", "sshd", "ufw", "docker", "cron", "rsyslog", "systemd-journald", "nginx"]
    target_services = core_services if service_name.lower() in ("all", "*", "") else [service_name]

    is_linux = platform.system().lower() == "linux"
    lines = ["=== TRẠNG THÁI DỊCH VỤ HỆ THỐNG (SERVICE STATUS) ==="]

    if is_linux and shutil.which("systemctl"):
        for svc in target_services:
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                state = res.stdout.strip() or "inactive"
                icon = "[RUNNING]" if state == "active" else "[INACTIVE]"
                lines.append(f"- Dịch vụ `{svc}`: {icon} (systemctl: {state})")
            except Exception as e:
                lines.append(f"- Dịch vụ `{svc}`: Không thể kiểm tra ({e})")
    else:
        running_names = {p.info["name"].lower() for p in psutil.process_iter(["name"]) if p.info.get("name")}
        for svc in target_services:
            matched = any(svc.lower() in rname for rname in running_names)
            state_str = "[RUNNING]" if matched else "[INACTIVE]"
            lines.append(f"- Dịch vụ `{svc}`: {state_str}")

    return "\n".join(lines)


def _read_system_log_lines(log_type: str = "auth", lines_count: int = 50) -> tuple[str, list[str]]:
    """Đọc trực tiếp file log hệ thống Linux hoặc journalctl."""
    log_paths = {
        "auth": ["/var/log/auth.log", "/var/log/secure"],
        "syslog": ["/var/log/syslog", "/var/log/messages"],
    }
    selected_paths = log_paths.get(log_type.lower(), ["/var/log/auth.log", "/var/log/syslog"])

    for path in selected_paths:
        if os.path.exists(path) and os.access(path, os.R_OK):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    all_l = f.readlines()
                    return path, [l.strip() for l in all_l[-lines_count:] if l.strip()]
            except Exception:
                continue

    if shutil.which("journalctl"):
        try:
            res = subprocess.run(
                ["journalctl", "-n", str(lines_count), "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                return "journalctl", [l.strip() for l in res.stdout.splitlines() if l.strip()]
        except Exception:
            pass

    if shutil.which("dmesg"):
        try:
            res = subprocess.run(
                ["dmesg", "--time-format=iso"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                out_lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                return "dmesg", out_lines[-lines_count:]
        except Exception:
            pass

    return "unavailable", []


def extract_suspicious_ips_from_logs(lines_count: int = 100) -> list[str]:
    """Trích xuất danh sách IP đăng nhập thất bại thực tế từ log hệ thống."""
    _, raw_lines = _read_system_log_lines("auth", lines_count=lines_count)
    ips = set()
    for line in raw_lines:
        low = line.lower()
        if "failed password" in low or "invalid user" in low or "authentication failure" in low:
            parts = line.split()
            if "from" in parts:
                idx = parts.index("from")
                if idx + 1 < len(parts):
                    ips.add(parts[idx + 1])
    return sorted(ips)


def analyze_logs(log_type: str = "auth", lines_count: int = 50) -> str:
    """Phân tích nhật ký hệ thống Linux thực tế (/var/log/auth.log, /var/log/syslog, journalctl)."""
    source_used, raw_lines = _read_system_log_lines(log_type=log_type, lines_count=lines_count)

    if not raw_lines:
        return (
            "=== KẾT QUẢ PHÂN TÍCH LOG HỆ THỐNG ===\n"
            "- Không đọc được `/var/log/auth.log`, `/var/log/syslog` hoặc `journalctl` "
            "(cần chạy trên Linux hoặc cấp quyền đọc nhóm `adm` / `sudo`)."
        )

    failed_ssh = [
        l for l in raw_lines
        if "failed password" in l.lower() or "invalid user" in l.lower() or "authentication failure" in l.lower()
    ]
    sudo_events = [l for l in raw_lines if "sudo:" in l.lower() or "command=" in l.lower()]
    error_events = [l for l in raw_lines if any(k in l.lower() for k in ["error", "fail", "denied", "segfault"])]

    attacker_ips = extract_suspicious_ips_from_logs(lines_count=lines_count)

    report = [
        f"=== KẾT QUẢ PHÂN TÍCH LOG HỆ THỐNG (Nguồn: `{source_used}`) ===",
        f"- Tổng số dòng log đã đọc: {len(raw_lines)}",
        f"- Sự kiện xác thực thất bại (Failed Auth/SSH): {len(failed_ssh)}",
        f"- Sự kiện thực thi sudo/privilege: {len(sudo_events)}",
        f"- Sự kiện cảnh báo/lỗi (Error/Denied): {len(error_events)}",
    ]

    if attacker_ips:
        report.append(f"- [!] Phát hiện IP đăng nhập thất bại: {', '.join(attacker_ips)}")

    if failed_ssh:
        report.append("\n--- Các dòng log xác thực thất bại gần nhất ---")
        for item in failed_ssh[-5:]:
            report.append(f"  * {item}")

    if sudo_events:
        report.append("\n--- Các dòng log Sudo gần nhất ---")
        for item in sudo_events[-5:]:
            report.append(f"  * {item}")

    if not failed_ssh and not sudo_events:
        report.append("\n--- 5 dòng log hệ thống mới nhất ---")
        for item in raw_lines[-5:]:
            report.append(f"  * {item}")

    return "\n".join(report)


def monitor_network() -> str:
    """Giám sát kết nối mạng, các cổng đang mở LISTEN và kết nối ESTABLISHED thực tế."""
    lines = ["=== GIÁM SÁT MẠNG & CỔNG ĐANG MỞ (NETWORK & LISTENING PORTS) ==="]
    listening_ports = []
    established_conns = []

    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            pid = c.pid or "-"
            proc_name = "unknown"
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    pass

            if c.status == psutil.CONN_LISTEN:
                listening_ports.append((c.laddr.port, laddr, pid, proc_name))
            elif c.status == psutil.CONN_ESTABLISHED:
                established_conns.append((laddr, raddr, pid, proc_name))
    except psutil.AccessDenied:
        lines.append("[!] Quyền truy cập hạn chế một số socket hệ thống (chạy sudo trên Linux để xem đầy đủ PID).")
    except Exception as e:
        lines.append(f"[!] Lỗi đọc socket: {e}")

    seen_ports = set()
    unique_listen = []
    for port, laddr, pid, pname in sorted(listening_ports, key=lambda x: x[0]):
        if (port, laddr) not in seen_ports:
            seen_ports.add((port, laddr))
            unique_listen.append((port, laddr, pid, pname))

    lines.append(f"\n1. Các cổng đang lắng nghe (LISTEN): {len(unique_listen)} cổng")
    risky_ports = {21: "FTP", 23: "Telnet", 3306: "MySQL", 4444: "ReverseShell/Metasploit", 6379: "Redis", 5432: "PostgreSQL"}
    detected_risky = []

    for port, laddr, pid, pname in unique_listen[:25]:
        risk_note = ""
        if port in risky_ports and not laddr.startswith("127.0.0.1") and not laddr.startswith("::1"):
            risk_note = f" [CẢNH BÁO: Cổng {risky_ports[port]} mở toàn cục]"
            detected_risky.append(f"Port {port} ({risky_ports[port]} - {laddr}) bởi {pname}")
        lines.append(f"   - Port {port:<5} ({laddr:<20}) | PID: {str(pid):<6} | Process: {pname}{risk_note}")

    lines.append(f"\n2. Kết nối đang thiết lập (ESTABLISHED): {len(established_conns)} kết nối")
    for laddr, raddr, pid, pname in established_conns[:10]:
        lines.append(f"   - {laddr:<22} -> {raddr:<22} | PID: {str(pid):<6} ({pname})")

    net_io = psutil.net_io_counters()
    sent_mb = net_io.bytes_sent / (1024 ** 2)
    recv_mb = net_io.bytes_recv / (1024 ** 2)
    lines.append(f"\n3. Lưu lượng I/O Mạng: Đã gửi {sent_mb:.2f} MB | Đã nhận {recv_mb:.2f} MB")

    if detected_risky:
        lines.append("\n[!] CẢNH BÁO CỔNG NHẠY CẢM MỞ PUBLIC: " + "; ".join(detected_risky))
    return "\n".join(lines)


def scan_anomalous_files(target_dir: str = "/tmp") -> str:
    """Quét và phát hiện các file bất thường trong thư mục chỉ định trên máy."""
    scan_path = target_dir
    if not os.path.exists(scan_path):
        import tempfile
        scan_path = tempfile.gettempdir()

    anomalies = []
    scanned_count = 0
    suspicious_exts = (".sh", ".elf", ".bin", ".pl", ".php", ".py", ".exe", ".bat", ".ps1")

    try:
        for root, dirs, files in os.walk(scan_path):
            if scanned_count > 500:
                break
            for fname in files:
                scanned_count += 1
                if scanned_count > 500:
                    break
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                    mode = st.st_mode

                    if fname.startswith("."):
                        anomalies.append(f"[Hidden File] `{fpath}`")

                    if mode & stat.S_ISUID:
                        anomalies.append(f"[SUID Bit Set] `{fpath}`")
                    if mode & stat.S_ISGID:
                        anomalies.append(f"[SGID Bit Set] `{fpath}`")

                    if platform.system().lower() == "linux" and (mode & stat.S_IWOTH):
                        anomalies.append(f"[World-Writable 777] `{fpath}`")

                    if fname.lower().endswith(suspicious_exts):
                        mtime_str = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        anomalies.append(
                            f"[Executable/Script] `{fpath}` (Sửa đổi: {mtime_str}, Size: {st.st_size} bytes)"
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    except Exception as e:
        return f"Lỗi khi quét thư mục `{scan_path}`: {e}"

    lines = [
        "=== BÁO CÁO QUÉT FILE BẤT THƯỜNG (ANOMALY FILE SCAN) ===",
        f"- Thư mục kiểm tra: `{scan_path}`",
        f"- Số lượng tệp đã quét: {scanned_count}",
        f"- Số dấu hiệu bất thường phát hiện: {len(anomalies)}",
    ]

    if anomalies:
        lines.append("\n--- Danh sách các file đáng ngờ phát hiện thực tế ---")
        for item in anomalies[:15]:
            lines.append(f"  ! {item}")
        lines.append(
            "\n[Khuyến nghị]: Kiểm tra và xóa các script lạ trong `/tmp`, gỡ quyền thực thi (`chmod -x`) và cấu hình `noexec,nosuid` cho `/tmp`."
        )
    else:
        lines.append("\n[+] Không phát hiện file thực thi ẩn, SUID lạ hoặc script đáng ngờ trong vùng quét.")

    return "\n".join(lines)


def generate_firewall_recommendations(
    suspicious_ips: str = "",
    allowed_ports: str = "22,80,443",
) -> str:
    """
    Tự động phân tích các cổng đang mở thực tế trên máy chủ và IP bất thường từ log
    để đề xuất cấu hình Firewall (UFW và iptables).
    """
    ips = [ip.strip() for ip in suspicious_ips.split(",") if ip.strip()]
    if not ips:
        ips = extract_suspicious_ips_from_logs(lines_count=100)

    allow_list = [p.strip() for p in allowed_ports.split(",") if p.strip().isdigit()]

    active_ports = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                if not c.laddr.ip.startswith("127.") and c.laddr.ip != "::1":
                    active_ports.add(str(c.laddr.port))
    except Exception:
        pass

    unexpected_ports = sorted([p for p in active_ports if p not in allow_list and int(p) < 49152])

    lines = [
        "=== ĐỀ XUẤT CẤU HÌNH FIREWALL TỰ ĐỘNG (UFW & IPTABLES HARDENING) ===",
        f"- Cổng dịch vụ cho phép (Whitelist): {', '.join(allow_list)}",
        f"- Cổng đang mở0.0.0.0/::: ngoài Whitelist phát hiện trên máy: {', '.join(unexpected_ports) if unexpected_ports else 'Không có'}",
        f"- IP đăng nhập thất bại trích xuất từ Log: {', '.join(ips) if ips else 'Không phát hiện IP bất thường trong log'}",
        "\n1. Cấu hình UFW (Uncomplicated Firewall):",
        "```bash",
        "sudo ufw default deny incoming",
        "sudo ufw default allow outgoing",
    ]

    if ips:
        lines.append("\n# Chặn các IP có dấu hiệu tấn công trong log")
        for ip in ips:
            lines.append(f"sudo ufw deny from {ip} to any")

    lines.append("\n# Mở các cổng dịch vụ hợp lệ (kèm chống Brute-force cho SSH)")
    for port in allow_list:
        if port == "22":
            lines.append("sudo ufw limit 22/tcp comment 'SSH Rate Limit'")
        else:
            lines.append(f"sudo ufw allow {port}/tcp")

    if unexpected_ports:
        lines.append("\n# Đóng các cổng đang mở ngoài danh sách cho phép")
        for up in unexpected_ports[:10]:
            lines.append(f"sudo ufw deny {up}/tcp")

    lines.extend([
        "\nsudo ufw --force enable",
        "sudo ufw status numbered",
        "```",
        "\n2. Cấu hình IPTABLES tương đương:",
        "```bash",
        "sudo iptables -P INPUT DROP",
        "sudo iptables -P FORWARD DROP",
        "sudo iptables -P OUTPUT ACCEPT",
        "sudo iptables -A INPUT -i lo -j ACCEPT",
        "sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ])
    for ip in ips:
        lines.append(f"sudo iptables -A INPUT -s {ip} -j DROP")
    for port in allow_list:
        lines.append(f"sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
    lines.append("```")

    return "\n".join(lines)
