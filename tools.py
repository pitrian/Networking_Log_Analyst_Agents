"""
tools.py - Custom tools cho hệ thống Multi-Agent phân tích log server.
Tất cả tools được định nghĩa tại đây, không cho phép agents tự định nghĩa.
Hỗ trợ đa định dạng log: Custom, Nginx, Apache, Syslog.
"""

import os
import re
from urllib.parse import unquote_plus
from datetime import datetime
from collections import Counter, defaultdict
from typing import Annotated

from log_parser_utils import parse_log_to_entries, get_format_display_name


# ============================================================
# GLOBAL HELPERS
# ============================================================

# Lab hiện tại: coi 192.168.* và 127.* là internal/trusted.
# Nếu môi trường của bạn dùng 10.* hoặc 172.16-31.* là internal, sửa tại đây.
TRUSTED_INTERNAL_PREFIXES = ("192.168.", "127.")


def is_trusted_internal_ip(ip: str) -> bool:
    """Kiểm tra IP có thuộc nhóm internal/trusted trong lab hiện tại hay không."""
    return bool(ip) and ip.startswith(TRUSTED_INTERNAL_PREFIXES)


def extract_all_ips(text: str) -> list[str]:
    """Trích xuất tất cả IPv4 từ chuỗi."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")


def parse_ts(ts: str):
    """Parse timestamp chuẩn YYYY-MM-DD HH:MM:SS, trả None nếu lỗi."""
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def detect_log_type(file_path: str) -> str:
    """
    Tự động nhận diện loại log.

    Supported:
    - apache_access
    - nginx_access
    - syslog
    - system
    - unknown
    """
    filename = os.path.basename(file_path).lower()

    # Ưu tiên filename heuristic trước
    if "nginx" in filename:
        return "nginx_access"
    if "apache" in filename:
        return "apache_access"
    if "syslog" in filename:
        return "syslog"
    if "system" in filename:
        return "system"

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [f.readline() for _ in range(20)]
    except Exception:
        return "unknown"

    sample = "\n".join(lines)

    # Nginx access log: thường có referrer + user-agent ở cuối
    nginx_pattern = (
        r'^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*?\s+HTTP/[\d.]+"\s+\d{3}\s+\d+\s+".*?"\s+".*?"$'
    )
    if re.search(nginx_pattern, sample, re.MULTILINE):
        return "nginx_access"

    # Apache access log: dạng common/simple không có referrer/user-agent
    apache_pattern = (
        r'^\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*?\s+HTTP/[\d.]+"\s+\d{3}\s+\d+$'
    )
    if re.search(apache_pattern, sample, re.MULTILINE):
        return "apache_access"

    # Syslog / system log
    syslog_pattern = r'^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+'
    if re.search(syslog_pattern, sample, re.MULTILINE):
        # nếu filename không giúp phân biệt, mặc định syslog
        return "syslog"

    # Fallback system patterns
    system_patterns = [
        r"kernel:",
        r"systemd\[\d+\]",
        r"sshd\[\d+\]",
        r"cron\[\d+\]",
        r"smartd\[\d+\]",
    ]
    for p in system_patterns:
        if re.search(p, sample):
            return "system"

    return "unknown"


SECURITY_CATEGORY_PATTERNS = {
    "sql_injection": [
        r"(?i)\bSQL\s+Injection\b",
        r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
        r"(?i)\bSELECT\s+.+\s+FROM\b",
        r"(?i)\bSELECT\s+\*\s+FROM\s+users\b",
        r"(?i)\bUNION\s+SELECT\s+password\s+FROM\s+admin\b",
        r"(?i)\bOR\s+'1'\s*=\s*'1'\b",
        r"(?i)'\s*OR\s*'1'\s*=\s*'1",
        r"(?i)\bOR\s+1\s*=\s*1\b",
        r"(?i)\bDROP\s+TABLE\b",
    ],
    "nosql_injection": [
        r"(?i)\bNoSQL\s+Injection\b",
        r'(?i)\{\s*"\$gt"\s*:',
        r'(?i)\{\s*"\$ne"\s*:',
        r"(?i)\$regex",
        r"(?i)\$where",
    ],
    "command_injection": [
        r"(?i)\bCommand\s+Injection\b",
        r"(?i)\bOS\s+Command\s+Injection\b",
        r"(?i)\|\s*(wget|curl|bash|sh)\b",
        r"(?i);\s*(cat|wget|curl|bash|sh)\b",
        r"(?i)/bin/(bash|sh)\b",
        r"(?i)\bcmd=;cat\s+\S+",
    ],
    "ldap_injection": [
        r"(?i)\bLDAP\s+Injection\b",
        r"(?i)\*\)\(&",
        r"(?i)objectClass=\*",
    ],
    "xss": [
        r"(?i)\bXSS\b",
        r"(?i)<script[\s>]",
        r"(?i)</script>",
        r"(?i)alert\s*\(",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
    ],
    "path_traversal": [
        r"(?i)\.\./\.\./",
        r"(?i)\.\./etc/passwd",
        r"(?i)\bPath\s+traversal\b",
        r"(?i)\bdirectory\s+traversal\b",
        r"(?i)\bLFI\b",
    ],
    "brute_force": [
        r"(?i)failed\s+login",
        r"(?i)login\s+failed",
        r"(?i)invalid\s+credentials",
        r"(?i)authentication\s+failure",
        r"(?i)too\s+many\s+login\s+attempts",
        r"(?i)maximum\s+authentication\s+attempts\s+exceeded",
        r"(?i)Failed\s+password\s+for\s+.*\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)Invalid\s+user\s+.*\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)authentication\s+failure.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)connection\s+closed\s+by\s+(\d+\.\d+\.\d+\.\d+).*preauth",
        r"(?i)\bAccount\s+'.+'\s+locked\b",
        r"(?i)\bBrute-?force\s+attack\s+detected\b",
        r"(?i)\bRapid\s+login\s+attempts\s+detected\b",
    ],
    "ddos_flooding": [
        r"(?i)\bddos\b",
        r"(?i)\bdos\b",
        r"(?i)syn\s+flood",
        r"(?i)possible\s+syn\s+flooding",
        r"(?i)flood(ing)?",
        r"(?i)rate\s+limit",
        r"(?i)too\s+many\s+requests",
        r"(?i)connection\s+limit\s+exceeded",
        r"(?i)too\s+many\s+connections",
    ],
    "unauthorized_access": [
        r"(?i)access\s+denied",
        r"(?i)forbidden",
        r"(?i)403\s+forbidden",
        r"(?i)unauthorized",
        r"(?i)authentication\s+required",
        r"(?i)\.\./",
        r"(?i)/etc/passwd",
        r"(?i)directory\s+traversal",
        r"(?i)/\.env",
        r"(?i)/\.git/config",
        r"(?i)/\.ssh/",
        r"(?i)/\.htaccess",
        r"(?i)/wp-admin/?",
        r"(?i)/phpmyadmin/?",
        r"(?i)/cgi-bin/",
        r"(?i)forced\s+browsing",
        r"(?i)access\s+to\s+restricted\s+area",
    ],
    "sensitive_data_exposure": [
        r"(?i)\b(password|passwd|secret|api[_-]?key|token|credential)\b\s*[=:]\s*\S+",
        r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        r"(?i)\bdebug\s*=\s*true\b",
        r"(?i)\btraceback\b",
        r"(?i)\bstack\s*trace\b",
    ],
}

SECURITY_RISK_WEIGHTS = {
    "sql_injection": 10,
    "nosql_injection": 9,
    "command_injection": 10,
    "ldap_injection": 8,
    "xss": 7,
    "path_traversal": 8,
    "brute_force": 6,
    "ddos_flooding": 7,
    "unauthorized_access": 7,
    "sensitive_data_exposure": 9,
}

SECURITY_CATEGORY_LABELS = {
    "sql_injection": "SQL INJECTION",
    "nosql_injection": "NoSQL INJECTION",
    "command_injection": "COMMAND INJECTION",
    "ldap_injection": "LDAP INJECTION",
    "xss": "XSS",
    "path_traversal": "PATH TRAVERSAL / LFI",
    "brute_force": "BRUTE FORCE",
    "ddos_flooding": "DDoS / FLOODING",
    "unauthorized_access": "UNAUTHORIZED / FORCED BROWSING",
    "sensitive_data_exposure": "SENSITIVE DATA EXPOSURE",
}

SECURITY_DETECTION_KEYWORDS = (
    "attempt detected",
    "rapid login attempts detected",
    "suspicious ip",
    "suspicious activity",
)

SECURITY_MITIGATION_KEYWORDS = (
    "added to blocklist",
    "added to watchlist",
    "ufw block",
)


def is_http_request_entry(entry) -> bool:
    """True nếu entry là HTTP request đã parse được status code."""
    return entry.status_code is not None and bool(entry.ip)


def get_minute_bucket(timestamp: str) -> str | None:
    """Lấy bucket theo phút từ timestamp chuẩn."""
    if not timestamp or len(timestamp) < 16:
        return None
    return timestamp[:16]


def normalize_endpoint_path(endpoint: str | None) -> str | None:
    """Chuan hoa endpoint de bao cao muc tieu bi nham ma khong giu query string."""
    if not endpoint:
        return None
    normalized = unquote_plus(endpoint).strip()
    if not normalized:
        return None
    normalized = normalized.split("?", 1)[0]
    return normalized or None


def extract_request_path(decoded_line: str) -> str | None:
    """Co gang trich xuat request path tu raw line neu parser khong dat endpoint."""
    match = re.search(
        r"\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)",
        decoded_line or "",
    )
    if not match:
        return None
    return normalize_endpoint_path(match.group(1))


def nearest_rank_percentile(values: list[float], percentile: float):
    """Tinh percentile theo nearest-rank, minh bach va de doi chieu."""
    if not values:
        return "N/A"
    sorted_values = sorted(values)
    rank = max(1, min(len(sorted_values), int((len(sorted_values) * percentile + 99) // 100)))
    return sorted_values[rank - 1]


def is_explicit_mitigation_log(decoded_line: str) -> bool:
    """Kiểm tra xem dòng log có ghi nhận hành động mitigation rõ ràng hay không."""
    lower = (decoded_line or "").lower()
    return any(keyword in lower for keyword in SECURITY_MITIGATION_KEYWORDS)


def is_security_detection_log(entry, decoded_line: str) -> bool:
    """Kiểm tra xem dòng log là detection/alert log thay vì raw evidence."""
    lower = (decoded_line or "").lower()
    if is_explicit_mitigation_log(decoded_line):
        return False
    if entry.service == "SecurityModule":
        return True
    return any(keyword in lower for keyword in SECURITY_DETECTION_KEYWORDS)


def match_security_categories(decoded_line: str) -> list[str]:
    """Tìm tất cả category security khớp với nội dung dòng log."""
    matched = []
    for category, patterns in SECURITY_CATEGORY_PATTERNS.items():
        if any(re.search(pattern, decoded_line) for pattern in patterns):
            matched.append(category)
    return matched


def collect_security_observations(entries) -> dict:
    """Chuẩn hóa security facts để các tool dùng cùng rule đếm và cùng phân loại."""
    evidence_by_line = {}
    category_lines = {category: [] for category in SECURITY_CATEGORY_PATTERNS}
    seen_category_lines = {category: set() for category in SECURITY_CATEGORY_PATTERNS}
    detection_logs = []
    mitigation_logs = []
    blocked_ips = set()
    watchlist_ips = set()
    suspicious_ips = set()
    ip_activity = Counter()
    login_failures = defaultdict(list)
    http_context_by_ip = defaultdict(list)

    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        decoded_line = unquote_plus(line_text or "")
        normalized_endpoint = normalize_endpoint_path(entry.endpoint) or extract_request_path(decoded_line)
        if entry.ip and not is_trusted_internal_ip(entry.ip) and normalized_endpoint:
            http_context_by_ip[entry.ip].append({
                "timestamp": entry.timestamp,
                "endpoint": normalized_endpoint,
            })

        decoded_endpoint = unquote_plus(entry.endpoint or "")
        if (
            entry.ip
            and entry.method == "POST"
            and decoded_endpoint in ("/api/login", "/login", "/auth/login")
            and entry.status_code in (401, 403)
        ):
            login_failures[entry.ip].append(entry.raw_line or entry.message or "")

    confirmed_bruteforce_lines = set()
    for attempts in login_failures.values():
        if len(attempts) >= 5:
            confirmed_bruteforce_lines.update(attempts)

    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_line = unquote_plus(line_text)
        matched_categories = set(match_security_categories(decoded_line))
        if line_text in confirmed_bruteforce_lines:
            matched_categories.add("brute_force")

        if is_explicit_mitigation_log(decoded_line):
            ips = [ip for ip in extract_all_ips(decoded_line) if not is_trusted_internal_ip(ip)]
            for ip in ips:
                suspicious_ips.add(ip)
                if "watchlist" in decoded_line.lower():
                    watchlist_ips.add(ip)
                else:
                    blocked_ips.add(ip)
            mitigation_logs.append({
                "timestamp": entry.timestamp,
                "service": entry.service,
                "message": (entry.message or "").strip(),
                "ips": ips,
                "raw": line_text,
            })
            continue

        if not matched_categories:
            continue

        if is_security_detection_log(entry, decoded_line):
            detection_logs.append({
                "timestamp": entry.timestamp,
                "service": entry.service,
                "message": (entry.message or "").strip(),
                "categories": sorted(matched_categories),
                "ips": [ip for ip in extract_all_ips(decoded_line) if not is_trusted_internal_ip(ip)],
                "endpoints": [],
                "raw": line_text,
            })
            continue

        event = evidence_by_line.setdefault(line_text, {
            "timestamp": entry.timestamp,
            "service": entry.service,
            "level": entry.level,
            "message": (entry.message or "").strip(),
            "endpoint": normalize_endpoint_path(entry.endpoint) or extract_request_path(decoded_line),
            "status_code": entry.status_code,
            "ips": set(),
            "categories": set(),
            "raw": line_text,
        })
        event["categories"].update(matched_categories)

        event_ips = set(extract_all_ips(decoded_line))
        if entry.ip:
            event_ips.add(entry.ip)

        for ip in event_ips:
            if not is_trusted_internal_ip(ip):
                event["ips"].add(ip)
                suspicious_ips.add(ip)
                ip_activity[ip] += 1

        for category in matched_categories:
            if line_text not in seen_category_lines[category]:
                seen_category_lines[category].add(line_text)
                category_lines[category].append(line_text)

    evidence_events = []
    for event in evidence_by_line.values():
        event["categories"] = sorted(event["categories"])
        event["ips"] = sorted(event["ips"])
        evidence_events.append(event)

    evidence_events.sort(key=lambda item: (item["timestamp"] or "", item["raw"]))

    mentioned_endpoints = set()
    mentioned_endpoints_by_ip = defaultdict(set)
    for event in evidence_events:
        if event["endpoint"]:
            mentioned_endpoints.add(event["endpoint"])
            for ip in event["ips"]:
                mentioned_endpoints_by_ip[ip].add(event["endpoint"])

    for item in detection_logs:
        item_ts = parse_ts(item["timestamp"])
        linked_endpoints = set()
        for ip in item["ips"]:
            for ctx in http_context_by_ip.get(ip, []):
                ctx_ts = parse_ts(ctx["timestamp"])
                if item_ts is None or ctx_ts is None:
                    continue
                if abs((item_ts - ctx_ts).total_seconds()) <= 5:
                    linked_endpoints.add(ctx["endpoint"])
                    mentioned_endpoints.add(ctx["endpoint"])
                    mentioned_endpoints_by_ip[ip].add(ctx["endpoint"])
        item["endpoints"] = sorted(linked_endpoints)

    risk_score = 0
    for event in evidence_events:
        if event["categories"]:
            risk_score += max(SECURITY_RISK_WEIGHTS[category] for category in event["categories"])

    return {
        "evidence_events": evidence_events,
        "category_lines": category_lines,
        "detection_logs": detection_logs,
        "mitigation_logs": mitigation_logs,
        "suspicious_ips": sorted(suspicious_ips),
        "blocked_ips": blocked_ips,
        "watchlist_ips": watchlist_ips,
        "ip_activity": ip_activity,
        "risk_score": risk_score,
        "mentioned_endpoints": sorted(mentioned_endpoints),
        "mentioned_endpoints_by_ip": {
            ip: sorted(endpoints)
            for ip, endpoints in mentioned_endpoints_by_ip.items()
        },
    }

# ============================================================
# TOOL 1: Parse Log File - Phân tích tổng quan file log
# ============================================================

def parse_log_file(
    file_path: Annotated[str, "Đường dẫn tới file log cần phân tích"]
) -> str:
    """
    Đọc và phân tích cấu trúc file log server, trả về thống kê tổng quan.
    Hỗ trợ đa định dạng: Custom App Log, Nginx, Apache, Syslog.
    Tự động nhận diện format.
    """

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    # =========================
    # Detect log type
    # =========================
    log_type = detect_log_type(file_path)

    # Parse log entries
    entries, log_format = parse_log_to_entries(file_path)
    format_name = get_format_display_name(log_format)

    if not entries:
        return f"""
LOG TYPE DETECTED: {log_type}

ERROR: Không thể parse file log. Format không được nhận diện."""

    total_lines = len(entries)
    log_levels = Counter()
    ips = Counter()
    endpoints = Counter()
    services = Counter()
    http_status_codes = Counter()
    methods = Counter()

    timestamps = [entry.timestamp for entry in entries if entry.timestamp]
    timestamps_sorted = sorted(timestamps) if timestamps else []

    for entry in entries:
        log_levels[entry.level] += 1
        services[entry.service] += 1

        if entry.ip:
            ips[entry.ip] += 1
        if entry.method:
            methods[entry.method] += 1
        if entry.endpoint:
            endpoints[entry.endpoint] += 1
        if entry.status_code is not None:
            http_status_codes[str(entry.status_code)] += 1

    time_range = "N/A"
    if timestamps_sorted:
        time_range = f"{timestamps_sorted[0]} → {timestamps_sorted[-1]}"

    result = f"""
===== BÁO CÁO PHÂN TÍCH TỔNG QUAN LOG =====

📄 Tổng số dòng log: {total_lines}
📄 Loại log nhận diện: {log_type}
📂 Định dạng log: {format_name} ({log_format})
⏰ Khoảng thời gian: {time_range}

📊 PHÂN LOẠI THEO LOG LEVEL:
{chr(10).join(f'  - {level}: {count} entries' for level, count in log_levels.most_common())}

🔧 SERVICES XUẤT HIỆN:
{chr(10).join(f'  - {svc}: {count} entries' for svc, count in services.most_common())}

🌐 HTTP METHODS:
{chr(10).join(f'  - {method}: {count} requests' for method, count in methods.most_common()) if methods else '  - N/A (không có HTTP request trong log)'}

📡 HTTP STATUS CODES:
{chr(10).join(f'  - {code}: {count} responses' for code, count in http_status_codes.most_common()) if http_status_codes else '  - N/A'}

🖥️ TOP IP ADDRESSES:
{chr(10).join(f'  - {ip}: {count} requests' for ip, count in ips.most_common(10)) if ips else '  - N/A'}

🔗 TOP ENDPOINTS:
{chr(10).join(f'  - {ep}: {count} hits' for ep, count in endpoints.most_common(10)) if endpoints else '  - N/A'}
"""
    return result.strip()


# ============================================================
# TOOL 2: Extract Error Entries - Lọc các lỗi
# ============================================================

def extract_error_entries(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Lọc và trích xuất tất cả các dòng log có level ERROR hoặc CRITICAL,
    phân loại theo service và mức độ nghiêm trọng.
    Hỗ trợ đa định dạng log.
    """

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)
    format_name = get_format_display_name(log_format)

    errors = []
    criticals = []
    error_by_service = defaultdict(list)

    for entry in entries:
        if entry.level in ("ERROR", "CRITICAL"):
            item = {
                "timestamp": entry.timestamp,
                "level": entry.level,
                "service": entry.service,
                "message": (entry.message or "").strip(),
            }
            error_by_service[entry.service].append(item)
            if entry.level == "CRITICAL":
                criticals.append(item)
            else:
                errors.append(item)

    result = f"""
===== TRÍCH XUẤT LỖI (ERROR/CRITICAL) =====

📂 Định dạng log: {format_name}
🔴 Tổng số CRITICAL: {len(criticals)}
🟠 Tổng số ERROR: {len(errors)}
📊 Tổng cộng: {len(criticals) + len(errors)} lỗi

--- CRITICAL ENTRIES ---
"""
    for entry in criticals:
        result += f"  [{entry['timestamp']}] [{entry['service']}] {entry['message']}\n"

    result += "\n--- ERROR ENTRIES ---\n"
    for entry in errors:
        result += f"  [{entry['timestamp']}] [{entry['service']}] {entry['message']}\n"

    result += "\n--- LỖI PHÂN THEO SERVICE ---\n"
    for service, entries_list in error_by_service.items():
        result += f"  🔧 {service}: {len(entries_list)} lỗi\n"
        for e in entries_list:
            result += f"     - [{e['level']}] {e['message']}\n"

    return result.strip()


# ============================================================
# TOOL 3: Detect Security Threats - Phát hiện lỗ hổng bảo mật
# ============================================================

def detect_security_threats(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích file log để phát hiện mối đe dọa bảo mật dựa trên bằng chứng trực tiếp."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)
    format_name = get_format_display_name(log_format)

    if not entries:
        return "ERROR: Không thể parse file log."

    security_data = collect_security_observations(entries)
    category_lines = security_data["category_lines"]
    evidence_events = security_data["evidence_events"]
    suspicious_ips = security_data["suspicious_ips"]
    blocked_ips = security_data["blocked_ips"]
    watchlist_ips = security_data["watchlist_ips"]
    ip_activity = security_data["ip_activity"]
    detection_logs = security_data["detection_logs"]
    mitigation_logs = security_data["mitigation_logs"]
    mentioned_endpoints = security_data["mentioned_endpoints"]
    risk_score = security_data["risk_score"]
    denied_requests = sum(
        1 for event in evidence_events
        if event.get("status_code") in (401, 403)
    )

    if risk_score == 0:
        severity = "THAP - khong thay bang chung tan cong ro rang trong log da parse"
    elif risk_score <= 20:
        severity = "THAP - co mot vai dau hieu dang ngo trong log"
    elif risk_score <= 50:
        severity = "TRUNG BINH - co nhieu dau hieu can kiem tra"
    elif risk_score <= 100:
        severity = "CAO - co nhieu bang chung su kien dang lo ngai"
    else:
        severity = "RAT CAO - log ghi nhan nhieu su kien dang ngo nghiem trong"

    result = f"""
===== BAO CAO PHAN TICH BAO MAT CHI TIET =====

Log format: {format_name}

[FACTS_FROM_LOG]
- Primary evidence events: {len(evidence_events)}
- Detection/alert logs (separate, not counted above): {len(detection_logs)}
- Explicit mitigation logs (separate, not counted above): {len(mitigation_logs)}
- External IPs seen in evidence: {len(suspicious_ips)}
- Target endpoints mentioned in security logs: {len(mentioned_endpoints)}
- Denied requests seen in evidence (401/403): {denied_requests}
- Explicit block actions in log: {len(blocked_ips)}
- Explicit watchlist actions in log: {len(watchlist_ips)}

[INFERENCE]
- Evidence-based severity: {severity}
- Risk score (dedup theo event): {risk_score}
- 401/403 chi cho thay request bi tu choi; dieu do KHONG tu dong chung minh co blocklist/firewall action neu log khong ghi ro.
- Rule dem: detection/alert log va mitigation log KHONG cong vao primary evidence events; neu dong log la brute-force/preauth close/SYN flooding warning va match rule security thi van duoc tinh la evidence event.
"""

    for category, label in SECURITY_CATEGORY_LABELS.items():
        result += f"\n--- {label} ({len(category_lines[category])}) ---\n"
        if category_lines[category]:
            for item in category_lines[category]:
                result += f"  - {item}\n"
            if category == "ddos_flooding":
                result += "  Note: chi xem day la dau hieu flooding tu log; khong tu gan IP nguon neu log khong neu ro.\n"
        else:
            result += "  - KHONG PHAT HIEN\n"

    result += "\n--- DETECTION / ALERT LOGS (khong cong vao total evidence events) ---\n"
    if detection_logs:
        for item in detection_logs[:10]:
            cats = ", ".join(item["categories"]) if item["categories"] else "N/A"
            result += f"  - [{item['timestamp']}] [{item['service']}] categories={cats} | {item['message']}\n"
        if len(detection_logs) > 10:
            result += f"  ... va {len(detection_logs) - 10} detection log khac\n"
    else:
        result += "  - KHONG CO DETECTION/ALERT LOG RIENG\n"

    result += "\n--- EXPLICIT MITIGATION LOGS (khong cong vao total evidence events) ---\n"
    if mitigation_logs:
        for item in mitigation_logs[:10]:
            result += f"  - [{item['timestamp']}] [{item['service']}] {item['message']}\n"
        if len(mitigation_logs) > 10:
            result += f"  ... va {len(mitigation_logs) - 10} mitigation log khac\n"
    else:
        result += "  - KHONG CO MITIGATION LOG RO RANG\n"

    result += "\n--- TARGET ENDPOINTS MENTIONED IN SECURITY LOGS ---\n"
    if mentioned_endpoints:
        for endpoint in mentioned_endpoints:
            result += f"  - {endpoint}\n"
    else:
        result += "  - KHONG CO TARGET ENDPOINT RO RANG\n"

    result += "\n--- IP DANG NGO TU EVIDENCE ---\n"
    if suspicious_ips:
        for ip in suspicious_ips:
            status_parts = []
            if ip in blocked_ips:
                status_parts.append("BLOCKED")
            if ip in watchlist_ips:
                status_parts.append("WATCHLIST")
            status = f" [{' | '.join(status_parts)}]" if status_parts else ""
            result += f"  - {ip}{status} (lien quan {ip_activity[ip]} evidence event)\n"
    else:
        result += "  - KHONG CO IP DANG NGO TRONG EVIDENCE EVENTS\n"

    return result.strip()

    threats = {
        "sql_injection": [],
        "nosql_injection": [],
        "command_injection": [],
        "ldap_injection": [],
        "xss": [],
        "path_traversal": [],
        "brute_force": [],
        "ddos_flooding": [],
        "unauthorized_access": [],
        "sensitive_data_exposure": [],
    }

    seen = {k: set() for k in threats}
    suspicious_ips = set()
    blocked_ips = set()
    watchlist_ips = set()
    ip_activity = Counter()
    login_failures = defaultdict(list)

    def add_finding(category: str, line_text: str):
        if line_text not in seen[category]:
            seen[category].add(line_text)
            threats[category].append(line_text)

        for ip in extract_all_ips(line_text):
            if not is_trusted_internal_ip(ip):
                suspicious_ips.add(ip)
                ip_activity[ip] += 1

    sql_patterns = [
        r"(?i)\bSQL\s+Injection\b",
        r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
        r"(?i)\bSELECT\s+.+\s+FROM\b",
        r"(?i)\bSELECT\s+\*\s+FROM\s+users\b",
        r"(?i)\bUNION\s+SELECT\s+password\s+FROM\s+admin\b",
        r"(?i)\bOR\s+'1'\s*=\s*'1'\b",
        r"(?i)'\s*OR\s*'1'\s*=\s*'1",
        r"(?i)\bOR\s+1\s*=\s*1\b",
        r"(?i)\bDROP\s+TABLE\b",
    ]

    nosql_patterns = [
        r"(?i)\bNoSQL\s+Injection\b",
        r'(?i)\{\s*"\$gt"\s*:',
        r'(?i)\{\s*"\$ne"\s*:',
        r"(?i)\$regex",
        r"(?i)\$where",
    ]

    command_injection_patterns = [
        r"(?i)\bCommand\s+Injection\b",
        r"(?i)\bOS\s+Command\s+Injection\b",
        r"(?i)\|\s*(wget|curl|bash|sh)\b",
        r"(?i);\s*(cat|wget|curl|bash|sh)\b",
        r"(?i)/bin/(bash|sh)\b",
        r"(?i)\bcmd=;cat\s+\S+",
    ]

    ldap_patterns = [
        r"(?i)\bLDAP\s+Injection\b",
        r"(?i)\*\)\(&",
        r"(?i)objectClass=\*",
    ]

    xss_patterns = [
        r"(?i)\bXSS\b",
        r"(?i)<script[\s>]",
        r"(?i)</script>",
        r"(?i)alert\s*\(",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
    ]

    traversal_patterns = [
        r"(?i)\.\./\.\./",
        r"(?i)\.\./etc/passwd",
        r"(?i)\bPath\s+traversal\b",
        r"(?i)\bdirectory\s+traversal\b",
        r"(?i)\bLFI\b",
    ]

    brute_force_patterns = [
        # Generic login failures (application logs)
        r"(?i)failed\s+login",
        r"(?i)login\s+failed",
        r"(?i)invalid\s+credentials",
        r"(?i)authentication\s+failure",

        # Too many login attempts
        r"(?i)too\s+many\s+login\s+attempts",
        r"(?i)maximum\s+authentication\s+attempts\s+exceeded",

        # SSH brute force (syslog)
        r"(?i)Failed\s+password\s+for\s+.*\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)Invalid\s+user\s+.*\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)authentication\s+failure.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)connection\s+closed\s+by\s+(\d+\.\d+\.\d+\.\d+).*preauth",
    ]

    ddos_patterns = [
        r"(?i)\bddos\b",
        r"(?i)\bdos\b",
        r"(?i)syn\s+flood",
        r"(?i)possible\s+syn\s+flooding",
        r"(?i)flood(ing)?",
        r"(?i)rate\s+limit",
        r"(?i)too\s+many\s+requests",
        r"(?i)connection\s+limit\s+exceeded",
        r"(?i)too\s+many\s+connections",
    ]

    unauthorized_patterns = [
        # Access denied / Forbidden
        r"(?i)access\s+denied",
        r"(?i)forbidden",
        r"(?i)403\s+forbidden",

        # Unauthorized access
        r"(?i)unauthorized",
        r"(?i)authentication\s+required",

        # Directory traversal / forced browsing
        r"(?i)\.\./",
        r"(?i)/etc/passwd",
        r"(?i)directory\s+traversal",

        # Sensitive file access
        r"(?i)/\.env",
        r"(?i)/\.git/config",
        r"(?i)/\.ssh/",

        # Forced browsing
        r"(?i)forced\s+browsing",
        r"(?i)access\s+to\s+restricted\s+area",
    ]

    sensitive_data_patterns = [
        r"(?i)\b(password|passwd|secret|api[_-]?key|token|credential)\b\s*[=:]\s*\S+",
        r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        r"(?i)\bdebug\s*=\s*true\b",
        r"(?i)\btraceback\b",
        r"(?i)\bstack\s*trace\b",
    ]

    # =========================================================
    # Vòng quét chính
    # =========================================================
    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_line = unquote_plus(line_text)
        lower = decoded_line.lower()

        # Ghi nhận block/watchlist nếu có trong log
        if "added to blocklist" in lower or "ufw block" in lower:
            for ip in extract_all_ips(decoded_line):
                if not is_trusted_internal_ip(ip):
                    blocked_ips.add(ip)

        if "added to watchlist" in lower:
            for ip in extract_all_ips(decoded_line):
                if not is_trusted_internal_ip(ip):
                    watchlist_ips.add(ip)

        checks = [
            ("sql_injection", sql_patterns),
            ("nosql_injection", nosql_patterns),
            ("command_injection", command_injection_patterns),
            ("ldap_injection", ldap_patterns),
            ("xss", xss_patterns),
            ("path_traversal", traversal_patterns),
            ("brute_force", brute_force_patterns),
            ("ddos_flooding", ddos_patterns),
            ("unauthorized_access", unauthorized_patterns),
            ("sensitive_data_exposure", sensitive_data_patterns),
        ]

        for category, patterns in checks:
            if any(re.search(pattern, decoded_line) for pattern in patterns):
                add_finding(category, line_text)

        # Heuristic brute-force cho access log:
        # cùng 1 IP POST vào endpoint login và nhận 401/403 nhiều lần
        decoded_endpoint = unquote_plus(entry.endpoint or "")
        if (
            entry.ip
            and entry.method == "POST"
            and decoded_endpoint in ("/api/login", "/login", "/auth/login")
            and entry.status_code in (401, 403)
        ):
            login_failures[entry.ip].append({
                "timestamp": entry.timestamp,
                "endpoint": decoded_endpoint,
                "status": entry.status_code,
                "raw": line_text,
            })

    # Nếu 1 IP có >= 5 login failures thì coi là brute-force
    for ip, attempts in login_failures.items():
        if len(attempts) >= 5:
            for item in attempts:
                add_finding("brute_force", item["raw"])

    risk_weights = {
        "sql_injection": 10,
        "nosql_injection": 9,
        "command_injection": 10,
        "ldap_injection": 8,
        "xss": 7,
        "path_traversal": 8,
        "brute_force": 6,
        "ddos_flooding": 7,
        "unauthorized_access": 7,
        "sensitive_data_exposure": 9,
    }

    total_threats = sum(len(v) for v in threats.values())
    risk_score = sum(len(threats[k]) * risk_weights[k] for k in risk_weights)

    if risk_score == 0:
        severity = "✅ AN TOÀN - Không phát hiện mối đe dọa rõ ràng"
    elif risk_score <= 20:
        severity = "🟡 THẤP - Có một vài dấu hiệu đáng ngờ"
    elif risk_score <= 50:
        severity = "🟠 TRUNG BÌNH - Có nhiều dấu hiệu cần xử lý"
    elif risk_score <= 100:
        severity = "🔴 CAO - Có nhiều mối đe dọa đáng kể"
    else:
        severity = "🚨 RẤT CAO - Phát hiện nhiều hoạt động tấn công rõ ràng"

    result = f"""
===== BÁO CÁO PHÂN TÍCH BẢO MẬT CHI TIẾT =====

📂 Định dạng log: {format_name}
🛡️ Mức độ nghiêm trọng: {severity}
📊 Risk Score: {risk_score}
📊 Tổng số phát hiện bảo mật: {total_threats}
🚨 Số IP đáng ngờ: {len(suspicious_ips)}
🚫 Số IP bị block rõ ràng từ log: {len(blocked_ips)}
👀 Số IP vào watchlist: {len(watchlist_ips)}

--- 💉 SQL INJECTION ({len(threats['sql_injection'])}) ---
"""
    if threats["sql_injection"]:
        for item in threats["sql_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🗄️ NoSQL INJECTION ({len(threats['nosql_injection'])}) ---\n"
    if threats["nosql_injection"]:
        for item in threats["nosql_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 💻 COMMAND INJECTION ({len(threats['command_injection'])}) ---\n"
    if threats["command_injection"]:
        for item in threats["command_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 📂 LDAP INJECTION ({len(threats['ldap_injection'])}) ---\n"
    if threats["ldap_injection"]:
        for item in threats["ldap_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🔓 XSS ({len(threats['xss'])}) ---\n"
    if threats["xss"]:
        for item in threats["xss"]:
            result += f"  🟠 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 📁 PATH TRAVERSAL / LFI ({len(threats['path_traversal'])}) ---\n"
    if threats["path_traversal"]:
        for item in threats["path_traversal"]:
            result += f"  🟠 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🔨 BRUTE FORCE ({len(threats['brute_force'])}) ---\n"
    if threats["brute_force"]:
        for item in threats["brute_force"]:
            result += f"  🟡 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🌊 DDoS / FLOODING ({len(threats['ddos_flooding'])}) ---\n"
    if threats["ddos_flooding"]:
        for item in threats["ddos_flooding"]:
            result += f"  🟠 {item}\n"
        result += "  📌 Lưu ý: Chỉ ghi nhận dấu hiệu flooding từ log; không tự gán IP nguồn nếu log không nêu rõ.\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🚫 UNAUTHORIZED / FORCED BROWSING ({len(threats['unauthorized_access'])}) ---\n"
    if threats["unauthorized_access"]:
        for item in threats["unauthorized_access"]:
            result += f"  🟠 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🔐 SENSITIVE DATA EXPOSURE ({len(threats['sensitive_data_exposure'])}) ---\n"
    if threats["sensitive_data_exposure"]:
        for item in threats["sensitive_data_exposure"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += "\n--- 🚨 IP ĐÁNG NGỜ ---\n"
    if suspicious_ips:
        for ip in sorted(suspicious_ips):
            status_parts = []
            if ip in blocked_ips:
                status_parts.append("BLOCKED")
            if ip in watchlist_ips:
                status_parts.append("WATCHLIST")
            status = f" [{' | '.join(status_parts)}]" if status_parts else ""
            result += f"  🔴 {ip}{status} (liên quan {ip_activity[ip]} phát hiện)\n"
    else:
        result += "  ✅ Không có IP đáng ngờ\n"

    return result.strip()


# ============================================================
# TOOL 3b: Scan Vulnerabilities - Quét lỗ hổng bảo mật chuyên sâu
# ============================================================

def scan_vulnerabilities(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Quét chuyên sâu hoạt động tấn công theo timeline và theo IP."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    security_data = collect_security_observations(entries)
    evidence_events = security_data["evidence_events"]
    detection_logs = security_data["detection_logs"]
    mitigation_logs = security_data["mitigation_logs"]
    blocked_ips = security_data["blocked_ips"]
    watchlist_ips = security_data["watchlist_ips"]
    mentioned_endpoints = security_data["mentioned_endpoints"]
    mentioned_endpoints_by_ip = security_data["mentioned_endpoints_by_ip"]

    ip_activities = defaultdict(lambda: {
        "evidence_count": 0,
        "denied_count": 0,
        "attack_types": Counter(),
        "blocked": False,
        "watchlist": False,
        "target_accounts": set(),
        "target_endpoints": set(),
        "fact_lines": [],
    })

    for ip in blocked_ips:
        ip_activities[ip]["blocked"] = True
    for ip in watchlist_ips:
        ip_activities[ip]["watchlist"] = True

    for event in evidence_events:
        target_accounts = set()
        user_match = re.search(r"(?i)\b(user|account)\b\s*['\"]?([A-Za-z0-9_.@-]+)", event["raw"])
        if user_match:
            target_accounts.add(user_match.group(2))

        for ip in event["ips"]:
            ip_activities[ip]["evidence_count"] += 1
            if event.get("status_code") in (401, 403):
                ip_activities[ip]["denied_count"] += 1
            for attack_type in event["categories"]:
                ip_activities[ip]["attack_types"][attack_type.upper()] += 1
            if event["endpoint"]:
                ip_activities[ip]["target_endpoints"].add(event["endpoint"])
            ip_activities[ip]["target_accounts"].update(target_accounts)
            labels = ", ".join(t.upper() for t in event["categories"])
            ip_activities[ip]["fact_lines"].append(
                f"[{event['timestamp']}] {labels}: {event['message'][:120]}"
            )

    detection_only_targets = {
        ip: endpoints
        for ip, endpoints in mentioned_endpoints_by_ip.items()
        if ip not in ip_activities and endpoints
    }

    def assess_ip_risk(activity_data):
        score = 0
        weight_map = {
            "SQL_INJECTION": 10,
            "COMMAND_INJECTION": 10,
            "NOSQL_INJECTION": 9,
            "LDAP_INJECTION": 8,
            "XSS": 7,
            "PATH_TRAVERSAL": 8,
            "BRUTE_FORCE": 6,
            "DDOS_FLOODING": 7,
            "UNAUTHORIZED_ACCESS": 7,
            "SENSITIVE_DATA_EXPOSURE": 9,
        }
        for attack_type, count in activity_data["attack_types"].items():
            score += weight_map.get(attack_type, 0) * count

        if score >= 40:
            return "RAT CAO", score
        if score >= 25:
            return "CAO", score
        if score >= 12:
            return "TRUNG BINH", score
        return "THAP", score

    sorted_ips = sorted(
        ip_activities.items(),
        key=lambda x: (assess_ip_risk(x[1])[1], x[1]["evidence_count"]),
        reverse=True,
    )

    timeline_start = evidence_events[0]["timestamp"] if evidence_events else "N/A"
    timeline_end = evidence_events[-1]["timestamp"] if evidence_events else "N/A"

    result = f"""
===== BAO CAO QUET LO HONG BAO MAT CHUYEN SAU =====

[FACTS_FROM_LOG]
- Primary evidence events: {len(evidence_events)}
- Detection/alert logs (separate): {len(detection_logs)}
- Explicit mitigation logs (separate): {len(mitigation_logs)}
- External IPs tied to evidence: {len(ip_activities)}
- Target endpoints mentioned in security logs: {len(mentioned_endpoints)}
- Timeline evidence: {timeline_start} -> {timeline_end}

[COUNTING_RULE]
- Moi dong evidence chi duoc dem 1 lan trong total.
- Detection log va mitigation log duoc bao cao rieng, khong cong vao total evidence events.
- UFW BLOCK/watchlist duoc xep vao mitigation log; preauth close va SYN flooding warning duoc tinh vao evidence events neu match security heuristics.
"""

    result += f"\n{'='*55}\n"
    result += "          TIMELINE CAC EVIDENCE EVENTS\n"
    result += f"{'='*55}\n"
    if evidence_events:
        for event in evidence_events:
            labels = ", ".join(t.upper() for t in event["categories"])
            ips = ", ".join(event["ips"]) if event["ips"] else "N/A"
            result += f"  - [{event['timestamp']}] types={labels} | ips={ips} | {event['message'][:100]}\n"
    else:
        result += "  - KHONG PHAT HIEN EVIDENCE EVENT RO RANG\n"

    result += f"\n{'='*55}\n"
    result += "          EXPLICIT DETECTION / MITIGATION LOGS\n"
    result += f"{'='*55}\n"
    if detection_logs:
        result += "  Detection logs:\n"
        for item in detection_logs[:8]:
            result += f"    - [{item['timestamp']}] [{item['service']}] {item['message']}\n"
    else:
        result += "  Detection logs: KHONG CO\n"
    if mitigation_logs:
        result += "  Mitigation logs:\n"
        for item in mitigation_logs[:8]:
            result += f"    - [{item['timestamp']}] [{item['service']}] {item['message']}\n"
    else:
        result += "  Mitigation logs: KHONG CO\n"

    result += f"\n{'='*55}\n"
    result += "          TARGET ENDPOINTS MENTIONED IN SECURITY LOGS\n"
    result += f"{'='*55}\n"
    if mentioned_endpoints:
        for endpoint in mentioned_endpoints:
            result += f"  - {endpoint}\n"
    else:
        result += "  - KHONG CO TARGET ENDPOINT RO RANG\n"

    if detection_only_targets:
        result += f"\n{'='*55}\n"
        result += "          DETECTION-CONTEXT TARGETS (KHONG TINH VAO EVIDENCE TOTAL)\n"
        result += f"{'='*55}\n"
        for ip, endpoints in sorted(detection_only_targets.items()):
            result += f"  - IP {ip}: {', '.join(endpoints)}\n"

    result += f"\n{'='*55}\n"
    result += "          PHAN TICH THEO IP\n"
    result += f"{'='*55}\n"
    if not sorted_ips:
        result += "  - KHONG CO IP DANG NGO DE PHAN TICH\n"
    else:
        for ip, data in sorted_ips:
            risk_label, risk_score = assess_ip_risk(data)
            state_parts = []
            if data["blocked"]:
                state_parts.append("BLOCKED")
            if data["watchlist"]:
                state_parts.append("WATCHLIST")
            if data["denied_count"] > 0:
                state_parts.append(f"DENIED_REQUESTS={data['denied_count']}")
            state = " | ".join(state_parts) if state_parts else "NO_EXPLICIT_ACTION"
            result += f"  IP: {ip}\n"
            result += f"    - Muc nguy hiem (heuristic): {risk_label} (score={risk_score})\n"
            result += f"    - Evidence events: {data['evidence_count']}\n"
            result += f"    - Trang thai tu log: {state}\n"
            if data["attack_types"]:
                for attack_type, count in data["attack_types"].most_common():
                    result += f"    - {attack_type}: {count}\n"
            if data["target_accounts"]:
                result += f"    - Accounts bi nham: {', '.join(sorted(data['target_accounts']))}\n"
            if data["target_endpoints"]:
                result += f"    - Endpoints bi nham: {', '.join(sorted(list(data['target_endpoints']))[:6])}\n"
            result += "    - Fact lines:\n"
            for item in data["fact_lines"][:5]:
                result += f"       {item}\n"
            if len(data["fact_lines"]) > 5:
                result += f"       ... va {len(data['fact_lines']) - 5} fact line khac\n"

    result += f"\n{'='*55}\n"
    result += "          KHUYEN NGHI\n"
    result += f"{'='*55}\n"

    all_attack_types = Counter()
    for data in ip_activities.values():
        all_attack_types.update(data["attack_types"])

    recommendations = {
        "SQL_INJECTION": "Su dung prepared statements va kiem soat input query parameters.",
        "XSS": "Encode output va trien khai Content-Security-Policy.",
        "COMMAND_INJECTION": "Khong truyen user input truc tiep vao shell/system commands.",
        "PATH_TRAVERSAL": "Canonicalize path va chi cho phep whitelist path hop le.",
        "BRUTE_FORCE": "Rate limit login, account lockout, MFA/CAPTCHA.",
        "NOSQL_INJECTION": "Validate input va tranh build query NoSQL truc tiep tu user input.",
        "LDAP_INJECTION": "Escape LDAP special characters va validate dau vao.",
        "DDOS_FLOODING": "Bat rate limit, reverse proxy/WAF, va theo doi luu luong bat thuong.",
        "UNAUTHORIZED_ACCESS": "Han che forced browsing bang access control va an tai nguyen nhay cam.",
        "SENSITIVE_DATA_EXPOSURE": "Giam log nhay cam va che gia tri bi mat truoc khi ghi log.",
    }

    if not all_attack_types:
        result += "  - KHONG CO KHUYEN NGHI BAO MAT KHAN CAP TU LOG HIEN TAI\n"
    else:
        for attack_type, count in all_attack_types.most_common():
            if attack_type in recommendations:
                result += f"  - {attack_type} ({count} evidence hits): {recommendations[attack_type]}\n"

    urgent_unblocked = [
        ip for ip, data in ip_activities.items()
        if not data["blocked"] and assess_ip_risk(data)[1] >= 25
    ]
    if urgent_unblocked:
        result += "\n  IP nguy co cao chua thay bi block ro rang trong log:\n"
        for ip in urgent_unblocked:
            result += f"    - {ip}\n"

    return result.strip()

    ip_activities = defaultdict(lambda: {
        "timestamps": [],
        "attack_types": Counter(),
        "blocked": False,
        "watchlist": False,
        "target_accounts": set(),
        "target_endpoints": set(),
        "log_entries": [],
    })

    attack_timeline = []

    attack_signatures = {
        "SQL_INJECTION": [
            r"(?i)\bSQL\s+Injection\b",
            r"(?i)\bUNION\s+SELECT\b",
            r"(?i)\bSELECT\s+.+\s+FROM\b",
            r"(?i)\bSELECT\s+\*\s+FROM\s+users\b",
            r"(?i)\bUNION\s+SELECT\s+password\s+FROM\s+admin\b",
            r"(?i)\bOR\s+'1'\s*=\s*'1'\b",
            r"(?i)'\s*OR\s*'1'\s*=\s*'1",
            r"(?i)\bOR\s+1\s*=\s*1\b",
        ],
        "XSS": [
            r"(?i)\bXSS\b",
            r"(?i)<script[\s>]",
            r"(?i)</script>",
            r"(?i)alert\s*\(",
        ],
        "COMMAND_INJECTION": [
            r"(?i)\bCommand\s+Injection\b",
            r"(?i)\bOS\s+Command\s+Injection\b",
            r"(?i)\|\s*(wget|curl|bash|sh)\b",
            r"(?i);\s*(cat|wget|curl|bash|sh)\b",
            r"(?i)/bin/(bash|sh)\b",
        ],
        "PATH_TRAVERSAL": [
            r"(?i)\.\./\.\./",
            r"(?i)\.\./etc/passwd",
            r"(?i)\bPath\s+traversal\b",
            r"(?i)\bdirectory\s+traversal\b",
            r"(?i)\bLFI\b",
        ],
        "BRUTE_FORCE": [
            r"(?i)\bFailed\s+login\s+attempt\b",
            r"(?i)\bInvalid\s+credentials\b",
            r"(?i)\bAccount\s+'.+'\s+locked\b",
            r"(?i)\bBrute-?force\s+attack\s+detected\b",
            r"(?i)\bRapid\s+login\s+attempts\s+detected\b",
        ],
        "NOSQL_INJECTION": [
            r"(?i)\bNoSQL\s+Injection\b",
            r'(?i)\{\s*"\$gt"\s*:',
            r'(?i)\{\s*"\$ne"\s*:',
            r"(?i)\$regex",
            r"(?i)\$where",
        ],
        "LDAP_INJECTION": [
            r"(?i)\bLDAP\s+Injection\b",
            r"(?i)\*\)\(&",
        ],
        "DDOS_OR_FLOODING": [
            r"(?i)\bSYN\s+flood(ing)?\b",
            r"(?i)\bflood(ing)?\b",
            r"(?i)\bDDoS\b",
            r"(?i)\btoo\s+many\s+requests\b",
        ],
        "UNAUTHORIZED_ACCESS": [
            r"(?i)\bForced\s+browsing\b",
            r"(?i)/\.env\b",
            r"(?i)/\.git/config\b",
            r"(?i)\bUnauthorized\s+access\b",
            r"(?i)\b403\b.*\bForbidden\b",
        ],
    }

    def mark_ip_state(decoded_text: str):
        lower = decoded_text.lower()
        ips = extract_all_ips(decoded_text)
        for ip in ips:
            if is_trusted_internal_ip(ip):
                continue
            if "added to blocklist" in lower or "ufw block" in lower:
                ip_activities[ip]["blocked"] = True
            if "added to watchlist" in lower:
                ip_activities[ip]["watchlist"] = True

    # =========================================================
    # Heuristic brute-force cho access log:
    # cùng IP POST vào endpoint login và nhận 401/403 >= 5 lần
    # =========================================================
    login_failures = defaultdict(list)

    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_endpoint = unquote_plus(entry.endpoint or "")
        if (
            entry.ip
            and entry.method == "POST"
            and decoded_endpoint in ("/api/login", "/login", "/auth/login")
            and entry.status_code in (401, 403)
        ):
            login_failures[entry.ip].append({
                "timestamp": entry.timestamp,
                "endpoint": decoded_endpoint,
                "status": entry.status_code,
                "raw": line_text,
            })

    confirmed_bruteforce_lines = set()
    for ip, attempts in login_failures.items():
        if len(attempts) >= 5:
            for item in attempts:
                confirmed_bruteforce_lines.add(item["raw"])

    # =========================================================
    # Main scan
    # =========================================================
    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_line = unquote_plus(line_text)

        mark_ip_state(decoded_line)

        ips = extract_all_ips(decoded_line)
        if entry.ip and entry.ip not in ips:
            ips.append(entry.ip)

        matched_types = []

        for attack_type, patterns in attack_signatures.items():
            if any(re.search(pattern, decoded_line) for pattern in patterns):
                matched_types.append(attack_type)

        # Heuristic brute-force from access log
        if line_text in confirmed_bruteforce_lines and "BRUTE_FORCE" not in matched_types:
            matched_types.append("BRUTE_FORCE")

        if not matched_types:
            continue

        external_ips = [ip for ip in ips if not is_trusted_internal_ip(ip)]

        for attack_type in matched_types:
            attack_timeline.append({
                "timestamp": entry.timestamp,
                "type": attack_type,
                "level": entry.level,
                "service": entry.service,
                "message": (entry.message or "").strip(),
                "ips": external_ips,
            })

            for ip in external_ips:
                ip_activities[ip]["timestamps"].append(entry.timestamp)
                ip_activities[ip]["attack_types"][attack_type] += 1
                ip_activities[ip]["log_entries"].append(
                    f"[{entry.timestamp}] {attack_type}: {(entry.message or '')[:120]}"
                )

                if entry.endpoint:
                    ip_activities[ip]["target_endpoints"].add(unquote_plus(entry.endpoint))

                user_match = re.search(r"(?i)(user|account)\s*['\"]?([\w@.-]+)", decoded_line)
                if user_match:
                    ip_activities[ip]["target_accounts"].add(user_match.group(2))

    def assess_ip_risk(activity_data):
        score = 0
        score += activity_data["attack_types"].get("SQL_INJECTION", 0) * 10
        score += activity_data["attack_types"].get("COMMAND_INJECTION", 0) * 10
        score += activity_data["attack_types"].get("NOSQL_INJECTION", 0) * 9
        score += activity_data["attack_types"].get("LDAP_INJECTION", 0) * 8
        score += activity_data["attack_types"].get("XSS", 0) * 7
        score += activity_data["attack_types"].get("PATH_TRAVERSAL", 0) * 8
        score += activity_data["attack_types"].get("BRUTE_FORCE", 0) * 6
        score += activity_data["attack_types"].get("DDOS_OR_FLOODING", 0) * 7
        score += activity_data["attack_types"].get("UNAUTHORIZED_ACCESS", 0) * 7

        if score >= 40:
            return "RẤT CAO 🚨", score
        if score >= 25:
            return "CAO 🔴", score
        if score >= 12:
            return "TRUNG BÌNH 🟠", score
        return "THẤP 🟡", score

    sorted_ips = sorted(
        ip_activities.items(),
        key=lambda x: assess_ip_risk(x[1])[1],
        reverse=True,
    )

    result = f"""
===== BÁO CÁO QUÉT LỖ HỔNG BẢO MẬT CHUYÊN SÂU =====

📊 Tổng số sự kiện tấn công/bất thường: {len(attack_timeline)}
🚨 Số IP đáng ngờ: {len(ip_activities)}
⏰ Timeline: {attack_timeline[0]['timestamp'] if attack_timeline else 'N/A'} → {attack_timeline[-1]['timestamp'] if attack_timeline else 'N/A'}

{'='*55}
          TIMELINE CÁC SỰ KIỆN BẢO MẬT
{'='*55}
"""
    if attack_timeline:
        for event in attack_timeline:
            result += f"  - [{event['timestamp']}] {event['type']:18s} | {event['message'][:100]}\n"
    else:
        result += "  ✅ Không phát hiện sự kiện bảo mật rõ ràng\n"

    result += f"\n{'='*55}\n"
    result += f"          PHÂN TÍCH THEO IP\n"
    result += f"{'='*55}\n"

    if not sorted_ips:
        result += "  ✅ Không có IP đáng ngờ để phân tích\n"
    else:
        for ip, data in sorted_ips:
            risk_label, risk_score = assess_ip_risk(data)
            state_parts = []
            if data["blocked"]:
                state_parts.append("BLOCKED")
            if data["watchlist"]:
                state_parts.append("WATCHLIST")
            state = " | ".join(state_parts) if state_parts else "NO_EXPLICIT_ACTION"

            distinct_types = len(data["attack_types"])
            multi_vector_note = ""
            if distinct_types >= 3:
                multi_vector_note = "⚠️ Dấu hiệu multi-vector behavior (nhiều loại tấn công khác nhau)."

            result += f"""
  ╔══════════════════════════════════════════════╗
  ║ IP: {ip}
  ║ Mức nguy hiểm: {risk_label} (Score: {risk_score})
  ║ Trạng thái từ log: {state}
  ╚══════════════════════════════════════════════╝
    📊 Tổng sự kiện liên quan: {sum(data['attack_types'].values())}
    🔫 Loại tấn công:
"""
            for attack_type, count in data["attack_types"].most_common():
                result += f"       - {attack_type}: {count} lần\n"

            if data["target_accounts"]:
                result += f"    🎯 Accounts bị nhắm: {', '.join(sorted(data['target_accounts']))}\n"
            if data["target_endpoints"]:
                result += f"    🔗 Endpoints bị nhắm: {', '.join(sorted(list(data['target_endpoints']))[:6])}\n"
            if multi_vector_note:
                result += f"    {multi_vector_note}\n"

            result += "    📜 Bằng chứng:\n"
            for item in data["log_entries"][:5]:
                result += f"       {item}\n"
            if len(data["log_entries"]) > 5:
                result += f"       ... và {len(data['log_entries']) - 5} sự kiện khác\n"

    result += f"\n{'='*55}\n"
    result += f"          KHUYẾN NGHỊ\n"
    result += f"{'='*55}\n"

    all_attack_types = Counter()
    for data in ip_activities.values():
        all_attack_types.update(data["attack_types"])

    recommendations = {
        "SQL_INJECTION": "Sử dụng prepared statements và kiểm soát input query parameters.",
        "XSS": "Encode output và triển khai Content-Security-Policy.",
        "COMMAND_INJECTION": "Không truyền user input trực tiếp vào shell/system commands.",
        "PATH_TRAVERSAL": "Canonicalize path và chỉ cho phép whitelist path hợp lệ.",
        "BRUTE_FORCE": "Rate limit login, account lockout, MFA/CAPTCHA.",
        "NOSQL_INJECTION": "Validate input và tránh build query NoSQL trực tiếp từ user input.",
        "LDAP_INJECTION": "Escape LDAP special characters và validate đầu vào.",
        "DDOS_OR_FLOODING": "Bật rate limit, reverse proxy/WAF, và theo dõi lưu lượng bất thường.",
        "UNAUTHORIZED_ACCESS": "Hạn chế forced browsing bằng access control và ẩn tài nguyên nhạy cảm.",
    }

    if not all_attack_types:
        result += "  ✅ Không có khuyến nghị bảo mật khẩn cấp từ log hiện tại\n"
    else:
        for attack_type, count in all_attack_types.most_common():
            if attack_type in recommendations:
                result += f"  - {attack_type} ({count} sự kiện): {recommendations[attack_type]}\n"

    urgent_unblocked = [
        ip for ip, data in ip_activities.items()
        if not data["blocked"] and assess_ip_risk(data)[1] >= 25
    ]
    if urgent_unblocked:
        result += "\n  🚨 IP nguy cơ cao chưa thấy bị block rõ ràng trong log:\n"
        for ip in urgent_unblocked:
            result += f"    - {ip}\n"

    return result.strip()


# ============================================================
# TOOL 4: Analyze System Health - Phân tích sức khỏe hệ thống
# ============================================================

def analyze_system_health(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích sức khỏe hệ thống từ log."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    http_entries = [entry for entry in entries if is_http_request_entry(entry)]
    if http_entries and log_format in ("apache", "nginx"):
        service_issues = []
        http_error_events = []
        for entry in http_entries:
            if entry.status_code >= 500:
                issue = (
                    f"[{entry.timestamp}] [{entry.service}] "
                    f"{entry.method or 'HTTP'} {entry.endpoint or '/'} -> {entry.status_code}"
                )
                service_issues.append(issue)
                http_error_events.append(issue)

        status_counter = Counter(str(entry.status_code) for entry in http_entries)
        denied_count = sum(1 for entry in http_entries if entry.status_code in (401, 403))

        health_score = "TOT"
        if len(http_error_events) >= 3:
            health_score = "NGUY HIEM"
        elif http_error_events:
            health_score = "CAN CHU Y"

        result = f"""
===== BAO CAO SUC KHOE HE THONG =====

[FACTS_FROM_LOG]
- Log format: {get_format_display_name(log_format)}
- Overall health status: {health_score}
- HTTP requests observed: {len(http_entries)}
- HTTP 5xx signals: {len(http_error_events)}
- Denied requests (401/403): {denied_count}
- Service issues: {len(service_issues)}

[INTERPRETATION]
- Access log khong chua CPU/RAM metrics, nen health duoc danh gia dua tren HTTP error signals.
- 401/403 cho thay request bi tu choi, nhung khong tu dong chung minh co blocking mechanism cu the.
- 5xx phan anh su co phia he thong/dich vu, vi vay khong nen danh gia la TOT neu 5xx xuat hien.

--- HTTP STATUS DISTRIBUTION ---
"""
        for code, count in status_counter.most_common():
            result += f"  - {code}: {count}\n"

        result += f"\n--- SERVICE ISSUES ({len(service_issues)}) ---\n"
        for item in service_issues:
            result += f"  {item}\n"

        result += f"\n--- HTTP ERROR SIGNALS ({len(http_error_events)}) ---\n"
        for item in http_error_events:
            result += f"  {item}\n"

        return result.strip()

    if log_format == "syslog":
        health_criticals = []
        health_warnings = []
        service_issues = []
        system_events = []

        for entry in entries:
            message = (entry.message or "").lower()
            original = f"[{entry.timestamp}] [{entry.service}] {entry.message}"

            if "out of memory" in message or "killed process" in message:
                health_criticals.append(original)
            elif "main process exited" in message and "status=9/kill" in message:
                health_criticals.append(original)
            elif "failed with result 'signal'" in message:
                health_criticals.append(original)
            elif "cpu clock throttled" in message:
                health_warnings.append(original)
            elif "syn flooding" in message:
                health_warnings.append(original)
            elif "ext4-fs error" in message:
                health_warnings.append(original)

            if any(keyword in message for keyword in [
                "mysql.service: main process exited",
                "mysql.service: failed with result",
                "scheduled restart job",
                "started mysql",
            ]):
                system_events.append(original)

            if any(keyword in message for keyword in [
                "main process exited",
                "failed with result",
                "out of memory",
                "killed process",
                "ext4-fs error",
                "cpu clock throttled",
                "syn flooding",
            ]):
                service_issues.append(original)

        health_criticals = list(dict.fromkeys(health_criticals))
        health_warnings = list(dict.fromkeys(health_warnings))
        service_issues = list(dict.fromkeys(service_issues))
        system_events = list(dict.fromkeys(system_events))

        health_score = "TOT"
        if health_criticals:
            health_score = "NGUY HIEM"
        elif health_warnings or service_issues:
            health_score = "CAN CHU Y"

        result = f"""
===== BAO CAO SUC KHOE HE THONG =====

[FACTS_FROM_LOG]
- Log format: {get_format_display_name(log_format)}
- Overall health status: {health_score}
- Health critical events: {len(health_criticals)}
- Health warnings: {len(health_warnings)}
- Service issues: {len(service_issues)}

[INTERPRETATION]
- Voi syslog, health duoc danh gia dua tren kernel/systemd/service events thay vi HTTP metrics.
- OOM kill, process bi SIGKILL, service fail do signal, CPU throttling va SYN flooding warning deu la tin hieu health/security quan trong.
"""

        result += f"\n--- HEALTH CRITICALS ({len(health_criticals)}) ---\n"
        for item in health_criticals:
            result += f"  {item}\n"

        result += f"\n--- HEALTH WARNINGS ({len(health_warnings)}) ---\n"
        for item in health_warnings:
            result += f"  {item}\n"

        result += f"\n--- SERVICE ISSUES ({len(service_issues)}) ---\n"
        for item in service_issues:
            result += f"  {item}\n"

        result += f"\n--- SYSTEM EVENTS ({len(system_events)}) ---\n"
        for item in system_events:
            result += f"  {item}\n"

        return result.strip()

    cpu_readings = []
    memory_readings = []
    disk_readings = []
    health_warnings = []
    health_criticals = []
    service_issues = []
    system_events = []
    http_error_events = []

    cpu_pattern = re.compile(r"CPU\s+Usage:\s*(\d+)%")
    mem_pattern = re.compile(r"Memory(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)
    disk_pattern = re.compile(r"Disk(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)

    for entry in entries:
        message = entry.message or ""

        cpu_match = cpu_pattern.search(message)
        if cpu_match:
            cpu_readings.append({"timestamp": entry.timestamp, "value": int(cpu_match.group(1))})

        mem_match = mem_pattern.search(message)
        if mem_match:
            memory_readings.append({"timestamp": entry.timestamp, "value": int(mem_match.group(1))})

        disk_match = disk_pattern.search(message)
        if disk_match:
            disk_readings.append({"timestamp": entry.timestamp, "value": int(disk_match.group(1))})

        if entry.service in ("SystemMonitor", "kernel", "systemd"):
            if entry.level == "CRITICAL":
                health_criticals.append(f"[{entry.timestamp}] {message}")
            elif entry.level in ("WARNING", "ERROR"):
                health_warnings.append(f"[{entry.timestamp}] {message}")
            elif entry.level == "INFO" and any(
                kw in message.lower()
                for kw in ["cleanup", "restart", "summary", "started", "stopped", "killed", "freed"]
            ):
                system_events.append(f"[{entry.timestamp}] {message}")

        if entry.level in ("ERROR", "CRITICAL") and entry.service not in ("SystemMonitor", "kernel"):
            if any(
                kw in message.lower()
                for kw in ["fail", "crash", "timeout", "outofmemory", "exhausted", "killed", "exited", "unavailable"]
            ):
                service_issues.append(f"[{entry.timestamp}] [{entry.service}] {message}")

        if entry.status_code is not None and entry.status_code >= 500:
            issue = (
                f"[{entry.timestamp}] [{entry.service}] "
                f"{entry.method or 'HTTP'} {entry.endpoint or '/'} -> {entry.status_code}"
            )
            service_issues.append(issue)
            http_error_events.append(issue)

    service_issues = list(dict.fromkeys(service_issues))

    def calc_stats(readings):
        if not readings:
            return {"min": "N/A", "max": "N/A", "avg": "N/A"}
        values = [r["value"] for r in readings]
        return {
            "min": min(values),
            "max": max(values),
            "avg": round(sum(values) / len(values), 1),
        }

    cpu_stats = calc_stats(cpu_readings)
    mem_stats = calc_stats(memory_readings)
    disk_stats = calc_stats(disk_readings)

    health_score = "TỐT"
    if health_criticals or (isinstance(cpu_stats["max"], int) and cpu_stats["max"] > 90):
        health_score = "NGUY HIỂM 🔴"
    elif health_warnings or (isinstance(mem_stats["max"], int) and mem_stats["max"] > 85):
        health_score = "CẦN CHÚ Ý ⚠️"

    result = f"""
===== BÁO CÁO SỨC KHỎE HỆ THỐNG =====

🏥 Đánh giá tổng thể: {health_score}

--- 🖥️ CPU USAGE ---
  Min: {cpu_stats['min']}%  |  Max: {cpu_stats['max']}%  |  Trung bình: {cpu_stats['avg']}%
  Số lần đo: {len(cpu_readings)}
"""
    for r in cpu_readings:
        status = "🔴" if r["value"] > 90 else "⚠️" if r["value"] > 70 else "✅"
        result += f"  {status} [{r['timestamp']}] CPU: {r['value']}%\n"

    result += f"""
--- 💾 MEMORY USAGE ---
  Min: {mem_stats['min']}%  |  Max: {mem_stats['max']}%  |  Trung bình: {mem_stats['avg']}%
  Số lần đo: {len(memory_readings)}
"""
    for r in memory_readings:
        status = "🔴" if r["value"] > 90 else "⚠️" if r["value"] > 70 else "✅"
        result += f"  {status} [{r['timestamp']}] Memory: {r['value']}%\n"

    result += f"""
--- 💿 DISK USAGE ---
  Min: {disk_stats['min']}%  |  Max: {disk_stats['max']}%  |  Trung bình: {disk_stats['avg']}%
  Số lần đo: {len(disk_readings)}
"""
    for r in disk_readings:
        status = "🔴" if r["value"] > 90 else "⚠️" if r["value"] >= 80 else "✅"
        result += f"  {status} [{r['timestamp']}] Disk: {r['value']}%\n"

    result += f"\n--- ⚠️ HEALTH WARNINGS ({len(health_warnings)}) ---\n"
    for w in health_warnings:
        result += f"  {w}\n"

    result += f"\n--- 🔴 HEALTH CRITICALS ({len(health_criticals)}) ---\n"
    for c in health_criticals:
        result += f"  {c}\n"

    result += f"\n--- 🔧 SERVICE ISSUES ({len(service_issues)}) ---\n"
    for s in service_issues:
        result += f"  {s}\n"

    result += f"\n--- 📋 SYSTEM EVENTS ---\n"
    for e in system_events:
        result += f"  {e}\n"

    return result.strip()


# ============================================================
# TOOL 5: Analyze Performance - Phân tích hiệu suất
# ============================================================

def analyze_performance(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích hiệu suất hệ thống từ log."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    http_entries = [e for e in entries if e.status_code is not None]

    if not http_entries:
        events_per_minute = Counter()
        level_counts = Counter()
        service_counts = Counter()
        for entry in entries:
            if entry.timestamp:
                minute_key = get_minute_bucket(entry.timestamp)
                if minute_key:
                    events_per_minute[minute_key] += 1
            level_counts[entry.level] += 1
            service_counts[entry.service] += 1

        peak_minute = events_per_minute.most_common(1)[0] if events_per_minute else ("N/A", 0)
        avg_epm = round(sum(events_per_minute.values()) / max(len(events_per_minute), 1), 1)

        result = f"""
===== BAO CAO PHAN TICH HIU SUAT / LOG ACTIVITY =====

[FACTS_FROM_LOG]
- Log format: {get_format_display_name(log_format)}
- HTTP requests observed: 0
- Log activity average: {avg_epm} events/phut
- Log activity peak: {peak_minute[1]} events/phut luc {peak_minute[0]}

[INTERPRETATION]
- Day la non-HTTP log, vi vay khong ap dung response time / error rate theo request.
- Thay vao do, report dung log activity volume va phan bo muc do log.
"""

        result += "\n--- EVENTS PER MINUTE ---\n"
        for minute, count in sorted(events_per_minute.items()):
            bar = "#" * min(count, 40)
            result += f"  {minute}: {count} events {bar}\n"

        result += "\n--- LOG LEVEL DISTRIBUTION ---\n"
        for level, count in level_counts.most_common():
            result += f"  - {level}: {count}\n"

        result += "\n--- ACTIVE SERVICES ---\n"
        for service, count in service_counts.most_common():
            result += f"  - {service}: {count}\n"

        return result.strip()

    server_reported_total_requests = None
    server_reported_avg_response = None
    server_summary_total_requests = None
    server_summary_errors = None
    server_summary_warnings = None

    response_times = []
    slow_requests = []
    error_requests = []
    requests_per_minute = Counter()
    status_codes = Counter()
    endpoint_performance = defaultdict(list)

    for entry in http_entries:
        status_code = str(entry.status_code)
        method = entry.method or "UNKNOWN"
        endpoint = entry.endpoint or "/"
        ip = entry.ip or "unknown"
        timestamp = entry.timestamp

        status_codes[status_code] += 1

        if timestamp:
            minute_key = get_minute_bucket(timestamp)
            requests_per_minute[minute_key] += 1

        if entry.response_time is not None:
            resp_time = entry.response_time
            response_times.append(resp_time)
            endpoint_performance[endpoint].append(resp_time)

            if resp_time > 1000:
                slow_requests.append({
                    "timestamp": timestamp,
                    "method": method,
                    "endpoint": endpoint,
                    "response_time": resp_time,
                    "ip": ip,
                })

        if status_code.startswith(("4", "5")):
            error_requests.append({
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status": status_code,
                "response_time": entry.response_time or 0,
                "ip": ip,
            })

    # đọc server summary metrics từ log
    for entry in entries:
        message = entry.message or ""

        m_total = re.search(r"Server status:\s*(\d+)\s+requests processed", message, re.IGNORECASE)
        if m_total:
            server_reported_total_requests = int(m_total.group(1))

        m_avg = re.search(r"Average response time:\s*(\d+)ms", message, re.IGNORECASE)
        if m_avg:
            server_reported_avg_response = int(m_avg.group(1))

        m_summary = re.search(
            r"System summary\s*-\s*Uptime:\s*[^,]+,\s*Total requests:\s*(\d+),\s*Errors:\s*(\d+),\s*Warnings:\s*(\d+)",
            message,
            re.IGNORECASE,
        )
        if m_summary:
            server_summary_total_requests = int(m_summary.group(1))
            server_summary_errors = int(m_summary.group(2))
            server_summary_warnings = int(m_summary.group(3))

    if response_times:
        avg_resp = round(sum(response_times) / len(response_times), 1)
        min_resp = min(response_times)
        max_resp = max(response_times)

        p95_resp = nearest_rank_percentile(response_times, 95)
        p99_resp = nearest_rank_percentile(response_times, 99)

    else:
        avg_resp = min_resp = max_resp = p95_resp = p99_resp = "N/A"

    total_requests = len(http_entries)
    total_errors = len(error_requests)

    error_rate = round(total_errors / total_requests * 100, 1) if total_requests > 0 else 0.0

    peak_minute = requests_per_minute.most_common(1)[0] if requests_per_minute else ("N/A", 0)

    endpoint_avg = {}
    for ep, times in endpoint_performance.items():
        if times:
            endpoint_avg[ep] = round(sum(times) / len(times), 1)

    slow_endpoints = sorted(
        [(ep, avg) for ep, avg in endpoint_avg.items() if avg >= 1000],
        key=lambda x: x[1],
        reverse=True,
    )
    highest_latency_endpoints = sorted(endpoint_avg.items(), key=lambda x: x[1], reverse=True)[:5]

    if avg_resp != "N/A":
        if avg_resp < 200:
            perf_grade = "✅ XUẤT SẮC"
        elif avg_resp < 500:
            perf_grade = "👍 TỐT"
        elif avg_resp < 1000:
            perf_grade = "⚠️ CẦN CẢI THIỆN"
        else:
            perf_grade = "🔴 KÉM"
    else:
        perf_grade = "N/A"

    if avg_resp != "N/A":
        if avg_resp < 200:
            perf_grade_label = "XUAT SAC"
        elif avg_resp < 500:
            perf_grade_label = "TOT"
        elif avg_resp < 1000:
            perf_grade_label = "CAN CAI THIEN"
        else:
            perf_grade_label = "KEM"
    else:
        perf_grade_label = "N/A"

    result = f"""
===== BAO CAO PHAN TICH HIEU SUAT =====

[FACTS_FROM_LOG]
- Log format: {get_format_display_name(log_format)}
- Overall performance grade: {perf_grade_label}
- HTTP requests observed directly: {total_requests}
- Raw HTTP error responses (4xx/5xx): {total_errors}
- Peak throughput from parsed HTTP entries: {peak_minute[1]} requests/phut luc {peak_minute[0]}

[MEASUREMENT_RULES]
- Throughput, error rate va response-time metrics ben duoi chi dua tren HTTP entries parse duoc.
- Percentile dung nearest-rank tren tap response times quan sat truc tiep.
- Slow request = 1 request co response time > 1000ms.
- Slow endpoint = average response time cua endpoint >= 1000ms.

--- RESPONSE TIME ---
  Tong HTTP requests: {total_requests}
  Trung binh: {avg_resp}ms
  Min: {min_resp}ms | Max: {max_resp}ms
  P95 (nearest-rank): {p95_resp}ms | P99 (nearest-rank): {p99_resp}ms

--- THROUGHPUT ---
  Peak: {peak_minute[1]} requests/phut luc {peak_minute[0]}
  Requests theo phut:
"""

    for minute, count in sorted(requests_per_minute.items()):
        bar = "#" * min(count, 40)
        result += f"    {minute}: {count} reqs {bar}\n"

    result += "\n--- SERVER SUMMARY METRICS (neu co trong log) ---\n"
    result += f"  Server status line - total requests: {server_reported_total_requests if server_reported_total_requests is not None else 'N/A'}\n"
    result += f"  Average response time line: {str(server_reported_avg_response) + 'ms' if server_reported_avg_response is not None else 'N/A'}\n"
    result += f"  System summary - total requests: {server_summary_total_requests if server_summary_total_requests is not None else 'N/A'}\n"
    result += f"  System summary - errors: {server_summary_errors if server_summary_errors is not None else 'N/A'}\n"
    result += f"  System summary - warnings: {server_summary_warnings if server_summary_warnings is not None else 'N/A'}\n"
    if server_summary_errors is not None and server_summary_errors != total_errors:
        result += "  Note: raw HTTP 4xx/5xx responses va 'System summary - Errors' la 2 metric khac nhau; summary line co ve la counter tong hop cap he thong/app, khong phai dem lai tung HTTP error response.\n"
    else:
        result += "  Note: server summary metrics co the khac voi tap HTTP entries quan sat truc tiep neu he thong ghi nhan metric theo scope khac.\n"

    result += f"""
--- ERROR RATE ---
  Tong loi HTTP 4xx/5xx: {total_errors}/{total_requests} ({error_rate}%)
  HTTP Status distribution:
"""

    for code, count in status_codes.most_common():
        result += f"    - {code}: {count}\n"

    result += f"\n--- SLOW REQUESTS (>1000ms): {len(slow_requests)} ---\n"
    for req in slow_requests:
        result += f"  - [{req['timestamp']}] {req['method']} {req['endpoint']} - {req['response_time']}ms (IP: {req['ip']})\n"

    result += f"\n--- SLOW ENDPOINTS (avg >= 1000ms) ---\n"
    if slow_endpoints:
        for ep, avg_time in slow_endpoints:
            result += f"  - {ep}: {avg_time}ms\n"
    else:
        result += "  - KHONG CO ENDPOINT NAO VUOT NGUONG AVG 1000ms\n"

    result += f"\n--- HIGHEST-LATENCY ENDPOINTS (top avg, khong dong nghia la slow) ---\n"
    for ep, avg_time in highest_latency_endpoints:
        result += f"  - {ep}: {avg_time}ms\n"

    result += "\n--- ERROR REQUESTS ---\n"
    for req in error_requests:
        result += f"  [{req['timestamp']}] {req['method']} {req['endpoint']} -> {req['status']} ({req['response_time']}ms, IP: {req['ip']})\n"

    return result.strip()

    result = f"""
===== BÁO CÁO PHÂN TÍCH HIỆU SUẤT =====

📈 Đánh giá tổng thể: {perf_grade}

--- ⏱️ RESPONSE TIME ---
  Tổng HTTP requests: {total_requests}
  Trung bình: {avg_resp}ms
  Min: {min_resp}ms | Max: {max_resp}ms
  P95: {p95_resp}ms | P99: {p99_resp}ms

--- 📊 THROUGHPUT ---
  Peak: {peak_minute[1]} requests/phút lúc {peak_minute[0]}
  Requests theo phút:
"""

    for minute, count in sorted(requests_per_minute.items()):
        bar = "█" * min(count, 40)
        result += f"    {minute}: {count} reqs {bar}\n"

    result += "\n--- 🧾 SERVER SUMMARY METRICS (nếu có trong log) ---\n"
    result += f"  Server reported total requests: {server_reported_total_requests if server_reported_total_requests is not None else 'N/A'}\n"
    result += f"  Server reported average response time: {str(server_reported_avg_response) + 'ms' if server_reported_avg_response is not None else 'N/A'}\n"
    result += "  Ghi chú: Các số liệu này có thể khác với metrics tính từ HTTP entries quan sát trực tiếp.\n"

    result += f"""
--- ❌ ERROR RATE ---
  Tổng lỗi: {total_errors}/{total_requests} ({error_rate}%)
  HTTP Status distribution:
"""

    for code, count in status_codes.most_common():
        indicator = "✅" if code.startswith("2") else "⚠️" if code.startswith("3") else "🟠" if code.startswith("4") else "🔴"
        result += f"    {indicator} {code}: {count}\n"

    result += f"\n--- 🐌 SLOW REQUESTS (>1000ms): {len(slow_requests)} ---\n"

    for req in slow_requests:
        result += f"  🔴 [{req['timestamp']}] {req['method']} {req['endpoint']} - {req['response_time']}ms (IP: {req['ip']})\n"

    result += f"\n--- 📉 SLOWEST ENDPOINTS (avg response time) ---\n"

    for ep, avg_time in slowest_endpoints:
        indicator = "🔴" if avg_time > 1000 else "⚠️" if avg_time > 500 else "✅"
        result += f"  {indicator} {ep}: {avg_time}ms\n"

    result += "\n--- 🚨 ERROR REQUESTS ---\n"

    for req in error_requests:
        result += f"  [{req['timestamp']}] {req['method']} {req['endpoint']} → {req['status']} ({req['response_time']}ms, IP: {req['ip']})\n"

    return result.strip()


# ============================================================
# TOOL 6: Correlate Events - Phân tích tương quan sự kiện
# ============================================================

def correlate_events(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích tương quan thời gian giữa sự kiện.
    Lưu ý: tương quan KHÔNG đồng nghĩa với quan hệ nhân quả.
    """

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    security_data = collect_security_observations(entries)
    evidence_events = security_data["evidence_events"]
    mitigation_logs = security_data["mitigation_logs"]
    error_entries = [e for e in entries if e.level in ("ERROR", "CRITICAL")]

    if log_format == "syslog":
        def cluster_security_events(events, max_gap_seconds=15):
            clusters = []
            current = []
            current_key = None
            for event in events:
                event_ts = parse_ts(event["timestamp"])
                primary_type = event["categories"][0] if event["categories"] else "unknown"
                primary_ip = event["ips"][0] if event["ips"] else "N/A"
                key = (primary_type, primary_ip)
                if not current:
                    current = [event]
                    current_key = key
                    continue
                prev_ts = parse_ts(current[-1]["timestamp"])
                gap = None if prev_ts is None or event_ts is None else (event_ts - prev_ts).total_seconds()
                if key == current_key and gap is not None and 0 <= gap <= max_gap_seconds:
                    current.append(event)
                else:
                    clusters.append((current_key, list(current)))
                    current = [event]
                    current_key = key
            if current:
                clusters.append((current_key, list(current)))
            return clusters

        operational_events = []
        operational_keywords = [
            "out of memory",
            "killed process",
            "main process exited",
            "failed with result",
            "scheduled restart job",
            "started mysql",
            "cpu clock throttled",
            "syn flooding",
            "ext4-fs error",
        ]
        for entry in entries:
            message = (entry.message or "").lower()
            if any(keyword in message for keyword in operational_keywords):
                operational_events.append(entry)

        op_cascades = []
        current_cascade = []
        for entry in operational_events:
            curr_ts = parse_ts(entry.timestamp)
            if curr_ts is None:
                continue
            if not current_cascade:
                current_cascade = [entry]
                continue
            prev_ts = parse_ts(current_cascade[-1].timestamp)
            gap = None if prev_ts is None else (curr_ts - prev_ts).total_seconds()
            if gap is not None and 0 <= gap <= 20:
                current_cascade.append(entry)
            else:
                if len(current_cascade) >= 2:
                    op_cascades.append(list(current_cascade))
                current_cascade = [entry]
        if len(current_cascade) >= 2:
            op_cascades.append(list(current_cascade))

        attack_bursts = cluster_security_events(evidence_events)
        burst_to_ops = []
        for (burst_type, burst_ip), burst_events in attack_bursts:
            burst_end = parse_ts(burst_events[-1]["timestamp"])
            if burst_end is None:
                continue
            nearest_op = None
            nearest_delay = None
            for op in operational_events:
                op_ts = parse_ts(op.timestamp)
                if op_ts is None:
                    continue
                diff = (op_ts - burst_end).total_seconds()
                if 0 < diff <= 90 and (nearest_delay is None or diff < nearest_delay):
                    nearest_delay = diff
                    nearest_op = op
            if nearest_op:
                burst_to_ops.append({
                    "burst_type": burst_type,
                    "burst_ip": burst_ip,
                    "count": len(burst_events),
                    "burst_end": burst_events[-1]["timestamp"],
                    "impact": f"[{nearest_op.timestamp}] [{nearest_op.service}] {(nearest_op.message or '')[:100]}",
                    "delay_seconds": int(nearest_delay),
                })

        suspicious_ips = security_data["suspicious_ips"]

        result = f"""
===== BAO CAO PHAN TICH TUONG QUAN SU KIEN =====

[FACTS_FROM_LOG]
- Total log entries: {len(entries)}
- Security evidence events: {len(evidence_events)}
- Security attack bursts/groups: {len(attack_bursts)}
- Operational cascades observed: {len(op_cascades)}
- Explicit mitigation logs: {len(mitigation_logs)}
- Suspicious IPs from security evidence: {len(suspicious_ips)}

[IMPORTANT_NOTE]
- Syslog co the chua ca attack activity lan system/service events.
- Chuoi SSH failed password duoc xem la attack burst, KHONG phai operational error cascade.
- Operational cascade uu tien cac su kien nhu OOM -> process kill -> service fail/restart.
"""

        result += f"\n{'='*55}\nATTACK BURSTS / GROUPS\n{'='*55}\n"
        if attack_bursts:
            for (burst_type, burst_ip), burst_events in attack_bursts:
                result += (
                    f"  - type={burst_type} ip={burst_ip} events={len(burst_events)} "
                    f"time={burst_events[0]['timestamp']} -> {burst_events[-1]['timestamp']}\n"
                )
        else:
            result += "  - KHONG PHAT HIEN ATTACK BURST RO RANG\n"

        result += f"\n{'='*55}\nOPERATIONAL CASCADES\n{'='*55}\n"
        if op_cascades:
            for idx, cascade in enumerate(op_cascades, 1):
                result += f"  Cascade #{idx}: {len(cascade)} events\n"
                for item in cascade:
                    result += f"    - [{item.timestamp}] [{item.service}] {(item.message or '')[:100]}\n"
        else:
            result += "  - KHONG PHAT HIEN OPERATIONAL CASCADE RO RANG\n"

        result += f"\n{'='*55}\nATTACK BURST -> OPERATIONAL IMPACT (TEMPORAL)\n{'='*55}\n"
        if burst_to_ops:
            for item in burst_to_ops:
                result += (
                    f"  - burst type={item['burst_type']} ip={item['burst_ip']} "
                    f"({item['count']} events, ket thuc luc {item['burst_end']})\n"
                )
                result += f"    -> Operational event sau {item['delay_seconds']}s: {item['impact']}\n"
                result += "    HINT: day chi la temporal correlation, can doi chieu them.\n"
        else:
            result += "  - CHUA THAY TEMPORAL LINK RO RANG GIUA ATTACK BURST VA OPERATIONAL IMPACT\n"

        result += f"\n{'='*55}\nMITIGATION LOGS\n{'='*55}\n"
        if mitigation_logs:
            for item in mitigation_logs:
                result += f"  - [{item['timestamp']}] [{item['service']}] {item['message']}\n"
        else:
            result += "  - KHONG CO MITIGATION LOG RO RANG\n"

        return result.strip()

    cascades = []
    current_cascade = []
    for entry in error_entries:
        curr_ts = parse_ts(entry.timestamp)
        if curr_ts is None:
            continue
        if not current_cascade:
            current_cascade = [entry]
            continue
        prev_ts = parse_ts(current_cascade[-1].timestamp)
        if prev_ts is None:
            current_cascade = [entry]
            continue
        if abs((curr_ts - prev_ts).total_seconds()) <= 30:
            current_cascade.append(entry)
        else:
            if len(current_cascade) >= 2:
                cascades.append(list(current_cascade))
            current_cascade = [entry]
    if len(current_cascade) >= 2:
        cascades.append(list(current_cascade))

    resource_events = []
    cpu_pattern = re.compile(r"CPU\s+Usage:\s*(\d+)%")
    mem_pattern = re.compile(r"Memory(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)
    disk_pattern = re.compile(r"Disk(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)

    for entry in entries:
        message = entry.message or ""
        cpu_match = cpu_pattern.search(message)
        mem_match = mem_pattern.search(message)
        disk_match = disk_pattern.search(message)

        if cpu_match and int(cpu_match.group(1)) >= 80:
            resource_events.append((entry.timestamp, f"CPU event ({message[:80]})"))
        if mem_match and int(mem_match.group(1)) >= 80:
            resource_events.append((entry.timestamp, f"Memory event ({message[:80]})"))
        if disk_match and int(disk_match.group(1)) >= 80:
            resource_events.append((entry.timestamp, f"Disk event ({message[:80]})"))
        if "connection pool exhausted" in message.lower():
            resource_events.append((entry.timestamp, f"DB_POOL event ({message[:80]})"))
        if "outofmemoryerror" in message.lower():
            resource_events.append((entry.timestamp, f"OOM event ({message[:80]})"))

    resource_correlations = []
    operational_error_entries = [
        err for err in error_entries
        if err.service not in ("SecurityModule", "AuthService")
    ]
    for res_ts_text, res_desc in resource_events:
        res_ts = parse_ts(res_ts_text)
        if res_ts is None:
            continue
        nearest_error = None
        nearest_delay = None
        for err in operational_error_entries:
            err_ts = parse_ts(err.timestamp)
            if err_ts is None:
                continue
            diff = (err_ts - res_ts).total_seconds()
            if 0 < diff <= 120 and (nearest_delay is None or diff < nearest_delay):
                nearest_delay = diff
                nearest_error = err
        if nearest_error:
            resource_correlations.append({
                "resource": res_desc,
                "error": f"[{nearest_error.timestamp}] [{nearest_error.service}] {(nearest_error.message or '')[:100]}",
                "delay_seconds": int(nearest_delay),
            })

    candidate_impacts = [
        e for e in entries
        if (
            e.level in ("ERROR", "CRITICAL") and e.service not in ("SecurityModule", "AuthService")
        ) or (
            e.service == "SystemMonitor"
            and e.level in ("WARNING", "CRITICAL")
            and any(k in (e.message or "").lower() for k in [
                "cpu usage exceeded",
                "memory usage exceeded",
                "disk i/o latency",
            ])
        )
    ]

    attack_impact = []
    for event in evidence_events:
        event_ts = parse_ts(event["timestamp"])
        if event_ts is None:
            continue
        nearest_impact = None
        nearest_delay = None
        for imp in candidate_impacts:
            imp_ts = parse_ts(imp.timestamp)
            if imp_ts is None:
                continue
            diff = (imp_ts - event_ts).total_seconds()
            if 0 < diff <= 180 and (nearest_delay is None or diff < nearest_delay):
                nearest_delay = diff
                nearest_impact = imp
        if nearest_impact:
            labels = ", ".join(event["categories"])
            attack_impact.append({
                "attack": f"[{event['timestamp']}] [{event['service']}] {labels}: {event['message'][:90]}",
                "impact": f"[{nearest_impact.timestamp}] [{nearest_impact.service}] {(nearest_impact.message or '')[:90]}",
                "delay_seconds": int(nearest_delay),
            })

    def cluster_security_bursts(events, max_gap_seconds=30):
        bursts = []
        current = []
        current_ip = None
        for event in events:
            event_ts = parse_ts(event["timestamp"])
            event_ip = event["ips"][0] if event["ips"] else "N/A"
            if not current:
                current = [event]
                current_ip = event_ip
                continue
            prev_ts = parse_ts(current[-1]["timestamp"])
            gap = None if prev_ts is None or event_ts is None else (event_ts - prev_ts).total_seconds()
            if event_ip == current_ip and gap is not None and 0 <= gap <= max_gap_seconds:
                current.append(event)
            else:
                bursts.append((current_ip, list(current)))
                current = [event]
                current_ip = event_ip
        if current:
            bursts.append((current_ip, list(current)))
        return bursts

    security_bursts = cluster_security_bursts(evidence_events)
    burst_candidate_impacts = []
    for burst_ip, burst_events in security_bursts:
        burst_end = parse_ts(burst_events[-1]["timestamp"])
        if burst_end is None:
            continue
        nearest_impact = None
        nearest_delay = None
        for imp in candidate_impacts:
            imp_ts = parse_ts(imp.timestamp)
            if imp_ts is None:
                continue
            diff = (imp_ts - burst_end).total_seconds()
            if 0 < diff <= 120 and (nearest_delay is None or diff < nearest_delay):
                nearest_delay = diff
                nearest_impact = imp
        if nearest_impact:
            burst_candidate_impacts.append({
                "burst_ip": burst_ip,
                "event_count": len(burst_events),
                "time_range": f"{burst_events[0]['timestamp']} -> {burst_events[-1]['timestamp']}",
                "categories": sorted({cat for event in burst_events for cat in event["categories"]}),
                "impact": f"[{nearest_impact.timestamp}] [{nearest_impact.service}] {(nearest_impact.message or '')[:90]}",
                "delay_seconds": int(nearest_delay),
            })

    root_causes = Counter()
    service_errors = defaultdict(list)
    for entry in error_entries:
        service_errors[entry.service].append(entry)
    for cascade in cascades:
        root_causes[cascade[0].service] += 1

    result = f"""
===== BAO CAO PHAN TICH TUONG QUAN SU KIEN =====

[FACTS_FROM_LOG]
- Total log entries: {len(entries)}
- ERROR/CRITICAL entries: {len(error_entries)}
- Security evidence events used for cross-checking: {len(evidence_events)}
- Security bursts grouped by IP/time (<=30s gap): {len(security_bursts)}
- Error cascades observed (<=30s gap): {len(cascades)}
- Resource -> nearest error candidate links (<=120s): {len(resource_correlations)}
- Security burst -> nearest impact candidate links (<=120s): {len(burst_candidate_impacts)}

[METHOD_NOTE]
- Cac lien ket duoi day la candidate temporal links, khong phai bang chung nhan qua.
- Security bursts duoc group theo IP va khoang cach thoi gian toi da 30 giay.
- Resource links va security links chi giu error/impact gan nhat trong cua so thoi gian da neu.
- Fact = dong log co the doi chieu truc tiep. Inference = goi y de kiem tra them.
"""

    result += f"\n{'='*55}\nERROR CASCADING ANALYSIS\n{'='*55}\n"
    if cascades:
        for i, cascade in enumerate(cascades, 1):
            result += f"  Cascade #{i}: {len(cascade)} events, service xuat hien som nhat = {cascade[0].service}\n"
            for entry in cascade:
                result += f"    - [{entry.timestamp}] [{entry.service}] {(entry.message or '')[:90]}\n"
            result += "    HINT: service xuat hien som nhat chi la goi y, khong phai root cause da duoc chung minh.\n"
    else:
        result += "  - KHONG PHAT HIEN ERROR CASCADE RO RANG\n"

    result += f"\n{'='*55}\nRESOURCE -> ERROR (TEMPORAL CANDIDATES)\n{'='*55}\n"
    if resource_correlations:
        for corr in resource_correlations:
            result += f"  - {corr['resource']}\n"
            result += f"    -> Error gan nhat sau {corr['delay_seconds']}s: {corr['error']}\n"
            result += "    HINT: day chi la gan nhau theo thoi gian.\n"
    else:
        result += "  - KHONG PHAT HIEN CANDIDATE LINK RO RANG GIUA RESOURCE EVENT VA ERROR\n"

    result += f"\n{'='*55}\nROOT CAUSE HINTS (HEURISTIC)\n{'='*55}\n"
    if root_causes:
        for service, count in root_causes.most_common():
            result += f"  - {service}: xuat hien som nhat trong {count} cascade(s)\n"
        result += f"  - Service nen uu tien kiem tra truoc: {root_causes.most_common(1)[0][0]}\n"
    else:
        result += "  - KHONG CO GOI Y ROOT CAUSE RO RANG TU CASCADE\n"

    result += f"\n{'='*55}\nSERVICE ERROR MAP\n{'='*55}\n"
    for service, errs in sorted(service_errors.items(), key=lambda x: len(x[1]), reverse=True):
        result += f"  - {service}: {len(errs)} loi\n"
        for e in errs[:3]:
            result += f"    * [{e.timestamp}] {(e.message or '')[:80]}\n"
        if len(errs) > 3:
            result += f"    * ... va {len(errs) - 3} loi khac\n"

    result += f"\n{'='*55}\nSECURITY BURSTS -> IMPACT (TEMPORAL CANDIDATES)\n{'='*55}\n"
    if security_bursts:
        for burst_ip, burst_events in security_bursts:
            categories = ", ".join(sorted({cat for event in burst_events for cat in event["categories"]}))
            result += (
                f"  - burst ip={burst_ip} events={len(burst_events)} "
                f"time={burst_events[0]['timestamp']} -> {burst_events[-1]['timestamp']} | categories={categories}\n"
            )
    else:
        result += "  - KHONG PHAT HIEN SECURITY BURST RO RANG\n"

    if burst_candidate_impacts:
        result += "\n  Candidate links:\n"
        for item in burst_candidate_impacts:
            categories = ", ".join(item["categories"]) if item["categories"] else "N/A"
            result += (
                f"    - burst ip={item['burst_ip']} | categories={categories} | "
                f"events={item['event_count']} | time={item['time_range']}\n"
            )
            result += f"      -> Impact gan nhat sau {item['delay_seconds']}s: {item['impact']}\n"
    else:
        result += "\n  - KHONG PHAT HIEN CANDIDATE LINK RO RANG GIUA SECURITY BURST VA IMPACT\n"

    return result.strip()

    root_causes = Counter()
    service_errors = defaultdict(list)
    for entry in error_entries:
        service_errors[entry.service].append(entry)
    for cascade in cascades:
        root_causes[cascade[0].service] += 1

    result = f"""
===== BAO CAO PHAN TICH TUONG QUAN SU KIEN =====

[FACTS_FROM_LOG]
- Total log entries: {len(entries)}
- ERROR/CRITICAL entries: {len(error_entries)}
- Security evidence events used for cross-checking: {len(evidence_events)}
- Error cascades observed: {len(cascades)}
- Resource -> nearest error temporal links: {len(resource_correlations)}
- Security evidence -> nearest impact temporal links: {len(attack_impact)}

[IMPORTANT_NOTE]
- Cac lien ket duoi day la temporal links.
- Chung KHONG tu dong chung minh quan he nhan qua truc tiep.
- Fact = dong log co the doi chieu truc tiep. Hint = heuristic can kiem tra them.
"""

    result += f"\n{'='*55}\nERROR CASCADING ANALYSIS\n{'='*55}\n"
    if cascades:
        for i, cascade in enumerate(cascades, 1):
            result += f"  Cascade #{i}: {len(cascade)} events, service xuat hien som nhat = {cascade[0].service}\n"
            for entry in cascade:
                result += f"    - [{entry.timestamp}] [{entry.service}] {(entry.message or '')[:90]}\n"
            result += "    HINT: service xuat hien som nhat chi la goi y, khong phai root cause da duoc chung minh.\n"
    else:
        result += "  - KHONG PHAT HIEN ERROR CASCADE RO RANG\n"

    result += f"\n{'='*55}\nRESOURCE -> ERROR (TEMPORAL)\n{'='*55}\n"
    if resource_correlations:
        for corr in resource_correlations:
            result += f"  - {corr['resource']}\n"
            result += f"    -> Error gan nhat sau {corr['delay_seconds']}s: {corr['error']}\n"
            result += "    HINT: day chi la gan nhau theo thoi gian.\n"
    else:
        result += "  - KHONG PHAT HIEN TEMPORAL LINK RO RANG GIUA RESOURCE EVENT VA ERROR\n"

    result += f"\n{'='*55}\nROOT CAUSE HINTS (HEURISTIC)\n{'='*55}\n"
    if root_causes:
        for service, count in root_causes.most_common():
            result += f"  - {service}: xuat hien som nhat trong {count} cascade(s)\n"
        result += f"  - Service nen uu tien kiem tra truoc: {root_causes.most_common(1)[0][0]}\n"
    else:
        result += "  - KHONG CO GOI Y ROOT CAUSE RO RANG TU CASCADE\n"

    result += f"\n{'='*55}\nSERVICE ERROR MAP\n{'='*55}\n"
    for service, errs in sorted(service_errors.items(), key=lambda x: len(x[1]), reverse=True):
        result += f"  - {service}: {len(errs)} loi\n"
        for e in errs[:3]:
            result += f"    * [{e.timestamp}] {(e.message or '')[:80]}\n"
        if len(errs) > 3:
            result += f"    * ... va {len(errs) - 3} loi khac\n"

    result += f"\n{'='*55}\nSECURITY EVIDENCE -> IMPACT (TEMPORAL ONLY)\n{'='*55}\n"
    if attack_impact:
        for item in attack_impact:
            result += f"  - Security evidence event: {item['attack']}\n"
            result += f"    -> Impact gan nhat sau {item['delay_seconds']}s: {item['impact']}\n"
            result += "    HINT: can doi chieu log goc de ket luan.\n"
    else:
        result += "  - KHONG PHAT HIEN TEMPORAL LINK RO RANG GIUA SECURITY EVIDENCE VA IMPACT\n"

    return result.strip()

    cascades = []
    current_cascade = []

    for entry in error_entries:
        curr_ts = parse_ts(entry.timestamp)
        if curr_ts is None:
            continue

        if not current_cascade:
            current_cascade = [entry]
            continue

        prev_ts = parse_ts(current_cascade[-1].timestamp)
        if prev_ts is None:
            current_cascade = [entry]
            continue

        diff_seconds = abs((curr_ts - prev_ts).total_seconds())

        if diff_seconds <= 30:
            current_cascade.append(entry)
        else:
            if len(current_cascade) >= 2:
                cascades.append(list(current_cascade))
            current_cascade = [entry]

    if len(current_cascade) >= 2:
        cascades.append(list(current_cascade))

    resource_events = []
    cpu_pattern = re.compile(r"CPU\s+Usage:\s*(\d+)%")
    mem_pattern = re.compile(r"Memory(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)
    disk_pattern = re.compile(r"Disk(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)

    for entry in entries:
        message = entry.message or ""

        cpu_match = cpu_pattern.search(message)
        mem_match = mem_pattern.search(message)
        disk_match = disk_pattern.search(message)

        if cpu_match:
            value = int(cpu_match.group(1))
            if value >= 80:
                resource_events.append({
                    "timestamp": entry.timestamp,
                    "type": "CPU",
                    "value": value,
                    "entry": entry,
                })

        if mem_match:
            value = int(mem_match.group(1))
            if value >= 80:
                resource_events.append({
                    "timestamp": entry.timestamp,
                    "type": "Memory",
                    "value": value,
                    "entry": entry,
                })

        if disk_match:
            value = int(disk_match.group(1))
            if value >= 80:
                resource_events.append({
                    "timestamp": entry.timestamp,
                    "type": "Disk",
                    "value": value,
                    "entry": entry,
                })

        if "connection pool exhausted" in message.lower():
            resource_events.append({
                "timestamp": entry.timestamp,
                "type": "DB_POOL",
                "value": 100,
                "entry": entry,
            })

        if "outofmemoryerror" in message.lower():
            resource_events.append({
                "timestamp": entry.timestamp,
                "type": "OOM",
                "value": 100,
                "entry": entry,
            })

    resource_correlations = []
    for res_event in resource_events:
        res_ts = parse_ts(res_event["timestamp"])
        if res_ts is None:
            continue

        nearest_error = None
        nearest_delay = None

        for err in error_entries:
            err_ts = parse_ts(err.timestamp)
            if err_ts is None:
                continue

            diff = (err_ts - res_ts).total_seconds()
            if 0 < diff <= 120:
                if nearest_delay is None or diff < nearest_delay:
                    nearest_delay = diff
                    nearest_error = err

        if nearest_error:
            resource_correlations.append({
                "resource": f"{res_event['type']} event at {res_event['timestamp']} ({(res_event['entry'].message or '')[:80]})",
                "error": f"[{nearest_error.timestamp}] [{nearest_error.service}] {(nearest_error.message or '')[:100]}",
                "delay_seconds": int(nearest_delay),
            })

    root_causes = Counter()
    service_errors = defaultdict(list)
    for entry in error_entries:
        service_errors[entry.service].append(entry)

    for cascade in cascades:
        root_service = cascade[0].service
        root_causes[root_service] += 1

    attack_patterns = [
        r"(?i)\bSQL\s+Injection\b",
        r"(?i)\bXSS\b",
        r"(?i)\bPath\s+traversal\b",
        r"(?i)\bBrute-?force\s+attack\s+detected\b",
        r"(?i)\bRapid\s+login\s+attempts\s+detected\b",
        r"(?i)\bNoSQL\s+Injection\b",
        r"(?i)\bLDAP\s+Injection\b",
        r"(?i)\bCommand\s+Injection\b",
        r"(?i)\bForced\s+browsing\b",
    ]

    attack_events = []
    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if any(re.search(p, line_text or "") for p in attack_patterns):
            attack_events.append(entry)

    candidate_impacts = [
        e for e in entries
        if (
            e.level in ("ERROR", "CRITICAL") and e.service not in ("SecurityModule", "AuthService")
        ) or (
            e.service == "SystemMonitor"
            and e.level in ("WARNING", "CRITICAL")
            and any(k in (e.message or "").lower() for k in [
                "cpu usage exceeded",
                "memory usage exceeded",
                "disk i/o latency",
            ])
        )
    ]

    attack_impact = []
    for atk in attack_events:
        atk_ts = parse_ts(atk.timestamp)
        if atk_ts is None:
            continue

        nearest_impact = None
        nearest_delay = None
        for imp in candidate_impacts:
            imp_ts = parse_ts(imp.timestamp)
            if imp_ts is None:
                continue

            diff = (imp_ts - atk_ts).total_seconds()
            if 0 < diff <= 180:
                if nearest_delay is None or diff < nearest_delay:
                    nearest_delay = diff
                    nearest_impact = imp

        if nearest_impact:
            attack_impact.append({
                "attack": f"[{atk.timestamp}] [{atk.service}] {(atk.message or '')[:90]}",
                "impact": f"[{nearest_impact.timestamp}] [{nearest_impact.service}] {(nearest_impact.message or '')[:90]}",
                "delay_seconds": int(nearest_delay),
            })

    result = f"""
===== BÁO CÁO PHÂN TÍCH TƯƠNG QUAN SỰ KIỆN =====

📊 Tổng log entries: {len(entries)}
🔴 Tổng ERROR/CRITICAL: {len(error_entries)}
🔗 Error cascades phát hiện: {len(cascades)}
📈 Resource → nearest error correlations: {len(resource_correlations)}
⚔️ Attack → nearest impact correlations: {len(attack_impact)}

⚠️ LƯU Ý:
Các kết quả dưới đây là TƯƠNG QUAN THỜI GIAN.
Chúng KHÔNG tự động chứng minh quan hệ nhân quả trực tiếp.

{'='*55}
          ERROR CASCADING ANALYSIS
{'='*55}
"""
    if cascades:
        for i, cascade in enumerate(cascades, 1):
            result += f"\n  🔗 Cascade #{i} ({len(cascade)} events, first error service: {cascade[0].service}):\n"
            for entry in cascade:
                result += f"    → [{entry.timestamp}] [{entry.service}] {(entry.message or '')[:90]}\n"
            result += f"    💡 Earliest event in cascade: {cascade[0].service} - {(cascade[0].message or '')[:100]}\n"
    else:
        result += "  ✅ Không phát hiện error cascade rõ ràng\n"

    result += f"""
{'='*55}
          RESOURCE → ERROR (TEMPORAL)
{'='*55}
"""
    if resource_correlations:
        for corr in resource_correlations:
            result += f"  ⚠️ {corr['resource']}\n"
            result += f"    → Error gần nhất sau {corr['delay_seconds']}s: {corr['error']}\n\n"
    else:
        result += "  ✅ Không phát hiện tương quan thời gian rõ ràng giữa resource event và error\n"

    result += f"""
{'='*55}
          ROOT CAUSE HINTS
{'='*55}
"""
    if root_causes:
        for service, count in root_causes.most_common():
            result += f"  🔍 {service}: xuất hiện đầu tiên trong {count} cascade(s)\n"
        result += f"\n  💡 Service nên ưu tiên kiểm tra: {root_causes.most_common(1)[0][0]}\n"
    else:
        result += "  ✅ Không có gợi ý root cause rõ ràng từ cascade\n"

    result += f"""
{'='*55}
          SERVICE ERROR MAP
{'='*55}
"""
    for service, errs in sorted(service_errors.items(), key=lambda x: len(x[1]), reverse=True):
        result += f"  🔧 {service}: {len(errs)} lỗi\n"
        for e in errs[:3]:
            result += f"     - [{e.timestamp}] {(e.message or '')[:80]}\n"
        if len(errs) > 3:
            result += f"     ... và {len(errs) - 3} lỗi khác\n"

    result += f"""
{'='*55}
          ATTACK → IMPACT (TEMPORAL ONLY)
{'='*55}
"""
    if attack_impact:
        for imp in attack_impact:
            result += f"  ⚔️ Attack event: {imp['attack']}\n"
            result += f"    → Impact gần nhất sau {imp['delay_seconds']}s: {imp['impact']}\n\n"
    else:
        result += "  ✅ Không phát hiện tương quan thời gian rõ ràng giữa attack event và impact\n"

    return result.strip()


# ============================================================
# TOOL 7: Analyze Traffic Patterns - Phân tích traffic
# ============================================================

def analyze_traffic_patterns(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích traffic patterns."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    http_entries = [entry for entry in entries if is_http_request_entry(entry)]

    if log_format == "syslog" or not http_entries:
        security_data = collect_security_observations(entries)
        suspicious_ips = security_data["suspicious_ips"]
        blocked_ips = security_data["blocked_ips"]
        watchlist_ips = security_data["watchlist_ips"]

        events_per_minute = Counter()
        ip_events = Counter()
        for entry in entries:
            minute_key = get_minute_bucket(entry.timestamp)
            if minute_key:
                events_per_minute[minute_key] += 1
            if entry.ip:
                ip_events[entry.ip] += 1

        peak_minute = events_per_minute.most_common(1)[0] if events_per_minute else ("N/A", 0)
        avg_epm = round(sum(events_per_minute.values()) / max(len(events_per_minute), 1), 1)

        result = f"""
===== BAO CAO PHAN TICH LOG ACTIVITY PATTERNS =====

[FACTS_FROM_LOG]
- Log format: {get_format_display_name(log_format)}
- Total log entries: {len(entries)}
- Unique IPs in log: {len(ip_events)}
- Suspicious IPs from security evidence: {len(suspicious_ips)}
- Explicitly blocked IPs in log: {len(blocked_ips)}
- Explicit watchlist IPs in log: {len(watchlist_ips)}
- Note: day la syslog/non-HTTP log nen metric dung la events/phut, khong phai requests/phut.
"""

        result += f"\n{'='*55}\nLOG ACTIVITY VOLUME\n{'='*55}\n"
        result += f"  Average: {avg_epm} events/phut\n"
        result += f"  Peak: {peak_minute[1]} events/phut luc {peak_minute[0]}\n"
        for minute, count in sorted(events_per_minute.items()):
            bar = "#" * min(count, 40)
            result += f"    {minute}: {count:3d} events {bar}\n"

        result += f"\n{'='*55}\nIP ACTIVITY SUMMARY\n{'='*55}\n"
        if ip_events:
            for ip, count in ip_events.most_common():
                tags = []
                if ip in suspicious_ips:
                    tags.append("SUSPICIOUS")
                if ip in blocked_ips:
                    tags.append("BLOCKED")
                if ip in watchlist_ips:
                    tags.append("WATCHLIST")
                tag_text = f" [{' | '.join(tags)}]" if tags else ""
                result += f"  - {ip}: {count} events{tag_text}\n"
        else:
            result += "  - KHONG CO IP DUOC TRICH XUAT TU LOG\n"

        result += f"\n{'='*55}\nKHUYEN NGHI\n{'='*55}\n"
        if suspicious_ips:
            result += "  - Co suspicious IPs duoc xac dinh tu security evidence; can doi chieu voi security report.\n"
        if blocked_ips:
            result += "  - Log da ghi nhan firewall block cho mot so IP; can tiep tuc theo doi sau block.\n"
        if not suspicious_ips and not blocked_ips:
            result += "  - Chua thay suspicious IP ro rang tu security evidence hien tai.\n"

        return result.strip()

    ip_data = defaultdict(lambda: {
        "count": 0,
        "endpoints": Counter(),
        "methods": Counter(),
        "status_codes": Counter(),
        "user_agents": set(),
        "timestamps": [],
        "is_internal": False,
        "is_bot": False,
    })

    user_agent_pattern = re.compile(r'ua="([^"]*)"')

    bot_signatures = [
        "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
        "wfuzz", "hydra", "curl/", "wget/", "python-requests/",
        "scrapy", "bot", "crawler", "spider", "kube-probe",
    ]

    total_requests = 0

    for entry in http_entries:
        ip = entry.ip
        total_requests += 1
        ip_data[ip]["count"] += 1
        ip_data[ip]["timestamps"].append(entry.timestamp)

        if entry.endpoint:
            ip_data[ip]["endpoints"][entry.endpoint] += 1
        if entry.method:
            ip_data[ip]["methods"][entry.method] += 1
        ip_data[ip]["status_codes"][str(entry.status_code)] += 1

        if is_trusted_internal_ip(ip):
            ip_data[ip]["is_internal"] = True

        ua_match = user_agent_pattern.search(entry.raw_line or "")
        if ua_match:
            ua = ua_match.group(1)
            ip_data[ip]["user_agents"].add(ua)
            if any(bot in ua.lower() for bot in bot_signatures):
                ip_data[ip]["is_bot"] = True

    internal_ips = {ip: d for ip, d in ip_data.items() if d["is_internal"]}
    external_ips = {ip: d for ip, d in ip_data.items() if not d["is_internal"]}
    bot_ips = {ip: d for ip, d in ip_data.items() if d["is_bot"]}

    suspicious_ips = {}
    for ip, data in external_ips.items():
        error_count = sum(v for k, v in data["status_codes"].items() if k.startswith(("4", "5")))
        if data["count"] > 0 and error_count > 0 and (error_count / data["count"]) > 0.5:
            suspicious_ips[ip] = data

    requests_per_minute = Counter()
    for entry in http_entries:
        minute_key = get_minute_bucket(entry.timestamp)
        if minute_key:
            requests_per_minute[minute_key] += 1

    peak_minute = requests_per_minute.most_common(1)[0] if requests_per_minute else ("N/A", 0)
    avg_rpm = round(sum(requests_per_minute.values()) / max(len(requests_per_minute), 1), 1)

    endpoint_hits = Counter()
    for _, data in ip_data.items():
        endpoint_hits.update(data["endpoints"])

    unique_visitors = len(ip_data)
    legitimate_visitors = len(internal_ips) + len({
        ip: d for ip, d in external_ips.items() if ip not in suspicious_ips and ip not in bot_ips
    })

    result = f"""
===== BAO CAO PHAN TICH TRAFFIC PATTERNS =====

[FACTS_FROM_LOG]
- Total HTTP requests with IP: {total_requests}
- Unique IPs: {unique_visitors}
- Internal IPs: {len(internal_ips)}
- External IPs: {len(external_ips)}
- Bot IPs by user-agent heuristic: {len(bot_ips)}
- Suspicious IPs by error-rate heuristic: {len(suspicious_ips)}
- Estimated legitimate visitors: {legitimate_visitors}
- Note: traffic metrics trong report nay chi dem HTTP entries de dong nhat voi performance report.
"""
    result += f"\n{'='*55}\nTRAFFIC TIMELINE\n{'='*55}\n"
    result += f"  Average: {avg_rpm} requests/phut\n"
    result += f"  Peak: {peak_minute[1]} requests/phut luc {peak_minute[0]}\n"
    for minute, count in sorted(requests_per_minute.items()):
        bar = "#" * min(count, 40)
        result += f"    {minute}: {count:3d} reqs {bar}\n"

    result += f"\n{'='*55}\nIP CLASSIFICATION\n{'='*55}\n"
    result += "\n  INTERNAL TRAFFIC (trusted):\n"
    for ip, data in sorted(internal_ips.items(), key=lambda x: x[1]["count"], reverse=True):
        top_ep = data["endpoints"].most_common(1)[0][0] if data["endpoints"] else "N/A"
        result += f"    - {ip:18s} | {data['count']:4d} reqs | Top: {top_ep}\n"

    result += "\n  EXTERNAL TRAFFIC:\n"
    for ip, data in sorted(external_ips.items(), key=lambda x: x[1]["count"], reverse=True):
        if ip in suspicious_ips:
            label = "REVIEW"
        elif ip in bot_ips:
            label = "BOT"
        else:
            label = "OK"
        error_count = sum(v for k, v in data["status_codes"].items() if k.startswith(("4", "5")))
        result += f"    - {ip:18s} | {data['count']:4d} reqs | Errors: {error_count} | {label}\n"

    result += f"\n{'='*55}\nBOT DETECTION\n{'='*55}\n"
    if bot_ips:
        for ip, data in bot_ips.items():
            uas = ", ".join(list(data["user_agents"])[:3])
            result += f"  - {ip}: {data['count']} requests\n"
            result += f"    User-Agents: {uas}\n"
            top_endpoints = data["endpoints"].most_common(3)
            result += f"    Target endpoints: {', '.join(ep for ep, _ in top_endpoints)}\n"
    else:
        result += "  - KHONG PHAT HIEN BOT TRAFFIC RO RANG THEO USER-AGENT\n"

    result += f"\n{'='*55}\nPOPULAR ENDPOINTS\n{'='*55}\n"
    for ep, count in endpoint_hits.most_common(10):
        bar = "#" * min(count, 30)
        result += f"  {ep:35s} | {count:4d} hits {bar}\n"

    result += f"\n{'='*55}\nKHUYEN NGHI\n{'='*55}\n"
    if suspicious_ips:
        result += "  - Co IP dang ngo theo heuristic ty le loi cao; nen xem xet them truoc khi chan.\n"
    if bot_ips:
        result += "  - Phat hien bot traffic theo user-agent; can nhac bot management/CAPTCHA.\n"
    if peak_minute[1] > avg_rpm * 3 and avg_rpm > 0:
        result += f"  - Peak traffic ({peak_minute[1]} rpm) cao gap {round(peak_minute[1] / avg_rpm, 1)}x trung binh; co the can xem xet auto-scaling.\n"
    if not suspicious_ips and not bot_ips:
        result += "  - Chua thay bat thuong ro rang trong HTTP traffic theo heuristic hien tai.\n"

    return result.strip()

    ip_data = defaultdict(lambda: {
        "count": 0,
        "endpoints": Counter(),
        "methods": Counter(),
        "status_codes": Counter(),
        "user_agents": set(),
        "timestamps": [],
        "is_internal": False,
        "is_bot": False,
    })

    user_agent_pattern = re.compile(r'ua="([^"]*)"')

    bot_signatures = [
        "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
        "wfuzz", "hydra", "curl/", "wget/", "python-requests/",
        "scrapy", "bot", "crawler", "spider", "kube-probe",
    ]

    total_requests = 0

    for entry in entries:
        if not entry.ip:
            continue

        ip = entry.ip
        total_requests += 1
        ip_data[ip]["count"] += 1
        ip_data[ip]["timestamps"].append(entry.timestamp)

        if entry.endpoint:
            ip_data[ip]["endpoints"][entry.endpoint] += 1
        if entry.method:
            ip_data[ip]["methods"][entry.method] += 1
        if entry.status_code is not None:
            ip_data[ip]["status_codes"][str(entry.status_code)] += 1

        if is_trusted_internal_ip(ip):
            ip_data[ip]["is_internal"] = True

        ua_match = user_agent_pattern.search(entry.raw_line or "")
        if ua_match:
            ua = ua_match.group(1)
            ip_data[ip]["user_agents"].add(ua)
            if any(bot in ua.lower() for bot in bot_signatures):
                ip_data[ip]["is_bot"] = True

    internal_ips = {ip: d for ip, d in ip_data.items() if d["is_internal"]}
    external_ips = {ip: d for ip, d in ip_data.items() if not d["is_internal"]}
    bot_ips = {ip: d for ip, d in ip_data.items() if d["is_bot"]}

    suspicious_ips = {}
    for ip, data in external_ips.items():
        error_count = sum(v for k, v in data["status_codes"].items() if k.startswith(("4", "5")))
        if data["count"] > 0 and error_count > 0 and (error_count / data["count"]) > 0.5:
            suspicious_ips[ip] = data

    requests_per_minute = Counter()
    for entry in entries:
        if entry.ip and entry.timestamp:
            minute_key = entry.timestamp[:16]
            requests_per_minute[minute_key] += 1

    peak_minute = requests_per_minute.most_common(1)[0] if requests_per_minute else ("N/A", 0)
    avg_rpm = round(sum(requests_per_minute.values()) / max(len(requests_per_minute), 1), 1)

    endpoint_hits = Counter()
    for _, data in ip_data.items():
        endpoint_hits.update(data["endpoints"])

    unique_visitors = len(ip_data)
    legitimate_visitors = len(internal_ips) + len({
        ip: d for ip, d in external_ips.items() if ip not in suspicious_ips and ip not in bot_ips
    })

    result = f"""
===== BÁO CÁO PHÂN TÍCH TRAFFIC PATTERNS =====

📊 Tổng requests có IP: {total_requests}
👥 Unique IPs: {unique_visitors}
🏠 Internal IPs: {len(internal_ips)}
🌍 External IPs: {len(external_ips)}
🤖 Bot IPs: {len(bot_ips)}
⚠️ Suspicious IPs: {len(suspicious_ips)}
👤 Estimated legitimate visitors: {legitimate_visitors}

{'='*55}
          TRAFFIC TIMELINE
{'='*55}
  📈 Average: {avg_rpm} requests/phút
  🔝 Peak: {peak_minute[1]} requests/phút lúc {peak_minute[0]}
"""
    for minute, count in sorted(requests_per_minute.items()):
        bar = "█" * min(count, 40)
        result += f"    {minute}: {count:3d} reqs {bar}\n"

    result += f"""
{'='*55}
          IP CLASSIFICATION
{'='*55}

  🏠 INTERNAL TRAFFIC (trusted):
"""
    for ip, data in sorted(internal_ips.items(), key=lambda x: x[1]["count"], reverse=True):
        top_ep = data["endpoints"].most_common(1)[0][0] if data["endpoints"] else "N/A"
        result += f"    ✅ {ip:18s} | {data['count']:4d} reqs | Top: {top_ep}\n"

    result += f"\n  🌍 EXTERNAL TRAFFIC:\n"
    for ip, data in sorted(external_ips.items(), key=lambda x: x[1]["count"], reverse=True):
        if ip in suspicious_ips:
            icon = "🔴"
            label = "SUSPICIOUS"
        elif ip in bot_ips:
            icon = "🤖"
            label = "BOT"
        else:
            icon = "🟢"
            label = "OK"

        error_count = sum(v for k, v in data["status_codes"].items() if k.startswith(("4", "5")))
        result += f"    {icon} {ip:18s} | {data['count']:4d} reqs | Errors: {error_count} | {label}\n"

    result += f"""
{'='*55}
          BOT DETECTION
{'='*55}
"""
    if bot_ips:
        for ip, data in bot_ips.items():
            uas = ", ".join(list(data["user_agents"])[:3])
            result += f"  🤖 {ip}: {data['count']} requests\n"
            result += f"     User-Agents: {uas}\n"
            top_endpoints = data["endpoints"].most_common(3)
            result += f"     Target endpoints: {', '.join(ep for ep, _ in top_endpoints)}\n\n"
    else:
        result += "  ✅ Không phát hiện bot traffic (dựa vào user-agent)\n"

    result += f"""
{'='*55}
          POPULAR ENDPOINTS
{'='*55}
"""
    for ep, count in endpoint_hits.most_common(10):
        bar = "█" * min(count, 30)
        result += f"  {ep:35s} | {count:4d} hits {bar}\n"

    result += f"""
{'='*55}
          KHUYẾN NGHỊ
{'='*55}
"""
    if suspicious_ips:
        result += "  🚨 Có IP đáng ngờ với tỷ lệ lỗi cao → Cân nhắc chặn hoặc rate-limit\n"
    if bot_ips:
        result += "  🤖 Phát hiện bot traffic → Triển khai bot management / CAPTCHA\n"
    if peak_minute[1] > avg_rpm * 3 and avg_rpm > 0:
        result += f"  📈 Peak traffic ({peak_minute[1]} rpm) cao gấp {round(peak_minute[1] / avg_rpm, 1)}x trung bình → Cân nhắc auto-scaling\n"
    if not suspicious_ips and not bot_ips:
        result += "  ✅ Traffic patterns bình thường - không cần hành động đặc biệt\n"

    return result.strip()


# ============================================================
# TOOL 8: Generate Report - Tạo báo cáo tổng hợp
# ============================================================

def generate_report(
    security_findings: Annotated[str, "Kết quả phân tích bảo mật"],
    health_findings: Annotated[str, "Kết quả phân tích sức khỏe hệ thống"],
    performance_findings: Annotated[str, "Kết quả phân tích hiệu suất và tương quan"]
) -> str:
    """Tổng hợp tất cả kết quả phân tích từ các agent thành một báo cáo
    markdown hoàn chỉnh và lưu ra file log_analysis_report.md.
    """

    def sanitize_summary_text(text: str) -> str:
        """Dọn placeholder và khoảng trắng thừa trước khi ghi report."""
        cleaned_lines = []
        seen_lines = set()
        for raw_line in (text or "").splitlines():
            line = raw_line.rstrip()
            normalized = line.strip().lower()
            if normalized in (
                "- không đủ dữ liệu: none",
                "- khong du du lieu: none",
                "không đủ dữ liệu: none",
                "khong du du lieu: none",
            ):
                continue
            if line.strip() in seen_lines and line.strip().startswith(("-", ">")):
                continue
            cleaned_lines.append(line)
            if line.strip():
                seen_lines.add(line.strip())

        sanitized = "\n".join(cleaned_lines)
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized).strip()
        return sanitized

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    security_findings = sanitize_summary_text(security_findings)
    health_findings = sanitize_summary_text(health_findings)
    performance_findings = sanitize_summary_text(performance_findings)

    report = f"""# 📋 BÁO CÁO PHÂN TÍCH LOG SERVER
**Thời gian tạo báo cáo:** {timestamp}
**Hệ thống:** Hệ thống Phân Tích Log Đa Tác Tử (Autogen Framework)

---

## 1. 🛡️ Phân Tích Bảo Mật

{security_findings}

---

## 2. 🏥 Phân Tích Sức Khỏe Hệ Thống

{health_findings}

---

## 3. 📈 Phân Tích Hiệu Suất

{performance_findings}

---

## 4. 📝 Tóm Tắt & Khuyến Nghị

> Báo cáo này được tạo tự động bởi hệ thống Multi-Agent sử dụng Autogen Framework.
> Các số liệu có thể bao gồm cả metrics tính từ log entries quan sát trực tiếp và metrics summary do hệ thống tự ghi trong log.
> Một số kết luận mang tính tương quan thời gian hoặc đánh giá heuristic; cần đối chiếu trực tiếp với log gốc khi ra quyết định vận hành hoặc bảo mật.

---
*Báo cáo được tạo bởi Hệ thống Phân Tích Log Đa Tác Tử*
"""

    report_path = os.path.abspath("log_analysis_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    return f"Báo cáo đã được tạo thành công và lưu tại: {report_path}"
