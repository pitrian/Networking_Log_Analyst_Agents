"""
log_parser_utils.py - Module phân tích đa định dạng log.
Hỗ trợ tự động nhận diện và parse 4 loại log:
  1. Custom Application Log
  2. Nginx Access Log  
  3. Apache Combined Log
  4. Syslog
  
Chuẩn hóa tất cả về cùng một cấu trúc NormalizedLogEntry.
"""

import re
import os
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from collections import Counter


@dataclass
class NormalizedLogEntry:
    """Cấu trúc log đã chuẩn hóa - chung cho tất cả formats."""
    timestamp: str           # ISO-like: "2026-03-13 08:00:01"
    level: str               # INFO, WARNING, ERROR, CRITICAL, DEBUG
    service: str             # Tên service/source (WebServer, nginx, apache, sshd, ...)
    message: str             # Nội dung log gốc
    ip: Optional[str] = None # IP address nếu có
    method: Optional[str] = None  # HTTP method (GET, POST, ...)
    endpoint: Optional[str] = None  # URL/path
    status_code: Optional[int] = None  # HTTP status code
    response_time: Optional[int] = None  # Response time (ms) nếu có
    response_size: Optional[int] = None  # Response size (bytes) nếu có
    raw_line: str = ""       # Dòng log gốc
    log_format: str = ""     # Format nguồn: custom/nginx/apache/syslog


# ============================================================
# FORMAT DETECTION
# ============================================================

# Regex patterns cho từng format
NGINX_PATTERN = re.compile(
    r'^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+'
    r'"(\w+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)'
    r'\s+"([^"]*)"\s+"([^"]*)"$'
)

APACHE_PATTERN = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+'
    r'"(\w+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+|-)$'
)

SYSLOG_PATTERN = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)'
)

CUSTOM_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(INFO|WARNING|ERROR|CRITICAL|DEBUG)\s+'
    r'\[(\w+)\]\s+(.*)'
)

HTTP_IN_CUSTOM = re.compile(
    r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(\d{3})\s+(\d+)ms\s+([\d.]+)'
)


def detect_log_format(file_path: str) -> str:
    """Tự động nhận diện định dạng file log.
    
    Returns:
        'nginx', 'apache', 'syslog', 'custom', hoặc 'unknown'
    """
    if not os.path.exists(file_path):
        return 'unknown'
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        sample_lines = []
        for i, line in enumerate(f):
            line = line.strip()
            if line:
                sample_lines.append(line)
            if len(sample_lines) >= 20:
                break
    
    if not sample_lines:
        return 'unknown'
   
#def detect_log_format(file_path: str, sample_size: int = 20) -> str:
    """
    Tự động nhận diện định dạng file log bằng cách đọc một số dòng mẫu.
    Args:
        file_path (str): Đường dẫn tới file log.
        sample_size (int): Số dòng mẫu để đọc. Mặc định là 20.
    Returns:
        'nginx', 'apache', 'syslog', 'custom', hoặc 'unknown'
    """
    if not os.path.exists(file_path):
        return 'unknown'
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        sample_lines = []
        for i, line in enumerate(f):
            line = line.strip()
            if line:
                sample_lines.append(line)
            if len(sample_lines) >= sample_size:
                break
    if not sample_lines:
        return 'unknown'
    # Phân tích mẫu ở đây...
    return detected_format
#Đừng quên cập nhật nơi nào đang gọi hàm cũ (như trong Log_Parser) thành:
#detected_format = detect_log_format(file_path, sample_size=50)
#Nhưng nếu gọi như trước:
#detected_format = detect_log_format(file_path)
#→ Vẫn hoạt động như cũ (sample_size=20 theo mặc định)##




    # Đếm số dòng match với từng format
    scores = {'nginx': 0, 'apache': 0, 'syslog': 0, 'custom': 0}
    
    for line in sample_lines:
        if CUSTOM_PATTERN.match(line):
            scores['custom'] += 1
        if NGINX_PATTERN.match(line):
            scores['nginx'] += 1
        if APACHE_PATTERN.match(line):
            scores['apache'] += 1
        if SYSLOG_PATTERN.match(line):
            scores['syslog'] += 1
    
    # Format có score cao nhất
    best_format = max(scores, key=scores.get)
    if scores[best_format] == 0:
        return 'unknown'
    
    return best_format


# ============================================================
# PARSERS
# ============================================================

def _parse_nginx_line(line: str) -> Optional[NormalizedLogEntry]:
    """Parse một dòng Nginx access log."""
    match = NGINX_PATTERN.match(line)
    if not match:
        return None
    
    groups = match.groups()
    ip = groups[0]
    remote_user = groups[1]
    time_str = groups[2]        # 13/Mar/2026:08:00:01 +0700
    method = groups[3]
    endpoint = groups[4]
    status_code = int(groups[5])
    body_bytes = int(groups[6])
    referer = groups[7] if len(groups) > 7 else '-'
    user_agent = groups[8] if len(groups) > 8 else '-'
    
    # Chuyển đổi timestamp
    try:
        dt = datetime.strptime(time_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, IndexError):
        timestamp = time_str
    
    # Xác định log level dựa trên status code
    if status_code >= 500:
        level = 'ERROR'
    elif status_code >= 400:
        level = 'WARNING'
    else:
        level = 'INFO'
    
    message = f'{method} {endpoint} {status_code} {body_bytes}bytes {ip}'
    if referer and referer != '-':
        message += f' referer="{referer}"'
    if user_agent and user_agent != '-':
        message += f' ua="{user_agent}"'
    
    return NormalizedLogEntry(
        timestamp=timestamp,
        level=level,
        service='nginx',
        message=message,
        ip=ip,
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        response_size=body_bytes,
        raw_line=line,
        log_format='nginx',
    )


def _parse_apache_line(line: str) -> Optional[NormalizedLogEntry]:
    """Parse một dòng Apache Combined log."""
    match = APACHE_PATTERN.match(line)
    if not match:
        return None
    
    ip, ident, user, time_str, method, endpoint, status_str, size_str = match.groups()
    status_code = int(status_str)
    body_bytes = int(size_str) if size_str != '-' else 0
    
    # Chuyển đổi timestamp
    try:
        dt = datetime.strptime(time_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, IndexError):
        timestamp = time_str
    
    if status_code >= 500:
        level = 'ERROR'
    elif status_code >= 400:
        level = 'WARNING'
    else:
        level = 'INFO'
    
    message = f'{method} {endpoint} {status_code} {body_bytes}bytes {ip}'
    if user != '-':
        message += f' user={user}'
    
    return NormalizedLogEntry(
        timestamp=timestamp,
        level=level,
        service='apache',
        message=message,
        ip=ip,
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        response_size=body_bytes,
        raw_line=line,
        log_format='apache',
    )


def _parse_syslog_line(line: str) -> Optional[NormalizedLogEntry]:
    """Parse một dòng Syslog."""
    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None
    
    time_str, hostname, service_raw, pid, message = match.groups()
    service = service_raw.rstrip(':')
    
    # Chuyển đổi timestamp (syslog không có năm, dùng năm hiện tại)
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {time_str}", '%Y %b %d %H:%M:%S')
        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        timestamp = time_str
    
    # Xác định log level dựa trên nội dung
    level = 'INFO'
    msg_lower = message.lower()
    if any(kw in msg_lower for kw in ['error', 'fail', 'fatal', 'critical', 'emergency', 'panic']):
        level = 'ERROR'
    elif any(kw in msg_lower for kw in ['crit', 'alert']):
        level = 'CRITICAL'
    elif any(kw in msg_lower for kw in ['warn', 'invalid', 'denied', 'refused', 'timeout', 'blocked']):
        level = 'WARNING'
    elif any(kw in msg_lower for kw in ['debug']):
        level = 'DEBUG'
    
    # Trích xuất IP nếu có
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
    ip = ip_match.group(1) if ip_match else None
    
    return NormalizedLogEntry(
        timestamp=timestamp,
        level=level,
        service=service,
        message=message,
        ip=ip,
        raw_line=line,
        log_format='syslog',
    )


def _parse_custom_line(line: str) -> Optional[NormalizedLogEntry]:
    """Parse một dòng Custom Application log."""
    match = CUSTOM_PATTERN.match(line)
    if not match:
        return None
    
    timestamp, level, service, message = match.groups()
    
    # Trích xuất thông tin HTTP nếu có
    ip = None
    method = None
    endpoint = None
    status_code = None
    response_time = None
    
    http_match = HTTP_IN_CUSTOM.search(message)
    if http_match:
        method = http_match.group(1)
        endpoint = http_match.group(2)
        status_code = int(http_match.group(3))
        response_time = int(http_match.group(4))
        ip = http_match.group(5)
    else:
        # Tìm IP trong message
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
        if ip_match:
            ip = ip_match.group(1)
    
    return NormalizedLogEntry(
        timestamp=timestamp,
        level=level,
        service=service,
        message=message,
        ip=ip,
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        response_time=response_time,
        raw_line=line,
        log_format='custom',
    )


# ============================================================
# MAIN PARSER
# ============================================================

def parse_log_to_entries(file_path: str) -> tuple:
    """Parse file log thành danh sách NormalizedLogEntry.
    Tự động nhận diện format.
    
    Returns:
        Tuple (entries: List[NormalizedLogEntry], format_name: str)
    """
    if not os.path.exists(file_path):
        return [], 'unknown'
    
    log_format = detect_log_format(file_path)
    
    parser_map = {
        'nginx': _parse_nginx_line,
        'apache': _parse_apache_line,
        'syslog': _parse_syslog_line,
        'custom': _parse_custom_line,
    }
    
    parser = parser_map.get(log_format)
    if not parser:
        # Fallback: thử tất cả parsers
        parser = _try_all_parsers
        log_format = 'auto'
    
    entries = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = parser(line)
            if entry:
                entries.append(entry)
    
    return entries, log_format


def _try_all_parsers(line: str) -> Optional[NormalizedLogEntry]:
    """Fallback: thử tất cả parsers cho một dòng."""
    for parser in [_parse_custom_line, _parse_nginx_line, _parse_apache_line, _parse_syslog_line]:
        result = parser(line)
        if result:
            return result
    return None


# ============================================================
# FORMAT INFO HELPER
# ============================================================

FORMAT_NAMES = {
    'nginx': 'Nginx Access Log',
    'apache': 'Apache Combined Log',
    'syslog': 'Syslog (RFC 3164)',
    'custom': 'Custom Application Log',
    'unknown': 'Unknown Format',
    'auto': 'Auto-detected (Mixed)',
}

def get_format_display_name(fmt: str) -> str:
    """Trả về tên hiển thị cho format."""
    return FORMAT_NAMES.get(fmt, fmt)
