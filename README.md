# 🔍 Multi-Agent Server Log Analyzer

Hệ thống phân tích log server sử dụng Multi-Agent với LLMs và framework **Autogen (pyautogen)**.
Hỗ trợ đa định dạng: **Custom App Log, Nginx, Apache, Syslog** (tự động nhận diện).

## 📐 Kiến Trúc Hệ Thống

```
Admin (UserProxyAgent)
  │
  ▼
GroupChatManager ──────────────────────────────────────────┐
  │                                                        │
  ├── Log_Parser (Coder)                                   │
  │     Tools: parse_log_file, extract_error_entries        │
  │                                                        │
  ├── Security_Analyst                                     │
  │     Tools: detect_security_threats, scan_vulnerabilities│
  │                                                        │
  ├── System_Health_Analyst                                │
  │     Tool: analyze_system_health                        │
  │                                                        │
  ├── Performance_Expert                                   │
  │     Tool: analyze_performance                          │
  │                                                        │
  ├── Correlation_Analyst                                  │
  │     Tools: correlate_events, analyze_traffic_patterns   │
  │                                                        │
  └── Final_Reporter                                       │
        Tool: generate_report                              │
                                                           │
  ◄────────────────────────────────────────────────────────┘
```

## 🚀 Cài Đặt & Chạy

### 1. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### 2. Cấu hình API Key

Đặt biến môi trường cho LLM provider bạn muốn sử dụng:

**OpenAI:**
```bash
set OPENAI_API_KEY=sk-your-api-key-here
# Tùy chọn: set OPENAI_MODEL=gpt-4o-mini
```

**Google Gemini:**
```bash
set GOOGLE_API_KEY=your-api-key-here
# Tùy chọn: set GOOGLE_MODEL=gemini-2.0-flash
```

**DeepSeek:**
```bash
set DEEPSEEK_API_KEY=sk-your-api-key-here
# Tùy chọn: set DEEPSEEK_MODEL=deepseek-chat
```

### 3. Chạy chương trình

```bash
# Phân tích file log mẫu (tự động nhận diện format)
python main.py sample_logs/server.log          # Custom App format
python main.py sample_logs/nginx_access.log    # Nginx format
python main.py sample_logs/apache_access.log   # Apache format
python main.py sample_logs/syslog.log          # Syslog format
```

### 4. Kết quả

- Kết quả phân tích hiển thị trên terminal (conversation giữa các agent)
- Báo cáo tổng hợp được lưu tại: `log_analysis_report.md`

## 📁 Cấu Trúc Project

| File | Mô tả |
|------|--------|
| `main.py` | Entry point - khởi chạy hệ thống multi-agent |
| `agents.py` | Định nghĩa 7 agents và thiết lập GroupChat |
| `tools.py` | 9 custom tools cho phân tích log |
| `log_parser_utils.py` | Module phân tích đa định dạng log (unified parser) |
| `requirements.txt` | Dependencies |
| `sample_logs/server.log` | File log mẫu - Custom Application Log |
| `sample_logs/nginx_access.log` | File log mẫu - Nginx Access Log |
| `sample_logs/apache_access.log` | File log mẫu - Apache Combined Log |
| `sample_logs/syslog.log` | File log mẫu - Syslog (RFC 3164) |

## 🧰 Custom Tools

| Tool | Agent sử dụng | Chức năng |
|------|---------------|-----------|
| `parse_log_file` | Log_Parser | Phân tích tổng quan: log levels, IPs, endpoints |
| `extract_error_entries` | Log_Parser | Trích xuất ERROR/CRITICAL entries |
| `detect_security_threats` | Security_Analyst | OWASP Top 10: SQL Injection, XSS, brute-force, etc. |
| `scan_vulnerabilities` | Security_Analyst | Quét chuyên sâu: timeline, IP risk, APT detection |
| `analyze_system_health` | System_Health_Analyst | CPU, Memory, Disk, crashes, warnings |
| `analyze_performance` | Performance_Expert | Response time (p95/p99), throughput, slow requests |
| `correlate_events` | Correlation_Analyst | Error cascading, root cause analysis, resource→error |
| `analyze_traffic_patterns` | Correlation_Analyst | Bot detection, IP classification, traffic timeline |
| `generate_report` | Final_Reporter | Tổng hợp báo cáo markdown |

## 📋 Định Dạng Log Hỗ Trợ

| Format | Auto-detect | Mô tả |
|--------|:-----------:|--------|
| Custom Application Log | ✅ | `2026-03-13 08:00:01 INFO [WebServer] ...` |
| Nginx Access Log | ✅ | Combined log format with user-agent |
| Apache Combined Log | ✅ | Standard Apache combined log format |
| Syslog (RFC 3164) | ✅ | `Mar 13 08:00:01 hostname service[pid]: ...` |

## 👥 Thành Viên

- 22162018 - Hồ Tùng Lâm
- 22162007 - Ngô Minh Chung
- 23162109 - Lê Văn Anh Tuấn
