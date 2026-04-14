# Báo cáo chi tiết: Cách thức hoạt động của Tool và vai trò từng Agent

Tài liệu này mô tả cách hệ thống Multi-Agent trong project hoạt động: các tool (Python function) làm gì, từng agent có vai trò gì, và agent sử dụng tool theo cơ chế nào để tạo ra báo cáo `log_analysis_report.md`.

## 1. Tổng quan kiến trúc

Hệ thống dùng **Autogen (pyautogen)** theo mô hình **GroupChat**:

- `main.py`: entry point, nhận đường dẫn file log từ CLI và khởi chạy nhóm agent.
- `agents.py`: định nghĩa agent, đăng ký tool, và **điều phối lượt nói (custom speaker selection)** theo pipeline cố định.
- `tools.py`: toàn bộ **custom tools** (hàm phân tích log) được agent gọi.
- `log_parser_utils.py`: bộ **unified parser** chuyển các định dạng log khác nhau về một cấu trúc thống nhất `NormalizedLogEntry`.

Luồng tổng quát:

1. Người dùng chạy: `python main.py <path-to-log>`
2. `main.py` gọi `create_agents_and_groupchat(log_file_path)` trong `agents.py`
3. Nhóm agent bắt đầu hội thoại theo pipeline:
   - Log_Parser → Security_Analyst → System_Health_Analyst → Performance_Expert → Correlation_Analyst → Final_Reporter
4. Final_Reporter gọi tool `generate_report(...)` để ghi file `log_analysis_report.md`.

## 2. Cơ chế “agent gọi tool” trong Autogen

Trong `agents.py` có hàm đăng ký tool:

```py
def register_tool(caller, func, name, description):
    caller.register_for_llm(name=name, description=description)(func)
    admin.register_for_execution(name=name)(func)
```

Ý nghĩa:

- `caller.register_for_llm(...)`: cho phép **agent “nhìn thấy” tool** trong danh sách function có thể gọi (tool call).
- `admin.register_for_execution(...)`: **Admin** là agent duy nhất được đăng ký quyền **thực thi** tool (chạy Python function thật và trả kết quả).

Vì vậy, khi một agent chuyên môn muốn gọi tool:

1. Agent tạo “tool call” (function call) với `name` và tham số.
2. `custom_speaker_selection(...)` sẽ chuyển lượt sang **Admin** để chạy tool.
3. Admin trả kết quả tool về chat.
4. `custom_speaker_selection(...)` chuyển lượt lại đúng agent vừa gọi tool để agent diễn giải/viết summary.

## 3. Điều phối pipeline bằng `custom_speaker_selection`

Hệ thống không chọn speaker ngẫu nhiên mà dùng “pipeline cố định”. Logic chính:

- Nếu message hiện tại chứa `tool_calls`/`function_call` → chuyển ngay sang `Admin` để thực thi tool.
- Nếu `Admin` vừa trả tool result → chuyển lại agent trước đó (agent đã yêu cầu tool).
- Sau mỗi phase, khi phát hiện marker đã có trong hội thoại (ví dụ `[SECURITY_FINDINGS]`) thì chuyển sang agent kế tiếp.

Các marker quan trọng mà pipeline dựa vào:

- `[LOG_PARSER_SUMMARY]` và `[ERROR_SUMMARY]`
- `[SECURITY_FINDINGS]`
- `[HEALTH_FINDINGS]`
- `[PERFORMANCE_FINDINGS]`
- `[CORRELATION_FINDINGS]`
- `TERMINATE` (kết thúc)

## 4. Unified Parser: `log_parser_utils.py`

### 4.1. Cấu trúc chuẩn hóa `NormalizedLogEntry`

Parser chuyển mọi dòng log về cùng cấu trúc:

- `timestamp` (chuẩn `YYYY-MM-DD HH:MM:SS` khi có thể)
- `level` (`INFO`, `WARNING`, `ERROR`, `CRITICAL`, `DEBUG`)
- `service` (nguồn log: `nginx`, `apache`, `sshd`, `kernel`, `WebServer`…)
- `message` (nội dung)
- Trường HTTP (nếu có): `ip`, `method`, `endpoint`, `status_code`, `response_time`, `response_size`
- `raw_line` (dòng gốc)
- `log_format` (`custom`/`nginx`/`apache`/`syslog`/`auto`)

### 4.2. Auto-detect format

`detect_log_format(file_path)` đọc tối đa 20 dòng đầu và chấm điểm match theo regex:

- `CUSTOM_PATTERN`, `NGINX_PATTERN`, `APACHE_PATTERN`, `SYSLOG_PATTERN`
- format có điểm cao nhất sẽ được chọn; nếu tất cả 0 → `unknown`

### 4.3. Parse file về danh sách entry

`parse_log_to_entries(file_path)`:

- Chọn parser theo format đã detect (hoặc fallback “auto” thử tất cả parser).
- Mỗi dòng parse được thành `NormalizedLogEntry`, bỏ qua dòng trống.
- Trả về `(entries, log_format)`.

Ghi chú parser theo format:

- Nginx/Apache: `level` suy từ HTTP status (`>=500` → `ERROR`, `>=400` → `WARNING`, còn lại `INFO`).
- Syslog: không có năm, parser dùng **năm hiện tại** (`datetime.now().year`), `level` suy theo keyword trong message.
- Custom: nếu message có pattern HTTP (`METHOD path status ...ms ip`) sẽ tách ra trường HTTP; nếu không sẽ chỉ cố gắng tìm IP trong message.

## 5. Tool layer: `tools.py`

Toàn bộ tool trả về `str` (text report) để agent đọc và viết summary.

### 5.1. Helper & quy ước chung

Một số helper quan trọng:

- `TRUSTED_INTERNAL_PREFIXES = ("192.168.", "127.")`: quy ước IP internal/trusted cho lab.
- `is_trusted_internal_ip(ip)`: lọc internal IP khỏi danh sách “external/suspicious”.
- `is_http_request_entry(entry)`: entry có `status_code` và có `ip`.
- `get_minute_bucket(timestamp)`: lấy bucket theo phút (cắt chuỗi `YYYY-MM-DD HH:MM`).
- `normalize_endpoint_path(endpoint)`: bỏ query string, decode URL-encoding.
- `nearest_rank_percentile(values, percentile)`: tính percentile theo **nearest-rank** để minh bạch và dễ đối chiếu.

### 5.2. Quy tắc đếm security thống nhất: `collect_security_observations(entries)`

Đây là hàm lõi giúp các tool security/correlation/traffic dùng **cùng một rule**:

- Phân tách 3 nhóm:
  - **Primary evidence events**: dòng “raw evidence” (khớp pattern tấn công) và **không phải** detection/alert log hay mitigation log.
  - **Detection/alert logs**: log cảnh báo/phát hiện (ví dụ service `SecurityModule`, hoặc keyword “attempt detected”…).
  - **Mitigation logs**: log thể hiện hành động giảm thiểu rõ ràng (keyword “added to blocklist/watchlist”, “UFW BLOCK”…).
- Evidence được **dedup theo raw line** (`evidence_by_line`), mỗi dòng evidence chỉ tính 1 lần.
- Brute-force có xác nhận: nếu 1 IP có ít nhất 5 lần POST login bị 401/403 thì các line đó được cộng thêm category `brute_force`.
- Endpoints:
  - Lấy từ `entry.endpoint` nếu parser có.
  - Nếu thiếu, cố gắng trích từ raw line bằng regex HTTP.
  - Link “detection log” với endpoint: nếu detection log có IP, hệ thống dò context HTTP cùng IP trong cửa sổ ±5s để gắn endpoint tương ứng.
- Risk score:
  - Mỗi evidence event cộng theo **max weight** của các category match trong event đó.

Kết quả trả về gồm: `evidence_events`, `category_lines`, `detection_logs`, `mitigation_logs`, `suspicious_ips`, `blocked_ips`, `watchlist_ips`, `mentioned_endpoints`, `mentioned_endpoints_by_ip`, `risk_score`, `ip_activity`.

## 6. Danh sách tool và chức năng chi tiết

### Tool 1: `parse_log_file(file_path)`

Mục tiêu: thống kê tổng quan file log.

Thực hiện:

- Detect log type (theo filename + regex sample): `detect_log_type(...)` trả `nginx_access`/`apache_access`/`syslog`/`system`/`unknown`.
- Parse toàn file bằng `parse_log_to_entries(...)`.
- Thống kê:
  - tổng số dòng parse được
  - time range (min→max timestamp)
  - phân bố `level`, `service`, `method`, `endpoint`, `status_code`, top IP

Output là một khối text “BÁO CÁO PHÂN TÍCH TỔNG QUAN LOG”.

### Tool 2: `extract_error_entries(file_path)`

Mục tiêu: trích xuất tất cả dòng `ERROR`/`CRITICAL`.

Thực hiện:

- Parse entries.
- Lọc `entry.level in ("ERROR", "CRITICAL")`
- Gom nhóm theo `service`, đồng thời list riêng `criticals` và `errors`.

Output gồm:

- Tổng CRITICAL/ERROR
- Danh sách CRITICAL entries, ERROR entries
- “LỖI PHÂN THEO SERVICE” kèm ví dụ message

### Tool 3: `detect_security_threats(file_path)`

Mục tiêu: phát hiện dấu hiệu tấn công dựa trên bằng chứng.

Thực hiện:

- Parse entries.
- Gọi `collect_security_observations(entries)` để lấy:
  - `evidence_events` (primary evidence)
  - `detection_logs` (alert/detection)
  - `mitigation_logs` (blocklist/watchlist/UFW…)
  - `mentioned_endpoints`, `suspicious_ips`, `risk_score`, …
- Tính thêm `denied_requests` = số evidence event có `status_code` là 401/403.
- Suy ra `severity` theo `risk_score` (heuristic).

Output có cấu trúc rõ:

- `[FACTS_FROM_LOG]`: số lượng evidence/detection/mitigation, denied 401/403, số IP external, số endpoint bị nhắc đến…
- `[INFERENCE]`: severity, risk score, và caveat:
  - 401/403 chỉ là “bị từ chối”, **không tự động** đồng nghĩa có “explicit blocking” nếu log không ghi rõ.
  - Detection/mitigation **không cộng** vào total evidence.
- Liệt kê theo category (SQLi/XSS/Traversal/Brute-force/…)
- Trích detection logs và mitigation logs (cắt top N)
- Endpoints bị nhắc đến + IP đáng ngờ kèm số evidence liên quan (`ip_activity`)

### Tool 3b: `scan_vulnerabilities(file_path)`

Mục tiêu: phân tích sâu theo timeline và theo IP.

Thực hiện:

- Dùng lại output của `collect_security_observations`.
- Tạo `ip_activities`: thống kê per-IP:
  - `evidence_count`, `denied_count`, `attack_types` (Counter), `blocked`, `watchlist`
  - `target_accounts` (trích từ raw bằng regex `user/account ...`)
  - `target_endpoints` + `fact_lines`
- `detection_only_targets`: endpoint được nhắc trong detection-context nhưng IP đó **không có** evidence event (phân tách scope).
- Chấm điểm rủi ro IP bằng `assess_ip_risk(...)` (heuristic weight theo attack type và số lượng).

Output gồm:

- `[FACTS_FROM_LOG]` + `[COUNTING_RULE]` (nhấn mạnh rule đếm)
- Timeline evidence events (theo timestamp)
- Detection logs + mitigation logs
- Target endpoints
- “DETECTION-CONTEXT TARGETS (không tính vào evidence total)” (nếu có)
- Phân tích theo IP: mức nguy hiểm (heuristic), evidence count, trạng thái BLOCKED/WATCHLIST/DENIED…
- Khuyến nghị theo loại tấn công xuất hiện và danh sách “IP nguy cơ cao chưa thấy bị block rõ ràng trong log” (nếu có)

### Tool 4: `analyze_system_health(file_path)`

Mục tiêu: đánh giá sức khỏe hệ thống theo log, với nhánh xử lý theo format.

Nhánh A: Apache/Nginx access log (có HTTP entries)

- Tính `http_error_events`: các request `status_code >= 500` (được coi là “service issue signal”).
- `denied_count`: số 401/403.
- `health_score`:
  - `NGUY HIEM` nếu có >= 3 sự kiện 5xx
  - `CAN CHU Y` nếu có 5xx (nhưng ít)
  - `TOT` nếu không có 5xx
- Output có `[FACTS_FROM_LOG]` và `[INTERPRETATION]` nhấn mạnh:
  - Access log **không có CPU/RAM**, nên health là suy luận từ error signal.
  - 401/403 không chứng minh được “blocking mechanism” nếu không có mitigation log.
  - Có 5xx thì không nên kết luận “TỐT” tuyệt đối.

Nhánh B: Syslog

- Dựa trên keyword để phân loại:
  - `health_criticals`: OOM kill, SIGKILL, ext4-fs error, CPU throttling, SYN flooding warning…
  - `health_warnings`: warning liên quan auth/ssh, firewall, resource…
  - `service_issues`: main process exited, failed with result, syn flooding…
  - `system_events`: scheduled restart, started mysql…
- `health_score`: `NGUY HIEM` nếu có critical, `CAN CHU Y` nếu có warning/service issues.

Nhánh C: Log hệ thống/custom có metric tài nguyên

- Trích CPU/Mem/Disk theo regex (`CPU Usage:`, `Memory usage:`, `Disk usage:`).
- Tóm tắt min/max/avg + list reading theo timestamp.
- Gom `health_warnings`, `health_criticals`, `service_issues`, `system_events`.

### Tool 5: `analyze_performance(file_path)`

Mục tiêu: phân tích hiệu suất.

Nhánh non-HTTP (không có `status_code`)

- Metric phù hợp là **events/phút** (log activity volume), không dùng “requests/phút”.
- Thống kê:
  - events per minute (average/peak)
  - phân bố log level
  - services active

Nhánh HTTP

- Dựng:
  - `response_times` (từ `entry.response_time` nếu có)
  - `requests_per_minute`
  - `error_requests`: các request có 4xx/5xx
  - `slow_requests`: response_time > 1000ms
  - endpoint_performance để tính “slow endpoint”
- P95/P99 dùng `nearest_rank_percentile(...)` và ghi rõ trong `[MEASUREMENT_RULES]`.
- “Slow request” và “Slow endpoint” đều dùng threshold **1000ms**.
- Có phần “SERVER SUMMARY METRICS (nếu có trong log)” và có caveat:
  - Raw HTTP error (đếm từ entries) và “System summary - Errors” trong log có thể là **2 scope khác nhau**, không nên ép phải bằng nhau.

### Tool 6: `correlate_events(file_path)`

Mục tiêu: phân tích tương quan theo thời gian (temporal correlation), nhấn mạnh **correlation ≠ causation**.

Nhánh Syslog

- Gom “attack bursts” theo key `(primary_type, primary_ip)` với gap <= 15s.
- Gom “operational cascades” theo keyword (OOM, mysql exit, CPU throttled, SYN flooding…) với gap <= 20s.
- Tìm “burst → operational impact” bằng cách tìm operational event gần nhất sau burst (<= 90s).
- Output gồm các khối:
  - ATTACK BURSTS / GROUPS
  - OPERATIONAL CASCADES
  - ATTACK BURST → OPERATIONAL IMPACT (TEMPORAL) (kèm HINT chỉ là gợi ý theo thời gian)
  - MITIGATION LOGS

Nhánh khác (custom/nginx/apache)

- “Error cascades”: nhóm các `ERROR/CRITICAL` cách nhau <= 30s.
- “Resource → Error candidates”: nếu có CPU/Mem/Disk >= 80% hoặc keyword “connection pool exhausted”, “outofmemoryerror” thì tìm error gần nhất sau đó <= 120s.
- “Security burst → Impact candidates”: nhóm evidence theo IP với gap <= 30s và tìm impact gần nhất sau burst <= 120s.
- Output có `[FACTS_FROM_LOG]` đếm rõ số cascade/link, và các khối “RESOURCE → ERROR” / “ATTACK → IMPACT” dạng temporal.

### Tool 7: `analyze_traffic_patterns(file_path)`

Mục tiêu: mô tả traffic/log activity theo thời gian và theo IP.

Nhánh Syslog/non-HTTP

- Metric: **events/phút**
- IP summary: tag `SUSPICIOUS`/`BLOCKED`/`WATCHLIST` dựa trên `collect_security_observations`.

Nhánh HTTP

- Dựng thống kê per-IP (count, endpoints, status code, user-agents).
- Bot detection: heuristic dựa vào user-agent chứa signature (`sqlmap`, `nikto`, `curl/`, `python-requests/`, `bot`, `crawler`, …).
- Suspicious IP: external IP có `error_count/data["count"] > 0.5` với error là 4xx hoặc 5xx.
- Output gồm:
  - traffic timeline (requests/phút average/peak)
  - IP classification (internal/external + nhãn REVIEW/BOT/OK)
  - bot detection
  - popular endpoints
  - khuyến nghị

### Tool 8: `generate_report(security_findings, health_findings, performance_findings)`

Mục tiêu: tổng hợp và ghi báo cáo Markdown cuối cùng.

Thực hiện:

- “Sanitize” các dòng placeholder kiểu `KHÔNG ĐỦ DỮ LIỆU: None`, đồng thời hạn chế duplicate bullet.
- Ghép 3 khối findings vào template Markdown.
- Ghi file `log_analysis_report.md` với encoding UTF-8 và trả về đường dẫn tuyệt đối.

## 7. Vai trò từng Agent và cách dùng tool

### 7.1. Admin (UserProxyAgent)

- Không tự phân tích log, không tự viết report.
- Vai trò: “executor” cho tool.
- Khi agent khác gọi tool, Admin thực thi và trả kết quả.

### 7.2. Log_Parser

Tool được phép:

- `parse_log_file`
- `extract_error_entries`

Cách làm:

1. Gọi `parse_log_file` để lấy tổng quan.
2. Gọi `extract_error_entries` để lấy lỗi quan trọng.
3. Viết `[LOG_PARSER_SUMMARY]` và `[ERROR_SUMMARY]` theo format quy định.

### 7.3. Security_Analyst

Tool được phép:

- `detect_security_threats`
- `scan_vulnerabilities`

Cách làm:

1. Gọi 2 tool để lấy bằng chứng (facts) và phân tích sâu.
2. Tách rõ:
   - **fact** (dòng log/counters từ tool)
   - **inference** (severity/heuristic)
3. Report theo `[SECURITY_FINDINGS]`, giữ đúng counting rule:
   - không trộn `detection_logs`, `mitigation_logs` vào “primary evidence events”.

### 7.4. System_Health_Analyst

Tool được phép:

- `analyze_system_health`

Cách làm:

- Gọi tool và viết `[HEALTH_FINDINGS]`.
- Với access log: phải ghi caveat “không có CPU/RAM metrics”.
- Với syslog: phải ghi đủ critical/warning như OOM, SIGKILL, throttling… nếu tool có.

### 7.5. Performance_Expert

Tool được phép:

- `analyze_performance`

Cách làm:

- Gọi tool và viết `[PERFORMANCE_FINDINGS]`.
- Dùng đúng thuật ngữ:
  - syslog/non-HTTP: events/phút
  - HTTP: requests/phút, response time, error rate
- Nêu rõ “measurement rules”, đặc biệt percentile nearest-rank và threshold 1000ms.

### 7.6. Correlation_Analyst

Tool được phép:

- `correlate_events`
- `analyze_traffic_patterns`

Cách làm:

- Gọi cả 2 tool, rồi viết `[CORRELATION_FINDINGS]`.
- Tất cả liên kết chỉ ở mức “temporal correlation / candidate link”, không khẳng định nhân quả.
- Phân tách traffic facts và security facts, không suy diễn quá dữ liệu.

### 7.7. Final_Reporter

Tool được phép:

- `generate_report`

Cách làm:

1. Nhận các findings từ các agent trước.
2. Gọi:
   ```py
   generate_report(
     security_findings=...,
     health_findings=...,
     performance_findings=...,
   )
   ```
3. Trả “Báo cáo đã hoàn thành. TERMINATE” để kết thúc phiên.

## 8. Ghi chú về độ chính xác và giới hạn

- Access log (Apache/Nginx) không có CPU/RAM, mọi kết luận “sức khỏe hệ thống” chỉ dựa trên **HTTP error signals**.
- 401/403 cho thấy request bị từ chối, nhưng “explicit blocking” chỉ được ghi nhận khi có **mitigation log** (blocklist/watchlist/UFW…).
- Các mục tương quan luôn là “temporal” (gần nhau theo thời gian), không kết luận quan hệ nhân quả.
- `TRUSTED_INTERNAL_PREFIXES` là giả định theo lab; nếu môi trường dùng `10.*` hoặc `172.16-31.*` làm internal thì cần cập nhật.

