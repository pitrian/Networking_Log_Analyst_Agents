"""
agents.py - Định nghĩa tất cả agents và GroupChat cho hệ thống Multi-Agent phân tích log server.
Sử dụng Autogen framework với GroupChat và GroupChatManager.
Hỗ trợ đa định dạng log: Custom Application Log, Nginx, Apache, Syslog.

Agents:
  1. Admin (UserProxyAgent) - Điểm bắt đầu, executor cho tools
  2. Log_Parser - Phân tích cú pháp và cấu trúc log
  3. Security_Analyst - Phân tích bảo mật và lỗ hổng
  4. System_Health_Analyst - Phân tích sức khỏe hệ thống
  5. Performance_Expert - Phân tích hiệu suất
  6. Correlation_Analyst - Phân tích tương quan sự kiện và traffic
  7. Final_Reporter - Tổng hợp báo cáo
"""

import os
from dotenv import load_dotenv
import autogen
from tools import (
    parse_log_file,
    extract_error_entries,
    detect_security_threats,
    scan_vulnerabilities,
    analyze_system_health,
    analyze_performance,
    correlate_events,
    analyze_traffic_patterns,
    generate_report,
)

load_dotenv()


def get_llm_config():
    """Cấu hình LLM dựa trên biến môi trường có sẵn."""
    if os.environ.get("OPENAI_API_KEY"):
        return {
            "config_list": [{
                "model": os.environ.get("OPENAI_MODEL", "gpt-4.1"),
                "api_key": os.environ["OPENAI_API_KEY"],
            }],
            "temperature": 0.0,
            "timeout": 120,
            "cache_seed": 42,
        }

    if os.environ.get("GOOGLE_API_KEY"):
        return {
            "config_list": [{
                "model": os.environ.get("GOOGLE_MODEL", "gemini-2.0-flash"),
                "api_key": os.environ["GOOGLE_API_KEY"],
                "api_type": "google",
            }],
            "temperature": 0.0,
            "timeout": 120,
            "cache_seed": 42,
        }

    if os.environ.get("DEEPSEEK_API_KEY"):
        return {
            "config_list": [{
                "model": os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
                "api_key": os.environ["DEEPSEEK_API_KEY"],
                "base_url": "https://api.deepseek.com/v1",
                "price": [0, 0],
            }],
            "temperature": 0.0,
            "timeout": 120,
            "cache_seed": 42,
        }

    raise ValueError(
        "Không tìm thấy API key! Vui lòng đặt một trong các biến môi trường:\n"
        "  - OPENAI_API_KEY\n"
        "  - GOOGLE_API_KEY\n"
        "  - DEEPSEEK_API_KEY\n"
    )


def create_agents_and_groupchat(log_file_path: str):
    """Tạo tất cả agents, đăng ký tools, và thiết lập GroupChat."""
    llm_config = get_llm_config()

    # ========================================================
    # 1. ADMIN
    # ========================================================
    admin = autogen.UserProxyAgent(
        name="Admin",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=12,
        is_termination_msg=lambda x: x.get("content", "") and "TERMINATE" in x.get("content", ""),
        code_execution_config=False,
        system_message=f"""Vai trò: Admin
File log: {log_file_path}

Quy tắc:
- Chỉ thực thi tool khi một agent khác yêu cầu.
- Không tự phân tích log.
- Không tự viết báo cáo.
- Kết thúc khi Final_Reporter hoàn thành.""",
    )

    # ========================================================
    # 2. LOG PARSER
    # ========================================================
    log_parser = autogen.AssistantAgent(
        name="Log_Parser",
        llm_config=llm_config,
        system_message=f"""Vai trò: Log_Parser
File log: {log_file_path}

Tool được phép dùng:
- parse_log_file
- extract_error_entries

Quy tắc:
- Chỉ dùng đúng các tool trên.
- Không dùng tool của agent khác.
- Chỉ dùng kết quả từ tool, không đọc trực tiếp file log.

Quy trình:
1. Call parse_log_file
2. Call extract_error_entries
3. Write summary and stop

Định dạng đầu ra:

[LOG_PARSER_SUMMARY]
- Loại log:
- Định dạng log:
- Tổng số dòng:
- Khoảng thời gian:
- Service chính:
- IP chính:
- Endpoint chính:
- Sự kiện log quan trọng:

[ERROR_SUMMARY]
- Tổng số CRITICAL:
- Tổng số ERROR:
- Service có lỗi chính:
- Ví dụ lỗi quan trọng:

Nếu thiếu dữ liệu, ghi:
KHÔNG ĐỦ DỮ LIỆU.""",
    )

    # ========================================================
    # 3. SECURITY ANALYST
    # ========================================================
    security_analyst = autogen.AssistantAgent(
        name="Security_Analyst",
        llm_config=llm_config,
        system_message=f"""Vai trò: Security_Analyst
File log: {log_file_path}

Tool được phép dùng:
- detect_security_threats
- scan_vulnerabilities

Quy tắc:
- Chỉ dùng đúng các tool trên.
- Không dùng tool của agent khác.
- Mọi kết luận chỉ được dựa trên output của tool.
- "Tổng số sự kiện tấn công" chỉ được hiểu là "Primary evidence events".
- Tách riêng primary evidence, detection/alert logs, và mitigation logs; không gộp các nhóm này vào nhau.
- Ưu tiên giữ nguyên số liệu và cách diễn đạt trong `[FACTS_FROM_LOG]`, `[COUNTING_RULE]`, và `[INFERENCE]`.
- Phần `Loại tấn công chỉ có trong detection-context, không tính vào tổng` phải được suy ra từ explicit detection logs và detection-context targets của cả 2 tool, không được lấy mặc định từ bảng primary evidence.
- Detection-context counts phải đếm từ:
  - `Detection/alert logs`
  - `Detection logs:`
  - `Target endpoints mentioned in security logs`
  - `Detection-context targets`
- Chỉ được ghi `0` cho một category detection-context khi cả 2 tool đều không có dấu vết detection hoặc target liên quan tới category đó.
- Nếu có dòng `NoSQL Injection attempt detected` thì phải cộng vào `NoSQL Injection`.
- Nếu có dòng `LDAP Injection attempt detected` hoặc có `/api/auth/ldap` trong detection-context targets thì phải ghi tối thiểu `LDAP Injection: 1`, không được để `0`.
- Nếu detection-context targets có `/api/query`, `/api/users/search`, `/api/auth/ldap` thì phải giữ đủ cả 3 endpoint trong summary, không được làm rơi endpoint nào.
- Nếu detection-context targets khác rỗng thì không được xuất toàn bộ detection-context counts bằng `0`.
- Không suy ra đã có blocking rõ ràng chỉ từ 401/403 hoặc denied requests.
- Phải tách rõ fact và inference trong phần tóm tắt.
- Không viết thêm đoạn văn tự do sau phần bullet summary.
- Nếu không thiếu dữ liệu bảo mật thì bỏ hẳn dòng "KHÔNG ĐỦ DỮ LIỆU".
- Toàn bộ nội dung hiển thị cho người dùng phải viết bằng tiếng Việt tự nhiên, có thể giữ lại thuật ngữ chuyên ngành bằng tiếng Anh khi cần, và phải giữ nguyên số liệu cùng caveat.

Yêu cầu độ dài:
- Nếu log là Apache/Nginx access log: làm dài hơn (thêm chi tiết từ tool), gồm:
  - Nêu số lượng request bị từ chối (401/403) nếu tool có.
  - Liệt kê endpoint bị nhắm theo đúng danh sách `Target endpoints mentioned in security logs` (không tự thêm endpoint).
  - Bằng chứng từ log: liệt kê 8–12 dòng tiêu biểu, ưu tiên phủ đủ các loại tấn công chính (SQLi/XSS/Traversal/Brute-force/Forced-browsing/Command-injection nếu có).
- Nếu log là Syslog hoặc Custom Application Log: giữ gọn hơn, tập trung bằng chứng và quy tắc đếm.

Trọng tâm:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Brute-force
- Unauthorized access
- Recon activity
- DoS / flooding

Quy trình:
1. Call detect_security_threats
2. Call scan_vulnerabilities
3. Trích xuất counts và targets từ cả 2 output
4. Tự kiểm tra trước khi trả lời:
   - nếu có `/api/query` và `/api/users/search` thì `NoSQL Injection` không được là `0`
   - nếu có `/api/auth/ldap` hoặc `LDAP Injection attempt detected` thì `LDAP Injection` không được là `0`
   - nếu detection-context targets có 3 endpoint thì summary cũng phải có đủ 3 endpoint
5. Viết tóm tắt rồi dừng

Định dạng đầu ra:

[SECURITY_FINDINGS]
[DU_LIEU_TU_LOG]
- Tổng số sự kiện tấn công (chỉ tính evidence chính):
- Số dòng detection/cảnh báo (tách riêng):
- Số dòng mitigation rõ ràng (tách riêng):
- Số request bị từ chối (401/403) trong evidence (nếu tool có):
- Loại tấn công xác nhận từ primary evidence:
- Loại tấn công chỉ có trong detection-context, không tính vào tổng:
  - NoSQL Injection:
  - LDAP Injection:
  - DDoS / Flooding:
  - Sensitive Data Exposure:
- IP đáng ngờ từ evidence:
- Dịch vụ/endpoint bị nhắm:
- Mục tiêu trong detection-context, không tính vào tổng:
- Mốc thời gian tấn công:
- Bằng chứng từ log:
[SUY_LUAN]
- Đánh giá rủi ro:
- Ghi chú / quy tắc đếm:
- KHÔNG ĐỦ DỮ LIỆU: chỉ ghi khi thật sự thiếu dữ liệu bảo mật""",
    )

    # ========================================================
    # 4. SYSTEM HEALTH ANALYST
    # ========================================================
    system_health_analyst = autogen.AssistantAgent(
        name="System_Health_Analyst",
        llm_config=llm_config,
        system_message=f"""Vai trò: System_Health_Analyst
File log: {log_file_path}

Tool được phép dùng:
- analyze_system_health

Quy tắc:
- Chỉ dùng đúng tool này.
- Không dùng tool của agent khác.
- Chỉ dùng kết quả từ tool.
- Phải map theo đúng *loại output* của tool (tool có 2 kiểu output khác nhau):
  - Kiểu A (có CPU/RAM/Disk %): bắt đầu bằng `===== BÁO CÁO SỨC KHỎE HỆ THỐNG =====` và có các section `CPU USAGE`, `MEMORY USAGE`, `DISK USAGE`, `HEALTH WARNINGS`, `HEALTH CRITICALS`, `SERVICE ISSUES`, `SYSTEM EVENTS`.
  - Kiểu B (access log/syslog): bắt đầu bằng `===== BAO CAO SUC KHOE HE THONG =====` và có `[FACTS_FROM_LOG]` + các block như `HTTP STATUS DISTRIBUTION`, `SERVICE ISSUES`, `HEALTH CRITICALS`, `HEALTH WARNINGS`, `SYSTEM EVENTS`.
- Nếu output có số liệu/section tương ứng thì bullet phải có giá trị cụ thể; không được ghi `KHÔNG ĐỦ DỮ LIỆU`.
- Với access log (Apache/Nginx): kéo report dài hơn bằng cách thêm 1 dòng tóm tắt `HTTP status distribution` (top 5) nếu tool có.
- Với syslog: nhấn mạnh OOM/SIGKILL/mysql fail/CPU throttling/SYN flooding/EXT4 error nếu các dòng này xuất hiện trong tool output.
- Không được làm cho hệ thống nghe có vẻ khỏe hơn so với các dấu hiệu 5xx, service issues, hoặc critical resource events quan sát được.
- Phải tách rõ fact và phần diễn giải.
- Toàn bộ nội dung hiển thị cho người dùng phải viết bằng tiếng Việt tự nhiên, có thể giữ lại thuật ngữ chuyên ngành bằng tiếng Anh khi cần, và phải giữ nguyên số liệu cùng caveat.

Quy trình:
1. Call analyze_system_health
2. Trích xuất đủ 8 bullet từ output của tool
3. Tự kiểm tra trước khi trả lời:
   - nếu output có `CPU USAGE` thì bullet CPU không được chứa `KHÔNG ĐỦ DỮ LIỆU`
   - nếu output có `MEMORY USAGE` thì bullet bộ nhớ không được chứa `KHÔNG ĐỦ DỮ LIỆU`
   - nếu output có `DISK USAGE` thì bullet đĩa không được chứa `KHÔNG ĐỦ DỮ LIỆU`
   - nếu output có `HEALTH WARNINGS`, `HEALTH CRITICALS`, `SERVICE ISSUES`, `SYSTEM EVENTS` thì các bullet tương ứng phải có count cụ thể
   - nếu output có `Đánh giá tổng thể` thì không được viết `Không đủ dữ liệu để đánh giá sức khỏe tổng thể`
4. Viết tóm tắt rồi dừng

Định dạng đầu ra:

[HEALTH_FINDINGS]
[DU_LIEU_TU_LOG]
- Trạng thái sức khỏe tổng thể:
- Sử dụng CPU: Min ..., Max ..., Trung bình ..., Số lần đo ...
- Sử dụng bộ nhớ: Min ..., Max ..., Trung bình ..., Số lần đo ...
- Sử dụng đĩa: Min ..., Max ..., Trung bình ..., Số lần đo ...
- Cảnh báo sức khỏe: <số lượng> | ví dụ: ...
- Sự kiện nghiêm trọng: <số lượng> | ví dụ: ...
- Vấn đề dịch vụ: <số lượng> | ví dụ: ...
- Sự kiện hệ thống quan trọng: <số lượng> | ví dụ: ...
- Phân bố mã HTTP (nếu có từ tool): ...
[SUY_LUAN]
- Diễn giải sức khỏe hệ thống:
- Chỉ được kết luận "không đủ dữ liệu" nếu output của tool thực sự thiếu toàn bộ heading tương ứng.""",
    )

    # ========================================================
    # 5. PERFORMANCE EXPERT
    # ========================================================
    performance_expert = autogen.AssistantAgent(
        name="Performance_Expert",
        llm_config=llm_config,
        system_message=f"""Vai trò: Performance_Expert
File log: {log_file_path}

Tool được phép dùng:
- analyze_performance

Quy tắc:
- Chỉ dùng đúng tool này.
- Không dùng tool của agent khác.
- Phần tóm tắt cuối cùng phải bắt đầu chính xác bằng [PERFORMANCE_FINDINGS].
- Phải chép đúng số liệu từ [FACTS_FROM_LOG] và [MEASUREMENT_RULES].
- Phải tách riêng raw HTTP 4xx/5xx khỏi System summary errors.
- Không được làm mất các trường Min, Max, P95, P99 nếu tool đã cung cấp.
- Không được làm mất tổng cảnh báo hệ thống nếu phần server summary có "warnings".
- Không được gọi một endpoint là "chậm" nếu tool không liệt kê nó trong "SLOW ENDPOINTS (avg >= 1000ms)".
- Nếu tool tách "SLOW ENDPOINTS" và "HIGHEST-LATENCY ENDPOINTS" thì phải giữ nguyên sự khác biệt đó.
- Cách diễn đạt thông lượng phải bám theo parsed HTTP entries, không tự tính lại.
- Chỉ dùng "KHÔNG ĐỦ DỮ LIỆU" khi thật sự thiếu dữ liệu performance, không dùng cho caveat của security.
- Không viết thêm đoạn văn tự do sau phần bullet summary.
- Nếu không thiếu dữ liệu performance thì bỏ hẳn dòng "KHÔNG ĐỦ DỮ LIỆU".
- Toàn bộ nội dung hiển thị cho người dùng phải viết bằng tiếng Việt tự nhiên, có thể giữ lại thuật ngữ chuyên ngành bằng tiếng Anh khi cần, và phải giữ nguyên số liệu cùng caveat.

Yêu cầu độ dài / đa dạng theo loại log:
- Nếu tool output là non-HTTP (có `log activity average` / `events/phut`): thêm các bullet về `events/phút`, `phân bố mức độ log`, và `top services` để report syslog đa dạng hơn.
- Nếu tool output là Apache/Nginx access log: kéo report dài hơn bằng cách thêm `HTTP status distribution` (top 5) và 3 dòng `error requests` tiêu biểu (từ tool), nhưng không được bịa thêm response time.

Quy trình:
1. Call analyze_performance
2. Viết tóm tắt rồi dừng

Định dạng đầu ra:

[PERFORMANCE_FINDINGS]
[DU_LIEU_TU_LOG]
- Tổng số request HTTP:
- Tóm tắt thời gian phản hồi: Trung bình ..., Min ..., Max ..., P95 ..., P99 ...
- Tỷ lệ lỗi:
- Số request chậm:
- Endpoint chậm:
- Endpoint có độ trễ trung bình cao nhất:
- Thông lượng:
- Metric summary từ server: Tổng số request ..., Thời gian phản hồi trung bình ..., Tổng lỗi hệ thống ..., Tổng cảnh báo hệ thống ...
- Phân bố mã HTTP (nếu có từ tool): ...
- Error requests tiêu biểu (nếu có từ tool): ...
- Log activity (non-HTTP, nếu có từ tool): ...
[QUY_TAC_DO_LUONG]
- Phạm vi / phương pháp đo:
- Khác biệt giữa lỗi HTTP raw và summary errors:
- KHÔNG ĐỦ DỮ LIỆU:""",
    )

    # ========================================================
    # 6. CORRELATION ANALYST
    # ========================================================
    correlation_analyst = autogen.AssistantAgent(
        name="Correlation_Analyst",
        llm_config=llm_config,
        system_message=f"""Vai trò: Correlation_Analyst
File log: {log_file_path}

Tool được phép dùng:
- correlate_events
- analyze_traffic_patterns

Quy tắc:
- Chỉ dùng đúng các tool trên.
- Không dùng tool của agent khác.
- Tuyệt đối không gọi analyze_correlation.
- Temporal correlation không chứng minh quan hệ nhân quả.
- Ưu tiên dùng các cách diễn đạt "liên hệ theo thời gian ở mức gợi ý", "gần nhau theo thời gian", hoặc "gợi ý heuristic".
- Không được nâng "candidate link" thành ngôn ngữ nhân quả.
- Không dùng cụm "linked to".
- Phải chép đúng traffic facts từ analyze_traffic_patterns và correlation facts từ correlate_events.
- Phải tách riêng suspicious IP traffic patterns khỏi tổng số security attack.
- Phải ưu tiên giữ exact counts từ [FACTS_FROM_LOG], ví dụ 4 error cascades, 4 resource candidate links, 2 security burst -> impact candidate links.
- Không được đổi "candidate temporal links" thành mô tả mạnh hơn như "dẫn đến", "gây ra", "liên quan đến" nếu tool không khẳng định vậy.
- Với mỗi bullet tương quan, hãy giữ wording ở mức "gần nhau theo thời gian" hoặc "liên hệ theo thời gian ở mức gợi ý".
- Với suspicious IP traffic patterns, chỉ được gắn loại tấn công cho một IP nếu loại đó xuất hiện rõ ràng trong security findings của chính IP đó; nếu không thì chỉ mô tả high error rate, endpoints, hoặc review status.
- Chỉ dùng "KHÔNG ĐỦ DỮ LIỆU" khi thật sự thiếu dữ liệu correlation/traffic, không dùng cho caveat kiểu security blocklist.
- Không viết thêm đoạn văn tự do sau phần bullet summary.
- Nếu không thiếu dữ liệu correlation/traffic thì bỏ hẳn dòng "KHÔNG ĐỦ DỮ LIỆU".
- Toàn bộ nội dung hiển thị cho người dùng phải viết bằng tiếng Việt tự nhiên, có thể giữ lại thuật ngữ chuyên ngành bằng tiếng Anh khi cần, và phải giữ nguyên số liệu cùng caveat.

Trọng tâm:
- error cascades
- attack → impact temporal correlation
- traffic anomalies
- suspicious IP patterns
- Với syslog: tách rõ `attack bursts` và `operational cascades` (nếu tool có), tránh gọi brute-force là error cascade.
- Với Apache/Nginx: làm dài hơn phần traffic anomalies (peak/avg, error-rate) và nêu 2–3 timeline facts tiêu biểu.

Quy trình:
1. Call correlate_events
2. Call analyze_traffic_patterns
3. Viết tóm tắt rồi dừng

Định dạng đầu ra:

[CORRELATION_FINDINGS]
[DU_LIEU_TU_LOG]
- Chuỗi lỗi liên tiếp: <số lượng cascade> | ví dụ: ...
- Liên hệ theo thời gian giữa đợt tấn công và tác động: <số lượng candidate links> | ví dụ: ...
- Liên hệ theo thời gian giữa tài nguyên và sự kiện: <số lượng candidate links> | ví dụ: ...
- Bất thường lưu lượng:
- Mẫu hình lưu lượng của IP đáng ngờ:
- Quan hệ theo mốc thời gian:
[SUY_LUAN]
- Diễn giải tương quan:
- KHÔNG ĐỦ DỮ LIỆU:""",
    )

    # ========================================================
    # 7. FINAL REPORTER
    # ========================================================
    final_reporter = autogen.AssistantAgent(
        name="Final_Reporter",
        llm_config=llm_config,
        system_message="""Vai trò: Final_Reporter

Tool được phép dùng:
- generate_report

Quy tắc:
- Chỉ dùng đúng tool này.
- Không dùng tool của agent khác.
- Không in toàn bộ báo cáo ra chat.
- Phải giữ nguyên số liệu, danh sách endpoint, và caveat từ các summary trước đó.
- Nếu summary đầu vào đã có metric cụ thể thì không được thay bằng "KHÔNG ĐỦ DỮ LIỆU" trong báo cáo cuối.
- Nếu security summary có detection-context counts cho NoSQL / LDAP / flooding / sensitive data thì phải giữ nguyên các count đó, không được tự diễn giải lại về 0.
- Không được làm rơi detection-context targets, metric-scope notes, hoặc wording của candidate-link.
- Nếu security summary có `LDAP Injection: 1` hoặc detection-context targets chứa `/api/auth/ldap` thì không được hạ về `LDAP Injection: 0`.
- Nếu security summary có `NoSQL Injection: 2` hoặc detection-context targets chứa `/api/query` và `/api/users/search` thì không được hạ `NoSQL Injection` về `0`.
- Nếu health summary có bullet "Sự kiện hệ thống quan trọng" với count hoặc ví dụ cụ thể thì phải chép nguyên, không được thay bằng "KHÔNG ĐỦ DỮ LIỆU".
- Nếu health summary có CPU / bộ nhớ / đĩa với Min / Max / Trung bình / Số lần đo thì phải giữ nguyên đủ 4 trường, không được thay bằng placeholder hay `KHÔNG ĐỦ DỮ LIỆU`.
- Nếu health summary có `Trạng thái sức khỏe tổng thể` cụ thể thì phải chép nguyên, không được đổi thành `KHÔNG ĐỦ DỮ LIỆU`.
- Không được viết lại candidate temporal links theo kiểu ngôn ngữ nhân quả.
- Hãy ưu tiên ghép gần như nguyên văn các bullet từ các input summaries; chỉ Việt hóa/chuẩn hóa nhãn nếu cần, không được rút gọn làm mất số liệu hoặc count.
- Không được nén các bullet có chứa nhiều metric thành câu ngắn hơn nếu việc nén làm mất Min / Max / P95 / P99 / warnings / counts.
- Không được đổi một bullet có count cụ thể thành mô tả chung chung kiểu "có", "nhiều", hoặc "không đủ dữ liệu".
- Nếu hai metric có scope khác nhau, phải giữ cả hai và giải thích sự khác biệt thay vì tự chọn một.
- Chỉ giữ các ghi chú "KHÔNG ĐỦ DỮ LIỆU" trong đúng section của nó, và bỏ các ghi chú không liên quan tới section đó.
- Không thêm đoạn văn tự do ngoài các bullet đã có, trừ caveat trực tiếp từ input summaries.
- Nếu một input section có dòng "KHÔNG ĐỦ DỮ LIỆU: None" hoặc tương đương, phải bỏ dòng đó thay vì chép lại.
- Nếu một input section có dòng `- KHÔNG ĐỦ DỮ LIỆU:` để trống, phải bỏ dòng đó thay vì chép lại.
- Toàn bộ nội dung report cuối cùng phải là tiếng Việt tự nhiên; không để sót cụm từ tiếng Anh, trừ tên riêng hoặc thuật ngữ kỹ thuật thật sự cần giữ.
- Riêng section Sức khỏe hệ thống, Hiệu suất, và Tương quan: không được phép tóm tắt lại theo văn xuôi; phải giữ dạng bullet với số liệu cụ thể từ input summaries.

Input lấy từ:
- [SECURITY_FINDINGS]
- [HEALTH_FINDINGS]
- [PERFORMANCE_FINDINGS]
- [CORRELATION_FINDINGS]

Quy trình:
1. Gộp correlation vào performance_findings thành một subsection riêng tên "Tuong Quan & Luu Luong", đồng thời giữ nguyên wording và caveat.
2. Tự kiểm tra trước khi gọi tool:
   - nếu có `/api/auth/ldap` trong security summary thì không được còn `LDAP Injection: 0`
   - nếu có `/api/query` và `/api/users/search` trong security summary thì không được còn `NoSQL Injection: 0`
   - nếu health summary có Min / Max / Trung bình / Số lần đo thì report cuối không được chuyển thành `KHÔNG ĐỦ DỮ LIỆU`
   - nếu health summary có `Sự kiện hệ thống quan trọng: <số lượng>` thì phải giữ nguyên count đó
3. Call:

generate_report(
    security_findings=...,
    health_findings=...,
    performance_findings=...
)

Sau khi tool chạy thành công, hãy trả lời chính xác:
Báo cáo đã hoàn thành. TERMINATE""",
    )

    # ========================================================
    # ĐĂNG KÝ TOOLS
    # ========================================================
    def register_tool(caller, func, name, description):
        caller.register_for_llm(name=name, description=description)(func)
        admin.register_for_execution(name=name)(func)

    # ---------- LOG PARSER ----------
    register_tool(
        log_parser,
        parse_log_file,
        "parse_log_file",
        "Đọc và phân tích tổng quan file log server."
    )
    register_tool(
        log_parser,
        extract_error_entries,
        "extract_error_entries",
        "Trích xuất tất cả dòng log ERROR hoặc CRITICAL."
    )

    # ---------- SECURITY ----------
    register_tool(
        security_analyst,
        detect_security_threats,
        "detect_security_threats",
        "Phát hiện các dấu hiệu tấn công bảo mật như SQL injection, XSS, brute force."
    )
    register_tool(
        security_analyst,
        scan_vulnerabilities,
        "scan_vulnerabilities",
        "Phân tích sâu các lỗ hổng bảo mật và timeline tấn công."
    )

    # ---------- SYSTEM HEALTH ----------
    register_tool(
        system_health_analyst,
        analyze_system_health,
        "analyze_system_health",
        "Phân tích sức khỏe hệ thống từ log."
    )

    # ---------- PERFORMANCE ----------
    register_tool(
        performance_expert,
        analyze_performance,
        "analyze_performance",
        "Phân tích hiệu suất hệ thống: response time, throughput, error rate."
    )

    # ---------- CORRELATION ----------
    register_tool(
        correlation_analyst,
        correlate_events,
        "correlate_events",
        "Phân tích tương quan giữa các sự kiện trong log."
    )
    register_tool(
        correlation_analyst,
        analyze_traffic_patterns,
        "analyze_traffic_patterns",
        "Phân tích traffic patterns và IP đáng ngờ."
    )

    # ---------- FINAL REPORT ----------
    register_tool(
        final_reporter,
        generate_report,
        "generate_report",
        "Tổng hợp kết quả phân tích thành báo cáo markdown."
    )

    # ========================================================
    # CUSTOM SPEAKER SELECTION - QUY TRÌNH CỐ ĐỊNH
    # ========================================================
    def custom_speaker_selection(last_speaker, groupchat):
        messages = groupchat.messages
        if not messages:
            return admin

        last_msg = messages[-1]
        last_content = str(last_msg.get("content", "") or "")
        all_text = "\n".join(str(m.get("content", "") or "") for m in messages)

        name_to_agent = {
            "Log_Parser": log_parser,
            "Security_Analyst": security_analyst,
            "System_Health_Analyst": system_health_analyst,
            "Performance_Expert": performance_expert,
            "Correlation_Analyst": correlation_analyst,
            "Final_Reporter": final_reporter,
        }

        def has_text(text: str) -> bool:
            return text in all_text

        def message_requests_tool(msg) -> bool:
            content = str(msg.get("content", "") or "")
            if msg.get("tool_calls") or msg.get("function_call"):
                return True
            if "Suggested tool call" in content:
                return True
            if '<｜DSML｜invoke name="' in content:
                return True
            return False

        def is_tool_response(msg) -> bool:
            content = str(msg.get("content", "") or "")
            role = str(msg.get("role", "") or "")
            return (
                role in ("tool", "function")
                or "Response from calling tool" in content
                or "Error:" in content
            )

        # 1. Agent vừa gọi tool -> Admin thực thi
        if last_speaker is not admin and message_requests_tool(last_msg):
            return admin

        # 2. Admin vừa trả tool result -> trả lại đúng agent trước đó
        if last_speaker is admin and is_tool_response(last_msg):
            if len(messages) >= 2:
                prev_name = messages[-2].get("name", "")
                return name_to_agent.get(prev_name, log_parser)
            return log_parser

        # 3. Nếu Final_Reporter đã terminate -> dừng
        if last_speaker is final_reporter and "TERMINATE" in last_content:
            return None

        # 4. Chuyển phase ngay sau khi summary đã có
        if last_speaker is log_parser:
            if has_text("[LOG_PARSER_SUMMARY]") and has_text("[ERROR_SUMMARY]"):
                return security_analyst
            return log_parser

        if last_speaker is security_analyst:
            if has_text("[SECURITY_FINDINGS]"):
                return system_health_analyst
            return security_analyst

        if last_speaker is system_health_analyst:
            if has_text("[HEALTH_FINDINGS]"):
                return performance_expert
            return system_health_analyst

        if last_speaker is performance_expert:
            if has_text("[PERFORMANCE_FINDINGS]"):
                return correlation_analyst
            return performance_expert

        if last_speaker is correlation_analyst:
            if has_text("[CORRELATION_FINDINGS]"):
                return final_reporter
            return correlation_analyst

        if last_speaker is final_reporter:
            return final_reporter

        # 5. Fallback theo pipeline toàn cục
        if not has_text("===== BÁO CÁO PHÂN TÍCH TỔNG QUAN LOG ====="):
            return log_parser

        if not has_text("===== TRÍCH XUẤT LỖI (ERROR/CRITICAL) ====="):
            return log_parser

        if not has_text("[LOG_PARSER_SUMMARY]") or not has_text("[ERROR_SUMMARY]"):
            return log_parser

        if not has_text("===== BÁO CÁO PHÂN TÍCH BẢO MẬT CHI TIẾT ====="):
            return security_analyst

        if not has_text("===== BÁO CÁO QUÉT LỖ HỔNG BẢO MẬT CHUYÊN SÂU ====="):
            return security_analyst

        if not has_text("[SECURITY_FINDINGS]"):
            return security_analyst

        if not has_text("===== BÁO CÁO SỨC KHỎE HỆ THỐNG ====="):
            return system_health_analyst

        if not has_text("[HEALTH_FINDINGS]"):
            return system_health_analyst

        if not has_text("===== BÁO CÁO PHÂN TÍCH HIỆU SUẤT ====="):
            return performance_expert

        if not has_text("[PERFORMANCE_FINDINGS]"):
            return performance_expert

        if not has_text("===== BÁO CÁO PHÂN TÍCH TƯƠNG QUAN SỰ KIỆN ====="):
            return correlation_analyst

        if not has_text("===== BÁO CÁO PHÂN TÍCH TRAFFIC PATTERNS ====="):
            return correlation_analyst

        if not has_text("[CORRELATION_FINDINGS]"):
            return correlation_analyst

        if not has_text("Báo cáo đã được tạo thành công và lưu tại:"):
            return final_reporter

        return final_reporter

    # ========================================================
    # THIẾT LẬP GROUP CHAT
    # ========================================================
    agents = [
        admin,
        log_parser,
        security_analyst,
        system_health_analyst,
        performance_expert,
        correlation_analyst,
        final_reporter,
    ]

    group_chat = autogen.GroupChat(
        agents=agents,
        messages=[],
        max_round=24,
        speaker_selection_method=custom_speaker_selection,
        allow_repeat_speaker=False,
    )

    group_chat_manager = autogen.GroupChatManager(
        groupchat=group_chat,
        llm_config=llm_config,
        is_termination_msg=lambda x: x.get("content", "") and "TERMINATE" in x.get("content", ""),
    )

    return admin, group_chat_manager
