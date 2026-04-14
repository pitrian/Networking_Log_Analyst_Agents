"""
main.py - Entry point cho hệ thống Multi-Agent phân tích log server.
Sử dụng Autogen framework với GroupChat.
Hỗ trợ đa định dạng: Custom, Nginx, Apache, Syslog (tự động nhận diện).

Cách sử dụng:
    python main.py <đường_dẫn_file_log>
    python main.py sample_logs/server.log          # Custom format
    python main.py sample_logs/nginx_access.log    # Nginx format
    python main.py sample_logs/apache_access.log   # Apache format
    python main.py sample_logs/syslog.log          # Syslog format
"""

import sys
import os
import logging

# Ẩn warning của AutoGen về API key format
logging.getLogger("autogen.oai.client").setLevel(logging.ERROR)

# Nếu vẫn còn log lặp từ logger cha, dùng thêm:
logging.getLogger("autogen").setLevel(logging.ERROR)
from agents import create_agents_and_groupchat


def print_banner():
    """In banner chào mừng."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║        🔍 MULTI-AGENT SERVER LOG ANALYZER 🔍                ║
║        Powered by Autogen Framework & LLMs                   ║
║                                                              ║
║  Agents:                                                     ║
║    👤 Admin          - Quản trị viên                         ║
║    🔧 Log_Parser     - Phân tích cấu trúc log               ║
║    🛡️  Security      - Phân tích bảo mật                     ║
║    🏥 Health         - Phân tích sức khỏe hệ thống           ║
║    📈 Performance    - Phân tích hiệu suất                   ║
║    🔗 Correlation    - Phân tích tương quan & traffic         ║
║    📝 Reporter       - Tổng hợp báo cáo                      ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    """Hàm chính - khởi chạy hệ thống multi-agent."""

    print_banner()

    if len(sys.argv) < 2:
        print("❌ Thiếu đường dẫn file log!")
        print("📖 Cách sử dụng: python main.py <đường_dẫn_file_log>")
        print("📖 Ví dụ:        python main.py sample_logs/server.log")
        sys.exit(1)

    log_file_path = sys.argv[1]

    if not os.path.exists(log_file_path):
        print(f"❌ File không tồn tại: {log_file_path}")
        sys.exit(1)

    log_file_path = os.path.abspath(log_file_path)
    print(f"📂 File log: {log_file_path}")
    print(f"📊 Kích thước: {os.path.getsize(log_file_path):,} bytes")

    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for _ in f)
        print(f"📝 Số dòng: {line_count:,}")
    except Exception as e:
        print(f"⚠️ Không đếm được số dòng log: {e}")

    api_found = False
    for key_name in ["OPENAI_API_KEY", "GOOGLE_API_KEY", "DEEPSEEK_API_KEY"]:
        if os.environ.get(key_name):
            provider = key_name.replace("_API_KEY", "").replace("_", " ")
            print(f"🔑 API Provider: {provider}")
            api_found = True
            break

    if not api_found:
        print("\n⚠️  Cảnh báo: Không tìm thấy API key trong biến môi trường.")
        print("Nếu bạn dùng file .env, hãy chắc rằng python-dotenv đã được cài.")
        print("Ví dụ file .env:")
        print("  OPENAI_API_KEY=sk-...")
        print("  hoặc DEEPSEEK_API_KEY=sk-...")
        print("-" * 60)

    print("\n" + "=" * 60)
    print("🚀 Khởi động hệ thống Multi-Agent...")
    print("=" * 60 + "\n")

    admin, group_chat_manager = create_agents_and_groupchat(log_file_path)

    initial_message = f"""
Hãy phân tích file log sau và tạo báo cáo cuối cùng:
{log_file_path}
"""

    try:
        admin.initiate_chat(
            group_chat_manager,
            message=initial_message,
        )
    except Exception as e:
        print(f"\n❌ Lỗi khi chạy multi-agent: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ Phân tích hoàn tất!")
    print("📄 Kiểm tra file báo cáo: log_analysis_report.md")
    print("=" * 60)


if __name__ == "__main__":
    main()