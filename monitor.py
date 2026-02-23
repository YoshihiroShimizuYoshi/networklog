import sys
from datetime import datetime

from collector import collect, ensure_dir
from detector import run as detect

CONTAMINATION = 0.1


def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")


if __name__ == "__main__":
    ensure_dir()
    log("🚀 監視開始（Ctrl+C で停止）")

    while True:
        try:
            log("📡 キャプチャ開始...")
            filename = collect()

            log(f"🤖 異常検知開始: {filename}")
            detect(source=filename, contamination=CONTAMINATION)

        except KeyboardInterrupt:
            log("🛑 監視を停止しました")
            sys.exit(0)
