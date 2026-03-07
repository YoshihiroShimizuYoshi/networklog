import sys
from datetime import datetime

from collector import collect, ensure_dir
from detector import run as detect
from llm_analyzer import analyze as llm_analyze
from es_client import index_alert, index_analysis

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
            result = detect(source=filename, contamination=CONTAMINATION)

            if result and result["anomalies"]:
                log("💬 Claude による分析中...")
                analysis_text = llm_analyze(result["anomalies"], result["baseline"])

                log("📥 Elasticsearch に書き込み中...")
                for anomaly in result["anomalies"]:
                    index_alert(anomaly)
                if analysis_text:
                    index_analysis(analysis_text, result["anomalies"])

        except KeyboardInterrupt:
            log("🛑 監視を停止しました")
            sys.exit(0)
