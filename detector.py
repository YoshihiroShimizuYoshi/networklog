import os
import sys
import argparse
import subprocess
from collections import defaultdict
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.dirname(__file__))
from analyzer import parse_log, parse_logs_dir

LOG_DIR = "logs"
ALERT_LOG = "alerts.log"
STANDARD_PORTS = {80, 443, 53, 22, 123, 8080, 8443, 25, 587, 110, 143}


def extract_features(records, window_seconds=60):
    """レコードから特徴量を抽出（1分ごとの時間窓）"""
    windows = defaultdict(list)
    for r in records:
        parts = r["time"].split(":")
        h, m = int(parts[0]), int(parts[1])
        s = float(parts[2])
        bucket = h * 3600 + m * 60 + int(s / window_seconds) * window_seconds
        windows[bucket].append(r)

    features, buckets = [], []
    for bucket, recs in sorted(windows.items()):
        pkt_count = len(recs)
        unique_src = len(set(r["src_ip"] for r in recs))
        unique_dst = len(set(r["dst_ip"] for r in recs))
        unique_ports = len(set(r["dst_port"] for r in recs))
        suspicious = sum(1 for r in recs if r["dst_port"] not in STANDARD_PORTS)
        suspicious_ratio = suspicious / pkt_count if pkt_count > 0 else 0

        features.append([pkt_count, unique_src, unique_dst, unique_ports, suspicious_ratio])
        buckets.append(bucket)

    return np.array(features), buckets


def detect_anomalies(features, contamination=0.1):
    """Isolation Forestで異常スコアとラベルを返す"""
    model = IsolationForest(contamination=contamination, random_state=42)
    labels = model.fit_predict(features)
    scores = model.decision_function(features)
    return labels, scores


def send_alert(message):
    """ターミナル出力 + macOS通知 + ログ記録"""
    print(f"\n⚠️  【異常検知】 {message}")

    try:
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{message}" with title "ネットワーク異常検知" sound name "Ping"'],
            check=False, capture_output=True
        )
    except Exception:
        pass

    with open(ALERT_LOG, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")


def run(source="dir", contamination=0.1):
    """解析・異常検知を実行。異常リストとベースラインを返す"""
    print("🔍 ログ読み込み中...")
    records = parse_logs_dir(LOG_DIR) if source == "dir" else parse_log(source)

    if not records:
        print("⚠️  解析できるレコードがありません")
        return {"anomalies": [], "baseline": {}}

    print(f"📊 {len(records)} 件のレコードを読み込みました")
    print("🤖 特徴量抽出中...")
    features, buckets = extract_features(records)

    if len(features) < 2:
        print("⚠️  データが少なすぎます（最低2つの時間窓が必要）")
        return {"anomalies": [], "baseline": {}}

    print(f"🧠 Isolation Forestで異常検知中... ({len(features)} 時間窓, contamination={contamination})")
    labels, scores = detect_anomalies(features, contamination)

    anomaly_count = sum(1 for l in labels if l == -1)
    print(f"\n📈 結果: {anomaly_count}/{len(features)} 時間窓で異常を検出\n")

    # 正常時間窓の平均をベースラインとして計算
    normal_features = features[labels == 1]
    baseline = {
        "avg_pkt":   float(normal_features[:, 0].mean()) if len(normal_features) else 0,
        "avg_ports": float(normal_features[:, 3].mean()) if len(normal_features) else 0,
        "avg_susp":  float(normal_features[:, 4].mean()) if len(normal_features) else 0,
    }

    anomalies = []
    for i, (label, score) in enumerate(zip(labels, scores)):
        if label == -1:
            bucket = buckets[i]
            h = bucket // 3600
            m = (bucket % 3600) // 60
            time_str = f"{h:02d}:{m:02d}"
            pkt, src, dst, ports, susp = features[i]
            msg = (f"{time_str} - パケット数:{int(pkt)}, "
                   f"送信元IP:{int(src)}, 宛先IP:{int(dst)}, "
                   f"ポート種類:{int(ports)}, 不審率:{susp:.1%} (score:{score:.3f})")
            send_alert(msg)
            anomalies.append({
                "time": time_str, "pkt": int(pkt), "src": int(src),
                "dst": int(dst), "ports": int(ports),
                "susp": float(susp), "score": float(score)
            })

    if anomaly_count == 0:
        print("  ✅ 異常は検出されませんでした")

    return {"anomalies": anomalies, "baseline": baseline}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ネットワーク異常検知")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--file", help="解析するファイルパス（省略時はlogsフォルダ全体）")
    parser.add_argument("--contamination", type=float, default=0.1,
                        help="異常とみなす割合 0.0〜0.5（デフォルト: 0.1）")
    args = parser.parse_args()

    source = args.file if args.file else "dir"
    result = run(source=source, contamination=args.contamination)

    if result and result["anomalies"]:
        from llm_analyzer import analyze as llm_analyze
        from es_client import index_alert, index_analysis
        analysis_text = llm_analyze(result["anomalies"], result["baseline"])
        for anomaly in result["anomalies"]:
            index_alert(anomaly)
        if analysis_text:
            index_analysis(analysis_text, result["anomalies"])

    print("\n✅ 完了")
