import re
from collections import defaultdict
from datetime import datetime

# ログファイルを読み込む
LOG_FILE = "network_log.txt"

def parse_log(filepath):
    """tcpdumpログをパースして構造化データに変換"""
    records = []
    pattern = r'(\d+:\d+:\d+\.\d+) IP ([\d]+\.[\d]+\.[\d]+\.[\d]+)\.(\d+) > ([\d]+\.[\d]+\.[\d]+\.[\d]+)\.(\d+):'
    
    with open(filepath, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                time, src_ip, src_port, dst_ip, dst_port = match.groups()
                records.append({
                    "time": time,
                    "src_ip": src_ip,
                    "src_port": int(src_port),
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port),
                    "raw": line.strip()
                })
    return records

def analyze(records):
    """基本的な集計・分析"""
    print(f"\n📊 総通信数: {len(records)} 件\n")

    # 外部IP集計
    external = defaultdict(int)
    for r in records:
        if not r["dst_ip"].startswith("192.168."):
            external[r["dst_ip"]] += 1

    print("🌐 外部接続先 TOP10:")
    for ip, count in sorted(external.items(), key=lambda x: -x[1])[:10]:
        print(f"  {ip:20s} {count:4d} 回")

    # ポート集計
    ports = defaultdict(int)
    for r in records:
        ports[r["dst_port"]] += 1

    print("\n🔌 よく使われるポート:")
    for port, count in sorted(ports.items(), key=lambda x: -x[1])[:5]:
        service = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 3389: "RDP"}.get(port, "不明")
        print(f"  ポート {port:5d} ({service:5s}): {count:4d} 回")

    # デバイス一覧
    devices = set()
    for r in records:
        if r["src_ip"].startswith("192.168."):
            devices.add(r["src_ip"])

    print(f"\n📱 検出されたデバイス: {len(devices)} 台")
    for d in sorted(devices):
        print(f"  {d}")

if __name__ == "__main__":
    print("🔍 ネットワークログ解析開始...")
    records = parse_log(LOG_FILE)
    analyze(records)
    print("\n✅ 完了")