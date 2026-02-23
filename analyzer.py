import re
import os
import glob
import argparse
from collections import defaultdict

LOG_FILE = "network_log.txt"
LOG_DIR = "logs"

# IPv4: "HH:MM:SS.ms IP x.x.x.x.port > x.x.x.x.port:"
# 日付プレフィックス(YYYY-MM-DD)はオプション
IPV4_PATTERN = re.compile(
    r'(?:\d{4}-\d{2}-\d{2} )?(\d+:\d+:\d+\.\d+) IP ([\d.]+)\.(\d+) > ([\d.]+)\.(\d+):'
)
# IPv6: "HH:MM:SS.ms IP6 addr.port > addr.port:"
IPV6_PATTERN = re.compile(
    r'(?:\d{4}-\d{2}-\d{2} )?(\d+:\d+:\d+\.\d+) IP6 ([0-9a-f:]+)\.(\d+) > ([0-9a-f:]+)\.(\d+):'
)


def parse_log(filepath):
    """tcpdumpログをパースして構造化データに変換（IPv4/IPv6対応）"""
    records = []
    with open(filepath, "r") as f:
        for line in f:
            m = IPV4_PATTERN.search(line)
            if m:
                time, src_ip, src_port, dst_ip, dst_port = m.groups()
                records.append({
                    "time": time, "src_ip": src_ip, "src_port": int(src_port),
                    "dst_ip": dst_ip, "dst_port": int(dst_port),
                    "version": 4, "raw": line.strip()
                })
                continue
            m = IPV6_PATTERN.search(line)
            if m:
                time, src_ip, src_port, dst_ip, dst_port = m.groups()
                records.append({
                    "time": time, "src_ip": src_ip, "src_port": int(src_port),
                    "dst_ip": dst_ip, "dst_port": int(dst_port),
                    "version": 6, "raw": line.strip()
                })
    return records


def parse_logs_dir(dirpath=LOG_DIR):
    """logsフォルダ内の全キャプチャファイルをまとめて読み込む"""
    files = sorted(glob.glob(os.path.join(dirpath, "capture_*.txt")))
    if not files:
        print(f"⚠️  {dirpath}/ にファイルが見つかりません")
        return []
    print(f"📂 {len(files)} ファイルを処理中...")
    all_records = []
    for f in files:
        recs = parse_log(f)
        print(f"  {os.path.basename(f)}: {len(recs)} 件")
        all_records.extend(recs)
    return all_records


def analyze(records):
    """基本的な集計・分析"""
    ipv4 = [r for r in records if r["version"] == 4]
    ipv6 = [r for r in records if r["version"] == 6]
    print(f"\n📊 総通信数: {len(records)} 件  (IPv4: {len(ipv4)}, IPv6: {len(ipv6)})\n")

    # 外部IP集計（IPv4）
    external = defaultdict(int)
    for r in ipv4:
        if not r["dst_ip"].startswith("192.168."):
            external[r["dst_ip"]] += 1

    if external:
        print("🌐 外部接続先 TOP10 (IPv4):")
        for ip, count in sorted(external.items(), key=lambda x: -x[1])[:10]:
            print(f"  {ip:20s} {count:4d} 回")

    # ポート集計（全体）
    ports = defaultdict(int)
    for r in records:
        ports[r["dst_port"]] += 1

    print("\n🔌 よく使われるポート TOP5:")
    services = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 3389: "RDP", 123: "NTP"}
    for port, count in sorted(ports.items(), key=lambda x: -x[1])[:5]:
        service = services.get(port, "不明")
        print(f"  ポート {port:5d} ({service:5s}): {count:4d} 回")

    # デバイス一覧（IPv4 ローカル）
    devices = {r["src_ip"] for r in ipv4 if r["src_ip"].startswith("192.168.")}
    if devices:
        print(f"\n📱 検出されたローカルデバイス: {len(devices)} 台")
        for d in sorted(devices):
            print(f"  {d}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ネットワークログ解析")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--file", help="解析するファイルパス")
    group.add_argument("--dir", nargs="?", const=LOG_DIR,
                       help=f"logsディレクトリを解析（省略時: {LOG_DIR}/）")
    args = parser.parse_args()

    print("🔍 ネットワークログ解析開始...")

    if args.file:
        records = parse_log(args.file)
    elif args.dir is not None:
        records = parse_logs_dir(args.dir)
    else:
        records = parse_log(LOG_FILE)

    analyze(records)
    print("\n✅ 完了")
