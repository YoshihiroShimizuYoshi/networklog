import subprocess
import os
import time
from datetime import datetime

LOG_DIR = "logs"
INTERFACE = "en0"
INTERVAL = 300  # 5分ごとに保存

def ensure_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def collect(duration=INTERVAL):
    """tcpdumpをduration秒間実行してファイルに保存"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{LOG_DIR}/capture_{timestamp}.txt"
    
    print(f"📡 キャプチャ開始: {filename}")
    
    cmd = [
        "sudo", "tcpdump",
        "-i", INTERFACE,
        "-n", "-l", "-tttt"
    ]
    
    with open(filename, "w") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
    
    print(f"✅ 保存完了: {filename}")
    return filename

if __name__ == "__main__":
    ensure_dir()
    print("🔍 ネットワークログ収集開始（Ctrl+Cで停止）")
    while True:
        try:
            collect()
        except KeyboardInterrupt:
            print("\n停止しました")
            break
