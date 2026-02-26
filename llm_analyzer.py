import os
from datetime import datetime

import anthropic
from dotenv import load_dotenv

load_dotenv()

ALERT_LOG = "alerts.log"
MODEL = "claude-opus-4-6"


def analyze(anomalies, baseline):
    """
    検知された異常をClaude APIに送り、日本語で分析結果を返す。

    anomalies: [{"time": "21:44", "pkt": 4674, "src": 53, "dst": 49,
                 "ports": 204, "susp": 0.49, "score": -0.046}, ...]
    baseline:  {"avg_pkt": 1200, "avg_ports": 40, "avg_susp": 0.2}
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\nℹ️  LLM分析をスキップ: .env に ANTHROPIC_API_KEY を設定すると Claude による分析が使えます")
        return None

    anomaly_lines = "\n".join(
        f"- {a['time']} パケット数:{a['pkt']}, 送信元IP:{a['src']}, "
        f"宛先IP:{a['dst']}, ポート種類:{a['ports']}, "
        f"不審率:{a['susp']:.1%} (score:{a['score']:.3f})"
        for a in anomalies
    )

    prompt = f"""あなたはネットワークセキュリティの専門家です。
以下のネットワーク異常検知結果を分析してください。

【通常時の基準値（正常な時間帯の平均）】
- パケット数: {baseline['avg_pkt']:.0f} 件/分
- ポート種類: {baseline['avg_ports']:.0f} 種類/分
- 不審ポート率: {baseline['avg_susp']:.1%}

【検知された異常 ({len(anomalies)} 件)】
{anomaly_lines}

以下の点を簡潔に日本語で説明してください：
1. 何が起きている可能性があるか
2. 危険度（低/中/高）
3. 推奨される対応"""

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=MODEL,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}]
    )
    result = message.content[0].text

    print("\n🧠 【Claude 分析結果】")
    print(result)

    with open(ALERT_LOG, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n[{timestamp}] === Claude 分析 ===\n{result}\n")

    return result
