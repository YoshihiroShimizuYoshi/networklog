# ネットワークログ AI 監視システム

## プロジェクト概要
ネットワークトラフィックを自動収集・解析・AI異常検知し、Claude APIで日本語分析するシステム。

- **場所**: `~/vscode/networklog`
- **GitHub**: https://github.com/YoshihiroShimizuYoshi/networklog
- **仮想環境**: `venv`（Python 3.12）
- **AI分析モデル**: `claude-opus-4-6` / max_tokens=2048

## 現在のファイル構成

| ファイル | 役割 |
|----------|------|
| `collector.py` | tcpdumpで5分ごとにキャプチャ → `logs/capture_YYYYMMDD_HHMMSS.txt` に保存。`sudo` が必要 |
| `analyzer.py` | ログをパース・集計（IPv4/IPv6対応）。`--file` / `--dir` 引数対応 |
| `detector.py` | Isolation Forestで異常検知。異常時はターミナル出力・macOS通知・`alerts.log` 記録。`run()` は異常リストとベースラインをdictで返す |
| `llm_analyzer.py` | 異常データをClaude APIに送り「何が起きているか・危険度・推奨対応」を日本語で分析。`alerts.log` にも記録 |
| `monitor.py` | 全体を自動ループ：キャプチャ → 異常検知 → LLM分析 を繰り返す |
| `.env` | `ANTHROPIC_API_KEY=sk-ant-...` を記載（`.gitignore` 済み・Git管理外） |

## 処理フロー

```
monitor.py（sudo で起動）
 └─ ループ（5分ごと）
     ├─ collector.py  → logs/ にキャプチャ保存
     ├─ detector.py   → Isolation Forestで異常検知
     │    ├─ 特徴量（1分窓）：パケット数・ユニークIP・ポート種類数・不審ポート率
     │    ├─ contamination=0.1（10%を異常とみなす）
     │    └─ 異常 → ターミナル警告 + macOS通知 + alerts.log
     └─ llm_analyzer.py → 異常があればClaude APIで日本語分析
```

## インストール済みパッケージ（venv）

```
numpy, pandas, scipy, sklearn  （Isolation Forest用）
anthropic                       （Claude API）
python-dotenv                   （.env読み込み）
requests
```

## 各スクリプトの使い方

```bash
# ログ解析のみ
venv/bin/python analyzer.py --dir
venv/bin/python analyzer.py --file logs/capture_XXXXXX.txt

# 異常検知 + LLM分析
venv/bin/python detector.py
venv/bin/python detector.py --file logs/capture_XXXXXX.txt
venv/bin/python detector.py --contamination 0.2

# 全自動監視（要 sudo）
sudo venv/bin/python monitor.py
```

## 動作確認済み

- `analyzer.py` → logsフォルダ・IPv6 正常動作
- `detector.py` → 18,634件から2件の異常を検知
- `llm_analyzer.py` → Claude APIで2件の異常を日本語分析（全文表示）
- GitHub push済み

---

## 今後の実装計画（優先順位順）

### Phase 1：Elasticsearch + Kibana 構築【最優先】

**目的**: データ蓄積・可視化基盤の整備。Ciscoルーターなし・開発環境のみで実施可能。

#### 作成するファイル

**`docker-compose.yml`**（プロジェクトルートに配置）

```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
volumes:
  esdata:
```

**`es_client.py`**（新規作成）

3つのインデックスへ書き込むクライアント：

| 関数 | インデックス | 内容 |
|------|-------------|------|
| `index_traffic(records, bucket)` | `network-traffic-*` | 1分間の集計データ |
| `index_alert(anomaly_data)` | `network-alerts-*` | 異常検知結果 |
| `index_analysis(text, anomalies)` | `network-ai-analysis-*` | LLM分析結果（日本語） |

追加パッケージ：
```bash
pip install elasticsearch python-dateutil
```

**`detector.py` と `llm_analyzer.py` の修正**

`monitor.py` の llm_analyze 呼び出し後に以下を追加：
```python
from es_client import index_alert, index_analysis

for anomaly in result['anomalies']:
    index_alert(anomaly)

if analysis_result:
    index_analysis(analysis_result, result['anomalies'])
```

#### Kibana ダッシュボード構成（起動後に設定）

- トラフィック量（時系列 Line Chart）
- 異常スコア推移（Area Chart）
- 送信元IP TOP10（Bar Chart）
- LLM危険度分布（Pie Chart）
- 最新アラート一覧（Data Table）
- AI分析テキスト（Markdown パネル）

---

### Phase 2：Isolation Forest 精度向上

**`detector.py` に追加する内容**：

```python
import joblib
MODEL_PATH = 'isolation_forest_model.pkl'

# ロード（存在すれば継続学習）
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    model.fit(features)
else:
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(features)

# 保存
joblib.dump(model, MODEL_PATH)
```

---

### Phase 2：contamination 閾値チューニング

- 現状の課題：`contamination=0.1` で 20:51 の時間帯が誤検知の可能性あり
- 新規ファイル `tuner.py`：ESに蓄積されたアラート履歴から誤検知率を計算し、自動調整

| 状況 | 推奨値 |
|------|--------|
| 学習開始時（データ少） | 0.05 |
| 通常運用（1週間以降） | 0.1 |
| 誤検知多発時 | 0.03〜0.05 |
| 高セキュリティ環境 | 0.15〜0.2 |

---

### Phase 3：レポート出力（HTML / CSV）

新規ファイル `reporter.py`：

| 関数 | 出力 | 内容 |
|------|------|------|
| `generate_html_report(date)` | HTML | 日次サマリー（グラフ・アラート・AI分析テキスト） |
| `generate_csv_export(date)` | CSV | 生データエクスポート（SIEM連携用） |
| `send_email_report(html_path)` | メール | SMTP経由で日次レポート送信 |

---

### Phase 4：Cisco ルーター Syslog 受信（将来）

社内ネットワークアクセス可能になった時点で実装。

```
Cisco ルーター
    │  logging host <MacのIP>
    │  logging trap informational
    ↓ UDP 514
syslog_receiver.py  →  logs/syslog_YYYYMMDD.txt
    ↓
syslog_parser.py    →  analyzer.py と同じ records 形式に変換
    ↓
detector.py / llm_analyzer.py（既存フローに合流）
```

新規ファイル：`syslog_receiver.py`、`syslog_parser.py`

---

## 注意事項

- `.env` に `ANTHROPIC_API_KEY` を記載（`.gitignore` 済み・コミット禁止）
- `logs/`、`alerts.log`、`network_log.txt`、`venv/` は `.gitignore` 済み
- `sudo` なしでは `collector.py` は動作しない（tcpdump の制約）
- `contamination=0.1` は暫定値。データ蓄積後に調整すること
