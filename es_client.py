from datetime import datetime, timezone

from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError

ES_HOST = "http://localhost:9200"

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = Elasticsearch(ES_HOST)
    return _client


def _index_name(prefix):
    date = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"{prefix}-{date}"


def _safe_index(index, doc):
    """ES が起動していない場合は警告を出してスキップ"""
    try:
        _get_client().index(index=index, document=doc)
    except ESConnectionError:
        print(f"⚠️  ES未接続: {index} への書き込みをスキップ（docker compose up -d で起動してください）")
    except Exception as e:
        print(f"⚠️  ES書き込みエラー ({index}): {e}")


def index_traffic(records, bucket):
    """1分間の集計データを記録"""
    h = bucket // 3600
    m = (bucket % 3600) // 60
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "bucket_time": f"{h:02d}:{m:02d}",
        "packet_count": len(records),
        "unique_src_ip": len(set(r["src_ip"] for r in records)),
        "unique_dst_ip": len(set(r["dst_ip"] for r in records)),
        "unique_ports":  len(set(r["dst_port"] for r in records)),
    }
    _safe_index(_index_name("network-traffic"), doc)


def index_alert(anomaly):
    """異常検知結果1件を記録"""
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "time":    anomaly["time"],
        "pkt":     anomaly["pkt"],
        "src_ips": anomaly["src"],
        "dst_ips": anomaly["dst"],
        "ports":   anomaly["ports"],
        "susp_ratio": anomaly["susp"],
        "anomaly_score": anomaly["score"],
    }
    _safe_index(_index_name("network-alerts"), doc)


def index_analysis(text, anomalies):
    """LLM分析結果（日本語テキスト）を記録"""
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_text": text,
        "anomaly_count": len(anomalies),
        "anomaly_times": [a["time"] for a in anomalies],
    }
    _safe_index(_index_name("network-ai-analysis"), doc)
