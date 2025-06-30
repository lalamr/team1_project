from scapy.all import sniff, IP, TCP
from tensorflow.keras.models import load_model
import joblib
import numpy as np
import mysql.connector
import time
from datetime import datetime
from collections import defaultdict

# ======================== 설정 ========================

DB_CONFIG = {
    "host": "172.30.0.10",  
    "port": 3306,
    "user": "ai_writer",
    "password": "1234",
    "database": "ai_security"
}

ignored_ips = ["127.0.0.1", "192.168.81.131", "192.168.81.100"]

# 모델 로드
ae = load_model("autoencoder.h5", compile=False)
scaler = joblib.load("scaler.pkl")
thr = joblib.load("ae_threshold.pkl")

# 탐지 기준
TIME_WINDOW = 2
THRESHOLD = 10
syn_tracker = defaultdict(lambda: {"count": 0, "last_time": time.time()})
ack_tracker = defaultdict(bool)

# ======================== 시그니처 삽입 함수 ========================

def insert_signature(ip):
    now = datetime.utcnow()
    conn = None

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        signature_id = f"SIG-{now.strftime('%Y%m%d%H%M%S')}-{ip.replace('.', '')[-4:]}"
        name = "SYN Flood Detection"
        severity = "High"
        attack_type = "DoS"
        recommended_action = "Drop"
        direction = "client-to-server"
        protocols = '["TCP"]'
        service = "TCP(80)"
        pattern_rules = '["SYN only, no ACK"]'
        context = '["Payload"]'
        stateful_criteria = "No ACK after multiple SYNs"
        packet_characteristics = "Flags=SYN, No ACK, small packet size"
        metadata = '{"source": "AI-Detector", "method": "AutoEncoder", "confidence": 0.95}'

        # 중복 방지 (내용 기준)
        cursor.execute("""
            SELECT id FROM ips_signatures
            WHERE name = %s AND attack_type = %s
              AND protocols = %s AND pattern_rules = %s
        """, (name, attack_type, protocols, pattern_rules))

        if cursor.fetchone():
            print(f"[DB] 유사 시그니처 이미 존재함: {name}, {attack_type}")
            return

        # 삽입
        cursor.execute("""
            INSERT INTO ips_signatures (
                signature_id, name, severity, attack_type,
                recommended_action, direction, protocols,
                service, pattern_rules, context,
                stateful_criteria, packet_characteristics, metadata,
                validated, published
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s
            )
        """, (
            signature_id, name, severity, attack_type,
            recommended_action, direction, protocols,
            service, pattern_rules, context,
            stateful_criteria, packet_characteristics, metadata,
            True, True
        ))

        conn.commit()
        print(f"[DB] 시그니처 등록 완료: {signature_id}")

    except mysql.connector.Error as e:
        print(f"[DB] MySQL 오류: {e}")
    finally:
        if conn:
            conn.close()

# ======================== 특징 추출 함수 ========================

def extract_features(pkt):
    features = np.zeros(80, dtype=np.float32)
    ip_layer = pkt.getlayer(IP)
    if not ip_layer:
        return None
    features[0] = len(pkt)
    features[1] = ip_layer.ttl
    features[2] = ip_layer.proto
    features[3] = getattr(pkt, "type", 0)
    return features

# ======================== 패킷 처리 함수 ========================

def on_packet(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP].src
    tcp = pkt[TCP]

    if ip in ignored_ips:
        return

    # ACK 처리
    if tcp.flags & 0x10:
        ack_tracker[ip] = True
        return

    # SYN 감지
    if tcp.flags == 0x02:
        now = time.time()
        entry = syn_tracker[ip]

        if now - entry["last_time"] > TIME_WINDOW:
            entry["count"] = 1
            entry["last_time"] = now
        else:
            entry["count"] += 1

        if entry["count"] >= THRESHOLD and not ack_tracker[ip]:
            print(f"[!] SYN Flood 의심: {ip}, count={entry['count']}")

            feat = extract_features(pkt)
            if feat is None:
                return

            X = scaler.transform(feat.reshape(1, -1))
            ae_err = np.mean((X - ae.predict(X)) ** 2)
            ae_p = 1 / (1 + np.exp(-50 * (ae_err - thr)))

            print(f"[DEBUG] ae_p: {ae_p:.4f}, ae_err: {ae_err:.6f}, src_ip: {ip}")

            if ae_p > 0.3:
                insert_signature(ip)

# ======================== 실행 ========================

if __name__ == "__main__":
    print("[*] AI 서버: 실시간 SYN Flood 감지 시작")
    sniff(filter="tcp", prn=on_packet, store=0)
