import mysql.connector
import os
import json

DB_CONFIG = {
    "host": "172.30.0.10",
    "port": 3306,
    "user": "ai_writer",
    "password": "1234",
    "database": "ai_security"
}

RULE_PATH = "/usr/local/snort/etc/snort/rules/ai_generated.rules"
SNORT_CONFIG_PATH = "/usr/local/snort/etc/snort/snort.lua"

def fetch_droppable_signatures():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT signature_id, attack_type, pattern_rules, direction,
                   protocols, service, packet_characteristics, stateful_criteria
            FROM ips_signatures
            WHERE validated = TRUE AND published = TRUE AND recommended_action = 'Drop'
        """)
        return cursor.fetchall()
    except Exception as e:
        print(f"[DB] 조회 오류: {e}")
        return []
    finally:
        if conn:
            conn.close()

def generate_snort_rule(sig):
    try:
        proto = json.loads(sig.get("protocols", '["ip"]'))[0].lower()
    except:
        proto = "ip"

    dst_port = "any"
    service = sig.get("service", "")
    if "(" in service and ")" in service:
        dst_port = service.split("(")[-1].rstrip(")")

    direction = sig.get("direction", "client-to-server")
    src, dst = "any", "$HOME_NET"
    if direction == "server-to-client":
        src, dst = "$HOME_NET", "any"
    elif direction == "both":
        src, dst = "any", "any"

    sid_num = int(''.join(filter(str.isdigit, sig['signature_id']))[-6:] or "200000")
    msg = sig.get("attack_type", "Suspicious Traffic")

    rule_opts = [f'msg:"{msg}"', f'sid:{sid_num}', "rev:1"]

    # === pattern_rules 적용 조건 제한 (payload 기반만 허용)
    try:
        pattern_rules = json.loads(sig.get("pattern_rules", "[]"))
        for p in pattern_rules:
            if p.strip() and " " not in p and p.isascii():
                rule_opts.append(f'content:"{p}"')
                rule_opts.append("nocase")
    except:
        pass  # 무시

    pkt_char = sig.get("packet_characteristics", "").lower()
    stateful = sig.get("stateful_criteria", "").lower()

    if "flags=syn" in pkt_char or "flags=s" in pkt_char:
        rule_opts.append("flags:S")

    if "no ack" in pkt_char or "no ack" in stateful:
        rule_opts.append("flow:stateless")

    # 항상 threshold 추가
    if not any("threshold" in r for r in rule_opts):
        rule_opts.append("threshold:type both, track by_src, count 10, seconds 2")

    return f'drop {proto} {src} any -> {dst} {dst_port} ({"; ".join(rule_opts)};)'

def save_rules_to_file(rules):
    try:
        with open(RULE_PATH, "w") as f:
            for rule in rules:
                f.write(rule + "\n")
        print(f"[+] {len(rules)} 개 룰이 {RULE_PATH}에 저장되었습니다.")
        return True
    except Exception as e:
        print(f"[파일] 룰 저장 실패: {e}")
        return False

def apply_snort_config():
    print("[*] Snort 설정 테스트 중...")
    result = os.system(f"/usr/local/snort/bin/snort -T -c {SNORT_CONFIG_PATH}")
    if result != 0:
        print("[!] Snort 설정 오류.")
        return False

    print("[*] supervisorctl을 통한 Snort 재시작...")
    restart_result = os.system("supervisorctl restart snort")
    if restart_result != 0:
        print("[!] supervisorctl 재시작 실패.")
        return False

    print("[✓] Snort 재시작 성공.")
    return True

def main():
    sigs = fetch_droppable_signatures()
    if not sigs:
        print("[i] 적용할 시그니처 없음.")
        return

    rules = [generate_snort_rule(sig) for sig in sigs]
    if save_rules_to_file(rules):
        if apply_snort_config():
            print("[✓] Snort 룰 적용 완료.")
        else:
            print("[!] Snort 설정 적용 실패.")

if __name__ == "__main__":
    main()
