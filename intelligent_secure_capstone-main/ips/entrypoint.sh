#!/bin/bash

# AI 컨테이너의 고정 IP (docker-compose.yml에서 지정한 값과 일치해야 함)
AI_IP="172.19.0.3"

# 복사할 포트 (예: HTTP 80 포트)
PORT=80

echo "[*] iptables TEE 설정 중..."
iptables -t mangle -C PREROUTING -p tcp --dport $PORT -j TEE --gateway $AI_IP 2>/dev/null

if [ $? -ne 0 ]; then
    iptables -t mangle -A PREROUTING -p tcp --dport $PORT -j TEE --gateway $AI_IP
    echo "[+] TEE 규칙 추가 완료: PREROUTING -> $AI_IP (포트 $PORT)"
else
    echo "[i] 이미 TEE 규칙이 존재합니다. 추가하지 않음."
fi

echo "[*] Snort supervisor 시작..."
exec /usr/bin/supervisord -c /etc/supervisord.conf
