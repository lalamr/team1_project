FROM kalilinux/kali-rolling

# 비동기 설치 최소화 및 비대화 모드 설정
ENV DEBIAN_FRONTEND=noninteractive

# 기본 테스트 도구 설치
RUN apt update && apt-get update && apt install -y \
    iproute2 \
    net-tools \
    hping3 \
    nmap \
    curl \
    iputils-ping \
    dnsutils \
    && apt clean

# 기본 bash 진입
CMD ["/bin/bash"]
