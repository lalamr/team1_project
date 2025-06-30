FROM python:3.11-slim

# 시스템 패키지 설치
RUN apt update && apt install -y \
    libpcap-dev \
    tcpdump \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리
WORKDIR /app

# 파이썬 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 코드와 모델 복사
COPY . .

# 시작 명령
CMD ["python", "start.py"]
