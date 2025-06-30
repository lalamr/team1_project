CREATE TABLE IF NOT EXISTS ips_signatures (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,         -- 내부 PK
    signature_id VARCHAR(64) UNIQUE NOT NULL,              -- 고유 Signature ID
    name TEXT NOT NULL,                                    -- 시그니처 이름
    severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL,  -- 심각도
    attack_type VARCHAR(50) NOT NULL,                      -- 공격 유형
    recommended_action ENUM('Drop', 'Ignore') NOT NULL,    -- 조치
    direction ENUM('client-to-server', 'server-to-client', 'both') DEFAULT NULL,  -- 방향

    protocols TEXT,         -- ['TCP', 'UDP'] 형태의 문자열
    service VARCHAR(100),   -- ex: 'HTTP(80)'
    pattern_rules TEXT,     -- 패턴 리스트 JSON 문자열
    context TEXT,           -- ['Header', 'Payload'] 등

    stateful_criteria TEXT,
    packet_characteristics TEXT,
    metadata JSON,

    validated BOOLEAN DEFAULT FALSE,
    published BOOLEAN DEFAULT FALSE,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

ALTER TABLE ips_signatures
ADD UNIQUE KEY unique_signature (
    name(100),
    attack_type,
    protocols(100),
    pattern_rules(100)
);
