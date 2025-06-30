-- 기본 네트워크 변수 설정
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- 기본 설정 포함
include = 'snort_defaults.lua'

-- Snort가 사용할 네트워크 인터페이스 (필요 시 명시)
-- interface = 'eth0'  -- 또는 command line의 -i 옵션으로 지정

-- 룰 파일 설정
ips = {
  enable_builtin_rules = true,
  rules = {
    '/usr/local/snort/etc/snort/rules/local.rules',
    '/usr/local/snort/etc/snort/rules/ai_generated.rules'
  }
}

-- 출력 설정 (FAST alert 형식, 파일 저장)
outputs = {
  {
    alert_fast = {
      file = true
    }
  }
}
