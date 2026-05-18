# LoadBalancer_Cooperative_Defense
분산시스템 개인 프로젝트_로드벨런서 협력 방어 시스템 구현 프로젝트
# 🛡️ AES-GCM 기반 지능형 로드밸런서 분산 방어 시스템 (PoC)

## 📌 프로젝트 개요
단순 IP 기반 차단의 한계를 극복하고, 제로 트러스트(Zero Trust) 관점에서 다수의 로드밸런서 노드가 위협 정보를 안전하게 동기화하는 **지능형 분산 방어 아키텍처**입니다. 
악성 페이로드의 본질적 시그니처를 추출 및 정규화(Normalization)하여 탐지하고, 해당 위협 정보를 AES-GCM으로 암호화하여 내부망(Redis)에 실시간 브로드캐스트함으로써 전체 방어망을 동기화합니다.

## 🚀 핵심 기능 (Core Features)
1. **L7 트래픽 정규화 (Payload Normalization):**
   - 대소문자 변환, 공백/탭 제거, SQL 주석 절삭 등을 통해 공격자의 '페이로드 변이(Mutation) 및 회피 공격'을 전처리 단계에서 무력화합니다.
2. **시그니처 기반 위협 탐지:**
   - IP 스푸핑(Spoofing)에 속지 않고, 정규화된 데이터의 SHA-256 해시값을 추출하여 고유한 공격 시그니처로 식별합니다.
3. **AES-GCM 위협 정보 동기화 :**
   - 식별된 위협 시그니처를 AES-GCM 알고리즘으로 암호화(Ciphertext + MAC Tag)하여 Redis에 브로드캐스트합니다.
   - 내부망 스니핑에 의한 방어 룰셋 유출을 막고, 데이터 변조 시 무결성 검증을 통해 방어합니다.
4. **협력형 분산 방어 (Cooperative Defense):**
   - 하나의 노드에서 위협을 탐지하면 즉각적으로 다른 모든 노드의 룰셋이 동기화되어 우회 접속을 원천 차단합니다.

## 🛠️ 기술 스택 (Tech Stack)
- **Infrastructure:** Docker, Docker Compose
- **Backend/LB:** Python (Flask), Requests
- **Database (Sync):** Redis
- **Security:** Cryptography (AES-GCM), Hashlib (SHA-256)

## 💻 실행 방법 (How to Run)
```bash
# 1. 인프라 및 로드밸런서 컨테이너 빌드 및 실행
docker-compose up -d --build

# 2. 페이로드 변이 공격 시뮬레이션 스크립트 실행
python3 attacker.py

# 3. 방어망 동기화 상태 모니터링 (웹 브라우저 접속)
http://localhost:8081/admin/redis-status
```


## 💡 한계점 및 고도화 과제 (Improvements & Future Work)
본 프로젝트는 PoC(개념 증명) 단계로, 향후 실제 엔터프라이즈 환경 적용을 위해 다음과 같은 아키텍처 고도화를 계획하고 있습니다.

## 1. 공격자 우회 및 시스템 무력화 대응 (Security Hardening)
다중 인코딩 및 난독화 우회 방어: 현재 알파벳 기반 정규화는 URL/Hex/Base64 등의 다중 인코딩 공격에 취약합니다. 전처리 단계에 다중 디코딩 파이프라인을 추가하여 방어력을 강화할 예정입니다.

자원 고갈(OOM) 공격 방어: 대용량 페이로드 전송이나 초당 수만 건의 무작위 페이로드 전송 시 로드밸런서 메모리 및 Redis 과부하가 발생할 수 있습니다. 이를 방지하기 위해 페이로드 크기 제한(Length Limit) 및 L4 계층의 IP 기반 Rate Limiting을 결합한 다중 계층 차단 로직 도입이 필요합니다.

HTTP 청크 분할 전송(Chunked Transfer) 대응: 패킷을 잘게 쪼개 보내는 스트리밍 우회 공격을 탐지하기 위해, 전체 페이로드를 안전하게 재조립 후 검사하는 버퍼링 윈도우 로직 검토가 필요합니다.

## 2. 서비스 가용성 및 오탐 방지 (Availability & UX)
정상 트래픽 오탐(False Positive) 방지: Heartbeat(ping)처럼 동일한 정상 데이터를 반복 전송하는 경우 공격으로 오인되어 전면 차단될 수 있습니다. 단순 해시 일치가 아닌 정규표현식(Regex) 기반의 몽타주 탐지 룰셋 동기화로 전환하여 오탐률을 낮춰야 합니다.

복호화 병목(Bottleneck) 현상 해결: 요청 1건당 Redis의 모든 차단 룰셋을 순회하며 복호화하는 현재 방식은 트래픽 피크 시 치명적인 지연(Latency)을 유발합니다. 암호화된 룰셋을 주기적으로 로컬 메모리에 캐싱(Local Caching)하여 복호화 연산을 최소화하는 비동기 구조로 개선이 필요합니다.

과도한 정규화 부작용 완화: 개발 커뮤니티 등에서 정상적인 보안 예시 코드(예: SQL 쿼리문)를 업로드할 때 오탐되는 것을 방지하기 위해, 특정 경로에 대한 화이트리스트(Whitelist) 예외 처리 라우팅 설계가 요구됩니다.
