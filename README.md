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
3. **AES-GCM 위협 정보 동기화 (Zero Trust):**
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