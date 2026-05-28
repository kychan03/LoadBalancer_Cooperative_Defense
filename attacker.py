import requests
import random
import time

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

LB1_URL = "http://localhost:8081"
LB2_URL = "http://localhost:8082"

NORMAL_PAYLOAD = "action=view_profile&user_id=42"
ATTACK_PAYLOAD = "DROP TABLE users; -- 기본 공격 페이로드"

print("==========================================================================")
print(" 🔥 WID-LB(WAF 통합형 분산 로드밸런서) 차세대 단계별 검증 시나리오 가동")
print("==========================================================================\n")

# --------------------------------------------------------------------------
print("▶️ [1단계] 정상 사용자의 일반 트래픽 분산(로드밸런싱) 검증")
print("-> 설명: 정상 패킷이 LB-1을 통해 백엔드(WEB-1, WEB-2)로 잘 나뉘어 가는지 확인합니다.")
print("--------------------------------------------------------------------------")
for i in range(4):
    fake_ip = random_ip()
    resp = requests.post(LB1_URL, data=NORMAL_PAYLOAD, headers={"X-Forwarded-For": fake_ip})
    print(f"[정상 요청 {i+1}] IP: {fake_ip:15} -> 응답:\n{resp.text.strip()}\n")
    time.sleep(0.5)


# --------------------------------------------------------------------------
print("\n▶️ [2단계] 1번 로드밸런서(LB-1) 대상 L7 DDoS 공격 감행 및 차단")
print("-> 설명: 동일한 악성 페이로드를 단시간 내 폭격하여 실시간 차단 룰을 유도합니다.")
print("--------------------------------------------------------------------------")
for i in range(7):
    fake_ip = random_ip() # IP를 계속 바꿔도 페이로드 해시로 잡는지 테스트
    resp = requests.post(LB1_URL, data=ATTACK_PAYLOAD, headers={"X-Forwarded-For": fake_ip})
    print(f"[공격 발생 {i+1}] IP: {fake_ip:15} -> 응답: {resp.text.strip()}")
    time.sleep(0.3)


# --------------------------------------------------------------------------
print("\n▶️ [3단계] 2번 로드밸런서(LB-2) 대상 변이(Mutation) 우회 공격 시도")
print("-> 설명: LB-1에서 생성된 면역력이 공유되었는지 보고, 대소문자/공백을 꼬아도 정규화로 막아내는지 검증합니다.")
print("--------------------------------------------------------------------------")
# 원본 'DROP TABLE users;'를 교묘하게 난독화 변형
mutated_payload = "   DrOp   tAbLe   users; /* 주석 우회 시도 */"
evasion_ip = random_ip()

print(f"[우회 시도 페이로드]: '{mutated_payload}'")
resp = requests.post(LB2_URL, data=mutated_payload, headers={"X-Forwarded-For": evasion_ip})
print(f"[최종 우회 공격 결과] IP: {evasion_ip:15} -> 응답:\n{resp.text.strip()}\n")


# --------------------------------------------------------------------------
print("▶️ [4단계] 공격 발생 중 정상 사용자의 가용성(Availability) 검증")
print("-> 설명: 악성 시그니처만 5분간 격리되었을 뿐, 일반 사용자는 무중단 서비스가 가능한지 확인합니다.")
print("--------------------------------------------------------------------------")
clean_ip = random_ip()
resp = requests.post(LB2_URL, data=NORMAL_PAYLOAD, headers={"X-Forwarded-For": clean_ip})
print(f"[정상 사용자 접속] IP: {clean_ip:15} -> 응답:\n{resp.text.strip()}")
print("==========================================================================")
print(" 🎉 시나리오 종료! 관리자 페이지(http://localhost:8081/admin/redis-status)에서 TTL을 확인하세요.")
print("==========================================================================")
