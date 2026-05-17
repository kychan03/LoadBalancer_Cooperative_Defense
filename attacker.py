import requests
import random
import time

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

print("==============================================")
print(" 🕵️‍♂️ 시나리오: 정규화를 뚫기 위한 '페이로드 변이' 공격")
print("==============================================\n")

print(">>> [Phase 1] LB-1(8081)에 미세하게 변형된 페이로드 지속 전송 (IP 계속 변경)")
for i in range(7):
    fake_ip = random_ip()
    headers = {"X-Forwarded-For": fake_ip}
    
    # 해커가 매번 대소문자, 공백, 주석을 랜덤으로 섞어서 공격(변이)함!
    spaces = " " * random.randint(1, 5)
    random_junk = f"-- JUNK_{random.randint(1000, 9999)}"
    
    # 예: dRoP TaBle  users; -- JUNK_8492
    mutated_payload = f"dRoP{spaces}TaBle{spaces}users; {random_junk}" 
    
    resp = requests.post("http://localhost:8081", data=mutated_payload, headers=headers)
    print(f"변이 공격 {i+1} (IP: {fake_ip:15}) -> 응답: {resp.text}")
    time.sleep(0.5)

print("\n----------------------------------------------")
print(">>> [Phase 2] 방어망 동기화 확인! 2번 로드밸런서(8082)에 완전히 다른 형태의 변이 공격 시도")
new_fake_ip = random_ip()
headers = {"X-Forwarded-For": new_fake_ip}

# 2번 서버에는 완전히 다른 변주를 준 공격을 시도함
ultimate_mutated_payload = "DROP    table USERS; /* 바이패스 시도 */"
resp = requests.post("http://localhost:8082", data=ultimate_mutated_payload, headers=headers)
print(f"최종 우회 공격 (IP: {new_fake_ip:15}) -> 응답: {resp.text}")