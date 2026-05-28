import os
import re
import redis
import hashlib
import requests
from flask import Flask, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
db = redis.Redis(host='redis', port=6379, db=0)

SHARED_SECRET_KEY = b'ZeroTrustEnterpriseDefenseKey123' 
BACKENDS = ["http://web1", "http://web2"]
turn = 0

# --- 🛡️ [추가됨] 데이터 정규화(Normalization) 모듈 ---
def normalize_payload(payload_bytes):
    if not payload_bytes:
        return ""
    
    # 1. 바이트를 문자열로 디코딩 (오류는 무시)
    text = payload_bytes.decode('utf-8', errors='ignore')
    
    # 2. 모든 문자를 소문자로 변환 (대소문자 변이 방어)
    text = text.lower()
    
    # 3. 모든 공백, 탭, 줄바꿈 완전 제거 (공백 변이 방어)
    text = re.sub(r'\s+', '', text)
    
    # 4. SQL 주석(-- 또는 /* */) 뒷부분 무시 (주석 변이 방어)
    text = text.split('--')[0]
    text = text.split('/*')[0]
    
    return text

# --- 🔐 AES-GCM 암호화/복호화 모듈 ---
def encrypt_signature(signature):
    aesgcm = AESGCM(SHARED_SECRET_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, signature.encode('utf-8'), None)
    return nonce.hex() + ":" + ciphertext.hex()

def decrypt_signature(encrypted_data):
    try:
        aesgcm = AESGCM(SHARED_SECRET_KEY)
        parts = encrypted_data.split(":")
        nonce = bytes.fromhex(parts[0])
        ciphertext = bytes.fromhex(parts[1])
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception:
        return None

# --- 🔍 패킷 시그니처 추출 (정규화 적용) ---
def get_packet_signature(req):
    payload = req.get_data()
    if not payload:
        return "empty_payload"
        
    # 정규화된 텍스트로 시그니처(해시)를 생성!
    normalized_text = normalize_payload(payload)
    return hashlib.sha256(normalized_text.encode('utf-8')).hexdigest()

# --- 📊 [추가됨] 관리자용 Redis 상태 확인 페이지 ---
@app.route('/admin/redis-status', methods=['GET'])
def redis_status():
    encrypted_threats = db.smembers("global_threat_signatures")
    result_html = "<h2>🛡️ 분산 방어망 동기화 상태 (Redis DB)</h2>"
    result_html += f"<p>현재 저장된 암호화된 시그니처 개수: <b>{len(encrypted_threats)}</b>개</p>"
    result_html += "<ul>"
    
    for enc_threat in encrypted_threats:
        raw_data = enc_threat.decode('utf-8')
        decrypted_sig = decrypt_signature(raw_data)
        
        result_html += f"<li><b>암호화된 원본 (DB 저장값):</b> {raw_data[:30]}...<br>"
        if decrypted_sig:
            result_html += f"<span style='color:green;'>↳ <b>복호화된 시그니처(SHA-256):</b> {decrypted_sig} (무결성 검증 통과)</span></li>"
        else:
            result_html += f"<span style='color:red;'>↳ <b>복호화 실패:</b> 데이터 변조 의심</span></li>"
            
    result_html += "</ul>"
    return result_html

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    global turn
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    signature = get_packet_signature(request)

    encrypted_threats = db.smembers("global_threat_signatures")
    blocked_signatures = set()
    
    for enc_threat in encrypted_threats:
        decrypted_sig = decrypt_signature(enc_threat.decode('utf-8'))
        if decrypted_sig:
            blocked_signatures.add(decrypted_sig)

    if signature in blocked_signatures:
        return f"🚨 [방어망 가동] IP({client_ip})를 우회했으나, 악성 페이로드 시그니처가 적발되어 전면 차단됩니다.", 403

    count = db.incr(f"rate:{signature}")
    if count == 1:
        db.expire(f"rate:{signature}", 10)
        
    if count > 5:
        encrypted_sig = encrypt_signature(signature)
        db.sadd("global_threat_signatures", encrypted_sig)
        return f"💀 [경보] 신규 위협 탐지! 시그니처를 AES-GCM으로 암호화하여 타 노드에 전파했습니다.", 403

    # 4. 🔀 지능형 로드밸런싱 (Round Robin + Failover)
    for _ in range(len(BACKENDS)):
        target = BACKENDS[turn]
        turn = (turn + 1) % len(BACKENDS)
        
        try:
            # 타겟 백엔드로 실제 요청 전달 (3초 타임아웃)
            resp = requests.request(
                method=request.method,
                url=f"{target}/{path}",
                headers={key: value for (key, value) in request.headers if key != 'Host'},
                data=request.get_data(),
                cookies=request.cookies,
                timeout=3, 
                allow_redirects=False
            )
            # 성공하면 트래픽을 어느 서버가 처리했는지 명확하게 표시!
            return f"✅ 정상 트래픽 통과\n🔀 트래픽 분산: {target} 노드가 처리함\n📄 백엔드 응답: {resp.text}"
            
        except requests.exceptions.RequestException:
            # 이 서버가 죽었거나 응답이 없다면? 당황하지 않고 다음 서버(for문)로 넘어감!
            continue
            
    # 모든 백엔드 서버가 죽었을 경우에만 에러 출력
    return "❌ [장애 발생] 연결 가능한 모든 백엔드 서버가 다운되었습니다 (503 Service Unavailable)", 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
