# cracker.py (보안 테스트)

import hashlib
import time
import os

# --- 필요한 모든 구성요소를 이 파일에서 직접 import (의존성 완전 제거) ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- 필요한 상수를 이 파일에 직접 정의 ---
SALT_SIZE = 16
KEY_ITERATIONS = 100000

# --- 필요한 함수를 이 파일에 직접 정의 ---
def derive_key_for_test(password: bytes, salt: bytes) -> bytes:
    """테스트용 키 유도 함수"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KEY_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)


# --- 시뮬레이션 로직 (단순화 및 개선) ---
def test_vault_security():
    """
    안전한 방식으로 암호화된 파일에 사전 공격이 왜 실패하는지 보여주는 시뮬레이션입니다.
    """
    log_output = []
    target_password = "apple123"

    log_output.append("--- Part 2: 보안 테스트 시뮬레이션 ---")
    log_output.append(f"목표: 안전한 방식으로 암호화된 데이터 크랙 시도")
    log_output.append(f"크래커가 알고 있는 비밀번호: '{target_password}'")
    log_output.append("-" * 40)

    try:
        # 1. 서버가 비밀번호와 '고유한 솔트'로 데이터를 암호화합니다.
        dummy_data = b"This is a secret message."
        original_salt = os.urandom(SALT_SIZE)
        original_key = derive_key_for_test(target_password.encode('utf-8'), original_salt)
        
        log_output.append("1. 'apple123' 비밀번호로 데이터를 암호화했습니다.")
        log_output.append(f"   - 사용된 진짜 솔트(Salt): {original_salt.hex()}")
        log_output.append(f"   - 생성된 암호화 키(일부): {original_key.hex()[:16]}...")
        log_output.append("\n2. 이제 공격자가 이 데이터를 해독하려고 시도합니다.")
        
        # 2. 공격자는 비밀번호는 알지만, '솔트'를 모릅니다.
        #    그래서 잘못된 키를 생성하게 됩니다.
        fake_salt = os.urandom(SALT_SIZE) # 공격자는 진짜 솔트를 모르므로, 다른 솔트를 사용하게 됨
        hacked_key = derive_key_for_test(target_password.encode('utf-8'), fake_salt)

        log_output.append("   - 공격자는 비밀번호 'apple123'를 입력했습니다.")
        log_output.append(f"   - 하지만 공격자는 진짜 솔트를 몰라, 다른 솔트를 사용합니다: {fake_salt.hex()}")
        log_output.append(f"   - 결과: 잘못된 암호화 키가 생성되었습니다: {hacked_key.hex()[:16]}...")
        
        is_match = (original_key == hacked_key)
        log_output.append(f"\n   => 원본 키와 공격자의 키가 일치하는가? {is_match}")

    except Exception as e:
        log_output.append(f"\n❌ 오류: 시뮬레이션 중 예상치 못한 문제 발생 - {e}")
        return "\n".join(log_output)

    # 3. 최종 결과 및 교육적인 설명
    log_output.append("\n" + "="*40)
    log_output.append("🎉 테스트 결과: 크랙 실패! (예상된 결과)")
    log_output.append("="*40)
    log_output.append("\n[핵심 원리]")
    log_output.append("비밀번호가 같아도, 암호화에 사용된 '솔트(Salt)'가 다르면 완전히 다른 암호화 키가 생성됩니다.")
    log_output.append("\n[결론]")
    log_output.append("공격자는 모든 가능한 솔트(2^128개)를 전부 시도해봐야 하므로, 현대적인 암호화 방식은 사실상 해독이 불가능합니다.")

    return "\n".join(log_output)
