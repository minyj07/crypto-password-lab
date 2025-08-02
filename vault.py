# vault.py (Part 1: 방어)
# '솔트'와 '키 유도 함수'를 사용한 안전한 파일 암호화/복호화 유틸리티

import os
import argparse
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- 상수 정의 ---
SALT_SIZE = 16  # 솔트 크기 (16바이트 / 128비트)
KEY_ITERATIONS = 100000  # PBKDF2 반복 횟수 (높을수록 안전)
ENCRYPTED_EXTENSION = ".enc" # 암호화된 파일 확장자

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    비밀번호와 솔트로부터 PBKDF2-HMAC-SHA256 키 유도 함수를 사용해 32바이트 AES 키를 생성합니다.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 키 길이
        salt=salt,
        iterations=KEY_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(file_path: str):
    """
    지정된 파일을 AES-GCM 방식으로 암호화합니다.
    결과 파일은 [솔트(16바이트)] + [Nonce(12바이트)] + [암호화된 데이터] 구조를 가집니다.
    """
    try:
        # 1. 사용자로부터 비밀번호를 안전하게 입력받습니다.
        password = getpass.getpass("암호화에 사용할 비밀번호를 입력하세요: ").encode('utf-8')
        
        # 2. 원본 파일 내용을 읽어옵니다.
        with open(file_path, 'rb') as f:
            data_to_encrypt = f.read()

        # 3. 암호학적으로 안전한 16바이트 솔트를 생성합니다.
        # 솔트는 모든 파일마다 고유해야 합니다.
        salt = os.urandom(SALT_SIZE)

        # 4. (비밀번호 + 솔트) 조합으로 실제 암호화에 사용할 키를 유도합니다.
        key = derive_key(password, salt)

        # 5. AES-GCM 암호화를 준비합니다.
        aesgcm = AESGCM(key)
        
        # 6. 암호화에 사용할 Nonce(Number used once)를 생성합니다.
        # Nonce 또한 매 암호화마다 고유해야 합니다.
        nonce = os.urandom(12) # GCM 모드에서는 12바이트 Nonce가 권장됩니다.

        # 7. 파일 내용을 암호화합니다.
        encrypted_data = aesgcm.encrypt(nonce, data_to_encrypt, None) # 추가 인증 데이터(AAD)는 없음

        # 8. 최종 결과 파일(.enc)을 저장합니다.
        # 구조: [솔트] + [Nonce] + [암호화된 데이터]
        encrypted_file_path = file_path + ENCRYPTED_EXTENSION
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(encrypted_data)
            
        print(f"✅ 성공: '{file_path}' 파일이 '{encrypted_file_path}'으로 안전하게 암호화되었습니다.")

    except FileNotFoundError:
        print(f"❌ 오류: '{file_path}' 파일을 찾을 수 없습니다.")
    except Exception as e:
        print(f"❌ 암호화 중 오류가 발생했습니다: {e}")

def decrypt_file(file_path: str):
    """
    AES-GCM으로 암호화된 파일을 복호화합니다.
    """
    try:
        # 1. 사용자로부터 비밀번호를 안전하게 입력받습니다.
        password = getpass.getpass("복호화할 파일의 비밀번호를 입력하세요: ").encode('utf-8')

        # 2. 암호화된 파일 내용을 읽어옵니다.
        with open(file_path, 'rb') as f:
            # 파일에서 솔트, Nonce, 암호화된 데이터를 분리합니다.
            salt = f.read(SALT_SIZE)
            nonce = f.read(12)
            encrypted_data = f.read()

        # 3. 입력된 비밀번호와 파일에서 읽은 솔트를 사용해 AES 키를 다시 만들어냅니다.
        key = derive_key(password, salt)

        # 4. AES-GCM 복호화를 준비합니다.
        aesgcm = AESGCM(key)

        # 5. 재생성된 키로 데이터를 복호화합니다.
        # 비밀번호가 틀리면 'InvalidTag' 예외가 발생하여 무결성 검증에 실패합니다.
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)

        # 6. 원본 파일을 복원합니다.
        original_file_path = file_path.removesuffix(ENCRYPTED_EXTENSION)
        with open(original_file_path, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"✅ 성공: '{file_path}' 파일이 '{original_file_path}'으로 복호화되었습니다.")

    except FileNotFoundError:
        print(f"❌ 오류: '{file_path}' 파일을 찾을 수 없습니다.")
    except InvalidTag:
        print("❌ 오류: 비밀번호가 틀렸거나 파일이 손상되었습니다. 복호화에 실패했습니다.")
    except Exception as e:
        print(f"❌ 복호화 중 오류가 발생했습니다: {e}")


# --- 웹 애플리케이션용 함수 ---

def encrypt_file_web(input_path: str, password_str: str, output_path: str):
    """
    웹 환경에서 파일을 암호화하고 (성공 여부, 메시지)를 반환합니다.
    """
    try:
        password = password_str.encode('utf-8')
        with open(input_path, 'rb') as f:
            data_to_encrypt = f.read()

        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data_to_encrypt, None)

        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(encrypted_data)
            
        return True, f"파일이 성공적으로 암호화되었습니다. 아래 링크로 다운로드하세요."

    except FileNotFoundError:
        return False, f"오류: 원본 파일을 찾을 수 없습니다."
    except Exception as e:
        return False, f"암호화 중 오류 발생: {e}"

def decrypt_file_web(input_path: str, password_str: str, output_path: str):
    """
    웹 환경에서 파일을 복호화하고 (성공 여부, 메시지)를 반환합니다.
    """
    try:
        password = password_str.encode('utf-8')
        with open(input_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(12)
            encrypted_data = f.read()

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return True, f"파일이 성공적으로 복호화되었습니다. 아래 링크로 다운로드하세요."

    except FileNotFoundError:
        return False, f"오류: 암호화된 파일을 찾을 수 없습니다."
    except InvalidTag:
        return False, "오류: 비밀번호가 틀렸거나 파일이 손상되었습니다."
    except Exception as e:
        return False, f"복호화 중 오류 발생: {e}"

# --- 기존 CLI 실행 부분 (참고용으로 남겨두거나 삭제) ---
def main_cli():
    """
    argparse를 사용하여 커맨드라인 인터페이스를 설정합니다.
    """
    parser = argparse.ArgumentParser(
        description="안전한 파일 암호화/복호화 유틸리티 (AES-GCM with PBKDF2)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # ... (이하 기존 CLI 코드와 동일)

if __name__ == '__main__':
    # 이 파일이 직접 실행될 때 (예: python vault.py encrypt ...)
    # 기존의 CLI 기능을 사용하도록 설정할 수 있습니다.
    # main_cli() # 웹 서버로 사용할 때는 이 부분을 주석 처리합니다.
    pass # 웹 앱에서는 app.py가 이 모듈을 임포트하므로 직접 실행되지 않습니다.
