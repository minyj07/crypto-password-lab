# Dockerfile

# 1. 베이스 이미지 설정
# Python 3.9 슬림 버전을 기반으로 이미지를 빌드합니다.
FROM python:3.9-slim

# 2. 작업 디렉토리 설정
# 컨테이너 내에서 명령어가 실행될 기본 디렉토리를 설정합니다.
WORKDIR /app

# 3. 의존성 파일 복사
# requirements.txt 파일을 먼저 복사하여 의존성을 설치합니다.
# (소스 코드가 변경되어도 이 부분은 캐시를 통해 재사용될 수 있어 빌드 속도가 향상됩니다.)
COPY requirements.txt .

# 4. 의존성 설치
# pip를 최신 버전으로 업그레이드하고, requirements.txt에 명시된 라이브러리를 설치합니다.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 5. 소스 코드 복사
# 현재 디렉토리의 모든 파일(.)을 컨테이너의 작업 디렉토리(/app)로 복사합니다.
COPY . .

# 6. 컨테이너 실행 명령어
# Gunicorn WSGI 서버를 사용하여 애플리케이션을 실행합니다.
# -w 4: 4개의 워커 프로세스를 사용 (CPU 코어 수에 따라 조절)
# --bind 0.0.0.0:5000: 모든 네트워크 인터페이스의 5000번 포트에 바인딩
# --timeout 600: 워커의 타임아웃을 600초(10분)로 설정하여 대용량 파일 업로드 시간을 확보
# app:app: app.py 파일의 app 객체를 의미
CMD ["gunicorn", "-w", "2", "--bind", "0.0.0.0:5000", "--timeout", "1800", "app:app"]

