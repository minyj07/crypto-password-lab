from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for, after_this_request
import os
import secrets
from werkzeug.utils import secure_filename

# 기존 스크립트를 웹 환경에 맞게 수정하여 import
from vault import derive_key, encrypt_file_web, decrypt_file_web
# cracker.py에서 test_vault_security 함수만 가져옵니다.
from cracker import test_vault_security

app = Flask(__name__)
# Flask의 flash 메시지 기능을 사용하기 위한 시크릿 키 설정
app.secret_key = secrets.token_hex(16)

# --- 설정 ---
# 2GB로 파일 업로드 용량 제한 설정 (서비스 안정성 확보)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024 # 2 Gigabytes

# 파일 업로드 및 다운로드를 위한 디렉토리 설정
UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

# 애플리케이션 시작 시 업로드 및 다운로드 폴더 생성
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    """메인 페이지를 렌더링합니다."""
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """파일 암호화 요청을 처리합니다."""
    # --- 1. 입력 값 검증 ---
    if 'file' not in request.files:
        flash('❌ 파일이 전송되지 않았습니다.')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')

    if file.filename == '':
        flash('❌ 파일을 선택해주세요.')
        return redirect(url_for('index'))

    if not password:
        flash('❌ 비밀번호를 입력해주세요.')
        return redirect(url_for('index'))

    # --- 2. 파일 처리 및 암호화 (파일 형식 제한 없음) ---
    if file:
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        # 파일 이름과 확장자를 분리하여 '_encrypted' 키워드를 추가합니다.
        root, ext = os.path.splitext(filename)
        output_filename = f"{root}_encrypted{ext}"
        output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], output_filename)

        success, message = encrypt_file_web(input_path, password, output_path)

        # 파일 처리 후 원본 파일 삭제
        try:
            os.remove(input_path)
        except Exception as e:
            app.logger.error(f"Error removing uploaded file {input_path}: {e}")

        if success:
            flash(f'✅ {message}')
            return redirect(url_for('index', download_file=output_filename))
        else:
            flash(f'❌ {message}')
            return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """파일 복호화 요청을 처리합니다."""
    # --- 1. 입력 값 검증 ---
    if 'file' not in request.files:
        flash('❌ 파일이 전송되지 않았습니다.')
        return redirect(url_for('index'))
        
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('❌ 파일을 선택해주세요.')
        return redirect(url_for('index'))

    if not password:
        flash('❌ 비밀번호를 입력해주세요.')
        return redirect(url_for('index'))

    # --- 2. 파일 처리 및 복호화 (파일 형식 제한 없음) ---
    if file:
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        # 복호화될 파일의 이름을 결정합니다.
        root, ext = os.path.splitext(filename)
        if '_encrypted' in root:
            output_filename = root.removesuffix('_encrypted') + ext
        elif ext == '.enc':
            output_filename = root
        else:
            output_filename = root

        output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], output_filename)

        success, message = decrypt_file_web(input_path, password, output_path)

        # 파일 처리 후 원본 파일 삭제
        try:
            os.remove(input_path)
        except Exception as e:
            app.logger.error(f"Error removing uploaded file {input_path}: {e}")

        if success:
            flash(f'✅ {message}')
            return redirect(url_for('index', download_file=output_filename))
        else:
            flash(f'❌ {message}')
            return redirect(url_for('index'))

# Part 2(구 Part 3) 보안 테스트 라우트
@app.route('/test_security', methods=['POST'])
def test_security():
    """보안 금고(vault) 파일에 대한 크래킹 시도를 시뮬레이션하고, 결과를 직접 렌더링합니다."""
    result_log = test_vault_security()
    # flash/redirect 대신, 결과를 직접 템플릿에 전달하여 렌더링합니다.
    return render_template('index.html', crack_result=result_log)

@app.route('/download/<filename>')
def download(filename):
    """암호화/복호화된 파일 다운로드를 처리하고, 다운로드 완료 후 파일을 삭제합니다."""
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)

    # 파일을 전송한 후 삭제하도록 설정
    @after_this_request
    def remove_file(response):
        try:
            os.remove(file_path)
        except Exception as e:
            app.logger.error(f"Error removing or closing downloaded file: {e}")
        return response

    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename, as_attachment=True)

# --- 오류 핸들러 ---
@app.errorhandler(413)
def request_entity_too_large(error):
    """파일 용량 초과 시 사용자에게 보여줄 오류 페이지"""
    flash('❌ 오류: 파일 용량이 너무 큽니다. (최대 2GB)')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
