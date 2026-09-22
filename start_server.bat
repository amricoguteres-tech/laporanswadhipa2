@echo off
setlocal
cd /d "%~dp0"

echo Memeriksa Python...
py --version
if errorlevel 1 (
    echo Python tidak dapat dijalankan.
    pause
    exit /b 1
)

if exist requirements.txt (
    echo Memasang dependensi...
    py -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Gagal memasang dependensi.
        pause
        exit /b 1
    )
)

if not defined ADMIN_PASSWORD_HASH (
    echo ADMIN_PASSWORD_HASH belum diatur.
    echo Buat hash dengan: py -c "from server import hash_password; print(hash_password('PasswordBaruAnda'))"
    pause
    exit /b 1
)

echo Menjalankan backend pada http://127.0.0.1:8000
py -u server.py

echo.
echo Backend berhenti dengan kode: %errorlevel%
pause