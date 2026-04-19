@echo off
chcp 65001 > nul

:: ═══════════════════════════════════════════════════════════════
:: SecureMail-Backend — Setup & Start Script (Windows)
:: Usage: Double-click setup.bat OR run in terminal
:: ═══════════════════════════════════════════════════════════════

set REPO_URL=https://github.com/The-Team-Dream/SecureMail-Backend

echo.
echo +==========================================+
echo ^|      SecureMail-Backend Setup           ^|
echo +==========================================+
echo.

:: ── 1. Check Docker ────────────────────────────────────────────
docker info > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)
echo [OK] Docker is running
echo.

:: ── 2. Create .env.standalone from example ─────────────────────
if not exist .env.standalone (
    copy .env.standalone.example .env.standalone > nul
    echo [OK] Created .env.standalone
) else (
    echo [INFO] .env.standalone already exists -- skipping copy
)
echo.

:: ── 3. Ask for DB Password ─────────────────────────────────────
echo ------------------------------------------
echo   DATABASE SETUP
echo ------------------------------------------
echo.
echo   Enter a password for PostgreSQL.
echo   Press Enter to use default: 0000
echo.
set /p db_pass="  PostgreSQL Password: "

:: Use default if empty
if "%db_pass%"=="" (
    set db_pass=0000
    echo.
    echo   [WARNING] Using default password: 0000
    echo             Not recommended for production
) else (
    echo.
    echo   [OK] Password set
)
echo.

:: ── 4. Write password into .env.standalone ─────────────────────
:: Use PowerShell to do the sed-equivalent replacement
powershell -Command "(Get-Content .env.standalone) -replace '^POSTGRES_PASSWORD=.*', 'POSTGRES_PASSWORD=%db_pass%' | Set-Content .env.standalone"
powershell -Command "(Get-Content .env.standalone) -replace 'postgresql://postgres:.*@postgres', 'postgresql://postgres:%db_pass%@postgres' | Set-Content .env.standalone"
powershell -Command "(Get-Content docker-compose.yml) -replace 'POSTGRES_PASSWORD: \".*\"', 'POSTGRES_PASSWORD: \"%db_pass%\"' | Set-Content docker-compose.yml"


echo [OK] Password written to .env.standalone
echo.

:: ── 5. Remind about optional secrets ───────────────────────────
echo ------------------------------------------
echo   [WARNING] OPTIONAL SECRETS - Fill later
echo ------------------------------------------
echo.
echo   The following features won't work until
echo   you fill their secrets in .env.standalone:
echo.
echo   - Gmail SMTP     : SMTP_PASSWORD
echo   - Google OAuth   : GOOGLE_CLIENT_ID
echo                      GOOGLE_CLIENT_SECRET
echo   - Cloudinary     : CLOUDINARY_CLOUD_NAME
echo                      CLOUDINARY_API_KEY
echo                      CLOUDINARY_API_SECRET
echo   - AbuseIPDB      : ABUSEIPDB_API_KEY
echo   - JWT            : JWT_SECRET
echo   - Encryption     : ENCRYPTION_KEY
echo.
echo   Full guide on how to get each secret:
echo   %REPO_URL%#getting-your-secrets
echo.
echo ------------------------------------------
echo.
pause

:: ── 6. Start Docker Compose ────────────────────────────────────
echo.
echo [START] Starting SecureMail Backend...
echo.
docker compose down -v > nul 2>&1
docker compose up --build -d

:: ── 7. Wait for backend ────────────────────────────────────────
echo.
echo [WAIT] Waiting for backend to be ready...
set RETRIES=20

:waitloop
docker compose logs backend 2>&1 | findstr /i "migrations have been successfully applied" > nul
if not errorlevel 1 goto done

set /a RETRIES-=1
if %RETRIES%==0 (
    echo.
    echo [ERROR] Backend failed to start. Check logs with:
    echo         docker compose logs backend
    pause
    exit /b 1
)
echo   still waiting...
timeout /t 3 /nobreak > nul
goto waitloop

:: ── 8. Done ────────────────────────────────────────────────────
:done
echo.
echo +==========================================+
echo ^|       OK  Backend is running!           
echo +==========================================+^|
echo ^|  API Docs: http://localhost:3000/api/docs/ 
echo ^|  Health:   http://localhost:3000/health    
echo +==========================================+^|
echo ^|  Logs:  docker compose logs -f backend 
echo ^|  Stop:  docker compose down            
echo +==========================================+
echo.
pause