@echo off
setlocal ENABLEEXTENSIONS

REM ---------------------------------------------------------
REM install_dezcrwlExe_autoPATH.bat
REM
REM 1) Clone/update repository from https://github.com/zebbern/dezcrwl.git
REM    into %USERPROFILE%\dezcrwl
REM 2) Install/upgrade dependencies and PyInstaller
REM 3) Ensure dezcrwl.py exists (force update if necessary)
REM 4) Build a one-file executable from dezcrwl.py (named dezcrwl.exe)
REM 5) Move the exe to %USERPROFILE%\bin (creating it if necessary)
REM 6) Automatically add %USERPROFILE%\bin to the user PATH if not present
REM 7) Instruct the user to open a new Command Prompt and run "dezcrwl -h"
REM ---------------------------------------------------------

REM ----- Step 0: Check prerequisites (Git & Python) -----
where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git is not installed or not on PATH. Please install Git.
    exit /b 1
)

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not on PATH. Please install Python 3.x.
    exit /b 1
)

REM ----- Step 1: Clone or update the repository -----
set "TARGET_DIR=%USERPROFILE%\dezcrwl"
if exist "%TARGET_DIR%\.git" (
    echo Repository already exists in %TARGET_DIR%. Pulling latest changes...
    pushd "%TARGET_DIR%"
    git pull
    popd
) else (
    echo Cloning repository into %TARGET_DIR%...
    git clone https://github.com/zebbern/dezcrwl.git "%TARGET_DIR%"
)

REM ----- Step 2: Change to the repository directory and install dependencies -----
pushd "%TARGET_DIR%"
echo Upgrading pip and installing required packages...
python -m pip install --upgrade pip
python -m pip install aiohttp argparse asyncio colorama python-dateutil logging pyyaml pystyle requests
python -m pip install --upgrade pyinstaller

REM ----- Step 3: Ensure dezcrwl.py exists -----
if not exist "dezcrwl.py" (
    echo [INFO] dezcrwl.py not found in %TARGET_DIR%.
    echo Attempting to update repository...
    git fetch --all
    git reset --hard origin/master
)

if not exist "dezcrwl.py" (
    echo [ERROR] dezcrwl.py still not found after updating repository.
    exit /b 1
)

REM ----- Step 4: Build the standalone executable using PyInstaller -----
echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist dezcrwl.spec del /f /q dezcrwl.spec

echo Building executable with PyInstaller...
python -m PyInstaller --onefile --name dezcrwl dezcrwl.py

if not exist "dist\dezcrwl.exe" (
    echo [ERROR] Build failed. Please check the PyInstaller output above.
    exit /b 1
)

REM ----- Step 5: Move the executable to a folder in PATH (%USERPROFILE%\bin) -----
set "INSTALL_DIR=%USERPROFILE%\bin"
if not exist "%INSTALL_DIR%" (
    echo Creating folder %INSTALL_DIR%...
    mkdir "%INSTALL_DIR%"
)

echo Moving executable to "%INSTALL_DIR%\dezcrwl.exe"...
move /Y "dist\dezcrwl.exe" "%INSTALL_DIR%\dezcrwl.exe"

REM ----- Step 6: Automatically add %USERPROFILE%\bin to the user PATH if not already present -----
echo Checking if %INSTALL_DIR% is in your PATH...
echo %PATH% | find /I "%INSTALL_DIR%" >nul
if errorlevel 1 (
    echo %INSTALL_DIR% not found in PATH. Adding it now...
    REM Append %INSTALL_DIR% to the existing user PATH
    set "NEWPATH=%PATH%;%INSTALL_DIR%"
    REM Use setx to update the user environment; note that this won't affect the current session.
    setx PATH "%NEWPATH%" >nul
    echo PATH updated. Please open a new Command Prompt for changes to take effect.
) else (
    echo %INSTALL_DIR% is already in PATH.
)

popd

REM ----- Step 7: Final instructions -----
echo.
echo ============================================
echo [SUCCESS] Installation complete!
echo.
echo Open a NEW Command Prompt or PowerShell window and type:
echo     dezcrwl -h
echo to test the installation.
echo ============================================
pause
endlocal
