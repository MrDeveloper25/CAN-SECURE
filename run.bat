@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set "VENV=.venv-win"
set "PY=%VENV%\Scripts\python.exe"

if not exist "%PY%" (
    echo Creando entorno virtual en %VENV% ...
    py -3 -m venv "%VENV%" || (
        echo No se encontro el lanzador "py". Instala Python desde https://www.python.org/downloads/
        pause
        exit /b 1
    )
    echo Instalando dependencias ...
    "%PY%" -m pip install --disable-pip-version-check -q -r requirements.txt || (
        echo Fallo la instalacion de dependencias.
        pause
        exit /b 1
    )
)

:menu
echo.
echo ===================== CAN-Secure =====================
echo  1. Pruebas manuales (menu interactivo)
echo  2. Ejecutar todas las pruebas
echo  3. Comparacion baseline vs CAN-Secure
echo  4. Demo sin proteccion (baseline)
echo  5. Demo con CAN-Secure
echo  0. Salir
echo ======================================================
set "OPT="
set /p "OPT=Elige una opcion: "

if "%OPT%"=="1" "%PY%" -m eval.manual_test
if "%OPT%"=="2" "%PY%" -m eval.manual_test --all
if "%OPT%"=="3" "%PY%" -m eval.comparison
if "%OPT%"=="4" "%PY%" -m eval.baseline_run
if "%OPT%"=="5" "%PY%" -m eval.secure_run
if "%OPT%"=="0" exit /b 0
goto menu
