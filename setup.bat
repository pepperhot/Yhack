@echo off
REM Setup script for YHACK - replaces old files with refactored versions
REM Run this from the Yhack root directory

echo.
echo ========================================
echo YHACK - Setup & File Replacement
echo ========================================
echo.

REM Check if files exist
if not exist "script_new.js" (
    echo ERROR: script_new.js not found!
    echo Make sure you're in the Yhack root directory
    exit /b 1
)

if not exist "styles_new.css" (
    echo ERROR: styles_new.css not found!
    exit /b 1
)

if not exist "server\scanManager_new.js" (
    echo ERROR: server\scanManager_new.js not found!
    exit /b 1
)

echo [1/3] Replacing script.js...
del /q script.js
ren script_new.js script.js
if errorlevel 1 goto error

echo [2/3] Replacing styles.css...
del /q styles.css
ren styles_new.css styles.css
if errorlevel 1 goto error

echo [3/3] Replacing server\scanManager.js...
del /q server\scanManager.js
ren server\scanManager_new.js server\scanManager.js
if errorlevel 1 goto error

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Copy .env.example to .env and configure (optional)
echo 2. Run: npm install
echo 3. Run: npm start
echo.
exit /b 0

:error
echo.
echo ERROR during file replacement!
echo Please check that all files exist and try again.
exit /b 1
