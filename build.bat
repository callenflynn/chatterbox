@echo off
REM Windows batch script to build Chatterbox executable

echo Installing PyInstaller...
pip install pyinstaller

echo Building Chatterbox executable...
pyinstaller --onefile --windowed --name chatterbox chatterbox.py

echo.
echo Build complete! 
echo Executable created at: dist\chatterbox.exe
echo.
echo To run the application:
echo   dist\chatterbox.exe
echo.
pause