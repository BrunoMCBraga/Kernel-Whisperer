SET INCLUDE=%INCLUDE%%cd%\Detours\include;
SET LIB=%LIB%%cd%\Detours\lib.X86;

SET MAKEFILE=makefile.mak

SET DLL_DIR=APIMonitor
SET DLL_NAME=apimonitor.dll

SET DLL_FULL_PATH=%DLL_DIR%\bin\%DLL_NAME%
SET STAGING_DIR=%DLL_DIR%\staging

SET CLIENT_NAME=client.exe

cd Client
nmake /f %MAKEFILE% all
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd bin
start .\%CLIENT_NAME%
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd ..\..

cd APIMonitor
nmake /f %MAKEFILE% all
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd ..

ECHO Signing DLL
signtool sign /v /f %STAGING_DIR%\testing.pfx /t http://timestamp.globalsign.com/scripts/timestamp.dll %DLL_FULL_PATH%


REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f /v RequireSignedAppInit_DLLs  /t REG_DWORD /d 0
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f /v LoadAppInit_DLLs  /t REG_DWORD /d 1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f /v AppInit_DLLs  /t REG_SZ /d "C:\Users\user\Desktop\Driver\APIMON~1\bin\APIMON~1.DLL"


REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /f /v RequireSignedAppInit_DLLs  /t REG_DWORD /d 0
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /f /v LoadAppInit_DLLs  /t REG_DWORD /d 1
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /f /v AppInit_DLLs  /t REG_SZ /d "C:\Users\user\Desktop\Driver\APIMON~1\bin\APIMON~1.DLL"