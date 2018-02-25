REM Notes: Driver files to be compiled should be on a Driver\src (C files) abd Driver\lib (header files). The Inf file should be on the same path as this cmd file.
SET DRIVER_DIR=Driver
SET DRIVER_SYS=KernelWhispererDriver.sys
SET SERVICE_NAME=kernelwhispererdriver
SET INF_FILE=KernelWhisperer.inf
SET SRC_DIR=%DRIVER_DIR%\src
SET BIN_DIR=%DRIVER_DIR%\bin
SET DRIVER_FULL_PATH=%BIN_DIR%\amd64\%DRIVER_SYS%
SET STAGING_DIR=%DRIVER_DIR%\staging

Rmdir /s %BIN_DIR% /q
::Rmdir /s %STAGING_DIR% /q
mkdir %BIN_DIR%
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
::mkdir %STAGING_DIR%
::IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%

ECHO Compiling driver...
cd %SRC_DIR%
build
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd ..\..\



::ECHO Making PVK/CER...
::makecert -sv %STAGING_DIR%\testing.pvk -n "CN=Test Signing Cert" %STAGING_DIR%\testing.cer -b 06/19/2017 -e 06/19/2067 -r 
::IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%

::ECHO Making PFX file...
::pvk2pfx -pvk %STAGING_DIR%\testing.pvk -spc %STAGING_DIR%\testing.cer -pfx %STAGING_DIR%\testing.pfx 
::IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%


ECHO Signing Driver
signtool sign /v /f %STAGING_DIR%\testing.pfx /t http://timestamp.globalsign.com/scripts/timestamp.dll %DRIVER_FULL_PATH%


ECHO Moving signed driver and Inf file to staging directory...
cp %DRIVER_FULL_PATH% %STAGING_DIR%
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cp %INF_FILE% %STAGING_DIR%
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd %STAGING_DIR%

REM This is not working. Whenever i try to  run this manually, it complains about a missing line on the INF file....Use Right0click->Install on the INF file.
ECHO Installing Driver
::InstallHinfSection <section> <mode> <path>
rundll32 setupapi, InstallHinfSection DefaultInstall 132 .\%INF_FILE% 
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd ..

ECHO Launching Driver
sc start %SERVICE_NAME%
