SET MAKEFILE=makefile.mak
SET BINARY_NAME=client.exe

cd Client
nmake /f %MAKEFILE% all
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%
cd bin
.\%BINARY_NAME%
cd ..\..
