SET MAKEFILE=makefile.mak
SET BINARY_NAME=client.exe

cd Client
nmake /f %MAKEFILE% all
cd bin
.\%BINARY_NAME%
cd ..\..
