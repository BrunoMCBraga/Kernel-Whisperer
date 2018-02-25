all: clean client.exe  

clean:
	del /S /Q bin\*
  
client.exe:  
  cl /EHsc /I lib\  src\*.cpp /link /out:bin\client.exe  
  
