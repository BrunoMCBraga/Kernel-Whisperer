all: clean apimonitor.dll 

clean:
	del /S /Q bin\*
  
apimonitor.dll:  
  cl /D_USRDLL /D_WINDLL /EHsc /I lib\ src\*.cpp /link /DLL /out:bin\apimonitor.dll  
  
