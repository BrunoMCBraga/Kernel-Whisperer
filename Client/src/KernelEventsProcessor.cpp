#include <iostream>
#include <string>
#include <vector>
#include <windows.h> 
#include <stdlib.h>
#include "logparser"
#include "util"
#include "kerneleventsprocessor"

using namespace std; 

#define IOCTL_KERNELWHISPERER_GETACTIVITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_LOG_BUFFER_SIZE 5000


int KernelEventsProcessor::run(DWORD currentPid, std::wstring hostNameWide){


   HANDLE hDevice;
   DWORD dwBytes;
   DWORD dwError = ERROR_SUCCESS;
   PWSTR driverRequestBuffer; 
   

   driverRequestBuffer = (PWSTR) calloc(MAX_LOG_BUFFER_SIZE,1);
   
   Util::setDebugPrivilege();

   hDevice = CreateFile("\\\\.\\KernelWhisperer", GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
   if (hDevice == INVALID_HANDLE_VALUE)
   {
        std::cout << "KernelEventsProcessor->run->CreateFile failed:" << std::hex << GetLastError() << std::endl;
        return dwError;
   }

    while(TRUE){
	    if (!DeviceIoControl(hDevice, IOCTL_KERNELWHISPERER_GETACTIVITY, NULL, 0, driverRequestBuffer, MAX_LOG_BUFFER_SIZE, &dwBytes, NULL))
	    {

            std::cout << "KernelEventsProcessor->run->DeviceIoControl failed:" << std::hex << GetLastError() << std::endl;
	        CloseHandle(hDevice);
	        return dwError;
	    }
      //Dwords so at least two bytes.
	    if((dwBytes > 2) && (dwBytes <= MAX_LOG_BUFFER_SIZE)){
        SQLDriver::getInstance()->sqlInsertProxy(LogParser::parse(std::wstring(driverRequestBuffer)), currentPid, hostNameWide);
        memset(driverRequestBuffer, 0, dwBytes);
	    }
    }

}