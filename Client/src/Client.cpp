#include <iostream>
#include <string>
#include <vector>
#include <windows.h> 
#include <stdlib.h>
#include <cstdlib>
#include "client"
#include "sqldriver"
#include "logparser"
#include "util"

using namespace std; 


#define IOCTL_KERNELWHISPERER_GETACTIVITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_LOG_BUFFER_SIZE 5000
#define MAX_HOSTNAME_BUFFER_SIZE 100
#define MAX_HOSTNAME_BUFFER_SIZE_WIDE 200


void sqlInsertProxy(std::vector<std::wstring> logComponents, DWORD currentPid, std::wstring hostname){

  unsigned long long parentPid;
  std::wstring pImagePath;
  std::wstring imagePath;


  SQLDriver sqlDriver;

  if(logComponents.size() == 0)
    return;

  
  
  if(currentPid == stoull(logComponents[2], NULL, 0))
    return;

  parentPid = (stoull(logComponents[2]) != 0) ? Util::getParentPid(stoull(logComponents[2])) : 0;
  pImagePath = (parentPid != 0) ? Util::escapeSpecialCharacters(Util::getImagePath(parentPid)) : std::wstring(L"");
  imagePath = (stoull(logComponents[2], NULL, 0) != 0) ? Util::escapeSpecialCharacters(Util::getImagePath(stoull(logComponents[2], NULL, 0))) : std::wstring(L"");

  if(logComponents[0].compare(std::wstring(L"REG")) == 0){
    if (logComponents[3].compare(std::wstring(L"CREATEKEY")) == 0){
      sqlDriver.insertRegistryEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath,  logComponents[3], logComponents[4], std::wstring(L""), std::wstring(L""));
    }
    else if (logComponents[3].compare(std::wstring(L"SETVALUE")) == 0){
      sqlDriver.insertRegistryEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3], logComponents[4], logComponents[5], logComponents[6]);  
    }
  }
  else if(logComponents[0].compare(std::wstring(L"FILE")) == 0){
    sqlDriver.insertFileEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3], logComponents[4]);
  }
  else if(logComponents[0].compare(std::wstring(L"NET")) == 0){
    
    sqlDriver.insertNetworkEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3], logComponents[4], logComponents[5], logComponents[6], logComponents[7], logComponents[8]);
  }
  else if(logComponents[0].compare(std::wstring(L"PROC")) == 0){
    sqlDriver.insertProcessEvent(logComponents[1], hostname, logComponents[3], pImagePath, logComponents[2], Util::escapeSpecialCharacters(logComponents[4]), Util::escapeSpecialCharacters(logComponents[5]));
  }

  else{
    std::wcout << L"Main->sqlInsertProxy failed: Unknown Log Tag (" << logComponents[0] << L")." << std::endl;
  }
}

int main()  
{  
   HANDLE hDevice;
   DWORD dwBytes;
   DWORD dwError = ERROR_SUCCESS;
   PWSTR driverRequestBuffer; 
   SQLDriver sqlDriver;
   WSADATA wsaData;

   DWORD currentPid = GetCurrentProcessId();
   char hostName[MAX_HOSTNAME_BUFFER_SIZE] = {'\0'};
   wchar_t hostNameWide[MAX_HOSTNAME_BUFFER_SIZE_WIDE] = {'\0'};
   struct hostent* hEnt = NULL;

   // Initialize Winsock
   if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0){
      std::cout << "Main->main->WSAStartup failed:" << std::hex << WSAGetLastError() << std::endl;
      return 1;
   }

   if(gethostname(hostName, MAX_HOSTNAME_BUFFER_SIZE) != 0){

      std::cout << "Main->main->gethostname failed:" << std::hex << WSAGetLastError() << std::endl;
      return 1; 
   }

   hEnt = gethostbyname(hostName);
   if(hEnt == NULL){
      std::cout << "Main->main->gethostbyname failed." << std::endl;
      return 1;
   }

   WSACleanup();

   if(sprintf(hostName, "%s", hEnt->h_name) < -1)
   {
      std::cout << "Main->main->sprintf failed." << std::endl;
      return 1;
   }  


   if(mbstowcs(hostNameWide, hostName, MAX_HOSTNAME_BUFFER_SIZE_WIDE) <= 0)
   {
      std::cout << "Main->main->mbstowcs failed." << std::endl;
      return 1; 
   }


   driverRequestBuffer = (PWSTR) calloc(MAX_LOG_BUFFER_SIZE,1);
   
   sqlDriver.initDB();
   Util::setDebugPrivilege();

   hDevice = CreateFile("\\\\.\\KernelWhisperer", GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
   if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "Main->CreateFile failed:" << std::hex << GetLastError() << std::endl;
        return dwError;
    }

    while(TRUE){
	    if (!DeviceIoControl(hDevice, IOCTL_KERNELWHISPERER_GETACTIVITY, NULL, 0, driverRequestBuffer, MAX_LOG_BUFFER_SIZE, &dwBytes, NULL))
	    {

          std::cout << "Main->DeviceIoControl failed:" << std::hex << GetLastError() << std::endl;
	        CloseHandle(hDevice);
	        return dwError;
	    }
      //Dwords so at least two bytes.
	    if((dwBytes > 2) && (dwBytes <= MAX_LOG_BUFFER_SIZE)){
        sqlInsertProxy(LogParser::parse(std::wstring(driverRequestBuffer)), currentPid, std::wstring(hostNameWide));
        memset(driverRequestBuffer, 0, dwBytes);
	    }
    }
    

}  