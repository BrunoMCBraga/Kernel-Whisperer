#include <iostream>
#include <sstream>
#include <thread>
#include <windows.h> 
#include "util"
#include "kerneleventsprocessor"
#include "apieventsprocessor"
#include "client"

using namespace std; 

#define MAX_HOSTNAME_BUFFER_SIZE 100
#define MAX_HOSTNAME_BUFFER_SIZE_WIDE 200

int main()  
{  
   DWORD currentPid = GetCurrentProcessId();
   SQLDriver* sqlDriver = SQLDriver::getInstance();
   KernelEventsProcessor kernelEventsProcessor;
   APIEventsProcessor apiEventsProcessor;


   WSADATA wsaData;
   char hostName[MAX_HOSTNAME_BUFFER_SIZE] = {'\0'};
   wchar_t hostNameWide[MAX_HOSTNAME_BUFFER_SIZE_WIDE] = {'\0'};
   struct hostent* hEnt = NULL;
   std::ostringstream hostStringStream;

   // Initialize Winsock
   if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0){
      std::cout << "KernelEventsProcessor->run->WSAStartup failed:" << std::hex << WSAGetLastError() << std::endl;
      return 1;
   }

   if(gethostname(hostName, MAX_HOSTNAME_BUFFER_SIZE) != 0){

      std::cout << "KernelEventsProcessor->run->gethostname failed:" << std::hex << WSAGetLastError() << std::endl;
      return 1; 
   }

   hEnt = gethostbyname(hostName);
   if(hEnt == NULL){
      std::cout << "KernelEventsProcessor->run->gethostbyname failed." << std::endl;
      return 1;
   }

   WSACleanup();

   hostStringStream << std::string(hEnt->h_name);

   if(mbstowcs(hostNameWide, hostStringStream.str().c_str(), MAX_HOSTNAME_BUFFER_SIZE_WIDE) <= 0)
   {
      std::cout << "KernelEventsProcessor->run->mbstowcs failed." << std::endl;
      return 1; 
   }

   sqlDriver->initDB();
   Util::setDebugPrivilege();
   
   std::thread kEPThread (kernelEventsProcessor.run, currentPid, std::wstring(hostNameWide));
   std::thread apiEPThread (apiEventsProcessor.run, currentPid, std::wstring(hostNameWide));

   kEPThread.join();
   apiEPThread.join();
}  