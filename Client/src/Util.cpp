#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h> 
#include <iostream>
#include <string>
#include <tchar.h>
#include <cstdlib>
#include <regex>
#include "util"

using namespace std; 

#define MAX_PATH_LENGTH 1000
#define MAX_PATH_LENGTH_WIDE 2000


void Util::setDebugPrivilege(){


	TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE tokenHandle;

    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_READ|TOKEN_WRITE,&tokenHandle)){
    	std::cout << "Util->setDebugPrivilege->OpenProcessToken failed:" << std::hex << GetLastError() << std::endl;
    	return;
    }

    if ( !LookupPrivilegeValue( 
            NULL,            // lookup privilege on local system
            SE_DEBUG_NAME,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return;// FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           tokenHandle, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return;// FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return;// FALSE;
    } 

    //return TRUE;

}

std::wstring Util::getImagePath(unsigned long long pid){

	  HANDLE processHandle = NULL;
	  char imageFilePath[MAX_PATH_LENGTH] = {0};
	  wchar_t imageFilePathWide[MAX_PATH_LENGTH_WIDE] = {L'\0'};
	  std::wstring defaultString = std::wstring(L"");
	  DWORD sizeOfBuffer = MAX_PATH_LENGTH;

	  if(pid == 0)
	  	return defaultString;

	
	processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if(processHandle == NULL){
		std::cout << "Util->getParentPid->OpenProcess failed:" << std::hex << GetLastError() << std::endl;	
		
		return std::wstring(imageFilePathWide); 
	}

	if(QueryFullProcessImageName(processHandle, PROCESS_NAME_NATIVE, imageFilePath, &sizeOfBuffer) == 0){
		std::cout << "Util->getParentPid->QueryFullProcessImageName failed:" << std::hex << GetLastError() << std::endl;	
		CloseHandle(processHandle);
		return std::wstring(imageFilePathWide); 	
	}


	_stprintf(imageFilePath, "%s", imageFilePath);
	mbstowcs(imageFilePathWide, imageFilePath, MAX_PATH_LENGTH_WIDE);
	
	CloseHandle(processHandle);
	return std::wstring(imageFilePathWide); 
}


unsigned long long Util::getParentPid(unsigned long long pid){

	unsigned long long dwParentProcessID = 0;
	HANDLE hProcessSnapshot;
	PROCESSENTRY32 processEntry32;

	if(pid == 0)
		return dwParentProcessID;
	
	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) ;
	if(hProcessSnapshot != INVALID_HANDLE_VALUE)
	{
		processEntry32.dwSize = sizeof(PROCESSENTRY32) ;
		if(Process32First(hProcessSnapshot, &processEntry32))
		{
			do
			{
				if (pid == processEntry32.th32ProcessID)
				{   
					dwParentProcessID = processEntry32.th32ParentProcessID ;
					break ;
				}
			}
			while(Process32Next(hProcessSnapshot, &processEntry32));
			
			CloseHandle(hProcessSnapshot) ;
		}

		else{
			
			std::cout << "Util->getParentPid->Process32First failed:" << std::hex << GetLastError() << std::endl;			
		}
	}

	else{

		std::cout << "Util->getParentPid->CreateToolhelp32Snapshot failed:" << std::hex << GetLastError() << std::endl;

	}

	return dwParentProcessID ;
}




std::wstring Util::escapeSpecialCharacters(std::wstring wst){

	std::wstring tempString;
	std::wregex backSlashRegex (std::wstring(L"\\\\"));
    std::wregex singleQuoteRegex (std::wstring(L"\\'"));
    std::wregex doubleQuoteRegex (std::wstring(L"\""));
    
    tempString = std::regex_replace(std::regex_replace(std::regex_replace(wst, backSlashRegex, std::wstring(L"\\\\")),singleQuoteRegex, std::wstring(L"\\'")),doubleQuoteRegex, std::wstring(L"\\\""));
    return tempString;


}