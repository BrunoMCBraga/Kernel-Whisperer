#include <windows.h>
#include <iostream>
#include <sstream>
#include "detours.h"
#include "APIMonitor"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

#define MAX_ERROR_MESSAGE_SIZE 200

static HANDLE hSlot;

BOOL sendAPIEvent(wchar_t* apiEventString){

	DWORD writtenBytes;
	BOOL result;
	std::ostringstream errorStringStream;
	std::wstringstream eventStringStream;
	FILETIME timeStampFT;
	ULONGLONG timeStamp;
	std::wstring finalEventString;

	GetSystemTimeAsFileTime(&timeStampFT);
	timeStamp = (((ULONGLONG) timeStampFT.dwHighDateTime) << 32) + timeStampFT.dwLowDateTime;
	eventStringStream << L"API<-->" << timeStamp << L"<-->" << GetCurrentProcessId() << L"<-->" << std::wstring(apiEventString);
	finalEventString = eventStringStream.str();
	result = WriteFile(hSlot, (LPCVOID) finalEventString.c_str(), (finalEventString.size()+1)*sizeof(wchar_t), &writtenBytes, (LPOVERLAPPED) NULL);

	if(!result){
		errorStringStream << "APIMonitor->sendAPIEvent->WriteFile failed:" << std::hex << GetLastError();
		OutputDebugString((LPCSTR) errorStringStream.str().c_str());
      	return FALSE;
	}

	return TRUE;
}


static BOOL (WINAPI *pWriteProcessMemory)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer,SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten) = WriteProcessMemory;
static BOOL (WINAPI * pAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) = AdjustTokenPrivileges;


//BOOL WINAPI WriteProcessMemory(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer,SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten);
BOOL WINAPI dWriteProcessMemory(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer,SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten){

	BOOL res = FALSE;
	OutputDebugString("WriteProcessMemory called.\n");
	sendAPIEvent(L"WriteProcessMemory");
	res = pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	return res;

}



//BOOL WINAPI AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength,PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
BOOL WINAPI dAdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength){

	BOOL res = FALSE;
	OutputDebugString("AdjustTokenPrivileges called.\n");
	sendAPIEvent(L"AdjustTokenPrivileges");
	res = pAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
	return res; 

}



BOOL detoursAttach(PVOID* pointerToRealFunction, PVOID pointerToProxy){

	DetourTransactionBegin();
            
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(pointerToRealFunction, pointerToProxy);
    
    if (DetourTransactionCommit() != NO_ERROR){
    	OutputDebugString("APIMonitor->detoursAttach->DetourTransactionCommit failed.");
    	return FALSE;
    }

    return TRUE;
}


BOOL detoursDetach(PVOID* pointerToRealFunction, PVOID pointerToProxy){

	DetourTransactionBegin();
            
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(pointerToRealFunction, pointerToProxy);
    
    if (DetourTransactionCommit() != NO_ERROR){
    	OutputDebugString("APIMonitor->detoursDetach->DetourTransactionCommit failed.");
    	return FALSE;
    }

    return TRUE;
}


//AdjustTokenPrivileges

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){

	SECURITY_ATTRIBUTES securityAttributes = {'\0'};
	std::ostringstream errorStringStream;

	if (DetourIsHelperProcess()) {
        return TRUE;
    }
    //TODO: for iexplorer, the child process is unable to access the slot due to access denied. This does not
    //happen with FireFox. The problem is solved if i run Iexplorer as admin..
	switch(fdwReason){
		case DLL_PROCESS_ATTACH:
			OutputDebugString("Attached\n");
			securityAttributes.bInheritHandle = TRUE;
			
			hSlot = CreateFile("\\\\.\\mailslot\\kw_mailslot", GENERIC_WRITE, FILE_SHARE_READ, &securityAttributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE) NULL);
			if(hSlot == INVALID_HANDLE_VALUE){
				errorStringStream << "APIMonitor->DllMain->CreateFile failed:" << std::hex << GetLastError();
				OutputDebugString((LPCSTR) errorStringStream.str().c_str());
		    	return FALSE;
			}

			DisableThreadLibraryCalls(hinstDLL);
            DetourRestoreAfterWith();
            
            if(!detoursAttach((PVOID*)&pWriteProcessMemory, dWriteProcessMemory)){
            	OutputDebugString("APIMonitor->DllMain(DLL_PROCESS_ATTACH)->detoursAttach(WriteProcessMemory) failed.\n");
            }
            
            if(!detoursAttach((PVOID*)&pAdjustTokenPrivileges, dAdjustTokenPrivileges)){
	       		OutputDebugString("APIMonitor->DllMain(DLL_PROCESS_ATTACH)->detoursDetach(AdjustTokenPrivileges) failed.\n");
	       	}
            
            OutputDebugString("Committed Transaction (Attached).\n");
		break;
		case DLL_PROCESS_DETACH:
			OutputDebugString("Detached\n");

			if(!detoursDetach((PVOID*)&pWriteProcessMemory, dWriteProcessMemory)){
				OutputDebugString("APIMonitor->DllMain(DLL_PROCESS_DETACH)->detoursDetach(WriteProcessMemory) failed.\n");
			}
			
	      	
			if(!detoursDetach((PVOID*)&pAdjustTokenPrivileges, dAdjustTokenPrivileges)){
	       		OutputDebugString("APIMonitor->DllMain(DLL_PROCESS_DETACH)->detoursDetach(AdjustTokenPrivileges) failed.\n");
	       	}

           	OutputDebugString("Committed Transaction (Detached).\n");
           	CloseHandle(hSlot);
		break;



	}
	return TRUE;


}