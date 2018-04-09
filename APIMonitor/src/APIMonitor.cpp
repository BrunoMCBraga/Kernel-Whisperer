#include <windows.h>
#include <iostream>
#include <sstream>
#include "detours.h"
#include "APIMonitor"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

#define MAX_ERROR_MESSAGE_SIZE 200
#define MUTEX_NAME "KernelWhispererDetoursMutex"

static HANDLE mutex;

BOOL sendAPIEvent(wchar_t* apiEventString){

	DWORD writtenBytes;
	BOOL result;
	std::ostringstream errorStringStream;
	std::wstringstream eventStringStream;
	FILETIME timeStampFT;
	ULONGLONG timeStamp;
	std::wstring finalEventString;
	HANDLE hSlot;
	DWORD waitResult;

	waitResult = WaitForSingleObject(mutex, INFINITE);

	switch(waitResult){
		case WAIT_FAILED:
			OutputDebugString("APIMonitor->sendAPIEvent->WaitForSingleObject failed: WAIT_FAILED");
	    	return FALSE;
		break;
		case WAIT_ABANDONED:
			OutputDebugString("APIMonitor->sendAPIEvent->WaitForSingleObject failed: WAIT_ABANDONED");
	    	return FALSE;
		break;
	}

	hSlot = CreateFile("\\\\.\\mailslot\\kw_mailslot", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE) NULL);
	if(hSlot == INVALID_HANDLE_VALUE){
		errorStringStream << "APIMonitor->sendAPIEvent->CreateFile failed:" << std::hex << GetLastError();
		OutputDebugString((LPCSTR) errorStringStream.str().c_str());
    	if(!ReleaseMutex(mutex)){
    		OutputDebugString("APIMonitor->sendAPIEvent->ReleaseMutex failed.");
    	}
    	return FALSE;
	}


	GetSystemTimeAsFileTime(&timeStampFT);
	timeStamp = (((ULONGLONG) timeStampFT.dwHighDateTime) << 32) + timeStampFT.dwLowDateTime;
	eventStringStream << L"API<-->" << timeStamp << L"<-->" << GetCurrentProcessId() << L"<-->" << std::wstring(apiEventString);
	finalEventString = eventStringStream.str();
	result = WriteFile(hSlot, (LPCVOID) finalEventString.c_str(), (finalEventString.size()+1)*sizeof(wchar_t), &writtenBytes, (LPOVERLAPPED) NULL);

	if(!result){
		errorStringStream << "APIMonitor->sendAPIEvent->WriteFile failed:" << std::hex << GetLastError();
		OutputDebugString((LPCSTR) errorStringStream.str().c_str());
      	CloseHandle(hSlot);
      	if(!ReleaseMutex(mutex)){
    		OutputDebugString("APIMonitor->sendAPIEvent->ReleaseMutex failed.");
    	}
      	return FALSE;
	}

	CloseHandle(hSlot);
	if(!ReleaseMutex(mutex)){
    		OutputDebugString("APIMonitor->sendAPIEvent->ReleaseMutex failed.");
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

	std::ostringstream errorStringStream;

	if (DetourIsHelperProcess()) {
        return TRUE;
    }
    
	switch(fdwReason){
		case DLL_PROCESS_ATTACH:
			OutputDebugString("Attached\n");
			mutex = CreateMutex(NULL, FALSE, MUTEX_NAME);
			//If the caller has limited access rights, the function will fail with ERROR_ACCESS_DENIED and the caller should use the OpenMutex function.
			if(mutex == NULL){
				errorStringStream << "APIMonitor->DllMain->CreateMutex failed:" << std::hex << GetLastError();
				OutputDebugString(errorStringStream.str().c_str());
				if(GetLastError() == ERROR_ACCESS_DENIED)
				{
					mutex = OpenMutex(SYNCHRONIZE ,FALSE, MUTEX_NAME);
					if(mutex == NULL){
						errorStringStream.str("");
						errorStringStream << "APIMonitor->DllMain->OpenMutex failed:" << std::hex << GetLastError();
						OutputDebugString(errorStringStream.str().c_str());
						return FALSE;
					}
				}
				else{
					return FALSE;
				}
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
		break;



	}
	return TRUE;


}