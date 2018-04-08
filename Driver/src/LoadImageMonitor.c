#define NDIS60 1 //Necessary for the network stuff. Will not work otherwise.
#include <ndis.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include "LoadImageMonitor.h"
#include "Util.h"

//PLOAD_IMAGE_NOTIFY_ROUTINE PloadImageNotifyRoutine;

#define MAX_LOG_BUFFER_SIZE 10000 //bytes

//The operating system does not call load-image notify routines when sections created with the SEC_IMAGE_NO_EXECUTE attribute are mapped to virtual memory.
void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo){

	
	
	NTSTATUS tempStatus;
	ULONG processId = 0;
	PVOID logStringBuffer;
	PUNICODE_STRING logString;
	LARGE_INTEGER currentTime;


	KeQuerySystemTime(&currentTime);

	processId = PsGetCurrentProcessId();

	logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
	if (logStringBuffer == NULL){
		DbgPrint("LoadImageMonitor->PloadImageNotifyRoutine->ExAllocatePool failed to allocate space for loadimage log.\n");
		return;
	}


	RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);
	

	//The Function to detect Loaded Files has many bugs. One of them is the fact that dlls have no full names (i.e. no volume). I have tried other functions to get the volume but i am unable to. Something to correct later.
	//Not a big deal for my purposes. Also, we can leverage the File Table to search for DLLS or EXES opened around that time.
	if(FullImageName != NULL)
		tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ld<-->%wZ", L"LOADIMAGE", currentTime.QuadPart, processId, ProcessId, FullImageName);
	else
		tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ld<-->%wZ", L"LOADIMAGE", currentTime.QuadPart, processId, ProcessId, L"INVALID");
	
	
	if(!NT_SUCCESS(tempStatus)){
		if (tempStatus == STATUS_BUFFER_OVERFLOW){
    		DbgPrint("LoadImageMonitor->PloadImageNotifyRoutine->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
    	}
    	else if (tempStatus == STATUS_INVALID_PARAMETER){
    		DbgPrint("LoadImageMonitor->PloadImageNotifyRoutine->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
    	}
    	ExFreePool(logStringBuffer);
    	return;
	}

	logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	if(logString == NULL){
		DbgPrint("LoadImageMonitor->PloadImageNotifyRoutine->ExAllocatePool failed to allocate memory for log unicode structure.\n");
		ExFreePool(logStringBuffer);
    	return;
	}
	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

	RtlInitUnicodeString(logString, logStringBuffer);
	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
		DbgPrint("LoadImageMonitor->PloadImageNotifyRoutine->RtlInitUnicodeString failed to create unicode string.\n"); 
		ExFreePool(logString);
		ExFreePool(logStringBuffer);
		return;
	}
	
	addNode(logString);
	RtlFreeUnicodeString(logString);


		
	return STATUS_SUCCESS;


}