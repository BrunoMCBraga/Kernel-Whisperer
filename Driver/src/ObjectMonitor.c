#define NDIS60 1 //Necessary for the network stuff. Will not work otherwise.
#include <ndis.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include "ObjectMonitor.h"
#include "Util.h"

#define MAX_LOG_BUFFER_SIZE 10000 //bytes
#define MAX_PERMISSION_BUFFER_SIZE 500 //bytes

wchar_t* accessMaskHexToString(ULONG hexMask){

	NTSTATUS tempStatus;
	wchar_t* arrayOfPermissions[9] = {0};
	PVOID permissionsStringBuffer = ExAllocatePool(NonPagedPool, MAX_PERMISSION_BUFFER_SIZE);

	if (permissionsStringBuffer == NULL){
		DbgPrint("ObjectMonitor->accessMaskHexToString->ExAllocatePool failed to allocate space for object log.\n");
		return NULL;
	}


	RtlZeroMemory(permissionsStringBuffer, MAX_PERMISSION_BUFFER_SIZE);

	/*

		https://msdn.microsoft.com/de-de/library/windows/desktop/aa374896(v=vs.85).aspx
	*/

	arrayOfPermissions[0] = ((hexMask & DELETE) != 0) ? L"DELETE" : NULL;
	arrayOfPermissions[1] = ((hexMask & READ_CONTROL) != 0) ? L"READ_CONTROL" : NULL;
	arrayOfPermissions[2] = ((hexMask & WRITE_DAC) != 0) ? L"WRITE_DAC" : NULL;
	arrayOfPermissions[3] = ((hexMask & WRITE_OWNER) != 0) ? L"WRITE_OWNER" : NULL;
	arrayOfPermissions[4] = ((hexMask & SYNCHRONIZE) != 0) ? L"SYNCHRONIZE" : NULL;


	arrayOfPermissions[5] = ((hexMask & GENERIC_READ) != 0) ? L"GENERIC_READ" : NULL;
	arrayOfPermissions[6] = ((hexMask & GENERIC_WRITE) != 0) ? L"GENERIC_WRITE" : NULL;
	arrayOfPermissions[7] = ((hexMask & GENERIC_EXECUTE) != 0) ? L"GENERIC_EXECUTE" : NULL;
	arrayOfPermissions[8] = ((hexMask & GENERIC_ALL) != 0) ? L"GENERIC_ALL" : NULL;

	tempStatus = RtlStringCbPrintfW(permissionsStringBuffer, MAX_PERMISSION_BUFFER_SIZE, L"|%ls|%ls|%ls|%ls|%ls|%ls|%ls|%ls|%ls|",(arrayOfPermissions[0] == NULL) ? L"-" : arrayOfPermissions[0], 
																																  (arrayOfPermissions[1] == NULL) ? L"-" : arrayOfPermissions[1], 
																																  (arrayOfPermissions[2] == NULL) ? L"-" : arrayOfPermissions[2],
																																  (arrayOfPermissions[3] == NULL) ? L"-" : arrayOfPermissions[3],
																																  (arrayOfPermissions[4] == NULL) ? L"-" : arrayOfPermissions[4],
																																  (arrayOfPermissions[5] == NULL) ? L"-" : arrayOfPermissions[5],
																																  (arrayOfPermissions[6] == NULL) ? L"-" : arrayOfPermissions[6],
																																  (arrayOfPermissions[7] == NULL) ? L"-" : arrayOfPermissions[7],
																																  (arrayOfPermissions[8] == NULL) ? L"-" : arrayOfPermissions[8]);
	if(!NT_SUCCESS(tempStatus)){
		if (tempStatus == STATUS_BUFFER_OVERFLOW){
    		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->accessMaskHexToString failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
    	}
    	else if (tempStatus == STATUS_INVALID_PARAMETER){
    		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->accessMaskHexToString failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
    	}
    	ExFreePool(permissionsStringBuffer);
    	return NULL;
	}																														  
	

	return (wchar_t*) permissionsStringBuffer;
}

OB_PREOP_CALLBACK_STATUS PobPreOperationCallbackProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation){

	//DbgPrint("PobPreOperationCallbackProcess called.\n");


	return OB_PREOP_SUCCESS;

}
void PobPostOperationCallbackProcess(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation){

	

	NTSTATUS tempStatus;
	ULONG processId = 0;
	PVOID logStringBuffer;
	PUNICODE_STRING logString;
	LARGE_INTEGER currentTime;
	wchar_t* permissionsArray;

	DbgPrint("PobPostOperationCallbackProcess called.\n");

	KeQuerySystemTime(&currentTime);

	processId = PsGetCurrentProcessId();

	logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
	if (logStringBuffer == NULL){
		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->ExAllocatePool failed to allocate space for object log.\n");
		return STATUS_UNSUCCESSFUL;
	}


	RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);
	if(NT_SUCCESS(OperationInformation->ReturnStatus)){
		permissionsArray = accessMaskHexToString((OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? OperationInformation->Parameters->CreateHandleInformation.GrantedAccess : OperationInformation->Parameters->DuplicateHandleInformation.GrantedAccess);
		if (permissionsArray != NULL){
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ld<-->%ls<-->%ls", L"OBJECT", currentTime.QuadPart, processId, L"PROCESS", PsGetProcessId(OperationInformation->Object),(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? L"OB_OPERATION_HANDLE_CREATE" : L"OB_OPERATION_HANDLE_DUPLICATE", permissionsArray);
			ExFreePool(permissionsArray);
		}
		else
		{
			DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->accessMaskHexToString returned null.\n");	
			ExFreePool(logStringBuffer);
			return;
		}
	}
	else
		tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ld<-->%ls", L"OBJECT", currentTime.QuadPart, processId, L"PROCESS", PsGetProcessId(OperationInformation->Object),(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? L"OB_OPERATION_HANDLE_CREATE" : L"OB_OPERATION_HANDLE_DUPLICATE");

	

	if(!NT_SUCCESS(tempStatus)){
		if (tempStatus == STATUS_BUFFER_OVERFLOW){
    		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
    	}
    	else if (tempStatus == STATUS_INVALID_PARAMETER){
    		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
    	}
    	ExFreePool(logStringBuffer);
    	return;
	}

	logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	if(logString == NULL){
		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->ExAllocatePool failed to allocate memory for log unicode structure.\n");
		ExFreePool(logStringBuffer);
    	return;
	}
	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

	RtlInitUnicodeString(logString, logStringBuffer);
	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
		DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->RtlInitUnicodeString failed to create unicode string.\n"); 
		ExFreePool(logString);
		ExFreePool(logStringBuffer);
		return;
	}
	
	addNode(logString);
	RtlFreeUnicodeString(logString);


		
	return STATUS_SUCCESS;

}

OB_PREOP_CALLBACK_STATUS PobPreOperationCallbackThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation){

	DbgPrint("PobPreOperationCallbackThread called.\n");
	return OB_PREOP_SUCCESS;

}

void PobPostOperationCallbackThread(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation){


	NTSTATUS tempStatus;
	ULONG processId = 0;
	PVOID logStringBuffer;
	PUNICODE_STRING logString;
	LARGE_INTEGER currentTime;
	wchar_t* permissionsArray;

	KeQuerySystemTime(&currentTime);

	processId = PsGetCurrentProcessId();

	logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
	if (logStringBuffer == NULL){
		DbgPrint("ObjectMonitor->PobPostOperationCallbackThread->ExAllocatePool failed to allocate space for object log.\n");
		return STATUS_UNSUCCESSFUL;
	}


	RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);
	//Will print verbatim ACCESS_MASK. Need to understand how to translate this into a string.
	if(NT_SUCCESS(OperationInformation->ReturnStatus)){
		permissionsArray = accessMaskHexToString((OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? OperationInformation->Parameters->CreateHandleInformation.GrantedAccess : OperationInformation->Parameters->DuplicateHandleInformation.GrantedAccess);
		if (permissionsArray != NULL){
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ld<-->%ls<-->%ls", L"OBJECT", currentTime.QuadPart, processId, L"THREAD", PsGetThreadProcessId(OperationInformation->Object),(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? L"OB_OPERATION_HANDLE_CREATE" : L"OB_OPERATION_HANDLE_DUPLICATE", permissionsArray);
			ExFreePool(permissionsArray);
		}
		else
		{
			DbgPrint("ObjectMonitor->PobPostOperationCallbackProcess->accessMaskHexToString returned null.\n");	
			ExFreePool(logStringBuffer);
			return;
		}
	}
	else
		tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ld<-->%ls", L"OBJECT", currentTime.QuadPart, processId, L"THREAD", PsGetThreadProcessId(OperationInformation->Object),(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) ? L"OB_OPERATION_HANDLE_CREATE" : L"OB_OPERATION_HANDLE_DUPLICATE");


	if(!NT_SUCCESS(tempStatus)){
		if (tempStatus == STATUS_BUFFER_OVERFLOW){
    		DbgPrint("ObjectMonitor->PobPostOperationCallbackThread->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
    	}
    	else if (tempStatus == STATUS_INVALID_PARAMETER){
    		DbgPrint("ObjectMonitor->PobPostOperationCallbackThread->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
    	}
    	ExFreePool(logStringBuffer);
    	return STATUS_UNSUCCESSFUL;
	}

	logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	if(logString == NULL){
		DbgPrint("ObjectMonitor->PobPostOperationCallbackThread->ExAllocatePool failed to allocate memory for log unicode structure.\n");
		ExFreePool(logStringBuffer);
    	return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

	RtlInitUnicodeString(logString, logStringBuffer);
	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
		DbgPrint("ObjectMonitor->PobPostOperationCallbackThread->RtlInitUnicodeString failed to create unicode string.\n"); 
		ExFreePool(logString);
		ExFreePool(logStringBuffer);
		return STATUS_UNSUCCESSFUL;
	}
	
	addNode(logString);
	RtlFreeUnicodeString(logString);


		
	return STATUS_SUCCESS;

}

OB_PREOP_CALLBACK_STATUS PobPreOperationCallbackDesktop(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation){

	//DbgPrint("PobPreOperationCallbackDesktop called.\n");
	return OB_PREOP_SUCCESS;

}

void PobPostOperationCallbackDesktop(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation){

	//DbgPrint("PobPostOperationCallbackDesktop called.\n");

}