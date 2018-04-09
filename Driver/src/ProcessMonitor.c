#include <ntstatus.h>
#include <ntstrsafe.h>
#include <ProcessMonitor.h>
#include "Util.h"

#define MAX_LOG_BUFFER_SIZE 5000


VOID PcreateProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo){

	NTSTATUS tempStatus;
	UINT64 processId;
	LARGE_INTEGER currentTime;
	PUNICODE_STRING logString;
	PVOID logStringBuffer;
	PUNICODE_STRING imageFileName;
	PUNICODE_STRING commandLine;
	

	KeQuerySystemTime(&currentTime);

	logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
		if (logStringBuffer == NULL){
			DbgPrint("ProcessMonitor->PcreateProcessNotifyRoutineEx->ExAllocatePool failed to allocate space.\n");
			return;
		}

	RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);
	

	if(CreateInfo != NULL){

		imageFileName = CreateInfo->ImageFileName != NULL ? CreateInfo->ImageFileName : NULL;
		commandLine = CreateInfo->CommandLine != NULL ? CreateInfo->CommandLine : NULL;

		if(imageFileName != NULL){
			if(commandLine != NULL){
				tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%d<-->%d<-->%wZ<-->%wZ<-->%ls", L"PROC", currentTime.QuadPart, ProcessId, CreateInfo->ParentProcessId, imageFileName, commandLine, L"S");
			}
			else{
				tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%d<-->%d<-->%wZ<-->%ls<-->%ls", L"PROC", currentTime.QuadPart, ProcessId, CreateInfo->ParentProcessId, imageFileName, L"-", L"S");	
			}

		}
		else {

			if(commandLine != NULL){
				tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%d<-->%d<-->%ls<-->%wZ<-->%ls", L"PROC", currentTime.QuadPart, ProcessId, CreateInfo->ParentProcessId, L"-", commandLine, L"S");
			}
			else{
				tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%d<-->%d<-->%ls<-->%ls<-->%ls", L"PROC", currentTime.QuadPart, ProcessId, CreateInfo->ParentProcessId, L"-", L"-", L"S");	
			}

		}
	
	}

	else{

		tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%d<-->%d<-->%ls<-->%ls<-->%ls", L"PROC", currentTime.QuadPart, ProcessId, 0, L"-", L"-", L"T");

	}


	if(!NT_SUCCESS(tempStatus)){
				if (tempStatus == STATUS_BUFFER_OVERFLOW){
		    		DbgPrint("ProcessMonitor->PcreateProcessNotifyRoutineEx->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
		    	}
		    	else if (tempStatus == STATUS_INVALID_PARAMETER){
		    		DbgPrint("ProcessMonitor->PcreateProcessNotifyRoutineEx->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
		    	}
		    	ExFreePool(logStringBuffer);
		    	
		    	return;
	    }

	    logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
    	if(logString == NULL){
    		DbgPrint("ProcessMonitor->PcreateProcessNotifyRoutineEx->ExAllocatePool failed to allocate memory for log string.\n");
    		ExFreePool(logStringBuffer);
	    	return;
    	}
    	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

    	RtlInitUnicodeString(logString, logStringBuffer);
    	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
    		DbgPrint("ProcessMonitor->PcreateProcessNotifyRoutineEx->RtlInitUnicodeString failed to create unicode string.\n"); 
	    	ExFreePool(logStringBuffer);
	    	ExFreePool(logString);
    		return;
    	}
		
		addNode(logString);
		
}
