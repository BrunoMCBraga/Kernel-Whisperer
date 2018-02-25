#include <Fltkernel.h>
#include <ntstrsafe.h>
#include "FileSystemMonitor.h"
#include "Util.h"

#define MAX_LOG_BUFFER_SIZE 2000
#define VOLUME_INFORMATION_SIZE 200
#define FILE_NAME_SIZE_MAX 200

PFLT_FILTER gFilterHandle;

FLT_PREOP_CALLBACK_STATUS FileSystemFilterPreOperationCallback (PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)

{	
	
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FileSystemFilterPostOperationCallback (PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{

	NTSTATUS tempStatus = STATUS_SUCCESS;
	WCHAR* operationResult = NULL;
	ULONG processId = 0;
	PVOID logStringBuffer;
	PUNICODE_STRING logString; 
	PUNICODE_STRING volumeName;
	VOID* volumeNameBuffer;
	ULONG volumeBytesReturned;
	LARGE_INTEGER currentTime;
	

	processId = FltGetRequestorProcessId(Data);
	if (processId == 0){
		DbgPrint("FileSystemFilter's FltGetRequestorProcessId failed.");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	KeQuerySystemTime(&currentTime);

	switch(Data->IoStatus.Information){
		case FILE_CREATED:
			operationResult = L"FILE_CREATED";
			break;
		case FILE_DOES_NOT_EXIST:
			operationResult = L"FILE_DOES_NOT_EXIST";
			break;
		case FILE_EXISTS:
			operationResult = L"FILE_EXISTS";
			break;
		case FILE_OPENED:
			operationResult = L"FILE_OPENED";
			break;
		case FILE_OVERWRITTEN:
			operationResult = L"FILE_OVERWRITTEN";
			break;
		case FILE_SUPERSEDED:
			operationResult = L"FILE_SUPERSEDED";
			break;
		default:
			operationResult = L"FILE_RESULT_UNKNOWN";
			break;


	}

	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE){
		
		logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
		if (logStringBuffer == NULL){
			DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->ExAllocatePool failed to allocate space.\n");
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);

		volumeName = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
		if (volumeName == NULL){
			DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->ExAllocatePool failed to allocate space for volume name unicode string.\n");
			ExFreePool(logStringBuffer);
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		RtlZeroMemory(volumeName, sizeof(UNICODE_STRING));

		volumeNameBuffer = ExAllocatePool(NonPagedPool, VOLUME_INFORMATION_SIZE);

		if (volumeNameBuffer == NULL){
			DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->ExAllocatePool failed to allocate space for volume.\n");
			ExFreePool(logStringBuffer);
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		RtlZeroMemory(volumeNameBuffer, VOLUME_INFORMATION_SIZE);
		volumeName->Buffer = volumeNameBuffer;
		volumeName->Length = 0;
		volumeName->MaximumLength = VOLUME_INFORMATION_SIZE;

		tempStatus = FltGetVolumeName(FltObjects->Volume, volumeName, &volumeBytesReturned);
		if(!NT_SUCCESS(tempStatus)){
			if (tempStatus == STATUS_INVALID_PARAMETER){
	    		DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->FltGetVolumeName: STATUS_BUFFER_OVERFLOW\n"); 
	    	}
	    	else if (tempStatus == STATUS_BUFFER_TOO_SMALL){
	    		DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->FltGetVolumeName: STATUS_INVALID_PARAMETER\n"); 
	    	}
	    	ExFreePool(logStringBuffer);
	    	RtlFreeUnicodeString(volumeName);
	    	return FLT_POSTOP_FINISHED_PROCESSING;
    	}


		

    	//This is a terrible solution but i cannot check whether the filename is valid or not. I have tried to use kernel functions to inspect the characteristics of the file being opened but with volumes, they 
    	//either cause blue screens or fail. The case where the volume is opened as a file is a corner case and requires me to check whether the string on the buffer is printable. Cannot think of a better way to do this for now.
    	if((FltObjects->FileObject->FileName.Length > 2) && (hasInvalidCharacters(&(FltObjects->FileObject->FileName)) == 0)){//dword should have at least 2 bytes...

    		if(FltObjects->FileObject->FileName.Buffer[0] == L'\\')
    			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%s<-->%wZ%wZ", L"FILE", currentTime.QuadPart, processId, operationResult, volumeName, FltObjects->FileObject->FileName);
			else
		 		tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%s<-->%wZ\\%wZ", L"FILE", currentTime.QuadPart, processId, operationResult, volumeName, FltObjects->FileObject->FileName);
		}
		else 
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%s<-->%wZ", L"FILE", currentTime.QuadPart, processId, operationResult, volumeName);
		

		if(!NT_SUCCESS(tempStatus)){
			if (tempStatus == STATUS_BUFFER_OVERFLOW){
	    		DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
	    	}
	    	else if (tempStatus == STATUS_INVALID_PARAMETER){
	    		DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
	    	}
	    	ExFreePool(logStringBuffer);
	    	RtlFreeUnicodeString(volumeName);
	    	return FLT_POSTOP_FINISHED_PROCESSING;
    	}

    	logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
    	if(logString == NULL){
    		DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->ExAllocatePool failed to allocate memory for log string.\n");
    		ExFreePool(logStringBuffer);
	    	RtlFreeUnicodeString(volumeName);
	    	return FLT_POSTOP_FINISHED_PROCESSING;
    	}
    	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

    	RtlInitUnicodeString(logString, logStringBuffer);
    	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
    		DbgPrint("FileSystemFilter->FileSystemFilterPostOperationCallback->RtlInitUnicodeString failed to create unicode string.\n"); 
	    	ExFreePool(logStringBuffer);
	    	ExFreePool(logString);
	    	RtlFreeUnicodeString(volumeName);
    		return FLT_POSTOP_FINISHED_PROCESSING;
    	}
    	addNode(logString);
	   	RtlFreeUnicodeString(volumeName);
    	RtlFreeUnicodeString(logString);

	}

	return FLT_POSTOP_FINISHED_PROCESSING;

}


NTSTATUS DfUnload (FLT_FILTER_UNLOAD_FLAGS Flags){

	DbgPrint("FileSystemFilter is being unloaded.\n");
    FltUnregisterFilter( gFilterHandle );
    return STATUS_SUCCESS;
}