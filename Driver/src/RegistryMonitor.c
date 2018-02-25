#include <ntifs.h>
#include <ntstatus.h>
#include <ntstrsafe.h>
#include "Util.h"
#include "RegistryMonitor.h"


#define MAX_LOG_BUFFER_SIZE 10000


EX_CALLBACK_FUNCTION RegistryCallback;

ExtractKeyPath(PVOID registryObject, PUNICODE_STRING registryPathBuffer){

			NTSTATUS tempStatus = STATUS_SUCCESS;
			ULONG realSizeOfPobjectNameInformation;

			PVOID pobjectNameInformationBuffer = ExAllocatePool(NonPagedPool, 1);
			if (pobjectNameInformationBuffer == NULL){
				DbgPrint("RegistryFilter->ExtractKeyPath->ExAllocatePool failed.");
				return;
			}

			
			RtlZeroMemory(pobjectNameInformationBuffer, 1);
			tempStatus = ObQueryNameString(registryObject,(POBJECT_NAME_INFORMATION) pobjectNameInformationBuffer, 1, &realSizeOfPobjectNameInformation);
			
			if (tempStatus == STATUS_INFO_LENGTH_MISMATCH){
				ExFreePool(pobjectNameInformationBuffer);
				pobjectNameInformationBuffer = ExAllocatePool(NonPagedPool, realSizeOfPobjectNameInformation);
				if (pobjectNameInformationBuffer == NULL){
					DbgPrint("RegistryFilter->ExtractKeyPath->ExAllocatePool failed.");
					return;
				}
				RtlZeroMemory(pobjectNameInformationBuffer, realSizeOfPobjectNameInformation);
				tempStatus = ObQueryNameString(registryObject,(POBJECT_NAME_INFORMATION) pobjectNameInformationBuffer, realSizeOfPobjectNameInformation, &realSizeOfPobjectNameInformation);
				if(!NT_SUCCESS(tempStatus)){
					DbgPrint("RegistryFilter->ExtractKeyPath->ExAllocatePool failed.");
					ExFreePool(pobjectNameInformationBuffer);
					return;
				}
			}
			else{
				if(!NT_SUCCESS(tempStatus)){
					ExFreePool(pobjectNameInformationBuffer);
					return;
				}
			}

			registryPathBuffer->Length = ((POBJECT_NAME_INFORMATION) pobjectNameInformationBuffer)->Name.Length;
			registryPathBuffer->MaximumLength = ((POBJECT_NAME_INFORMATION) pobjectNameInformationBuffer)->Name.MaximumLength;
			registryPathBuffer->Buffer = ExAllocatePool(NonPagedPool, registryPathBuffer->MaximumLength);

			tempStatus = RtlUnicodeStringCopy(registryPathBuffer, (PUNICODE_STRING) pobjectNameInformationBuffer);
			if(!NT_SUCCESS(tempStatus)){
				if(tempStatus == STATUS_BUFFER_OVERFLOW){
					DbgPrint("RegistryFilter->ExtractKeyPath->RtlUnicodeStringCopy failed with error: STATUS_BUFFER_OVERFLOW.");
				}
				else if (tempStatus == STATUS_INVALID_PARAMETER){
					DbgPrint("RegistryFilter->ExtractKeyPath->RtlUnicodeStringCopy failed with error: STATUS_INVALID_PARAMETER.");
				}
				else
					DbgPrint("RegistryFilter->ExtractKeyPath->RtlUnicodeStringCopy failed with error: UNKNOW_ERROR.");

				registryPathBuffer->Length = 0;
				registryPathBuffer->MaximumLength = 0;
				registryPathBuffer->Buffer = NULL;
				return;
			}
			

			ExFreePool(pobjectNameInformationBuffer);

}


NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{		
		NTSTATUS tempStatus;
   		ULONG processId = 0;

   		ULONG sizeOfKeyObjectData;
   		HANDLE keyHandle;
		PUNICODE_STRING keyPath;
		PUNICODE_STRING registryPathBuffer;
		PVOID logStringBuffer;
		PUNICODE_STRING logString;
		LARGE_INTEGER currentTime;

		if((((int)((REG_NOTIFY_CLASS)Argument1)) != RegNtPreSetValueKey) && (((int)((REG_NOTIFY_CLASS)Argument1)) != RegNtPreCreateKeyEx)){
			return;
		}

		KeQuerySystemTime(&currentTime);

		processId = PsGetCurrentProcessId();
		if (processId == 0){
				DbgPrint("RegistryFilter's FltGetRequestorProcessId failed.");
				return STATUS_UNSUCCESSFUL;
		}


		logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
		if (logStringBuffer == NULL){
			DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryValueKey->RegNtPreQueryValueKey->ExAllocatePool failed to allocate space for registry log.\n");
			return STATUS_UNSUCCESSFUL;
		}


		RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);

		switch((int)((REG_NOTIFY_CLASS)Argument1)){
			case RegNtDeleteKey:
			break;
			case RegNtPreSetValueKey:

				registryPathBuffer = (PUNICODE_STRING) ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
				registryPathBuffer->Length = 0;
				registryPathBuffer->MaximumLength = 0;
				registryPathBuffer->Buffer = NULL;
				

				if (registryPathBuffer == NULL){
						DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryValueKey->RegNtPreQueryValueKey->ExAllocatePool failed.");
						return STATUS_UNSUCCESSFUL;
				}
				RtlZeroMemory(registryPathBuffer,sizeof(UNICODE_STRING));
			
				ExtractKeyPath(((PREG_QUERY_KEY_INFORMATION)Argument2)->Object, registryPathBuffer);
				if ((registryPathBuffer->Buffer == NULL) || (registryPathBuffer->Length == 0)){
					DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryKey->RegNtPreQueryValueKey->ExtractKeyPath failed.");
					ExFreePool(registryPathBuffer);
					return STATUS_UNSUCCESSFUL;
				}
				//The documentation says REG_SZ/EXPAND/LINK are UNICODE strings but they are LPWSTR apparently.
				switch(((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Type){
					case REG_SZ:
						//*((PUNICODE_STRING)(((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Data))
						tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%ls<-->%wZ<-->%wZ<-->%ls", L"REG", currentTime.QuadPart, processId, L"SETVALUE", registryPathBuffer, (((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName), ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Data);
						break;
					case REG_DWORD:	
						tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%ls<-->%wZ<-->%wZ<-->%p", L"REG", currentTime.QuadPart, processId, L"SETVALUE", registryPathBuffer, (((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName), (DWORD)((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Data);
						break;
					case REG_EXPAND_SZ:
						tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%ls<-->%wZ<-->%wZ,<-->%ls", L"REG", currentTime.QuadPart, processId, L"SETVALUE", registryPathBuffer, (((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName), ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Data);						break;
						break;
					case REG_LINK:
						tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%ls<-->%wZ<-->%wZ,<-->%ls", L"REG", currentTime.QuadPart, processId, L"SETVALUE", registryPathBuffer, (((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName), ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Data);						break;
						break;
					default:
						ExFreePool(registryPathBuffer);
						return STATUS_SUCCESS;

					break;
				}

				break;
				ExFreePool(registryPathBuffer);
			case RegNtPreQueryValueKey:
			/*TOO NOISY!
			ExtractKeyPath(((PREG_QUERY_KEY_INFORMATION)Argument2)->Object, registryPathBuffer);
			if ((registryPathBuffer->Buffer == NULL) || (registryPathBuffer->Length == 0)){
				DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryKey->RegNtPreQueryValueKey->ExtractKeyPath failed.");
				ExFreePool(registryPathBuffer);
				return STATUS_UNSUCCESSFUL;
			}

			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%lld<-->%lu<-->%ls<-->%wZ<-->%wZ", L"REG", currentTime.QuadPart, processId, L"QUERYVALUE", registryPathBuffer, ((PREG_QUERY_VALUE_KEY_INFORMATION)Argument2)->ValueName);
			*/
			break;
			case RegNtDeleteValueKey:
			break;
			case RegNtSetInformationKey:
			break;
			case RegNtRenameKey:
			break;
			case RegNtEnumerateKey:
			break;
			case RegNtEnumerateValueKey:
			break;
			case RegNtPreQueryKey:
			/*TOO NOISY!
			ExtractKeyPath(((PREG_QUERY_KEY_INFORMATION)Argument2)->Object, registryPathBuffer);
			if ((registryPathBuffer->Buffer == NULL) || (registryPathBuffer->Length == 0)){
				DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryKey->RegNtPreQueryValueKey->ExtractKeyPath failed.");
				ExFreePool(registryPathBuffer);
				return STATUS_UNSUCCESSFUL;
			}
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%lld<-->%lu<-->%ls<-->%wZ", L"REG", currentTime.QuadPart, processId, L"QUERYKEY", registryPathBuffer);

			break;
			case RegNtPreQueryValueKey:

			ExtractKeyPath(((PREG_QUERY_KEY_INFORMATION)Argument2)->Object, registryPathBuffer);
			if ((registryPathBuffer->Buffer == NULL) || (registryPathBuffer->Length == 0)){
				DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryKey->RegNtPreQueryValueKey->ExtractKeyPath failed.");
				ExFreePool(registryPathBuffer);
				return STATUS_UNSUCCESSFUL;
			}

			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%lld<-->%lu<-->%ls<-->%wZ<-->%wZ", L"REG", currentTime.QuadPart, processId, L"QUERYVALUE", registryPathBuffer, ((PREG_QUERY_VALUE_KEY_INFORMATION)Argument2)->ValueName);
			*/
			break;
			case RegNtQueryMultipleValueKey:
			break;
			case RegNtPreCreateKeyEx:
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%lu<-->%ls<-->%wZ", L"REG", currentTime.QuadPart, processId, L"CREATEKEY", *(((PREG_CREATE_KEY_INFORMATION)Argument2)->CompleteName));
			break;
			case RegNtPreOpenKey:
			break;
			default:
			break;


		} 


			if(!NT_SUCCESS(tempStatus)){
				if (tempStatus == STATUS_BUFFER_OVERFLOW){
		    		DbgPrint("RegistryFilter->RegistryCallback->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
		    	}
		    	else if (tempStatus == STATUS_INVALID_PARAMETER){
		    		DbgPrint("RegistryFilter->RegistryCallback->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
		    	}
		    	ExFreePool(logStringBuffer);
		    	return STATUS_UNSUCCESSFUL;
	    	}

	    	logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	    	if(logString == NULL){
	    		DbgPrint("RegistryFilter->RegistryCallback->ExAllocatePool failed to allocate memory for log unicode structure.\n");
	    		ExFreePool(logStringBuffer);
		    	return STATUS_UNSUCCESSFUL;
	    	}
	    	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

	    	RtlInitUnicodeString(logString, logStringBuffer);
	    	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
	    		DbgPrint("RegistryFilter->RegistryCallback->RegNtPreQueryValueKey->RtlInitUnicodeString failed to create unicode string.\n"); 
	    		ExFreePool(logString);
	    		ExFreePool(logStringBuffer);
	    		return STATUS_UNSUCCESSFUL;
	    	}
	    	
       	addNode(logString);
	    RtlFreeUnicodeString(logString);


		
		return STATUS_SUCCESS;

}