#include "Util.h"
#include <ntstrsafe.h>
#include <ntddk.h>


#define MAX_LIST_SIZE 10000
PLOGS_LIST globalList = NULL;
PKEVENT globalListSyncEvent = NULL;

VOID initSyncObject(){

	globalListSyncEvent = ExAllocatePool(NonPagedPool, sizeof(KEVENT));
   	KeInitializeEvent(globalListSyncEvent, SynchronizationEvent, TRUE);
   	

}

VOID deleteNode(PLOGS_NODE node){
	RtlFreeUnicodeString(node->entryText);
	node->next=NULL;
}

VOID addNode(PUNICODE_STRING eventString){

	NTSTATUS tempStatus;
	PLOGS_NODE entryTextEntry = NULL;
	PUNICODE_STRING stringCopy = NULL;
	VOID* stringCopyBuffer = NULL;
	PLOGS_NODE nodeToDelete = NULL;
	PLOGS_LIST listHead = NULL;
	
	
	KeWaitForSingleObject(globalListSyncEvent ,Executive,KernelMode,TRUE, NULL);
	if (MAX_LIST_SIZE == 0){
		DbgPrint("Util->addNode->ExAllocatePool failed: MAX_LIST_SIZE is zero.");
		KeSetEvent(globalListSyncEvent, 0, FALSE);
		return;
	}

	entryTextEntry = (PLOGS_NODE) ExAllocatePool(NonPagedPool, sizeof(LOGS_NODE));

	if (entryTextEntry == NULL){
		DbgPrint("Util->addNode->ExAllocatePool failed.");
		KeSetEvent(globalListSyncEvent, 0, FALSE);
		return;
	}

	RtlZeroMemory(entryTextEntry, sizeof(LOGS_NODE));
	
	stringCopy = (PUNICODE_STRING) ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	
	if (stringCopy == NULL){

		ExFreePool(entryTextEntry);
		KeSetEvent(globalListSyncEvent, 0, FALSE);
		return;
	}

	RtlZeroMemory(stringCopy, sizeof(UNICODE_STRING));

	stringCopyBuffer = ExAllocatePool(NonPagedPool, eventString->MaximumLength);

	if (stringCopyBuffer == NULL){
		ExFreePool(entryTextEntry);
		ExFreePool(stringCopy);
		KeSetEvent(globalListSyncEvent, 0, FALSE);
		return;
	}

	RtlZeroMemory(stringCopyBuffer, eventString->MaximumLength);


	stringCopy->Length = eventString->Length;
	stringCopy->MaximumLength = eventString->MaximumLength;
	stringCopy->Buffer = stringCopyBuffer;

	tempStatus = RtlUnicodeStringCopy(stringCopy, eventString);
	if(!NT_SUCCESS(tempStatus)){
				if(tempStatus == STATUS_BUFFER_OVERFLOW){
					DbgPrint("Util->addNode->RtlUnicodeStringCopy failed with error: STATUS_BUFFER_OVERFLOW.");
				}
				else if (tempStatus == STATUS_INVALID_PARAMETER){
					DbgPrint("Util->addNode->RtlUnicodeStringCopy failed with error: STATUS_INVALID_PARAMETER.");
				}
				else
					DbgPrint("Util->addNode->RtlUnicodeStringCopy failed with error: UNKNOW_ERROR.");
				
				ExFreePool(stringCopy);
				ExFreePool(entryTextEntry);
				KeSetEvent(globalListSyncEvent, 0, FALSE);
				return;
	}

	entryTextEntry->entryText = stringCopy;
	entryTextEntry->next = NULL;

	//Must be initialized...
	if(globalList == NULL)
	{
		listHead = (PLOGS_LIST) ExAllocatePool(NonPagedPool, sizeof(LOGS_LIST));
		if (listHead == NULL){
			DbgPrint("Util->addNode->ExAllocatePool failed: Unable to create list head.");
			ExFreePool(stringCopy);
			ExFreePool(entryTextEntry);
			KeSetEvent(globalListSyncEvent, 0, FALSE);
			return;
		}

		RtlZeroMemory(listHead, sizeof(LOGS_LIST));
		listHead->listBegin = entryTextEntry;
		listHead->listEnd = entryTextEntry;
		listHead->listSize = 1;

		globalList = listHead;
		//DbgPrint("NULL:%wZ",globalList->listEnd->entryText);

	}
	else{
			//List too long, we remove the first node...
			
			
			if(globalList->listSize > MAX_LIST_SIZE){
				//DbgPrint("List too long. Removing node.");
				nodeToDelete = globalList->listBegin;
				globalList->listBegin = globalList->listBegin->next;
				globalList->listEnd->next = entryTextEntry;
				globalList->listEnd = entryTextEntry;
				
				deleteNode(nodeToDelete);
				//DbgPrint("Over Max:%wZ",globalList->listEnd->entryText);
				KeSetEvent(globalListSyncEvent, 0, FALSE);
				return;
			}

			else {	
					//DbgPrint("Adding node.");

					if(globalList->listBegin == NULL){
						globalList->listBegin = entryTextEntry;
						globalList->listEnd = entryTextEntry;
						globalList->listSize = 1;
						KeSetEvent(globalListSyncEvent, 0, FALSE);
						return;
					}

					//There is only one node pointing to itself.
					if((globalList->listBegin->next == NULL) && (globalList->listEnd->next == NULL)){
						globalList->listBegin->next = entryTextEntry;
					}

	
					//DbgPrint("Size:%lu",globalList->listSize);
					globalList->listEnd->next = entryTextEntry;
					globalList->listEnd = entryTextEntry;
					globalList->listSize++;
					//DbgPrint("Below Max:%wZ",globalList->listEnd->entryText);
					KeSetEvent(globalListSyncEvent, 0, FALSE);
					return;

			}

			


	}


	KeSetEvent(globalListSyncEvent, 0, FALSE);

}





ULONG getOldestLogString(void* outputBuffer, ULONG outputBufferSize){


	NTSTATUS tempStatus;
	PLOGS_NODE oldestLogEntry = NULL;
	PUNICODE_STRING stringCopy = NULL;
	PLOGS_NODE nodeToDelete = NULL;
	ULONG maxBytesToCopy = 0;

	KeWaitForSingleObject(globalListSyncEvent ,Executive,KernelMode,TRUE, NULL);


	if((globalList != NULL) && (globalList->listSize > 0))
	{
		
		if(outputBuffer == NULL){
			DbgPrint("outputBuffer is NULL");
			return;
		}

		if(globalList == NULL){
			DbgPrint("globalList is NULL");
			return;	
		}
		if(globalList->listBegin->entryText->Length == 0)
		{
			DbgPrint("No string...");
			return;	

		}

		//DbgPrint("Received Buffer with:%lu bytes", outputBufferSize);
		oldestLogEntry = globalList->listBegin;
		maxBytesToCopy = min(oldestLogEntry->entryText->MaximumLength,outputBufferSize);
		//DbgPrint("Copying:%d",maxBytesToCopy);
		RtlCopyMemory(outputBuffer, oldestLogEntry->entryText->Buffer, maxBytesToCopy);
		//DbgPrint("Copying:%ls",outputBuffer);

		nodeToDelete = globalList->listBegin;
		globalList->listBegin = globalList->listBegin->next;
		deleteNode(nodeToDelete);
		globalList->listSize = (globalList->listSize == 1) ? 0 : (globalList->listSize-1);///Tehre was an error here retest!!!
		


	}

	KeSetEvent(globalListSyncEvent, 0, FALSE);
	return maxBytesToCopy;
}


int hasInvalidCharacters(PUNICODE_STRING uString){

	USHORT index;
	wchar_t tempCharValue;
	
	for(index = 0;index < uString->Length; ++index){
		tempCharValue = uString->Buffer[index];
		//If we get a zero, we can immediatelly return. This means that the string only contains one null byte, when the string is copied around there is a boundary. If the string has some valid characters and then a null, still makes sense.
		//As soon as we get an invalid character on the second if (here i assume within the ASCII world to make things simple), we reject the string. Later this can be extended for more characters. 
		if((unsigned long)tempCharValue == 0)
			return 0;
		if(((unsigned long)tempCharValue < (unsigned long) 31) || ((unsigned long)tempCharValue > (unsigned long) 126)){
			return 1;
		}

	}
	DbgPrint("Success");
	return 0;
}


