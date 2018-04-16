#include "Util.h"
#include <ntstrsafe.h>
#include <ntddk.h>


#define MAX_LIST_SIZE 50000000
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
	PLOGS_NODE logsNode = NULL;
	PLOGS_NODE nodeToDelete = NULL;
	PLOGS_LIST listHead = NULL;
	
	
	KeWaitForSingleObject(globalListSyncEvent, Executive, KernelMode,TRUE, NULL);
	if (MAX_LIST_SIZE == 0){
		DbgPrint("Util->addNode->ExAllocatePool failed: MAX_LIST_SIZE is zero.");
		KeSetEvent(globalListSyncEvent, 0, FALSE);
		return;
	}

	logsNode = (PLOGS_NODE) ExAllocatePool(NonPagedPool, sizeof(LOGS_NODE));

	if (logsNode == NULL){
		DbgPrint("Util->addNode->ExAllocatePool failed.");
		KeSetEvent(globalListSyncEvent, 0, FALSE);
		return;
	}

	RtlZeroMemory(logsNode, sizeof(LOGS_NODE));
	
	
	logsNode->entryText = eventString;
	logsNode->next = NULL;

	//Must be initialized...
	if(globalList == NULL)
	{
		listHead = (PLOGS_LIST) ExAllocatePool(NonPagedPool, sizeof(LOGS_LIST));
		if (listHead == NULL){
			DbgPrint("Util->addNode->ExAllocatePool failed: Unable to create list head.");
			ExFreePool(logsNode);
			KeSetEvent(globalListSyncEvent, 0, FALSE);
			return;
		}

		RtlZeroMemory(listHead, sizeof(LOGS_LIST));
		listHead->listBegin = logsNode;
		listHead->listEnd = logsNode;
		listHead->listSize = 1;

		globalList = listHead;

	}
	else{
			//List too long, we remove the first node...			
			if(globalList->listSize > MAX_LIST_SIZE){
				DbgPrint("Util->addNode list full. Droping events.");
				nodeToDelete = globalList->listBegin;
				globalList->listBegin = globalList->listBegin->next;
				globalList->listEnd->next = logsNode;
				globalList->listEnd = logsNode;
				
				deleteNode(nodeToDelete);
				KeSetEvent(globalListSyncEvent, 0, FALSE);
				return;
			}

			else {	

					if(globalList->listBegin == NULL){
						globalList->listBegin = logsNode;
						globalList->listEnd = logsNode;
						globalList->listSize = 1;
						KeSetEvent(globalListSyncEvent, 0, FALSE);
						return;
					}

					//There is only one node pointing to itself.
					if((globalList->listBegin->next == NULL) && (globalList->listEnd->next == NULL)){
						globalList->listBegin->next = logsNode;
					}

	
					globalList->listEnd->next = logsNode;
					globalList->listEnd = logsNode;
					globalList->listSize++;
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
			DbgPrint("Util->getOldestLogString failed: outputBuffer is NULL.");
			KeSetEvent(globalListSyncEvent, 0, FALSE);
			return;
		}

		if(globalList->listBegin->entryText->Length == 0)
		{
			DbgPrint("Util->getOldestLogString failed: string to be returned has length zero.");
			KeSetEvent(globalListSyncEvent, 0, FALSE);
			return;	
		}

		oldestLogEntry = globalList->listBegin;
		maxBytesToCopy = min(oldestLogEntry->entryText->MaximumLength,outputBufferSize);
		RtlCopyMemory(outputBuffer, oldestLogEntry->entryText->Buffer, maxBytesToCopy);

		nodeToDelete = globalList->listBegin;
		globalList->listBegin = globalList->listBegin->next;
		deleteNode(nodeToDelete);
		globalList->listSize = (globalList->listSize == 1) ? 0 : (globalList->listSize-1);
		


	}

	KeSetEvent(globalListSyncEvent, 0, FALSE);
	return maxBytesToCopy;
}


int hasInvalidCharacters(PUNICODE_STRING uString){

	USHORT index;
	wchar_t tempCharValue;
	
	if(uString == NULL){
		DbgPrint("Util->hasInvalidCharacters failed: uString is NULL.");
		return 1;
	}

	for(index = 0;(index < uString->Length) && (index < uString->MaximumLength); ++index){
		tempCharValue = uString->Buffer[index];
		//If we get a zero, we can immediatelly return. This means that the string only contains one null byte, when the string is copied around there is a boundary. If the string has some valid characters and then a null, still makes sense.
		//As soon as we get an invalid character on the second if (here i assume within the ASCII world to make things simple), we reject the string. Later this can be extended for more characters. 
		if((unsigned long)tempCharValue == 0)
			return 0;
		if(((unsigned long)tempCharValue < (unsigned long) 31) || ((unsigned long)tempCharValue > (unsigned long) 126)){
			return 1;
		}

	}
	return 0;
}


