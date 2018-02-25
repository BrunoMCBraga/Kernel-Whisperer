#include <ntddk.h>

typedef struct _LOGS_NODE LOGS_NODE;
typedef struct _LOGS_NODE* PLOGS_NODE;

typedef struct _LOGS_NODE{

	PUNICODE_STRING entryText;
	PLOGS_NODE next;	
};

typedef struct _LOGS_LIST{

	PLOGS_NODE listBegin;
	PLOGS_NODE listEnd;
	ULONG listSize;

} LOGS_LIST, *PLOGS_LIST;



typedef struct _KERNEL_WHISPERER_REQUEST{

	void* buffer;

} KERNEL_WHISPERER_REQUEST, *PKERNEL_WHISPERER_REQUEST;


typedef struct _KERNEL_WHISPERER_RESPONSE{

	VOID* response;

} KERNEL_WHISPERER_RESPONSE, *PKERNEL_WHISPERER_RESPONSE;



VOID initSyncObject();
VOID deleteNode(PLOGS_NODE node);
VOID addNode(PUNICODE_STRING eventString);
VOID removeOldestNode();
ULONG getOldestLogString(void* outputBuffer, ULONG outputBufferSize);
int hasInvalidCharacters(PUNICODE_STRING uString);


