#include <Fltkernel.h>


NTSTATUS DfUnload (FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FileSystemFilterPreOperationCallback (PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FileSystemFilterPostOperationCallback (PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

extern PFLT_FILTER gFilterHandle;

