//PLOAD_IMAGE_NOTIFY_ROUTINE PloadImageNotifyRoutine;
#include <ntstrsafe.h>

void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);