#include <Fltkernel.h>

NTSTATUS ClassDispatchUnimplemented(PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS ClassDeviceControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID Unload(PDRIVER_OBJECT DriverObject);
VOID deployFileSystemMonitor(PDRIVER_OBJECT DriverObject);
VOID deployRegistryMonitor(PDRIVER_OBJECT DriverObject);
VOID deployNetworkMonitor();
VOID deployProcessMonitor();
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);


CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
 
    { IRP_MJ_CREATE,
      0,
      FileSystemFilterPreOperationCallback,
      FileSystemFilterPostOperationCallback },
    { IRP_MJ_OPERATION_END } //This one is necessary!!!!

};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                           //  Context
    Callbacks,                          //  Operation callbacks
    DfUnload,                           //  MiniFilterUnload
    NULL,                    //  InstanceSetup
    NULL,            //  InstanceQueryTeardown
    NULL,            //  InstanceTeardownStart
    NULL,         //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  NormalizeNameComponent
    NULL,                               //  NormalizeContextCleanup
    NULL,  //  TransactionNotification
    NULL                                //  NormalizeNameComponentEx

};

