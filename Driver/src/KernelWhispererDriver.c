#define NDIS60 1 //Necessary for the network stuff. Will not work otherwise.
#include <winerror.h>
#include <ntstatus.h>
#include <ntstrsafe.h>
#include "FileSystemMonitor.h"
#include "RegistryMonitor.h"
#include "NetworkMonitor.h"
#include "ProcessMonitor.h"
#include "Util.h"
#include "KernelWhispererDriver.h"



#define REGISTRY_MONITOR_ALTITUDE L"420000"
#define SIZE_OF_REGISTRY_MONITOR_ALTITUDE_STRING 20
#define SIZE_OF_REGISTRY_MONITOR_ALTITUDE_IN_BYTES SIZE_OF_REGISTRY_MONITOR_ALTITUDE_STRING*sizeof(WCHAR)
#define IOCTL_KERNELWHISPERER_GETACTIVITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//File system filter handle.
PFLT_FILTER gFilterHandle;
//Registry filter cookie.
LARGE_INTEGER callbackRoutineCookie;
PDEVICE_OBJECT  pDeviceObj;

UINT32 fwpsListenCalloutId;
UINT32 fwpsRecvAcceptCalloutId;
UINT32 fwpsConnectCalloutId;

UINT32 fwpmListenCalloutId;
UINT32 fwpmRecvAcceptCalloutId;
UINT32 fwpmConnectCalloutId;

UINT64 fwpmListenFilterId;
UINT64 fwpmRecvAcceptFilterId;
UINT64 fwpmConnectFilterId;



HANDLE engineHandle;

DRIVER_DISPATCH ClassDispatchUnimplemented;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH ClassDeviceControlDispatch;



NTSTATUS ClassDispatchUnimplemented(PDEVICE_OBJECT DeviceObject, PIRP Irp){

	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return STATUS_INVALID_DEVICE_REQUEST;
}



NTSTATUS ClassDeviceControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
		

{	
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
	
	VOID* userModeBuffer = NULL;
	ULONG copiedBytes;

	if (pStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_KERNELWHISPERER_GETACTIVITY){
			userModeBuffer = Irp->AssociatedIrp.SystemBuffer;
			copiedBytes = getOldestLogString(userModeBuffer, pStack->Parameters.DeviceIoControl.OutputBufferLength);
    }

    
    Irp->IoStatus.Information = copiedBytes;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;

}



DRIVER_UNLOAD Unload;
VOID Unload(PDRIVER_OBJECT DriverObject){
	
	
	DbgPrint("Unloading driver.\n");  
	FltUnregisterFilter(gFilterHandle);
	CmUnRegisterCallback(callbackRoutineCookie);
	PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, TRUE);

	IoDeleteDevice(pDeviceObj);
	
	FwpmFilterDeleteById(engineHandle, fwpmListenFilterId);
	FwpmFilterDeleteById(engineHandle, fwpmRecvAcceptFilterId);
	FwpmFilterDeleteById(engineHandle, fwpmConnectFilterId);


	FwpmCalloutDeleteById(engineHandle, fwpmListenCalloutId);
	FwpmCalloutDeleteById(engineHandle, fwpmRecvAcceptCalloutId);
	FwpmCalloutDeleteById(engineHandle, fwpmConnectCalloutId);


	FwpsCalloutUnregisterById(fwpsListenCalloutId);
	FwpsCalloutUnregisterById(fwpsRecvAcceptCalloutId);
	FwpsCalloutUnregisterById(fwpsConnectCalloutId);


	

}


VOID deployFileSystemMonitor(PDRIVER_OBJECT DriverObject){

		NTSTATUS tempStatus;
   		DbgPrint("Registering File System filter.\n");  
	    tempStatus = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	    if (!NT_SUCCESS(tempStatus)){
	    	switch(tempStatus){
	    		case STATUS_INSUFFICIENT_RESOURCES:
	    			DbgPrint("deployFileSystemMonitor's FltRegisterFilter failed: STATUS_INSUFFICIENT_RESOURCES\n");
	    			break;
	    		case STATUS_INVALID_PARAMETER:
	    			DbgPrint("deployFileSystemMonitor's FltRegisterFilter failed: STATUS_INVALID_PARAMETER\n");
	    			break;
	    		case STATUS_FLT_NOT_INITIALIZED:
	    			DbgPrint("deployFileSystemMonitor's FltRegisterFilter failed: STATUS_FLT_NOT_INITIALIZED\n");
	    			break;
	    		case STATUS_OBJECT_NAME_NOT_FOUND:
	    			DbgPrint("deployFileSystemMonitor's FltRegisterFilter failed: STATUS_OBJECT_NAME_NOT_FOUND\n");
	    			break;
	    		default:
	    			DbgPrint("deployFileSystemMonitor's FltRegisterFilter failed:%p\n", tempStatus);
	    			break;
	    	}   
		}

		else {
			tempStatus = FltStartFiltering(gFilterHandle);
			if (!NT_SUCCESS(tempStatus)){
				switch(tempStatus){
					case STATUS_INVALID_PARAMETER:
						DbgPrint("deployFileSystemMonitor's FltStartFiltering failed: STATUS_INVALID_PARAMETER\n");
						break;
					default:
						DbgPrint("deployFileSystemMonitor's FltStartFiltering failed:%p\n", tempStatus);
						break;
				}
				FltUnregisterFilter(gFilterHandle);
			}


		}


}

VOID deployRegistryMonitor(PDRIVER_OBJECT DriverObject){

		NTSTATUS tempStatus;
		WCHAR altitudeBuffer[SIZE_OF_REGISTRY_MONITOR_ALTITUDE_STRING];
   		UNICODE_STRING altitude; 

    	tempStatus = RtlStringCbPrintfW(altitudeBuffer, SIZE_OF_REGISTRY_MONITOR_ALTITUDE_STRING, L"%s", REGISTRY_MONITOR_ALTITUDE);
    	if (tempStatus == STATUS_BUFFER_OVERFLOW){
    		DbgPrint("deployRegistryMonitor's RtlStringCbPrintfW failed to copy altitude string: STATUS_BUFFER_OVERFLOW\n"); 
    		return;	
    	}
    	else if (tempStatus == STATUS_INVALID_PARAMETER){
    		DbgPrint("deployRegistryMonitor's RtlStringCbPrintfW failed to copy altitude string: STATUS_INVALID_PARAMETER\n"); 
    		return;	
    	}

    	RtlInitUnicodeString(&altitude, altitudeBuffer);

    	if ((altitude.Buffer == NULL) || (altitude.Length == 0)){
    		DbgPrint("deployRegistryMonitor's RtlInitUnicodeString failed to create altitude unicode string.\n"); 
    		return;	
    	}


    	tempStatus = CmRegisterCallbackEx(RegistryCallback,&altitude,DriverObject,NULL,&callbackRoutineCookie,NULL);
    	if (tempStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION){
    		DbgPrint("deployRegistryMonitor's CmRegisterCallbackEx failed: STATUS_FLT_INSTANCE_ALTITUDE_COLLISION\n");
    		return;	 
    	}
    	else if (tempStatus == STATUS_INSUFFICIENT_RESOURCES){
    		DbgPrint("deployRegistryMonitor'sCmRegisterCallbackEx failed: STATUS_INSUFFICIENT_RESOURCES\n");  
    		return;	
    	}

}

VOID deployNetworkMonitor(){

		NTSTATUS tempStatus;

		FWPM_SESSION* fwpmSession;


		FWPS_CALLOUT* fwpsListenCallout;
		FWPS_CALLOUT* fwpsRecvAcceptCallout;
		FWPS_CALLOUT* fwpsConnectCallout;
		

		FWPM_CALLOUT* fwpmListenCallout;
		FWPM_CALLOUT* fwpmRecvAcceptCallout;
		FWPM_CALLOUT* fwpmConnectCallout;

		FWPM_FILTER* fwpmListenFilter;
		FWPM_FILTER* fwpmRecvAcceptFilter;
		FWPM_FILTER* fwpmConnectFilter;	

		fwpmSession = ExAllocatePool(NonPagedPool, sizeof(FWPM_SESSION));
  		
  		if(fwpmSession == NULL){
  			DbgPrint("deployNetworkMonitor's ExAllocatePool failed: failed to allocate memory for FWPM_SESSION\n");
  			return;  
  		}

  		RtlZeroMemory(fwpmSession, sizeof(FWPM_SESSION));
    	
    	//fwpmSession->flags = FWPM_SESSION_FLAG_DYNAMIC;  triggers c022000b STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS on FwpmCalloutAdd 
    	tempStatus = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, fwpmSession, &engineHandle);

    	if(engineHandle == NULL)
    	{
    		DbgPrint("deployNetworkMonitor's FwpmEngineOpen failed.");
   			ExFreePool(fwpmSession);
   			return;
    	}

    	if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == ERROR_SUCCESS)
	    		DbgPrint("deployNetworkMonitor's FwpmEngineOpen failed: STATUS_FWP_ALREADY_EXISTS\n");	 
	    	
	    	else if (tempStatus == FWP_E_ALREADY_EXISTS)
	    		DbgPrint("deployNetworkMonitor's FwpmEngineOpen failed: FWP_E_ALREADY_EXISTS\n");  

	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmEngineOpen failed: failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
	    	return;
    	}

    	tempStatus = FwpmTransactionBegin(engineHandle, 0);

    	if(!NT_SUCCESS(tempStatus)){
	    	DbgPrint("deployNetworkMonitor's FwpmTransactionBegin failed: failed:%p\n", tempStatus);
	    	ExFreePool(fwpmSession);
	    	return;
    	}

		
		
		fwpsListenCallout = getFWPSListenCallout();
		fwpsRecvAcceptCallout = getFWPSRecvAcceptCallout();
		fwpsConnectCallout =  getFWPSConnectCallout();

		

		if(fwpsListenCallout == NULL){
			DbgPrint("deployNetworkMonitor's getFWPS_Callout failed: fwpsListenCallout null");
   			ExFreePool(fwpmSession);
   			return;

		} 

		if(fwpsRecvAcceptCallout == NULL){
			DbgPrint("deployNetworkMonitor's getFWPS_Callout failed: fwpsRecvAcceptCallout null");
   			ExFreePool(fwpsListenCallout);
   			return;

		} 

		if(fwpsConnectCallout == NULL){
			DbgPrint("deployNetworkMonitor's getFWPS_Callout failed: fwpsConnectCallout null");
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
   			ExFreePool(fwpmSession);
   			return;

		} 	

    	tempStatus = FwpsCalloutRegister(pDeviceObj, fwpsListenCallout, &fwpsListenCalloutId);
		if(!NT_SUCCESS(tempStatus)){
			if (tempStatus == STATUS_FWP_ALREADY_EXISTS)
	    		DbgPrint("deployNetworkMonitor's FwpsCalloutRegister (Listen) failed: STATUS_FWP_ALREADY_EXISTS\n");	 
	    	else 
	    		DbgPrint("deployNetworkMonitor's FwpsCalloutRegister (Listen) failed:%p\n", tempStatus);  
	    	
	    	ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);
	    	ExFreePool(fwpmSession);
	    	return;
    	}

    	tempStatus = FwpsCalloutRegister(pDeviceObj, fwpsRecvAcceptCallout, &fwpsRecvAcceptCalloutId);
		if(!NT_SUCCESS(tempStatus)){
			if (tempStatus == STATUS_FWP_ALREADY_EXISTS)
	    		DbgPrint("deployNetworkMonitor's FwpsCalloutRegister (Recv/Accept) failed: STATUS_FWP_ALREADY_EXISTS\n");	 
	    	else 
	    		DbgPrint("deployNetworkMonitor's FwpsCalloutRegister (Recv/Accept) failed:%p\n", tempStatus);  
	    	
	    	ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);
	    	ExFreePool(fwpmSession);
	    	return;
    	}

    	tempStatus = FwpsCalloutRegister(pDeviceObj, fwpsConnectCallout, &fwpsConnectCalloutId);
		if(!NT_SUCCESS(tempStatus)){
			if (tempStatus == STATUS_FWP_ALREADY_EXISTS)
	    		DbgPrint("deployNetworkMonitor's FwpsCalloutRegister (Connect) failed: STATUS_FWP_ALREADY_EXISTS\n");	 
	    	else 
	    		DbgPrint("deployNetworkMonitor's FwpsCalloutRegister (Connect) failed:%p\n", tempStatus);  
	    	
	    	ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);
	    	ExFreePool(fwpmSession);
	    	return;
    	}
  	

    	fwpmListenCallout = getFWPMListenCallout();
		fwpmRecvAcceptCallout = getFWPMRecvAcceptCallout();
		fwpmConnectCallout =getFWPMConnectCallout();

		if(fwpmListenCallout == NULL){
			DbgPrint("deployNetworkMonitor's getFWPM_Callout failed: fwpmListenCallout is null.");
   			
   			ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);
   			return;

		}

		if(fwpmRecvAcceptCallout == NULL){
			DbgPrint("deployNetworkMonitor's getFWPM_Callout failed: fwpmListenCallout is null.");
   			
   			ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
   			return;

		}

		if(fwpmConnectCallout == NULL){
			DbgPrint("deployNetworkMonitor's getFWPM_Callout failed: fwpmListenCallout is null.");
   			
   			ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
   			return;

		}

		tempStatus = FwpmCalloutAdd(engineHandle, fwpmListenCallout, NULL, &fwpmListenCalloutId);
    	if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == FWP_E_INVALID_PARAMETER)
	    		DbgPrint("deployNetworkMonitor's FwpmCalloutAdd failed: FWP_E_INVALID_PARAMETER\n");  
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmCalloutAdd failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);
	    	return;
    	}
	
    	
		tempStatus = FwpmCalloutAdd(engineHandle, fwpmRecvAcceptCallout, NULL, &fwpmRecvAcceptCalloutId);
    	if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == FWP_E_INVALID_PARAMETER)
	    		DbgPrint("deployNetworkMonitor's FwpmCalloutAdd failed: FWP_E_INVALID_PARAMETER\n");  
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmCalloutAdd failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);
	    	return;
    	}
	

    	
		tempStatus = FwpmCalloutAdd(engineHandle, fwpmConnectCallout, NULL, &fwpmConnectCalloutId);
    	if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == FWP_E_INVALID_PARAMETER)
	    		DbgPrint("deployNetworkMonitor's FwpmCalloutAdd failed: FWP_E_INVALID_PARAMETER\n");  
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmCalloutAdd failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);
	    	return;
    	}


    	fwpmListenFilter = getFWPMListenFilter();
		fwpmRecvAcceptFilter = getFWPMRecvAcceptFilter();
		fwpmConnectFilter =getFWPMConnectFilter();

		if(fwpmListenFilter == NULL){
			DbgPrint("deployNetworkMonitor's getFWPM_Callout failed: fwpmListenFilter is null.");
   			
   			ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);

   			return;

		}

		if(fwpmRecvAcceptFilter == NULL){
			DbgPrint("deployNetworkMonitor's getFWPM_Callout failed: fwpmRecvAcceptFilter is null.");
   			
   			ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);

			ExFreePool(fwpmListenFilter);

   			return;

		}

		if(fwpmConnectFilter == NULL){
			DbgPrint("deployNetworkMonitor's getFWPM_Callout failed: fwpmConnectFilter is null.");
   			
   			ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);

			ExFreePool(fwpmListenFilter);
			ExFreePool(fwpmRecvAcceptFilter);

   			return;

		}   

		tempStatus = FwpmFilterAdd(engineHandle, fwpmListenFilter, NULL, &fwpmListenFilterId);
		if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == ERROR_INVALID_SECURITY_DESCR)
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed: ERROR_INVALID_SECURITY_DESCR\n");  
	    	else if (tempStatus == FWP_E_CALLOUT_NOTIFICATION_FAILED)
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed: FWP_E_CALLOUT_NOTIFICATION_FAILED\n");  
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);


			ExFreePool(fwpmListenFilter);
			ExFreePool(fwpmRecvAcceptFilter);
			ExFreePool(fwpmConnectFilter);
	    	return;
		}	



		tempStatus = FwpmFilterAdd(engineHandle, fwpmRecvAcceptFilter, NULL, &fwpmListenFilterId);
		if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == ERROR_INVALID_SECURITY_DESCR)
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed: ERROR_INVALID_SECURITY_DESCR\n");  
	    	else if (tempStatus == FWP_E_CALLOUT_NOTIFICATION_FAILED)
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed: FWP_E_CALLOUT_NOTIFICATION_FAILED\n");  
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);

			ExFreePool(fwpmListenFilter);
			ExFreePool(fwpmRecvAcceptFilter);
			ExFreePool(fwpmConnectFilter);
	    	return;
		}	



		tempStatus = FwpmFilterAdd(engineHandle, fwpmConnectFilter, NULL, &fwpmConnectFilterId);
		if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == ERROR_INVALID_SECURITY_DESCR)
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed: ERROR_INVALID_SECURITY_DESCR\n");  
	    	else if (tempStatus == FWP_E_CALLOUT_NOTIFICATION_FAILED)
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed: FWP_E_CALLOUT_NOTIFICATION_FAILED\n");  
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmFilterAdd failed:%p\n", tempStatus);
	    	
	    	ExFreePool(fwpmSession);
   			
   			ExFreePool(fwpsListenCallout);
			ExFreePool(fwpsRecvAcceptCallout);
			ExFreePool(fwpsConnectCallout);

			ExFreePool(fwpmListenCallout);
			ExFreePool(fwpmRecvAcceptCallout);
			ExFreePool(fwpmConnectCallout);

			ExFreePool(fwpmListenFilter);
			ExFreePool(fwpmRecvAcceptFilter);
			ExFreePool(fwpmConnectFilter);
	    	return;
		}	

    	tempStatus = FwpmTransactionCommit(engineHandle);

    	if(!NT_SUCCESS(tempStatus)){
    		if (tempStatus == ERROR_SUCCESS)
	    		DbgPrint("deployNetworkMonitor's FwpmTransactionCommit failed: STATUS_FWP_ALREADY_EXISTS\n");	 
	    	else
	    		DbgPrint("deployNetworkMonitor's FwpmTransactionCommit failed:%p\n", tempStatus);
	    	

	    	tempStatus = FwpmTransactionAbort(engineHandle);
	    	if(!NT_SUCCESS(tempStatus)){
	    		if (tempStatus == ERROR_SUCCESS)
		    		DbgPrint("deployNetworkMonitor's FwpmTransactionAbort failed: STATUS_FWP_ALREADY_EXISTS\n");	 
		    	else
		    		DbgPrint("deployNetworkMonitor's FwpmTransactionAbort failed:%p\n", tempStatus);

				ExFreePool(fwpmSession);
   			
	   			ExFreePool(fwpsListenCallout);
				ExFreePool(fwpsRecvAcceptCallout);
				ExFreePool(fwpsConnectCallout);

				ExFreePool(fwpmListenCallout);
				ExFreePool(fwpmRecvAcceptCallout);
				ExFreePool(fwpmConnectCallout);

				ExFreePool(fwpmListenFilter);
				ExFreePool(fwpmRecvAcceptFilter);
				ExFreePool(fwpmConnectFilter);
			    return;
	    	}
		}


		

}


VOID deployProcessMonitor(){

	NTSTATUS tempStatus;

	tempStatus = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, FALSE);

	if(!NT_SUCCESS(tempStatus)){
   			switch(tempStatus){
   				case STATUS_INVALID_PARAMETER:
   					DbgPrint("deployProcessMonitor's PsSetCreateProcessNotifyRoutineEx failed: STATUS_INVALID_PARAMETER\n");
	    			break;
	    		case STATUS_OBJECT_NAME_COLLISION:
	    			DbgPrint("deployProcessMonitor's PsSetCreateProcessNotifyRoutineEx failed: STATUS_ACCESS_DENIED\n");
	    			break;
	    		default:
	    			DbgPrint("deployProcessMonitor's PsSetCreateProcessNotifyRoutineEx failed:%p\n", tempStatus);
	    			break;

   			}


   		}

}


DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)    
{
		NTSTATUS tempStatus;
   		
   		UNICODE_STRING  usDeviceName = RTL_CONSTANT_STRING(L"\\Device\\KernelWhisperer");
    	UNICODE_STRING  usSymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Global\\KernelWhisperer");
    	int idx = 0;


    	DbgPrint("Setting IRP handlers.\n");   		
   		for (idx = 0; idx <= IRP_MJ_MAXIMUM_FUNCTION; idx++) {
        	DriverObject->MajorFunction[idx] = ClassDispatchUnimplemented;
    	}

    	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ClassDeviceControlDispatch;
    	DriverObject->MajorFunction[IRP_MJ_CREATE] = ClassDeviceControlDispatch;

   		tempStatus = IoCreateDevice(DriverObject, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);


   		if(!NT_SUCCESS(tempStatus)){
   			switch(tempStatus){
   				case STATUS_INSUFFICIENT_RESOURCES:
   					DbgPrint("DriverEntry's IoCreateDevice failed: STATUS_INSUFFICIENT_RESOURCES\n");
	    			break;
	    		case STATUS_OBJECT_NAME_COLLISION:
	    			DbgPrint("DriverEntry's IoCreateDevice failed: STATUS_OBJECT_NAME_COLLISION\n");
	    			break;
	    		default:
	    			DbgPrint("DriverEntry's IoCreateDevice failed:%p\n", tempStatus);
	    			break;

   			}

   			return STATUS_UNSUCCESSFUL;

   		}

   		else{

   			if(pDeviceObj == NULL){
   				DbgPrint("DriverEntry's IoCreateDevice failed: null device object.\n");
   				IoDeleteDevice(pDeviceObj);	
   				return STATUS_UNSUCCESSFUL;
   			}

   			tempStatus = IoCreateSymbolicLink(&usSymbolicLink, &usDeviceName);
   			if(!NT_SUCCESS(tempStatus)){
   				DbgPrint("DriverEntry's IoCreateSymbolicLink failed:%p\n", tempStatus);
   				IoDeleteDevice(pDeviceObj);	
   				return STATUS_UNSUCCESSFUL;
   			}

   		}
   		initSyncObject();
   		deployFileSystemMonitor(DriverObject);
   		deployRegistryMonitor(DriverObject);
   		deployNetworkMonitor();
   		deployProcessMonitor();
   		return STATUS_SUCCESS;

		
	    	

}  

