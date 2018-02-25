#define NDIS60 1 //Necessary for the network stuff. Will not work otherwise.
#include <ndis.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <fwpsk.h>
#include <fwpmu.h>
#include <ntddndis.h>
#include "NetworkMonitor.h"
#include "Util.h"

#define SIZE_OF_IP_BUFFER 20
#define MAX_LOG_BUFFER_SIZE 2000

char* uint32ToString(UINT32 ipAddress){
	wchar_t* ipBuffer = ExAllocatePool(NonPagedPool, SIZE_OF_IP_BUFFER*sizeof(wchar_t));
	unsigned char ipOctets[] = {0,0,0,0};
	NTSTATUS temptStatus;
	int loopIndex;

	RtlZeroMemory(ipBuffer, SIZE_OF_IP_BUFFER*sizeof(wchar_t));
	
	for (loopIndex=0; loopIndex<4; loopIndex++)
		ipOctets[loopIndex] = (( ipAddress >> (loopIndex*8) ) & 0xFF);
	
	//Make check on return;
	RtlStringCbPrintfW(ipBuffer, SIZE_OF_IP_BUFFER*sizeof(wchar_t), L"%d.%d.%d.%d", ipOctets[3],ipOctets[2],ipOctets[1],ipOctets[0]);

	return ipBuffer;
}

VOID NTAPI FwpsCalloutClassifyFn(const FWPS_INCOMING_VALUES *inFixedValues, const FWPS_INCOMING_METADATA_VALUES *inMetaValues, void *layerData, const FWPS_FILTER *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT *classifyOut){
	
	NTSTATUS tempStatus;
	UINT64 processId;
	UINT64 sourceInterfaceIndex;
	wchar_t* type;
	short unsigned dstPort;
	HANDLE injectionHandle;
	wchar_t* protocol;
	LARGE_INTEGER currentTime;
	PUNICODE_STRING logString;
	PVOID logStringBuffer;
	wchar_t* localIPAddress = NULL;
	wchar_t* remoteIPAddress = NULL;

	
	KeQuerySystemTime(&currentTime);
	processId = inMetaValues->processId;

	logStringBuffer = ExAllocatePool(NonPagedPool, MAX_LOG_BUFFER_SIZE);
		if (logStringBuffer == NULL){
			DbgPrint("NetworkMonitor->FwpsCalloutClassifyFn->ExAllocatePool failed to allocate space.\n");
			return;
		}

	RtlZeroMemory(logStringBuffer, MAX_LOG_BUFFER_SIZE);

	switch (inFixedValues->layerId){
		case FWPS_LAYER_ALE_AUTH_LISTEN_V4:
			type = L"LISTEN";
			protocol = L"TCP";
			localIPAddress = uint32ToString(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS].value.uint32);
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ls<-->%ls<-->%u", L"NET", currentTime.QuadPart, processId, protocol, type, localIPAddress, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT].value.uint16);
			break;
		case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
			type = L"RECV/ACCEPT";
			switch (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint8){
				case 1:
					protocol = L"ICMP";
					break;
				case 6:
					protocol = L"TCP";
					break;
				case 17:
					protocol = L"UDP";
					break;
				default:
					protocol = L"UNKNOWN";
					break;
			}
			localIPAddress = uint32ToString(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32);
			remoteIPAddress = uint32ToString(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32);
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ls<-->%ls<-->%u<-->%ls<-->%u", L"NET", currentTime.QuadPart, processId, protocol, type, localIPAddress, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16,remoteIPAddress, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16);
			break;
		case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
			type = L"CONNECT";
			switch (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8){
				case 1:
					protocol = L"ICMP";
					break;
				case 6:
					protocol = L"TCP";
					break;
				case 17:
					protocol = L"UDP";
					break;
				default:
					protocol = L"UNKNOWN";
					break;
			}
			localIPAddress = uint32ToString(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32);
			remoteIPAddress = uint32ToString(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32);
			tempStatus = RtlStringCbPrintfW(logStringBuffer, MAX_LOG_BUFFER_SIZE, L"%ls<-->%I64u<-->%ld<-->%ls<-->%ls<-->%ls<-->%u<-->%ls<-->%u", L"NET", currentTime.QuadPart, processId, protocol, type, localIPAddress, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16,remoteIPAddress, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16);
			break;
		default:
			DbgPrint("NetworkMonitor->FwpsCalloutClassifyFn error: Unknown Layer Id.");
			if (localIPAddress != NULL)
    			ExFreePool(localIPAddress);
    		if(remoteIPAddress != NULL)
    			ExFreePool(remoteIPAddress);
			return;
	}
	
		if(!NT_SUCCESS(tempStatus)){
			if (tempStatus == STATUS_BUFFER_OVERFLOW){
	    		DbgPrint("NetworkMonitor->FwpsCalloutClassifyFn->RtlStringCbPrintfW failed to generate log string: STATUS_BUFFER_OVERFLOW\n"); 
	    	}
	    	else if (tempStatus == STATUS_INVALID_PARAMETER){
	    		DbgPrint("NetworkMonitor->FwpsCalloutClassifyFn->RtlStringCbPrintfW failed to generate log string: STATUS_INVALID_PARAMETER\n"); 
	    	}
	    	ExFreePool(logStringBuffer);
	    	if (localIPAddress != NULL)
    			ExFreePool(localIPAddress);
    		if(remoteIPAddress != NULL)
    			ExFreePool(remoteIPAddress);
	    	return;
    	}

    	logString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
    	if(logString == NULL){
    		DbgPrint("NetworkMonitor->FwpsCalloutClassifyFn->ExAllocatePool failed to allocate memory for log string.\n");
    		ExFreePool(logStringBuffer);
    		if (localIPAddress != NULL)
    			ExFreePool(localIPAddress);
    		if(remoteIPAddress != NULL)
    			ExFreePool(remoteIPAddress);
	    	return;
    	}
    	RtlZeroMemory(logString, sizeof(UNICODE_STRING));

    	RtlInitUnicodeString(logString, logStringBuffer);
    	if ((logString->Buffer == NULL) || (logString->Length == 0) || (logString->MaximumLength == 0)){
    		DbgPrint("NetworkMonitor->FwpsCalloutClassifyFn->RtlInitUnicodeString failed to create unicode string.\n"); 
	    	ExFreePool(logStringBuffer);
	    	ExFreePool(logString);
	    	if (localIPAddress != NULL)
    			ExFreePool(localIPAddress);
    		if(remoteIPAddress != NULL)
    			ExFreePool(remoteIPAddress);
    		return;
    	}

    	addNode(logString);
    	RtlFreeUnicodeString(logString);
    	if (localIPAddress != NULL)
    		ExFreePool(localIPAddress);
    	if(remoteIPAddress != NULL)
    		ExFreePool(remoteIPAddress);
	

	
}




NTSTATUS NTAPI FwpsCalloutNotifyFn(FWPS_CALLOUT_NOTIFY_TYPE notifyType,const GUID *filterKey,FWPS_FILTER *filter){
	return STATUS_SUCCESS;
}


VOID NTAPI FwpsCalloutFlowDeleteNotifyFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext){

}


//FWPM_LAYER_ALE_AUTH_LISTEN_V4
FWPS_CALLOUT* getFWPSListenCallout(){
	FWPS_CALLOUT* calloutStruct = ExAllocatePool(NonPagedPool, sizeof(FWPS_CALLOUT));
	
	RtlZeroMemory(calloutStruct, sizeof(FWPS_CALLOUT));
	calloutStruct->calloutKey = CLSID_NetworkMonitorListen;
	calloutStruct->flags = 0;
	calloutStruct->classifyFn = FwpsCalloutClassifyFn;
	calloutStruct->notifyFn = FwpsCalloutNotifyFn;
	calloutStruct->flowDeleteFn = FwpsCalloutFlowDeleteNotifyFn;
	return calloutStruct;
}


FWPM_CALLOUT* getFWPMListenCallout(){

	FWPM_CALLOUT* calloutStruct = ExAllocatePool(NonPagedPool, sizeof(FWPM_CALLOUT));
	RtlZeroMemory(calloutStruct, sizeof(FWPM_CALLOUT));


	calloutStruct->calloutKey = CLSID_NetworkMonitorListen;
	calloutStruct->displayData.name = L"NetworkMonitor Callout: TCP Listen (IPV4).";
	calloutStruct->flags = FWPM_CALLOUT_FLAG_PERSISTENT;
	calloutStruct->applicableLayer = FWPM_LAYER_ALE_AUTH_LISTEN_V4;
	

	
	return calloutStruct;
	

}


FWPM_FILTER* getFWPMListenFilter(){

	FWPM_FILTER* layerFilters = ExAllocatePool(NonPagedPool, sizeof(FWPM_FILTER));
	RtlZeroMemory(layerFilters, sizeof(FWPM_FILTER));
	

	layerFilters->displayData.name = L"NetworkMonitor Filter: TCP Listen (IPV4).";
	layerFilters->flags = FWPM_FILTER_FLAG_PERSISTENT;
	layerFilters->layerKey = FWPM_LAYER_ALE_AUTH_LISTEN_V4;
	layerFilters->action.type = FWP_ACTION_CALLOUT_INSPECTION;
	layerFilters->action.calloutKey = CLSID_NetworkMonitorListen;
	layerFilters->numFilterConditions = 0;

	
	return layerFilters;

	
}

//FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
FWPS_CALLOUT* getFWPSRecvAcceptCallout(){
	FWPS_CALLOUT* calloutStruct = ExAllocatePool(NonPagedPool, sizeof(FWPS_CALLOUT));
	
	RtlZeroMemory(calloutStruct, sizeof(FWPS_CALLOUT));
	calloutStruct->calloutKey = CLSID_NetworkMonitoRecvAccept;
	calloutStruct->flags = 0;
	calloutStruct->classifyFn = FwpsCalloutClassifyFn;
	calloutStruct->notifyFn = FwpsCalloutNotifyFn;
	calloutStruct->flowDeleteFn = FwpsCalloutFlowDeleteNotifyFn;
	return calloutStruct;
}


FWPM_CALLOUT* getFWPMRecvAcceptCallout(){

	FWPM_CALLOUT* calloutStruct = ExAllocatePool(NonPagedPool, sizeof(FWPM_CALLOUT));

	RtlZeroMemory(calloutStruct, sizeof(FWPM_CALLOUT));

	calloutStruct->calloutKey = CLSID_NetworkMonitoRecvAccept;
	calloutStruct->displayData.name = L"NetworkMonitor Callout: Incoming TCP (IPV4).";
	calloutStruct->flags = FWPM_CALLOUT_FLAG_PERSISTENT;
	calloutStruct->applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

	return calloutStruct;


}
FWPM_FILTER* getFWPMRecvAcceptFilter(){

	FWPM_FILTER* layerFilters = ExAllocatePool(NonPagedPool, sizeof(FWPM_FILTER));
	RtlZeroMemory(layerFilters, sizeof(FWPM_FILTER));

	layerFilters->displayData.name = L"NetworkMonitor Filter: Incoming TCP (IPV4).";
	layerFilters->flags = FWPM_FILTER_FLAG_PERSISTENT;
	layerFilters->layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	layerFilters->action.type = FWP_ACTION_CALLOUT_INSPECTION;
	layerFilters->action.calloutKey = CLSID_NetworkMonitoRecvAccept;
	layerFilters->numFilterConditions = 0;
	return layerFilters;

}

////FWPM_LAYER_ALE_AUTH_CONNECT_V4
FWPS_CALLOUT* getFWPSConnectCallout(){

	FWPS_CALLOUT* calloutStruct = ExAllocatePool(NonPagedPool, sizeof(FWPS_CALLOUT));
	
	RtlZeroMemory(calloutStruct, sizeof(FWPS_CALLOUT));
	calloutStruct->calloutKey = CLSID_NetworkMonitorConnect;
	calloutStruct->flags = 0;
	calloutStruct->classifyFn = FwpsCalloutClassifyFn;
	calloutStruct->notifyFn = FwpsCalloutNotifyFn;
	calloutStruct->flowDeleteFn = FwpsCalloutFlowDeleteNotifyFn;
	return calloutStruct;


}
FWPM_CALLOUT* getFWPMConnectCallout(){

	FWPM_CALLOUT* calloutStruct = ExAllocatePool(NonPagedPool, sizeof(FWPM_CALLOUT));

	RtlZeroMemory(calloutStruct, sizeof(FWPM_CALLOUT));

	calloutStruct->calloutKey = CLSID_NetworkMonitorConnect;
	calloutStruct->displayData.name = L"NetworkMonitor Callout: Outbound TCP (IPV4).";
	calloutStruct->flags = FWPM_CALLOUT_FLAG_PERSISTENT;
	calloutStruct->applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	return calloutStruct;


}
FWPM_FILTER* getFWPMConnectFilter(){

	FWPM_FILTER* layerFilters = ExAllocatePool(NonPagedPool, sizeof(FWPM_FILTER));
	RtlZeroMemory(layerFilters, sizeof(FWPM_FILTER));

	layerFilters->displayData.name = L"NetworkMonitor Filter: Outbound TCP (IPV4).";
	layerFilters->flags = FWPM_FILTER_FLAG_PERSISTENT;
	layerFilters->layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	layerFilters->action.type = FWP_ACTION_CALLOUT_INSPECTION;
	layerFilters->action.calloutKey = CLSID_NetworkMonitorConnect;
	layerFilters->numFilterConditions = 0;
	return layerFilters;
}
