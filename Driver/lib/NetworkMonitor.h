#define NDIS60 1 //Necessary for the network stuff. Will not work otherwise.
#include <ndis.h>
#include <ntddk.h>
#include <guiddef.h>
#include <fwpsk.h>
#include <fwpmu.h>

DEFINE_GUID(CLSID_NetworkMonitorListen, 0xa6c5a715, 0x5c6e, 0x11d2, 0x97, 0x7a, 0x0, 0x0, 0xf8, 0x7a, 0x92, 0x6f);
DEFINE_GUID(CLSID_NetworkMonitoRecvAccept, 0xa6c5a715, 0x8c6e, 0x11d2, 0x97, 0x7a, 0x1, 0x0, 0xf8, 0x7a, 0x92, 0x6f);
DEFINE_GUID(CLSID_NetworkMonitorConnect, 0xa6c5a715, 0x8c6e, 0x11d2, 0x97, 0x7a, 0x0, 0x0, 0xf8, 0x9a, 0x92, 0x6f);


char* uint32ToString(UINT32 ipAddress);
//FWPS_CALLOUT_CLASSIFY_FN FwpsCalloutClassifyFn;
VOID NTAPI FwpsCalloutClassifyFn(
  const FWPS_INCOMING_VALUES *inFixedValues,
  const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
  void *layerData,
  const FWPS_FILTER *filter,
  UINT64 flowContext,
  FWPS_CLASSIFY_OUT *classifyOut
);

//FWPS_CALLOUT_NOTIFY_FN FwpsCalloutNotifyFn;
NTSTATUS NTAPI FwpsCalloutNotifyFn(FWPS_CALLOUT_NOTIFY_TYPE notifyType,const GUID *filterKey,FWPS_FILTER *filter);

//FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FwpsCalloutFlowDeleteNotifyFn;
VOID NTAPI FwpsCalloutFlowDeleteNotifyFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext);
FWPS_CALLOUT* getSCalloutStructure();

////FWPM_LAYER_ALE_AUTH_LISTEN_V4
FWPS_CALLOUT* getFWPSListenCallout();
FWPM_CALLOUT* getFWPMListenCallout();
FWPM_FILTER* getFWPMListenFilter();

//FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
FWPS_CALLOUT* getFWPSRecvAcceptCallout();
FWPM_CALLOUT* getFWPMRecvAcceptCallout();
FWPM_FILTER* getFWPMRecvAcceptFilter();

//FWPM_LAYER_ALE_AUTH_CONNECT_V4
FWPS_CALLOUT* getFWPSConnectCallout();
FWPM_CALLOUT* getFWPMConnectCallout();
FWPM_FILTER* getFWPMConnectFilter();





