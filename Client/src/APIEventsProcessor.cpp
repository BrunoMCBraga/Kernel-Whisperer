#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <aclapi.h>
#include "sqldriver"
#include "logparser"
#include "apieventsprocessor"

using namespace std;

#define MAX_MESSAGE_SIZE 500

int APIEventsProcessor::run(DWORD currentPid, std::wstring hostNameWide){

  HANDLE hSLot;
  HANDLE hEvent;
  DWORD nextMessageSize;
  DWORD pendingMessages;
  DWORD numberOfBytesRead;
  wchar_t message[MAX_MESSAGE_SIZE] = {'\0'};
  OVERLAPPED ov; 
  BOOL result;
  DWORD error;
  EXPLICIT_ACCESS explicitAccessArray[1] = {'\0'};
  SECURITY_ATTRIBUTES msSecurityAttributes = {'\0'};
  SECURITY_DESCRIPTOR msSecurityDescriptor = {'\0'};
  SID_IDENTIFIER_AUTHORITY sidAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
  PSID pEveryoneSID;
  PACL pAcl;


  result = AllocateAndInitializeSid(&sidAuthWorld, 1,SECURITY_WORLD_RID,0, 0, 0, 0, 0, 0, 0,&pEveryoneSID);
  if(!result){
    std::cout << "APIEventsProcessor->run->AllocateAndInitializeSid failed:" << std::hex << GetLastError() << std::endl;
    return 1;
  }


  explicitAccessArray[0].grfAccessPermissions = (GENERIC_ALL | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL);
  explicitAccessArray[0].grfAccessMode = SET_ACCESS;
  explicitAccessArray[0].grfInheritance= CONTAINER_INHERIT_ACE|OBJECT_INHERIT_ACE;
  explicitAccessArray[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  explicitAccessArray[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  explicitAccessArray[0].Trustee.ptstrName = (LPTSTR) pEveryoneSID;

  error = SetEntriesInAcl(1, explicitAccessArray, NULL, &pAcl);
  if(error != ERROR_SUCCESS){
    std::cout << "APIEventsProcessor->run->SetEntriesInAcl failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }

  result = InitializeSecurityDescriptor(&msSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
  if(!result){
    std::cout << "APIEventsProcessor->run->InitializeSecurityDescriptor failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }

  //We need to set the DACL inside SECURITY_DESCRIPTOR to NULL to allow full access. I may restrict this a bit more
  //later but it does not seem necessary.

  result = SetSecurityDescriptorDacl(&msSecurityDescriptor, TRUE, pAcl, FALSE);

  if(!result){
    std::cout << "APIEventsProcessor->run->SetSecurityDescriptorDacl failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }

  msSecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  msSecurityAttributes.lpSecurityDescriptor = &msSecurityDescriptor;
  msSecurityAttributes.bInheritHandle = FALSE;

  hSLot = CreateMailslot("\\\\.\\mailslot\\kw_mailslot", 0, MAILSLOT_WAIT_FOREVER, &msSecurityAttributes);

  if(hSLot == INVALID_HANDLE_VALUE){
    std::cout << "APIEventsProcessor->run->CreateMailslot failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }
  
  hEvent = CreateEvent(NULL, FALSE, FALSE, "KWMailSlotEvent");
  if(hEvent == NULL){
    std::cout << "APIEventsProcessor->run->CreateEvent failed:" << std::hex << GetLastError() << std::endl;  
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }

  ov.Offset = 0;
  ov.OffsetHigh = 0;
  ov.hEvent = hEvent;

  while(TRUE){
  
    result = GetMailslotInfo(hSLot, (LPDWORD) NULL, &nextMessageSize, &pendingMessages, (LPDWORD) NULL);

    if(!result){
      std::cout << "APIEventsProcessor->run->GetMailslotInfo failed: " << std::hex << GetLastError() << std::endl;
      continue;
    }


    if((pendingMessages > 0) && (nextMessageSize > 0)){

      result = ReadFile(hSLot, message, nextMessageSize, &numberOfBytesRead, &ov);
      if(!result){
        std::cout << "APIEventsProcessor->run->ReadFile failed: " << std::hex << GetLastError() << std::endl;
        continue;
      }      

      SQLDriver::getInstance()->sqlInsertProxy(LogParser::parse(std::wstring(message)), currentPid, hostNameWide);
      memset(message, 0, numberOfBytesRead);

    }

  }
  if(pEveryoneSID)
    FreeSid(pEveryoneSID);
  if(pAcl)
    LocalFree(pAcl);


  return 0;
}