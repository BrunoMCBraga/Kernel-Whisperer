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

  SID_IDENTIFIER_AUTHORITY sidMLA = SECURITY_MANDATORY_LABEL_AUTHORITY;
  PSID pLowIntegritySID;
  PACL pSACL;
  DWORD aclLength;


  result = InitializeSecurityDescriptor(&msSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
  if(!result){
    std::cout << "APIEventsProcessor->run->InitializeSecurityDescriptor failed:" << std::hex << GetLastError() << std::endl;
    return 1;
  }

  result = AllocateAndInitializeSid(&sidAuthWorld, 1,SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0,&pEveryoneSID);
  if(!result){
    std::cout << "APIEventsProcessor->run->AllocateAndInitializeSid failed:" << std::hex << GetLastError() << std::endl;
    return 1;
  }


  explicitAccessArray[0].grfAccessPermissions = (GENERIC_READ | GENERIC_WRITE);
  explicitAccessArray[0].grfAccessMode = SET_ACCESS;
  explicitAccessArray[0].grfInheritance= NO_INHERITANCE;
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

  result = SetSecurityDescriptorDacl(&msSecurityDescriptor, TRUE, pAcl, FALSE);

  if(!result){
    std::cout << "APIEventsProcessor->run->SetSecurityDescriptorDacl failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }

  /*
    Some processes like Internet Explorer spawn child processes with low-integrity. We need to account for those
    by allowing low-integrity processes to access the mailslot. We need to configure a SACL. 

  */

  result = AllocateAndInitializeSid(&sidMLA, 1, 0x1000, 0, 0, 0, 0, 0, 0, 0, &pLowIntegritySID);
  if(!result){
    std::cout << "APIEventsProcessor->run->AllocateAndInitializeSid failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    return 1;
  }

  aclLength = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetLengthSid(pLowIntegritySID) - sizeof(DWORD);
  pSACL = (PACL) LocalAlloc(LPTR, aclLength);

  if(pSACL == NULL){
    std::cout << "APIEventsProcessor->run->LocalAlloc failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    return 1;
  }

  result = InitializeAcl(pSACL, aclLength, ACL_REVISION);
  if(!result){
    std::cout << "APIEventsProcessor->run->InitializeAcl failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    if(pSACL)
      LocalFree(pSACL);
    return 1;
  }

  result = AddMandatoryAce(pSACL, ACL_REVISION, 0, 0, pLowIntegritySID);
  if(!result){
    std::cout << "APIEventsProcessor->run->AddMandatoryAce failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    if(pSACL)
      LocalFree(pSACL);
    return 1;
  }

  result = SetSecurityDescriptorSacl(&msSecurityDescriptor, TRUE, pSACL, FALSE);
  if(!result){
    std::cout << "APIEventsProcessor->run->SetSecurityDescriptorSacl failed:" << std::hex << GetLastError() << std::endl;
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    if(pSACL)
      LocalFree(pSACL);
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
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    if(pSACL)
      LocalFree(pSACL);
    return 1;
  }
  
  hEvent = CreateEvent(NULL, FALSE, FALSE, "KWMailSlotEvent");
  if(hEvent == NULL){
    std::cout << "APIEventsProcessor->run->CreateEvent failed:" << std::hex << GetLastError() << std::endl;  
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    if(pSACL)
      LocalFree(pSACL);
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
      std::cout << "Reading" << std::endl;
      result = ReadFile(hSLot, message, nextMessageSize, &numberOfBytesRead, &ov);
      if(!result){
        std::cout << "APIEventsProcessor->run->ReadFile failed: " << std::hex << GetLastError() << std::endl;
        continue;
      }      
      std::wcout << std::wstring(message) << std::endl;
      SQLDriver::getInstance()->sqlInsertProxy(LogParser::parse(std::wstring(message)), currentPid, hostNameWide);
      memset(message, 0, numberOfBytesRead);

    }

  }
    if(pEveryoneSID)
      FreeSid(pEveryoneSID);
    if(pAcl)
      LocalFree(pAcl);
    if(pLowIntegritySID)
      FreeSid(pLowIntegritySID);
    if(pSACL)
      LocalFree(pSACL);


  return 0;
}