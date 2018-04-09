#include <iostream>
#include <string>
#include <sstream> 
#include <winsock2.h>  
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include "util"
#include "sqldriver"

using namespace std;


#define DB_RESPONSE_BUFFER_LENGTH 2000
#define DB_QUERY_BUFFER_LENGTH 512

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

static long regEntries = 0;
static long fileEntries = 0;
static long networkEntries = 0;
static long processEntries = 0;
static long objectEntries = 0;
static long imageLoadEntries = 0;
static long apiEntries = 0;

SQLDriver* SQLDriver::sqlDriverInstance = NULL;

SQLDriver::SQLDriver(){}

SQLDriver* SQLDriver::getInstance(){

	if(sqlDriverInstance == NULL)
		sqlDriverInstance = new SQLDriver();
	return sqlDriverInstance;
}


void SQLDriver::sqlInsertProxy(std::vector<std::wstring> logComponents, DWORD currentPid, std::wstring hostname){

  unsigned long long parentPid;
  std::wstring pImagePath;
  std::wstring imagePath;
  
  unsigned long long tempPid;
  std::wstring tempImagePath; //This string will contain the path for the process associated with either the thread id or pid associated with the open handle.


  if(logComponents.size() == 0)
    return;

  
  
  if(currentPid == stoull(logComponents[2], NULL, 0))
    return;

  parentPid = (stoull(logComponents[2]) != 0) ? Util::getParentPid(stoull(logComponents[2])) : 0;
  pImagePath = (parentPid != 0) ? Util::escapeSpecialCharacters(Util::getImagePath(parentPid)) : std::wstring(L"");
  imagePath = (stoull(logComponents[2], NULL, 0) != 0) ? Util::escapeSpecialCharacters(Util::getImagePath(stoull(logComponents[2], NULL, 0))) : std::wstring(L"");
  //MAKE SURE THAT THE NUMBER OF PARAMETERS IS CORRECT. ADD ANOTHER ELEMENT TO IF.
  if(logComponents[0].compare(std::wstring(L"REG")) == 0){
    if (logComponents[3].compare(std::wstring(L"CREATEKEY")) == 0){
      (SQLDriver::getInstance())->insertRegistryEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath,  logComponents[3], logComponents[4], std::wstring(L""), std::wstring(L""));
    }
    else if (logComponents[3].compare(std::wstring(L"SETVALUE")) == 0){
      (SQLDriver::getInstance())->insertRegistryEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3], logComponents[4], logComponents[5], logComponents[6]);  
    }
  }
  else if(logComponents[0].compare(std::wstring(L"FILE")) == 0){
    (SQLDriver::getInstance())->insertFileEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3], logComponents[4]);
  }
  else if(logComponents[0].compare(std::wstring(L"NET")) == 0){
    (SQLDriver::getInstance())->insertNetworkEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3], logComponents[4], logComponents[5], logComponents[6], logComponents[7], logComponents[8]);
  }
  else if(logComponents[0].compare(std::wstring(L"PROC")) == 0){
    (SQLDriver::getInstance())->insertProcessEvent(logComponents[1], hostname, logComponents[3], pImagePath, logComponents[2], Util::escapeSpecialCharacters(logComponents[4]), logComponents[6], Util::escapeSpecialCharacters(logComponents[5]));
  }

  else if(logComponents[0].compare(std::wstring(L"OBJECT")) == 0){
    tempPid = stoull(logComponents[4]);
    tempImagePath = (tempPid != 0) ? Util::escapeSpecialCharacters(Util::getImagePath(tempPid)) : std::wstring(L"");
    (SQLDriver::getInstance())->insertObjectEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[4],  tempImagePath, logComponents[3], logComponents[5], logComponents[6]);
  }

  else if(logComponents[0].compare(std::wstring(L"LOADIMAGE")) == 0){
    tempPid = stoull(logComponents[3]);
    tempImagePath = (tempPid != 0) ? Util::escapeSpecialCharacters(Util::getImagePath(tempPid)) : std::wstring(L"");
    (SQLDriver::getInstance())->insertLoadImageEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3],  tempImagePath, logComponents[4]);
  }

  else if(logComponents[0].compare(std::wstring(L"API")) == 0){
    (SQLDriver::getInstance())->insertAPIEvent(logComponents[1], hostname, std::to_wstring(parentPid), pImagePath, logComponents[2], imagePath, logComponents[3]);
  }

  else{
    std::wcout << L"Main->sqlInsertProxy failed: Unknown Log Tag (" << logComponents[0] << L")." << std::endl;
  }
}



int SQLDriver::sendCommand(const wchar_t* command, size_t stringSize){

	 	WSADATA wsaData;
	    SOCKET ConnectSocket = INVALID_SOCKET;
	  
	    struct sockaddr_in connectionInfo;
	    char recvbuf[DB_RESPONSE_BUFFER_LENGTH];
	    int iResult;
	    int recvbuflen = DB_RESPONSE_BUFFER_LENGTH;
	    char* charBuffer = (char*) calloc(stringSize+1,1);
	    size_t inLeft, outLeft;
	    int commandIndex = 0;
	    int charBufferIndex = 0;
	    char tempCommandChar;
	    int wideCharToMultiByteResult;

	    std::wcout << L"INSERT:[" << std::wstring(command) << L"]" << std::endl;
	    wideCharToMultiByteResult = WideCharToMultiByte(CP_UTF8, 0, command, -1, charBuffer, stringSize*sizeof(wchar_t), NULL, NULL);
	    if(wideCharToMultiByteResult == 0){
	    	switch (GetLastError()){
	    		case ERROR_INSUFFICIENT_BUFFER:
	    			std::cout << "SQLDriver->sendCommand->WideCharToMultiByte failed: ERROR_INSUFFICIENT_BUFFER" << std::endl;
	    		break;
	    		case ERROR_INVALID_FLAGS:
	    			std::cout << "SQLDriver->sendCommand->WideCharToMultiByte failed: ERROR_INVALID_FLAGS" << std::endl;
	    		break;
	    		case ERROR_INVALID_PARAMETER:
	    			std::cout << "SQLDriver->sendCommand->WideCharToMultiByte failed: ERROR_INVALID_PARAMETER" << std::endl;
	    		break;
	    		case ERROR_NO_UNICODE_TRANSLATION:
	    			std::cout << "SQLDriver->sendCommand->WideCharToMultiByte failed: ERROR_NO_UNICODE_TRANSLATION" << std::endl;
	    		break;
	    		default:
	    			std::cout << "SQLDriver->sendCommand->WideCharToMultiByte failed:" << std::hex << GetLastError() << std::endl;
	    		break;
	    	}
	    	
	    	return 1;

	    }	    
	    
	    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
	    	std::cout << "SQLDriver->sendCommand->WSAStartup failed:" << std::hex << WSAGetLastError() << std::endl;
	        free(charBuffer);
	        return 1;
	    }

	  
	    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	    if (ConnectSocket == INVALID_SOCKET) {
	          std::cout << "SQLDriver->sendCommand->socket failed:" << std::hex << WSAGetLastError() << std::endl;
	          WSACleanup();
	          free(charBuffer);
	          return 1;	
	    }


	    if (ConnectSocket == INVALID_SOCKET) {
	        std::cout << "SQLDriver->sendCommand->socket failed:" << std::hex << WSAGetLastError() << std::endl;
	        WSACleanup();
	        free(charBuffer);
	        return 1;
	    }

	    connectionInfo.sin_family = AF_INET;
	    connectionInfo.sin_addr.s_addr = inet_addr(DB_IP);
	    connectionInfo.sin_port = htons(DB_PORT);

	    if (connect( ConnectSocket, ((struct sockaddr*)&connectionInfo), sizeof(sockaddr_in)) != 0) {
	    	 std::cout << "SQLDriver->sendCommand->connect failed:" << std::hex << WSAGetLastError() << std::endl;
	         closesocket(ConnectSocket);
	         ConnectSocket = INVALID_SOCKET; 
	         return 1;
	    }


	    if (send( ConnectSocket, charBuffer, stringSize, 0 ) == SOCKET_ERROR) {
	        std::cout << "SQLDriver->sendCommand->send failed:" << std::hex << WSAGetLastError() << std::endl;
	        closesocket(ConnectSocket);
	        WSACleanup();
	        free(charBuffer);
	        return 1;
	    }


	    if (shutdown(ConnectSocket, SD_SEND) == SOCKET_ERROR) {
			std::cout << "SQLDriver->sendCommand->shutdown failed:" << std::hex << WSAGetLastError() << std::endl;	        
			closesocket(ConnectSocket);
	        WSACleanup();
	        free(charBuffer);
	        return 1;
	    }

	    do {

	        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
	        if ( iResult > 0 )
	            continue;
	        else if ( iResult == 0 )
	            continue;
	        else
	        	continue;

	    } while( iResult > 0 );

	    closesocket(ConnectSocket);
	    WSACleanup();
	    std::cout << "Response:" << std::string(recvbuf) << std::endl;
	    std::cout << "FileEntries:" << to_string(fileEntries) << std::endl;
	    std::cout << "RegEntries:" << to_string(regEntries) << std::endl; 
	    std::cout << "NetworkEntries:" << to_string(networkEntries) << std::endl; 
	    std::cout << "ProcessEntries:" << to_string(processEntries) << std::endl;
	    std::cout << "ObjectEntries:" << to_string(processEntries) << std::endl;
	    std::cout << "ImageLoadEntries:" << to_string(imageLoadEntries) << std::endl;
	    std::cout << "ImageLoadEntries:" << to_string(apiEntries) << std::endl;
	    free(charBuffer);
	    return 0;

}



int SQLDriver::initDB(){

	std::wstring dbInitString = std::wstring(DB_INIT); 
	return sendCommand(dbInitString.c_str(), dbInitString.length());

}


int SQLDriver::insertRegistryEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring type, std::wstring key, std::wstring value, std::wstring data){


	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_REGISTRY_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid << L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid << L',' << L'\'' << imageFilePath << L'\'' << L',' << L'\'' <<  type << L'\'' << L',' << L'\'' << key << L'\'' << L',' << L'\'' << value << L'\'' << L',' << L'\'' << data << L'\'' << FORMAT_DB_INSERT_REGISTRY_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	regEntries+=1;
	return sendCommand(finalString.c_str(), finalString.length());

}



int SQLDriver::insertFileEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring type, std::wstring file){

	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_FILE_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid <<  L',' << L'\'' << imageFilePath << L'\'' << L',' << L'\'' << type << L'\'' << L',' << L'\'' << file << L'\'' << FORMAT_DB_INSERT_FILE_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	fileEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());

}


int SQLDriver::insertNetworkEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring protocol, std::wstring type, std::wstring lIP, std::wstring lPort, std::wstring remoteIP, std::wstring remotePort){

	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_NETWORK_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' <<  pImageFilePath << L'\'' << L',' << pid << L',' <<  L'\'' << imageFilePath << L'\'' <<	L',' << L'\'' << protocol << L'\'' << L',' << L'\'' << type << L'\'' << L',' << L'\'' << lIP << L'\'' << L',' << lPort << L',' << L'\'' << remoteIP << L'\'' << L',' << remotePort << FORMAT_DB_INSERT_NETWORK_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	networkEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());

}

int SQLDriver::insertProcessEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring pStatus, std::wstring commandLine){

	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_PROCESS_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid << L',' << L'\'' << imageFilePath << L'\'' << L',' << L'\'' << pStatus << L'\'' << L',' << L'\'' << commandLine << L'\'' << FORMAT_DB_INSERT_PROCESS_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	processEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());

}


int SQLDriver::insertObjectEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring objPid, std::wstring objImageFilePath, std::wstring objType, std::wstring handleOperation, std::wstring permissions){
	
	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_OBJECT_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid << L',' << L'\'' << imageFilePath << L'\'' << L',' << objPid << L',' << L'\'' << objImageFilePath << L'\'' << L',' << L'\'' << objType << L'\'' << L',' << L'\'' << handleOperation << L'\'' << L',' << L'\'' << permissions << L'\'' << FORMAT_DB_INSERT_OBJECT_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	objectEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());	

}


int SQLDriver::insertLoadImageEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring hostProcessPid, std::wstring hostProcessImageFilePath, std::wstring loadedImage){

	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_LOAD_IMAGE_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid << L',' << L'\'' << imageFilePath << L'\'' << L',' << hostProcessPid << L',' << L'\'' << hostProcessImageFilePath << L'\'' << L',' << L'\'' << loadedImage << L'\'' <<  FORMAT_DB_INSERT_LOAD_IMAGE_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	imageLoadEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());
}

int SQLDriver::insertAPIEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring function){

	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_API_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid <<  L',' << L'\'' << imageFilePath << L'\'' << L',' << L'\'' << function << L'\'' << FORMAT_DB_INSERT_API_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	apiEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());

}

