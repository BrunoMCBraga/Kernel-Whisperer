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

	    printf("INSERT:[%ls]\n", command);

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
	    printf("Response:%s\n",recvbuf);
	    printf("FileEntries:%d\n", fileEntries);
	    printf("RegEntries:%d\n", regEntries);
	    printf("NetworkEntries:%d\n", networkEntries);
	    printf("ProcessEntries:%d\n", processEntries);
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

int SQLDriver::insertProcessEvent(std::wstring timestamp, std::wstring hostname, std::wstring ppid, std::wstring pImageFilePath, std::wstring pid, std::wstring imageFilePath, std::wstring commandLine){

	std::wstringstream queryStringStream;
	queryStringStream << FORMAT_DB_INSERT_PROCESS_EVENT_FIRST << timestamp << L',' << L'\'' << hostname << L'\'' << L',' << ppid <<  L',' << L'\'' << pImageFilePath << L'\'' << L',' << pid << L',' << L'\'' << imageFilePath << L'\'' << L',' << L'\'' << commandLine << L'\'' << FORMAT_DB_INSERT_PROCESS_EVENT_SECOND;
	std::wstring finalString = queryStringStream.str();
	processEntries+=1;
	
	return sendCommand(finalString.c_str(), finalString.length());

}


