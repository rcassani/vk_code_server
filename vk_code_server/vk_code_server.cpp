// keyboard_hook.cpp
// 
// Installs a Low Level Keyboard Hook WH_KEYBOARD_LL
// The values shown are UINT8 Virtual-Key Codes
// https://msdn.microsoft.com/en-us/library/windows/desktop/dd375731(v=vs.85).aspx
// Raymundo Cassani
// 2016

#ifndef WIN32_LEAN_AND_MEAN		//TCP
#define WIN32_LEAN_AND_MEAN     //TCP
#endif                          //TCP


#include <iostream>
#include <Windows.h>    // HOOKS
#include <winsock2.h>   // TCP
#include <ws2tcpip.h>   // TCP
#include <stdlib.h>     // TCP

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Ws2_32.lib")             //TCP
#pragma comment (lib, "Mswsock.lib")           //TCP
#pragma comment (lib, "AdvApi32.lib")          //TCP

// HHOOK variable
HHOOK hHook{ NULL };
BOOL client_cnx = false;
SOCKET ClientSocket = INVALID_SOCKET;

/*
 * Event Handler (callback funtion), it is called in response to a change in the state of a key
 * https://msdn.microsoft.com/en-us/library/ms644985(v=vs.85).aspx
 */
LRESULT CALLBACK CatchLowLevelKeyboardProc(const int nCode, const WPARAM wParam, const LPARAM lParam)
{
	// lParam is cast as KBDLLHOOKSTRUCT
	KBDLLHOOKSTRUCT keyInfo = *((KBDLLHOOKSTRUCT*)lParam);

	// wParam is the The identifier of the keyboard message. 
	// This parameter can be one of the following messages: WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, or WM_SYSKEYUP. 
	switch (wParam)
	{
	case WM_KEYDOWN:
		printf("KeyDown event, Key = %d = %c \r\n ", keyInfo.vkCode, keyInfo.vkCode);
		if (ClientSocket != INVALID_SOCKET)
		{
			unsigned char buf[1];
			buf[0] = (keyInfo.vkCode >> 0) & 0xff;
			
			printf("ClientSocket = OK2");
			int iSendResult = send(ClientSocket, (char*)buf, sizeof(buf), 0);
			printf("%d", iSendResult);
		}
		break;
	}
	// Passes the hook information to the next hook procedure. So other hooks can work
	return CallNextHookEx(hHook, nCode, wParam, lParam);
}


/*
 * Handles Close (X in corner) and Ctrl-C interruption

BOOL CtrlHandler(DWORD fdwCtrlType)
{
	//running = false;
	printf("%d", fdwCtrlType);
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		printf("control C");
		return(FALSE);
	
		// CTRL-CLOSE (X in corner)
	case CTRL_CLOSE_EVENT:
		printf("TAAACHE\n\n");
		Beep(600, 600);
		return(TRUE);

	default:
		return TRUE;
	}
}
*/

/*
 * Creates Listening Socket (Server)
 */
SOCKET CreateListenSocket(char* port)
{

	// Initialize Winsock
	WSADATA wsaData;        //structure is used to store Windows Sockets initialization information		
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		//printf("Error at WSAStartup(), error %d\n", iResult); 
		return INVALID_SOCKET;
	}

	struct addrinfo *result = NULL, *ptr = NULL, hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, port, &hints, &result);
	if (iResult != 0)
	{
		//printf("Error at getaddrinfo(), error %d\n", iResult); 
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Create a SOCKET for connecting to server
	SOCKET ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return INVALID_SOCKET;
	}

	return ListenSocket;
}

/*
 * Opens the communications with the Client
 */
SOCKET ConnectClientSocket(SOCKET ListenSocket)
{
	int iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return INVALID_SOCKET;
	}
}


int main(int argc, char* argv[])
{
	char *port = NULL;
	SOCKET ListenSocket = INVALID_SOCKET;

	
	// Installing HOOK
	printf("Installing the hook\r\n");
	hHook = SetWindowsHookEx(WH_KEYBOARD_LL, CatchLowLevelKeyboardProc, NULL, 0);
	if (hHook != NULL)
	{
		printf("Hook installed successfully\r\n");
	}
	else
	{
		printf("Error installing hook\r\n");
	}

	/* 
	if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE))
	{
		printf("Handler added successfully\r\n");
	}
	else
	{
		printf("Error adding handler\r\n");
	}
	*/
	
	// Getting arguments & Creating ListenSocket
	if (argc != 2)
	{
		printf("Usage: %s <PORT>\n", argv[0]);
		printf("KEYDOWN events will not be streamed\n");
	}
	else
	{
		port = argv[1];
		printf("Opening Listnener at port: %s\n", port);
		ListenSocket = CreateListenSocket(port);
		if (ListenSocket == INVALID_SOCKET)
		{
			printf("Error at creating listener at port: %s\n", port);
			printf("KEYDOWN events will not be streamed\n");
		}
	}

	printf("client_cnx was false, waiting for client ...");
	ClientSocket = ConnectClientSocket(ListenSocket);
	if (ClientSocket == INVALID_SOCKET)
	{
		printf("ClientSocket = Invalid");
		client_cnx = false;
	}
	else
	{
		printf("ClientSocket = OK");
		client_cnx = true;
	}


		
	while (true)
	{		
		GetMessage(NULL, NULL, 0, 0);
	}
	
	return 0;
}
