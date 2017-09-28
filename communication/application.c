#include "stdafx.h"
#include <windows.h>

// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

int __cdecl main(int argc, char* argv[])
{
	HANDLE hDevice;
	char *welcome = "Hello from userland.";
	DWORD dwBytesRead = 0;
	char ReadBuffer[50] = { 0 };

	hDevice = CreateFile(L"\\\\.\\MyDevice", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("Handle : %p\n", hDevice);

	DeviceIoControl(hDevice, IOCTL_HELLO, welcome, strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	printf("Message received from kerneland : %s\n", ReadBuffer);
	printf("Bytes read : %d\n", dwBytesRead);

	CloseHandle(hDevice);

	return 0;
}
