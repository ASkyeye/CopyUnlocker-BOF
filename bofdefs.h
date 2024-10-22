/**
 * Copyright 2024 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <windows.h>

#ifdef BOF
#define GetModuleHandleA 		 	KERNEL32$GetModuleHandleA
#define GetProcAddress 				KERNEL32$GetProcAddress
#define CreateToolhelp32Snapshot	KERNEL32$CreateToolhelp32Snapshot
#define Process32First 			 	KERNEL32$Process32First
#define Process32Next 			 	KERNEL32$Process32Next
#define OpenProcess 				KERNEL32$OpenProcess
#define GetFileType 				KERNEL32$GetFileType
#define DuplicateHandle 			KERNEL32$DuplicateHandle
#define CloseHandle 				KERNEL32$CloseHandle
#define QueryDosDeviceA 			KERNEL32$QueryDosDeviceA
#define GetVolumePathNameA 			KERNEL32$GetVolumePathNameA
#define GetFileSizeEx 				KERNEL32$GetFileSizeEx
#define CreateFileMappingA 			KERNEL32$CreateFileMappingA
#define MapViewOfFile 				KERNEL32$MapViewOfFile
#define CreateFileA 				KERNEL32$CreateFileA
#define WriteFile 					KERNEL32$WriteFile
#define UnmapViewOfFile				KERNEL32$UnmapViewOfFile
#define GetLastError				KERNEL32$GetLastError

#define snprintf 					MSVCRT$_snprintf
//strlen

WINBASEAPI int __cdecl MSVCRT$_snprintf(char *buffer, size_t count, const char *__format, ...);

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileType(HANDLE hFile);
WINBASEAPI WINBOOL WINAPI KERNEL32$DuplicateHandle(  
	HANDLE   hSourceProcessHandle,
	HANDLE   hSourceHandle,
	HANDLE   hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD    dwDesiredAccess,
	BOOL     bInheritHandle,
	DWORD    dwOptions);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$QueryDosDeviceA(LPCSTR lpDeviceName, LPSTR lpTargetPath, DWORD ucchMax);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetVolumePathNameA(
	LPCSTR lpszFileName, 
	LPSTR lpszVolumePathName, 
	DWORD   cchBufferLength);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingA(
	HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD  flProtect,
	DWORD  dwMaximumSizeHigh,
	DWORD  dwMaximumSizeLow,
	LPCSTR lpName);
WINBASEAPI LPVOID WINAPI KERNEL32$MapViewOfFile(
	HANDLE hFileMappingObject,
	DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(
	LPCSTR lpFileName, 
	DWORD dwDesiredAccess, 
	DWORD dwShareMode, 
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
	DWORD dwCreationDisposition, 
	DWORD dwFlagsAndAttributes, 
	HANDLE hTemplateFile);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteFile(
	HANDLE  hFile,
	LPCVOID lpBuffer,
	DWORD   nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI KERNEL32$UnmapViewOfFile(LPCVOID lpBaseAddress);

#define intAlloc(size) 				KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) 		KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) 
#define intFree(addr) 				KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
//#define intZeroMemory(addr,size) 	MSVCRT$memset((addr),0,size)

#define msg(fmt, ...) BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__ )
#define err(fmt, ...) BeaconPrintf(CALLBACK_ERROR, fmt, ##__VA_ARGS__ )

#else

#include <stdio.h>

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) 
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define msg(fmt, ...) printf(fmt, ##__VA_ARGS__ )
#define err(fmt, ...) printf(fmt, ##__VA_ARGS__ )
#endif