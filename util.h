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

#include <windows.h>

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

SIZE_T StringLengthA(_In_ LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

PCHAR StringCopyA(_Inout_ PCHAR String1, _In_ LPCSTR String2)
{
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

PCHAR ToLower(_In_ PCHAR Ptr)
{
    PCHAR sv = Ptr;
    while (*sv != '\0')
    {
        if (*sv >= 'A' && *sv <= 'Z')
            *sv = *sv + ('a' - 'A');

        sv++;
    }
    return Ptr;
}

/*
s1 and s2 are the string sizes NOT counting terminating NULL, dstSz is the TOTAL destination string size, including termination
*/
BOOL StringConcat(PCHAR dest, size_t dstSz, PCSTR str1, size_t s1, PCSTR str2, size_t s2){
    if (s1 > StringLengthA(str1) || s2 > StringLengthA(str2) || dstSz < s1 + s2 + 1){
        //printf("bad input string size\n");
        return FALSE;
    }
    for (int i = 0; i < s1; i++){
        dest[i] = str1[i];
    }
    for (int i = 0; i < s2; i++){
        dest[s1+i] = str2[i];
    }
    dest[dstSz-1] = '\0';
    return TRUE;
}

INT cmpstr( _In_ LPCSTR String1, _In_ LPCSTR String2 )
{
	for ( ; *String1 == *String2; String1++, String2++ )
	{
		if ( *String1 == '\0' )
        {
			return 0;
        };
	};
	return ( ( *( LPCSTR )String1 < *( LPCSTR )String2 ) ? -1 : +1 );
};

SIZE_T WCharStringToCharString(_Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}