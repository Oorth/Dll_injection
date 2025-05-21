//cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP
/*
    /c               # compile only, no linking
    /GS-             # disable stack‑security cookies
    /Zl              # omit default CRT startup code
    /O2              # full optimization (speed + size)
    /Oy              # omit frame pointers (no stack‑frame prologue/epilogue)
    /Gy              # enable function‑level COMDATs (slightly smaller code)
    /MT              # (optional) link the static CRT if need to use a few CRT routines, try avoid CRT entirely 
*/
#include "injection.h"
#include <winternl.h>

#pragma comment(linker, "/SECTION:.stub,RE")

///////////////////////////////////////////////////////////////////////////////
BYTE* pSourceBase = nullptr;
BYTE* pTargetBase = nullptr;
IMAGE_DOS_HEADER* pDosHeader = nullptr;
IMAGE_NT_HEADERS* pNtHeader = nullptr;
IMAGE_OPTIONAL_HEADER* pOptionalHeader = nullptr;
IMAGE_FILE_HEADER* pFileHeader = nullptr;
IMAGE_SECTION_HEADER* pSectionHeader = nullptr;

size_t Dll_Actual_Size = 0;
DWORD peOffset = 0;

struct _RESOURCES
{
    BYTE* Injected_dll_base;
    BYTE* Injected_Shellcode_base;
}sResources_for_shellcode;

///////////////////////////////////////////////////////////////////////////////
static void* FindExportAddress(HMODULE, const char*);
extern "C" __declspec(noinline) void __stdcall shellcode(LPVOID);
///////////////////////////////////////////////////////////////////////////////

NTSTATUS SanityCheck()
{
    norm("\n.......................................SanityCheck.......................................");

    pDosHeader = (IMAGE_DOS_HEADER*) pSourceBase;
    if(pDosHeader->e_magic != 0x5A4D)
    {
        fuk("Invalid DOSHeader signature");
        return false;
    } else norm("\nDOSHeader signature\t\t\t-> ", std::hex, GREEN"0x", pDosHeader->e_magic);

    //...............................................................................

    if(Dll_Actual_Size < sizeof(IMAGE_DOS_HEADER))
    {
        fuk("Buffer too small for DOSHeader header");
        return false;
    } else norm("\nBuffer Size\t\t\t\t-> ", std::hex, GREEN"0x", Dll_Actual_Size);
    
    //...............................................................................

    peOffset = pDosHeader->e_lfanew;
    if(peOffset + sizeof(IMAGE_NT_HEADERS) > Dll_Actual_Size)
    {
        fuk("e_lfanew points past buffer end");
        return false;   
    } else norm("\nvalid e_lfanew\t\t\t\t-> ", GREEN"YES");

    //...............................................................................

    pNtHeader = (IMAGE_NT_HEADERS*)(pSourceBase + peOffset);
    pOptionalHeader = &pNtHeader->OptionalHeader;
    pFileHeader = (IMAGE_FILE_HEADER*)(&pNtHeader->FileHeader);
    
    if(pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        fuk("Invalid NtHeader Signature");
    } else norm("\nNtHeader sign\t\t\t\t-> ", GREEN"YES");


    if(pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        fuk("Not a 64-bit or 32-bit PE");
        return false;
    } else norm("\nArchitecture \t\t\t\t-> ", GREEN"", (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? "64-bit" : "32-bit");

    //...............................................................................

    if(pNtHeader->OptionalHeader.SizeOfHeaders > Dll_Actual_Size)
    {
        fuk("Headers claim bigger than file");
        return false;
    } else norm("\nHeader size\t\t\t\t-> ", GREEN"OK");

    //...............................................................................

    WORD numSecs = pNtHeader->FileHeader.NumberOfSections;
    BYTE* secTable = (BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS64);
    if((secTable - pSourceBase) + numSecs * sizeof(IMAGE_SECTION_HEADER) > Dll_Actual_Size)
    {
        fuk("Section table overruns file");
        return false;
    } else norm("\nSection table overrun\t\t\t-> ", GREEN"NO");
    
    //...............................................................................

    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)secTable;
    for(int i = 0; i < numSecs; ++i)
    {
        IMAGE_SECTION_HEADER &s = secs[i];
        if(s.PointerToRawData + s.SizeOfRawData > Dll_Actual_Size)
        {
            fuk("Section raw data out of bounds");
            return false;
        }

        if(s.VirtualAddress + max(s.Misc.VirtualSize, s.SizeOfRawData) > pNtHeader->OptionalHeader.SizeOfImage)
        {
            fuk("Section VSize out of image bounds");
            return false;
        }
    }
    norm("\nSections VSize out of image bounds\t-> ", GREEN"NO");
    norm("\nSections data OutOfBounds\t\t-> ", GREEN"NO");

    //...............................................................................

    DWORD fileAlign = pNtHeader->OptionalHeader.FileAlignment;
    DWORD sectionAlign = pNtHeader->OptionalHeader.SectionAlignment;
    if(fileAlign == 0 || sectionAlign == 0 || (fileAlign & (fileAlign - 1)) || (sectionAlign & (sectionAlign - 1)) || sectionAlign < fileAlign)
    {
        fuk("Weird alignment values");
        return false;
    } else norm("\nAlignment\t\t\t\t-> ", GREEN"OK");
    

    norm("\n.......................................SanityCheck.......................................\n");
    return true;
}

NTSTATUS ManualMap(HANDLE hproc, std::vector <unsigned char> *downloaded_dll)
{
    norm("\n===========================================ManualMap===========================================");

    pSourceBase = downloaded_dll->data();
    Dll_Actual_Size = downloaded_dll->size();
    
    SanityCheck();

    //==========================================================================================

    #pragma region Allocate_mem

    /* 
        Allocated pOptionalHeader->SizeOfImage of memory at preffered base
        target base ->      pTargetBase
        space allocated ->  pOptionalHeader->SizeOfImage

        Verify
            State should be 0x1000
            type should be 0x20000
            Protect should be 0x40
    */

    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, reinterpret_cast<void *>(pOptionalHeader->ImageBase), pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!pTargetBase)
    {
        warn("Allocation on preffered base failed, allocating randomly\n");
        
        pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, nullptr, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if(!pTargetBase)
        {
            fuk("Coudnt allocate memory ", GetLastError());
            delete[] pSourceBase;
            return 0;
        }
    } norm(std::hex, "\nAllocated ", CYAN"0x", pOptionalHeader->SizeOfImage, " bytes (", pOptionalHeader->SizeOfImage / 1024, " KB)", RESET" remote Memory at -> ", CYAN"0x", (uintptr_t)pTargetBase);


    //verify
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID baseAddress = 0;

    if(VirtualQueryEx(hproc, pTargetBase, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if(mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x40) norm(std::hex,"\n[", GREEN"OK", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect, "\n");
        else norm(std::hex, "\n[", RED"ISSUE", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect);
    } else fuk("VirtualQueryEx failed");

    #pragma endregion
    
    //==========================================================================================

    #pragma region Cpy_Headers

    /* 
        Cpy the whole header to the target base at pTargetBase
        size of header is in pOptionalHeader->SizeOfHeaders;

        Verify
            query the region
            no header and section overlap

    */

    norm("\n- - - - - - - - - - - - - Copy Headers - - - - - - - - - - - - -");
    norm("\nCopying Headers in the target..");

    if(!WriteProcessMemory(hproc, pTargetBase, pSourceBase, pOptionalHeader->SizeOfHeaders, nullptr))
    {
        fuk("Failed to copy headers");
        delete[] pSourceBase;
        return 0;
    }

    //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =
    // MEMORY_BASIC_INFORMATION mbi;
    if(VirtualQueryEx(hproc, pTargetBase, &mbi, sizeof(mbi)) != sizeof(mbi))
    {
        fuk("Can't query remote region");
        return false;
    }

    IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeader);
    if(pOptionalHeader->SizeOfHeaders > pSection->PointerToRawData)
    {
        fuk("Headers overlap first section!");
        return false;
    }
    //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =

    norm("\nHeaders Copied to ", std::hex, CYAN"0x", (uintptr_t)pTargetBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pTargetBase + pOptionalHeader->SizeOfHeaders), RESET" size[", CYAN"0x", (uintptr_t)pOptionalHeader->SizeOfHeaders, RESET"]");

    norm("\n- - - - - - - - - - - - - Copy Headers - - - - - - - - - - - - -\n");
    #pragma endregion

    //==========================================================================================

    #pragma region Cpy_Sections

    /* 
        copy the sections to the target at pTargetBase + pSectionHeader->VirtualAddress
        form an offset of PointerToRawData in pSourceBase

        verify each by printing the section names and then the start and end addresses of all..
    */
    
    norm("\n= = = = = = = = = = = = = Copy Sections = = = = = = = = = = = = =");
    norm("\nCopying Sections in the target..");
    
    // IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeader);
    for(UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++pSection)
    {
        if(pSection->SizeOfRawData)
        {
            auto pSource = pSourceBase + pSection->PointerToRawData;
            auto pTarget = pTargetBase + pSection->VirtualAddress;
            
            if(!WriteProcessMemory(hproc, pTarget, pSource, pSection->SizeOfRawData, nullptr))
            {
                fuk("Coudnt copy the sections in target memory");
                delete[] pSourceBase;
                return 0;
            }
            

            //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =

            if(pSection->SizeOfRawData > 0x7FFFFFFF)
            {
                fuk("Section size too large - possible overflow");
                delete[] pSourceBase;
                return 0;
            }
            
            uintptr_t sectionEnd = (uintptr_t)pTarget + pSection->SizeOfRawData;      // Overflow check
            if(sectionEnd < (uintptr_t)pTarget)
            {  
                fuk("Section address overflow detected");
                delete[] pSourceBase;
                return 0;
            }

            MEMORY_BASIC_INFORMATION mbi;
            if(VirtualQuery((LPCVOID)pTarget, &mbi, sizeof(mbi)) == 0)                     // Verify section is within allocated memory bounds
            {
                fuk("Cannot query memory region");
                delete[] pSourceBase;
                return 0;
            }

            if(sectionEnd > ((uintptr_t)mbi.BaseAddress + mbi.RegionSize))
            {
                fuk("Section extends beyond allocated memory");
                delete[] pSourceBase;
                return 0;
            }

            //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =

            norm("\nSection ", GREEN"", pSection->Name, RESET"\tfrom ", std::hex, CYAN"0x", (uintptr_t)pTarget, RESET"", " to ", CYAN"0x", sectionEnd, RESET" size[", CYAN"0x", (uintptr_t)pSection->SizeOfRawData, RESET"]");
        }
    }
    norm("\n= = = = = = = = = = = = = Copy Sections = = = = = = = = = = = = =");

    #pragma endregion

    //==========================================================================================

    #pragma region Inject_Shellcode
    /*
        calculate the size of the shellcode and store it in shellcodeBlockSize
        inject the shellcode at pShellcodeTargetBase
        
        Execute it via a remote thread...
    */

    norm("\n\n=_=_=_=_=_=_=_=_=_=_=_=_=_Cpy Shellcode_=_=_=_=_=_=_=_=_=_=_=_=_=");
    norm("\nCopying Shellcode in the target..");

    
    BYTE* exeBase = (BYTE*)GetModuleHandle(NULL);
    auto dos  = (IMAGE_DOS_HEADER*)exeBase;
    auto nt   = (IMAGE_NT_HEADERS*)(exeBase + dos->e_lfanew);
    auto sec  = IMAGE_FIRST_SECTION(nt);

    void* vpStartAddressOfShellcode = nullptr;
    size_t shellcodeBlockSize = 0;
    IMAGE_SECTION_HEADER* stubSection = nullptr;

    for(UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++sec)
    {
        if(sec->SizeOfRawData)
        {
            if(memcmp(sec->Name, ".stub", 5) == 0)
            {
                vpStartAddressOfShellcode = exeBase + sec->VirtualAddress;
                shellcodeBlockSize = sec->Misc.VirtualSize;
                stubSection = sec;
                break;
            }
        }
    }
    if(!stubSection)
    {
        fuk("Could not find .stub section");
        return 0;
    } norm("\nStart location of ", CYAN"", stubSection->Name, RESET" is", CYAN" 0x", (uintptr_t)vpStartAddressOfShellcode, RESET" size[", CYAN"0x", shellcodeBlockSize, RESET"]");
    
    // BYTE* pShellcodeTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, nullptr, shellcodeBlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    // if(!pShellcodeTargetBase)
    // {
    //     fuk("Coudnt allocate memory ", GetLastError());
    //     delete[] pSourceBase;
    //     return 0;
    // } norm(std::hex, "\n\nAllocated ", CYAN"0x", shellcodeBlockSize, " bytes (", shellcodeBlockSize / 1024.0, " KB)", RESET" remote Memory at -> ", CYAN"0x", (uintptr_t)pShellcodeTargetBase);

    BYTE* pShellcodeResourceBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, nullptr, shellcodeBlockSize + sizeof(_RESOURCES), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!pShellcodeResourceBase)
    {
        fuk("Coudnt allocate memory ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm(std::hex, "\n\nAllocated ", CYAN"0x", shellcodeBlockSize, " bytes (", shellcodeBlockSize / 1024.0, " KB)", RESET" remote Memory at -> ", CYAN"0x", (uintptr_t)pShellcodeResourceBase);

    //verify
    if(VirtualQueryEx(hproc, pShellcodeResourceBase, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if(mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x40) norm(std::hex,"\n[", GREEN"OK", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect, "\n");
        else norm(std::hex, "\n[", RED"ISSUE", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect);
    } else fuk("VirtualQueryEx failed");

    //-------------------------------
        BYTE* pShellcodeTargetBase = pShellcodeResourceBase + sizeof(sResources_for_shellcode);
        sResources_for_shellcode.Injected_dll_base = pTargetBase;
        sResources_for_shellcode.Injected_Shellcode_base = pShellcodeTargetBase;
    //--------------------------------------------------fill resources data before this------------------

    if(!WriteProcessMemory(hproc, pShellcodeResourceBase, &sResources_for_shellcode, sizeof(sResources_for_shellcode), nullptr))
    {
        fuk("Failed to copy the shellcode ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm("\nShellcode resources Copied to ", std::hex, CYAN"0x", (uintptr_t)pShellcodeResourceBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pShellcodeResourceBase + sizeof(sResources_for_shellcode)), RESET" size[", CYAN"0x", sizeof(sResources_for_shellcode), RESET"]");


    //-----------------

    if(!WriteProcessMemory(hproc, pShellcodeTargetBase, vpStartAddressOfShellcode, shellcodeBlockSize, nullptr))
    {
        fuk("Failed to copy the shellcode ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm("\nShellcode Copied to ", std::hex, CYAN"0x", (uintptr_t)pShellcodeTargetBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pShellcodeTargetBase + shellcodeBlockSize), RESET" size[", CYAN"0x", shellcodeBlockSize, RESET"]");

    
    //-----------------

    uintptr_t shellcodeFunctionAddressInMyProcess = (uintptr_t)&shellcode;
    uintptr_t shellcodeRVA = shellcodeFunctionAddressInMyProcess - (uintptr_t)exeBase;

    DWORD offsetOfShellcodeInStub = shellcodeRVA - stubSection->VirtualAddress;
    LPVOID pActualShellcodeEntryInTarget = (PBYTE)pShellcodeTargetBase + offsetOfShellcodeInStub;

    DWORD ShellcodeThreadId = 0;
    if(!CreateRemoteThread(hproc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pActualShellcodeEntryInTarget), pShellcodeResourceBase, 0, &ShellcodeThreadId))
    {
        fuk("Failed to create a thread shellcode ", GetLastError());
        return 0;
    } norm("\nThread id -> ", std::dec, CYAN"", ShellcodeThreadId);


    norm("\n=_=_=_=_=_=_=_=_=_=_=_=_=_Cpy Shellcode_=_=_=_=_=_=_=_=_=_=_=_=_=");
    #pragma endregion

    //==========================================================================================

    norm("\n===========================================ManualMap===========================================");

    fuk("!Base Relocation"); return 0;
    fuk("!Import Resolution (IAT Patching)"); return 0;
    fuk("!TLS Callbacks"); return 0;
    fuk("!Memory Protections Hardening"); return 0;
    fuk("!Call the Entry Point"); return 0;
    /*
        Cleanup & Stealth Tidy-Up
        Header Zeroing: overwrite the DOS/PE headers at pRemoteBase to hinder scanners.
        Unhook Imports: if any hooked APIs to drive the loader, unhook them in your shellcode region.
        Self-Erase Loader Stub: if inject a small bootstrap stub, have it VirtualFreeEx its own memory once the real DLL is running.
    */

    return 1;
}

static void* FindExportAddress(HMODULE hModule, const char* funcName)
{
    if(!hModule || !funcName) return nullptr;

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    DWORD peOffset = dos->e_lfanew;
    DWORD peSig = *(DWORD*)(base + peOffset);
    
    // printf("\n[DEBUG] DOS e_lfanew: 0x%X", peOffset);
    // printf("\n[DEBUG] NT Signature: 0x%X", peSig);

    base = (BYTE*)hModule;
    dos = (IMAGE_DOS_HEADER*)base;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE){ fuk("Magic did not match"); return nullptr; }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE){ fuk("NT signature did not match"); return nullptr; }

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(dir.VirtualAddress == 0){ fuk("Optional header issue"); return nullptr; }

    // printf("\nExportDir VA: 0x%X, Size: 0x%X", dir.VirtualAddress, dir.Size);
    warn("Trying to resolve ",YELLOW"", funcName);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions);

    for(DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        char* name = (char*)(base + nameRVAs[i]);
        if(_stricmp(name, funcName) == 0)
        {
            DWORD funcRVA = functions[ordinals[i]];
            BYTE* addr = base + funcRVA;

            // Forwarded export check
            if(funcRVA >= dir.VirtualAddress && funcRVA < dir.VirtualAddress + dir.Size)
            {
                fuk("Forwarded export: ", funcName);
                return nullptr;
            }
            return (void*)addr;
        }
    }

    fuk("Function not found: ", funcName);
    return nullptr;
}


#pragma region Shellcode
#pragma code_seg(push, ".stub")

    #define S_OK ((HRESULT)0L)                                                  // Common HRESULT for success
    #define STRSAFE_E_INSUFFICIENT_BUFFER ((HRESULT)0x8007007AL)                // From strsafe.h

    typedef int(WINAPI* pfnMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    typedef void(WINAPI* pfnOutputDebugStringW)(LPCWSTR lpOutputString);
    typedef HRESULT(WINAPI* pfnStringCchPrintfW)(LPWSTR pszDest, size_t cchDest, LPCWSTR pszFormat, ...);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    __declspec(allocate(".stub")) static const WCHAR kNtdll[] = L"ntdll.dll";
    __declspec(allocate(".stub")) static const WCHAR kUsr32[] = L"user32.dll";
    __declspec(allocate(".stub")) static const WCHAR hKernelbase[] = L"kernelbase.dll";

    __declspec(allocate(".stub")) static const CHAR MessageBoxWFunction[] = "MessageBoxW";
    __declspec(allocate(".stub")) static const CHAR OutputDebugStringWFunction[] = "OutputDebugStringW";

    __declspec(allocate(".stub")) pfnMessageBoxW my_MessageBoxW = nullptr;
    __declspec(allocate(".stub")) pfnOutputDebugStringW my_OutputDebugStringW = nullptr;

    __declspec(allocate(".stub")) static const WCHAR g_hexChars[] = L"0123456789ABCDEF";

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    __declspec(noinline) void __stdcall HelperSplitFilename(const WCHAR* full, SIZE_T fullLen, const WCHAR** outName, SIZE_T* outLen)
    {
        SIZE_T i = fullLen;
        while(i > 0)
        {
            WCHAR c = full[i - 1];
            if(c == L'\\' || c == L'/') break;
            --i;
        }
        *outName = full + i;
        *outLen  = fullLen - i;
    }

    __declspec(noinline) bool __stdcall isSame(const char* a, const char* b)
    {
        while(*a && *b)
        {
            char ca = *a, cb = *b;
            if(ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
            if(cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
            if(ca != cb) return false;
            ++a; ++b;
        }
        return (*a == '\0' && *b == '\0');
    }

    __declspec(noinline) bool __stdcall isSameW(const WCHAR* a, const WCHAR* b, SIZE_T len)
    {
        for(SIZE_T i = 0; i < len; i++)
        {
            WCHAR ca = a[i], cb = b[i];
            // tolower for ASCII A–Z
            if(ca >= L'A' && ca <= L'Z') ca += 32;
            if(cb >= L'A' && cb <= L'Z') cb += 32;
            if(ca != cb) return false;
        }
        return true;
    }


    __declspec(noinline) static WCHAR* __stdcall UllToHexW(unsigned __int64 val, WCHAR* buf_end, int max_chars)
    {
        // Helper to convert unsigned long long to hex string
        // Writes to buffer from right to left, returns pointer to start of written string in buffer
        if(max_chars <= 0) return buf_end;
        
        WCHAR* p = buf_end;
        *p = L'\0';
        if(val == 0 && max_chars > 0)
        {
            --p;
            *p = L'0';
            
            return p;
        }
        int count = 0;
        while(val > 0 && count < max_chars)
        {
            --p;
            *p = g_hexChars[val & 0xF];
            val >>= 4;
            count++;
        }
        return p;
    }

    __declspec(noinline) static WCHAR* __stdcall IntToDecW(int val, WCHAR* buf_end, int max_chars)
    {
        // Helper to convert integer to decimal string
        // Writes to buffer from right to left, returns pointer to start of written string in buffer
        if(max_chars <= 0) return buf_end;

        WCHAR* p = buf_end;
        *p = L'\0';
        if(val == 0 && max_chars > 0)
        {
            --p;
            *p = L'0';
            
            return p;
        }
        
        bool negative = false;
        if(val < 0)
        {
            negative = true;
            val = -val;                             // Make positive, careful with INT_MIN
            if(val < 0)
            {   
                // Overflow for INT_MIN
                // Handle INT_MIN specifically if needed, or just let it be large positive
            }
        }

        int count = 0;
        while(val > 0 && count < max_chars)
        {
            --p;
            *p = L'0' + (val % 10);
            val /= 10;
            count++;
        }
        if(negative && count < max_chars)
        {
            --p;
            *p = L'-';
        }
        return p;
    }

    __declspec(noinline) static int __cdecl ShellcodeSprintfW(LPWSTR pszDest, size_t cchDest, LPCWSTR pszFormat, ...)
    {
        // Supports: %s (LPCWSTR), %hs (LPCSTR), %p (void* as hex), %X (unsigned int as hex), %d (int as dec)
        // Returns number of characters written (excluding null terminator), or -1 on error/truncation
        
        if(!pszDest || !pszFormat || cchDest == 0) return -1;

        LPWSTR pDest = pszDest;
        LPCWSTR pFmt = pszFormat;
        size_t remaining = cchDest -1;      // Space for null terminator

        va_list args;
        va_start(args, pszFormat);

        WCHAR tempNumBuf[24];               // Buffer for number to string conversions (e.g., 64-bit hex + null)

        while(*pFmt && remaining > 0)
        {
            if(*pFmt == L'%')
            {
                pFmt++;
                switch(*pFmt)
                {
                    case L's': // Wide string
                    {
                        LPCWSTR str_arg = va_arg(args, LPCWSTR);
                        if(!str_arg) str_arg = L"(null)";
                        while(*str_arg && remaining > 0)
                        {
                            *pDest++ = *str_arg++;
                            remaining--;
                        }
                        break;
                    }

                    case L'h': // Potentially char* string
                    {    
                        if(*(pFmt + 1) == L's')
                        {
                            pFmt++; // consume 's'
                            LPCSTR str_arg_a = va_arg(args, LPCSTR);
                            if(!str_arg_a) str_arg_a = "(null)";
                            while(*str_arg_a && remaining > 0)
                            {
                                *pDest++ = (WCHAR)(*str_arg_a++); // Basic ASCII to WCHAR conversion
                                remaining--;
                            }
                        } 
                        else  // Not 'hs', treat as literal 'h'
                        {
                            if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                            if(remaining > 0) { *pDest++ = L'h'; remaining--; }
                        }
                        break;
                    }

                    case L'p': // Pointer (hex)
                    case L'X': // Hex unsigned int (can be extended for %llX for 64-bit)
                    {
                        unsigned __int64 val_arg;
                        if(*pFmt == L'p') val_arg = (unsigned __int64)va_arg(args, void*);
                        else val_arg = (unsigned __int64)va_arg(args, unsigned int); // Promote to 64-bit for UllToHexW

                        WCHAR* num_str_start = UllToHexW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1) );
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }
                    
                    case L'd': // Integer (decimal)
                    {
                        int val_arg = va_arg(args, int);
                        
                        WCHAR* num_str_start = IntToDecW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1) );
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }
                    
                    case L'%': // Literal percent
                    {
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                        break;
                    }
                        
                    default: // Unknown format specifier, print literally
                    {
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                        if(*pFmt && remaining > 0) { *pDest++ = *pFmt; remaining--; } // Print the char after %
                        break;
                    }
                }
            } 
            else 
            {
                *pDest++ = *pFmt;
                remaining--;
            }
            if(*pFmt) pFmt++; // Move to next format char if not end of string
        }

        va_end(args);
        *pDest = L'\0'; // Null terminate

        if(*pFmt != L'\0') return -1; // Format string not fully processed (ran out of buffer)
        return (int)(pDest - pszDest); // Number of characters written
    }


    __declspec(noinline) static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, const char* funcName)
    {
        if(!hModule || !funcName) return nullptr;

        BYTE* base = (BYTE*)hModule;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        DWORD peOffset = dos->e_lfanew;
        DWORD peSig = *(DWORD*)(base + peOffset);
        
        base = (BYTE*)hModule;
        dos = (IMAGE_DOS_HEADER*)base;
        if(dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if(nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if(dir.VirtualAddress == 0) return nullptr;

        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
        DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);
        WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions);

        for(DWORD i = 0; i < exp->NumberOfNames; ++i)
        {
            char* name = (char*)(base + nameRVAs[i]);
            if(isSame(name, funcName))
            {
                DWORD funcRVA = functions[ordinals[i]];
                BYTE* addr = base + funcRVA;

                // Forwarded export check
                if(funcRVA >= dir.VirtualAddress && funcRVA < dir.VirtualAddress + dir.Size) return nullptr;
                return (void*)addr;
            }
        }
        return nullptr;
    }

    __declspec(noinline) void __stdcall shellcode(LPVOID lpParameter)
    {
        struct _LIBS
        {
            HMODULE hHookedNtdll;
            HMODULE hUnhookedNtdll;
            HMODULE hKERNEL32;
            HMODULE hKERNELBASE;
            HMODULE hUsr32;
        }sLibs;

        typedef struct _MY_PEB_LDR_DATA
        {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID  SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } MY_PEB_LDR_DATA, *MY_PPEB_LDR_DATA;

        typedef struct _LDR_DATA_TABLE_ENTRY
        {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

        _RESOURCES* pResources = (_RESOURCES*)lpParameter;

        #ifdef _M_IX86
            PEB* pPEB = (PEB*) __readfsqword(0x30);
        #else
            PEB* pPEB = (PEB*) __readgsqword(0x60);   
        #endif
        
        MY_PEB_LDR_DATA* pLdr = (MY_PEB_LDR_DATA*)pPEB->Ldr;
        auto head = &pLdr->InLoadOrderModuleList;
        auto current = head->Flink;    // first entry is the EXE itself
        
        //walk load‑order
        while(current != head)
        {
            auto entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if(entry->BaseDllName.Buffer)
            {
                const WCHAR* namePtr;
                SIZE_T nameLen;

                HelperSplitFilename(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR), &namePtr, &nameLen);

                SIZE_T k32len = sizeof(kUsr32)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, kUsr32, k32len)) sLibs.hUsr32 = (HMODULE)entry->DllBase;

                k32len = sizeof(hKernelbase)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, hKernelbase, k32len)) sLibs.hKERNELBASE = (HMODULE)entry->DllBase;

                k32len = sizeof(kNtdll)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, kNtdll, k32len)) sLibs.hHookedNtdll = (HMODULE)entry->DllBase;
            }
            current = current->Flink;
        }
        if(sLibs.hUsr32 == nullptr || sLibs.hKERNELBASE == nullptr) __debugbreak();
        
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        my_MessageBoxW = (pfnMessageBoxW)ShellcodeFindExportAddress(sLibs.hUsr32, MessageBoxWFunction);
        if(my_MessageBoxW == nullptr) __debugbreak();

        my_OutputDebugStringW = (pfnOutputDebugStringW)ShellcodeFindExportAddress(sLibs.hKERNELBASE, OutputDebugStringWFunction);
        if(my_OutputDebugStringW == nullptr) __debugbreak();
            
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        __declspec(allocate(".stub")) static const WCHAR INJECTED[] = L"INJECTED"; __declspec(allocate(".stub")) static const WCHAR s2[] = L"Hello from injected shellcode!";
        // my_MessageBoxW(NULL, s2, INJECTED, MB_OK | MB_TOPMOST);
        my_OutputDebugStringW(s2);

        __declspec(allocate(".stub")) static const WCHAR s3[] = L"Shellcode is injected at -> ";
        my_OutputDebugStringW(s3);
        

        // __debugbreak();
    }

#pragma code_seg(pop)
#pragma endregion