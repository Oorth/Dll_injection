//cl /EHsc /GS- /Oy .\main.cpp .\injection.cpp /link /OUT:main.exe
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

#pragma comment(linker, "/SECTION:.stub,RWE")

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

///////////////////////////////////////////////////////////////////////////////
void* FindExportAddress(HMODULE hModule, const char* funcName);
__declspec(noinline) void __stdcall shellcode(RESOURCES sResources);
__declspec(noinline) void __cdecl ShellcodeEndMarker();
///////////////////////////////////////////////////////////////////////////////

NTSTATUS SanityCheck()
{
    norm("\n.......................................SanityCheck.......................................");

    pDosHeader = (IMAGE_DOS_HEADER*) pSourceBase;
    if (pDosHeader->e_magic != 0x5A4D)
    {
        fuk("Invalid DOSHeader signature");
        return false;
    } else norm("\nDOSHeader signature\t\t\t-> ", std::hex, GREEN"0x", pDosHeader->e_magic);

    //...............................................................................

    if (Dll_Actual_Size < sizeof(IMAGE_DOS_HEADER))
    {
        fuk("Buffer too small for DOSHeader header");
        return false;
    } else norm("\nBuffer Size\t\t\t\t-> ", std::hex, GREEN"0x", Dll_Actual_Size);
    
    //...............................................................................

    peOffset = pDosHeader->e_lfanew;
    if (peOffset + sizeof(IMAGE_NT_HEADERS64) > Dll_Actual_Size)
    {
        fuk("e_lfanew points past buffer end");
        return false;   
    } else norm("\nvalid e_lfanew\t\t\t\t-> ", GREEN"YES");

    //...............................................................................

    pNtHeader = (IMAGE_NT_HEADERS64*)(pSourceBase + peOffset);
    pOptionalHeader = &pNtHeader->OptionalHeader;
    pFileHeader = &pNtHeader->FileHeader;
    
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
    for (int i = 0; i < numSecs; ++i)
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

    void* vpStartAddressOfShellcode = &shellcode;
    void* vpEndAddressOfShellcode = &ShellcodeEndMarker;

    size_t shellcodeBlockSize = (uintptr_t)vpEndAddressOfShellcode - (uintptr_t)vpStartAddressOfShellcode;

    
    BYTE* pShellcodeTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, nullptr, shellcodeBlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!pShellcodeTargetBase)
    {
        fuk("Coudnt allocate memory ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm(std::hex, "\n\nAllocated ", CYAN"0x", shellcodeBlockSize, " bytes (", shellcodeBlockSize / 1024.0, " KB)", RESET" remote Memory at -> ", CYAN"0x", (uintptr_t)pShellcodeTargetBase);


    //verify
    if(VirtualQueryEx(hproc, pShellcodeTargetBase, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if(mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x40) norm(std::hex,"\n[", GREEN"OK", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect, "\n");
        else norm(std::hex, "\n[", RED"ISSUE", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect);
    } else fuk("VirtualQueryEx failed");



    if(!WriteProcessMemory(hproc, pShellcodeTargetBase, vpStartAddressOfShellcode, shellcodeBlockSize, nullptr))
    {
        fuk("Failed to copy the shellcode");
        delete[] pSourceBase;
        return 0;
    } norm("\nShellcode Copied to ", std::hex, CYAN"0x", (uintptr_t)pShellcodeTargetBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pShellcodeTargetBase + shellcodeBlockSize), RESET" size[", CYAN"0x", shellcodeBlockSize, RESET"]");

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

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
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

    __declspec(noinline) void __stdcall shellcode(RESOURCES sResources)
    {
        
        sResources.My_LoadLibraryA = LoadLibraryA;
        sResources.FindExportAddress = FindExportAddress;


        int a = 0x10;
        __debugbreak();
    }

    __declspec(noinline) void __cdecl ShellcodeEndMarker(){ }           //MarkerFunction
#pragma code_seg(pop)
#pragma endregion