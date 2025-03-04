// /std:c++17
#pragma once
#include "injection.h"
#include <fstream>

#define DEBUG_RELOC 0
#define DEBUG_SECTIONS 1

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef __WIN64
    #define RELOC_FLAG RELOC_FLAG64
#else
    #define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE hProc, const char* szDllFile)
{

    BYTE* pSrcData = nullptr;
    BYTE* pTargetBase = nullptr;

    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    
    std::cout << "-> Trying Reading DLL file";
    std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
    if (File.fail())
    {
        std::cerr << "[!] Failed to open file: " << szDllFile << std::endl;
        File.close();
        return false;
    } std::cout << "\t\t[DONE]" << std::endl;

    auto FileSize = File.tellg();
    if(FileSize < 0x1000)
    {
        std::cerr << "[!] File size too small" << std::endl;
        File.close();
        return false;
    }

    pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
    if (!pSrcData)
    {
        std::cerr << "[!] Failed to allocate memory" << std::endl;
        File.close();
        return false;
    }
    
    File.seekg(0, std::ios::beg);
    File.read(reinterpret_cast<char*>(pSrcData), FileSize);
    File.close();

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData) -> e_magic != 0x5A4D)
    {
        std::cerr << "[!] Invalid DOS header" << std::endl;
        delete[] pSrcData;
        return false;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData) -> e_lfanew);
    pOldOptHeader = &pOldNtHeader -> OptionalHeader;
    pOldFileHeader = &pOldNtHeader -> FileHeader;

    std::cout << "[*] Checking architecture";
    #ifdef _WIN64
        if(pOldFileHeader -> Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            std::cerr << "[!] Invalid architecture" << std::endl;
            delete[] pSrcData;
            return false;
        }
    #else
        if(pOldFileHeader -> Machine != IMAGE_FILE_MACHINE_I386)
        {
            std::cerr << "[!] Invalid architecture" << std::endl;
            delete[] pSrcData;
            return false;
        }
    #endif
    std::cout << "\t\t[DONE]" << std::endl;

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Allocate memory for full DLL image
    std::cout << "-> Trying to allocate at 0x" << std::hex << reinterpret_cast<void*>(pOldOptHeader -> ImageBase);
    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader -> ImageBase), pOldOptHeader -> SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!pTargetBase)
    {
        pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader -> SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if(!pTargetBase)
        {
            std::cerr << "[!] Memory allocation failed (Error: " << GetLastError() << ")" << std::endl;
            delete[] pSrcData;
            return false;
        }
    }
    if (pTargetBase) std::cout << "\t[allocated memory at: 0x" << std::hex << reinterpret_cast<void*>(pTargetBase) << "]" << std::endl;
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);


    std::cout << "\n[*] Writing sections to target process";
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for(UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
    {
        if(pSectionHeader -> SizeOfRawData)
        {
            if(!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
            {
                std::cerr << "[!] Cant map sections";
                delete[] pSrcData;
                VirtualFreeEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, MEM_RELEASE);
            }
        }
    } std::cout << "\t[DONE]" << std::endl;

    #if DEBUG_SECTIONS
    std::cout<<"\n"; for(int i=0;i<15;i++)std::cout << "=";std::cout << "SECTION_DEBUGGING";for(int i=0;i<15;i++)std::cout << "=";std::cout << std::endl;
    
        auto* pDebugSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pDebugSectionHeader)
        {
            BYTE* sectionDest = pTargetBase + pSectionHeader->VirtualAddress;
            std::cout << "-> Section Name: " << pDebugSectionHeader->Name;
            std::cout << " Section Size: 0x" << std::hex << pDebugSectionHeader->SizeOfRawData << " bytes" << std::endl;
            std::cout << "Section from [0x" << std::hex << (uintptr_t)sectionDest << "]  -> [0x" << (uintptr_t)(sectionDest + pDebugSectionHeader->SizeOfRawData - 1) << "]";
            
            std::cout << "\tTrue size [0x" << std::hex << pDebugSectionHeader->SizeOfRawData << "]"; if(i == pOldFileHeader->NumberOfSections - 1) std::cout << std::endl;
            if(i < pOldFileHeader->NumberOfSections - 1) 
            {
            auto nextSection = pDebugSectionHeader + 1;
            std::cout << "\tPadding [0x" << std::hex << (nextSection->VirtualAddress - (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)) << "]" << std::endl;
            }
        }

    for(int i=0;i<15;i++)std::cout << "=";std::cout << "SECTION_DEBUGGING";for(int i=0;i<15;i++)std::cout << "=";std::cout << std::endl << std::endl;
    #endif

    std::cout << "[*] Writing to target process";
    memcpy(pSrcData, &data, sizeof(data));
    WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);
    delete[] pSrcData;
    std::cout << "\t\t[DONE]" << std::endl;
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //Write shellcode to the remote process
    std::cout << "[*] Writing shellcode to target process";
    void* pShellCode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!pShellCode)
    {
        std::cerr << "[!] Failed" << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    WriteProcessMemory(hProc, pTargetBase, &data, sizeof(data), nullptr);
    //WriteProcessMemory(hProc, pShellCode, ShellCode, 0x1000, nullptr);
    std::cout << "\t[DONE]" << std::endl;

system("pause");

    std::cout << "[*] Creating remote thread";
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode), pTargetBase, 0, nullptr);
    if(!hThread)
    {
        std::cerr << "[!] Failed to create remote thread " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    } //std::cout << "\t\t[DONE]" << std::endl;
    std::cout << "Created thread at 0x" << std::hex << (uintptr_t)pShellCode << " (handle: 0x" << std::hex << hThread << ")" << std::endl;
    CloseHandle(hThread);

system("pause");

    HINSTANCE hCheck = 0;
    while(!hCheck)
    {
        MANUAL_MAPPING_DATA data_checked{ 0 };
        SIZE_T bytesRead;
        if(!ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), &bytesRead))
        {
            std::cerr << "[!] Failed to read process memory" << std::endl;
            return false;
        }

        hCheck = data_checked.hMod;
        Sleep(10);
    }

    VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
    
    return true;
}

void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData)
{

    if(!pData) return;

    BYTE* pBase = reinterpret_cast<BYTE*>(pData);
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);
    auto _MessageBoxA = pData->pMessageBoxA;

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Relocations
    _MessageBoxA(NULL, "Relocating Image", "Manual Mapping", MB_OK);
    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if(LocationDelta)
    {
        if(!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while(pRelocData->VirtualAddress)
        {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            #if DEBUG_RELOC
                std::cout << "No of Entries in reloc = " << std::hex << numEntries << std::endl << std::endl;
            #endif

            for(UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
            {
                if(RELOC_FLAG(*pRelativeInfo))
                {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
                    *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);

                    #if DEBUG_RELOC 
                        std::cout << "Patching Address: [0x" << std::hex << (pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF)) << "] -> [" << *pPatch << "]\t [" << i + 1 << "/" << AmountOfEntries << "]" << std::dec << std::endl;
                    #endif

                }
            }

            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    } std::cout << "\t[Relocation completed]" << std::endl;

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Imports
    if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while(pImportDescr)
        {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            
            HINSTANCE hDll = _LoadLibraryA(szMod);
            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if(!pThunkRef) pThunkRef = pFuncRef;

            for(; *pThunkRef; ++pThunkRef, ++pFuncRef)
            {
                if(IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) *pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                else
                {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = _GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }

    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // TLS
    if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

        for(; *pCallback && *pCallback; ++pCallback) (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Entry point
    _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

    pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}