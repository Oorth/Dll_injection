//cl /std:c++17 /EHsc .\main.cpp .\injection.cpp /link /OUT:main.exe
#include "injection.h"

bool ManualMap(HANDLE hproc, const char* dllPath);

const char* szDLLFile = "C:\\MALWARE\\dll_injection\\basic_dll\\cute_lib.dll";
const char szProc[] = "notepad.exe";

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


int main()
{

    PROCESSENTRY32 PE32{0};
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
        system("pause");
        return 1;
    }

    DWORD PID = 0;
    // BOOL bRet = Process32First(hSnap, &PE32);
    // while(bRet)
    // {
    //     if(!_wcsicmp(reinterpret_cast<const wchar_t*>(PE32.szExeFile), L"notepad.exe"))
    //     {
    //         std::cout << "Found process: " << PE32.szExeFile << " with PID: " << PE32.th32ProcessID << std::endl;
    //         PID = PE32.th32ProcessID;
    //         break;
    //     }
    //     bRet = Process32Next(hSnap, &PE32);
    // }CloseHandle(hSnap);
    std::cout << "Trying to get a handle to the process...\n"; 
    PID = GetProcessID(L"notepad.exe");
    if (PID == 0)
    {
        std::cerr << "[Target process not found]\n";
        return 1;
    } std::cout << "Process ID: " << PID << "\n";


    std::cout << "-> Attempting to open process";
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        std::cerr << "[!] Failed to open process: " << GetLastError() << std::endl;
        return 1;
    } std::cout << "\t\t[DONE]" << std::endl;

    if(!ManualMap(hProc, szDLLFile))
    {
        CloseHandle(hProc);
        std::cerr << "[!] Failed to inject DLL" << std::endl;
        system("pause");
        return 1;
    }CloseHandle(hProc);

    std::cout << "[+] DLL injected successfully" << std::endl;
    return 0;

}