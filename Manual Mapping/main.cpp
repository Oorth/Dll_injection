//cl /std:c++17 /EHsc .\main.cpp .\injection.cpp /link /OUT:main.exe
#define DEBUG 1
#include "injection.h"
#include <iostream>
#include <Windows.h>


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
    ok("IN\n");
    PROCESSENTRY32 PE32{0};
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE)
    {
        fuk("Failed to create snapshot: ", GetLastError(),"\n");
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

    norm("Trying to get a handle to the process...\n");
    PID = GetProcessID(L"notepad.exe");
    if (PID == 0)
    {
        fuk("[Target process not found]\n");
        return 1;
    } norm("Process ID: ", CYAN"", PID, "\n");


    norm("-> Attempting to open process");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        fuk("[!] Failed to open process: ", GetLastError(), "\n");
        return 1;
    } norm(GREEN"\t\t[DONE]\n");

    if(!ManualMap(hProc, szDLLFile))
    {
        CloseHandle(hProc);
        fuk("Failed to inject DLL");
        system("pause");
        return 1;
    } CloseHandle(hProc);

    ok("DLL injected successfully\n");
    return 0;

}