#include "injection.h"

const char* szDLLFile[] = "C:\\MALWARE\\dll_injection\\basic_dll\\cute_lib.dll";
const char szProc[] = "notepad.exe";

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

    DWORD dwPID = 0;
    BOOL bRet = Process32First(hSnap, &PE32);
    while(bRet)
    {
        if(!strcmp(szProc, PE32.szExeFile))
        {
            std::cout << "Found process: " << PE32.szExeFile << " with PID: " << PE32.th32ProcessID << std::endl;
            PID = PE32.th32ProcessID;
            break;
        }
        bRet = Process32Next(hSnap, &PE32);
    }CloseHandle(hSnap);

    HANDEL hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hproc)
    {
        std::cerr << "[!] Failed to open process: " << GetLastError() << std::endl;
        return 1;
    }

    if(!ManualMap(hProc, szDLLFile))
    {
        CloseHandle(hProc);
        std::cerr << "[!] Failed to inject DLL" << std::endl;
        system("pause");
        return 1;
    }CloseHandle(hproc);

    std::cout << "[+] DLL injected successfully" << std::endl;
    return 0;
    
}