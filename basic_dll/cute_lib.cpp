//cl /EHsc /LD .\cute_lib.cpp /link User32.lib
#include <windows.h>

DWORD WINAPI ShowMessageBoxThread(LPVOID lpParam)
{
    const char* message = (const char*)lpParam;
    MessageBoxA(NULL, message, "Notification", MB_OK);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    const char* msg = nullptr;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        msg = "Process Attached";
        break;
    case DLL_THREAD_ATTACH:
        msg = "Thread Attached";
        break;
    case DLL_THREAD_DETACH:
        msg = "Thread Detached";
        break;
    case DLL_PROCESS_DETACH:
        msg = "Process Detached";
        break;
    }
    if (msg)
    {
        // Duplicate the message string so it's valid in the new thread
        char* msgCopy = _strdup(msg);
        if (msgCopy)
        {
            HANDLE hThread = CreateThread(NULL, 0, ShowMessageBoxThread, msgCopy, 0, NULL);
            if (hThread)
                CloseHandle(hThread);
        }
    }
    return TRUE;
}
