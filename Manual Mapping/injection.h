#include <windows.h>
#include <iostream>
#include <filesystem>
#include <tlhelp32.h>

using f_LoadLibraryA = HMODULE(WINAPI*)(const char*);
using f_GetProcAddress = uintptr_t(WINAPI*)(HINSTANCE, const char*);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void*, DWORD, void*);

struct MANUAL_MAPPING
{
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    HINSTANCE hMod;
};

bool ManualMap(HANDLE hproc, const char* dllPath);