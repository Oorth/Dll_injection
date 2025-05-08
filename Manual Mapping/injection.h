#pragma once
#define DEBUG 1

#include "DbgMacros.h"
#include <windows.h>
#include <tlhelp32.h>

// using f_LoadLibraryA = HMODULE(WINAPI*)(const char*);
// using f_GetProcAddress = uintptr_t(WINAPI*)(HINSTANCE, const char*);
// using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void*, DWORD, void*);
// using f_MessageBoxA = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);

// struct MANUAL_MAPPING_DATA
// {
//     f_LoadLibraryA pLoadLibraryA;
//     f_GetProcAddress pGetProcAddress;
//     HINSTANCE hMod;

//     f_MessageBoxA pMessageBoxA;
// };

bool ManualMap(HANDLE hproc, const char* dllPath);