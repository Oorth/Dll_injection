#include <Windows.h>
// Forward declaration, if ShellcodeFindExportAddress calls itself.
// C++ usually handles this fine if the definition is before the first recursive call point,
// but an explicit forward declaration can be clearer or sometimes necessary.

typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
__declspec(noinline) static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, LPCSTR lpProcNameOrOrdinal, pfnLoadLibraryA pLoadLibraryAFunc);


__declspec(noinline) static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, LPCSTR lpProcNameOrOrdinal, pfnLoadLibraryA pLoadLibraryAFunc)
{
    if (!hModule) {
        // LOG_W(L"    [SFEA] Called with NULL module for %p", lpProcNameOrOrdinal);
        return nullptr;
    }

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_DATA_DIRECTORY* pExportDataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0) {
        // LOG_W(L"    [SFEA] No export directory in module 0x%p for %p", hModule, lpProcNameOrOrdinal);
        return nullptr;
    }

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + pExportDataDir->VirtualAddress);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions); // RVAs to function bodies or forwarders

    bool isOrdinalLookup = false;
    WORD ordinalToFind = 0;

#if defined(_WIN64)
    if (((ULONG_PTR)lpProcNameOrOrdinal >> 16) == 0) {
        isOrdinalLookup = true;
        ordinalToFind = LOWORD((ULONG_PTR)lpProcNameOrOrdinal);
    }
#else
    if (HIWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal) == 0) {
        isOrdinalLookup = true;
        ordinalToFind = LOWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal);
    }
#endif

    DWORD funcRVA = 0; // Will hold the RVA of the function/forwarder

    if (isOrdinalLookup) {
        // ORDINAL LOOKUP
        // LOG_W(L"    [SFEA] Module 0x%p: Looking up by ordinal: %hu", hModule, ordinalToFind);
        if (ordinalToFind < exp->Base || (ordinalToFind - exp->Base) >= exp->NumberOfFunctions) {
            // LOG_W(L"    [SFEA] Ordinal %hu out of range (Base: %u, Count: %u)", ordinalToFind, exp->Base, exp->NumberOfFunctions);
            return nullptr;
        }

        DWORD functionIndexInArray = ordinalToFind - exp->Base;
        if (functionIndexInArray >= exp->NumberOfFunctions) return nullptr; // Should be caught by above
        
        funcRVA = functions[functionIndexInArray];
    }
    else
    {
        // NAME LOOKUP
        LPCSTR funcName = lpProcNameOrOrdinal;
        if (!funcName || *funcName == '\0') return nullptr;
        // LOG_W(L"    [SFEA] Module 0x%p: Looking up by name: %hs", hModule, funcName);

        DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);
        WORD* nameOrdinals = (WORD*)(base + exp->AddressOfNameOrdinals); // Indices into 'functions'
        
        bool foundByName = false;
        for (DWORD i = 0; i < exp->NumberOfNames; ++i)
        {
            char* currentExportName = (char*)(base + nameRVAs[i]);
            if (isSame(currentExportName, funcName)) { // Your case-insensitive compare
                WORD functionIndexInArray = nameOrdinals[i];
                if (functionIndexInArray >= exp->NumberOfFunctions) {
                    // LOG_W(L"    [SFEA] Name '%hs' gave an ordinal array index %hu out of bounds (%u).", funcName, functionIndexInArray, exp->NumberOfFunctions);
                    return nullptr;
                }
                funcRVA = functions[functionIndexInArray];
                foundByName = true;
                break;
            }
        }
        if (!foundByName) {
            // LOG_W(L"    [SFEA] Name '%hs' not found in export table of module 0x%p.", funcName, hModule);
            return nullptr;
        }
    }

    if (funcRVA == 0) {
        // LOG_W(L"    [SFEA] RVA for %p in module 0x%p is zero.", lpProcNameOrOrdinal, hModule);
        return nullptr; // No valid RVA found
    }
    
    BYTE* addr = base + funcRVA;

    // Check if this RVA points within the export directory itself (indicates a forwarded export)
    if (funcRVA >= pExportDataDir->VirtualAddress && funcRVA < (pExportDataDir->VirtualAddress + pExportDataDir->Size)) {
        // This is a forwarder string like "OTHERDLL.OtherFunction" or "OTHERDLL.#123"
        char* forwarderString = (char*)addr; // The RVA points to this string
        // LOG_W(L"    [SFEA] Proc %p from module 0x%p is forwarded to: '%hs'", lpProcNameOrOrdinal, hModule, forwarderString);

        if (!pLoadLibraryAFunc) { // We need LoadLibrary to handle forwarders
            // LOG_W(L"    [SFEA] pLoadLibraryAFunc is NULL, cannot resolve forwarder for %hs", forwarderString);
            return nullptr;
        }

        // --- Parse the forwarder string ---
        // Find the '.' separating DLL name from function/ordinal
        char* dotSeparator = nullptr;
        char* tempPtr = forwarderString;
        while (*tempPtr != '\0') {
            if (*tempPtr == '.') {
                dotSeparator = tempPtr;
                break;
            }
            tempPtr++;
        }

        if (!dotSeparator || dotSeparator == forwarderString) { // No dot, or starts with a dot (invalid)
            // LOG_W(L"    [SFEA] Malformed forwarder string (no dot or starts with dot): %hs", forwarderString);
            return nullptr;
        }

        // Extract DLL name (temporarily null-terminate at the dot)
        *dotSeparator = '\0'; 
        char* forwardedDllName = forwarderString;
        char* forwardedFuncNameOrOrdinalStr = dotSeparator + 1; // Points to char after original dot

        if (*forwardedFuncNameOrOrdinalStr == '\0') { // Nothing after the dot
            *dotSeparator = '.'; // Restore dot
            // LOG_W(L"    [SFEA] Malformed forwarder string (nothing after dot): %hs", forwarderString);
            return nullptr;
        }
        
        HMODULE hForwardedModule = pLoadLibraryAFunc(forwardedDllName);
        *dotSeparator = '.'; // Restore the dot in the original forwarder string in case it's needed elsewhere (unlikely here)

        if (!hForwardedModule) {
            // LOG_W(L"    [SFEA] Failed to load forwarded DLL: '%hs' (forwarded from %hs in 0x%p)", 
            //       forwardedDllName, lpProcNameOrOrdinal, hModule);
            return nullptr;
        }

        LPCSTR finalProcNameToResolve;
        if (*forwardedFuncNameOrOrdinalStr == '#') { // Forwarding to an ordinal, e.g., "#123"
            // Convert "#123" to (LPCSTR)123
            WORD fwdOrdinal = 0;
            char* pNum = forwardedFuncNameOrOrdinalStr + 1; // Skip '#'
            while (*pNum >= '0' && *pNum <= '9') {
                fwdOrdinal = fwdOrdinal * 10 + (*pNum - '0');
                pNum++;
            }
            if (fwdOrdinal == 0 && *(forwardedFuncNameOrOrdinalStr + 1) != '0') { // Check for invalid ordinal like "#XYZ"
                // LOG_W(L"    [SFEA] Invalid forwarded ordinal format: %hs", forwardedFuncNameOrOrdinalStr);
                return nullptr;
            }
            finalProcNameToResolve = (LPCSTR)(ULONG_PTR)fwdOrdinal;
        } else { // Forwarding to a name
            finalProcNameToResolve = forwardedFuncNameOrOrdinalStr;
        }

        // Recursive call to resolve from the new module
        // Pass the same pLoadLibraryAFunc down for further potential forwarding
        return ShellcodeFindExportAddress(hForwardedModule, finalProcNameToResolve, pLoadLibraryAFunc);
    } else {
        // Not a forwarded export, this is the direct address of the function
        return (void*)addr;
    }
}