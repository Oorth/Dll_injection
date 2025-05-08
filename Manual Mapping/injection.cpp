#include "injection.h"

bool ManualMap(HANDLE hproc, const char* dllPath)
{
    ok("Alive\n");
    return 1;
}