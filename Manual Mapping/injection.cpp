#include "injection.h"

BYTE* base = nullptr;
IMAGE_DOS_HEADER* dos = nullptr;
IMAGE_NT_HEADERS* ntHeader = nullptr;
IMAGE_OPTIONAL_HEADER* optionalHeader = nullptr;
BYTE* pTargetBase = nullptr;

size_t bufferSize = 0;
DWORD peOffset = 0;

NTSTATUS SanityCheck()
{
    norm("\n.......................................SanityCheck.......................................");

    dos = (IMAGE_DOS_HEADER*) base;
    if (dos->e_magic != 0x5A4D)
    {
        fuk("Invalid DOS signature");
        return false;
    } else norm("\nDOS signature\t\t\t\t-> ", std::hex, GREEN"", dos->e_magic);

    //...............................................................................

    if (bufferSize < sizeof(IMAGE_DOS_HEADER))
    {
        fuk("Buffer too small for DOS header");
        return false;
    } else norm("\nBuffer Size\t\t\t\t-> ", std::hex, GREEN"0x", bufferSize);
    
    //...............................................................................

    peOffset = dos->e_lfanew;
    if (peOffset + sizeof(IMAGE_NT_HEADERS64) > bufferSize)
    {
        fuk("e_lfanew points past buffer end");
        return false;   
    } else norm("\nvalid e_lfanew\t\t\t\t-> ", GREEN"YES");

    //...............................................................................

    ntHeader = (IMAGE_NT_HEADERS64*)(base + peOffset);
    
    if(ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        fuk("Invalid NtHeader Signature");
    } else norm("\nNtHeader sign\t\t\t\t-> ", GREEN"YES");


    if(ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        fuk("Not a 64-bit or 32-bit PE");
        return false;
    } else norm("\nArchitecture \t\t\t\t-> ", GREEN"", (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? "64-bit" : "32-bit");

    //...............................................................................

    if(ntHeader->OptionalHeader.SizeOfHeaders > bufferSize)
    {
        fuk("Headers claim bigger than file");
        return false;
    } else norm("\nHeader size\t\t\t\t-> ", GREEN"OK");

    //...............................................................................

    WORD numSecs = ntHeader->FileHeader.NumberOfSections;
    BYTE* secTable = (BYTE*)ntHeader + sizeof(IMAGE_NT_HEADERS64);
    if((secTable - base) + numSecs * sizeof(IMAGE_SECTION_HEADER) > bufferSize)
    {
        fuk("Section table overruns file");
        return false;
    } else norm("\nSection table overrun\t\t\t-> ", GREEN"NO");
    
    //...............................................................................

    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)secTable;
    for (int i = 0; i < numSecs; ++i)
    {
        IMAGE_SECTION_HEADER &s = secs[i];
        if(s.PointerToRawData + s.SizeOfRawData > bufferSize)
        {
            fuk("Section raw data out of bounds");
            return false;
        }

        if(s.VirtualAddress + max(s.Misc.VirtualSize, s.SizeOfRawData) > ntHeader->OptionalHeader.SizeOfImage)
        {
            fuk("Section VSize out of image bounds");
            return false;
        }
    }
    norm("\nSections VSize out of image bounds\t-> ", GREEN"NO");
    norm("\nSections data OutOfBounds\t\t-> ", GREEN"NO");

    //...............................................................................

    DWORD fileAlign = ntHeader->OptionalHeader.FileAlignment;
    DWORD sectionAlign = ntHeader->OptionalHeader.SectionAlignment;
    if(fileAlign == 0 || sectionAlign == 0 || (fileAlign & (fileAlign - 1)) || (sectionAlign & (sectionAlign - 1)) || sectionAlign < fileAlign)
    {
        fuk("Weird alignment values");
        return false;
    } else norm("\nAlignment\t\t\t\t-> ", GREEN"OK");
    

    norm("\n.......................................SanityCheck.......................................");
    return true;
}


bool ManualMap(HANDLE hproc, std::vector <unsigned char> *downloaded_dll)
{
    norm("\n===========================================ManualMap============================================");

    base = downloaded_dll->data();
    bufferSize = downloaded_dll->size();
    
    SanityCheck();
    
    //==========================================================================================

    

    norm("\n===========================================ManualMap============================================");
    return 1;
}