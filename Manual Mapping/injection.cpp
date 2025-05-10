#include "injection.h"

BYTE* pSourceBase = nullptr;
BYTE* pTargetBase = nullptr;
IMAGE_DOS_HEADER* pSrc_dosHeader = nullptr;
IMAGE_NT_HEADERS* pSrc_ntHeader = nullptr;
IMAGE_OPTIONAL_HEADER* pSrc_optionalHeader = nullptr;
IMAGE_FILE_HEADER* pSrc_fileHeader = nullptr;

size_t Dll_Actual_Size = 0;
DWORD peOffset = 0;

NTSTATUS SanityCheck()
{
    norm("\n.......................................SanityCheck.......................................");

    pSrc_dosHeader = (IMAGE_DOS_HEADER*) pSourceBase;
    if (pSrc_dosHeader->e_magic != 0x5A4D)
    {
        fuk("Invalid DOSHeader signature");
        return false;
    } else norm("\nDOSHeader signature\t\t\t-> ", std::hex, GREEN"0x", pSrc_dosHeader->e_magic);

    //...............................................................................

    if (Dll_Actual_Size < sizeof(IMAGE_DOS_HEADER))
    {
        fuk("Buffer too small for DOSHeader header");
        return false;
    } else norm("\nBuffer Size\t\t\t\t-> ", std::hex, GREEN"0x", Dll_Actual_Size);
    
    //...............................................................................

    peOffset = pSrc_dosHeader->e_lfanew;
    if (peOffset + sizeof(IMAGE_NT_HEADERS64) > Dll_Actual_Size)
    {
        fuk("e_lfanew points past buffer end");
        return false;   
    } else norm("\nvalid e_lfanew\t\t\t\t-> ", GREEN"YES");

    //...............................................................................

    pSrc_ntHeader = (IMAGE_NT_HEADERS64*)(pSourceBase + peOffset);
    
    if(pSrc_ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        fuk("Invalid NtHeader Signature");
    } else norm("\nNtHeader sign\t\t\t\t-> ", GREEN"YES");


    if(pSrc_ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && pSrc_ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        fuk("Not a 64-bit or 32-bit PE");
        return false;
    } else norm("\nArchitecture \t\t\t\t-> ", GREEN"", (pSrc_ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? "64-bit" : "32-bit");

    //...............................................................................

    if(pSrc_ntHeader->OptionalHeader.SizeOfHeaders > Dll_Actual_Size)
    {
        fuk("Headers claim bigger than file");
        return false;
    } else norm("\nHeader size\t\t\t\t-> ", GREEN"OK");

    //...............................................................................

    WORD numSecs = pSrc_ntHeader->FileHeader.NumberOfSections;
    BYTE* secTable = (BYTE*)pSrc_ntHeader + sizeof(IMAGE_NT_HEADERS64);
    if((secTable - pSourceBase) + numSecs * sizeof(IMAGE_SECTION_HEADER) > Dll_Actual_Size)
    {
        fuk("Section table overruns file");
        return false;
    } else norm("\nSection table overrun\t\t\t-> ", GREEN"NO");
    
    //...............................................................................

    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)secTable;
    for (int i = 0; i < numSecs; ++i)
    {
        IMAGE_SECTION_HEADER &s = secs[i];
        if(s.PointerToRawData + s.SizeOfRawData > Dll_Actual_Size)
        {
            fuk("Section raw data out of bounds");
            return false;
        }

        if(s.VirtualAddress + max(s.Misc.VirtualSize, s.SizeOfRawData) > pSrc_ntHeader->OptionalHeader.SizeOfImage)
        {
            fuk("Section VSize out of image bounds");
            return false;
        }
    }
    norm("\nSections VSize out of image bounds\t-> ", GREEN"NO");
    norm("\nSections data OutOfBounds\t\t-> ", GREEN"NO");

    //...............................................................................

    DWORD fileAlign = pSrc_ntHeader->OptionalHeader.FileAlignment;
    DWORD sectionAlign = pSrc_ntHeader->OptionalHeader.SectionAlignment;
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

    pSourceBase = downloaded_dll->data();
    Dll_Actual_Size = downloaded_dll->size();
    
    SanityCheck();
    
    //==========================================================================================



    norm("\n===========================================ManualMap============================================");
    return 1;
}