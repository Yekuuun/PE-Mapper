/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
*/

#include "mapper.h"

/**
 * Retreive informations about NTHeader based on rawPE base address.
 * @param rawPE => BYTE* pointing on base of PE.
 */
PIMAGE_NT_HEADERS GetNtHeader(BYTE* rawPE)
{
    if(rawPE == nullptr)
    {
        std::cout << "[-] Null ptr for rawPE" << std::endl;
        return nullptr;
    }

    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)rawPE;
    if(DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "[-] NOT A PE FILE." << std::endl;
        return nullptr;
    }

    //address of struct.
    PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((char*)(rawPE) + DOSHeader->e_lfanew);
    if(NTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "[-] NOT A PE FILE." << std::endl;
        return nullptr;
    }

    return NTHeader;
}

/**
 * Manually mapping PE sections.
 * @param image => ptr to allocated memory
 * @param rawPE => ptr to raw PE data.
 * @param ntHeader => ptr to NT HEADER of rawPE file.
 */
BOOL ManualMap(BYTE* image, BYTE* rawPE, PIMAGE_NT_HEADERS ntHeader)
{
    if(image == nullptr || rawPE == nullptr)
    {
        std::cout << "[-] Error manipulating pointers." << std::endl;
        return false;
    }

    memcpy(image, rawPE, ntHeader->OptionalHeader.SizeOfHeaders);

    //manually allocating sections.
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy((BYTE*)(image)+section[i].VirtualAddress, (BYTE*)(rawPE)+section[i].PointerToRawData, section[i].SizeOfRawData);
    }

    return true;
}

/**
 * Relocate function.
 * Thanks to Hasherezade for this function.
 * LINK : https://github.com/hasherezade/malware_training_vol1
 */
BOOL Relocate(BYTE* image, PIMAGE_NT_HEADERS nt, FIELD_PTR newImgBase)
{
    IMAGE_DATA_DIRECTORY relocationsDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocationsDirectory.VirtualAddress == 0) {
        return true;
    }
    PIMAGE_BASE_RELOCATION ProcessBReloc = (PIMAGE_BASE_RELOCATION)(relocationsDirectory.VirtualAddress + (FIELD_PTR)image);
    // apply relocations:
    while (ProcessBReloc->VirtualAddress != 0)
    {
        DWORD page = ProcessBReloc->VirtualAddress;

        if (ProcessBReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            size_t count = (ProcessBReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPWORD)(ProcessBReloc + 1);

            for (size_t i = 0; i < count; i++)
            {
                if (list[i].Type & RELOC_FIELD)
                {
                    DWORD rva = list[i].Offset + page;

                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)image + rva);
                    //relocate the address
                    *p = ((*p) - nt->OptionalHeader.ImageBase) + (FIELD_PTR)newImgBase;
                }
            }
        }
        ProcessBReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ProcessBReloc + ProcessBReloc->SizeOfBlock);
    }
    return true;
}


/**
 * Loading imports of a PE file.
 * @param image => address of loaded PE in memory
 * @param nt => pt to NTHEADER
 */
BOOL LoadImports(BYTE* image, PIMAGE_NT_HEADERS nt)
{
    IMAGE_DATA_DIRECTORY imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(imports.VirtualAddress == 0)
    {
        std::cout << "[!] No imports." << std::endl;
        return true;
    }

    //ptr to IMAGE_IMPORT_DESCRIPTOR
    PIMAGE_IMPORT_DESCRIPTOR pImageDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imports.VirtualAddress + (FIELD_PTR)image); //offset calculation => address of first module loaded.

    //iterating through loaded DLL's.
    while(pImageDesc->Name != NULL)
    {
        LPCSTR libraryName = (LPCSTR)pImageDesc->Name + (FIELD_PTR)image;
        std::cout << "[*] Library name : " << libraryName << std::endl;
        HMODULE library = LoadLibraryA(libraryName);

        if (library)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((FIELD_PTR)image + pImageDesc->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {
                FIELD_PTR functionAddress = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    functionAddress = (FIELD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((FIELD_PTR)image + thunk->u1.AddressOfData);
                    functionAddress = (FIELD_PTR)GetProcAddress(library, functionName->Name);
                }
                thunk->u1.Function = functionAddress;
                ++thunk;
            }
        }

        pImageDesc++;
    }

    return true;
}


/**
 * Load & run PE.
 * @param rawPE => BYTE* to raw PE file.
 * @param sizeFile => DWORD for handling size of file selected.
 */
BOOL GetPEInformations(BYTE* rawPE, DWORD sizeFile)
{
    //base variables.
    LPVOID allocatedMemory = NULL; //image base address loaded in mem.
    HANDLE hThread         = NULL;

    BOOL state = false;

    PIMAGE_NT_HEADERS ntH = GetNtHeader(rawPE);
    if(ntH == nullptr)
    {
        return false;
    }

    //write file into memory.
    allocatedMemory = VirtualAlloc(NULL, ntH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(allocatedMemory == NULL)
    {
        std::cout << "[-] Unable to loadfile into memory." << std::endl;
        return false;
    }
    std::cout << "[*] Successfully allocated memory with size of image :" << ntH->OptionalHeader.SizeOfImage << std::endl;
    
    //mapping sections.
    if(!ManualMap((BYTE*)allocatedMemory, rawPE, ntH))
    {
        std::cout << "[-] Error mapping PE sections into memory." << std::endl;
        if(allocatedMemory)
        {
            VirtualFree(allocatedMemory, 0, MEM_RELEASE);;
        }
        return false;
    }
    std::cout << "[*] Successfully mapped PE sections" << std::endl;

    //relocation.
    if(!Relocate((BYTE*)allocatedMemory, ntH, (FIELD_PTR)allocatedMemory))
    {
        std::cout << "[-] Relocate has failed" << std::endl;
        if(allocatedMemory)
        {
            VirtualFree(allocatedMemory, 0, MEM_RELEASE);;
        }
        return false;
    }
    std::cout << "[*] Successfully relocated addresses" << std::endl;

    //loading imports.
    if(!LoadImports((BYTE*)allocatedMemory, ntH))
    {
        std::cout << "[-] Loading imports has failed." << std::endl;
        if(allocatedMemory)
        {
            VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        }
        return false;
    }
    std::cout << "[*] Successfully loaded imports" << std::endl;

    return true;
}