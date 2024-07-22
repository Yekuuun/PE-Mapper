#include "utils.h"


/**
 * Thanks to Hasherezade for code. 
 * Link to ressource : https://github.com/hasherezade/malware_training_vol1
 */
#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

#ifdef _WIN64
#define RELOC_FIELD RELOC_64BIT_FIELD
typedef ULONG_PTR FIELD_PTR;
#else
#define RELOC_FIELD RELOC_32BIT_FIELD
typedef  DWORD_PTR FIELD_PTR;
#endif

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

/**
 * Load & run PE.
 * @param rawPE => BYTE* to raw PE file.
 * @param sizeFile => DWORD for handling size of file selected.
 */
BOOL GetPEInformations(BYTE* rawPE, DWORD sizeFile);