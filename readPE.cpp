#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <sys/stat.h>
#define PRIERR printf("[!] Cannot load file...\n exit.\n")
#define _BYTE1(x) (  x        & 0xFF )
#define _BYTE2(x) ( (x >>  8) & 0xFF )
#define _BYTE3(x) ( (x >> 16) & 0xFF )
#define _BYTE4(x) ( (x >> 24) & 0xFF )

#define BYTE_SWAP_16(x) ((WORD)( _BYTE1(x)<<8 | _BYTE2(x) ))
#define BYTE_SWAP_32(x) ((DWORD)( _BYTE1(x)<<24 | _BYTE2(x)<<16 | _BYTE3(x)<<8 | _BYTE4(x) ))

int readPE64(DWORD *bin, int size) {
    return 0;

}

void dumpDOSHeader(IMAGE_DOS_HEADER *dos_header) {
    puts("[*] DOS Header");
    printf("e_magic  : %s\n", (char *)&dos_header->e_magic);
    puts("");
    
}

void dumpPEHeader(IMAGE_NT_HEADERS32 *pe_header) {
    int i;

    IMAGE_FILE_HEADER file_header = pe_header->FileHeader;
    IMAGE_OPTIONAL_HEADER32 op_header = pe_header->OptionalHeader;
    IMAGE_DATA_DIRECTORY *Data_Directory = op_header.DataDirectory;

    // PE Header
    puts("[*] PE Header");
    printf("signature : %s\n", (char *)&pe_header->Signature);
    puts("");

    // File Header
    puts("[**] File Header");
    printf("Machine : 0x%x -> ", file_header.Machine);
    
    switch (file_header.Machine) {
        case 0x8664:
            puts("x64");
            break;
        
        case 0x14c:
            puts("x32");
            break;
        
        default:
            puts("Unknown");
            break;

    }

    printf("NumberOfSections : %d\n", file_header.NumberOfSections);
    printf("SizeOfOptionalHeader : %d\n", file_header.SizeOfOptionalHeader);
    printf("Characteristics : 0x%x\n", file_header.Characteristics);
    printf("\tIMAGE_FILE_RELOCS_STRIPPED\t\t: %d\n", (file_header.Characteristics & 0x0001)? 1 : 0);
    printf("\tIMAGE_FILE_EXECUTABLE_IMAGE\t\t: %d\n", (file_header.Characteristics & 0x0002)? 1 : 0);
    printf("\tIMAGE_FILE_LINE_NUMS_STRIPPED\t\t: %d\n", (file_header.Characteristics & 0x0004)? 1 : 0);
    printf("\tIMAGE_FILE_LOCAL_SYMS_STRIPPED\t\t: %d\n", (file_header.Characteristics & 0x0008)? 1 : 0);
    printf("\tIMAGE_FILE_AGGRESSIVE_WS_TRIM\t\t: %d\n", (file_header.Characteristics & 0x0010)? 1 : 0);
    printf("\tIMAGE_FILE_LARGE_ADDRESS_AWARE\t\t: %d\n", (file_header.Characteristics & 0x0020)? 1 : 0);
    printf("\tIMAGE_FILE_BYTES_REVERSED_LO\t\t: %d\n", (file_header.Characteristics & 0x0080)? 1 : 0);
    printf("\tIMAGE_FILE_32BIT_MACHINE\t\t: %d\n", (file_header.Characteristics & 0x0100)? 1 : 0);
    printf("\tIMAGE_FILE_DEBUG_STRIPPED\t\t: %d\n", (file_header.Characteristics & 0x0200)? 1 : 0);
    printf("\tIMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\t: %d\n", (file_header.Characteristics & 0x0400)? 1 : 0);
    printf("\tIMAGE_FILE_NET_RUN_FROM_SWAP\t\t: %d\n", (file_header.Characteristics & 0x0800)? 1 : 0);
    printf("\tIMAGE_FILE_SYSTEM\t\t\t: %d\n", (file_header.Characteristics & 0x1000)? 1 : 0);
    printf("\tIMAGE_FILE_DLL\t\t\t\t: %d\n", (file_header.Characteristics & 0x2000)? 1 : 0);
    printf("\tIMAGE_FILE_UP_SYSTEM_ONLY\t\t: %d\n", (file_header.Characteristics & 0x4000)? 1 : 0);
    printf("\tIMAGE_FILE_BYTES_REVERSED_HI\t\t: %d\n", (file_header.Characteristics & 0x8000)? 1 : 0);

    puts("");

    // Optional Header
    puts("[**] Optional Header");
    printf("Magic : 0x%x -> ", op_header.Magic);
    switch (op_header.Magic) {
        case 0x10b:
            puts("PE32");
            break;

        case 0x20b:
            puts("PE32+");
            break;
        
        default:
            puts("Unknown.");
            break;

    }

    printf("AddressOfEntryPoint : 0x%08x\n", op_header.AddressOfEntryPoint);
    printf("ImageBase : 0x%08x\n", op_header.ImageBase);
    printf("SectionAlignment : 0x%x\n", op_header.SectionAlignment);
    printf("FileAlignment : 0x%x\n", op_header.FileAlignment);
    printf("SizeOfImage : %d\n", op_header.SizeOfImage);
    puts("");

    puts("[**] Data Directory");
    puts("[***] Export");
    printf("VitualAddress : 0x%08x\n", Data_Directory[0].VirtualAddress);
    printf("Size : %d\n", Data_Directory[0].Size);
    puts("");

    puts("[***] Import");
    printf("VitualAddress : 0x%08x\n", Data_Directory[1].VirtualAddress);
    printf("Size : %d\n", Data_Directory[1].Size);
    puts("");

    puts("[***] Import Address Table");
    printf("VitualAddress : 0x%08x\n", Data_Directory[12].VirtualAddress);
    printf("Size : %d\n", Data_Directory[12].Size);
    puts("");

}


void dumpSectionHeader(IMAGE_SECTION_HEADER *section_header) {    
    puts("SectionHeader");
    printf("Name : %s\n", section_header->Name);
    printf("VirtualSize : 0x%08x\n", section_header->Misc.VirtualSize);
    printf("VirtualAddress : 0x%08x\n", section_header->VirtualAddress);
    printf("SizeOfRawData : %\n", section_header->SizeOfRawData);
    printf("PointerToRawData : %d\n", section_header->PointerToRawData);
    printf("Characteristics : %x\n", section_header->Characteristics);
    printf("\tIMAGE_SCN_TYPE_NO_PAD\t\t: %d\n", (section_header->Characteristics & 0x00000008)? 1 : 0);
    printf("\tIMAGE_SCN_CNT_CODE\t\t: %d\n", (section_header->Characteristics & 0x00000020)? 1 : 0);
    printf("\tIMAGE_SCN_CNT_INITIALIZED_DATA\t: %d\n", (section_header->Characteristics & 0x00000040)? 1 : 0);
    printf("\tIMAGE_SCN_CNT_UNINITIALIZED_DATA: %d\n", (section_header->Characteristics & 0x00000080)? 1 : 0);
    printf("\tIMAGE_SCN_LNK_OTHER\t\t: %d\n", (section_header->Characteristics & 0x00000100)? 1 : 0);
    printf("\tIMAGE_SCN_LNK_INFO\t\t: %d\n", (section_header->Characteristics & 0x00000200)? 1 : 0);
    printf("\tIMAGE_SCN_LNK_REMOVE\t\t: %d\n", (section_header->Characteristics & 0x00000800)? 1 : 0);
    printf("\tIMAGE_SCN_LNK_COMDAT\t\t: %d\n", (section_header->Characteristics & 0x00001000)? 1 : 0);
    printf("\tIMAGE_SCN_GPREL\t\t\t: %d\n", (section_header->Characteristics & 0x00008000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_PURGEABLE\t\t: %d\n", (section_header->Characteristics & 0x00020000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_16BIT\t\t: %d\n", (section_header->Characteristics & 0x00020000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_LOCKED\t\t: %d\n", (section_header->Characteristics & 0x00040000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_PRELOAD\t\t: %d\n", (section_header->Characteristics & 0x00080000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_1BYTES\t\t: %d\n", (section_header->Characteristics & 0x00100000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_2BYTES\t\t: %d\n", (section_header->Characteristics & 0x00200000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_4BYTES\t\t: %d\n", (section_header->Characteristics & 0x00300000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_8BYTES\t\t: %d\n", (section_header->Characteristics & 0x00400000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_16BYTES\t\t: %d\n", (section_header->Characteristics & 0x00500000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_32BYTES\t\t: %d\n", (section_header->Characteristics & 0x00600000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_64BYTES\t\t: %d\n", (section_header->Characteristics & 0x00700000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_128BYTES\t: %d\n", (section_header->Characteristics & 0x00800000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_256BYTES\t: %d\n", (section_header->Characteristics & 0x00900000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_512BYTES\t: %d\n", (section_header->Characteristics & 0x00A00000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_1024BYTES\t: %d\n", (section_header->Characteristics & 0x00B00000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_2048BYTES\t: %d\n", (section_header->Characteristics & 0x00C00000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_4096BYTES\t: %d\n", (section_header->Characteristics & 0x00D00000)? 1 : 0);
    printf("\tIMAGE_SCN_ALIGN_8192BYTES\t: %d\n", (section_header->Characteristics & 0x00E00000)? 1 : 0);
    printf("\tIMAGE_SCN_LNK_NRELOC_OVFL\t: %d\n", (section_header->Characteristics & 0x01000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_DISCARDABLE\t: %d\n", (section_header->Characteristics & 0x02000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_NOT_CACHED\t: %d\n", (section_header->Characteristics & 0x04000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_NOT_PAGED\t\t: %d\n", (section_header->Characteristics & 0x08000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_SHARED\t\t: %d\n", (section_header->Characteristics & 0x10000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_EXECUTE\t\t: %d\n", (section_header->Characteristics & 0x20000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_READ\t\t: %d\n", (section_header->Characteristics & 0x40000000)? 1 : 0);
    printf("\tIMAGE_SCN_MEM_WRITE\t\t: %d\n", (section_header->Characteristics & 0x80000000)? 1 : 0);
    puts("");

}


int main(int argc, char *argv) {
    char *file_name = "sample1.exe";
    DWORD *buf;
    int i,size;
    FILE *fd;

    struct stat st;
    IMAGE_DOS_HEADER dos_header = { 0 };
    IMAGE_NT_HEADERS32 pe_header = { 0 };
    IMAGE_SECTION_HEADER section_header = { 0 };

    if ( (fd = fopen(file_name, "rb")) == NULL ) {
        PRIERR;
        return -1;
    }

    if (stat(file_name, &st) != 0) {
        PRIERR;
		return -1;
	}

    size = st.st_size;

    buf = (DWORD*)malloc(size);
    memset(buf, 0x0, size);
    //if (
    fread(buf, sizeof(unsigned char), size, fd);
    //) <= 0) puts("[!] Cannot read file.\n");
    
    // HexDump
/*    for (i=0; i<size; i++) {
        if (i % 4 == 0) puts(" ");
        printf("%08X ", buf[i]);

    }
    puts("\n");
*/

    printf("[*] Address : %p\n", buf);
    memcpy(&dos_header, buf, sizeof(IMAGE_DOS_HEADER));
    
    buf += dos_header.e_lfanew/4;
    memcpy(&pe_header, buf, sizeof(IMAGE_NT_HEADERS32));
    printf("[*] Address : %p\n", buf);

    buf += sizeof(IMAGE_NT_HEADERS32)/4;

    dumpDOSHeader(&dos_header);
    dumpPEHeader(&pe_header);    


    for (i=0; i<pe_header.FileHeader.NumberOfSections; i++) {
        memcpy(&section_header, buf, sizeof(IMAGE_SECTION_HEADER));
        
        dumpSectionHeader(&section_header);

        buf += sizeof(IMAGE_SECTION_HEADER)/4;
    }

    fclose(fd);
    return 0;

}