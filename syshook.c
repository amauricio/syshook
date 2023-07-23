#include <windows.h>
#include <stdio.h>


#define SYSCALL_LEN 21

/*
 * syscall pattern
 *  ntdll!NtReadVirtualMemory:
    00007ffb`352ad7b0 4c8bd1           mov     r10, rcx
    00007ffb`352ad7b3 b83f000000       mov     eax, 3Fh
    00007ffb`352ad7b8 f604250803fe7f01 test    byte ptr [7FFE0308h], 1
    00007ffb`352ad7c0 7503             jne     00007FFB352AD7C5
    00007ffb`352ad7c2 0f05             syscall 
    00007ffb`352ad7c4 c3               ret     
    00007ffb`352ad7c5 cd2e             int     2Eh
    00007ffb`352ad7c7 c3               ret     
    00007ffb`352ad7c8 0f1f840000000000 nop     dword ptr [rax+rax]
    
    opcodes: 4c 8b d1 b8 3f 00 00 00 f6 04 25 08 03 fe 7f 01 75 03 0f 05 c3 cd 2e c3 0f 1f 84 00 00 00 00 00
    mandatory: 4c 8b d1 b8 [...] which is the eax register
    so the first 4 bytes are needed
        
 * */

int SysCallingThePatch(char *addr);
int SysCallExit(int status);

typedef NTSTATUS (NTAPI* __NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded
);

typedef struct {
    char functionName[100];
    int flagF;
    int flagA;
    int flagB;
    // Add more flags as needed
} Args;


HMODULE hModule;
Args args;

/*
 * Function to initialize the Args struct
 * It sets the default values for the flags
 * */
void initArgs(Args* args) {
    args->functionName[0] = '\0';
    args->flagF = 0;
    args->flagA = 0;
    args->flagB = 0;
    // Initialize other flags as needed
}

/*
 * Function to parse the arguments passed to the program
 * It fills the Args struct with the values passed
 * */
void parseArgs(int argc, char* argv[], Args* args) {
    initArgs(args);

    int i;
    for (i = 1; i < argc; i++) {
        
        if(strcmp(argv[i], "-f") == 0){
            args->flagF = 1;
        }
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strcpy(args->functionName, argv[i + 1]);
            i++; // Skip the next argument as it's the value for -f
        }
        
        if (strcmp(argv[i], "-a") == 0) {
            args->flagA = 1;
        }
        // Add other flags handling as needed
    }
}

/*
 * Function to check if the first 4 bytes of the function are the mandatory ones
 * Returns TRUE if the syscall is valid, FALSE otherwise
 * */
BOOL isValidSyscall(BYTE* bytes){
    BYTE mandatory[] = {0x4c, 0x8b, 0xd1, 0xb8};
    for(int i = 0; i < 4; i++){
        if(mandatory[i] != bytes[i]){
            return FALSE;
        }
    }
    return TRUE;
}

/*
 * Function to read and return the syscall opcodes from 
 * Winapi function in ntdl.dll
 * */
BOOL retBytesFromFunction(char*out, char* name, size_t length){
    char* respFunction =  (char *)GetProcAddress(hModule, name);
    if(respFunction == NULL){
        return FALSE;
    }
    memcpy(out, respFunction, length);
    return TRUE;
}

/*
 * Function to replace the opcodes from syscall with ret, so the trick is :
 * the EDR will analyze empy parameters and when it comes to the syscall will find NOPS
 * In the end there is just a RET wich mean at this point EAX=Syscall number
 * No matter the previous process
 * */
char* patchCall(char** syscallBackup, char* ntFunction){ // could be nt and zw
    // print 30 bytes
       printf("[$] Patching the function %s\n", ntFunction);
    char* ptrKrnlFunction = (char *)GetProcAddress(hModule, ntFunction);
    DWORD odProtection = 0;
    BOOL isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ptrKrnlFunction + 18), 12, PAGE_EXECUTE_READWRITE, &odProtection);
    LPVOID addrKrnFunction = (LPVOID)((DWORD_PTR)ptrKrnlFunction + 18);
    
    //get the 9 characters
    memcpy(*syscallBackup, addrKrnFunction, 7);

    memcpy(addrKrnFunction, "\x41\x89\xc4\x44\x89\xe0\xc3", 7); //not calling syscall 
    printf("[$] Successfully patched the function %s\n", ntFunction);
    return ptrKrnlFunction;
}

/*
 * Function to restore the syscall opcodes
 * */
char* unpatchCall(char*syscallBackup, char* ntFunction){
    printf("[$] Unpatching the function %s\n", ntFunction);
    char* ptrKrnlFunction = (char *)GetProcAddress(hModule, ntFunction);
    DWORD odProtection = 0;
    BOOL isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ptrKrnlFunction + 18), 12, PAGE_EXECUTE_READWRITE, &odProtection);
    memcpy((LPVOID)((DWORD_PTR)ptrKrnlFunction + 18),syscallBackup, 7); //calling syscall
    printf("[$] Successfully unpatched the function %s\n", ntFunction);
    return ptrKrnlFunction;
}

/*
 * Function to get the syscall number from the patched function
 * */
DWORD GetSSNIndirectSyscall(char* ntFunction){
    /*
     * calling convention
     * RCX, RDX, R8, R9, [STACK]
     * fill with zeros (8bytes/x64)
     * */
    //print 21 bytes
    char* syscallBackup = malloc(9);
    char *addrFunction = patchCall(&syscallBackup, ntFunction);

    DWORD* dstPtr = 0;
    void(*callback)() = (void(*)())addrFunction;
    int EAX = SysCallingThePatch(addrFunction);
    unpatchCall(syscallBackup, ntFunction);
    
    return EAX;
}

void checkByName(char* name){ 

    //validate only one
    printf("[*] Checking the function %s\n", name);
    
    
    char outSyscall[21];
    memset(outSyscall, 0, 21);
    BOOL wasAble = retBytesFromFunction(outSyscall, name, SYSCALL_LEN);
    if(!wasAble){
        printf("[!] Error: Unable to get the syscall from %s\n", name);
        return 1;
    }
    BOOL isValid = isValidSyscall((BYTE *)outSyscall);
    if(isValid){
        DWORD syscallNumber = *(DWORD *)(outSyscall + 4);
        printf("[*] No hook was found in : %s\n", name);
        printf("[*] Syscall number: %x\n", syscallNumber);
        return 0;
    }else{
        char checker[] = {0x0f, 0x05};
        //check if it has the checker opcodes into outSyscall
        BOOL itHas = FALSE;
        int i = 0;
        while(i < SYSCALL_LEN){
            if(outSyscall[i] == checker[0] && outSyscall[i+1] == checker[1]){
                itHas = TRUE;
                break;
            }
            i++;
        }
        if(!itHas){
            printf("[!] Error: Unable to get the syscall from %s\n", name);
            return 1;
        }
        printf("[!] Syscall hooked\n");
    }
    int dynamicSyscallNumber = GetSSNIndirectSyscall(name);
    printf("[*] Syscall number [Dynamic]: %x\n", dynamicSyscallNumber);

    //What happens if the syscall has a hook and we are not able to see it.
    //The EDR works with 2 inputs, the parameters given from the user mode to the syscall and with the result
    // so if we run a syscall with no suspicious parameters, the EDR will not detect it.
    //let see we have NtReadVirtualMemory
}


/*
 * Get all Zw and Nt function from EAT in ntdll.dll
 * */
void execAllCoreFunctions(size_t* countFunctions){
    //get EAT from ntdll.dll
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(DWORD_PTR)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFunctions = (PDWORD)((DWORD_PTR)hModule + exportDirectory->AddressOfFunctions);
    PDWORD pNames = (PDWORD)((DWORD_PTR)hModule + exportDirectory->AddressOfNames);
    PWORD pOrdinals = (PWORD)((DWORD_PTR)hModule + exportDirectory->AddressOfNameOrdinals);
    
    char **functions = (char **)malloc(exportDirectory->NumberOfFunctions * sizeof(char *));
    size_t count = 0;
    for(int i = 0; i < exportDirectory->NumberOfFunctions; i++){
        char* name = (char *)((DWORD_PTR)hModule + pNames[i]);
        DWORD ordinal = pOrdinals[i];
        DWORD address = pFunctions[ordinal];
        //only Zw and Nt compared with names
        if(strncmp(name, "Zw", 2) == 0 || strncmp(name, "Nt", 2) == 0){
            printf("---------------------------------\n");
            char tmpBN[100];
            memset(tmpBN, 0, 100);
            strncpy(tmpBN, name, 100);
            checkByName(tmpBN);
            count++;
        }
    }
    *countFunctions = count; 
}



int main(int argc, char** argv){
       //usage ./syshook.exe -f function_name
    if(argc < 2){
        printf("Usage: %s -f/-a [function_name]", argv[0]);
        return 1;
    }

    parseArgs(argc, argv, &args);
    if(args.flagF == 1 && args.flagA == 1){
        printf("[-] Error: -f and -a cannot be used together\n");
        return 1;
    }
    
    if(args.flagF == 1 && strlen(args.functionName)==0){
        printf("[-] Error: -f requires a function name\n");
        return 1;
    }
    
    

    //first instance the module xd
    hModule = LoadLibrary("ntdll.dll");
    if(hModule == NULL){
        printf("[!] Last error: %d\n", GetLastError());
        return 1;
    }
        
    if(args.flagA) {
        //validate all
        size_t countFuntions = 0; 
        execAllCoreFunctions(&countFuntions);
        printf("[!] %d functions checked", countFuntions);

        return 0;

    }else if(args.flagF){
    
        checkByName(args.functionName);
        return 0;
     
        
    }else{
        printf("[-] Error: -f or -a is required\n");
        return 1;
    }

    
      return 0;
}
