# 👻 syshook 
Tool to detect syscalls usermode hooks (ntdll.dll) from EDRs/AVs

## Description
**syshook** allows you to detect if a syscall is hooked or not, and retrieve the SSDT index of the syscall using a PATCH and UNPATCH method.
1. A function name is given as an argument (ex. NtReadVirtualMemory).
2. The function address is retrieved using `GetProcAddress` from `ntdll.dll`.
3. The function `SysCallThePatch` is called, but before is prepared the arguments (based on x64 calling convention)
4. Using `VirtualProtect` and `memcpy` the function is patched to avoid calling the `syscall` instruction. The code is the next, and as you can see it does nothing but is used to fill the instructions.
    ```assembly
    mov r12d,eax
    mov eax,r12d
    ret
    ```

4. The function is called and the `eax` register is retrieved.
5. Finally, the function is unpached using `memcpy` and `VirtualProtect` to restore the original code.

<hr />
<details>
<summary>☠️ Click in case you are interested in how i came up with this idea</summary>

<hr />
I was researching how to bypass EDR/AVs using syscalls and find ways to get the syscall number dynamically. There are many techniques to perform this (such as Hell's Gate and all the Gates, xd), but I was searching for a way that does not depend on the continuation of the syscall numbers. After all, an EDR/AV is just a software, so if there is a method to read the syscall number by calling a non-malicious function and then somehow retrieve the number obtained, it could be useful, regardless of whether the EDR/AV analyzes the arguments of the function.

EDRs/AVs usually use 2 steps to analyze the user-mode hook:

1. The jmp sends all the parameters to a function that is used to analyze the syscall.
2. It returns but also analyzes the response of the syscall, so the ret does not return to the original function; it returns to the EDR/AV.

So, the basic idea is that. Patch - Call - Unpatch. Then, I realize that it could be used first to get the hooked function and retrieve the syscall number in a machine that has an EDR/AV installed. I think that it couldn't be used to bypass the EDR/AV, but it could be used to get the syscall number dynamically. Anyway I am going to test it in a machine with an EDR/AV installed to see if it works. (later I will update this section) 

</details>

## Usage

Scan all the Nt and Zw functions from ntdll.dll

```bash
./syshook -a
```

Scan a specific function

```bash
./syshook -f NtReadVirtualMemory
```

## Output
```
# No hooked function
[*] Checking the function ZwAllocateUserPhysicalPagesEx
[*] No hook was found in : ZwAllocateUserPhysicalPagesEx
[*] Syscall number: 74
```

```
# Hooked function
[*] Checking the function ZwWriteVirtualMemory
[!] Syscall hooked
[$] Patching the function ZwWriteVirtualMemory
[$] Successfully patched the function ZwWriteVirtualMemory
[$] Unpatching the function ZwWriteVirtualMemory
[$] Successfully unpatched the function ZwWriteVirtualMemory
[*] Syscall number [Dynamic]: 3a
```
Where the syscall is `3a`, should consider that the `3a` is not visible because is dynamically calculated. The EDR/AV hooked this function by replacing the `syscall` instruction by a `jmp` to some analysis function. 
