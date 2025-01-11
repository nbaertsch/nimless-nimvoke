import std/macros
from winim/lean import PCHAR, WORD, DWORD, PVOID, NULL, SIZE_T, HANDLE, LPVOID, PDWORD, HEAP_GENERATE_EXCEPTIONS, NTSTATUS, BOOL, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, LPTR, HLOCAL, PAGE_EXECUTE_READ, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE
from winim import HeapCreate, HeapAlloc, HeapDestroy, VirtualProtect, VirtualAlloc, VirtualFree
import gpa, gmh, hash, ninst, stdio


type
    doSyscall* = proc (ssn: uint16, jmpAddr: uint64): NTSTATUS {.varargs, stdcall.}


template `+`[T](x: T, y: typed): T =
    cast[T](cast[SIZE_T](x) + cast[SIZE_T](y))

# Freshycalls
const TRAMPOLINE_SIZE_FRESHY = 59
proc getSyscallTrampoline*(ninst: ptr Ninst) {.inline.} = 
    ## Returns a pointer to the R-X asm stub used for making syscalls. Asm refference: https://github.com/crummie5/FreshyCalls/blob/master/syscall.cpp
    ## Allocation is done on a private heap created specifically for this purpose.
    
    # Allocate some space on the private heap for our syscall trampoline
    var syscallTrampoline = cast[ptr UncheckedArray[byte]](ninst.pVirtualAllocEx(cast[HANDLE](0xFFFFFFFFFFFFFFFF), cast[LPVOID](0), cast[SIZE_T](TRAMPOLINE_SIZE_FRESHY), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE))


    # Syscall stub source: https://github.com/crummie5/FreshyCalls/blob/master/syscall.cpp
    #syscallTrampoline = cast[ptr UncheckedArray[byte]](cast[SIZE_T](syscallTrampoline) + 4)
    syscallTrampoline[0] = byte(0x41) # push r13
    syscallTrampoline[1] = byte(0x55)

    syscallTrampoline[2] = byte(0x41) # push r14
    syscallTrampoline[3] = byte(0x56)

    syscallTrampoline[4] = byte(0x49) # mov r14, rdx
    syscallTrampoline[5] = byte(0x89)
    syscallTrampoline[6] = byte(0xD6)

    syscallTrampoline[7] = byte(0x49) # mov r13, rcx
    syscallTrampoline[8] = byte(0x89)
    syscallTrampoline[9] = byte(0xCD)

    syscallTrampoline[10] = byte(0x4C) # mov rcx, r8
    syscallTrampoline[11] = byte(0x89) 
    syscallTrampoline[12] = byte(0xC1) 

    syscallTrampoline[13] = byte(0x4C) # mov rdx, r9
    syscallTrampoline[14] = byte(0x89) 
    syscallTrampoline[15] = byte(0xCA)
    
    syscallTrampoline[16] = byte(0x4C) # mov r8, [rsp+38h]
    syscallTrampoline[17] = byte(0x8B) 
    syscallTrampoline[18] = byte(0x44)
    syscallTrampoline[19] = byte(0x24)
    syscallTrampoline[20] = byte(0x38)

    syscallTrampoline[21] = byte(0x4C) # mov r9, [rsp+40h]
    syscallTrampoline[22] = byte(0x8B)
    syscallTrampoline[23] = byte(0x4C)
    syscallTrampoline[24] = byte(0x24)
    syscallTrampoline[25] = byte(0x40)

    syscallTrampoline[26] = byte(0x48) # add rsp, 28h
    syscallTrampoline[27] = byte(0x83)
    syscallTrampoline[28] = byte(0xC4)
    syscallTrampoline[29] = byte(0x28)

    syscallTrampoline[30] = byte(0x4C) # lea r11, [rip+0x0C]
    syscallTrampoline[31] = byte(0x8D)
    syscallTrampoline[32] = byte(0x1D)
    syscallTrampoline[33] = byte(0x0C)
    syscallTrampoline[34] = byte(0x00)
    syscallTrampoline[35] = byte(0x00)
    syscallTrampoline[36] = byte(0x00)

    syscallTrampoline[37] = byte(0x41) # call r11
    syscallTrampoline[38] = byte(0xFF)
    syscallTrampoline[39] = byte(0xD3)

    syscallTrampoline[40] = byte(0x48) # sub rsp, 28h
    syscallTrampoline[41] = byte(0x83)
    syscallTrampoline[42] = byte(0xEC)
    syscallTrampoline[43] = byte(0x28)

    syscallTrampoline[44] = byte(0x41) # pop r14
    syscallTrampoline[45] = byte(0x5E)

    syscallTrampoline[46] = byte(0x41) # pop r13
    syscallTrampoline[47] = byte(0x5D)

    syscallTrampoline[48] = byte(0xC3) # ret

    syscallTrampoline[49] = byte(0x4C) # mov rax, r13
    syscallTrampoline[50] = byte(0x89)
    syscallTrampoline[51] = byte(0xE8)

    syscallTrampoline[52] = byte(0x49) # mov r10, rcx
    syscallTrampoline[53] = byte(0x89)
    syscallTrampoline[54] = byte(0xCA) 
    
    syscallTrampoline[55] = byte(0x41) # jmp r14
    syscallTrampoline[56] = byte(0xFF) 
    syscallTrampoline[57] = byte(0xE6)

    syscallTrampoline[58] = byte(0xC3) # ret
    
    # set the page permission of the trampolines to R-X
    var
        op: DWORD = 0
        success: bool
        pSyscallTrampoline: PVOID = nil
    pSyscallTrampoline = ninst.pVirtualAllocEx(cast[HANDLE](0xFFFFFFFFFFFFFFFF), nil, cast[SIZE_T](TRAMPOLINE_SIZE_FRESHY), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if pSyscallTrampoline.isNil(): ninst.print("[x] Failed to allocate syscall trampoline stub\n")
    #success = ninst.pVirtualProtectEx(cast[HANDLE](0), cast[LPVOID](syscallTrampoline), cast[SIZE_T](TRAMPOLINE_SIZE_FRESHY), PAGE_EXECUTE_READ, addr op)
    #if not success: ninst.print("[x] Failed to set allocated syscall trampoline stub to R-X\n")
    #else: ninst.print("[+] Allocated syscall trampoline stub set to R-X\n")

    # Copy the syscall trampoline to the allocated memory
    copyMem(cast[ptr byte](pSyscallTrampoline), cast[ptr byte](syscallTrampoline), TRAMPOLINE_SIZE_FRESHY)

    ninst.doSyscall = cast[doSyscall](syscallTrampoline)

proc sortSyscalls(ninst: ptr Ninst) {.inline.} =
    ## Sort syscalls array by ordinal using bubble sort
    var i = 0
    while ninst.syscalls[i] != nil:
        var j = 0
        # Changed inner loop to start from beginning
        while ninst.syscalls[j] != nil and ninst.syscalls[j + 1] != nil:
            if ninst.syscalls[j].pFunc > ninst.syscalls[j + 1].pFunc:
                # Swap elements
                var temp = ninst.syscalls[j]
                ninst.syscalls[j] = ninst.syscalls[j + 1]
                ninst.syscalls[j + 1] = temp
            inc j
        inc i

proc initSyscalls*(ninst: ptr Ninst) {.inline.} =
    ## Populates a table of syscall data types, sorts the table, 
    ## identifies hooks, and retrieves SSNs and syscall address's
    ninst.hNtdll = gmh("ntdll.dll")
    var
        modBase = ninst.hNtdll
        dosHeader: IMAGE_DOS_HEADER
        ntHeader: IMAGE_NT_HEADERS
        exportDirectory: IMAGE_EXPORT_DIRECTORY
        exportDirectoryOffset: DWORD 
        pExportFuncTable: PVOID 
        pExportNameTable: PVOID 
        pExportOrdinalTable: PVOID 

    dosHeader = cast[ptr IMAGE_DOS_HEADER](modBase)[]
    ntHeader = cast[ptr IMAGE_NT_HEADERS](cast[SIZE_T](modBase) + cast[SIZE_T](dosHeader.e_lfanew))[]
    exportDirectoryOffset = (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress
    exportDirectory = cast[ptr IMAGE_EXPORT_DIRECTORY](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectoryOffset))[]

    pExportFuncTable = cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectory.AddressOfFunctions))
    pExportNameTable = cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectory.AddressOfNames))
    pExportOrdinalTable = cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectory.AddressOfNameOrdinals))

    # populate syscalls with syscall names, name-hashes, func ptrs, and ordinals
    var index = 0
    for funcNum in 0..exportDirectory.NumberOfNames:
        var
            syscall = cast[ptr Syscall](ninst.pGlobalAlloc(0, sizeof(Syscall)))
            funcName: cstring

        syscall.pName = cast[PCHAR](cast[SIZE_T](modBase) + cast[SIZE_T](cast[ptr DWORD](pExportNameTable + funcNum * sizeof(DWORD))[]))
        syscall.ord = cast[ptr WORD](cast[SIZE_T](pExportOrdinalTable) + cast[SIZE_T](funcNum * sizeof(WORD)))[]
        syscall.pFunc = cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](cast[ptr DWORD](pExportFuncTable + syscall.ord.int * sizeof(DWORD))[]))

        # syscall's only
        funcName = cast[cstring](syscall.pName)
        if (funcName.len < 2) or not ((funcName[0] == 'Z') and (funcName[1] == 'w')):
            discard ninst.pGlobalFree(cast[HLOCAL](syscall)) # free the syscall
            continue

        # add syscall to unsorted arrays
        ninst.syscalls[index] = syscall
        inc index

    ninst.syscallCount = index


    # Sort the syscall table by function address so we can infer syscall numbers for hooked syscalls later (Halos Gate)
    #sortSyscalls(ninst)
    #ninst.print("syscalls sorted\n")

    #ninst.print("checking for hooks\n")

    # If the first four bytes aren't `move r10, rcx; mov eax [SSN]` than mark the syscall as hooked
    for s in 0..(ninst.syscallCount - 1):
        # Check for mov r10, rcx; mov eax [SSN] 
        if (cast[ptr byte](ninst.syscalls[s].pFunc)[] == 0x4C) and
            (cast[ptr byte](ninst.syscalls[s].pFunc + 1)[] == 0x8B) and
            (cast[ptr byte](ninst.syscalls[s].pFunc + 2)[] == 0xD1) and 
            (cast[ptr byte](ninst.syscalls[s].pFunc + 3)[] == 0xB8):
                discard

        else: # This syscall is hooked
            ninst.syscalls[s].hooked = true
            continue

        for i in 0..32:
            # Check for syscall instruction
            if (cast[ptr byte](ninst.syscalls[s].pFunc + i)[] == 0x0F) and 
                (cast[ptr byte](ninst.syscalls[s].pFunc + i + 1)[] == 0x05):
                    ninst.syscalls[s].pSyscall = (ninst.syscalls[s].pFunc + i)
                    continue

    sortSyscalls(ninst)

    # Simply count the syscall's now that they're sorted
    for s in 0..(ninst.syscallCount - 1):
        ninst.syscalls[s].ssn = (s).WORD

    ninst.getSyscallTrampoline() # prep the trampoline

macro syscall*(ninst: ptr Ninst, funcName: untyped, args: varargs[untyped]): untyped =
    ## Convenince macro for calling indirect syscall's by name.
    ## Syscall numbers retrieved by sort-and-count. This macro hides the
    ## details of syscall retrieval and calling from the caller.
    var funcNameStr = funcName.strVal
    if funcNameStr[0..1] == "Nt":
        funcNameStr[0] = 'Z'
        funcNameStr[1] = 'w'
    quote do:
        (block: # by wrapping the block in parens, we can return the status variable
            var status: NTSTATUS
            for s in 0..(ninst.syscallCount - 1):
                if ninst.syscalls[s].pName.hashStrA() == static(hashStrA(`funcNameStr`)):
                    status = ninst.doSyscall(ninst.syscalls[s].ssn.uint16, cast[uint64](ninst.syscalls[s].pSyscall),
                        `args`
                    )
            status
        )
