import gmh, gpa, str

import winim

type
    doSyscall = proc (ssn: uint16, jmpAddr: uint64): NTSTATUS {.varargs, stdcall.}
    NtRaiseHardError = proc (status: uint64, count: uint64, mask: uint64, pargs: uint64, response: uint64): uint64 {.stdcall.}
    Syscall* = object
        pName*: PCHAR
        ord*: WORD
        pFunc*: PVOID
        pSyscall*: PVOID = NULL
        ssn*: WORD
        hooked*: bool
        stubSize*: SIZE_T

    Ninst* = object
        hNtdll*: HMODULE
        hKernel32*: HMODULE
        hHeap*: HANDLE
        pLoadLibraryA*: typeof(LoadLibraryA)
        pGetLastError*: typeof(GetLastError)
        hUser32*: HMODULE
        pwsprintfA*: typeof(wsprintfA)
        pLocalAlloc*: typeof(LocalAlloc)
        pLocalFree*: typeof(LocalFree)
        pGetStdHandle*: typeof(GetStdHandle)
        pWriteConsoleA*: typeof(WriteConsoleA)
        pMessageBoxA*: typeof(MessageBoxA)
        pHeapCreate*: typeof(HeapCreate)
        pHeapAlloc*: typeof(HeapAlloc)
        pHeapFree*: typeof(HeapFree)
        pHeapDestroy*: typeof(HeapDestroy)
        pVirtualProtect*: FARPROC
        pVirtualAlloc*: FARPROC
        pVirtualFree*: FARPROC
        pVirtualAllocEx*: typeof(VirtualAllocEx)
        pVirtualFreeEx*: typeof(VirtualFreeEx)
        pVirtualProtectEx*: typeof(VirtualProtectEx)
        pGlobalAlloc*: typeof(GlobalAlloc)
        pGlobalFree*: typeof(GlobalFree)
        pRtlInitUnicodeString*: typeof(RtlInitUnicodeString)
        pNtRaiseHardError*: typeof(NtRaiseHardError)
        syscalls*: array[500, ptr Syscall]
        syscallHashes*: array[500, uint32]
        syscallCount*: int
        doSyscall*: typeof(doSyscall)

proc loadUser32*(n: var Ninst) {.inline.} =
    var sUser32 {.stackStringA.} = "user32.dll"
    n.hUser32 = n.pLoadLibraryA(CPTR(sUser32))

proc initNinst*(): ptr Ninst {.inline.} =
    # Get KERNEL32.DLL base address
    var hKernel32 = gmh("KERNEL32.DLL")
    # Get LocalAlloc/Free address'
    var pLocalAlloc = gpa(hKernel32, "LocalAlloc", LocalAlloc)
    var pLocalFree = gpa(hKernel32, "LocalFree", LocalFree)
    var pVirtualAllocEx = gpa(hKernel32, "VirtualAllocEx", VirtualAllocEx)
    var pVirtualFreeEx = gpa(hKernel32, "VirtualFreeEx", VirtualFreeEx)
    var pVirtualProtectEx = gpa(hKernel32, "VirtualProtectEx", VirtualProtectEx)
    var pGlobalAlloc = gpa(hKernel32, "GlobalAlloc", GlobalAlloc)
    var pGetLastError = gpa(hKernel32, "GetLastError", GetLastError)

    # Allocate memory for the Ninst struct
    var pNinst = cast[ptr Ninst](pGlobalAlloc(GMEM_FIXED, sizeof(Ninst)))

    # Initialize the Ninst struct
    pNinst.hKernel32 = hKernel32
    pNinst.pLocalAlloc = pLocalAlloc
    pNinst.pLocalFree = pLocalFree
    pNinst.pVirtualAllocEx = pVirtualAllocEx
    pNinst.pVirtualFreeEx = pVirtualFreeEx
    pNinst.pVirtualProtectEx = pVirtualProtectEx
    pNinst.pGlobalAlloc = pGlobalAlloc
    pNinst.pGlobalFree = gpa(hKernel32, "GlobalFree", GlobalFree)

    # Load user32.dll
    pNinst.pLoadLibraryA = gpa(hKernel32, "LoadLibraryA", LoadLibraryA)
    var sUser32 {.stackStringA.} = "user32.dll"
    pNinst.hUser32 = pNinst.pLoadLibraryA(CPTR(sUser32))

    # Load common function pointers
    pNinst.pwsprintfA = gpa(pNinst.hUser32, "wsprintfA", wsprintfA)
    pNinst.pGetStdHandle = gpa(pNinst.hKernel32, "GetStdHandle", GetStdHandle)
    pNinst.pWriteConsoleA = gpa(pNinst.hKernel32, "WriteConsoleA", WriteConsoleA)
    pNinst.pMessageBoxA = gpa(pNinst.hUser32, "MessageBoxA", MessageBoxA)
    pNinst.pVirtualAlloc = gpa(pNinst.hKernel32, "VirtualAllocEx", VirtualAllocEx)
    pNinst.pVirtualFree = gpa(pNinst.hKernel32, "VirtualFreeEx", VirtualFreeEx)
    pNinst.pVirtualProtect = gpa(pNinst.hKernel32, "VirtualProtectEx", VirtualProtectEx)
    pNinst.pGetLastError = gpa(pNinst.hKernel32, "GetLastError", GetLastError)

    return pNinst

proc cleanupNinst*(n: ptr Ninst) {.inline.} =
    if n.doSyscall != nil:
        discard n.pGlobalFree(cast[HLOCAL](n.doSyscall))
    discard n.pGlobalFree(cast[HLOCAL](n))

