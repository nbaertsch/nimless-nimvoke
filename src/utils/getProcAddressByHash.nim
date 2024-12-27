from winim/lean import FARPROC, HMODULE, PVOID, PCHAR, WORD, DWORD, SIZE_T, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, LIST_ENTRY, PEB, PPEB, PEB_LDR_DATA, NULL, CHAR
from ./nimjaStructs import NIMJA_LDR_DATA_TABLE_ENTRY
from ./hash import hashStringDjb2A, hashStringDjb2W
from ./getpeb import GetPEB
from ./str import stackStringA

proc getModuleHandleByHash*(modHash: uint32): PVOID =
    ## Given a hash of a module name, returns the module base.
    let peb: PEB = cast[PPEB](GetPEB())[]
    let head: NIMJA_LDR_DATA_TABLE_ENTRY = cast[ptr NIMJA_LDR_DATA_TABLE_ENTRY](cast[LIST_ENTRY](cast[ptr PEB_LDR_DATA](peb.Ldr)[].Reserved2[1]).Flink)[]
    let tail = head.InLoadOrderLinks.Blink
    var cursor = head
    var done = false
    while not done: # iterate through InLoadOrderLinks until we find our dll base address
        if cast[uint](cursor) == cast[uint](tail): done = true # reached end of list
        let dllName: cstring = cast[cstring](cursor.FullDllName.Buffer)
        if(hashStringDjb2A(dllName) == modHash): # module found
            done = true
            return cursor.DllBase
        if not done:
            cursor = cast[ptr NIMJA_LDR_DATA_TABLE_ENTRY](cursor.InLoadOrderLinks.Flink)[]

    return cast[PVOID](0) # module not found, not loaded?

proc getProcAddressByHash*(modHash, funcHash: uint32): FARPROC =
    ## Given a hash of a module name and a hash of a function name exported by that module, returns the address of the function.
    
    # First get the module base address
    var modBase: PVOID = getModuleHandleByHash(modHash)
    if modBase == NULL:
        return NULL # module not loaded

    # Now we get the exported function address
    var
        dosHeader: IMAGE_DOS_HEADER
        ntHeader: IMAGE_NT_HEADERS
        exportDirectory: IMAGE_EXPORT_DIRECTORY
        exportDirectoryOffset: DWORD
        pExportFuncTable: SIZE_T
        pExportNameTable: SIZE_T
        pExportOrdinalTable: SIZE_T
        pFunc: PVOID
        ord: WORD
        pName: PCHAR
    
    dosHeader = cast[ptr IMAGE_DOS_HEADER](modBase)[]
    ntHeader = cast[ptr IMAGE_NT_HEADERS](cast[SIZE_T](modBase) + cast[SIZE_T](dosHeader.e_lfanew))[]
    exportDirectoryOffset = (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress
    exportDirectory = cast[ptr IMAGE_EXPORT_DIRECTORY](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectoryOffset))[]

    pExportFuncTable = cast[SIZE_T](modBase) + exportDirectory.AddressOfFunctions
    pExportNameTable = cast[SIZE_T](modBase) + exportDirectory.AddressOfNames
    pExportOrdinalTable = cast[SIZE_T](modBase) + exportDirectory.AddressOfNameOrdinals 

    for funcNum in 0 .. exportDirectory.NumberOfNames:
        var funcName: cstring

        pName = cast[PCHAR](cast[SIZE_T](modBase) + cast[SIZE_T](cast[ptr DWORD](pExportNameTable + funcNum * sizeof(DWORD))[]))
        ord = cast[ptr WORD](cast[SIZE_T](pExportOrdinalTable) + cast[SIZE_T](funcNum * sizeof(WORD)))[]
        pFunc = cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](cast[ptr DWORD](pExportFuncTable + ord.int * sizeof(DWORD))[]))

        funcName = cast[cstring](pName)
        if funcHash == hashStringDjb2A(funcName):
            if cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectoryOffset)) <= pFunc and pFunc < cast[PVOID](cast[SIZE_T](modBase) + cast[SIZE_T](exportDirectoryOffset) + cast[SIZE_T]((ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size)):
                # forwarded import
                var fwdStrWithDot = cast[cstring](pFunc)
                var len = fwdStrWithDot.len
                ## get index of first dot
                var dotIndex = 0
                for i in 0..len-1:
                    if fwdStrWithDot[i] == '.':
                        dotIndex = i
                        break
                ## get the dll name and the function name
                var fwdStackString {.stackStringA.} = fwdStrWithDot
                ## replace dot with null terminator
                var idx = 0
                while true:
                    if fwdStackString[idx] == '.'.byte:
                        fwdStackString[idx] = 0.byte
                        break
                    idx.inc
                
                ## get the hash of the dll name and the function name
                var dllNameHash = hashStringDjb2A(cast[ptr UncheckedArray[byte]](fwdStackString[0].addr))
                var funcNameHash = hashStringDjb2A(cast[ptr UncheckedArray[byte]](fwdStackString[idx+1].addr))

                return getProcAddressByHash(dllNameHash, funcNameHash)
            else:
                return cast[FARPROC](pFunc)

    return NULL