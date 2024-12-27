from winim/lean import PEB, PPEB, PVOID, LIST_ENTRY, PEB_LDR_DATA, FARPROC, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, DWORD, WORD, SIZE_T, NULL, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, PCHAR
from utils/hash import hashStringDjb2AStatic
from std/macros import quote, newIdentNode, newLit, strVal
from utils/getProcAddressByHash import getProcAddressByHash


macro dinvokeDefine*(funcName: untyped, libName: untyped, funcDef: untyped): untyped =
    ## Defines a new delegate function var `funcName`, of type `funcDef`, and casts the appropriate function ptr to the delegate.
    ## Function ptr's are retrieved by PEB walk. Will fail if module is not loaded into process.
    let funcNameStr = funcName.strVal
    quote do:
        var `funcName` {.inject.} = cast[`funcDef`](hashStringDjb2AStatic((`libName`.cstring)).getProcAddressByHash(hashStringDjb2AStatic(`funcNameStr`.cstring)))