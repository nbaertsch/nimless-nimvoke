import std/[strutils, sequtils]
import winim/lean
from std/strutils import toHex

proc staticReadFileBytes(fileName: string): seq[char] {.compileTime.} =
    return readFile(fileName).toSeq()

proc main() =
    echo "Running shellcode..."
    var oldProtect: DWORD
    var shellcode = staticReadFileBytes("./bin/shellcode.bin")
    if defined(WithBP):
        shellcode.add(0xCC.char)
        shellcode = @[0xCC.char].concat(shellcode)
    echo "Shellcode length: ", shellcode.len()
    let p = VirtualAlloc(NULL, shellcode.len(), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if p == NULL:
        echo "Failed to allocate memory"
        return
    copyMem(p, addr shellcode[0], shellcode.len())
    MessageBoxA(cast[HWND](0), "Shellcode ptr: " & cast[SIZE_T](p).toHex(), "Test", MB_OK)
    cast[proc(){.stdcall.}](p)()
    echo "Shellcode executed"

main()