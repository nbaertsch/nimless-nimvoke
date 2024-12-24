# Package
version       = "0.1.0"
author        = "nbaertsch"
description   = "Nim shellcode development template"
license       = "MIT"
srcDir        = "src"
binDir = "bin"
bin           = @["shellcode", "extract"]

# Dependencies
requires "nim >= 1.6.0"
requires "winim >= 3.9.0"
requires "termstyle >= 0.1.0"


# Tasks
task shellcode, "Build the shellcode":
    exec "nim c -o:bin/shellcode.exe src/shellcode.nim"
    exec "nim c -r -o:bin/extract.exe src/extract.nim bin/shellcode.exe bin/shellcode.bin"

task extract, "Extract shellcode from a PE file":
    if paramCount() < 2:
        echo "Usage: nimble extract <input_exe> <output_bin>"
        return
    exec "nim c -r -o:bin/extract.exe src/extract.nim " & paramStr(3) & " " & paramStr(4)

task test, "Test the shellcode":
    exec "nim c -r -o:bin/test.exe src/test.nim"
