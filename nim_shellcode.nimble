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
    rmDir "cache"
    for file in listFiles("bin"):
        rmFile file
    exec "nim c -o:bin/shellcode.exe -d:mingw src/shellcode.nim"
    exec "nim c -o:bin/extract.exe src/extract.nim"
    exec "./bin/extract.exe bin/shellcode.exe bin/shellcode.bin"

task test, "Test the shellcode":
    exec "nim c -o:bin/test.exe -d:mingw ./src/test.nim"
    exec "./bin/test.exe"