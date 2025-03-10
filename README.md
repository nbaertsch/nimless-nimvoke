# Nimless Nimvoke
This is a template for writing shellcode that makes syscalls. It's based on my nimvoke project, but this compiles to PIC shellcode thanks to previous [work](https://github.com/m4ul3r/writing_nimless) by [m4ul3r](https://github.com/m4ul3r).

## What?
`shellcode.nim` is a template for writing shellcode that makes syscalls. The provided example is a simple `NtRaiseHardError` message box.

## How?
### Building via docker
`build-docker.(bat|sh)`: In a docker container, compile and carve out the shellcode from `shellcode.nim`. Shellcode will be written to `shellcode.bin` and printed as a nim byte array to stdout.

### Building locally
First ensure you have nim installed and set up to cross-compile to x86_64 via gcc v11.1.0. The version is important here, later versions will not correctly build the shellcode (this is why bullseye is used in the dockerfile).

`nimble shellcode`: Run inside the docker container or locally to build shellcode.
  - builds `shellcode.nim`.
  - builds `extract.nim`.
  - runs `extract.exe` which carves out the shellcode from the .text section of `shellcode.exe`, writes the bytes to `shellcode.bin`, and prints shellcode as a nim byte array to stdout.

`nimble test`: Builds a simple test binary that reads `shellcode.bin` and self-injects it.

### Writing
`src/ninst.nim` defines the `Ninst` struct that holds function pointers to the syscalls you want to make.

`src/utils/syscalls.nim` is a helper that populates the `Ninst` struct with syscall names, name-hashes, func ptrs, and ordinals. You'll see the `var ninst = initNinst()` in `shellcode.nim` which initializes the `Ninst` struct with function pointers to needed Win32 functions.

Like [nimvoke](https://github.com/nbaertsch/nimvoke), `syscalls.nim` needs to parse ntdll to get syscall function pointers, sort them, and check if any are hooked. Before you can make syscalls, you must `ninst.initSyscalls()` to do the needful searching and sorting.

From there, you can call syscalls like so:
```nim
var status = ninst.syscall("NtRaiseHardError", # Name of syscall, which will be hashed at compile time
        cast[uint64](0x50000018), # These are the remaining syscall params...
        3,
        3,
        cast[uint64](args.addr),
        0.uint64,
        cast[uint64](response.addr)
    )
```

Since this shellcode won't return cleanly (pull requests welcome), you'll need to call `ninst.pExitProcess(0)` at then end of your `shellcode.nim` to exit the process cleanly.
