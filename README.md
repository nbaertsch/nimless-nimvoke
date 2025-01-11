# Nimless Nimvoke
This is a template for writing shellcode that makes syscalls. It's based on my nimvoke project, but this compiles to PIC shellcode.

## WTF do I do tho?
`nimble shellcode`:
  - builds the shellcode.nim file.
  - builds extract.nim
  - runs extract.exe which carves out the shellcode from the .text section of shellcode.exe, writes the bytes to shellcode.bin, and prints shellcode as a nim byte array to stdout

`nimble test`:
  - builds a simple test binary that slurps the shellcode.bin and self-injects it.

# Stolen Code Alert!
Most of the non-syscall code is taken from m4ul3r's [writing-nimless](https://github.com/m4ul3r/writing_nimless) repo.
