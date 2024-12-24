## Nim Flags
##------------------------------------
--define:mingw

## Standard Flags
--define:release
--define:danger 
--mm:none 
--threads:off 
--cpu:amd64
--opt:size

## Set the cache directory
--nimcache:"./cache/$projectname"

## Turn off main procedure generation, that will be set with a linker
## flag to NimMainModule 
--noMain:on

## Use Nim's routines to prevent linking to MSVCRT
--define:nimNoLibc 

## Turn off Winim's embedded resource
--define:noRes 

## Rebuild the binary to force rehashing
--forcebuild

## Skip any parent configs
--skipParentCfg

## Turn off all checks
--checks:off
--nanChecks:off
--infChecks:off
--styleCheck:off

## Misc. Flags
--hotCodeReloading:off
--tlsEmulation:off
--stackTraceMsgs:off
--sinkInference:off
--styleChecks:off

## GCC flags 
##------------------------------------
## Standard Flags
--t:"-masm=intel"
--t:"-Os"
--t:"-fpic"
--t:"-fomit-frame-pointer"
# --t:"-mno-sse"

## Function allignment
--t:"-fno-align-functions"
--t:"-flimit-function-alignment"
--t:"-fno-align-labels"
--t:"-fno-align-jumps"

## Turn off MingW's startup code & dynamically linked libraries (Kernel32 & MSVCRT)
## This is the equivalent of using: -nodefaultlibs -nostartfiles
--t:"-nostdlib"

## Place functions & data in their own sections, this allows for our linker to
## garbage collect efficiently and reduce the code size.
--t:"-ffunction-sections"
--t:"-fdata-sections"

## Allow the use of case statements for cleaner code
--t:"-fno-jump-tables"

## Turn off Exceptions
--t:"-fno-exceptions"

## Suppress generation of stack unwinding tables
--t:"-fno-asynchronous-unwind-tables"

## Merge identical constants and variables to reduce code size
--t:"-fmerge-all-constants"

## Linker flags 
##------------------------------------
## Bypass all of Nim's initialization procedures, there is no GC so they aren't needed.
## This also turns off IO, so echo/debugecho will not work with this turned on.
--l:"-Wl,-eNimMainModule"
 
## This needs to be passed to the compiler AND the linker...
## Reference: http://www.independent-software.com/linking-a-flat-binary-from-c-with-mingw.html
--l:"-nostdlib"

## Garbage collect all unused code sections.
--l:"-Wl,--gc-sections"

## Strip the executable of all debugging information
# --l:"-Wl,-s"

# --l:"-T./script.ld"