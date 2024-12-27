import utils/[getmoduleh, getProcAddressByHash, stack, str, hash]
import winim
from dinvoke import dinvokeDefine

# declaring WinExec
#type  WinExec = (proc(lpCmdLine: LPCSTR, uCmdShow: UINT): int32 {.stdcall.})

proc main() =
    var sCalcExe {.stackStringA.} = "calc.exe"

    dinvokeDefine(WinExec, "Kernel32.dll", proc(lpCmdLine: LPCSTR, uCmdShow: UINT): int32 {.stdcall.})

    discard WinExec(cast[LPCSTR](addr sCalcExe[0]), cast[UINT](0))

when isMainModule:
    allignStack()
    main()