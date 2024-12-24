import utils/[getmoduleh, getprocaddr, stack, str]
import winim

# declaring WinExec
type  WinExec = (proc(lpCmdLine: LPCSTR, uCmdShow: UINT): int32 {.stdcall.})

proc main() =
  var sKernel32 {.stackStringA.} = "Kernel32.dll"

  var sWinExec {.stackStringA.} = "WinExec"

  var sCalcExe {.stackStringA.} = "calc.exe"

  var
    h: HMODULE = getModuleHandle(cast[cstring](addr sKernel32[0]))
    pWinExec: WinExec = cast[WinExec](getProcAddress(h, cast[cstring](addr sWinExec[0])))

  discard pWinExec(cast[LPCSTR](addr sCalcExe[0]), cast[UINT](0))

when isMainModule:
  allignStack()
  main()