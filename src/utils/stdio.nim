import ninst
import str
from winim import LPSTR, HLOCAL, FARPROC, LPTR, NULL, STD_OUTPUT_HANDLE, HWND, LPCSTR, MB_OK

proc print*(ninst: ptr Ninst, cs: cstring) {.inline.} =
    ## Print a string to the console
    var buf = cast[LPSTR](ninst.pLocalAlloc(LPTR, 1024))
    if cast[uint](buf) != 0:
        var length = ninst.pwsprintfA(buf, cast[cstring](addr cs[0]))
        discard ninst.pWriteConsoleA(ninst.pGetStdHandle(STD_OUTPUT_HANDLE), buf, length, NULL, NULL)
        discard ninst.pLocalFree(cast[HLOCAL](buf))

template print*(ninst: ptr Ninst, args: varargs[untyped]) =
    var buf = cast[LPSTR](ninst.pLocalAlloc(LPTR, 1024))
    if cast[uint](buf) != 0:
      var length = ninst.pwsprintfA(buf, args)
      discard ninst.pWriteConsoleA(ninst.pGetStdHandle(STD_OUTPUT_HANDLE), buf, length, NULL, NULL)
      discard ninst.pLocalFree(cast[HLOCAL](buf))

proc msgbox*(ninst: ptr Ninst, cs_title: cstring, cs_text: cstring) {.inline.} =
    ## Display a message box
    discard ninst.pMessageBoxA(cast[HWND](0), cast[LPCSTR](addr cs_title[0]), cast[LPCSTR](addr cs_text[0]), MB_OK)

proc dumpHex*(ninst: ptr Ninst, data: pointer, size: int) {.inline.} =
    ninst.print("0x")
    var 
      p = cast[ptr byte](data)
      ascii: array[17, byte]
    for i in 0 ..< size:
      ninst.print("%02x ", p[])
      if p[] >= ' '.byte and p[] <= '~'.byte:
        ascii[i mod 16] = p[]
      else: ascii[i mod 16] = '.'.byte
      if ((i+1) mod 8) == 0 or (i + 1) == size:
        ninst.print(" ")
        if (i + 1) mod 16 == 0:
          ninst.print("|  %s \n", cast[cstring](ascii[0].addr))
        elif (i + 1) == size:
          ascii[(i+1) mod 16] = '\0'.byte
          if ((i+1) mod 16) <= 8:
            ninst.print(" ")
          for j in (i + 1) mod 16 ..< 16:
            ninst.print("   ")
          ninst.print("|  %s \n", cast[cstring](ascii[0].addr))
      p = cast[ptr byte](cast[uint](data) + i.uint + 1)

template print*(ninst: ptr Ninst, s: string) =
    var ss {.stackStringA.} = s
    print(ninst, cast[cstring](addr ss[0]))

template msgbox*(ninst: ptr Ninst, sTitle: string, sText: string) =
    var ssTitle {.stackStringA.} = sTitle
    var ssText {.stackStringA.} = sText
    msgbox(ninst, cast[cstring](addr ssTitle[0]), cast[cstring](addr ssText[0]))


