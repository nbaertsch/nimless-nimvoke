import std/macros
import utils/[gmh, gpa, stack, str, hash, stdio, ninst, syscalls, convert]
import winim
import utils/debug

# Messagebox via NtRaiseHardError syscall
proc KeMessageBox*(ninst: ptr Ninst, title: PCWSTR, text: PCWSTR, msgType: ULONG_PTR): ULONG {.inline.} =
    var 
        uTitle: UNICODE_STRING = UNICODE_STRING(Length: 0, MaximumLength: 0, Buffer: nil)
        uText: UNICODE_STRING = UNICODE_STRING(Length: 0, MaximumLength: 0, Buffer: nil)
        response: ULONG = 0

    # get length of title and text
    var
        titleLen = 0
        textLen = 0
        c: WCHAR = cast[ptr UncheckedArray[WCHAR]](title)[0]
    while c != 0.WCHAR:
        titleLen += 1
        c = cast[ptr UncheckedArray[WCHAR]](title)[titleLen]
    c = cast[ptr UncheckedArray[WCHAR]](text)[0]
    while c != 0.WCHAR:
        textLen += 1
        c = cast[ptr UncheckedArray[WCHAR]](text)[textLen]

    uTitle.Length = cast[USHORT](titleLen * 2)
    uTitle.MaximumLength = cast[USHORT](titleLen * 2)
    uTitle.Buffer = cast[PWSTR](title)

    uText.Length = cast[USHORT](textLen * 2)
    uText.MaximumLength = cast[USHORT](textLen * 2)
    uText.Buffer = cast[PWSTR](text)

    var args: array[3, ULONG_PTR] = [
        cast[ULONG_PTR](uText.addr),
        cast[ULONG_PTR](uTitle.addr),
        msgType
    ]

    var status = ninst.syscall("NtRaiseHardError",
        cast[uint64](0x50000018), # STATUS_SERVICE_NOTIFICATION (0x40000018u) | HARDERROR_OVERRIDE_ERRORMODE (0x10000000u)
        3, # num of params
        3, # paramater mask (?) - allways 3 for whatever reason
        cast[uint64](args.addr), # param array
        0.uint64, # response option (okay)
        cast[uint64](response.addr) # response
    )

    return response

proc main() =
    # Initialize ninst  
    var ninst = initNinst()
    
    # Init syscalls
    ninst.initSyscalls()

    # Print syscalls
    #[
    for s in 0..(ninst.syscallCount - 1):
        ninst.print(ninst.syscalls[s].pName)
        ninst.print("\n")
    ]#

    # NtRaiseHardError
    var
        title {.stackStringW.} = "NtRaiseHardError Says Hello!"
        text {.stackStringW.} = "Hello from nimless-nimvoke."
        msgType = 0

    discard KeMessageBox(ninst, cast[PCWSTR](title[0].addr), cast[PCWSTR](text[0].addr), msgType)

    # Cleanup ninst
    cleanupNinst(ninst)


when isMainModule:
    allignStack()
    main()
    cleanupStack()