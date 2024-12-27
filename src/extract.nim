import winim/lean
import termstyle
import std/[strutils, sequtils, cmdline]

# debug print template - https://nim-lang.org/docs/tut2.html#templates
template `debug` (ss: varargs[string, `$`]) =
    when (not defined RELEASE) and (not defined SILENT):
        var str = ""
        for s in ss:
            str &= s
        echo magenta &"[DEBUG] ", str

proc prettyPrintBytes*(bytes: seq[byte]): string =
    const MAXLEN = 16
    var count = 1
    result = "" # unnecesary but for sanity
    result.add("array[" & $bytes.len() & ", byte] = [\n    byte ")
    for i in bytes:
        if count == bytes.len():
            result.add("0x" & toHex(i) & "]")
            break
        elif count.mod(MAXLEN) == 0:
            result.add("\n    ")
        result.add("0x" & toHex(i) & ",")
        count += 1

proc readFileBytes(fullName: string): seq[byte] =
    var
        file = open(fullName, fmRead)
        b = cast[seq[byte]](file.readAll())
    file.close()
    return b

proc extract_text(filename: string): seq[byte] =
    # Read bytes
    echo ("Extracting .text from " & fileName & "...")
    var fileBytes: seq[byte]
    fileBytes = readFileBytes(fileName)
    
    if fileBytes.len() == 0:
        echo red("Failed to read file")
        return

    var mzMagic = (fileBytes[0].char & fileBytes[1].char)
    echo "magicBytes: ", mzMagic
    if mzMagic != "MZ":
        debug white(&"{filename}: ") & yellow(&"Bad magic bytes: {mzMagic}")
        return

    # optHeaederOffset
    var optHeaderOffset: LONG = cast[ptr LONG](addr fileBytes[60])[]
    debug "optHeaderOffset = ", toHex(optHeaderOffset.int), &"({optHeaderOffset})"

    var peSignature = join(cast[seq[char]](fileBytes[optHeaderOffset..optHeaderOffset + 4]))
    if peSignature[0] != 'P' or peSignature[1] != 'E':
        debug white(&"{filename}: ") & yellow(&"Not a PE file (sig: {cast[ptr WORD](addr peSignature[0])[].int.toHex()})")
        return

    var coffset = optHeaderOffset.int + 4
    debug "coffset = ", toHex(coffset), &"({coffset})"

    var coffFileHeader: IMAGE_FILE_HEADER = cast[ptr IMAGE_FILE_HEADER](addr fileBytes[coffset])[] # `0x3c` is the size of the DOS-stub + 4-byte signatture ("PE\0\0") = COFF File Header (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN#coff-file-header-object-and-image)

    var peMagic: WORD = cast[ptr WORD](addr fileBytes[coffset + sizeof(IMAGE_FILE_HEADER)])[]
    debug "peMagic = ", peMagic.int.toHex(), &" ({(peMagic == WORD 0x10B) or (peMagic == WORD 0x20B) })"
    var isX64:bool
    if peMagic == WORD 0x10B:
        isX64 = false
        debug "ARCH: x32"
    elif peMagic == WORD 0x20B:
        isX64 = true
        debug "ARCH: x64"
    else:
        debug red"Malformed optional header magic number"
        return

    # If we made it here, the file is indeed a PE file

    #[
        Enumerate the sections
    ]#
    var numSections: int = coffFileHeader.NumberOfSections.int
    debug "numSections = ", numSections
    var pSectionTable: ptr UncheckedArray[IMAGE_SECTION_HEADER] =  cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](&fileBytes[coffset + sizeof(IMAGE_FILE_HEADER) + coffFileHeader.SizeOfOptionalHeader.int]) # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN#section-table-section-headers
    #[  https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
        IMAGE_SECTION_HEADER* {.pure.} = object
        Name*: array[IMAGE_SIZEOF_SHORT_NAME, BYTE]
        Misc*: IMAGE_SECTION_HEADER_Misc
        VirtualAddress*: DWORD
        SizeOfRawData*: DWORD
        PointerToRawData*: DWORD
        PointerToRelocations*: DWORD
        PointerToLinenumbers*: DWORD
        NumberOfRelocations*: WORD
        NumberOfLinenumbers*: WORD
        Characteristics*: DWORD
    ]#
    
    #print PE sig
    debug "PE Signature: ", fileBytes[optHeaderOffset].char & fileBytes[optHeaderOffset+1].char

    #print coff heaeder
    debug &"COFF Header: arch:{coffFileHeader.Machine.int.toHex()}, sections: {numSections}, size: {coffFileHeader.SizeOfOptionalHeader.int}"    

    var sectionHeader: IMAGE_SECTION_HEADER
    for s in 0..numSections-1:
        sectionHeader = pSectionTable[][s]

        if sectionHeader.Name[0] == '.'.byte and
            sectionHeader.Name[1] == 't'.byte and
            sectionHeader.Name[2] == 'e'.byte and
            sectionHeader.Name[3] == 'x'.byte and
            sectionHeader.Name[4] == 't'.byte and
            sectionHeader.Name[5] == 0:
            echo "Found .text section"
            return fileBytes[sectionHeader.PointerToRawData..sectionHeader.PointerToRawData.int + sectionHeader.Misc.VirtualSize.int]

    echo red("No .text section found")
    return @[]

proc main() =
    if paramCount() < 2:
        echo red("Usage: extract.exe <filename> <shellcode_output_file>")
        return

    var fileName = paramStr(1)
    var shellcodeFile = paramStr(2)
    var shellcode = extract_text(fileName)
    echo prettyPrintBytes(shellcode)
    var sf = open(shellcodeFile, fmWrite)
    discard sf.writeBytes(shellcode, 0 ,shellcode.len())
    sf.close()


main()
