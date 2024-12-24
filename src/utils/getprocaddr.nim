import winim

import memcmp, hash

proc getProcAddress*(hModule: HMODULE, lpApiName: cstring): FARPROC {.inline, noSideEffect.} =
  let
    pBase = cast[int](hModule)
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
    pImgNtHdrs = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)
  # assume this always works -- adds extra bytes
  # if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) or (pImgNtHdrs.Signature != IMAGE_NT_SIGNATURE):
  #   return cast[FARPROC](0)
  let
    imgOptHdr: IMAGE_OPTIONAL_HEADER = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdrs.OptionalHeader)
    pImgExportDir: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](cast[DWORD64](pBase) + cast[DWORD64](imgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
    functionNameArray: ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[uint](pBase) + pImgExportDir.AddressOfNames.uint)
    functionAddressArray:  ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[uint](pBase) + pImgExportDir.AddressOfFunctions.uint)
    functionOrdinalArray: ptr UncheckedArray[WORD] = cast[ptr UncheckedArray[WORD]](cast[uint](pBase) + pImgExportDir.AddressOfNameOrdinals.uint)

  var i: DWORD = 0
  while i < pImgExportDir.NumberOfFunctions:
    var 
      pFunctionName: PCHAR = (cast[PCHAR](cast[uint](pBase) + functionNameArray[i].uint))
      pFunctionAddress: PVOID = cast[PVOID](cast[uint](pBase) + functionAddressArray[functionOrdinalArray[i]].uint)
    if memcmp(cast[uint](pFunctionName), cast[uint](lpApiName), lpApiname.len, 1) == 0:
      return cast[FARPROC](pFunctionAddress)
    i.inc
  return cast[FARPROC](NULL)

proc getProcAddressHash*(hModule: HMODULE, apiNameHash: uint32): FARPROC {.inline, noSideEffect.} =
  var 
    pBase = hModule
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
    pImgNtHdr = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)
  # assume this always works -- adds extra bytes
  # if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) or (pImgNtHdr.Signature != IMAGE_NT_SIGNATURE):
    # return cast[FARPROC](0)
  var
    imgOptHdr = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdr.OptionalHeader)
    pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pBase) + imgOptHdr.DataDirectory[0].VirtualAddress)
    funcNameArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfNames)
    funcAddressArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfFunctions)
    funcOrdinalArray = cast[ptr UncheckedArray[WORD]](cast[int](pBase) + pImgExportDir.AddressOfNameOrdinals)
  
  for i in 0 ..< pImgExportDir.NumberOfFunctions:
    var pFunctionName = cast[cstring](cast[PCHAR](cast[int](pBase) + funcNameArray[i]))
    if apiNameHash == hashStringDjb2A(pFunctionName):
      return cast[FARPROC](cast[int](pBase) + funcAddressArray[funcOrdinalArray[i]])
  return cast[FARPROC](0)