import winim

proc hashStringDjb2A*(s: cstring): uint32 {.inline.} =
  var hash: uint32 = 0xff
  for i in s: hash = ((hash shl 5) + hash) + cast[uint32](i)
  return hash

proc hashStringDjb2W*(s: wstring): uint32  =
  var hash: uint32 = 0xff
  for i in s: hash = ((hash shl 5) + hash) + cast[uint32](i)
  return hash

proc hashStringDjb2AStatic*(s: cstring): uint32 {.compiletime.} =
  return hashStringDjb2A(s)

proc hashStringDjb2WStatic*(s: wstring): uint32 {.compiletime.} =
  return hashStringDjb2W(s)

proc hashStringDjb2A*(s: ptr UncheckedArray[byte]): uint32 =
    var
        hash: uint32 = 0xff
        i: uint32 = 0
    while s[][i] != 0:
        hash = ((hash shl 5) + hash) + cast[uint32](s[][i])
        i.inc
    return hash

proc hashStringDjb2AStatic*(s: ptr UncheckedArray[byte]): uint32 {.compiletime.} =
    return hashStringDjb2A(s)