from winim/lean import UNICODE_STRING, UCHAR, LPTR, LocalAlloc, SIZE_T


# creates a new cstring from a UNICODE_STRING structure
template ustringToAscii*(ustring: UNICODE_STRING): cstring =
    ## Convert a UNICODE_STRING structure to a nim native ascii string
    block:  # Wrap in a block to create proper scope and return
        var buffer: array[256, char]
        var str = cast[cstring](addr buffer[0])
        var arrayWChar = cast[ptr UncheckedArray[UCHAR]](ustring.Buffer)
        var e = 0
        var last: char = 'a'
        for i in 0.uint32..<ustring.Length:
            if arrayWChar[i] == 0:
                if last == '\0':
                    break
                continue
            last = cast[char](arrayWChar[i])
            str[e] = last
            e.inc
        str[e] = '\0'
        str  # Last expression becomes the result

# inplace lowercases a cstring
template cstringToLower*(s: cstring): cstring =
    var buffer {.noinit.}: array[256, char] # The {.noinit.} pragma tells the compiler not to initialize the array (which is fine in this case since we're writing to every position we'll use), and more importantly, it prevents the buffer from being deallocated when the template scope ends.
    # std_debug_print("s: ", s)
    for i in 0..buffer.len-1:
        if i >= s.len:
            buffer[i] = cast[char](0)
        else:
            if s[i] >= 'A' and s[i] <= 'Z':
                buffer[i] = cast[char](cast[uint8](s[i]) xor 0x20)
            else:
                buffer[i] = s[i]
    var str = cast[cstring](addr buffer[0])
    str

proc cstringToLowerStatic*(s: cstring): cstring {.compiletime.} =
    var buffer: array[256, char]  # Using fixed size array on stack
    result = cast[cstring](addr buffer[0])
    for i in 0..s.len-1:
        if s[i] >= 'A' and s[i] <= 'Z':
            result[i] = cast[char](cast[uint8](s[i]) xor 0x20)
        else:
            result[i] = s[i]
    return result

template cstringToLower*(s: ptr UncheckedArray[byte]): cstring =
    return cstringToLower(cast[ptr cstring](s))


proc intToStr*(value: uint32): array[11, char] {.inline.} =
    var
        num = value
        buffer: array[11, char]  # Max length for uint32 (10 digits) plus null terminator
        i = 9  # Start from end of buffer (leaving room for null terminator)
    
    if num == 0:
        buffer[0] = '0'
        buffer[1] = '\0'
        return buffer

    buffer[10] = '\0'  # Null terminator
    while num > 0:
        buffer[i] = char((num mod 10) + ord('0'))
        num = num div 10
        dec(i)

    # Move everything to the start of the buffer
    var j = 0
    inc(i)
    while i <= 10:
        buffer[j] = buffer[i]
        inc(j)
        inc(i)
    
    while j <= 10:
        buffer[j] = '\0'
        inc(j)

    return buffer

proc dwordToCstring*(value: uint32): array[11, char] {.inline.} =
    var
        num = value
        buffer: array[11, char]  # Max length for uint32 (10 digits) plus null terminator
        i = 9  # Start from end of buffer (leaving room for null terminator)
    
    if num == 0:
        buffer[0] = '0'
        buffer[1] = '\0'
        return buffer

    buffer[10] = '\0'  # Null terminator
    while num > 0:
        buffer[i] = char((num mod 10) + ord('0'))
        num = num div 10
        dec(i)

    # Move everything to the start of the buffer
    var j = 0
    inc(i)
    while i <= 10:
        buffer[j] = buffer[i]
        inc(j)
        inc(i)
    
    while j <= 10:
        buffer[j] = '\0'
        inc(j)

    return buffer
