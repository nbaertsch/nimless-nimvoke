
proc allignStack*() {.asmNoStackFrame, inline, nosideeffect.} = 
  asm """
    xor rax, rax
    pop rax
    and rsp, 0xfffffffffffffff0
    mov rbp, rsp
    sub rsp, 0x5000    # allocate stack space, arbitrary size ... depends on payload
    push rax
    ret
  """

proc cleanupStack*() {.asmNoStackFrame, inline, nosideeffect.} =
  # this doesnt work, shellcode still crashes
  asm """
      mov rsp, rbp      # Restore stack pointer
      pop rbp           # Restore frame pointer
      and rsp, -16      # Re-align stack to 16 bytes (optional)
      ret
  """