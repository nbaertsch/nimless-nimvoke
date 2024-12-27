from winim/lean import PVOID

when defined amd64:
    {.passC:"-masm=intel".}
    proc GetPEB*(): ptr PVOID {.asmNoStackFrame.} =
        ## Uses inline assembly to get a pointer to the PEB.
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov rbx, qword ptr gs:[rdi+0x40]
            mov rax, rbx
            pop rbx
            ret
        """

when defined i386:
    {.passC:"-masm=intel".}
    proc GetPEB*(): ptr PVOID {.asmNoStackFrame.} =
        ## Uses inline assembly to get a pointer to the PEB
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov eax, fs:[rdi+0x10]
            pop rbx
            ret
        """