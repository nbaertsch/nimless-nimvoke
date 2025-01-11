from winim/lean import PVOID, PPEB
import ./nimjaStructs

when defined amd64:
    {.passC:"-masm=intel".}
    proc GetPEB*(pPeb: ptr NimjaPeb) {.inline, asmNoStackFrame.} =
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov rbx, qword ptr gs:[rdi+0x40]
            mov rax, rbx
            pop rbx
            :"=r"(`pPeb`)
        """
    template GetPEB*(pPeb: PPEB) =
        ## Uses inline assembly to get a pointer to the PEB
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov rbx, qword ptr gs:[rdi+0x40]
            mov rax, rbx
            pop rbx
            :"=r"(`pPeb`)
        """

when defined i386:
    {.passC:"-masm=intel".}
    proc GetPEB*(pPeb: ptr NimjaPeb) {.inline, asmNoStackFrame.} =
        ## Uses inline assembly to get a pointer to the PEB
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov eax, fs:[rdi+0x10]
            pop rbx
            :"=r"(`pPeb`)
        """
    template GetPEB*(pPeb: PPEB) =
        ## Uses inline assembly to get a pointer to the PEB
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov eax, fs:[rdi+0x10]
            pop rbx
            :"=r"(`pPeb`)
        """