BITS 64
global _start

_start:
    mov rax,0x1
    mov rdi,0x1
    mov rsi,0x0a6f6c6c6568
    push rsi
    push rsp
    pop rsi
    mov rdx,0x7
    syscall

    mov al,0x3c
    syscall