#include <cpuminer-config.h>

#if defined(__linux__) && defined(__ELF__)
    .section .note.GNU-stack,"",%progbits
#endif

    .text
    .p2align 6
    .globl fast_aesb_single_round
    .globl _fast_aesb_single_round
fast_aesb_single_round:
_fast_aesb_single_round:
#if defined(_WIN64) || defined(__CYGWIN__)
    movdqa (%rcx), %xmm1
    aesenc (%r8), %xmm1
    movdqa %xmm1, (%rdx)
#else
    movdqa (%rdi), %xmm1
    aesenc (%rdx), %xmm1
    movdqa %xmm1, (%rsi)
#endif
    ret

    .text
    .p2align 6
    .globl fast_aesb_pseudo_round_mut
    .globl _fast_aesb_pseudo_round_mut
fast_aesb_pseudo_round_mut:
_fast_aesb_pseudo_round_mut:
#if defined(_WIN64) || defined(__CYGWIN__)
    mov %rdx, %r9
    add $0xA0, %r9
    movdqa (%rcx), %xmm1
 
    .LOOP:
            aesenc (%rdx), %xmm1
            add $0x10, %rdx
			cmp %r9, %rdx
            jl .LOOP

    movdqa %xmm1, (%rcx)
#else
    mov %rsi, %r9
    add $0xA0, %r9
    movdqa (%rdi), %xmm1
 
    .LOOP:
            aesenc (%rsi), %xmm1
            add $0x10, %rsi
            cmp %r9, %rsi
            jl .LOOP

    movdqa %xmm1, (%rdi)
#endif
    ret

    .text
    .globl mul128
    .globl _mul128
mul128:
_mul128:
#if defined(_WIN64) || defined(__CYGWIN__)
	mov %rcx, %rax
	mul %rdx
	mov %rdx, (%r8)
#else
	mov %rdx, %r8
	mov %rdi, %rax
	mul %rsi
	mov %rdx, (%r8)
#endif
	ret
