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
    ret

    .text
    .p2align 6
    .globl fast_aesb_pseudo_round_mut
    .globl _fast_aesb_pseudo_round_mut
fast_aesb_pseudo_round_mut:
_fast_aesb_pseudo_round_mut:
    ret
