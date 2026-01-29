; Secure memory wipe using x86_64 assembly
; Prevents compiler optimizations from removing the wipe

section .text
global crypto_wipe

; void crypto_wipe(void *ptr, size_t len)
; rdi = ptr, rsi = len
crypto_wipe:
    test    rsi, rsi          ; Check if len == 0
    jz      .done
    
    mov     rcx, rsi          ; Copy length to rcx
    xor     rax, rax          ; Zero rax
    
    ; Align to 8-byte boundary
    mov     rdx, rdi
    and     rdx, 7
    jz      .aligned
    
    mov     r8, 8
    sub     r8, rdx
    cmp     r8, rcx
    cmova   r8, rcx
    
.unaligned_loop:
    mov     byte [rdi], al
    inc     rdi
    dec     rcx
    dec     r8
    jnz     .unaligned_loop
    
.aligned:
    ; Clear 64 bytes at a time using AVX2
    cmp     rcx, 64
    jb      .small
    
    vzeroall                  ; Clear all YMM registers
    
.avx_loop:
    vmovdqa [rdi], ymm0
    vmovdqa [rdi+32], ymm0
    add     rdi, 64
    sub     rcx, 64
    cmp     rcx, 64
    jae     .avx_loop
    
.small:
    ; Clear 8 bytes at a time
    cmp     rcx, 8
    jb      .bytes
    
.qword_loop:
    mov     qword [rdi], rax
    add     rdi, 8
    sub     rcx, 8
    cmp     rcx, 8
    jae     .qword_loop
    
.bytes:
    ; Clear remaining bytes
    test    rcx, rcx
    jz      .done
    
.byte_loop:
    mov     byte [rdi], al
    inc     rdi
    dec     rcx
    jnz     .byte_loop
    
.done:
    mfence                    ; Memory fence to ensure completion
    ret
