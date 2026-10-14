// x86_64 injection shellcode, assembled by build.rs into a byte array.
//
// It runs in the target process on a bare Mach thread. It spawns a real
// pthread (dlopen and friends need `pthread_self`), has that pthread call
// dlopen on our library, and leaves the Mach thread spinning. `mac.rs`
// patches the 8-byte ASCII markers below before injecting:
//   PTHRDCRT -> &pthread_create_from_mach_thread
//   DLOPEN__ -> &dlopen
//   LIBLIBLIB... -> the library path (NUL-terminated; marks where it starts)
// Here PTHRDCRT and DLOPEN__ are the immediates of `movabs rax, <marker>`, so
// they land inline in the code.
//
// build.rs assembles this and copies out the __text section verbatim, so the
// internal labels are `L`-prefixed: a non-local symbol would leave its
// rip-relative displacement as a 0 placeholder for the linker instead of the
// resolved offset. `tests::shellcode_matches_reference` guards the output.

.intel_syntax noprefix
.text
_start:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x10
    lea  rdi, [rbp-8]
    xor  eax, eax
    mov  ecx, eax
    lea  rdx, [rip+Lthread]
    mov  rsi, rcx
    movabs rax, 0x5452434452485450   # PTHRDCRT
    call rax
    mov  [rbp-0xc], eax
    add  rsp, 0x10
    pop  rbp
    mov  rax, 0xd13
Lspin:
    jmp  Lspin
    ret
Lthread:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x10
    mov  esi, 1
    mov  [rbp-8], rdi
    lea  rdi, [rip+Llibpath]
    movabs rax, 0x5F5F4E45504F4C44   # DLOPEN__
    call rax
    xor  esi, esi
    mov  edi, esi
    mov  [rbp-0x10], rax
    mov  rax, rdi
    add  rsp, 0x10
    pop  rbp
    ret
Llibpath:
    .ascii "LIBLIBLIBLIB"
