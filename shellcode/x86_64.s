// x86_64 injection shellcode, assembled by build.rs into a byte array.
//
// It runs in the target process on a bare Mach thread. It promotes the Mach
// thread to a real pthread (dlopen and friends need `pthread_self`), has it
// call dlopen on our library, and then exits instead of spinning:
//   - on success pthread_create_from_mach_thread does not return; the new
//     pthread simply returns from its start routine after dlopen, which
//     pthreads treats as pthread_exit
//   - on failure the bare Mach thread kills itself with thread_terminate
//   - Lspin is a last resort for thread_terminate failing; unreachable in
//     practice, so injection leaves no thread burning CPU
// mac.rs patches the 8-byte ASCII markers below before injecting:
//   PTHRDCRT -> &pthread_create_from_mach_thread
//   DLOPEN__ -> &dlopen
//   MTHRSELF -> &mach_thread_self
//   THRTERM_ -> &thread_terminate
//   LIBLIBLIB... -> the library path (NUL-terminated; marks where it starts)
// The markers are the immediates of `movabs rax, <marker>`, so they land
// inline in the code.
//
// Stack discipline: thread_create_running starts rsp exactly at the value we
// give it (16-byte aligned, no return address pushed), so at _start entry
// rsp ≡ 0 (mod 16). `push rbp` + `sub rsp, 0x18` brings it back to ≡ 0 at
// every `call`, as the ABI requires. Lthread is entered as a normal pthread
// start routine (rsp ≡ 8 mod 16), so its `push rbp` + `sub rsp, 0x10` is
// already correct.
//
// build.rs assembles this and copies out the __text section verbatim, so the
// internal labels are `L`-prefixed: a non-local symbol would leave its
// rip-relative displacement as a 0 placeholder for the linker instead of the
// resolved offset.

.intel_syntax noprefix
.text
_start:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x18
    lea  rdi, [rbp-8]
    xor  eax, eax
    mov  ecx, eax
    lea  rdx, [rip+Lthread]
    mov  rsi, rcx
    movabs rax, 0x5452434452485450   # PTHRDCRT
    call rax                         # pthread_create_from_mach_thread: noreturn on success
    # Promotion failed — terminate this bare Mach thread rather than spin.
    movabs rax, 0x464C45535248544D   # MTHRSELF
    call rax                         # rax = mach_thread_self()
    mov  edi, eax
    movabs rax, 0x5F4D524554524854   # THRTERM_
    call rax                         # thread_terminate(self): noreturn on success
Lspin:                               # unreachable unless thread_terminate fails
    jmp  Lspin
Lthread:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x10
    mov  esi, 1
    mov  [rbp-8], rdi
    lea  rdi, [rip+Llibpath]
    movabs rax, 0x5F5F4E45504F4C44   # DLOPEN__
    call rax                         # dlopen(libpath, RTLD_LAZY)
    xor  esi, esi
    mov  edi, esi
    mov  [rbp-0x10], rax
    mov  rax, rdi
    add  rsp, 0x10
    pop  rbp
    ret                              # returning from a start routine = pthread_exit
Llibpath:
    .ascii "LIBLIBLIBLIB"
