// arm64 injection shellcode, assembled by build.rs into a byte array.
//
// It runs in the target process on a bare Mach thread. It promotes the Mach
// thread to a real pthread (dlopen and friends need `pthread_self`), has it
// call dlopen on our library, and then exits instead of spinning:
//   - on success pthread_create_from_mach_thread does not return; the new
//     pthread simply returns from its start routine after dlopen, which
//     pthreads treats as pthread_exit
//   - on failure the bare Mach thread kills itself with thread_terminate
//   - _loop is a last resort for thread_terminate failing; unreachable in
//     practice, so injection leaves no thread burning CPU
// mac.rs patches the 8-byte ASCII markers below before injecting:
//   PTHRDCRT -> &pthread_create_from_mach_thread
//   DLOPEN__ -> &dlopen
//   MTHRSELF -> &mach_thread_self
//   THRTERM_ -> &thread_terminate
//   LIBLIBLIB... -> the library path (NUL-terminated; marks where it starts)
// The markers are loaded with `adr`+`ldr`, so they are plain data slots here.
//
// build.rs assembles this and copies out the __text section verbatim, so
// every label reference must resolve within the section (no relocations into
// the final bytes).

.text
.p2align 2
_start:
    sub   sp, sp, #16
    mov   x0, sp              // &pthread_t out-param
    mov   x1, xzr             // attr = NULL
    mov   x3, xzr             // arg = NULL
    adr   x2, _thread         // start routine
    adr   x4, pthrdcrt
    ldr   x5, [x4]
    blr   x5                  // pthread_create_from_mach_thread: noreturn on success
    // Promotion failed — terminate this bare Mach thread rather than spin.
    adr   x7, mthrself
    ldr   x8, [x7]
    blr   x8                  // x0 = mach_thread_self()
    adr   x7, thrterm
    ldr   x8, [x7]
    blr   x8                  // thread_terminate(x0): noreturn on success
_loop:                        // unreachable unless thread_terminate fails
    adr   x7, _loop
    br    x7
pthrdcrt: .ascii "PTHRDCRT"
dlopenp:  .ascii "DLOPEN__"
mthrself: .ascii "MTHRSELF"
thrterm:  .ascii "THRTERM_"
_thread:
    stp   fp, lr, [sp, #-16]!
    mov   fp, sp
    mov   x1, #1              // RTLD_LAZY
    adr   x0, libpath
    adr   x7, dlopenp
    ldr   x8, [x7]
    blr   x8                  // dlopen(libpath, RTLD_LAZY)
    ldp   fp, lr, [sp], #16
    ret                       // returning from a start routine = pthread_exit
libpath:
    .rept 28
    .ascii "LIB"
    .endr
