// arm64 injection shellcode, assembled by build.rs into a byte array.
//
// It runs in the target process on a bare Mach thread. It spawns a real
// pthread (dlopen and friends need `pthread_self`), has that pthread call
// dlopen on our library, and leaves both threads spinning. `mac.rs` patches
// the 8-byte ASCII markers below before injecting:
//   PTHRDCRT -> &pthread_create_from_mach_thread
//   DLOPEN__ -> &dlopen
//   PTHRDEXT -> &pthread_exit (currently unused)
//   LIBLIBLIB... -> the library path (NUL-terminated; marks where it starts)
// The markers are loaded with `adr`+`ldr`, so they are plain data slots here.
//
// build.rs assembles this and copies out the __text section verbatim, so
// every label reference must resolve within the section (no relocations into
// the final bytes). `tests::shellcode_matches_reference` guards the output.

.text
.p2align 2
_start:
    mov   x0, sp
    sub   x0, x0, #16
    mov   x1, xzr
    mov   x3, xzr
    adr   x4, pthrdcrt
    adr   x2, _thread
    ldr   x5, [x4]
    blr   x5
_loop:
    adr   x7, _loop
    br    x7
pthrdcrt: .ascii "PTHRDCRT"
dlopenp:  .ascii "DLOPEN__"
pthrdext: .ascii "PTHRDEXT"
_thread:
    mov   x1, #1
    adr   x0, libpath
    adr   x7, dlopenp
    ldr   x8, [x7]
    blr   x8
    adr   x7, _loop
    br    x7
libpath:
    .rept 28
    .ascii "LIB"
    .endr
