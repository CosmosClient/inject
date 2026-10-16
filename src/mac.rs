//! macOS dylib injection via Mach VM APIs.
//!
//! Injects a dynamic library into a remote process by:
//! 1. Acquiring the target's Mach task port via `task_for_pid`
//! 2. Allocating remote memory for a stack and shellcode
//! 3. Patching the shellcode with runtime function addresses and the library path
//! 4. Writing the patched shellcode into the remote process
//! 5. Spawning a remote Mach thread that executes the shellcode
//!
//! The shellcode promotes the injected Mach thread to a real pthread (since many
//! APIs like `dlopen` depend on `pthread_self()`), then calls `dlopen` to load the
//! target library — triggering its `#[ctor]` constructor. Both threads then exit
//! (the pthread by returning from its start routine, the Mach thread via
//! `thread_terminate` if promotion failed), so an injection leaves no thread
//! spinning in the target.
//!
//! Based on Jonathan Levin's inject.c from <http://newosxbook.com/src.jl?tree=listings&file=inject.c>,
//! updated for modern macOS with the Mach-thread-to-pthread promotion technique.

use std::ffi::CString;

use libc::pid_t;

// ---------------------------------------------------------------------------
// Mach / VM type aliases (matching the C Mach headers)
// ---------------------------------------------------------------------------
type MachPort = u32;
type KernReturn = i32;
type MachVmAddress = u64;
type MachVmSize = u64;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const KERN_SUCCESS: i32 = 0;
const STACK_SIZE: MachVmSize = 65536;
const VM_FLAGS_ANYWHERE: i32 = 1;
const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_PROT_EXECUTE: i32 = 4;

// ARM64 thread state constants (from mach/arm/thread_status.h)
#[cfg(target_arch = "aarch64")]
const ARM_THREAD_STATE64: i32 = 6;
#[cfg(target_arch = "aarch64")]
const ARM_THREAD_STATE64_COUNT: u32 = 68; // sizeof(arm_thread_state64_t) / sizeof(uint32_t)

// x86_64 thread state constants
#[cfg(target_arch = "x86_64")]
const X86_THREAD_STATE64: i32 = 4;
#[cfg(target_arch = "x86_64")]
const X86_THREAD_STATE64_COUNT: u32 = 42;

// ---------------------------------------------------------------------------
// Shellcode
// ---------------------------------------------------------------------------
// Assembled from `shellcode/<arch>.s` by build.rs (see there and the .s files
// for the markers it patches and the control flow). `SHELLCODE` is the array
// for the target architecture.
include!(concat!(env!("OUT_DIR"), "/shellcode.rs"));

// ---------------------------------------------------------------------------
// Mach port lifecycle
// ---------------------------------------------------------------------------

/// Give back a send right we hold in our own task. Best-effort: a failure
/// here means the port was already gone, which is fine.
unsafe fn release_port(port: MachPort) {
    unsafe { mach_port_deallocate(mach_task_self(), port) };
}

// ---------------------------------------------------------------------------
// ARM64 thread state structures (repr(C) to match kernel layout)
// ---------------------------------------------------------------------------
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ArmThreadState64 {
    x: [u64; 29], // General purpose registers x0–x28
    fp: u64,       // Frame pointer (x29)
    lr: u64,       // Link register (x30)
    sp: u64,       // Stack pointer
    pc: u64,       // Program counter
    cpsr: u32,     // Current program status register
    flags: u32,    // Padding / flags
}

// ---------------------------------------------------------------------------
// x86_64 thread state structure (repr(C) to match kernel layout)
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct X86ThreadState64 {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rdi: u64, rsi: u64, rbp: u64, rsp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
    rip: u64,
    rflags: u64,
    cs: u64, fs: u64, gs: u64,
}

// ---------------------------------------------------------------------------
// Mach kernel FFI declarations
// ---------------------------------------------------------------------------
unsafe extern "C" {
    fn mach_task_self() -> MachPort;

    /// Acquire the Mach task port for a process. Requires root or the
    /// `task_for_pid-allow` entitlement.
    fn task_for_pid(target: MachPort, pid: pid_t, task: *mut MachPort) -> KernReturn;

    /// Allocate virtual memory in a remote task's address space.
    fn mach_vm_allocate(
        target: MachPort,
        address: *mut MachVmAddress,
        size: MachVmSize,
        flags: i32,
    ) -> KernReturn;

    /// Write data into a remote task's address space.
    fn mach_vm_write(
        target: MachPort,
        address: MachVmAddress,
        data: u64, // vm_offset_t — pointer cast to u64
        count: u32,
    ) -> KernReturn;

    /// Set memory protection flags on a region in a remote task.
    fn vm_protect(
        target: MachPort,
        address: MachVmAddress,
        size: MachVmSize,
        set_maximum: i32, // boolean: set max protection (TRUE) or current (FALSE)
        new_protection: i32,
    ) -> KernReturn;

    /// Deallocate a send right in a task's IPC space.
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;

    /// Create a thread in a remote task and immediately start it running
    /// with the given register state.
    fn thread_create_running(
        task: MachPort,
        flavor: i32,
        new_state: *const u8, // raw pointer to the thread state struct
        new_state_count: u32, // number of u32s in the state
        thread: *mut MachPort,
    ) -> KernReturn;
}

// RTLD_DEFAULT for dlsym — search all loaded images
const RTLD_DEFAULT: *mut std::ffi::c_void = std::ptr::null_mut::<std::ffi::c_void>().wrapping_sub(2);

// ---------------------------------------------------------------------------
// Shellcode patching
// ---------------------------------------------------------------------------

/// Build a patched shellcode buffer with real function addresses and the library path.
///
/// Takes the static shellcode template, replaces placeholder markers with runtime
/// addresses, and appends enough space for the full library path (null-terminated).
/// Returns `None` if any required symbol could not be resolved — patching a null
/// address in would crash the remote thread.
///
/// This works because the injector and target process share the same dyld
/// shared cache, so function addresses resolved in our process are valid in
/// the remote process too.
fn build_patched_shellcode(lib_path: &str) -> Option<Vec<u8>> {
    // Find where the "LIBLIBLIB" placeholder starts in the template.
    // Everything before it is executable code + function pointer slots.
    let lib_placeholder_offset = SHELLCODE
        .windows(9)
        .position(|w| w == b"LIBLIBLIB")
        .expect("shellcode template missing LIBLIBLIB placeholder");

    // Build a buffer: [shellcode instructions] [lib path + NUL terminator]
    // The path region starts at lib_placeholder_offset.
    let path_bytes = lib_path.as_bytes();
    let total_size = lib_placeholder_offset + path_bytes.len() + 1; // +1 for NUL
    let mut code = vec![0u8; total_size];

    // Copy the instruction portion of the template (everything before the path placeholder)
    code[..lib_placeholder_offset].copy_from_slice(&SHELLCODE[..lib_placeholder_offset]);

    // Write the library path (already NUL-terminated since the buffer is zeroed)
    code[lib_placeholder_offset..lib_placeholder_offset + path_bytes.len()]
        .copy_from_slice(path_bytes);

    // Resolve function addresses from our own address space and patch them in.
    let resolve = |name: &str| -> Option<u64> {
        let c_name = CString::new(name).unwrap();
        let addr = unsafe { libc::dlsym(RTLD_DEFAULT, c_name.as_ptr()) };
        if addr.is_null() {
            eprintln!("dlsym({name}) returned null — cannot build shellcode");
            None
        } else {
            Some(addr as u64)
        }
    };
    let addr_pthread_create = resolve("pthread_create_from_mach_thread")?;
    let addr_thread_self = resolve("mach_thread_self")?;
    let addr_thread_terminate = resolve("thread_terminate")?;
    let addr_dlopen: u64 = libc::dlopen as *const () as u64;

    // Walk the code portion byte-by-byte looking for 8-byte placeholder markers
    for i in 0..lib_placeholder_offset.saturating_sub(7) {
        if &code[i..i + 8] == b"PTHRDCRT" {
            code[i..i + 8].copy_from_slice(&addr_pthread_create.to_ne_bytes());
        }
        if &code[i..i + 8] == b"DLOPEN__" {
            code[i..i + 8].copy_from_slice(&addr_dlopen.to_ne_bytes());
        }
        if &code[i..i + 8] == b"MTHRSELF" {
            code[i..i + 8].copy_from_slice(&addr_thread_self.to_ne_bytes());
        }
        if &code[i..i + 8] == b"THRTERM_" {
            code[i..i + 8].copy_from_slice(&addr_thread_terminate.to_ne_bytes());
        }
    }

    Some(code)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inject a dylib into the process with the given PID.
///
/// Returns `true` on success, `false` on failure. Errors are logged to stderr.
pub fn inject(pid: pid_t, lib_path: &str) -> bool {
    unsafe { inject_inner(pid, lib_path) }
}

unsafe fn inject_inner(pid: pid_t, lib_path: &str) -> bool {
    // -- Step 1: Get the Mach task port for the target process --
    // This is the critical gate — without it we can't touch the remote process.
    // Requires root privileges or the task_for_pid-allow entitlement.
    let mut remote_task: MachPort = 0;
    let kr = unsafe { task_for_pid(mach_task_self(), pid, &mut remote_task) };
    if kr != KERN_SUCCESS {
        eprintln!("task_for_pid failed for pid {pid} (kern_return: {kr})");
        return false;
    }

    // The task port is only needed while setting up; release it either way so
    // repeated injections don't accumulate send rights in our IPC space.
    let success = unsafe { inject_with_task(remote_task, lib_path) };
    unsafe { release_port(remote_task) };
    success
}

unsafe fn inject_with_task(remote_task: MachPort, lib_path: &str) -> bool {
    // -- Step 2: Prepare and patch the shellcode --
    // We do this first so we know the exact size to allocate in the remote process.
    let Some(code) = build_patched_shellcode(lib_path) else {
        return false;
    };
    let code_size = code.len() as MachVmSize;

    // -- Step 3: Allocate remote memory for the stack and shellcode --
    // We don't care where the memory lands — VM_FLAGS_ANYWHERE lets the kernel pick.
    let mut remote_stack: MachVmAddress = 0;
    let mut remote_code: MachVmAddress = 0;

    if unsafe { mach_vm_allocate(remote_task, &mut remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE) }
        != KERN_SUCCESS
    {
        eprintln!("Failed to allocate remote stack");
        return false;
    }

    if unsafe { mach_vm_allocate(remote_task, &mut remote_code, code_size, VM_FLAGS_ANYWHERE) }
        != KERN_SUCCESS
    {
        eprintln!("Failed to allocate remote code region");
        return false;
    }

    // -- Step 4: Write the patched shellcode into the remote process's memory --
    let kr = unsafe {
        mach_vm_write(
            remote_task,
            remote_code,
            code.as_ptr() as u64,
            code.len() as u32,
        )
    };
    if kr != KERN_SUCCESS {
        eprintln!("mach_vm_write failed (kern_return: {kr})");
        return false;
    }

    // -- Step 5: Set memory protections --
    // Code region: readable + executable (no write — W^X)
    let kr = unsafe {
        vm_protect(
            remote_task,
            remote_code,
            code_size,
            0, // set current protection, not maximum
            VM_PROT_READ | VM_PROT_EXECUTE,
        )
    };
    if kr != KERN_SUCCESS {
        eprintln!("vm_protect (code) failed (kern_return: {kr})");
        return false;
    }

    // Stack region: readable + writable
    let kr = unsafe {
        vm_protect(
            remote_task,
            remote_stack,
            STACK_SIZE,
            0, // set current protection, not maximum
            VM_PROT_READ | VM_PROT_WRITE,
        )
    };
    if kr != KERN_SUCCESS {
        eprintln!("vm_protect (stack) failed (kern_return: {kr})");
        return false;
    }

    // -- Step 6: Set up the initial thread state and launch the remote thread --
    // Point the program counter at our shellcode and the stack pointer at the
    // middle of our allocated stack (leaving headroom in both directions).
    let stack_middle = remote_stack + (STACK_SIZE / 2);

    unsafe {
        let mut thread: MachPort = 0;

        #[cfg(target_arch = "aarch64")]
        let kr = {
            let mut state = std::mem::zeroed::<ArmThreadState64>();
            state.pc = remote_code;
            state.sp = stack_middle;
            thread_create_running(
                remote_task,
                ARM_THREAD_STATE64,
                &state as *const _ as *const u8,
                ARM_THREAD_STATE64_COUNT,
                &mut thread,
            )
        };

        #[cfg(target_arch = "x86_64")]
        let kr = {
            let mut state = std::mem::zeroed::<X86ThreadState64>();
            state.rip = remote_code;
            state.rsp = stack_middle;
            state.rbp = stack_middle;
            thread_create_running(
                remote_task,
                X86_THREAD_STATE64,
                &state as *const _ as *const u8,
                X86_THREAD_STATE64_COUNT,
                &mut thread,
            )
        };

        if kr != KERN_SUCCESS {
            eprintln!("thread_create_running failed (kern_return: {kr})");
            false
        } else {
            // The thread keeps running on its own; we don't need its send right.
            release_port(thread);
            true
        }
    }
}
