use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject,
};
use windows::core::s;

/// How long to wait for the remote `LoadLibraryA` call to finish.
const LOAD_TIMEOUT_MS: u32 = 5000;

/// Closes the wrapped handle on drop, so every early return cleans up.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub fn inject(pid: u32, dll: &Path) -> bool {
    unsafe { inject_inner(pid, dll).is_some() }
}

unsafe fn inject_inner(pid: u32, dll: &Path) -> Option<()> {
    let path_bytes = dll.to_str()?.as_bytes();
    let mut path_cstr = Vec::with_capacity(path_bytes.len() + 1);
    path_cstr.extend_from_slice(path_bytes);
    path_cstr.push(0);
    let len = path_cstr.len();

    let process = OwnedHandle(unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid).ok()? });
    let remote_buf =
        unsafe { VirtualAllocEx(process.0, None, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if remote_buf.is_null() {
        return None;
    }
    let free_remote = || unsafe {
        let _ = VirtualFreeEx(process.0, remote_buf, 0, MEM_RELEASE);
    };

    let mut written = 0;
    let wrote = unsafe {
        WriteProcessMemory(process.0, remote_buf, path_cstr.as_ptr() as _, len, Some(&mut written))
    };
    if wrote.is_err() || written != len {
        free_remote();
        return None;
    }

    let Some(load_library) = (unsafe {
        GetModuleHandleA(s!("kernel32.dll"))
            .ok()
            .and_then(|kernel32| GetProcAddress(kernel32, s!("LoadLibraryA")))
    }) else {
        free_remote();
        return None;
    };

    let thread = match unsafe {
        CreateRemoteThread(
            process.0,
            None,
            0,
            Some(std::mem::transmute(load_library)),
            Some(remote_buf),
            0,
            None,
        )
    } {
        Ok(thread) => OwnedHandle(thread),
        Err(_) => {
            free_remote();
            return None;
        }
    };

    // Only free the path buffer once LoadLibraryA has returned; if it is
    // still running, leaking a few bytes beats it reading freed memory.
    if unsafe { WaitForSingleObject(thread.0, LOAD_TIMEOUT_MS) } != WAIT_OBJECT_0 {
        return None;
    }
    free_remote();
    Some(())
}
