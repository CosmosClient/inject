//! Inject a dynamic library into a running process.
//!
//! [`inject`] loads a library into another process so its constructor runs
//! there. On macOS it takes the target's Mach task port and starts a remote
//! thread that `dlopen`s the library; on Windows it uses
//! `CreateRemoteThread(LoadLibraryA)`. macOS needs root (or the
//! `task_for_pid-allow` entitlement); Windows needs a handle with the right
//! access.

use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(target_os = "windows")]
pub mod win;

/// Why an injection attempt failed.
#[derive(Debug)]
pub enum InjectionError {
    /// The library path was not valid UTF-8.
    PathInvalid,
    /// No file exists at the library path.
    LibNotFound,
    /// The target process is not running.
    ProcessNotRunning,
    /// The injection itself failed (see stderr for the failing step).
    CouldNotInject,
    /// No injector is implemented for this OS.
    UnsupportedPlatform,
}

/// Loads the dynamic library at `lib` into the process with the given `pid`,
/// running its constructor there.
pub fn inject(pid: u32, lib: PathBuf) -> Result<(), InjectionError> {
    if !lib.exists() {
        return Err(InjectionError::LibNotFound);
    }
    let Some(lib_path) = lib.to_str() else {
        return Err(InjectionError::PathInvalid);
    };

    inject_impl(pid, lib_path, &lib)
}

#[cfg(target_os = "macos")]
fn inject_impl(pid: u32, lib_path: &str, _lib: &Path) -> Result<(), InjectionError> {
    if mac::inject(pid as i32, lib_path) {
        Ok(())
    } else {
        Err(InjectionError::CouldNotInject)
    }
}

#[cfg(target_os = "windows")]
fn inject_impl(pid: u32, _lib_path: &str, lib: &Path) -> Result<(), InjectionError> {
    if win::inject(pid, lib) {
        Ok(())
    } else {
        Err(InjectionError::CouldNotInject)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn inject_impl(_pid: u32, _lib_path: &str, _lib: &Path) -> Result<(), InjectionError> {
    Err(InjectionError::UnsupportedPlatform)
}
