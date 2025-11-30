use libc::c_char;
use serde::Serialize;
use std::ffi::CString;

/// Small, stable FFI for plugins.
///
/// Plugins should export `decode_packet` with C ABI:
/// `extern "C" fn decode_packet(data: *const u8, len: usize) -> *mut c_char`
/// returning a *malloc'd* C string with JSON result, or null on failure.
///
/// This file provides a safe helper to build that string.
pub fn json_to_c_ptr<T: Serialize>(v: &T) -> *mut c_char {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    let c = CString::new(s).unwrap();
    c.into_raw()
}

/// Helper to free pointer returned by plugin
#[unsafe(no_mangle)]
pub extern "C" fn deeptrace_free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { let _ = CString::from_raw(s); } // dropped
}
