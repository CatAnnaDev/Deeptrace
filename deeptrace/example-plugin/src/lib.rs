use plugins_sdk::json_to_c_ptr;
use serde::Serialize;
use std::ffi::c_char;

/// Example plugin exposing `decode_packet` C ABI function.
#[derive(Serialize)]
struct Out<'a> {
    ok: bool,
    reason: &'a str,
}

#[unsafe(no_mangle)]
pub extern "C" fn decode_packet(data: *const u8, len: usize) -> *mut c_char {
    if data.is_null() || len == 0 {
        return std::ptr::null_mut();
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    if slice.len() > 0 && slice[0] == 0xAA {
        let o = Out { ok: true, reason: "starts_with_0xAA" };
        json_to_c_ptr(&o)
    } else {
        std::ptr::null_mut()
    }
}
