use std::ffi::CStr;
use std::os::raw::c_char;

// Garuda Vision FFI — C bindings for Gecko integration

#[no_mangle]
pub extern "C" fn garuda_check_url(url: *const c_char) -> u8 {
    if url.is_null() {
        return 0;
    }

    let url = unsafe { CStr::from_ptr(url) };
    let url = match url.to_str() {
        Ok(url) => url,
        Err(_) => return 0,
    };

    let (score, _) = garuda_core::flag_a::analyse(url);
    score
}
