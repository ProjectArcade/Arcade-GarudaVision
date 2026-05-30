use std::ffi::CStr;
use std::os::raw::c_char;

// Garuda Vision FFI — C bindings for Gecko integration

#[no_mangle]
pub extern "C" fn garuda_check_url(url: *const c_char) -> u8 {
    if url.is_null() {
        return 255;
    }

    let url = unsafe { CStr::from_ptr(url) };
    let url = match url.to_str() {
        Ok(url) => url,
        Err(_) => return 255,
    };

    let (score, _) = garuda_core::flag_a::analyse(url);
    score
}

#[no_mangle]
pub extern "C" fn garuda_check_page(url: *const c_char, html: *const c_char) -> u8 {
    if url.is_null() || html.is_null() {
        return 255;
    }

    let url_cstr = unsafe { CStr::from_ptr(url) };
    let url_str = match url_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 255,
    };

    let html_cstr = unsafe { CStr::from_ptr(html) };
    let html_str = match html_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 255,
    };

    let parts = garuda_core::url::parse_url(url_str);

    let (score_a, _) = garuda_core::flag_a::analyse(url_str);
    let (score_b, _) = garuda_core::flag_b::analyse(html_str, &parts.host);

    let combined = score_a.saturating_add(score_b);
    combined.min(100)
}
