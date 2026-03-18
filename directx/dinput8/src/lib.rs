//! dinput8.dll — DirectInput 8.
//!
//! Games use this for keyboard, mouse, and gamepad input.
//! Phase 3: wire to HID driver.

#![no_std]

pub type HResult = i32;
pub const S_OK:      HResult = 0;
pub const E_NOTIMPL: HResult = 0x8000_4001u32 as i32;

/// DirectInput8Create — factory function.
#[no_mangle]
pub unsafe extern "C" fn DirectInput8Create(
    _hinst:       *mut u8,
    _dw_version:  u32,
    _riid:        *const [u8; 16],
    pp_out:       *mut *mut u8,
    _p_unk_outer: *mut u8,
) -> HResult {
    log::info!("DirectInput8Create: stub");
    if !pp_out.is_null() {
        unsafe { *pp_out = core::ptr::null_mut(); }
    }
    // TODO Phase 3: return IDirectInput8 COM object backed by HID driver.
    S_OK
}
