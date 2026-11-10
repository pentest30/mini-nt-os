//! dsound.dll — DirectSound 8.
//!
//! Games use DirectSound for all audio output.
//! Phase 2: COM skeleton returning S_OK so audio init doesn't abort.
//! Phase 3: route audio buffers to HDA driver via ALSA-style ring buffer.

#![no_std]
extern crate alloc;

pub type HResult = i32;
pub const S_OK:      HResult = 0;
pub const E_NOTIMPL: HResult = 0x8000_4001u32 as i32;

/// DirectSoundCreate8 — main factory.
#[no_mangle]
pub unsafe extern "C" fn DirectSoundCreate8(
    _lp_guid:     *const u8,
    ppDS:         *mut *mut u8,
    _p_unk_outer: *mut u8,
) -> HResult {
    log::info!("DirectSoundCreate8: stub");
    if !ppDS.is_null() {
        unsafe { *ppDS = core::ptr::null_mut(); }
    }
    // Return S_OK with null device — games should handle this gracefully.
    // TODO Phase 3: create real IDirectSound8 object.
    S_OK
}
