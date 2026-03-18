//! winmm.dll — Windows Multimedia API.
//!
//! Critical for games: timeBeginPeriod / timeGetTime.
//! Almost every XP game calls timeBeginPeriod(1) to get 1 ms timer resolution.

#![no_std]

pub const TIMERR_NOERROR: u32 = 0;
pub const TIMERR_NOCANDO: u32 = 97;

/// timeBeginPeriod — request minimum timer resolution in milliseconds.
/// Must return TIMERR_NOERROR and actually achieve ~1 ms resolution.
#[no_mangle]
pub extern "C" fn timeBeginPeriod(u_period: u32) -> u32 {
    hal::timer::set_resolution(u_period * 10_000);
    TIMERR_NOERROR
}

#[no_mangle]
pub extern "C" fn timeEndPeriod(_u_period: u32) -> u32 { TIMERR_NOERROR }

/// timeGetTime — milliseconds since system boot (same as GetTickCount but
/// games prefer this one from winmm for audio synchronisation).
#[no_mangle]
pub extern "C" fn timeGetTime() -> u32 {
    // TODO: read HAL tick counter.
    0
}
