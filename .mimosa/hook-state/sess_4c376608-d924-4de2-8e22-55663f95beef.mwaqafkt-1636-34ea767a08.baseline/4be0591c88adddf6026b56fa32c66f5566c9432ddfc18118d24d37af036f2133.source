//! The mouse: what a mouse driver gives win32k (MOUSE_INPUT_DATA,
//! `ntddmou.h`).

use core::mem::{offset_of, size_of};

/// MOUSE_INPUT_DATA `Flags`: a move relative to the last one.
pub const MOUSE_MOVE_RELATIVE: u16 = 0;
/// The move is to an absolute position (0..0xFFFF on each axis).
pub const MOUSE_MOVE_ABSOLUTE: u16 = 1;

/// MOUSE_INPUT_DATA `ButtonFlags`: a button going down or up, the wheel.
pub const MOUSE_LEFT_BUTTON_DOWN: u16 = 0x0001;
pub const MOUSE_LEFT_BUTTON_UP: u16 = 0x0002;
pub const MOUSE_RIGHT_BUTTON_DOWN: u16 = 0x0004;
pub const MOUSE_RIGHT_BUTTON_UP: u16 = 0x0008;
pub const MOUSE_MIDDLE_BUTTON_DOWN: u16 = 0x0010;
pub const MOUSE_MIDDLE_BUTTON_UP: u16 = 0x0020;
/// The wheel turned: `ButtonData` is the signed amount, in WHEEL_DELTA units
/// (120 a notch, positive away from the user).
pub const MOUSE_WHEEL: u16 = 0x0400;
/// One notch of the wheel.
pub const WHEEL_DELTA: i16 = 120;

/// MOUSE_INPUT_DATA: a move, buttons, the wheel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MouseInputData {
    pub unit_id: u16,
    /// MOUSE_MOVE_RELATIVE or MOUSE_MOVE_ABSOLUTE.
    pub flags: u16,
    /// MOUSE_*_BUTTON_DOWN/UP, MOUSE_WHEEL.
    pub button_flags: u16,
    /// With MOUSE_WHEEL: the signed amount.
    pub button_data: u16,
    pub raw_buttons: u32,
    /// The move, right positive.
    pub last_x: i32,
    /// The move, down positive (screen coordinates).
    pub last_y: i32,
    pub extra_information: u32,
}

const _: () = {
    assert!(size_of::<MouseInputData>() == 24);
    assert!(offset_of!(MouseInputData, flags) == 2);
    assert!(offset_of!(MouseInputData, button_flags) == 4);
    assert!(offset_of!(MouseInputData, button_data) == 6);
    assert!(offset_of!(MouseInputData, raw_buttons) == 8);
    assert!(offset_of!(MouseInputData, last_x) == 12);
    assert!(offset_of!(MouseInputData, last_y) == 16);
    assert!(offset_of!(MouseInputData, extra_information) == 20);
};
