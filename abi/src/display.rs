//! The display settings, as the i386 clients of win32k see them (CLAUDE.md,
//! rule 5): `DEVMODEW` (EnumDisplaySettings, ChangeDisplaySettings) and
//! `DISPLAY_DEVICEW` (EnumDisplayDevices), with the SDK's flags and return
//! values. ReactOS's `wingdi.h` and `winuser.h` (the pinned version) serve as
//! the specification of the formats; offsets are checked at compile time.
//!
//! `user32` is built for NT 5.x: its `DEVMODEW` is 220 bytes (with the
//! panning fields), and NtUserEnumDisplaySettings takes only that size.

use core::mem::{offset_of, size_of};

/// CCHDEVICENAME: the characters of a device name (`dmDeviceName`,
/// `DeviceName`), its NUL included.
pub const CCHDEVICENAME: usize = 32;
/// CCHFORMNAME: the characters of `dmFormName`.
pub const CCHFORMNAME: usize = 32;
/// The characters of `DeviceString`, `DeviceID` and `DeviceKey`.
pub const CCHDEVICESTRING: usize = 128;

/// DM_SPECVERSION: the `dmSpecVersion` of NT 5.
pub const DM_SPECVERSION: u16 = 0x0401;

/// DM_*: the fields of a `DEVMODEW` that hold a value (`dmFields`).
pub mod dm {
    pub const POSITION: u32 = 0x0000_0020;
    pub const DISPLAYORIENTATION: u32 = 0x0000_0080;
    pub const BITSPERPEL: u32 = 0x0004_0000;
    pub const PELSWIDTH: u32 = 0x0008_0000;
    pub const PELSHEIGHT: u32 = 0x0010_0000;
    pub const DISPLAYFLAGS: u32 = 0x0020_0000;
    pub const DISPLAYFREQUENCY: u32 = 0x0040_0000;
    pub const PANNINGWIDTH: u32 = 0x0800_0000;
    pub const PANNINGHEIGHT: u32 = 0x1000_0000;
    pub const DISPLAYFIXEDOUTPUT: u32 = 0x2000_0000;
}

/// CDS_*: the flags of ChangeDisplaySettings.
pub mod cds {
    pub const UPDATEREGISTRY: u32 = 0x0000_0001;
    pub const TEST: u32 = 0x0000_0002;
    pub const FULLSCREEN: u32 = 0x0000_0004;
    pub const GLOBAL: u32 = 0x0000_0008;
    pub const SET_PRIMARY: u32 = 0x0000_0010;
    pub const VIDEOPARAMETERS: u32 = 0x0000_0020;
    pub const NORESET: u32 = 0x1000_0000;
    pub const RESET: u32 = 0x4000_0000;
}

/// DISP_CHANGE_*: what ChangeDisplaySettings returns (a LONG).
pub mod disp_change {
    pub const SUCCESSFUL: i32 = 0;
    pub const RESTART: i32 = 1;
    pub const FAILED: i32 = -1;
    pub const BADMODE: i32 = -2;
    pub const NOTUPDATED: i32 = -3;
    pub const BADFLAGS: i32 = -4;
    pub const BADPARAM: i32 = -5;
}

/// ENUM_CURRENT_SETTINGS: the `iModeNum` of the mode in use.
pub const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
/// ENUM_REGISTRY_SETTINGS: the `iModeNum` of the mode the registry keeps.
pub const ENUM_REGISTRY_SETTINGS: u32 = 0xFFFF_FFFE;

/// DISPLAY_DEVICE_*: `DISPLAY_DEVICEW.StateFlags`.
pub mod display_device {
    /// An adapter that is part of the desktop.
    pub const ATTACHED_TO_DESKTOP: u32 = 0x0000_0001;
    /// The primary adapter.
    pub const PRIMARY_DEVICE: u32 = 0x0000_0004;
    /// An adapter compatible with VGA.
    pub const VGA_COMPATIBLE: u32 = 0x0000_0010;
    /// A monitor that is on.
    pub const ACTIVE: u32 = 0x0000_0001;
    /// A monitor attached to its adapter.
    pub const ATTACHED: u32 = 0x0000_0002;
}

/// WM_DISPLAYCHANGE: the mode changed; `wParam` its bits per pixel,
/// `lParam` MAKELONG(width, height). Sent to the top-level windows.
pub const WM_DISPLAYCHANGE: u32 = 0x007E;

/// DEVMODEW, 220 bytes (NT 5): the display fields only are named; the
/// printer's (`dmOrientation`… in the union, `dmColor`…) stay bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevModeW {
    pub device_name: [u16; CCHDEVICENAME],
    pub spec_version: u16,
    pub driver_version: u16,
    pub size: u16,
    pub driver_extra: u16,
    pub fields: u32,
    /// `dmPosition` (POINTL) for a display.
    pub position_x: i32,
    pub position_y: i32,
    pub display_orientation: u32,
    pub display_fixed_output: u32,
    /// `dmColor`, `dmDuplex`, `dmYResolution`, `dmTTOption`, `dmCollate`.
    pub printer: [u16; 5],
    pub form_name: [u16; CCHFORMNAME],
    pub log_pixels: u16,
    pub bits_per_pel: u32,
    pub pels_width: u32,
    pub pels_height: u32,
    pub display_flags: u32,
    pub display_frequency: u32,
    pub icm_method: u32,
    pub icm_intent: u32,
    pub media_type: u32,
    pub dither_type: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub panning_width: u32,
    pub panning_height: u32,
}

/// The size of a `DEVMODEW` of NT 4 (without the panning fields), the
/// smallest win32k reads all the display fields from.
pub const DEVMODEW_SIZE_400: usize = 212;

impl Default for DevModeW {
    fn default() -> Self {
        Self {
            device_name: [0; CCHDEVICENAME],
            spec_version: 0,
            driver_version: 0,
            size: 0,
            driver_extra: 0,
            fields: 0,
            position_x: 0,
            position_y: 0,
            display_orientation: 0,
            display_fixed_output: 0,
            printer: [0; 5],
            form_name: [0; CCHFORMNAME],
            log_pixels: 0,
            bits_per_pel: 0,
            pels_width: 0,
            pels_height: 0,
            display_flags: 0,
            display_frequency: 0,
            icm_method: 0,
            icm_intent: 0,
            media_type: 0,
            dither_type: 0,
            reserved1: 0,
            reserved2: 0,
            panning_width: 0,
            panning_height: 0,
        }
    }
}

impl DevModeW {
    /// The record in `bytes`: as many bytes as there are (`dmSize` may be
    /// less than ours), the rest zero.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut record = Self::default();
        let length = bytes.len().min(size_of::<Self>());
        // SAFETY: a `#[repr(C)]` record of integers without padding (its size
        // is checked below), for which any bytes are a value; `length` is
        // within both.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), (&mut record as *mut Self).cast::<u8>(), length);
        }
        record
    }
}

/// DISPLAY_DEVICEW, 840 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayDeviceW {
    pub cb: u32,
    pub device_name: [u16; CCHDEVICENAME],
    pub device_string: [u16; CCHDEVICESTRING],
    pub state_flags: u32,
    pub device_id: [u16; CCHDEVICESTRING],
    pub device_key: [u16; CCHDEVICESTRING],
}

impl Default for DisplayDeviceW {
    fn default() -> Self {
        Self {
            cb: size_of::<Self>() as u32,
            device_name: [0; CCHDEVICENAME],
            device_string: [0; CCHDEVICESTRING],
            state_flags: 0,
            device_id: [0; CCHDEVICESTRING],
            device_key: [0; CCHDEVICESTRING],
        }
    }
}

/// `text` into the fixed array `field`, cut to leave its NUL.
pub fn set_text<const N: usize>(field: &mut [u16; N], text: &str) {
    *field = [0; N];
    for (unit, at) in text.encode_utf16().zip(field.iter_mut().take(N - 1)) {
        *at = unit;
    }
}

const _: () = {
    assert!(size_of::<DevModeW>() == 220);
    assert!(offset_of!(DevModeW, spec_version) == 64);
    assert!(offset_of!(DevModeW, size) == 68);
    assert!(offset_of!(DevModeW, driver_extra) == 70);
    assert!(offset_of!(DevModeW, fields) == 72);
    assert!(offset_of!(DevModeW, position_x) == 76);
    assert!(offset_of!(DevModeW, display_orientation) == 84);
    assert!(offset_of!(DevModeW, form_name) == 102);
    assert!(offset_of!(DevModeW, log_pixels) == 166);
    assert!(offset_of!(DevModeW, bits_per_pel) == 168);
    assert!(offset_of!(DevModeW, pels_width) == 172);
    assert!(offset_of!(DevModeW, pels_height) == 176);
    assert!(offset_of!(DevModeW, display_flags) == 180);
    assert!(offset_of!(DevModeW, display_frequency) == 184);
    assert!(offset_of!(DevModeW, icm_method) == 188);
    assert!(offset_of!(DevModeW, panning_width) == DEVMODEW_SIZE_400);
    assert!(size_of::<DisplayDeviceW>() == 840);
    assert!(offset_of!(DisplayDeviceW, device_name) == 4);
    assert!(offset_of!(DisplayDeviceW, device_string) == 68);
    assert!(offset_of!(DisplayDeviceW, state_flags) == 324);
    assert!(offset_of!(DisplayDeviceW, device_id) == 328);
    assert!(offset_of!(DisplayDeviceW, device_key) == 584);
};

/// `as_bytes` for records of integers whose sizes, checked above, leave no
/// padding.
macro_rules! as_bytes {
    ($($record:ty),*) => {$(
        impl $record {
            /// Its bytes, as they go to user mode.
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: a `#[repr(C)]` record of integers without padding
                // (its size is checked above): every byte is initialised.
                unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
            }
        }
    )*};
}

as_bytes!(DevModeW, DisplayDeviceW);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_devmode_reads_back_from_its_bytes() {
        let mut mode = DevModeW { size: 220, fields: dm::PELSWIDTH | dm::PELSHEIGHT, ..DevModeW::default() };
        (mode.pels_width, mode.pels_height, mode.bits_per_pel) = (800, 600, 32);
        let bytes = mode.as_bytes();
        assert_eq!(&bytes[172..176], &800u32.to_le_bytes(), "dmPelsWidth");
        assert_eq!(DevModeW::from_bytes(bytes), mode);
        let short = DevModeW::from_bytes(&bytes[..180]);
        assert_eq!((short.pels_height, short.display_frequency), (600, 0), "what is past the bytes is zero");
    }

    #[test]
    fn a_text_field_keeps_its_nul() {
        let mut name = [0xFFFFu16; 8];
        set_text(&mut name, "\\\\.\\DISPLAY1");
        assert!(name[..7].iter().copied().eq("\\\\.\\DIS".encode_utf16()));
        assert_eq!(name[7], 0, "cut to leave the NUL");
        set_text(&mut name, "AB");
        assert_eq!(name[..3], [u16::from(b'A'), u16::from(b'B'), 0]);
        assert_eq!(name[3..], [0; 5], "the rest cleared");
    }
}
