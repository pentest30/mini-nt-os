//! VMMDev, the integration device of VirtualBox (PCI 80EE:CAFE): the
//! requests of its mouse integration. The guest writes a request in physical
//! memory below 4 GiB, then its physical address to the device's request
//! port (BAR0, an I/O BAR); the device handles it during that write and
//! leaves its status in the request's `rc`.
//!
//! Specification: VirtualBox's public guest interface (`VMMDev.h`), read as
//! a specification; no VirtualBox code is used.

use core::mem::{offset_of, size_of};

/// The device's PCI identity.
pub const VENDOR_ID: u16 = 0x80EE;
pub const DEVICE_ID: u16 = 0xCAFE;

/// `VMMDevRequestHeader::version`.
pub const REQUEST_HEADER_VERSION: u32 = 0x0001_0001;
/// `VBoxGuestInfo::interfaceVersion`: the major version must be 1.
pub const INTERFACE_VERSION: u32 = 0x0001_0004;
/// `VBOXOSTYPE_Unknown`: Mino does not pose as another system.
pub const OS_TYPE_UNKNOWN: u32 = 0;

/// Request types.
pub const REQUEST_GET_MOUSE_STATUS: u32 = 1;
pub const REQUEST_SET_MOUSE_STATUS: u32 = 2;
/// Until the guest reports itself, the device refuses every other request.
pub const REQUEST_REPORT_GUEST_INFO: u32 = 50;

/// The `rc` a request carries before the device handles it
/// (`VERR_GENERAL_FAILURE`); the device leaves 0 or more on success.
pub const RC_NOT_HANDLED: i32 = -1;

/// Mouse features (`mouseFeatures`).
/// The guest reads absolute positions from the device.
pub const MOUSE_GUEST_CAN_ABSOLUTE: u32 = 1 << 0;
/// The host sends absolute positions (its mouse integration is on).
pub const MOUSE_HOST_WANTS_ABSOLUTE: u32 = 1 << 1;
/// The guest draws no pointer: the host must show its own.
pub const MOUSE_GUEST_NEEDS_HOST_CURSOR: u32 = 1 << 2;
/// The guest learns of a new position by the device's interrupt rather than
/// by an empty packet of the PS/2 mouse.
pub const MOUSE_NEW_PROTOCOL: u32 = 1 << 4;
/// The largest absolute position on each axis (the smallest is 0).
pub const MOUSE_RANGE_MAX: i32 = 0xFFFF;

/// `VMMDevRequestHeader`: the head of every request.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestHeader {
    /// The size of the whole request, header included.
    pub size: u32,
    /// [`REQUEST_HEADER_VERSION`].
    pub version: u32,
    pub request_type: u32,
    /// The device's status: [`RC_NOT_HANDLED`] before it, 0 or more on
    /// success, negative on failure.
    pub rc: i32,
    pub reserved1: u32,
    /// `fRequestor`: 0, a legacy guest.
    pub requestor: u32,
}

impl RequestHeader {
    /// The header of a request of `size` bytes and type `request_type`.
    pub const fn new(size: usize, request_type: u32) -> Self {
        Self {
            size: size as u32,
            version: REQUEST_HEADER_VERSION,
            request_type,
            rc: RC_NOT_HANDLED,
            reserved1: 0,
            requestor: 0,
        }
    }
}

/// `VMMDevReqMouseStatus`: GetMouseStatus and SetMouseStatus.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MouseStatus {
    pub header: RequestHeader,
    /// MOUSE_*.
    pub features: u32,
    /// The absolute position, 0 to [`MOUSE_RANGE_MAX`] across the screen.
    pub x: i32,
    pub y: i32,
}

impl MouseStatus {
    /// A request of type `request_type` with `features`.
    pub const fn new(request_type: u32, features: u32) -> Self {
        Self { header: RequestHeader::new(size_of::<Self>(), request_type), features, x: 0, y: 0 }
    }
}

/// `VMMDevReportGuestInfo`: the guest's interface version and system.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestInfo {
    pub header: RequestHeader,
    /// [`INTERFACE_VERSION`].
    pub interface_version: u32,
    /// `VBOXOSTYPE`: [`OS_TYPE_UNKNOWN`].
    pub os_type: u32,
}

impl GuestInfo {
    pub const fn new() -> Self {
        Self {
            header: RequestHeader::new(size_of::<Self>(), REQUEST_REPORT_GUEST_INFO),
            interface_version: INTERFACE_VERSION,
            os_type: OS_TYPE_UNKNOWN,
        }
    }
}

const _: () = {
    assert!(size_of::<RequestHeader>() == 24);
    assert!(offset_of!(RequestHeader, request_type) == 8);
    assert!(offset_of!(RequestHeader, rc) == 12);
    assert!(offset_of!(RequestHeader, requestor) == 20);
    assert!(size_of::<MouseStatus>() == 36);
    assert!(offset_of!(MouseStatus, features) == 24);
    assert!(offset_of!(MouseStatus, x) == 28);
    assert!(offset_of!(MouseStatus, y) == 32);
    assert!(size_of::<GuestInfo>() == 32);
    assert!(offset_of!(GuestInfo, interface_version) == 24);
    assert!(offset_of!(GuestInfo, os_type) == 28);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_carry_their_size_version_and_type() {
        let status = MouseStatus::new(REQUEST_SET_MOUSE_STATUS, MOUSE_GUEST_CAN_ABSOLUTE);
        assert_eq!((status.header.size, status.header.version), (36, 0x0001_0001));
        assert_eq!((status.header.request_type, status.header.rc, status.features), (2, -1, 1));
        let info = GuestInfo::new();
        assert_eq!((info.header.size, info.header.request_type), (32, 50));
        assert_eq!((info.interface_version, info.os_type), (0x0001_0004, 0));
    }
}
