//! d3d9.dll — Direct3D 9 shim layer.
//!
//! This is the most important DirectX component for XP-era game compat.
//! ~90% of games from 2002–2007 use D3D9.
//!
//! Architecture:
//!   Game → IDirect3D9 / IDirect3DDevice9 (our stub COM objects)
//!        → Vulkan or WGPU backend (Phase 4)
//!
//! We implement the COM vtable pattern that D3D9 uses.
//! Games call through function pointers in the vtable — we must match
//! the exact vtable layout of d3d9.dll from Windows XP SP2.
//!
//! Reference: DXVK source (d3d9/d3d9_interface.cpp) for vtable layout.
//! ReactOS: dll/directx/wine/d3d9/
//!
//! Phase 2: COM skeleton + software rasterizer (enough to show a window).
//! Phase 3: Vulkan backend (real GPU acceleration).

#![no_std]
extern crate alloc;

use alloc::boxed::Box;
use core::ffi::c_void;

// ── COM infrastructure ────────────────────────────────────────────────────────

/// HRESULT — COM return type.
pub type HResult = i32;

pub const S_OK:           HResult = 0;
pub const E_NOTIMPL:      HResult = 0x8000_4001u32 as i32;
pub const E_INVALIDARG:   HResult = 0x8007_0057u32 as i32;
pub const D3DERR_NOTAVAILABLE: HResult = 0x8876_086Au32 as i32;

/// IUnknown vtable — base of all COM interfaces.
#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface: unsafe extern "C" fn(*mut c_void, *const [u8;16], *mut *mut c_void) -> HResult,
    pub add_ref:         unsafe extern "C" fn(*mut c_void) -> u32,
    pub release:         unsafe extern "C" fn(*mut c_void) -> u32,
}

// ── IDirect3D9 ────────────────────────────────────────────────────────────────

/// IDirect3D9 vtable layout (must match d3d9.dll exactly).
/// Only the slots we implement are filled; others return E_NOTIMPL.
#[repr(C)]
pub struct IDirect3D9Vtbl {
    // IUnknown
    pub query_interface:         unsafe extern "C" fn(*mut c_void, *const [u8;16], *mut *mut c_void) -> HResult,
    pub add_ref:                 unsafe extern "C" fn(*mut c_void) -> u32,
    pub release:                 unsafe extern "C" fn(*mut c_void) -> u32,
    // IDirect3D9
    pub register_software_device: unsafe extern "C" fn(*mut c_void, *mut c_void) -> HResult,
    pub get_adapter_count:       unsafe extern "C" fn(*mut c_void) -> u32,
    pub get_adapter_identifier: unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> HResult,
    pub get_adapter_mode_count: unsafe extern "C" fn(*mut c_void, u32, u32) -> u32,
    pub enum_adapter_modes:     unsafe extern "C" fn(*mut c_void, u32, u32, u32, *mut c_void) -> HResult,
    pub get_adapter_display_mode: unsafe extern "C" fn(*mut c_void, u32, *mut c_void) -> HResult,
    pub check_device_type:      unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, i32) -> HResult,
    pub check_device_format:    unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32) -> HResult,
    pub check_device_multi_sample_type: unsafe extern "C" fn(*mut c_void, u32, u32, u32, i32, *mut u32) -> HResult,
    pub check_depth_stencil_match: unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32) -> HResult,
    pub check_device_format_conversion: unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32) -> HResult,
    pub get_device_caps:        unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> HResult,
    pub get_adapter_monitor:    unsafe extern "C" fn(*mut c_void, u32) -> *mut c_void,
    pub create_device:          unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void, u32, *mut c_void, *mut *mut c_void) -> HResult,
}

/// IDirect3D9 object.
pub struct Direct3D9 {
    pub vtbl: *const IDirect3D9Vtbl,
    ref_count: spin::Mutex<u32>,
}

// ── Direct3DCreate9 ───────────────────────────────────────────────────────────

/// Direct3DCreate9 — the single exported factory function.
/// Games call this first. Returns NULL on failure.
///
/// # Safety
/// Standard D3D9 COM rules apply.
#[no_mangle]
pub unsafe extern "C" fn Direct3DCreate9(sdk_version: u32) -> *mut Direct3D9 {
    log::info!("Direct3DCreate9(sdk_version={})", sdk_version);

    // Accepted SDK versions: D3D_SDK_VERSION = 32 (most XP games)
    if sdk_version != 32 {
        log::warn!("Direct3DCreate9: unexpected SDK version {}", sdk_version);
    }

    static VTBL: IDirect3D9Vtbl = IDirect3D9Vtbl {
        query_interface:              d3d9_query_interface,
        add_ref:                      d3d9_add_ref,
        release:                      d3d9_release,
        register_software_device:     d3d9_not_impl_1,
        get_adapter_count:            d3d9_get_adapter_count,
        get_adapter_identifier:       d3d9_not_impl_2,
        get_adapter_mode_count:       d3d9_get_adapter_mode_count,
        enum_adapter_modes:           d3d9_not_impl_3,
        get_adapter_display_mode:     d3d9_not_impl_2,
        check_device_type:            d3d9_check_device_type,
        check_device_format:          d3d9_not_impl_1,
        check_device_multi_sample_type: d3d9_not_impl_4,
        check_depth_stencil_match:    d3d9_not_impl_1,
        check_device_format_conversion: d3d9_not_impl_1,
        get_device_caps:              d3d9_not_impl_2,
        get_adapter_monitor:          d3d9_get_adapter_monitor,
        create_device:                d3d9_create_device,
    };

    let obj = Box::new(Direct3D9 {
        vtbl:      &VTBL as *const _,
        ref_count: spin::Mutex::new(1),
    });

    Box::into_raw(obj)
}

// ── IDirect3D9 method implementations ────────────────────────────────────────

unsafe extern "C" fn d3d9_query_interface(
    _this: *mut c_void, _riid: *const [u8;16], _ppv: *mut *mut c_void,
) -> HResult { E_NOTIMPL }

unsafe extern "C" fn d3d9_add_ref(this: *mut c_void) -> u32 {
    let obj = &*(this as *mut Direct3D9);
    let mut r = obj.ref_count.lock();
    *r += 1; *r
}

unsafe extern "C" fn d3d9_release(this: *mut c_void) -> u32 {
    let obj = &*(this as *mut Direct3D9);
    let mut r = obj.ref_count.lock();
    if *r > 0 { *r -= 1; }
    let remaining = *r;
    drop(r);
    if remaining == 0 {
        // SAFETY: ref count reached zero, we own the object.
        let _ = unsafe { Box::from_raw(this as *mut Direct3D9) };
    }
    remaining
}

unsafe extern "C" fn d3d9_get_adapter_count(_this: *mut c_void) -> u32 { 1 }

unsafe extern "C" fn d3d9_get_adapter_mode_count(_this: *mut c_void, _adapter: u32, _format: u32) -> u32 {
    // Advertise a handful of common resolutions.
    4
}

unsafe extern "C" fn d3d9_check_device_type(
    _this: *mut c_void, _adapter: u32, _device_type: u32,
    _adapter_format: u32, _back_buffer_format: u32, _windowed: i32,
) -> HResult { S_OK }

unsafe extern "C" fn d3d9_get_adapter_monitor(_this: *mut c_void, _adapter: u32) -> *mut c_void {
    0x1 as *mut c_void // fake HMONITOR
}

unsafe extern "C" fn d3d9_create_device(
    _this: *mut c_void,
    _adapter: u32,
    _device_type: u32,
    _h_focus_wnd: *mut c_void,
    _behavior_flags: u32,
    _presentation_params: *mut c_void,
    pp_returned_device: *mut *mut c_void,
) -> HResult {
    log::info!("IDirect3D9::CreateDevice — stub (Phase 2: software rasterizer)");
    // TODO Phase 3: create IDirect3DDevice9 backed by Vulkan.
    if !pp_returned_device.is_null() {
        unsafe { *pp_returned_device = core::ptr::null_mut(); }
    }
    E_NOTIMPL
}

// Stub helpers for unimplemented slots
unsafe extern "C" fn d3d9_not_impl_1(_: *mut c_void, _: u32) -> HResult { E_NOTIMPL }
unsafe extern "C" fn d3d9_not_impl_2(_: *mut c_void, _: u32, _: *mut c_void) -> HResult { E_NOTIMPL }
unsafe extern "C" fn d3d9_not_impl_3(_: *mut c_void, _: u32, _: u32, _: u32, _: *mut c_void) -> HResult { E_NOTIMPL }
unsafe extern "C" fn d3d9_not_impl_4(_: *mut c_void, _: u32, _: u32, _: u32, _: i32, _: *mut u32) -> HResult { E_NOTIMPL }
