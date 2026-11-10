//! d3d8.dll — Direct3D 8 shim layer (Phase 3).
//!
//! Ghost Recon 2001 (GOG v1.4, DRM-free) uses D3D8, NOT D3D9.
//! Fixed-function pipeline only — no vertex or pixel shaders needed.
//!
//! # Runtime architecture
//! The actual machine code stubs are written by `loader.rs:write_d3d8_page()`
//! into a mapped page at `0x7400_1000`. This crate documents the vtable
//! layouts and serves as a reference for the stub generator.
//!
//! # COM vtable layout (must match d3d8.dll XP SP2 exactly)
//!
//! ## IDirect3D8 (16 methods)
//! 0  QueryInterface  1  AddRef  2  Release
//! 3  RegisterSoftwareDevice  4  GetAdapterCount
//! 5  GetAdapterIdentifier    6  GetAdapterModeCount
//! 7  EnumAdapterModes        8  GetAdapterDisplayMode
//! 9  CheckDeviceType        10  CheckDeviceFormat
//! 11 CheckDeviceMultiSampleType  12 CheckDepthStencilMatch
//! 13 GetDeviceCaps          14  GetAdapterMonitor
//! 15 CreateDevice
//!
//! ## IDirect3DDevice8 (97 methods)
//! See write_d3d8_page() in executive/ps/src/loader.rs for full list.
//!
//! ## IDirect3DTexture8 (19 methods — inherits Resource8 + BaseTexture8)
//! ## IDirect3DVertexBuffer8 (14 methods — inherits Resource8)
//! ## IDirect3DIndexBuffer8 (14 methods — inherits Resource8)
//!
//! # Key calls Ghost Recon makes (fixed-function path):
//! ```
//! device.SetTransform(D3DTS_WORLD/VIEW/PROJ, &matrix);
//! device.SetTexture(stage, pTexture);
//! device.SetRenderState(D3DRS_LIGHTING, FALSE);
//! device.SetStreamSource(0, pVB, stride);
//! device.SetIndices(pIB, baseVertex);
//! device.BeginScene();
//! device.DrawIndexedPrimitive(D3DPT_TRIANGLELIST, ...);
//! device.EndScene();
//! device.Present(NULL, NULL, NULL, NULL);
//! ```

#![no_std]
extern crate alloc;

use core::ffi::c_void;

// ── COM error codes ──────────────────────────────────────────────────────────
pub type HResult = i32;
pub const S_OK:       HResult = 0x0000_0000;
pub const E_NOTIMPL:  HResult = 0x8000_4001u32 as i32;
pub const E_FAIL:     HResult = 0x8000_4005u32 as i32;

// ── D3D8 error codes ─────────────────────────────────────────────────────────
pub const D3DERR_INVALIDCALL:    HResult = 0x8876_086Bu32 as i32;
pub const D3DERR_NOTAVAILABLE:   HResult = 0x8876_086Au32 as i32;
pub const D3DERR_OUTOFVIDEOMEMORY: HResult = 0x8876_0200u32 as i32;

// ── D3D8 constants (selected — what Ghost Recon actually uses) ───────────────
pub const D3DADAPTER_DEFAULT: u32 = 0;
pub const D3DDEVTYPE_HAL:     u32 = 1;

pub const D3DCREATE_HARDWARE_VERTEXPROCESSING: u32 = 0x0040;
pub const D3DCREATE_SOFTWARE_VERTEXPROCESSING: u32 = 0x0020;
pub const D3DCREATE_MIXED_VERTEXPROCESSING:    u32 = 0x0080;

pub const D3DTS_WORLD:      u32 = 256;
pub const D3DTS_VIEW:       u32 = 2;
pub const D3DTS_PROJECTION: u32 = 3;

pub const D3DPT_TRIANGLELIST: u32 = 4;
pub const D3DPT_TRIANGLESTRIP: u32 = 5;

pub const D3DRS_LIGHTING:  u32 = 137;
pub const D3DRS_ZENABLE:   u32 = 7;
pub const D3DRS_CULLMODE:  u32 = 22;
pub const D3DRS_ALPHABLENDENABLE: u32 = 27;
pub const D3DRS_SRCBLEND:  u32 = 19;
pub const D3DRS_DESTBLEND: u32 = 20;

pub const D3DLOCK_DISCARD: u32 = 0x2000;

/// D3D_SDK_VERSION accepted by Direct3DCreate8.
pub const D3D_SDK_VERSION: u32 = 220;

// ── IDirect3D8 vtable reference (16 slots) ───────────────────────────────────
/// The machine code vtable is at `d3d8_base + 0x1A20`.
/// The IDirect3D8 object is at  `d3d8_base + 0x1A60`.
#[repr(C)]
pub struct IDirect3D8Vtbl {
    pub query_interface:               unsafe extern "C" fn(*mut c_void, *const [u8;16], *mut *mut c_void) -> HResult,
    pub add_ref:                       unsafe extern "C" fn(*mut c_void) -> u32,
    pub release:                       unsafe extern "C" fn(*mut c_void) -> u32,
    pub register_software_device:      unsafe extern "C" fn(*mut c_void, *mut c_void) -> HResult,
    pub get_adapter_count:             unsafe extern "C" fn(*mut c_void) -> u32,
    pub get_adapter_identifier:        unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> HResult,
    pub get_adapter_mode_count:        unsafe extern "C" fn(*mut c_void, u32) -> u32,
    pub enum_adapter_modes:            unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> HResult,
    pub get_adapter_display_mode:      unsafe extern "C" fn(*mut c_void, u32, *mut c_void) -> HResult,
    pub check_device_type:             unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, i32) -> HResult,
    pub check_device_format:           unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32, u32) -> HResult,
    pub check_device_multi_sample_type: unsafe extern "C" fn(*mut c_void, u32, u32, u32, i32, u32) -> HResult,
    pub check_depth_stencil_match:     unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32) -> HResult,
    pub get_device_caps:               unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> HResult,
    pub get_adapter_monitor:           unsafe extern "C" fn(*mut c_void, u32) -> *mut c_void,
    pub create_device:                 unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void, u32, *mut c_void, *mut *mut c_void) -> HResult,
}

// ── IDirect3DDevice8 vtable reference (97 slots) ─────────────────────────────
/// The machine code vtable is at `d3d8_base + 0x1A70`.
/// The IDirect3DDevice8 object is at `d3d8_base + 0x1BF8`.
///
/// Full method list with vtable index → machine code page offset:
///   slot 0  (page+0x110) QueryInterface
///   slot 1  (page+0x120) AddRef
///   slot 2  (page+0x130) Release
///   slot 3  (page+0x140) TestCooperativeLevel
///   slot 4  (page+0x150) GetAvailableTextureMem
///   slot 5  (page+0x160) ResourceManagerDiscardBytes
///   slot 6  (page+0x170) GetDirect3D
///   slot 7  (page+0x180) GetDeviceCaps
///   slot 8  (page+0x190) GetDisplayMode
///   slot 9  (page+0x1A0) GetCreationParameters
///   slot 10 (page+0x1B0) SetCursorProperties
///   slot 11 (page+0x1C0) SetCursorPosition
///   slot 12 (page+0x1D0) ShowCursor
///   slot 13 (page+0x1E0) CreateAdditionalSwapChain
///   slot 14 (page+0x1F0) Reset
///   slot 15 (page+0x200) Present
///   slot 16 (page+0x210) GetBackBuffer
///   slot 17 (page+0x220) GetRasterStatus
///   slot 18 (page+0x230) SetGammaRamp
///   slot 19 (page+0x240) GetGammaRamp
///   slot 20 (page+0x250) CreateTexture ← writes ppTexture = objtex_va
///   slot 21 (page+0x260) CreateVolumeTexture → E_NOTIMPL
///   slot 22 (page+0x270) CreateCubeTexture → E_NOTIMPL
///   slot 23 (page+0x280) CreateVertexBuffer ← writes ppVB = objvb_va
///   slot 24 (page+0x290) CreateIndexBuffer  ← writes ppIB = objib_va
///   slot 25 (page+0x2A0) CreateRenderTarget → S_OK
///   slot 26 (page+0x2B0) CreateDepthStencilSurface → S_OK
///   slot 27 (page+0x2C0) CreateImageSurface → S_OK
///   slot 28 (page+0x2D0) CopyRects → S_OK
///   slot 29 (page+0x2E0) UpdateTexture → S_OK
///   slot 30 (page+0x2F0) GetFrontBuffer → S_OK
///   slot 31 (page+0x300) SetRenderTarget → S_OK
///   slot 32 (page+0x310) GetRenderTarget → S_OK
///   slot 33 (page+0x320) GetDepthStencilSurface → S_OK
///   slot 34 (page+0x330) BeginScene → S_OK
///   slot 35 (page+0x340) EndScene → S_OK
///   slot 36 (page+0x350) Clear → S_OK
///   slot 37 (page+0x360) SetTransform → S_OK
///   ...
///   slot 96 (page+0x710) DeletePatch → S_OK
pub struct IDirect3DDevice8Vtbl; // placeholder — see loader.rs for machine code

// ── Static COM object layout in the stub page ─────────────────────────────────
// IDirect3D8 object    = { u32 vtable_ptr, u32 ref_count }  @ base+0x1A60
// IDirect3DDevice8 obj = { u32 vtable_ptr, u32 ref_count }  @ base+0x1BF8
// IDirect3DTexture8 obj = { u32 vtable_ptr, u32 ref_count } @ base+0x1C50
// IDirect3DVertexBuffer8 obj = { u32 vtbl, u32 rc }         @ base+0x1CA0
// IDirect3DIndexBuffer8 obj  = { u32 vtbl, u32 rc }         @ base+0x1CF0
// Lock buffer (64 bytes zeroed)                              @ base+0x1D00
