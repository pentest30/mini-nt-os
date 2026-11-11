//! GDI, the drawing part of win32k (02 §7.2), as its i386 clients see it
//! (CLAUDE.md, rule 5): the GDI handle table that win32k shares, read-only,
//! with each GUI process (`PEB.GdiSharedHandleTable`), the attributes of a
//! device context in the user memory of its owner (`DC_ATTR`), the batch of
//! calls that `gdi32` queues in the TEB (`GdiTebBatch`), and the constants
//! of the calls that use them. ReactOS's `win32ss/include/ntgdihdl.h` and
//! `ntgdityp.h` (the pinned version) serve as the specification of the
//! formats (ADR-002); offsets are checked at compile time, and those that the
//! pinned `gdi32` reads (`PatBlt`, `GdiSelectBrush`) are noted.
//!
//! A GDI handle is `FullUnique << 16 | index`: the index of its entry in the
//! table (16 bits), then its type (7 bits, [`GDI_HANDLE_TYPE_MASK`]), the
//! stock bit and a reuse count. `gdi32` finds the entry by the index and
//! checks it against the handle (`GdiValidateHandle`,
//! `GdiGetHandleUserData`): the entry's base type is not zero, its
//! `FullUnique` carries the handle's type, and its owner is the current
//! process (or none, for a public object such as a stock one).

use core::mem::{offset_of, size_of};

use crate::user::Rect32;

/// GDI_HANDLE_COUNT: the entries of the handle table.
pub const GDI_HANDLE_COUNT: u32 = 0x1_0000;
/// The index of a handle's entry.
pub const GDI_HANDLE_INDEX_MASK: u32 = GDI_HANDLE_COUNT - 1;
/// The type of a handle (`GDILoObjType`), base and extended.
pub const GDI_HANDLE_TYPE_MASK: u32 = 0x007F_0000;
/// The base type of a handle (`GDIObjType << 16`).
pub const GDI_HANDLE_BASETYPE_MASK: u32 = 0x001F_0000;
/// A stock object's handle has this bit.
pub const GDI_HANDLE_STOCK_MASK: u32 = 0x0080_0000;
/// The reuse count of a handle, in its top byte.
pub const GDI_HANDLE_REUSE_MASK: u32 = 0xFF00_0000;
/// The stock bit in an entry's `FullUnique` (the handle's upper half).
pub const GDI_ENTRY_STOCK_MASK: u16 = 0x0080;
/// What one reuse adds to an entry's `FullUnique`.
pub const GDI_ENTRY_REUSE_INCREMENT: u16 = 0x0100;
/// RESERVE_ENTRIES_COUNT: the first entries of the table, never given out.
pub const RESERVE_ENTRIES_COUNT: u32 = 10;

/// GDIObjType_*: the base type of an object, in its entry (`Objt`) and in
/// bits 16 to 20 of its handle.
pub mod objt {
    pub const DC: u8 = 0x01;
    pub const PEN: u8 = 0x03;
    pub const RGN: u8 = 0x04;
    pub const SURF: u8 = 0x05;
    pub const PAL: u8 = 0x08;
    pub const LFONT: u8 = 0x0A;
    pub const BRUSH: u8 = 0x10;
}

/// GDILoObjType_*: the type of a handle, as `gdi32` tests it.
pub const LO_DC_TYPE: u32 = 0x0001_0000;
pub const LO_REGION_TYPE: u32 = 0x0004_0000;
pub const LO_BITMAP_TYPE: u32 = 0x0005_0000;
pub const LO_BRUSH_TYPE: u32 = 0x0010_0000;
pub const LO_FONT_TYPE: u32 = 0x000A_0000;
/// A pen: a brush object, of an extended handle type.
pub const LO_PEN_TYPE: u32 = 0x0030_0000;
/// A DC of another kind (a printer's, a metafile's).
pub const LO_ALTDC_TYPE: u32 = 0x0021_0000;

/// GDI_TABLE_ENTRY: an entry of the handle table, as a client reads it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiTableEntry32 {
    /// The object in the kernel (`einfo.pobj`): an address the client never
    /// follows.
    pub kernel_data: u32,
    /// The owner's process ID, 0 for a public object; bit 0 is a lock bit
    /// that the client ignores.
    pub process_id: u32,
    /// The handle's upper half: its type, stock bit and reuse count.
    pub full_unique: u16,
    /// Its base type ([`objt`]).
    pub object_type: u8,
    pub flags: u8,
    /// The object's attributes in the owner's memory (`pUser`): a
    /// [`DcAttr32`] for a DC, `BRUSH_ATTR` for a brush, or 0.
    pub user_data: u32,
}

/// DEVCAPS: the primary display's capabilities, after the entries of the
/// shared table (`GetDeviceCaps` of a display DC reads them there).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DevCaps32 {
    pub version: u32,
    pub technology: u32,
    pub horz_size_m: u32,
    pub vert_size_m: u32,
    pub horz_size: u32,
    pub vert_size: u32,
    pub horz_res: u32,
    pub vert_res: u32,
    pub bits_pixel: u32,
    pub planes: u32,
    pub num_pens: u32,
    pub num_fonts: u32,
    pub num_colors: u32,
    pub raster_caps: u32,
    pub aspect_x: u32,
    pub aspect_y: u32,
    pub aspect_xy: u32,
    pub log_pixels_x: u32,
    pub log_pixels_y: u32,
    pub size_palette: u32,
    pub color_res: u32,
    pub physical_width: u32,
    pub physical_height: u32,
    pub physical_offset_x: u32,
    pub physical_offset_y: u32,
    pub text_caps: u32,
    pub v_refresh: u32,
    pub desktop_horz_res: u32,
    pub desktop_vert_res: u32,
    pub blt_alignment: u32,
    pub panning_horz_res: u32,
    pub panning_vert_res: u32,
    pub x_panning_alignment: u32,
    pub y_panning_alignment: u32,
    pub shade_blend: u32,
    pub color_mgmt_caps: u32,
}

/// What follows the entries in GDI_SHARED_HANDLE_TABLE, up to `pvLangPack`
/// (the public fonts, `cfPublic`, come after: `gdi32` does not read them).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiSharedTail32 {
    pub dev_caps: DevCaps32,
    /// `flDeviceUniq`: changes with the display settings.
    pub device_uniq: u32,
    pub lang_pack: u32,
}

/// The offset of [`GdiSharedTail32`] in the shared table.
pub const GDI_SHARED_TAIL: u32 = GDI_HANDLE_COUNT * size_of::<GdiTableEntry32>() as u32;

/// The offset of entry `index` in the shared table.
pub const fn gdi_entry_offset(index: u32) -> u32 {
    index * size_of::<GdiTableEntry32>() as u32
}

/// FLOATOBJ of an i386 kernel: a float in GDI's own format.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FloatObj32 {
    pub ul1: u32,
    pub ul2: u32,
}

/// MATRIX: a coordinate transform.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Matrix32 {
    pub ef_m11: FloatObj32,
    pub ef_m12: FloatObj32,
    pub ef_m21: FloatObj32,
    pub ef_m22: FloatObj32,
    pub ef_dx: FloatObj32,
    pub ef_dy: FloatObj32,
    pub fx_dx: i32,
    pub fx_dy: i32,
    pub fl_accel: u32,
}

/// POINTL, SIZEL.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointL32 {
    pub x: i32,
    pub y: i32,
}

/// RGN_ATTR: a region's complexity and bounding rectangle. A region of a
/// client has one in the client's memory (the `UserData` of its entry),
/// where `gdi32` reads it and, for an empty or rectangular region, changes
/// it (CombineRgn, SetRectRgn) without calling the kernel, marking it
/// [`ATTR_RGN_DIRTY`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RgnAttr32 {
    /// [`ATTR_RGN_VALID`], [`ATTR_RGN_DIRTY`].
    pub attr_flags: u32,
    /// NULLREGION, SIMPLEREGION or COMPLEXREGION.
    pub complexity: u32,
    pub rect: Rect32,
}

/// The kernel wrote the attributes of the region.
pub const ATTR_RGN_VALID: u32 = 0x0000_0010;
/// `gdi32` changed the region in its attributes: the kernel takes it back
/// before using the region (REGION_vSyncRegion).
pub const ATTR_RGN_DIRTY: u32 = 0x0000_0020;

impl RgnAttr32 {
    /// The attributes in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        Some(Self {
            attr_flags: word(0),
            complexity: word(4),
            rect: Rect32 {
                left: word(8) as i32,
                top: word(0xC) as i32,
                right: word(0x10) as i32,
                bottom: word(0x14) as i32,
            },
        })
    }
}

/// RGN_AND … RGN_COPY: how CombineRgn and ExtSelectClipRgn combine.
pub mod rgn {
    pub const AND: i32 = 1;
    pub const OR: i32 = 2;
    pub const XOR: i32 = 3;
    pub const DIFF: i32 = 4;
    pub const COPY: i32 = 5;
}

/// DC_ATTR: the attributes of a DC that its owner's `gdi32` reads and
/// writes directly; win32k takes them back when it draws (`ulDirty_` says
/// what changed).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DcAttr32 {
    pub ldc: u32,
    /// `ulDirty_`: [`dirty`].
    pub dirty: u32,
    /// The selected brush (`GdiSelectBrush` swaps it).
    pub hbrush: u32,
    pub hpen: u32,
    pub cr_background_clr: u32,
    pub ul_background_clr: u32,
    pub cr_foreground_clr: u32,
    pub ul_foreground_clr: u32,
    /// The colour of the DC brush (`SetDCBrushColor`).
    pub cr_brush_clr: u32,
    pub ul_brush_clr: u32,
    pub cr_pen_clr: u32,
    pub ul_pen_clr: u32,
    pub cs_cp: u32,
    pub graphics_mode: i32,
    pub rop2: u8,
    pub bk_mode_byte: u8,
    pub fill_mode_byte: u8,
    pub stretch_blt_mode_byte: u8,
    pub current: PointL32,
    pub fx_current: PointL32,
    pub bk_mode: i32,
    pub fill_mode: i32,
    pub stretch_blt_mode: i32,
    pub font_mapper: u32,
    pub icm_mode: i32,
    pub cm_xform: u32,
    pub color_space: u32,
    pub icm_flags: u32,
    pub icm_brush_color: i32,
    pub icm_pen_color: i32,
    pub licm: u32,
    pub fl_text_align: u32,
    pub text_align: i32,
    pub text_extra: i32,
    pub rel_abs: i32,
    pub break_extra: i32,
    pub c_break: i32,
    pub lfnt_new: u32,
    pub world_to_device: Matrix32,
    pub device_to_world: Matrix32,
    pub world_to_page: Matrix32,
    pub ef_m11_ptod: FloatObj32,
    pub ef_m22_ptod: FloatObj32,
    pub ef_dx_ptod: FloatObj32,
    pub ef_dy_ptod: FloatObj32,
    pub map_mode: i32,
    pub layout: u32,
    pub window_org_x: i32,
    pub window_org: PointL32,
    pub window_ext: PointL32,
    pub viewport_org: PointL32,
    pub viewport_ext: PointL32,
    pub fl_xform: u32,
    pub virtual_device_pixel: PointL32,
    pub virtual_device_mm: PointL32,
    pub virtual_device_size: PointL32,
    pub brush_origin: PointL32,
    pub vis_rect_region: RgnAttr32,
}

/// The `ulDirty_` bits of a [`DcAttr32`].
pub mod dirty {
    pub const DIRTY_FILL: u32 = 0x0000_0001;
    pub const DIRTY_LINE: u32 = 0x0000_0002;
    pub const DIRTY_TEXT: u32 = 0x0000_0004;
    pub const DIRTY_BACKGROUND: u32 = 0x0000_0008;
    pub const DIRTY_CHARSET: u32 = 0x0000_0010;
    /// What a new DC has (`DIRTY_DEFAULT`).
    pub const DIRTY_DEFAULT: u32 = DIRTY_CHARSET | DIRTY_BACKGROUND | DIRTY_TEXT | DIRTY_LINE | DIRTY_FILL;
    /// `ptlCurrent` is stale, `ptfxCurrent` holds the current position.
    pub const DIRTY_PTLCURRENT: u32 = 0x0000_0100;
    /// `ptfxCurrent` is stale: `gdi32`'s MoveToEx wrote `ptlCurrent` alone.
    pub const DIRTY_PTFXCURRENT: u32 = 0x0000_0200;
    /// The pen's style state starts again (MoveToEx).
    pub const DIRTY_STYLESTATE: u32 = 0x0000_0400;
    /// `hbrush` changed (`GdiSelectBrush`).
    pub const DC_BRUSH_DIRTY: u32 = 0x0000_1000;
    pub const DC_PEN_DIRTY: u32 = 0x0000_2000;
    /// A memory DC with a DIB section: `PatBlt` calls the kernel at once
    /// instead of queuing.
    pub const DC_DIBSECTION: u32 = 0x0000_4000;
    /// A DC of the primary display.
    pub const DC_PRIMARY_DISPLAY: u32 = 0x0001_0000;
    /// Set by `PatBlt` when it queues.
    pub const DC_MODE_DIRTY: u32 = 0x0020_0000;
}

/// `flXform` bits.
pub mod xform {
    pub const WORLD_TO_PAGE_IDENTITY: u32 = 0x0002;
    pub const PAGE_TO_DEVICE_IDENTITY: u32 = 0x0800;
    pub const PAGE_TO_DEVICE_SCALE_IDENTITY: u32 = 0x1000;
}

/// R2_COPYPEN, OPAQUE, ALTERNATE, BLACKONWHITE, GM_COMPATIBLE, MM_TEXT:
/// a new DC's modes.
pub const R2_COPYPEN: u8 = 13;
pub const OPAQUE: i32 = 2;
pub const ALTERNATE: i32 = 1;
pub const BLACKONWHITE: i32 = 1;
pub const GM_COMPATIBLE: i32 = 1;
pub const MM_TEXT: i32 = 1;
/// CLR_INVALID.
pub const CLR_INVALID: u32 = 0xFFFF_FFFF;

impl DcAttr32 {
    /// A new DC's attributes (DC_vInitDc), with `hbrush` and `hpen` as its
    /// brush and pen, on a display of `width` by `height` pixels. The
    /// transform matrices stay zero: no transform yet (`flXform` says the
    /// identities, `MM_TEXT`).
    pub fn initial(hbrush: u32, hpen: u32, width: i32, height: i32) -> Self {
        let white = 0x00FF_FFFF;
        Self {
            dirty: dirty::DIRTY_DEFAULT | dirty::DC_PRIMARY_DISPLAY,
            hbrush,
            hpen,
            cr_background_clr: white,
            ul_background_clr: white,
            cr_brush_clr: white,
            ul_brush_clr: white,
            graphics_mode: GM_COMPATIBLE,
            rop2: R2_COPYPEN,
            bk_mode_byte: OPAQUE as u8,
            fill_mode_byte: ALTERNATE as u8,
            stretch_blt_mode_byte: BLACKONWHITE as u8,
            bk_mode: OPAQUE,
            fill_mode: ALTERNATE,
            stretch_blt_mode: BLACKONWHITE,
            icm_brush_color: CLR_INVALID as i32,
            icm_pen_color: CLR_INVALID as i32,
            map_mode: MM_TEXT,
            window_ext: PointL32 { x: 1, y: 1 },
            viewport_ext: PointL32 { x: 1, y: 1 },
            fl_xform: xform::PAGE_TO_DEVICE_SCALE_IDENTITY
                | xform::PAGE_TO_DEVICE_IDENTITY
                | xform::WORLD_TO_PAGE_IDENTITY,
            virtual_device_pixel: PointL32 { x: width, y: height },
            ..Self::default()
        }
    }
}

/// GDIBATCHBUFSIZE: the bytes of the TEB's batch buffer.
pub const GDI_BATCH_BUFFER_SIZE: usize = 0x136 * 4;
/// GDI_BATCH_LIMIT: the calls that a client queues at most
/// (`PEB.GdiDCAttributeList`).
pub const GDI_BATCH_LIMIT: u32 = 20;

/// GDI_TEB_BATCH: the calls that `gdi32` queues (GdiAllocBatchCommand),
/// for the DC `hdc`, until win32k runs them (at the thread's next call to
/// win32k, or after a callback to user mode).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdiTebBatch32 {
    /// The bytes used in `buffer`.
    pub offset: u32,
    /// The DC of the queued calls (0: any).
    pub hdc: u32,
    pub buffer: [u8; GDI_BATCH_BUFFER_SIZE],
}

/// GDIBATCHCMD: what a queued call is.
pub mod batch {
    pub const PAT_BLT: u16 = 0;
    pub const POLY_PAT_BLT: u16 = 1;
    pub const TEXT_OUT: u16 = 2;
    pub const EXT_TEXT_OUT: u16 = 3;
    pub const SET_BRUSH_ORG: u16 = 4;
    pub const EXT_SEL_CLIP_RGN: u16 = 5;
    pub const SEL_OBJ: u16 = 6;
    pub const DEL_OBJ: u16 = 7;
    pub const DEL_RGN: u16 = 8;
}

/// GDIBATCHHDR: the head of a queued call.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiBatchHeader32 {
    /// The bytes of the whole call.
    pub size: u16,
    /// [`batch`].
    pub cmd: u16,
}

/// GDIBSPATBLT: a queued PatBlt, with a snapshot of the DC's brush and
/// colours.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiBsPatBlt32 {
    pub header: GdiBatchHeader32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub hbrush: u32,
    pub rop: u32,
    pub cr_foreground_clr: u32,
    pub cr_background_clr: u32,
    pub cr_brush_clr: u32,
    pub icm_brush_color: i32,
    /// Not filled by gdi32's PatBlt: whatever the TEB held there.
    pub viewport_org: PointL32,
    pub ul_foreground_clr: u32,
    pub ul_background_clr: u32,
    pub ul_brush_clr: u32,
}

impl GdiBsPatBlt32 {
    /// The call in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        Some(Self {
            header: GdiBatchHeader32 {
                size: u16::from_le_bytes([bytes[0], bytes[1]]),
                cmd: u16::from_le_bytes([bytes[2], bytes[3]]),
            },
            x: word(4) as i32,
            y: word(8) as i32,
            width: word(0xC) as i32,
            height: word(0x10) as i32,
            hbrush: word(0x14),
            rop: word(0x18),
            cr_foreground_clr: word(0x1C),
            cr_background_clr: word(0x20),
            cr_brush_clr: word(0x24),
            icm_brush_color: word(0x28) as i32,
            viewport_org: PointL32 { x: word(0x2C) as i32, y: word(0x30) as i32 },
            ul_foreground_clr: word(0x34),
            ul_background_clr: word(0x38),
            ul_brush_clr: word(0x3C),
        })
    }
}

/// GDIBS_NORECT: in the mode of a queued ExtSelectClipRgn, no region (its
/// rectangle unused).
pub const GDIBS_NORECT: u32 = 0x8000_0000;

/// GDIBSEXTSELCLPRGN: a queued ExtSelectClipRgn (RGN_COPY only), with the
/// bounds of its region (a rectangle, or none: [`GDIBS_NORECT`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiBsExtSelClipRgn32 {
    pub header: GdiBatchHeader32,
    pub mode: u32,
    pub rect: Rect32,
}

/// GDIBSOBJECT: a queued call on an object (DeleteObject of a region or of
/// a brush, SelectObject of a font).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiBsObject32 {
    pub header: GdiBatchHeader32,
    pub handle: u32,
}

/// The header and the words after it in `bytes`, if they hold `size`
/// bytes.
fn words(bytes: &[u8], size: usize) -> Option<(GdiBatchHeader32, impl Fn(usize) -> u32 + '_)> {
    if bytes.len() < size {
        return None;
    }
    let header = GdiBatchHeader32 {
        size: u16::from_le_bytes([bytes[0], bytes[1]]),
        cmd: u16::from_le_bytes([bytes[2], bytes[3]]),
    };
    Some((header, move |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])))
}

impl GdiBsExtSelClipRgn32 {
    /// The call in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (header, word) = words(bytes, size_of::<Self>())?;
        let rect =
            Rect32 { left: word(8) as i32, top: word(0xC) as i32, right: word(0x10) as i32, bottom: word(0x14) as i32 };
        Some(Self { header, mode: word(4), rect })
    }
}

impl GdiBsObject32 {
    /// The call in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (header, word) = words(bytes, size_of::<Self>())?;
        Some(Self { header, handle: word(4) })
    }
}

/// Raster operations of PatBlt (ROP3, with their legacy low word).
/// GDI_OBJECT_TYPE_*: the kinds of object NtGdiGetDCObject (GetCurrentObject)
/// asks of a DC.
pub mod object_type {
    pub const BITMAP: u32 = 0x0005_0000;
    pub const PALETTE: u32 = 0x0008_0000;
    pub const FONT: u32 = 0x000A_0000;
    pub const BRUSH: u32 = 0x0010_0000;
    pub const PEN: u32 = 0x0030_0000;
    pub const EXTPEN: u32 = 0x0050_0000;
}

/// GdiDpToLp, GdiLpToDp: the directions of NtGdiTransformPoints.
pub const GDI_DP_TO_LP: u32 = 0;
pub const GDI_LP_TO_DP: u32 = 1;

pub mod rop {
    /// The brush.
    pub const PATCOPY: u32 = 0x00F0_0021;
    /// The brush XOR the destination.
    pub const PATINVERT: u32 = 0x005A_0049;
    /// NOT the destination.
    pub const DSTINVERT: u32 = 0x0055_0009;
    /// Black.
    pub const BLACKNESS: u32 = 0x0000_0042;
    /// White.
    pub const WHITENESS: u32 = 0x00FF_0062;
    /// The source.
    pub const SRCCOPY: u32 = 0x00CC_0020;
    /// BitBlt: include the windows layered on the source (no such windows
    /// yet).
    pub const CAPTUREBLT: u32 = 0x4000_0000;
    /// BitBlt: no mirroring of the source (no mirrored DCs yet).
    pub const NOMIRRORBITMAP: u32 = 0x8000_0000;
}

/// What a display's GDIINFO says, as DEVCAPS (and GetDeviceCaps) give it.
pub mod caps {
    /// GDI_DRIVER_VERSION: `ulVersion`.
    pub const GDI_DRIVER_VERSION: u32 = 0x4000;
    /// DT_RASDISPLAY: `ulTechnology`.
    pub const DT_RASDISPLAY: u32 = 1;
    /// RC_*: `ulRasterCaps`.
    pub const RC_BITBLT: u32 = 0x0001;
    pub const RC_BITMAP64: u32 = 0x0008;
    pub const RC_GDI20_OUTPUT: u32 = 0x0010;
    pub const RC_DI_BITMAP: u32 = 0x0080;
    pub const RC_DIBTODEV: u32 = 0x0200;
    pub const RC_BIGFONT: u32 = 0x0400;
    pub const RC_STRETCHBLT: u32 = 0x0800;
    pub const RC_FLOODFILL: u32 = 0x1000;
    pub const RC_STRETCHDIB: u32 = 0x2000;
    pub const RC_OP_DX_OUTPUT: u32 = 0x4000;
    /// TC_*: `ulTextCaps`.
    pub const TC_OP_CHARACTER: u32 = 0x0001;
    pub const TC_OP_STROKE: u32 = 0x0002;
    pub const TC_CP_STROKE: u32 = 0x0004;
    pub const TC_UA_ABLE: u32 = 0x0800;
    pub const TC_SO_ABLE: u32 = 0x1000;
    pub const TC_RA_ABLE: u32 = 0x2000;
    pub const TC_VA_ABLE: u32 = 0x4000;
}

/// BI_RGB, BI_BITFIELDS: a DIB's `biCompression`.
pub const BI_RGB: u32 = 0;
pub const BI_BITFIELDS: u32 = 3;
/// DIB_RGB_COLORS, DIB_PAL_COLORS: what a DIB's colour table holds.
pub const DIB_RGB_COLORS: u32 = 0;
pub const DIB_PAL_COLORS: u32 = 1;

/// BITMAPINFOHEADER: what a DIB is (`bmiHeader` of a BITMAPINFO, which
/// `gdi32` gives in this form: ConvertBitmapInfo).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BitmapInfoHeader32 {
    /// Its own size: at least 40 (a BITMAPV4HEADER or V5 is longer).
    pub size: u32,
    pub width: i32,
    /// Positive: the rows go up from the bottom one; negative: down from
    /// the top one.
    pub height: i32,
    pub planes: u16,
    pub bit_count: u16,
    pub compression: u32,
    pub size_image: u32,
    pub x_pels_per_meter: i32,
    pub y_pels_per_meter: i32,
    pub clr_used: u32,
    pub clr_important: u32,
}

impl BitmapInfoHeader32 {
    /// The header in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let half = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        Some(Self {
            size: word(0),
            width: word(4) as i32,
            height: word(8) as i32,
            planes: half(0xC),
            bit_count: half(0xE),
            compression: word(0x10),
            size_image: word(0x14),
            x_pels_per_meter: word(0x18) as i32,
            y_pels_per_meter: word(0x1C) as i32,
            clr_used: word(0x20),
            clr_important: word(0x24),
        })
    }
}

/// BRUSH_ATTR: a client brush's attributes, in its process (`gdi32` reads
/// its colour; it deletes a brush that has them by a batched call).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrushAttr32 {
    pub attr_flags: u32,
    /// COLORREF.
    pub color: u32,
}

/// What GetClipBox (and a region's `iComplexity`) returns.
pub const ERROR: i32 = 0;
pub const NULLREGION: i32 = 1;
pub const SIMPLEREGION: i32 = 2;
pub const COMPLEXREGION: i32 = 3;

/// GetStockObject's indices, those of the brushes.
pub mod stock {
    pub const WHITE_BRUSH: usize = 0;
    pub const LTGRAY_BRUSH: usize = 1;
    pub const GRAY_BRUSH: usize = 2;
    pub const DKGRAY_BRUSH: usize = 3;
    pub const BLACK_BRUSH: usize = 4;
    pub const NULL_BRUSH: usize = 5;
    pub const OEM_FIXED_FONT: usize = 10;
    pub const ANSI_FIXED_FONT: usize = 11;
    pub const ANSI_VAR_FONT: usize = 12;
    pub const SYSTEM_FONT: usize = 13;
    pub const DEVICE_DEFAULT_FONT: usize = 14;
    pub const SYSTEM_FIXED_FONT: usize = 16;
    pub const DEFAULT_GUI_FONT: usize = 17;
    /// The bitmap of a new memory DC: 1 × 1, monochrome (outside
    /// `STOCK_LAST`, as ReactOS has it; 20 is not used).
    pub const DEFAULT_BITMAP: usize = 21;
    /// The stock objects (`NB_STOCK_OBJECTS`).
    pub const COUNT: usize = 22;
}

const _: () = {
    assert!(size_of::<GdiTableEntry32>() == 16);
    assert!(offset_of!(GdiTableEntry32, process_id) == 4);
    assert!(offset_of!(GdiTableEntry32, full_unique) == 8);
    assert!(offset_of!(GdiTableEntry32, object_type) == 0xA);
    assert!(offset_of!(GdiTableEntry32, user_data) == 0xC);
    assert!(size_of::<DevCaps32>() == 36 * 4);
    assert!(GDI_SHARED_TAIL == 0x10_0000);
    assert!(size_of::<GdiSharedTail32>() == 0x98);
    assert!(size_of::<Matrix32>() == 60);
    // gdi32!GdiSelectBrush: [pdcattr + 8], `or [pdcattr + 4], 0x1000`;
    // gdi32!PatBlt: `test byte [pdcattr + 5], 0x40`, then the snapshot.
    assert!(offset_of!(DcAttr32, dirty) == 4);
    assert!(offset_of!(DcAttr32, hbrush) == 8);
    assert!(offset_of!(DcAttr32, cr_background_clr) == 0x10);
    assert!(offset_of!(DcAttr32, ul_background_clr) == 0x14);
    assert!(offset_of!(DcAttr32, cr_foreground_clr) == 0x18);
    assert!(offset_of!(DcAttr32, ul_foreground_clr) == 0x1C);
    assert!(offset_of!(DcAttr32, cr_brush_clr) == 0x20);
    assert!(offset_of!(DcAttr32, ul_brush_clr) == 0x24);
    assert!(offset_of!(DcAttr32, current) == 0x3C);
    assert!(offset_of!(DcAttr32, lfnt_new) == 0x90);
    assert!(offset_of!(DcAttr32, world_to_device) == 0x94);
    assert!(offset_of!(DcAttr32, map_mode) == 0x168);
    assert!(offset_of!(DcAttr32, viewport_org) == 0x184);
    assert!(offset_of!(DcAttr32, brush_origin) == 0x1B0);
    assert!(offset_of!(DcAttr32, vis_rect_region) == 0x1B8);
    assert!(size_of::<DcAttr32>() == 0x1D0);
    // TEB.GdiTebBatch at 0x1D4: gdi32!PatBlt reads Offset at 0x1D4, HDC at
    // 0x1D8, and writes from 0x1DC; its buffer holds 0x4D8 bytes.
    assert!(size_of::<GdiTebBatch32>() == 0x4E0);
    assert!(offset_of!(GdiTebBatch32, hdc) == 4);
    assert!(offset_of!(GdiTebBatch32, buffer) == 8);
    // gdi32!PatBlt: `add eax, 0x40`, `mov word [eax], 0x40`.
    assert!(size_of::<GdiBsPatBlt32>() == 0x40);
    assert!(offset_of!(GdiBsPatBlt32, hbrush) == 0x14);
    assert!(offset_of!(GdiBsPatBlt32, rop) == 0x18);
    assert!(offset_of!(GdiBsPatBlt32, ul_foreground_clr) == 0x34);
    // GdiAllocBatchCommand: sizeof(GDIBSEXTSELCLPRGN), sizeof(GDIBSOBJECT).
    assert!(size_of::<GdiBsExtSelClipRgn32>() == 24);
    assert!(offset_of!(GdiBsExtSelClipRgn32, rect) == 8);
    assert!(size_of::<GdiBsObject32>() == 8);
    // gdi32!GetRgnBox: `mov eax, [attr + 4]`, the rectangle from 8.
    assert!(size_of::<RgnAttr32>() == 0x18);
    assert!(size_of::<BitmapInfoHeader32>() == 40);
    assert!(offset_of!(BitmapInfoHeader32, bit_count) == 0xE);
    assert!(offset_of!(BitmapInfoHeader32, clr_important) == 0x24);
    assert!(size_of::<BrushAttr32>() == 8);
    assert!(offset_of!(BrushAttr32, color) == 4);
    assert!(offset_of!(RgnAttr32, complexity) == 4);
    assert!(offset_of!(RgnAttr32, rect) == 8);
    // GetObject: sizeof(BITMAP), sizeof(DIBSECTION) of the i386 SDK.
    assert!(size_of::<Bitmap32>() == 24);
    assert!(offset_of!(Bitmap32, planes) == 16);
    assert!(offset_of!(Bitmap32, bits) == 20);
    assert!(size_of::<DibSection32>() == 84);
    assert!(offset_of!(DibSection32, header) == 24);
    assert!(offset_of!(DibSection32, bitfields) == 64);
    assert!(offset_of!(DibSection32, section) == 76);
    assert!(offset_of!(DibSection32, offset) == 80);
};

/// BITMAP: what GetObject says of a bitmap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bitmap32 {
    /// Always 0.
    pub bm_type: i32,
    pub width: i32,
    pub height: i32,
    /// The bytes of a row: aligned on 16 bits, on 32 for a DIB section.
    pub width_bytes: i32,
    pub planes: u16,
    pub bits_pixel: u16,
    /// A DIB section's pixels in its process; 0 for another bitmap.
    pub bits: u32,
}

/// DIBSECTION: what GetObject says of a DIB section, given room for it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DibSection32 {
    pub bitmap: Bitmap32,
    pub header: BitmapInfoHeader32,
    /// Its red, green and blue masks.
    pub bitfields: [u32; 3],
    /// The application's section it was made from; 0 without one.
    pub section: u32,
    pub offset: u32,
}

/// `as_bytes` for records of integers whose sizes, checked above, leave no
/// padding.
macro_rules! as_bytes {
    ($($record:ty),*) => {$(
        impl $record {
            /// Its bytes, as they go to user mode or to the shared section.
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: a `#[repr(C)]` record of integers without padding
                // (its size is checked above): every byte is initialised.
                unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
            }
        }
    )*};
}

as_bytes!(
    GdiTableEntry32,
    GdiSharedTail32,
    DcAttr32,
    GdiBsPatBlt32,
    GdiBsExtSelClipRgn32,
    GdiBsObject32,
    RgnAttr32,
    BitmapInfoHeader32,
    BrushAttr32,
    Bitmap32,
    DibSection32
);

/// LF_FACESIZE: the characters of a face name, its NUL included.
pub const LF_FACESIZE: usize = 32;

/// LOGFONTW: a font as a client asks for it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFontW32 {
    /// Negative: the em height; positive: the cell height; 0: the default.
    pub height: i32,
    pub width: i32,
    pub escapement: i32,
    pub orientation: i32,
    /// FW_*: 0 is the default, 400 normal, 700 bold.
    pub weight: i32,
    pub italic: u8,
    pub underline: u8,
    pub strike_out: u8,
    pub char_set: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u16; LF_FACESIZE],
}

impl Default for LogFontW32 {
    fn default() -> Self {
        Self {
            height: 0,
            width: 0,
            escapement: 0,
            orientation: 0,
            weight: 0,
            italic: 0,
            underline: 0,
            strike_out: 0,
            char_set: 0,
            out_precision: 0,
            clip_precision: 0,
            quality: 0,
            pitch_and_family: 0,
            face_name: [0; LF_FACESIZE],
        }
    }
}

impl LogFontW32 {
    /// Its bytes, as they go to user mode.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: a `#[repr(C)]` record of integers without padding (5
        // LONGs, 8 BYTEs and 32 WCHARs: 92 bytes, checked below): every byte
        // is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }

    /// The font in `bytes`, as a client wrote it; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.get(..size_of::<Self>())?;
        let word = |at: usize| i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let mut face_name = [0u16; LF_FACESIZE];
        for (i, unit) in face_name.iter_mut().enumerate() {
            *unit = u16::from_le_bytes([bytes[28 + 2 * i], bytes[29 + 2 * i]]);
        }
        Some(Self {
            height: word(0),
            width: word(4),
            escapement: word(8),
            orientation: word(12),
            weight: word(16),
            italic: bytes[20],
            underline: bytes[21],
            strike_out: bytes[22],
            char_set: bytes[23],
            out_precision: bytes[24],
            clip_precision: bytes[25],
            quality: bytes[26],
            pitch_and_family: bytes[27],
            face_name,
        })
    }

    /// Its face name, up to its NUL.
    pub fn face(&self) -> &[u16] {
        let end = self.face_name.iter().position(|&unit| unit == 0).unwrap_or(LF_FACESIZE);
        &self.face_name[..end]
    }
}

const _: () = assert!(size_of::<LogFontW32>() == 92);

/// ENUMLOGFONTEXDVW, what NtGdiHfontCreate is given (`gdi32` passes no size):
/// a LOGFONTW, its full name, style and script (64, 32 and 32 characters),
/// then a DESIGNVECTOR (two words and 16 values).
pub const ENUM_LOG_FONT_EX_DV_SIZE: usize = size_of::<LogFontW32>() + 2 * (64 + 32 + 32) + 4 * (2 + 16);

/// An ENUMLOGFONTEXDVW up to its design vector's values, what GetObject
/// gives at most of a font without axes (`dvValues[dvNumAxes]`, FontGetObject).
pub const ENUM_LOG_FONT_EX_DV_NO_AXES_SIZE: usize = size_of::<LogFontW32>() + 2 * (64 + 32 + 32) + 4 * 2;

/// TEXTMETRICW.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextMetricW32 {
    pub height: i32,
    pub ascent: i32,
    pub descent: i32,
    pub internal_leading: i32,
    pub external_leading: i32,
    pub ave_char_width: i32,
    pub max_char_width: i32,
    pub weight: i32,
    pub overhang: i32,
    pub digitized_aspect_x: i32,
    pub digitized_aspect_y: i32,
    pub first_char: u16,
    pub last_char: u16,
    pub default_char: u16,
    pub break_char: u16,
    pub italic: u8,
    pub underlined: u8,
    pub struck_out: u8,
    pub pitch_and_family: u8,
    pub char_set: u8,
    /// The padding of the structure to 4 bytes.
    pub reserved: [u8; 3],
}

/// TMDIFF: the ANSI characters of a TEXTMETRICA, and the size of an
/// OUTLINETEXTMETRIC (0: not asked).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TmDiff32 {
    pub cjotma: u32,
    pub ch_first: u8,
    pub ch_last: u8,
    pub ch_default: u8,
    pub ch_break: u8,
}

/// TMW_INTERNAL: what NtGdiGetTextMetricsW writes (68 bytes, the size
/// `gdi32` passes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TmwInternal32 {
    pub text_metric: TextMetricW32,
    pub diff: TmDiff32,
}

/// GDIBSTEXTOUT: a TextOut or ExtTextOut that `gdi32` queued (GdiBCTextOut),
/// with the DC's text attributes taken when it was queued; from offset 0x50,
/// the `lpDx` values (`size` bytes) then the characters (the C structure ends
/// with a union of two characters, which its size counts).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiBsTextOut32 {
    pub header: GdiBatchHeader32,
    pub cr_foreground_clr: u32,
    pub cr_background_clr: u32,
    pub bk_mode: i32,
    pub ul_foreground_clr: u32,
    pub ul_background_clr: u32,
    pub x: i32,
    pub y: i32,
    /// ETO_*, and [`GDIBS_NORECT`] without a rectangle.
    pub options: u32,
    pub rect: Rect32,
    pub cs_cp: u32,
    /// The characters.
    pub count: u32,
    /// The bytes of the `lpDx` values before them.
    pub size: u32,
    pub hlfnt_new: u32,
    pub fl_text_align: u32,
    pub viewport_org: PointL32,
}

impl GdiBsTextOut32 {
    /// The call in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (header, word) = words(bytes, size_of::<Self>())?;
        Some(Self {
            header,
            cr_foreground_clr: word(4),
            cr_background_clr: word(8),
            bk_mode: word(0xC) as i32,
            ul_foreground_clr: word(0x10),
            ul_background_clr: word(0x14),
            x: word(0x18) as i32,
            y: word(0x1C) as i32,
            options: word(0x20),
            rect: Rect32 {
                left: word(0x24) as i32,
                top: word(0x28) as i32,
                right: word(0x2C) as i32,
                bottom: word(0x30) as i32,
            },
            cs_cp: word(0x34),
            count: word(0x38),
            size: word(0x3C),
            hlfnt_new: word(0x40),
            fl_text_align: word(0x44),
            viewport_org: PointL32 { x: word(0x48) as i32, y: word(0x4C) as i32 },
        })
    }
}

/// GDIBSEXTTEXTOUT: an ExtTextOut without characters that only fills its
/// rectangle (ETO_OPAQUE), with the background colour taken when queued.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GdiBsExtTextOut32 {
    pub header: GdiBatchHeader32,
    pub count: u32,
    pub options: u32,
    pub rect: Rect32,
    pub viewport_org: PointL32,
    pub ul_background_clr: u32,
}

impl GdiBsExtTextOut32 {
    /// The call in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (header, word) = words(bytes, size_of::<Self>())?;
        Some(Self {
            header,
            count: word(4),
            options: word(8),
            rect: Rect32 {
                left: word(0xC) as i32,
                top: word(0x10) as i32,
                right: word(0x14) as i32,
                bottom: word(0x18) as i32,
            },
            viewport_org: PointL32 { x: word(0x1C) as i32, y: word(0x20) as i32 },
            ul_background_clr: word(0x24),
        })
    }
}

/// ETO_*: options of ExtTextOut.
pub mod eto {
    pub const OPAQUE: u32 = 0x0002;
    pub const CLIPPED: u32 = 0x0004;
    pub const GLYPH_INDEX: u32 = 0x0010;
    pub const RTLREADING: u32 = 0x0080;
    pub const IGNORELANGUAGE: u32 = 0x1000;
    pub const PDY: u32 = 0x2000;
}

/// TA_*: the text alignment of a DC.
pub mod ta {
    pub const UPDATECP: u32 = 0x0001;
    pub const RIGHT: u32 = 0x0002;
    pub const CENTER: u32 = 0x0006;
    pub const BOTTOM: u32 = 0x0008;
    pub const BASELINE: u32 = 0x0018;
    /// The horizontal part: TA_LEFT (0), TA_RIGHT or TA_CENTER.
    pub const HORIZONTAL: u32 = 0x0006;
    /// The vertical part: TA_TOP (0), TA_BOTTOM or TA_BASELINE.
    pub const VERTICAL: u32 = 0x0018;
}

/// TRANSPARENT: a background mode where text leaves what is under it.
pub const TRANSPARENT: i32 = 1;
/// ANSI_CHARSET, DEFAULT_CHARSET and SYMBOL_CHARSET.
pub const ANSI_CHARSET: u8 = 0;
pub const DEFAULT_CHARSET: u8 = 1;
pub const SYMBOL_CHARSET: u8 = 2;

const _: () = {
    assert!(size_of::<LogFontW32>() == 92);
    assert!(offset_of!(LogFontW32, weight) == 16);
    assert!(offset_of!(LogFontW32, italic) == 20);
    assert!(offset_of!(LogFontW32, pitch_and_family) == 27);
    assert!(offset_of!(LogFontW32, face_name) == 28);
    assert!(ENUM_LOG_FONT_EX_DV_SIZE == 420);
    assert!(size_of::<TextMetricW32>() == 60);
    assert!(offset_of!(TextMetricW32, first_char) == 44);
    assert!(offset_of!(TextMetricW32, italic) == 52);
    assert!(offset_of!(TextMetricW32, char_set) == 56);
    assert!(size_of::<TmwInternal32>() == 0x44);
    assert!(size_of::<GdiBsTextOut32>() == 0x50);
    assert!(offset_of!(GdiBsTextOut32, options) == 0x20);
    assert!(offset_of!(GdiBsTextOut32, count) == 0x38);
    assert!(offset_of!(GdiBsTextOut32, hlfnt_new) == 0x40);
    assert!(offset_of!(GdiBsTextOut32, viewport_org) == 0x48);
    assert!(size_of::<GdiBsExtTextOut32>() == 0x28);
    assert!(offset_of!(GdiBsExtTextOut32, ul_background_clr) == 0x24);
};

as_bytes!(TmwInternal32, GdiBsTextOut32, GdiBsExtTextOut32);

// The other character sets of a LOGFONT: those of the code pages of a
// TrueType font (`OS/2` ulCodePageRange1), and OEM.
pub const SHIFTJIS_CHARSET: u8 = 128;
pub const HANGEUL_CHARSET: u8 = 129;
pub const JOHAB_CHARSET: u8 = 130;
pub const GB2312_CHARSET: u8 = 134;
pub const CHINESEBIG5_CHARSET: u8 = 136;
pub const GREEK_CHARSET: u8 = 161;
pub const TURKISH_CHARSET: u8 = 162;
pub const VIETNAMESE_CHARSET: u8 = 163;
pub const HEBREW_CHARSET: u8 = 177;
pub const ARABIC_CHARSET: u8 = 178;
pub const BALTIC_CHARSET: u8 = 186;
pub const RUSSIAN_CHARSET: u8 = 204;
pub const THAI_CHARSET: u8 = 222;
pub const EASTEUROPE_CHARSET: u8 = 238;
pub const OEM_CHARSET: u8 = 255;

// lfPitchAndFamily: the pitch (low bits) and the family (high bits).
pub const FIXED_PITCH: u8 = 1;
pub const VARIABLE_PITCH: u8 = 2;
pub const FF_MODERN: u8 = 0x30;

// The precisions and quality of an enumerated TrueType font.
pub const OUT_OUTLINE_PRECIS: u8 = 8;
pub const CLIP_DEFAULT_PRECIS: u8 = 0;
pub const PROOF_QUALITY: u8 = 2;

// The FontType of an enumerated font.
pub const RASTER_FONTTYPE: u32 = 0x0001;
pub const TRUETYPE_FONTTYPE: u32 = 0x0004;

// ntmFlags.
pub const NTM_ITALIC: u32 = 0x01;
pub const NTM_BOLD: u32 = 0x20;
pub const NTM_REGULAR: u32 = 0x40;

/// LF_FULLFACESIZE: the characters of a full name, its NUL included.
pub const LF_FULLFACESIZE: usize = 64;

/// ENUMLOGFONTEXW: a LOGFONTW, the full name, the style and the script of an
/// enumerated font.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumLogFontExW32 {
    pub log_font: LogFontW32,
    pub full_name: [u16; LF_FULLFACESIZE],
    pub style: [u16; LF_FACESIZE],
    pub script: [u16; LF_FACESIZE],
}

impl Default for EnumLogFontExW32 {
    fn default() -> Self {
        Self {
            log_font: LogFontW32::default(),
            full_name: [0; LF_FULLFACESIZE],
            style: [0; LF_FACESIZE],
            script: [0; LF_FACESIZE],
        }
    }
}

/// NEWTEXTMETRICW: a TEXTMETRICW and what an enumeration adds to it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewTextMetricW32 {
    pub text_metric: TextMetricW32,
    /// NTM_*.
    pub flags: u32,
    /// ntmSizeEM: the em square, in font units.
    pub size_em: u32,
    /// ntmCellHeight: the cell, in font units.
    pub cell_height: u32,
    pub avg_width: u32,
}

/// FONTSIGNATURE: the Unicode ranges and the code pages of a font.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FontSignature32 {
    pub usb: [u32; 4],
    pub csb: [u32; 2],
}

/// NEWTEXTMETRICEXW.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewTextMetricExW32 {
    pub ntm: NewTextMetricW32,
    pub signature: FontSignature32,
}

/// FONTFAMILYINFO (ReactOS's `ntgdibad.h`): one font of
/// NtGdiGetFontFamilyInfo, which gdi32's EnumFontFamiliesEx hands to its
/// callback.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FontFamilyInfo32 {
    pub enum_log_font: EnumLogFontExW32,
    pub new_text_metric: NewTextMetricExW32,
    /// RASTER_FONTTYPE, TRUETYPE_FONTTYPE.
    pub font_type: u32,
}

const _: () = {
    assert!(size_of::<EnumLogFontExW32>() == 348);
    assert!(offset_of!(EnumLogFontExW32, full_name) == 92);
    assert!(offset_of!(EnumLogFontExW32, style) == 220);
    assert!(offset_of!(EnumLogFontExW32, script) == 284);
    assert!(size_of::<NewTextMetricW32>() == 76);
    assert!(offset_of!(NewTextMetricW32, flags) == 60);
    assert!(size_of::<FontSignature32>() == 24);
    assert!(size_of::<NewTextMetricExW32>() == 100);
    assert!(size_of::<FontFamilyInfo32>() == 452);
    assert!(offset_of!(FontFamilyInfo32, new_text_metric) == 348);
    assert!(offset_of!(FontFamilyInfo32, font_type) == 448);
};

as_bytes!(FontFamilyInfo32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_queued_pat_blt_reads_back_from_its_bytes() {
        let call = GdiBsPatBlt32 {
            header: GdiBatchHeader32 { size: 0x40, cmd: batch::PAT_BLT },
            x: -3,
            y: 4,
            width: 100,
            height: -50,
            hbrush: 0x0090_0010,
            rop: rop::PATCOPY,
            cr_brush_clr: 0x00FF_FFFF,
            viewport_org: PointL32 { x: 1, y: 2 },
            ul_brush_clr: 7,
            ..GdiBsPatBlt32::default()
        };
        assert_eq!(GdiBsPatBlt32::from_bytes(call.as_bytes()), Some(call));
        assert_eq!(GdiBsPatBlt32::from_bytes(&call.as_bytes()[..0x3F]), None, "one byte short");
    }

    #[test]
    fn queued_clips_and_deletions_and_region_attributes_read_back() {
        let clip = GdiBsExtSelClipRgn32 {
            header: GdiBatchHeader32 { size: 24, cmd: batch::EXT_SEL_CLIP_RGN },
            mode: rgn::COPY as u32 | GDIBS_NORECT,
            rect: Rect32 { left: -1, top: 2, right: 30, bottom: 40 },
        };
        assert_eq!(GdiBsExtSelClipRgn32::from_bytes(clip.as_bytes()), Some(clip));
        assert_eq!(GdiBsExtSelClipRgn32::from_bytes(&clip.as_bytes()[..23]), None);
        let delete = GdiBsObject32 { header: GdiBatchHeader32 { size: 8, cmd: batch::DEL_RGN }, handle: 0x0104_0123 };
        assert_eq!(GdiBsObject32::from_bytes(delete.as_bytes()), Some(delete));
        assert_eq!(GdiBsObject32::from_bytes(&delete.as_bytes()[..7]), None);
        let attr = RgnAttr32 {
            attr_flags: ATTR_RGN_DIRTY,
            complexity: 2,
            rect: Rect32 { left: 1, top: 2, right: 3, bottom: 4 },
        };
        assert_eq!(RgnAttr32::from_bytes(attr.as_bytes()), Some(attr));
        assert_eq!(RgnAttr32::from_bytes(&attr.as_bytes()[..0x17]), None);
    }

    #[test]
    fn a_new_dc_selects_its_brush_with_the_default_modes() {
        let attr = DcAttr32::initial(0x0190_0010, 0, 1280, 800);
        let bytes = attr.as_bytes();
        assert_eq!(&bytes[8..12], &0x0190_0010u32.to_le_bytes());
        assert_eq!(attr.dirty & dirty::DIRTY_FILL, dirty::DIRTY_FILL, "the brush to realise");
        assert_eq!(attr.dirty & dirty::DC_DIBSECTION, 0, "PatBlt queues");
        assert_eq!((attr.cr_background_clr, attr.cr_foreground_clr), (0x00FF_FFFF, 0));
        assert_eq!((attr.map_mode, attr.bk_mode, attr.rop2), (MM_TEXT, OPAQUE, R2_COPYPEN));
        assert_eq!((attr.window_ext, attr.viewport_ext), (PointL32 { x: 1, y: 1 }, PointL32 { x: 1, y: 1 }));
    }

    #[test]
    fn entries_follow_each_other_then_the_tail() {
        assert_eq!(gdi_entry_offset(0), 0);
        assert_eq!(gdi_entry_offset(10), 0xA0);
        assert_eq!(gdi_entry_offset(GDI_HANDLE_COUNT), GDI_SHARED_TAIL);
    }
}
