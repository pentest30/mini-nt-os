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

/// RGN_ATTR: a region's complexity and bounding rectangle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RgnAttr32 {
    pub attr_flags: u32,
    /// NULLREGION, SIMPLEREGION or COMPLEXREGION.
    pub complexity: u32,
    pub rect: Rect32,
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

/// Raster operations of PatBlt (ROP3, with their legacy low word).
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
    /// The stock objects (`STOCK_LAST + 1`).
    pub const COUNT: usize = 21;
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
};

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

as_bytes!(GdiTableEntry32, GdiSharedTail32, DcAttr32, GdiBsPatBlt32);

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
