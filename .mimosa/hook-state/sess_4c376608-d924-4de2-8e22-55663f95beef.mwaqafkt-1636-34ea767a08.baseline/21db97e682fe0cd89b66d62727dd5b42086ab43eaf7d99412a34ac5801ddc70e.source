//! What `NtQueryVirtualMemory` returns to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2, and the values of the section services. ReactOS's NDK headers (`mmtypes.h`) serve
//! as the specification of the format; offsets are checked at compile time.

use core::mem::{offset_of, size_of};

/// Allocation attributes of a section (NtCreateSection).
pub const SEC_BASED: u32 = 0x0020_0000;
pub const SEC_NO_CHANGE: u32 = 0x0040_0000;
pub const SEC_FILE: u32 = 0x0080_0000;
pub const SEC_IMAGE: u32 = 0x0100_0000;
pub const SEC_RESERVE: u32 = 0x0400_0000;
pub const SEC_COMMIT: u32 = 0x0800_0000;
pub const SEC_NOCACHE: u32 = 0x1000_0000;

/// `SECTION_INHERIT` (NtMapViewOfSection).
pub const VIEW_SHARE: u32 = 1;
pub const VIEW_UNMAP: u32 = 2;

/// MemoryBasicInformation: the range of pages of the same state and
/// protection that starts at an address.
pub const MEMORY_BASIC_INFORMATION: u32 = 0;

/// MEMORY_BASIC_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryBasicInformation32 {
    /// The page the range starts at.
    pub base_address: u32,
    /// The start of its reservation; 0 for a free range.
    pub allocation_base: u32,
    /// The protection the reservation was made with (`PAGE_*`).
    pub allocation_protect: u32,
    pub region_size: u32,
    /// `MEM_COMMIT`, `MEM_RESERVE` or `MEM_FREE`.
    pub state: u32,
    /// The protection of its pages, if committed (`PAGE_*`).
    pub protect: u32,
    /// `MEM_PRIVATE`, `MEM_MAPPED` or `MEM_IMAGE`; 0 for a free range.
    pub kind: u32,
}

const _: () = {
    assert!(size_of::<MemoryBasicInformation32>() == 0x1C);
    assert!(offset_of!(MemoryBasicInformation32, allocation_protect) == 0x08);
    assert!(offset_of!(MemoryBasicInformation32, region_size) == 0x0C);
    assert!(offset_of!(MemoryBasicInformation32, state) == 0x10);
    assert!(offset_of!(MemoryBasicInformation32, protect) == 0x14);
    assert!(offset_of!(MemoryBasicInformation32, kind) == 0x18);
};

impl MemoryBasicInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: seven u32 fields, no padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

/// NtQuerySection's classes: SectionBasicInformation, SectionImageInformation.
pub const SECTION_BASIC_INFORMATION: u32 = 0;
pub const SECTION_IMAGE_INFORMATION: u32 = 1;

/// SECTION_BASIC_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionBasicInformation32 {
    /// The base of a based section (`SEC_BASED`); 0 otherwise.
    pub base_address: u32,
    /// `SEC_IMAGE`, `SEC_FILE`, `SEC_COMMIT`…
    pub attributes: u32,
    /// Its size in bytes; the image's in memory for an image.
    pub size: i64,
}

const _: () = {
    assert!(size_of::<SectionBasicInformation32>() == 0x10);
    assert!(offset_of!(SectionBasicInformation32, attributes) == 0x04);
    assert!(offset_of!(SectionBasicInformation32, size) == 0x08);
};

/// SECTION_IMAGE_INFORMATION, as XP SP2 lays it out: what an image section
/// knows of its PE, for the process made from it (RtlCreateUserProcess).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionImageInformation32 {
    /// The entry point at the image's preferred base.
    pub transfer_address: u32,
    pub zero_bits: u32,
    /// The stack of its threads: reserved, then committed.
    pub maximum_stack_size: u32,
    pub committed_stack_size: u32,
    /// `IMAGE_SUBSYSTEM_*`, and its version.
    pub sub_system_type: u32,
    pub sub_system_minor_version: u16,
    pub sub_system_major_version: u16,
    pub gp_value: u32,
    /// `IMAGE_FILE_*` of the file header.
    pub image_characteristics: u16,
    pub dll_characteristics: u16,
    /// `IMAGE_FILE_MACHINE_*`.
    pub machine: u16,
    /// A BOOLEAN.
    pub image_contains_code: u8,
    pub image_flags: u8,
    pub loader_flags: u32,
    /// The size of the image's file.
    pub image_file_size: u32,
    pub reserved: u32,
}

const _: () = {
    assert!(size_of::<SectionImageInformation32>() == 0x30);
    assert!(offset_of!(SectionImageInformation32, maximum_stack_size) == 0x08);
    assert!(offset_of!(SectionImageInformation32, sub_system_type) == 0x10);
    assert!(offset_of!(SectionImageInformation32, sub_system_minor_version) == 0x14);
    assert!(offset_of!(SectionImageInformation32, sub_system_major_version) == 0x16);
    assert!(offset_of!(SectionImageInformation32, gp_value) == 0x18);
    assert!(offset_of!(SectionImageInformation32, image_characteristics) == 0x1C);
    assert!(offset_of!(SectionImageInformation32, machine) == 0x20);
    assert!(offset_of!(SectionImageInformation32, image_contains_code) == 0x22);
    assert!(offset_of!(SectionImageInformation32, loader_flags) == 0x24);
    assert!(offset_of!(SectionImageInformation32, image_file_size) == 0x28);
};

impl SectionBasicInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: two u32 and an i64, no padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

impl SectionImageInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: fields laid out back to back, no padding (offsets and size
        // checked above): every byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}
