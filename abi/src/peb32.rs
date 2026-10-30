//! PEB32 (CLAUDE.md, rule 5): the Process Environment Block that an i386
//! process sees, laid out as on XP SP2. ReactOS's NDK headers serve as the
//! specification of the format; offsets are checked at compile time.
//!
//! The PEB has a page of its own; its heap list (`process_heaps`) follows it
//! in that page.
//!
//! Moved from `ps::peb` (audit §3.2), whose offsets after 0x20 were not those
//! of XP: the OS version is at 0xA4, not 0x74.

use core::mem::{offset_of, size_of};

/// UNICODE_STRING as an i386 process sees it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnicodeString32 {
    /// In bytes, without the terminator.
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u32,
}

/// The OS version every PEB shows (ADR-003): XP 5.1.2600 SP2.
pub const OS_MAJOR_VERSION: u32 = 5;
pub const OS_MINOR_VERSION: u32 = 1;
pub const OS_BUILD_NUMBER: u16 = 2600;
/// Service pack 2.0, as `(major << 8) | minor`.
pub const OS_CSD_VERSION: u16 = 0x0200;
/// VER_PLATFORM_WIN32_NT.
pub const OS_PLATFORM_ID: u32 = 2;

/// The XP x86 PEB.
#[repr(C)]
pub struct Peb32 {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    /// IsDebuggerPresent.
    pub being_debugged: u8,
    pub spare_bool: u8,
    pub mutant: u32,
    /// GetModuleHandle(NULL).
    pub image_base_address: u32,
    pub ldr: u32,
    pub process_parameters: u32,
    pub sub_system_data: u32,
    /// GetProcessHeap.
    pub process_heap: u32,
    pub fast_peb_lock: u32,
    pub fast_peb_lock_routine: u32,
    pub fast_peb_unlock_routine: u32,
    pub environment_update_count: u32,
    pub kernel_callback_table: u32,
    pub system_reserved: u32,
    pub atl_thunk_slist_ptr32: u32,
    pub free_list: u32,
    pub tls_expansion_counter: u32,
    pub tls_bitmap: u32,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: u32,
    pub read_only_shared_memory_heap: u32,
    pub read_only_static_server_data: u32,
    pub ansi_code_page_data: u32,
    pub oem_code_page_data: u32,
    pub unicode_case_table_data: u32,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    _align: u32,
    /// In 100 ns units, negative (relative).
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: u32,
    pub heap_segment_commit: u32,
    pub heap_decommit_total_free_threshold: u32,
    pub heap_decommit_free_block_threshold: u32,
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: u32,
    pub gdi_shared_handle_table: u32,
    pub process_starter_helper: u32,
    pub gdi_dc_attribute_list: u32,
    pub loader_lock: u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub image_process_affinity_mask: u32,
    pub gdi_handle_buffer: [u32; 34],
    pub post_process_init_routine: u32,
    pub tls_expansion_bitmap: u32,
    pub tls_expansion_bitmap_bits: [u32; 32],
    pub session_id: u32,
    pub app_compat_flags: u64,
    pub app_compat_flags_user: u64,
    pub shim_data: u32,
    pub app_compat_info: u32,
    pub csd_version: UnicodeString32,
    pub activation_context_data: u32,
    pub process_assembly_storage_map: u32,
    pub system_default_activation_context_data: u32,
    pub system_assembly_storage_map: u32,
    pub minimum_stack_commit: u32,
    _tail: u32,
}

const _: () = {
    assert!(size_of::<UnicodeString32>() == 8);
    assert!(size_of::<Peb32>() == 0x210);
    assert!(offset_of!(Peb32, being_debugged) == 0x02);
    assert!(offset_of!(Peb32, image_base_address) == 0x08);
    assert!(offset_of!(Peb32, ldr) == 0x0C);
    assert!(offset_of!(Peb32, process_parameters) == 0x10);
    assert!(offset_of!(Peb32, process_heap) == 0x18);
    assert!(offset_of!(Peb32, kernel_callback_table) == 0x2C);
    assert!(offset_of!(Peb32, tls_bitmap) == 0x40);
    assert!(offset_of!(Peb32, ansi_code_page_data) == 0x58);
    assert!(offset_of!(Peb32, number_of_processors) == 0x64);
    assert!(offset_of!(Peb32, nt_global_flag) == 0x68);
    assert!(offset_of!(Peb32, critical_section_timeout) == 0x70);
    assert!(offset_of!(Peb32, heap_segment_reserve) == 0x78);
    assert!(offset_of!(Peb32, number_of_heaps) == 0x88);
    assert!(offset_of!(Peb32, process_heaps) == 0x90);
    assert!(offset_of!(Peb32, loader_lock) == 0xA0);
    assert!(offset_of!(Peb32, os_major_version) == 0xA4);
    assert!(offset_of!(Peb32, os_minor_version) == 0xA8);
    assert!(offset_of!(Peb32, os_build_number) == 0xAC);
    assert!(offset_of!(Peb32, os_csd_version) == 0xAE);
    assert!(offset_of!(Peb32, os_platform_id) == 0xB0);
    assert!(offset_of!(Peb32, image_subsystem) == 0xB4);
    assert!(offset_of!(Peb32, image_process_affinity_mask) == 0xC0);
    assert!(offset_of!(Peb32, gdi_handle_buffer) == 0xC4);
    assert!(offset_of!(Peb32, post_process_init_routine) == 0x14C);
    assert!(offset_of!(Peb32, tls_expansion_bitmap_bits) == 0x154);
    assert!(offset_of!(Peb32, session_id) == 0x1D4);
    assert!(offset_of!(Peb32, app_compat_flags) == 0x1D8);
    assert!(offset_of!(Peb32, csd_version) == 0x1F0);
    assert!(offset_of!(Peb32, minimum_stack_commit) == 0x208);
};

impl Peb32 {
    /// A PEB with every field zero.
    pub fn zeroed() -> Self {
        // SAFETY: every field is an integer or an array of integers, for
        // which all-zero bytes are a valid value.
        unsafe { core::mem::zeroed() }
    }

    /// A zeroed PEB showing XP 5.1.2600 SP2 (ADR-003), for the image at
    /// `image_base`.
    pub fn xp(image_base: u32) -> Self {
        let mut peb = Self::zeroed();
        peb.image_base_address = image_base;
        peb.os_major_version = OS_MAJOR_VERSION;
        peb.os_minor_version = OS_MINOR_VERSION;
        peb.os_build_number = OS_BUILD_NUMBER;
        peb.os_csd_version = OS_CSD_VERSION;
        peb.os_platform_id = OS_PLATFORM_ID;
        peb.number_of_processors = 1;
        peb
    }

    /// Its bytes, as they go into the process.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: the struct has no implicit padding (explicit `_align` and
        // `_tail`, size checked above) and only integer fields: every byte is
        // initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_xp_peb_shows_5_1_2600_sp2() {
        let peb = Peb32::xp(0x40_0000);
        assert_eq!((peb.os_major_version, peb.os_minor_version, peb.os_build_number), (5, 1, 2600));
        assert_eq!((peb.os_csd_version, peb.os_platform_id), (0x0200, 2));
        assert_eq!((peb.image_base_address, peb.being_debugged, peb.nt_global_flag), (0x40_0000, 0, 0));
    }

    #[test]
    fn the_bytes_put_each_field_at_its_xp_offset() {
        let peb = Peb32::xp(0x0040_0000);
        let bytes = peb.as_bytes();
        let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        assert_eq!(bytes.len(), 0x210);
        assert_eq!(u32_at(0x08), 0x0040_0000, "ImageBaseAddress");
        assert_eq!(u32_at(0x64), 1, "NumberOfProcessors");
        assert_eq!((u32_at(0xA4), u32_at(0xA8), u32_at(0xB0)), (5, 1, 2), "OSMajor/MinorVersion, OSPlatformId");
        assert_eq!(u16::from_le_bytes([bytes[0xAC], bytes[0xAD]]), 2600, "OSBuildNumber");
    }
}
