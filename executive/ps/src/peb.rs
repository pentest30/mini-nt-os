//! PEB — Process Environment Block (XP x86 layout).
//!
//! The PEB lives in user-mode address space and is read by:
//!   - ntdll (loader, heap, TLS)
//!   - kernel32 (GetCommandLineW, GetModuleHandle, etc.)
//!   - Games directly (heap pointer, OS version check)
//!
//! CRITICAL: field offsets must match XP x86 exactly.
//! Games compiled for XP32 use hard-coded offsets.
//! We target a 64-bit kernel but games are 32-bit PE32 — the PEB
//! they see must be the 32-bit layout (Wow64 PEB).

/// XP x86 (32-bit) PEB layout.
/// Reference: Geoff Chappell winternl.h / ReactOS include/ndk/pstypes.h
#[repr(C, packed)]
pub struct Peb32 {
    pub inherited_address_space:    u8,         // 0x00
    pub read_image_file_exec_opts:  u8,         // 0x01
    pub being_debugged:             u8,         // 0x02  ← IsDebuggerPresent()
    pub bit_field:                  u8,         // 0x03
    pub mutant:                     u32,        // 0x04
    pub image_base_address:         u32,        // 0x08  ← GetModuleHandle(NULL)
    pub ldr:                        u32,        // 0x0C  → PEB_LDR_DATA *
    pub process_parameters:         u32,        // 0x10  → RTL_USER_PROCESS_PARAMETERS *
    pub sub_system_data:            u32,        // 0x14
    pub process_heap:               u32,        // 0x18  ← GetProcessHeap()
    pub fast_peb_lock:              u32,        // 0x1C
    _pad1:                          [u8; 0x54], // 0x20–0x73 (skipped fields)
    pub os_major_version:           u32,        // 0x74  ← must be 5 (XP)
    pub os_minor_version:           u32,        // 0x78  ← must be 1 (XP)
    pub os_build_number:            u16,        // 0x7C  ← 2600 (XP RTM) or 2600 SP3
    pub os_csd_version:             u16,        // 0x7E
    pub os_platform_id:             u32,        // 0x80  ← 2 = VER_PLATFORM_WIN32_NT
    pub image_subsystem:            u32,        // 0x84
    pub image_subsystem_major_ver:  u32,        // 0x88
    pub image_subsystem_minor_ver:  u32,        // 0x8C
    _pad2:                          [u8; 0x14], // 0x90–0xA3
    pub number_of_processors:       u32,        // 0xA4
    pub nt_global_flag:             u32,        // 0xA8
}

impl Peb32 {
    /// Initialise a PEB with XP-compatible OS version fields.
    /// `image_base` — base address of the main .exe.
    /// `heap_base`  — address of the default process heap.
    pub fn new_xp(image_base: u32, heap_base: u32) -> Self {
        let mut peb: Peb32 = unsafe { core::mem::zeroed() };
        peb.image_base_address       = image_base;
        peb.process_heap             = heap_base;
        peb.os_major_version         = 5;      // Windows XP
        peb.os_minor_version         = 1;
        peb.os_build_number          = 2600;   // XP SP2 build
        peb.os_csd_version           = 0x0200; // Service Pack 2
        peb.os_platform_id           = 2;      // VER_PLATFORM_WIN32_NT
        peb.image_subsystem          = 2;      // IMAGE_SUBSYSTEM_WINDOWS_GUI
        peb.image_subsystem_major_ver = 4;
        peb.image_subsystem_minor_ver = 0;
        peb.number_of_processors     = 1;
        peb
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
// These verify the XP-compatible PEB field values and critical byte offsets.
// Games hard-code offsets into the PEB; any layout change breaks them.
//
// Key fields games read:
//   PEB+0x02  BeingDebugged  (IsDebuggerPresent)
//   PEB+0x08  ImageBaseAddress
//   PEB+0x18  ProcessHeap
//   PEB+0x74  OSMajorVersion → must be 5
//   PEB+0x78  OSMinorVersion → must be 1
//   PEB+0x7C  OSBuildNumber  → must be 2600

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    // ── T3-2a: XP OS version fields (CRITICAL — games check these) ──────────

    #[test]
    fn os_major_version_is_5() {
        let peb = Peb32::new_xp(0x0040_0000, 0x0010_0000);
        assert_eq!({ peb.os_major_version }, 5, "must report Windows XP (5.1)");
    }

    #[test]
    fn os_minor_version_is_1() {
        let peb = Peb32::new_xp(0x0040_0000, 0x0010_0000);
        assert_eq!({ peb.os_minor_version }, 1);
    }

    #[test]
    fn os_build_number_is_2600() {
        let peb = Peb32::new_xp(0x0040_0000, 0x0010_0000);
        assert_eq!({ peb.os_build_number }, 2600);
    }

    #[test]
    fn os_platform_id_is_nt() {
        let peb = Peb32::new_xp(0x0040_0000, 0x0010_0000);
        assert_eq!({ peb.os_platform_id }, 2, "VER_PLATFORM_WIN32_NT");
    }

    // ── T3-2b: critical field offsets ────────────────────────────────────────

    #[test]
    fn being_debugged_at_offset_0x02() {
        assert_eq!(offset_of!(Peb32, being_debugged), 0x02);
    }

    #[test]
    fn image_base_address_at_offset_0x08() {
        assert_eq!(offset_of!(Peb32, image_base_address), 0x08);
    }

    #[test]
    fn process_heap_at_offset_0x18() {
        assert_eq!(offset_of!(Peb32, process_heap), 0x18);
    }

    #[test]
    fn os_major_version_at_offset_0x74() {
        assert_eq!(offset_of!(Peb32, os_major_version), 0x74);
    }

    #[test]
    fn os_minor_version_at_offset_0x78() {
        assert_eq!(offset_of!(Peb32, os_minor_version), 0x78);
    }

    #[test]
    fn os_build_number_at_offset_0x7c() {
        assert_eq!(offset_of!(Peb32, os_build_number), 0x7C);
    }

    // ── T3-2c: init values ───────────────────────────────────────────────────

    #[test]
    fn new_xp_sets_image_base() {
        let peb = Peb32::new_xp(0x0042_0000, 0x0010_0000);
        assert_eq!({ peb.image_base_address }, 0x0042_0000);
    }

    #[test]
    fn new_xp_sets_process_heap() {
        let peb = Peb32::new_xp(0x0040_0000, 0xDEAD_BEEF);
        assert_eq!({ peb.process_heap }, 0xDEAD_BEEF);
    }

    #[test]
    fn being_debugged_is_zero_by_default() {
        let peb = Peb32::new_xp(0x0040_0000, 0x0010_0000);
        assert_eq!(peb.being_debugged, 0, "IsDebuggerPresent must return false");
    }
}
