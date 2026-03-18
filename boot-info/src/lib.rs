//! BootInfo — ABI contract between bootloader and kernel.
//!
//! This crate is `no_std` with zero dependencies. Both `bootloader` and
//! `kernel` depend on it so the struct layout is guaranteed identical.
//!
//! # Layout stability
//! All types are `#[repr(C)]`. Never reorder or remove fields — the
//! bootloader writes this structure into physical memory before jumping
//! to `kernel_main`, so any mismatch silently corrupts the kernel.

#![no_std]

/// Maximum number of memory regions reported by the bootloader.
/// 256 is enough for any QEMU or real machine memory map.
pub const MEMORY_MAP_MAX: usize = 256;

// ── Top-level handoff struct ─────────────────────────────────────────────────

/// Passed (by reference) from the bootloader to `kernel_main`.
///
/// The bootloader fills every field before calling `ExitBootServices`.
/// The kernel must treat this as read-only after receipt.
///
/// # Safety
/// The pointer fields (`memory_map_ptr`) point into the bootloader's own
/// static storage, which remains valid because UEFI boot-services memory
/// is no longer reclaimed after `ExitBootServices` (it becomes conventional
/// memory — we mark it `MemoryKind::UefiRuntime` and avoid reusing it until
/// Phase 2 when the kernel explicitly reclaims it).
#[repr(C)]
#[derive(Debug)]
pub struct BootInfo {
    /// Magic value — must equal [`BOOT_INFO_MAGIC`].
    /// Kernel checks this before reading any other field.
    pub magic: u64,

    /// Physical address where the kernel image was loaded.
    /// On x86_64 this is always `0x0010_0000` (1 MiB mark).
    pub kernel_phys_base: u64,

    /// Size of the kernel image in bytes.
    pub kernel_size: u64,

    /// Virtual base of the Higher-Half Direct Map.
    /// Any physical address `p` is accessible at `hhdm_offset + p`.
    /// Set to `0xFFFF_8000_0000_0000` (matches CLAUDE.md kernel-mode base).
    pub hhdm_offset: u64,

    /// Physical address of the ACPI RSDP structure.
    /// Used by the HAL to locate the MADT and find the local APIC base.
    /// `0` if the firmware did not provide one (QEMU always provides it).
    pub rsdp_phys: u64,

    /// Physical base address of an optional RAM disk image loaded by bootloader.
    /// `0` when no RAM disk was provided.
    pub ramdisk_phys_base: u64,

    /// Size in bytes of the optional RAM disk image.
    pub ramdisk_size: u64,

    /// Number of valid entries in `memory_map`.
    pub memory_map_len: u32,

    _pad: u32,

    /// GOP linear framebuffer info. `framebuffer.is_valid()` returns false
    /// if GOP was not available (headless / serial-only mode).
    pub framebuffer: FramebufferInfo,

    /// Physical memory map provided by UEFI.
    pub memory_map: [MemoryRegion; MEMORY_MAP_MAX],
}

/// Sentinel value stored in `BootInfo::magic`.
/// ASCII "MINOBOOT" → `0x544F4F42_4F4E494D`.
pub const BOOT_INFO_MAGIC: u64 = 0x544F4F42_4F4E494Du64;

impl BootInfo {
    /// Create a zeroed-out `BootInfo` with the magic pre-filled.
    /// The bootloader calls this, then populates each field.
    pub const fn new() -> Self {
        Self {
            magic:            BOOT_INFO_MAGIC,
            kernel_phys_base: 0,
            kernel_size:      0,
            hhdm_offset:      0xFFFF_8000_0000_0000,
            rsdp_phys:        0,
            ramdisk_phys_base: 0,
            ramdisk_size:      0,
            memory_map_len:   0,
            _pad:             0,
            framebuffer:      FramebufferInfo::zeroed(),
            memory_map:       [MemoryRegion::zeroed(); MEMORY_MAP_MAX],
        }
    }

    /// Return only the valid slice of the memory map.
    #[inline]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.memory_map[..self.memory_map_len as usize]
    }

    /// Validate magic; returns `false` if the struct was not written by the
    /// Mino bootloader (e.g. wrong address passed by firmware).
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC
    }
}

// ── Memory map ───────────────────────────────────────────────────────────────

/// A contiguous physical memory region as reported by UEFI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryRegion {
    /// Classification of this region.
    pub kind: MemoryKind,
    /// First page frame number of this region.
    pub start_pfn: u64,
    /// Number of 4 KiB pages in this region.
    pub page_count: u64,
}

impl MemoryRegion {
    pub const fn zeroed() -> Self {
        Self {
            kind:       MemoryKind::Reserved,
            start_pfn:  0,
            page_count: 0,
        }
    }

    /// Physical start address of the region.
    #[inline]
    pub fn phys_start(&self) -> u64 {
        self.start_pfn * 4096
    }

    /// Physical end address (exclusive).
    #[inline]
    pub fn phys_end(&self) -> u64 {
        (self.start_pfn + self.page_count) * 4096
    }
}

/// Classification of a physical memory region.
///
/// Variants match the UEFI memory type taxonomy, collapsed to what the
/// Mino kernel actually needs to distinguish.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MemoryKind {
    /// Available for general use by the kernel / buddy allocator.
    Usable = 0,
    /// Firmware/hardware reserved — do not touch.
    #[default]
    Reserved = 1,
    /// ACPI tables — reclaimable after ACPI init (Phase 2).
    AcpiReclaimable = 2,
    /// UEFI runtime services — must remain mapped for firmware calls.
    UefiRuntime = 3,
    /// The kernel image itself — excluded from buddy allocator.
    KernelImage = 4,
    /// Bootloader stack / data — reclaimable after `kernel_main` starts.
    BootloaderReclaimable = 5,
    /// Framebuffer — mapped separately if needed.
    Framebuffer = 6,
}

impl MemoryKind {
    /// Returns `true` if the buddy allocator should own these pages.
    #[inline]
    pub fn is_usable(self) -> bool {
        matches!(self, MemoryKind::Usable)
    }
}

// ── Framebuffer ───────────────────────────────────────────────────────────────

/// GOP linear framebuffer descriptor filled by the bootloader.
///
/// The kernel accesses the framebuffer at `hhdm_offset + base` (physical
/// address mapped into the HHDM by the bootloader's identity map).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical base address of the linear framebuffer.
    pub base:   u64,
    /// Horizontal resolution in pixels.
    pub width:  u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Pixels per scan line (may be > `width` due to hardware alignment).
    pub stride: u32,
    /// Pixel colour layout.
    pub format: PixelFormat,
}

impl FramebufferInfo {
    pub const fn zeroed() -> Self {
        Self { base: 0, width: 0, height: 0, stride: 0, format: PixelFormat::Unknown }
    }

    /// Returns `true` if the bootloader successfully located a GOP framebuffer.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.base != 0 && self.width > 0 && self.height > 0
    }
}

/// Pixel colour component order as reported by UEFI GOP.
///
/// In both cases each pixel occupies 4 bytes (the 4th byte is reserved / padding).
///
/// - `Bgr`: memory order is `[B, G, R, _]` — write `0x00RRGGBB` as a `u32` directly.
/// - `Rgb`: memory order is `[R, G, B, _]` — swap R and B before writing.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Unknown = 0,
    /// Blue byte first in memory (most common on x86 hardware / QEMU / VBox).
    Bgr = 1,
    /// Red byte first in memory.
    Rgb = 2,
}
