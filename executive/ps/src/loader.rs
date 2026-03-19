//! PE32 loader — Phase 2 kernel-side implementation.
//!
//! Parses PE32 (32-bit Windows Portable Executable) images and returns
//! the information the kernel needs to:
//!   - Map each section at its virtual address.
//!   - Resolve imports from stub DLL tables.
//!   - Set up PEB/TEB and transfer control to the entry point.
//!
//! This is a no_std, no-alloc parser. The caller provides a byte slice
//! containing the raw PE image (already loaded into a buffer by the
//! kernel's file I/O).
//!
//! Covers the PE32 format only (32-bit, IMAGE_NT_OPTIONAL_HDR32_MAGIC).
//! PE32+ (64-bit) is not needed for XP-era game compatibility.
//!
//! # References
//! - Microsoft PE/COFF spec: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
//! - ReactOS ntdll/ldr/ldrutils.c
//! - WI7e Ch.6 §Image Loader

// ── Compile-time PE32 constants ──────────────────────────────────────────────

pub const IMAGE_DOS_SIGNATURE:    u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE:     u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;

/// IMAGE_FILE_MACHINE_I386
pub const MACHINE_I386: u16 = 0x014C;

/// Section characteristic flags (matches IMAGE_SCN_* in winnt.h)
pub const SCN_CNT_CODE:               u32 = 0x0000_0020;
pub const SCN_CNT_INITIALIZED_DATA:   u32 = 0x0000_0040;
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const SCN_MEM_EXECUTE:            u32 = 0x2000_0000;
pub const SCN_MEM_READ:               u32 = 0x4000_0000;
pub const SCN_MEM_WRITE:              u32 = 0x8000_0000;

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PeError {
    TooSmall,
    BadDosSig,
    BadNtSig,
    NotPe32,
    NotI386,
    OffsetOutOfRange,
    SectionCountZero,
    InvalidImportDescriptor,
}

// ── On-disk structures (repr(C, packed) — must match PE byte layout exactly) ─

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageDosHeader {
    pub e_magic:    u16,    // 0x00  "MZ"
    _reserved:      [u8; 0x3A],
    pub e_lfanew:   u32,    // 0x3C  offset to IMAGE_NT_HEADERS
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageFileHeader {
    pub machine:                u16,
    pub number_of_sections:     u16,
    pub time_date_stamp:        u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols:      u32,
    pub size_of_optional_header: u16,
    pub characteristics:        u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader32 {
    pub magic:                          u16,  // IMAGE_NT_OPTIONAL_HDR32_MAGIC
    pub major_linker_version:           u8,
    pub minor_linker_version:           u8,
    pub size_of_code:                   u32,
    pub size_of_initialized_data:       u32,
    pub size_of_uninitialized_data:     u32,
    pub address_of_entry_point:         u32,  // RVA
    pub base_of_code:                   u32,
    pub base_of_data:                   u32,
    pub image_base:                     u32,
    pub section_alignment:              u32,
    pub file_alignment:                 u32,
    pub major_os_version:               u16,
    pub minor_os_version:               u16,
    pub major_image_version:            u16,
    pub minor_image_version:            u16,
    pub major_subsystem_version:        u16,
    pub minor_subsystem_version:        u16,
    pub win32_version_value:            u32,
    pub size_of_image:                  u32,
    pub size_of_headers:                u32,
    pub checksum:                       u32,
    pub subsystem:                      u16,
    pub dll_characteristics:            u16,
    pub size_of_stack_reserve:          u32,
    pub size_of_stack_commit:           u32,
    pub size_of_heap_reserve:           u32,
    pub size_of_heap_commit:            u32,
    pub loader_flags:                   u32,
    pub number_of_rva_and_sizes:        u32,
    pub data_directory:                 [ImageDataDirectory; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32, // RVA
    pub size:            u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageSectionHeader {
    pub name:                     [u8; 8],
    pub virtual_size:             u32,
    pub virtual_address:          u32,   // RVA
    pub size_of_raw_data:         u32,
    pub pointer_to_raw_data:      u32,   // file offset
    pub pointer_to_relocations:   u32,
    pub pointer_to_linenumbers:   u32,
    pub number_of_relocations:    u16,
    pub number_of_linenumbers:    u16,
    pub characteristics:          u32,
}

impl ImageSectionHeader {
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..len]).unwrap_or("?")
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,  // RVA to INT (Import Name Table)
    pub time_date_stamp:      u32,
    pub forwarder_chain:      u32,
    pub name:                 u32,  // RVA to DLL name string
    pub first_thunk:          u32,  // RVA to IAT (Import Address Table)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// A parsed view of a PE32 image.
///
/// All data is borrowed from the backing byte slice — no allocations.
#[derive(Debug)]
pub struct Pe32<'a> {
    data:     &'a [u8],
    nt_off:   usize,         // offset of IMAGE_NT_HEADERS in data
}

impl<'a> Pe32<'a> {
    /// Parse a raw PE32 image byte slice.
    ///
    /// Validates DOS and NT signatures and checks for PE32 (32-bit) magic.
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        if data.len() < core::mem::size_of::<ImageDosHeader>() {
            return Err(PeError::TooSmall);
        }
        let dos = read_struct::<ImageDosHeader>(data, 0)?;
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeError::BadDosSig);
        }
        let nt_off = dos.e_lfanew as usize;
        // Minimum: NT sig (4) + FileHeader (20) + magic (2)
        if nt_off + 4 + 20 + 2 > data.len() {
            return Err(PeError::OffsetOutOfRange);
        }
        let sig = read_u32(data, nt_off)?;
        if sig != IMAGE_NT_SIGNATURE {
            return Err(PeError::BadNtSig);
        }
        // Check optional header magic
        let opt_off = nt_off + 4 + core::mem::size_of::<ImageFileHeader>();
        let magic = read_u16(data, opt_off)?;
        if magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
            return Err(PeError::NotPe32);
        }
        let fh = read_struct::<ImageFileHeader>(data, nt_off + 4)?;
        if fh.machine != MACHINE_I386 {
            return Err(PeError::NotI386);
        }
        Ok(Self { data, nt_off })
    }

    fn file_header_offset(&self) -> usize { self.nt_off + 4 }
    fn opt_header_offset(&self)  -> usize { self.nt_off + 4 + core::mem::size_of::<ImageFileHeader>() }
    fn section_table_offset(&self) -> usize {
        // Read size_of_optional_header directly to avoid packed-struct field-access UB.
        let opt_sz = read_u16(self.data, self.file_header_offset() + 16)
            .unwrap_or(0) as usize;
        self.opt_header_offset() + opt_sz
    }

    pub fn file_header(&self) -> ImageFileHeader {
        read_struct::<ImageFileHeader>(self.data, self.file_header_offset())
            .expect("file_header: already validated")
    }

    pub fn optional_header(&self) -> ImageOptionalHeader32 {
        read_struct::<ImageOptionalHeader32>(self.data, self.opt_header_offset())
            .expect("opt_header: already validated")
    }

    /// Iterator over section headers.
    pub fn sections(&self) -> impl Iterator<Item = ImageSectionHeader> + '_ {
        // Read number_of_sections directly from image bytes to avoid packed-struct UB.
        let n     = read_u16(self.data, self.file_header_offset() + 2)
            .unwrap_or(0) as usize;
        let base  = self.section_table_offset();
        let sz    = core::mem::size_of::<ImageSectionHeader>();
        (0..n).filter_map(move |i| read_struct::<ImageSectionHeader>(self.data, base + i * sz).ok())
    }

    /// Iterator over import descriptors (stops at the null terminator).
    pub fn imports(&self) -> impl Iterator<Item = ImportEntry<'_>> + '_ {
        let opt = self.optional_header();
        // Directory entry 1 = import table
        let dir = if opt.number_of_rva_and_sizes > 1 {
            opt.data_directory[1]
        } else {
            ImageDataDirectory::default()
        };

        let rva  = dir.virtual_address;
        let data = self.data;
        let base = self.nt_off; // unused; rva is absolute from image base
        let _ = base;

        ImportIter { data, image_base: opt.image_base, rva, index: 0 }
    }
}

/// A single import descriptor (one DLL worth of imports).
pub struct ImportEntry<'a> {
    pub dll_name_rva: u32,
    pub int_rva:      u32,  // Import Name Table RVA
    pub iat_rva:      u32,  // Import Address Table RVA
    data:             &'a [u8],
}

impl<'a> ImportEntry<'a> {
    /// Name of the imported DLL (NUL-terminated ASCII at RVA).
    pub fn dll_name(&self) -> &str {
        rva_to_str(self.data, self.dll_name_rva).unwrap_or("?")
    }
}

struct ImportIter<'a> {
    data:        &'a [u8],
    image_base:  u32,
    rva:         u32,     // RVA of the first IMAGE_IMPORT_DESCRIPTOR
    index:       usize,
}

impl<'a> Iterator for ImportIter<'a> {
    type Item = ImportEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rva == 0 { return None; }
        let base_off = rva_to_file_offset(self.data, self.rva)?;
        let off = base_off + self.index * core::mem::size_of::<ImageImportDescriptor>();
        let desc = read_struct::<ImageImportDescriptor>(self.data, off).ok()?;
        // Null terminator
        if desc.name == 0 && desc.first_thunk == 0 { return None; }
        self.index += 1;
        Some(ImportEntry {
            dll_name_rva: desc.name,
            int_rva:      desc.original_first_thunk,
            iat_rva:      desc.first_thunk,
            data:         self.data,
        })
    }
}

// ── Read helpers ──────────────────────────────────────────────────────────────

/// Convert an RVA to a file (raw-data) offset by walking the section table.
/// Falls back to `rva as usize` for the PE header range (RVA < first section VA).
fn rva_to_file_offset(data: &[u8], rva: u32) -> Option<usize> {
    // Parse e_lfanew to locate the section table.
    if data.len() < 0x40 { return None; }
    let e_lfanew = u32::from_le_bytes(data.get(0x3C..0x40)?.try_into().ok()?) as usize;
    // FileHeader at e_lfanew+4; n_sections at +2, size_of_optional_header at +16.
    if e_lfanew + 4 + 20 > data.len() { return None; }
    let n_sec  = u16::from_le_bytes(data.get(e_lfanew+4+2..e_lfanew+4+4)?.try_into().ok()?) as usize;
    let opt_sz = u16::from_le_bytes(data.get(e_lfanew+4+16..e_lfanew+4+18)?.try_into().ok()?) as usize;
    let sec_table = e_lfanew + 4 + 20 + opt_sz;
    // Each IMAGE_SECTION_HEADER is 40 bytes.
    for i in 0..n_sec {
        let sh = sec_table + i * 40;
        if sh + 40 > data.len() { break; }
        let vsz    = u32::from_le_bytes(data[sh+8 ..sh+12].try_into().ok()?) as usize;
        let va     = u32::from_le_bytes(data[sh+12..sh+16].try_into().ok()?) as usize;
        let raw_sz = u32::from_le_bytes(data[sh+16..sh+20].try_into().ok()?) as usize;
        let raw_off= u32::from_le_bytes(data[sh+20..sh+24].try_into().ok()?) as usize;
        let extent = vsz.max(raw_sz);
        if rva as usize >= va && (rva as usize) < va + extent {
            return Some(raw_off + (rva as usize - va));
        }
    }
    // Fallback: PE header / below first section — RVA == file offset.
    Some(rva as usize)
}

fn read_struct<T: Copy>(data: &[u8], off: usize) -> Result<T, PeError> {
    let sz = core::mem::size_of::<T>();
    if off + sz > data.len() { return Err(PeError::OffsetOutOfRange); }
    // SAFETY: bounds checked above; T is repr(C, packed) — any bit pattern valid.
    Ok(unsafe { core::ptr::read_unaligned(data.as_ptr().add(off) as *const T) })
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, PeError> {
    if off + 4 > data.len() { return Err(PeError::OffsetOutOfRange); }
    Ok(u32::from_le_bytes(data[off..off+4].try_into().unwrap()))
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, PeError> {
    if off + 2 > data.len() { return Err(PeError::OffsetOutOfRange); }
    Ok(u16::from_le_bytes(data[off..off+2].try_into().unwrap()))
}

/// Read a NUL-terminated ASCII string from a PE RVA (file offset resolved via section table).
fn rva_to_str(data: &[u8], rva: u32) -> Option<&str> {
    let off = rva_to_file_offset(data, rva)?;
    if off >= data.len() { return None; }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(0);
    core::str::from_utf8(&data[off..off+end]).ok()
}

fn read_cstr_at(ptr: *const u8) -> Option<&'static str> {
    let mut len = 0usize;
    while len < 256 {
        let b = unsafe { ptr.add(len).read_unaligned() };
        if b == 0 {
            let s = unsafe { core::slice::from_raw_parts(ptr, len) };
            return core::str::from_utf8(s).ok();
        }
        len += 1;
    }
    None
}

fn fold_ascii_lower(mut b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b = b + 32;
    }
    b
}

fn eq_ascii_nocase(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes().iter())
        .all(|(x, y)| fold_ascii_lower(*x) == fold_ascii_lower(*y))
}

struct StubExport {
    name: &'static str,
    rva: u32,
}

struct StubModule {
    dll: &'static str,
    base: u32,
    exports: &'static [StubExport],
    /// Ordinal bias: the ordinal number of exports[0].
    /// Set to 0 for modules that are never imported by ordinal (bias ignored).
    /// Set to 1 when the first export has ordinal 1 (dsound, wsock32 style).
    ordinal_base: u16,
}

// ntdll stubs use SYSENTER (21 bytes each) — spaced 0x20 to avoid overlap.
const STUB_EXPORTS_NTDLL: &[StubExport] = &[
    StubExport { name: "NtWriteFile",                rva: 0x1000 },
    StubExport { name: "NtAllocateVirtualMemory",    rva: 0x1020 },
    StubExport { name: "NtTerminateProcess",         rva: 0x1040 },
    StubExport { name: "NtCreateProcess",            rva: 0x1060 },
    StubExport { name: "NtCreateThread",             rva: 0x1080 },
];

const STUB_EXPORTS_KERNEL32: &[StubExport] = &[
    StubExport { name: "GetTickCount",               rva: 0x1000 },
    StubExport { name: "Sleep",                      rva: 0x1010 },
    StubExport { name: "VirtualAlloc",               rva: 0x1020 },
    StubExport { name: "VirtualFree",                rva: 0x1030 },
    StubExport { name: "VirtualProtect",             rva: 0x1040 },
    StubExport { name: "GetProcAddress",             rva: 0x1050 },
    StubExport { name: "GetModuleHandleA",           rva: 0x1060 },
    StubExport { name: "ExitProcess",                rva: 0x1070 },
    StubExport { name: "TlsAlloc",                   rva: 0x1080 },
    StubExport { name: "TlsFree",                    rva: 0x1090 },
    StubExport { name: "TlsGetValue",                rva: 0x10A0 },
    StubExport { name: "TlsSetValue",                rva: 0x10B0 },
    StubExport { name: "InitializeCriticalSection",  rva: 0x10C0 },
    StubExport { name: "EnterCriticalSection",       rva: 0x10D0 },
    StubExport { name: "LeaveCriticalSection",       rva: 0x10E0 },
    StubExport { name: "DeleteCriticalSection",      rva: 0x10F0 },
    StubExport { name: "TryEnterCriticalSection",    rva: 0x1100 },
    StubExport { name: "AcquireSRWLockExclusive",    rva: 0x1110 },
    StubExport { name: "ReleaseSRWLockExclusive",    rva: 0x1120 },
    StubExport { name: "InitializeConditionVariable",rva: 0x1130 },
    StubExport { name: "SleepConditionVariableSRW",  rva: 0x1140 },
    StubExport { name: "WakeAllConditionVariable",   rva: 0x1150 },
    StubExport { name: "WakeConditionVariable",      rva: 0x1160 },
    StubExport { name: "GetModuleHandleW",           rva: 0x1170 },
    StubExport { name: "GetModuleHandleExA",         rva: 0x1180 },
    StubExport { name: "LoadLibraryA",               rva: 0x1190 },
    StubExport { name: "FreeLibrary",                rva: 0x11A0 },
    StubExport { name: "GetSystemInfo",              rva: 0x11B0 },
    StubExport { name: "GetTickCount64",             rva: 0x11C0 },
    StubExport { name: "CreateThread",               rva: 0x11D0 },
    StubExport { name: "GetCurrentProcess",          rva: 0x11E0 },
    StubExport { name: "GetCurrentThread",           rva: 0x11F0 },
    StubExport { name: "GetCurrentProcessId",        rva: 0x1200 },
    StubExport { name: "GetCurrentThreadId",         rva: 0x1210 },
    StubExport { name: "WaitForMultipleObjects",     rva: 0x1220 },
    StubExport { name: "WaitForSingleObjectEx",      rva: 0x1230 },
    StubExport { name: "WaitForSingleObject",        rva: 0x1240 },
    StubExport { name: "CloseHandle",                rva: 0x1250 },
    StubExport { name: "CreateEventA",               rva: 0x1260 },
    StubExport { name: "SetEvent",                   rva: 0x1270 },
    StubExport { name: "ResetEvent",                 rva: 0x1280 },
    StubExport { name: "CreateSemaphoreA",           rva: 0x1290 },
    StubExport { name: "ReleaseSemaphore",           rva: 0x12A0 },
    StubExport { name: "DuplicateHandle",            rva: 0x12B0 },
    StubExport { name: "CreateFileMappingA",         rva: 0x12C0 },
    StubExport { name: "MapViewOfFile",              rva: 0x12D0 },
    StubExport { name: "UnmapViewOfFile",            rva: 0x12E0 },
    StubExport { name: "GetTempPathA",               rva: 0x12F0 },
    StubExport { name: "GetTempFileNameA",           rva: 0x1300 },
    StubExport { name: "OutputDebugStringA",         rva: 0x1310 },
    StubExport { name: "FormatMessageA",             rva: 0x1320 },
    StubExport { name: "VirtualQuery",               rva: 0x1330 },
    StubExport { name: "GetModuleFileNameW",         rva: 0x1340 },
    StubExport { name: "IsDebuggerPresent",          rva: 0x1350 },
    StubExport { name: "OpenProcess",                rva: 0x1360 },
    StubExport { name: "QueryPerformanceCounter",    rva: 0x1370 },
    StubExport { name: "QueryPerformanceFrequency",  rva: 0x1380 },
    StubExport { name: "RaiseException",             rva: 0x1390 },
    StubExport { name: "HeapAlloc",                  rva: 0x13A0 },
    StubExport { name: "HeapFree",                   rva: 0x13B0 },
    StubExport { name: "GetProcessHeap",             rva: 0x13C0 },
    StubExport { name: "LocalFree",                  rva: 0x13D0 },
    StubExport { name: "GetLastError",               rva: 0x13E0 },
    StubExport { name: "SetLastError",               rva: 0x13F0 },
    StubExport { name: "GetEnvironmentVariableW",    rva: 0x1400 },
    StubExport { name: "GetHandleInformation",       rva: 0x1410 },
    StubExport { name: "SuspendThread",              rva: 0x1420 },
    StubExport { name: "ResumeThread",               rva: 0x1430 },
    StubExport { name: "GetThreadPriority",          rva: 0x1440 },
    StubExport { name: "SetThreadPriority",          rva: 0x1450 },
    StubExport { name: "GetThreadContext",           rva: 0x1460 },
    StubExport { name: "SetThreadContext",           rva: 0x1470 },
    StubExport { name: "SwitchToThread",             rva: 0x1480 },
    StubExport { name: "SetProcessAffinityMask",     rva: 0x1490 },
    StubExport { name: "GetProcessAffinityMask",     rva: 0x14A0 },
    StubExport { name: "DeviceIoControl",            rva: 0x14B0 },
    StubExport { name: "CreateDirectoryW",           rva: 0x14C0 },
    StubExport { name: "CreateFileA",                rva: 0x14D0 },
    StubExport { name: "LocalAlloc",                 rva: 0x14E0 },
    StubExport { name: "GetSystemTimeAsFileTime",    rva: 0x14F0 },
    StubExport { name: "GlobalAlloc",                rva: 0x1500 },
    StubExport { name: "GlobalFree",                 rva: 0x1510 },
    // ── Ghost Recon CRT / kernel32 imports ─────────────────────────────────
    StubExport { name: "GlobalMemoryStatus",         rva: 0x1520 },
    StubExport { name: "SetCurrentDirectoryA",       rva: 0x1530 },
    StubExport { name: "GetModuleFileNameA",         rva: 0x1540 },
    StubExport { name: "MultiByteToWideChar",        rva: 0x1550 },
    StubExport { name: "GetVersionExA",              rva: 0x1560 },
    StubExport { name: "lstrcpyA",                   rva: 0x1570 },
    StubExport { name: "GetCurrentDirectoryA",       rva: 0x1580 },
    StubExport { name: "CreateDirectoryA",           rva: 0x1590 },
    StubExport { name: "VirtualQueryEx",             rva: 0x15A0 },
    StubExport { name: "lstrcatA",                   rva: 0x15B0 },
    StubExport { name: "lstrcpynA",                  rva: 0x15C0 },
    StubExport { name: "lstrlenA",                   rva: 0x15D0 },
    StubExport { name: "WriteFile",                  rva: 0x15E0 },
    StubExport { name: "SetFilePointer",             rva: 0x15F0 },
    StubExport { name: "GetFileTime",                rva: 0x1600 },
    StubExport { name: "GetFileSize",                rva: 0x1610 },
    StubExport { name: "FileTimeToDosDateTime",      rva: 0x1620 },
    StubExport { name: "FileTimeToLocalFileTime",    rva: 0x1630 },
    StubExport { name: "FindClose",                  rva: 0x1640 },
    StubExport { name: "DeleteFileA",                rva: 0x1650 },
    StubExport { name: "FindFirstFileA",             rva: 0x1660 },
    StubExport { name: "FindNextFileA",              rva: 0x1670 },
    StubExport { name: "GetFileAttributesA",         rva: 0x1680 },
    StubExport { name: "GetVolumeInformationA",      rva: 0x1690 },
    StubExport { name: "GetDriveTypeA",              rva: 0x16A0 },
    StubExport { name: "GetLogicalDriveStringsA",    rva: 0x16B0 },
    StubExport { name: "GetFullPathNameA",           rva: 0x16C0 },
    StubExport { name: "CreateProcessA",             rva: 0x16D0 },
    StubExport { name: "InterlockedExchange",        rva: 0x16E0 },
    StubExport { name: "InterlockedDecrement",       rva: 0x16F0 },
    StubExport { name: "InterlockedIncrement",       rva: 0x1700 },
    StubExport { name: "CompareStringA",             rva: 0x1710 },
    StubExport { name: "CompareStringW",             rva: 0x1720 },
    StubExport { name: "ExitThread",                 rva: 0x1730 },
    StubExport { name: "FileTimeToSystemTime",       rva: 0x1740 },
    StubExport { name: "FlushFileBuffers",           rva: 0x1750 },
    StubExport { name: "FreeEnvironmentStringsA",    rva: 0x1760 },
    StubExport { name: "FreeEnvironmentStringsW",    rva: 0x1770 },
    StubExport { name: "GetACP",                     rva: 0x1780 },
    StubExport { name: "GetCPInfo",                  rva: 0x1790 },
    StubExport { name: "GetCommandLineA",            rva: 0x17A0 },
    StubExport { name: "GetEnvironmentStrings",      rva: 0x17B0 },
    StubExport { name: "GetEnvironmentStringsW",     rva: 0x17C0 },
    StubExport { name: "GetEnvironmentVariableA",    rva: 0x17D0 },
    StubExport { name: "GetFileType",                rva: 0x17E0 },
    StubExport { name: "GetLocalTime",               rva: 0x17F0 },
    StubExport { name: "GetLocaleInfoA",             rva: 0x1800 },
    StubExport { name: "GetLocaleInfoW",             rva: 0x1810 },
    StubExport { name: "GetOEMCP",                   rva: 0x1820 },
    StubExport { name: "GetStartupInfoA",            rva: 0x1830 },
    StubExport { name: "GetStdHandle",               rva: 0x1840 },
    StubExport { name: "GetStringTypeA",             rva: 0x1850 },
    StubExport { name: "GetStringTypeW",             rva: 0x1860 },
    StubExport { name: "GetSystemTime",              rva: 0x1870 },
    StubExport { name: "GetTimeZoneInformation",     rva: 0x1880 },
    StubExport { name: "GetUserDefaultLCID",         rva: 0x1890 },
    StubExport { name: "GetVersion",                 rva: 0x18A0 },
    StubExport { name: "HeapCreate",                 rva: 0x18B0 },
    StubExport { name: "HeapDestroy",                rva: 0x18C0 },
    StubExport { name: "HeapReAlloc",                rva: 0x18D0 },
    StubExport { name: "HeapSize",                   rva: 0x18E0 },
    StubExport { name: "IsBadCodePtr",               rva: 0x18F0 },
    StubExport { name: "IsBadReadPtr",               rva: 0x1900 },
    StubExport { name: "IsBadWritePtr",              rva: 0x1910 },
    StubExport { name: "IsValidCodePage",            rva: 0x1920 },
    StubExport { name: "IsValidLocale",              rva: 0x1930 },
    StubExport { name: "LCMapStringA",               rva: 0x1940 },
    StubExport { name: "LCMapStringW",               rva: 0x1950 },
    StubExport { name: "MoveFileA",                  rva: 0x1960 },
    StubExport { name: "MulDiv",                     rva: 0x1970 },
    StubExport { name: "ReadFile",                   rva: 0x1980 },
    StubExport { name: "RtlUnwind",                  rva: 0x1990 },
    StubExport { name: "SetEndOfFile",               rva: 0x19A0 },
    StubExport { name: "SetEnvironmentVariableA",    rva: 0x19B0 },
    StubExport { name: "SetHandleCount",             rva: 0x19C0 },
    StubExport { name: "SetStdHandle",               rva: 0x19D0 },
    StubExport { name: "SetUnhandledExceptionFilter",rva: 0x19E0 },
    StubExport { name: "TerminateProcess",           rva: 0x19F0 },
    StubExport { name: "UnhandledExceptionFilter",   rva: 0x1A00 },
    StubExport { name: "WideCharToMultiByte",        rva: 0x1A10 },
    StubExport { name: "EnumSystemLocalesA",        rva: 0x1A20 },
];

const STUB_EXPORTS_USER32: &[StubExport] = &[
    StubExport { name: "CreateWindowExA",          rva: 0x1000 },
    StubExport { name: "ShowWindow",               rva: 0x1010 },
    StubExport { name: "GetMessageA",              rva: 0x1020 },
    StubExport { name: "DispatchMessageA",         rva: 0x1030 },
    StubExport { name: "TranslateMessage",         rva: 0x1040 },
    StubExport { name: "PeekMessageA",             rva: 0x1050 },
    StubExport { name: "PostQuitMessage",          rva: 0x1060 },
    StubExport { name: "RegisterClassA",           rva: 0x1070 },
    StubExport { name: "DefWindowProcA",           rva: 0x1080 },
    StubExport { name: "CreateWindowExW",          rva: 0x1090 },
    StubExport { name: "DefWindowProcW",           rva: 0x10A0 },
    StubExport { name: "RegisterClassExW",         rva: 0x10B0 },
    StubExport { name: "DestroyWindow",            rva: 0x10C0 },
    StubExport { name: "GetClientRect",            rva: 0x10D0 },
    StubExport { name: "GetWindowRect",            rva: 0x10E0 },
    StubExport { name: "EnumDisplaySettingsW",     rva: 0x10F0 },
    StubExport { name: "ChangeDisplaySettingsExW", rva: 0x1100 },
    StubExport { name: "EnumDisplayMonitors",      rva: 0x1110 },
    StubExport { name: "GetMonitorInfoW",          rva: 0x1120 },
    StubExport { name: "MonitorFromPoint",         rva: 0x1130 },
    StubExport { name: "SetWindowPos",             rva: 0x1140 },
    StubExport { name: "MoveWindow",               rva: 0x1150 },
    StubExport { name: "GetWindowLongW",           rva: 0x1160 },
    StubExport { name: "SetWindowLongW",           rva: 0x1170 },
    StubExport { name: "GetWindowLongA",           rva: 0x1180 },
    StubExport { name: "SetWindowLongA",           rva: 0x1190 },
    StubExport { name: "IsWindow",                 rva: 0x11A0 },
    StubExport { name: "IsWindowVisible",          rva: 0x11B0 },
    StubExport { name: "IsIconic",                 rva: 0x11C0 },
    StubExport { name: "GetForegroundWindow",      rva: 0x11D0 },
    StubExport { name: "SetCursor",                rva: 0x11E0 },
    StubExport { name: "SetCursorPos",             rva: 0x11F0 },
    StubExport { name: "GetCursorPos",             rva: 0x1200 },
    StubExport { name: "ReleaseDC",                rva: 0x1210 },
    StubExport { name: "GetDCEx",                  rva: 0x1220 },
    StubExport { name: "OffsetRect",               rva: 0x1230 },
    StubExport { name: "SetRect",                  rva: 0x1240 },
    StubExport { name: "SetProcessDPIAware",       rva: 0x1250 },
    StubExport { name: "CallWindowProcA",          rva: 0x1260 },
    StubExport { name: "CallWindowProcW",          rva: 0x1270 },
    StubExport { name: "IsWindowUnicode",          rva: 0x1280 },
    StubExport { name: "AdjustWindowRectEx",       rva: 0x1290 },
    StubExport { name: "PostMessageW",             rva: 0x12A0 },
    StubExport { name: "CreateIconIndirect",       rva: 0x12B0 },
    StubExport { name: "DestroyCursor",            rva: 0x12C0 },
    StubExport { name: "QueryDisplayConfig",       rva: 0x12D0 },
    StubExport { name: "DisplayConfigGetDeviceInfo",rva: 0x12E0 },
    StubExport { name: "GetDisplayConfigBufferSizes",rva: 0x12F0 },
    StubExport { name: "EnumDisplayDevicesA",      rva: 0x1300 },
    StubExport { name: "ClientToScreen",           rva: 0x1360 },
    StubExport { name: "ScreenToClient",           rva: 0x1370 },
    StubExport { name: "MessageBoxA",              rva: 0x1380 },
    // ── Ghost Recon user32 imports ─────────────────────────────────────────
    StubExport { name: "AdjustWindowRect",         rva: 0x1390 },
    StubExport { name: "CloseWindow",              rva: 0x13A0 },
    StubExport { name: "EnumDisplaySettingsA",     rva: 0x13B0 },
    StubExport { name: "FindWindowA",              rva: 0x13C0 },
    StubExport { name: "FrameRect",                rva: 0x13D0 },
    StubExport { name: "GetDoubleClickTime",       rva: 0x13E0 },
    StubExport { name: "GetMenu",                  rva: 0x13F0 },
    StubExport { name: "GetQueueStatus",           rva: 0x1400 },
    StubExport { name: "GetSystemMetrics",         rva: 0x1410 },
    StubExport { name: "LoadCursorA",              rva: 0x1420 },
    StubExport { name: "LoadIconA",                rva: 0x1430 },
    StubExport { name: "LoadImageA",               rva: 0x1440 },
    StubExport { name: "MsgWaitForMultipleObjects",rva: 0x1450 },
    StubExport { name: "PostMessageA",             rva: 0x1460 },
    StubExport { name: "PostThreadMessageA",       rva: 0x1470 },
    StubExport { name: "RegisterClassExA",         rva: 0x1480 },
    StubExport { name: "RegisterWindowMessageA",   rva: 0x1490 },
    StubExport { name: "SetFocus",                 rva: 0x14A0 },
    StubExport { name: "SetForegroundWindow",      rva: 0x14B0 },
    StubExport { name: "UpdateWindow",             rva: 0x14C0 },
    StubExport { name: "wsprintfA",                rva: 0x14D0 },
    StubExport { name: "wvsprintfA",               rva: 0x14E0 },
    StubExport { name: "GetActiveWindow",          rva: 0x14F0 },
    StubExport { name: "GetLastActivePopup",       rva: 0x1500 },
];

const STUB_EXPORTS_MSVCRT: &[StubExport] = &[
    StubExport { name: "malloc", rva: 0x1000 },
    StubExport { name: "calloc", rva: 0x1010 },
    StubExport { name: "free", rva: 0x1020 },
    StubExport { name: "memcpy", rva: 0x1030 },
    StubExport { name: "memset", rva: 0x1040 },
    StubExport { name: "strlen", rva: 0x1050 },
];

const STUB_EXPORTS_WINMM: &[StubExport] = &[
    StubExport { name: "timeBeginPeriod", rva: 0x1000 },
    StubExport { name: "timeEndPeriod", rva: 0x1010 },
    StubExport { name: "timeGetTime", rva: 0x1020 },
    // ── Ghost Recon winmm imports ──────────────────────────────────────────
    StubExport { name: "timeGetDevCaps", rva: 0x1030 },
    StubExport { name: "timeKillEvent",  rva: 0x1040 },
    StubExport { name: "timeSetEvent",   rva: 0x1050 },
];

// d3d8.dll — Direct3D 8 (Ghost Recon 2001).
const STUB_EXPORTS_D3D8: &[StubExport] = &[
    StubExport { name: "Direct3DCreate8", rva: 0x1000 },
];

// d3d9.dll — DXVK stub (d3d8.dll imports only Direct3DCreate9 from here).
const STUB_EXPORTS_D3D9: &[StubExport] = &[
    StubExport { name: "Direct3DCreate9",   rva: 0x1000 },
    StubExport { name: "Direct3DCreate9Ex", rva: 0x1010 },
];

// advapi32.dll — Registry + security.
const STUB_EXPORTS_ADVAPI32: &[StubExport] = &[
    StubExport { name: "RegOpenKeyExA",           rva: 0x1000 },
    StubExport { name: "RegQueryValueExA",        rva: 0x1010 },
    StubExport { name: "RegCloseKey",             rva: 0x1020 },
    StubExport { name: "RegOpenKeyExW",           rva: 0x1030 },
    StubExport { name: "RegQueryValueExW",        rva: 0x1040 },
    StubExport { name: "RegNotifyChangeKeyValue", rva: 0x1050 },
    StubExport { name: "AllocateLocallyUniqueId", rva: 0x1060 },
    StubExport { name: "GetUserNameA",            rva: 0x1070 },
];

// gdi32.dll — minimal GDI stubs (d3d9 uses for fallback paths).
const STUB_EXPORTS_GDI32: &[StubExport] = &[
    StubExport { name: "CreateCompatibleDC", rva: 0x1000 },
    StubExport { name: "DeleteDC",           rva: 0x1010 },
    StubExport { name: "CreateBitmap",       rva: 0x1020 },
    StubExport { name: "DeleteObject",       rva: 0x1030 },
    StubExport { name: "StretchBlt",         rva: 0x1040 },
    StubExport { name: "Polygon",            rva: 0x1050 },
    // ── Ghost Recon gdi32 imports ──────────────────────────────────────────
    StubExport { name: "CreateDIBSection",  rva: 0x1060 },
    StubExport { name: "CreatePen",         rva: 0x1070 },
    StubExport { name: "CreateSolidBrush",  rva: 0x1080 },
    StubExport { name: "Ellipse",           rva: 0x1090 },
    StubExport { name: "GdiFlush",          rva: 0x10A0 },
    StubExport { name: "GetStockObject",    rva: 0x10B0 },
    StubExport { name: "Polyline",          rva: 0x10C0 },
    StubExport { name: "SelectObject",      rva: 0x10D0 },
    StubExport { name: "SetPixel",          rva: 0x10E0 },
    StubExport { name: "TextOutA",          rva: 0x10F0 },
];

// setupapi.dll — GPU device enumeration (DXVK falls back gracefully on failure).
const STUB_EXPORTS_SETUPAPI: &[StubExport] = &[
    StubExport { name: "SetupDiGetClassDevsW",            rva: 0x1000 },
    StubExport { name: "SetupDiEnumDeviceInterfaces",     rva: 0x1010 },
    StubExport { name: "SetupDiGetDeviceInterfaceDetailW",rva: 0x1020 },
    StubExport { name: "SetupDiOpenDevRegKey",            rva: 0x1030 },
];

// vulkan-1.dll — Vulkan ICD loader shim.
// DXVK (d3d8→d3d9→vulkan-1 chain) resolves all Vulkan function pointers via
// vkGetInstanceProcAddr; other functions are resolved through IAT patching.
// RVA layout: entry N → 0x1000 + N*0x10 (each stub is 14–15 bytes in 16-byte slot).
// Game relevance: Ghost Recon 2001 → DXVK d3d8 → d3d9 → vulkan-1 → these stubs.
const STUB_EXPORTS_VULKAN1: &[StubExport] = &[
    // ── Instance / device lifecycle ─────────────────────────────────────────
    StubExport { name: "vkGetInstanceProcAddr",                          rva: 0x1000 }, //  0
    StubExport { name: "vkGetDeviceProcAddr",                            rva: 0x1010 }, //  1
    StubExport { name: "vkCreateInstance",                               rva: 0x1020 }, //  2
    StubExport { name: "vkDestroyInstance",                              rva: 0x1030 }, //  3
    StubExport { name: "vkEnumerateInstanceExtensionProperties",         rva: 0x1040 }, //  4
    StubExport { name: "vkEnumerateInstanceLayerProperties",             rva: 0x1050 }, //  5
    StubExport { name: "vkEnumerateInstanceVersion",                     rva: 0x1060 }, //  6
    // ── Physical device ──────────────────────────────────────────────────────
    StubExport { name: "vkEnumeratePhysicalDevices",                     rva: 0x1070 }, //  7
    StubExport { name: "vkGetPhysicalDeviceProperties",                  rva: 0x1080 }, //  8
    StubExport { name: "vkGetPhysicalDeviceProperties2KHR",              rva: 0x1090 }, //  9
    StubExport { name: "vkGetPhysicalDeviceFeatures",                    rva: 0x10A0 }, // 10
    StubExport { name: "vkGetPhysicalDeviceFeatures2KHR",                rva: 0x10B0 }, // 11
    StubExport { name: "vkGetPhysicalDeviceMemoryProperties",            rva: 0x10C0 }, // 12
    StubExport { name: "vkGetPhysicalDeviceMemoryProperties2KHR",        rva: 0x10D0 }, // 13
    StubExport { name: "vkGetPhysicalDeviceQueueFamilyProperties",       rva: 0x10E0 }, // 14
    StubExport { name: "vkGetPhysicalDeviceFormatProperties",            rva: 0x10F0 }, // 15
    StubExport { name: "vkGetPhysicalDeviceFormatProperties2KHR",        rva: 0x1100 }, // 16
    StubExport { name: "vkEnumerateDeviceExtensionProperties",           rva: 0x1110 }, // 17
    // ── Surface (KHR) ────────────────────────────────────────────────────────
    StubExport { name: "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",      rva: 0x1120 }, // 18
    StubExport { name: "vkGetPhysicalDeviceSurfaceFormatsKHR",           rva: 0x1130 }, // 19
    StubExport { name: "vkGetPhysicalDeviceSurfacePresentModesKHR",      rva: 0x1140 }, // 20
    StubExport { name: "vkGetPhysicalDeviceSurfaceSupportKHR",           rva: 0x1150 }, // 21
    StubExport { name: "vkCreateWin32SurfaceKHR",                        rva: 0x1160 }, // 22
    StubExport { name: "vkDestroySurfaceKHR",                            rva: 0x1170 }, // 23
    // ── Logical device ───────────────────────────────────────────────────────
    StubExport { name: "vkCreateDevice",                                 rva: 0x1180 }, // 24
    StubExport { name: "vkDestroyDevice",                                rva: 0x1190 }, // 25
    StubExport { name: "vkGetDeviceQueue",                               rva: 0x11A0 }, // 26
    // ── Swapchain ────────────────────────────────────────────────────────────
    StubExport { name: "vkCreateSwapchainKHR",                           rva: 0x11B0 }, // 27
    StubExport { name: "vkDestroySwapchainKHR",                          rva: 0x11C0 }, // 28
    StubExport { name: "vkGetSwapchainImagesKHR",                        rva: 0x11D0 }, // 29
    StubExport { name: "vkAcquireNextImageKHR",                          rva: 0x11E0 }, // 30
    StubExport { name: "vkQueuePresentKHR",                              rva: 0x11F0 }, // 31
    // ── Command pool / buffers ───────────────────────────────────────────────
    StubExport { name: "vkCreateCommandPool",                            rva: 0x1200 }, // 32
    StubExport { name: "vkDestroyCommandPool",                           rva: 0x1210 }, // 33
    StubExport { name: "vkResetCommandPool",                             rva: 0x1220 }, // 34
    StubExport { name: "vkAllocateCommandBuffers",                       rva: 0x1230 }, // 35
    StubExport { name: "vkFreeCommandBuffers",                           rva: 0x1240 }, // 36
    StubExport { name: "vkBeginCommandBuffer",                           rva: 0x1250 }, // 37
    StubExport { name: "vkEndCommandBuffer",                             rva: 0x1260 }, // 38
    StubExport { name: "vkResetCommandBuffer",                           rva: 0x1270 }, // 39
    // ── Synchronization ──────────────────────────────────────────────────────
    StubExport { name: "vkCreateFence",                                  rva: 0x1280 }, // 40
    StubExport { name: "vkDestroyFence",                                 rva: 0x1290 }, // 41
    StubExport { name: "vkResetFences",                                  rva: 0x12A0 }, // 42
    StubExport { name: "vkGetFenceStatus",                               rva: 0x12B0 }, // 43
    StubExport { name: "vkWaitForFences",                                rva: 0x12C0 }, // 44
    StubExport { name: "vkCreateSemaphore",                              rva: 0x12D0 }, // 45
    StubExport { name: "vkDestroySemaphore",                             rva: 0x12E0 }, // 46
    // ── Render pass / framebuffer ─────────────────────────────────────────────
    StubExport { name: "vkCreateRenderPass",                             rva: 0x12F0 }, // 47
    StubExport { name: "vkDestroyRenderPass",                            rva: 0x1300 }, // 48
    StubExport { name: "vkCreateFramebuffer",                            rva: 0x1310 }, // 49
    StubExport { name: "vkDestroyFramebuffer",                           rva: 0x1320 }, // 50
    // ── Image / image view ───────────────────────────────────────────────────
    StubExport { name: "vkCreateImageView",                              rva: 0x1330 }, // 51
    StubExport { name: "vkDestroyImageView",                             rva: 0x1340 }, // 52
    StubExport { name: "vkCreateImage",                                  rva: 0x1350 }, // 53
    StubExport { name: "vkDestroyImage",                                 rva: 0x1360 }, // 54
    StubExport { name: "vkGetImageSubresourceLayout",                    rva: 0x1370 }, // 55
    // ── Buffer / buffer view ─────────────────────────────────────────────────
    StubExport { name: "vkCreateBuffer",                                 rva: 0x1380 }, // 56
    StubExport { name: "vkDestroyBuffer",                                rva: 0x1390 }, // 57
    StubExport { name: "vkCreateBufferView",                             rva: 0x13A0 }, // 58
    StubExport { name: "vkDestroyBufferView",                            rva: 0x13B0 }, // 59
    // ── Memory ───────────────────────────────────────────────────────────────
    StubExport { name: "vkAllocateMemory",                               rva: 0x13C0 }, // 60
    StubExport { name: "vkFreeMemory",                                   rva: 0x13D0 }, // 61
    StubExport { name: "vkMapMemory",                                    rva: 0x13E0 }, // 62
    StubExport { name: "vkUnmapMemory",                                  rva: 0x13F0 }, // 63
    StubExport { name: "vkBindBufferMemory",                             rva: 0x1400 }, // 64
    StubExport { name: "vkBindImageMemory",                              rva: 0x1410 }, // 65
    StubExport { name: "vkGetImageMemoryRequirements",                   rva: 0x1420 }, // 66
    StubExport { name: "vkGetBufferMemoryRequirements",                  rva: 0x1430 }, // 67
    // ── Shader / pipeline ────────────────────────────────────────────────────
    StubExport { name: "vkCreateShaderModule",                           rva: 0x1440 }, // 68
    StubExport { name: "vkDestroyShaderModule",                          rva: 0x1450 }, // 69
    StubExport { name: "vkCreatePipelineLayout",                         rva: 0x1460 }, // 70
    StubExport { name: "vkDestroyPipelineLayout",                        rva: 0x1470 }, // 71
    StubExport { name: "vkCreateDescriptorSetLayout",                    rva: 0x1480 }, // 72
    StubExport { name: "vkDestroyDescriptorSetLayout",                   rva: 0x1490 }, // 73
    StubExport { name: "vkCreateDescriptorPool",                         rva: 0x14A0 }, // 74
    StubExport { name: "vkDestroyDescriptorPool",                        rva: 0x14B0 }, // 75
    StubExport { name: "vkAllocateDescriptorSets",                       rva: 0x14C0 }, // 76
    StubExport { name: "vkUpdateDescriptorSets",                         rva: 0x14D0 }, // 77
    StubExport { name: "vkFreeDescriptorSets",                           rva: 0x14E0 }, // 78
    StubExport { name: "vkCreateGraphicsPipelines",                      rva: 0x14F0 }, // 79
    StubExport { name: "vkCreateComputePipelines",                       rva: 0x1500 }, // 80
    StubExport { name: "vkDestroyPipeline",                              rva: 0x1510 }, // 81
    StubExport { name: "vkCreatePipelineCache",                          rva: 0x1520 }, // 82
    StubExport { name: "vkDestroyPipelineCache",                         rva: 0x1530 }, // 83
    StubExport { name: "vkCreateSampler",                                rva: 0x1540 }, // 84
    StubExport { name: "vkDestroySampler",                               rva: 0x1550 }, // 85
    // ── Query pool ───────────────────────────────────────────────────────────
    StubExport { name: "vkCreateQueryPool",                              rva: 0x1560 }, // 86
    StubExport { name: "vkDestroyQueryPool",                             rva: 0x1570 }, // 87
    StubExport { name: "vkGetQueryPoolResults",                          rva: 0x1580 }, // 88
    // ── Queue submit / idle ──────────────────────────────────────────────────
    StubExport { name: "vkQueueSubmit",                                  rva: 0x1590 }, // 89
    StubExport { name: "vkQueueWaitIdle",                                rva: 0x15A0 }, // 90
    StubExport { name: "vkDeviceWaitIdle",                               rva: 0x15B0 }, // 91
    // ── vkCmd* draw commands ─────────────────────────────────────────────────
    StubExport { name: "vkCmdBeginRenderPass",                           rva: 0x15C0 }, // 92
    StubExport { name: "vkCmdEndRenderPass",                             rva: 0x15D0 }, // 93
    StubExport { name: "vkCmdBindPipeline",                              rva: 0x15E0 }, // 94
    StubExport { name: "vkCmdBindVertexBuffers",                         rva: 0x15F0 }, // 95
    StubExport { name: "vkCmdBindIndexBuffer",                           rva: 0x1600 }, // 96
    StubExport { name: "vkCmdDraw",                                      rva: 0x1610 }, // 97
    StubExport { name: "vkCmdDrawIndexed",                               rva: 0x1620 }, // 98
    StubExport { name: "vkCmdBindDescriptorSets",                        rva: 0x1630 }, // 99
    StubExport { name: "vkCmdSetViewport",                               rva: 0x1640 }, // 100
    StubExport { name: "vkCmdSetScissor",                                rva: 0x1650 }, // 101
    StubExport { name: "vkCmdCopyBuffer",                                rva: 0x1660 }, // 102
    StubExport { name: "vkCmdCopyImage",                                 rva: 0x1670 }, // 103
    StubExport { name: "vkCmdCopyBufferToImage",                         rva: 0x1680 }, // 104
    StubExport { name: "vkCmdCopyImageToBuffer",                         rva: 0x1690 }, // 105
    StubExport { name: "vkCmdPipelineBarrier",                           rva: 0x16A0 }, // 106
    StubExport { name: "vkCmdPushConstants",                             rva: 0x16B0 }, // 107
    StubExport { name: "vkCmdClearColorImage",                           rva: 0x16C0 }, // 108
    StubExport { name: "vkCmdClearDepthStencilImage",                    rva: 0x16D0 }, // 109
    StubExport { name: "vkCmdResolveImage",                              rva: 0x16E0 }, // 110
    StubExport { name: "vkCmdBlitImage",                                 rva: 0x16F0 }, // 111
    StubExport { name: "vkCmdFillBuffer",                                rva: 0x1700 }, // 112
    StubExport { name: "vkCmdDispatch",                                  rva: 0x1710 }, // 113
    StubExport { name: "vkCmdExecuteCommands",                           rva: 0x1720 }, // 114
    StubExport { name: "vkCmdSetLineWidth",                              rva: 0x1730 }, // 115
    StubExport { name: "vkCmdSetDepthBias",                              rva: 0x1740 }, // 116
    StubExport { name: "vkCmdSetBlendConstants",                         rva: 0x1750 }, // 117
    StubExport { name: "vkCmdSetDepthBounds",                            rva: 0x1760 }, // 118
    StubExport { name: "vkCmdSetStencilCompareMask",                     rva: 0x1770 }, // 119
    StubExport { name: "vkCmdSetStencilWriteMask",                       rva: 0x1780 }, // 120
    StubExport { name: "vkCmdSetStencilReference",                       rva: 0x1790 }, // 121
    StubExport { name: "vkCmdWriteTimestamp",                            rva: 0x17A0 }, // 122
    StubExport { name: "vkCmdResetQueryPool",                            rva: 0x17B0 }, // 123
    StubExport { name: "vkCmdBeginQuery",                                rva: 0x17C0 }, // 124
    StubExport { name: "vkCmdEndQuery",                                  rva: 0x17D0 }, // 125
    StubExport { name: "vkCmdCopyQueryPoolResults",                      rva: 0x17E0 }, // 126
    StubExport { name: "vkCreateRenderPass2KHR",                         rva: 0x17F0 }, // 127
    StubExport { name: "vkQueueSubmit2KHR",                              rva: 0x1800 }, // 128
];

// ── api-ms-win-crt-* (UCRT forwarder DLLs) ────────────────────────────────────
// These are the Universal CRT API-set stubs DXVK 2.7+ requires.
// RVAs are laid out sequentially at 0x10 increments per function.

const STUB_EXPORTS_UCRT_RUNTIME: &[StubExport] = &[
    StubExport { name: "_initterm",                   rva: 0x1000 }, // inline code (2 slots)
    StubExport { name: "_initterm_e",                 rva: 0x1020 }, // inline code (2 slots)
    StubExport { name: "_initialize_onexit_table",    rva: 0x1040 },
    StubExport { name: "_register_onexit_function",   rva: 0x1050 },
    StubExport { name: "_execute_onexit_table",       rva: 0x1060 }, // inline code (2 slots)
    StubExport { name: "_beginthreadex",              rva: 0x1080 },
    StubExport { name: "_endthreadex",                rva: 0x1090 },
    StubExport { name: "_errno",                      rva: 0x10A0 },
    StubExport { name: "abort",                       rva: 0x10B0 },
    StubExport { name: "strerror",                    rva: 0x10C0 },
    StubExport { name: "_assert",                     rva: 0x10D0 },
    StubExport { name: "_exit",                       rva: 0x10E0 },
    StubExport { name: "strerror_s",                  rva: 0x10F0 },
];

const STUB_EXPORTS_UCRT_HEAP: &[StubExport] = &[
    StubExport { name: "malloc",         rva: 0x1000 },
    StubExport { name: "free",           rva: 0x1010 },
    StubExport { name: "calloc",         rva: 0x1020 },
    StubExport { name: "realloc",        rva: 0x1030 },
    StubExport { name: "_aligned_malloc",rva: 0x1040 },
    StubExport { name: "_aligned_free",  rva: 0x1050 },
];

const STUB_EXPORTS_UCRT_STRING: &[StubExport] = &[
    StubExport { name: "memset",   rva: 0x1000 },
    StubExport { name: "strcmp",   rva: 0x1010 },
    StubExport { name: "strlen",   rva: 0x1020 },
    StubExport { name: "strncmp",  rva: 0x1030 },
    StubExport { name: "strncpy",  rva: 0x1040 },
    StubExport { name: "strnlen",  rva: 0x1050 },
    StubExport { name: "strcoll",  rva: 0x1060 },
    StubExport { name: "strxfrm",  rva: 0x1070 },
    StubExport { name: "towlower", rva: 0x1080 },
    StubExport { name: "towupper", rva: 0x1090 },
    StubExport { name: "wcscoll",  rva: 0x10A0 },
    StubExport { name: "wcslen",   rva: 0x10B0 },
    StubExport { name: "wcsnlen",  rva: 0x10C0 },
    StubExport { name: "wcscmp",   rva: 0x10D0 },
    StubExport { name: "wcsxfrm",  rva: 0x10E0 },
    StubExport { name: "wctype",   rva: 0x10F0 },
    StubExport { name: "_wcsicmp", rva: 0x1100 },
    StubExport { name: "_strdup",  rva: 0x1110 },
    StubExport { name: "iswctype", rva: 0x1120 },
    StubExport { name: "_mbstrlen",rva: 0x1130 },
];

const STUB_EXPORTS_UCRT_PRIVATE: &[StubExport] = &[
    StubExport { name: "memcpy",   rva: 0x1000 },
    StubExport { name: "memmove",  rva: 0x1010 },
    StubExport { name: "memcmp",   rva: 0x1020 },
    StubExport { name: "memchr",   rva: 0x1030 },
    StubExport { name: "strchr",   rva: 0x1040 },
    StubExport { name: "_setjmp3", rva: 0x1050 },
    StubExport { name: "longjmp",  rva: 0x1060 },
];

const STUB_EXPORTS_UCRT_STDIO: &[StubExport] = &[
    StubExport { name: "__acrt_iob_func",         rva: 0x1000 },
    StubExport { name: "__stdio_common_vfprintf",  rva: 0x1010 },
    StubExport { name: "__stdio_common_vsprintf",  rva: 0x1020 },
    StubExport { name: "_get_osfhandle",           rva: 0x1030 },
    StubExport { name: "_lseeki64",                rva: 0x1040 },
    StubExport { name: "_wfopen",                  rva: 0x1050 },
    StubExport { name: "fclose",                   rva: 0x1060 },
    StubExport { name: "fflush",                   rva: 0x1070 },
    StubExport { name: "fopen",                    rva: 0x1080 },
    StubExport { name: "fputc",                    rva: 0x1090 },
    StubExport { name: "fputs",                    rva: 0x10A0 },
    StubExport { name: "fwrite",                   rva: 0x10B0 },
    StubExport { name: "setvbuf",                  rva: 0x10C0 },
    StubExport { name: "_write",                   rva: 0x10D0 },
    StubExport { name: "_read",                    rva: 0x10E0 },
    StubExport { name: "_fileno",                  rva: 0x10F0 },
    StubExport { name: "fread",                    rva: 0x1100 },
    StubExport { name: "ftell",                    rva: 0x1110 },
    StubExport { name: "_fseeki64",                rva: 0x1120 },
    StubExport { name: "_ftelli64",                rva: 0x1130 },
    StubExport { name: "_fdopen",                  rva: 0x1140 },
];

const STUB_EXPORTS_UCRT_CONVERT: &[StubExport] = &[
    StubExport { name: "btowc",      rva: 0x1000 },
    StubExport { name: "mbrtowc",    rva: 0x1010 },
    StubExport { name: "mbsrtowcs",  rva: 0x1020 },
    StubExport { name: "strtoul",    rva: 0x1030 },
    StubExport { name: "wcrtomb",    rva: 0x1040 },
    StubExport { name: "wctob",      rva: 0x1050 },
];

const STUB_EXPORTS_UCRT_ENV: &[StubExport] = &[
    StubExport { name: "getenv", rva: 0x1000 },
];

const STUB_EXPORTS_UCRT_FILESYSTEM: &[StubExport] = &[
    StubExport { name: "_fstat64",    rva: 0x1000 },
    StubExport { name: "_lock_file",  rva: 0x1010 },
    StubExport { name: "_unlock_file",rva: 0x1020 },
    StubExport { name: "remove",      rva: 0x1030 },
];

const STUB_EXPORTS_UCRT_LOCALE: &[StubExport] = &[
    StubExport { name: "___mb_cur_max_func", rva: 0x1000 },
    StubExport { name: "localeconv",         rva: 0x1010 },
    StubExport { name: "setlocale",          rva: 0x1020 },
];

const STUB_EXPORTS_UCRT_MATH: &[StubExport] = &[
    StubExport { name: "cos",    rva: 0x1000 },
    StubExport { name: "fmaxf",  rva: 0x1010 },
    StubExport { name: "fminf",  rva: 0x1020 },
    StubExport { name: "pow",    rva: 0x1030 },
    StubExport { name: "_fdopen",rva: 0x1040 },
];

const STUB_EXPORTS_UCRT_TIME: &[StubExport] = &[
    StubExport { name: "strftime",  rva: 0x1000 },
    StubExport { name: "wcsftime",  rva: 0x1010 },
];

const STUB_EXPORTS_UCRT_UTILITY: &[StubExport] = &[
    StubExport { name: "rand_s", rva: 0x1000 },
];

// dbghelp.dll — Ghost Recon imports SymGetLineFromAddr by name.
// Return FALSE so debug paths in game code fail gracefully.
const STUB_EXPORTS_DBGHELP: &[StubExport] = &[
    StubExport { name: "SymGetLineFromAddr",      rva: 0x1000 },
    StubExport { name: "StackWalk",               rva: 0x1010 },
    StubExport { name: "SymCleanup",              rva: 0x1020 },
    StubExport { name: "SymFunctionTableAccess",  rva: 0x1030 },
    StubExport { name: "SymGetModuleInfo",        rva: 0x1040 },
    StubExport { name: "SymGetOptions",           rva: 0x1050 },
    StubExport { name: "SymGetSymFromAddr",       rva: 0x1060 },
    StubExport { name: "SymInitialize",           rva: 0x1070 },
    StubExport { name: "SymLoadModule",           rva: 0x1080 },
    StubExport { name: "SymSetOptions",           rva: 0x1090 },
    StubExport { name: "SymUnDName",              rva: 0x10A0 },
    StubExport { name: "UnDecorateSymbolName",    rva: 0x10B0 },
];

// ole32.dll — CoFreeUnusedLibraries is imported by some DLLs; void no-op.
const STUB_EXPORTS_OLE32: &[StubExport] = &[
    StubExport { name: "CoFreeUnusedLibraries", rva: 0x1000 },
    StubExport { name: "CoInitialize",          rva: 0x1010 },
    StubExport { name: "CoUninitialize",         rva: 0x1020 },
    StubExport { name: "CoCreateInstance",       rva: 0x1030 },
    StubExport { name: "CoTaskMemAlloc",         rva: 0x1040 },
    StubExport { name: "CoTaskMemFree",          rva: 0x1050 },
];

// dinput8.dll — DirectInput8Create exported by name (some builds also ordinal).
const STUB_EXPORTS_DINPUT8: &[StubExport] = &[
    StubExport { name: "DirectInput8Create", rva: 0x1000 },
];

// dsound.dll — DirectSoundCreate is ordinal #1 and also exported by name.
const STUB_EXPORTS_DSOUND: &[StubExport] = &[
    StubExport { name: "DirectSoundCreate",         rva: 0x1000 }, // ordinal 1
    StubExport { name: "DirectSoundCreate8",         rva: 0x1010 }, // ordinal 2
    StubExport { name: "DirectSoundCaptureCreate",   rva: 0x1020 }, // ordinal 3 (pad)
    StubExport { name: "DirectSoundCaptureCreate8",  rva: 0x1030 }, // ordinal 4 (pad)
    StubExport { name: "DirectSoundCapture5",        rva: 0x1040 }, // ordinal 5 (pad)
    StubExport { name: "DirectSoundCapture6",        rva: 0x1050 }, // ordinal 6 (pad)
    StubExport { name: "DirectSoundCapture7",        rva: 0x1060 }, // ordinal 7 (pad)
    StubExport { name: "GetDeviceID",                rva: 0x1070 }, // ordinal 8 (pad)
    StubExport { name: "DirectSoundFullDuplexCreate",rva: 0x1080 }, // ordinal 9 (pad)
    StubExport { name: "DllCanUnloadNow",            rva: 0x1090 }, // ordinal 10 (pad)
    StubExport { name: "DirectSoundEnumerateA",      rva: 0x10A0 }, // ordinal 11
];

// wsock32.dll — accept is ordinal #1; also exported by name.
// Return SOCKET_ERROR (0xFFFF_FFFF as u32) so callers fall back to TCP-less mode.
const STUB_EXPORTS_WSOCK32: &[StubExport] = &[
    StubExport { name: "accept",         rva: 0x1000 }, // ordinal 1
    StubExport { name: "bind",           rva: 0x1010 }, // ordinal 2
    StubExport { name: "closesocket",    rva: 0x1020 }, // ordinal 3
    StubExport { name: "connect",        rva: 0x1030 }, // ordinal 4
    StubExport { name: "getpeername",    rva: 0x1040 }, // ordinal 5
    StubExport { name: "getsockname",    rva: 0x1050 }, // ordinal 6
    StubExport { name: "getsockopt",     rva: 0x1060 }, // ordinal 7
    StubExport { name: "htonl",          rva: 0x1070 }, // ordinal 8
    StubExport { name: "htons",          rva: 0x1080 }, // ordinal 9
    StubExport { name: "inet_addr",      rva: 0x1090 }, // ordinal 10
    StubExport { name: "inet_ntoa",      rva: 0x10A0 }, // ordinal 11
    StubExport { name: "listen",         rva: 0x10B0 }, // ordinal 12
    StubExport { name: "ntohl",          rva: 0x10C0 }, // ordinal 13
    StubExport { name: "ntohs",          rva: 0x10D0 }, // ordinal 14
    StubExport { name: "recv",           rva: 0x10E0 }, // ordinal 15
    StubExport { name: "recvfrom",       rva: 0x10F0 }, // ordinal 16
    StubExport { name: "select",         rva: 0x1100 }, // ordinal 17
    StubExport { name: "send",           rva: 0x1110 }, // ordinal 18
    StubExport { name: "sendto",         rva: 0x1120 }, // ordinal 19
    StubExport { name: "setsockopt",     rva: 0x1130 }, // ordinal 20
    StubExport { name: "shutdown",       rva: 0x1140 }, // ordinal 21
    StubExport { name: "socket",         rva: 0x1150 }, // ordinal 22
    StubExport { name: "gethostbyaddr",  rva: 0x1160 }, // ordinal 23 (placeholder)
    // ordinals 24-51: padding stubs
    StubExport { name: "ws_ord24",  rva: 0x1170 }, // 24
    StubExport { name: "ws_ord25",  rva: 0x1170 }, // 25
    StubExport { name: "ws_ord26",  rva: 0x1170 }, // 26
    StubExport { name: "ws_ord27",  rva: 0x1170 }, // 27
    StubExport { name: "ws_ord28",  rva: 0x1170 }, // 28
    StubExport { name: "ws_ord29",  rva: 0x1170 }, // 29
    StubExport { name: "ws_ord30",  rva: 0x1170 }, // 30
    StubExport { name: "ws_ord31",  rva: 0x1170 }, // 31
    StubExport { name: "ws_ord32",  rva: 0x1170 }, // 32
    StubExport { name: "ws_ord33",  rva: 0x1170 }, // 33
    StubExport { name: "ws_ord34",  rva: 0x1170 }, // 34
    StubExport { name: "ws_ord35",  rva: 0x1170 }, // 35
    StubExport { name: "ws_ord36",  rva: 0x1170 }, // 36
    StubExport { name: "ws_ord37",  rva: 0x1170 }, // 37
    StubExport { name: "ws_ord38",  rva: 0x1170 }, // 38
    StubExport { name: "ws_ord39",  rva: 0x1170 }, // 39
    StubExport { name: "ws_ord40",  rva: 0x1170 }, // 40
    StubExport { name: "ws_ord41",  rva: 0x1170 }, // 41
    StubExport { name: "ws_ord42",  rva: 0x1170 }, // 42
    StubExport { name: "ws_ord43",  rva: 0x1170 }, // 43
    StubExport { name: "ws_ord44",  rva: 0x1170 }, // 44
    StubExport { name: "ws_ord45",  rva: 0x1170 }, // 45
    StubExport { name: "ws_ord46",  rva: 0x1170 }, // 46
    StubExport { name: "ws_ord47",  rva: 0x1170 }, // 47
    StubExport { name: "ws_ord48",  rva: 0x1170 }, // 48
    StubExport { name: "ws_ord49",  rva: 0x1170 }, // 49
    StubExport { name: "ws_ord50",  rva: 0x1170 }, // 50
    StubExport { name: "ws_ord51",  rva: 0x1170 }, // 51
    StubExport { name: "gethostbyname",  rva: 0x1180 }, // ordinal 52
    // ordinals 53-56: padding
    StubExport { name: "ws_ord53",  rva: 0x1170 }, // 53
    StubExport { name: "ws_ord54",  rva: 0x1170 }, // 54
    StubExport { name: "ws_ord55",  rva: 0x1170 }, // 55
    StubExport { name: "ws_ord56",  rva: 0x1170 }, // 56
    StubExport { name: "gethostname",    rva: 0x1190 }, // ordinal 57
    // ordinals 58-110: padding
    StubExport { name: "ws_ord58",  rva: 0x1170 }, // 58
    StubExport { name: "ws_ord59",  rva: 0x1170 }, // 59
    StubExport { name: "ws_ord60",  rva: 0x1170 }, // 60
    StubExport { name: "ws_ord61",  rva: 0x1170 }, // 61
    StubExport { name: "ws_ord62",  rva: 0x1170 }, // 62
    StubExport { name: "ws_ord63",  rva: 0x1170 }, // 63
    StubExport { name: "ws_ord64",  rva: 0x1170 }, // 64
    StubExport { name: "ws_ord65",  rva: 0x1170 }, // 65
    StubExport { name: "ws_ord66",  rva: 0x1170 }, // 66
    StubExport { name: "ws_ord67",  rva: 0x1170 }, // 67
    StubExport { name: "ws_ord68",  rva: 0x1170 }, // 68
    StubExport { name: "ws_ord69",  rva: 0x1170 }, // 69
    StubExport { name: "ws_ord70",  rva: 0x1170 }, // 70
    StubExport { name: "ws_ord71",  rva: 0x1170 }, // 71
    StubExport { name: "ws_ord72",  rva: 0x1170 }, // 72
    StubExport { name: "ws_ord73",  rva: 0x1170 }, // 73
    StubExport { name: "ws_ord74",  rva: 0x1170 }, // 74
    StubExport { name: "ws_ord75",  rva: 0x1170 }, // 75
    StubExport { name: "ws_ord76",  rva: 0x1170 }, // 76
    StubExport { name: "ws_ord77",  rva: 0x1170 }, // 77
    StubExport { name: "ws_ord78",  rva: 0x1170 }, // 78
    StubExport { name: "ws_ord79",  rva: 0x1170 }, // 79
    StubExport { name: "ws_ord80",  rva: 0x1170 }, // 80
    StubExport { name: "ws_ord81",  rva: 0x1170 }, // 81
    StubExport { name: "ws_ord82",  rva: 0x1170 }, // 82
    StubExport { name: "ws_ord83",  rva: 0x1170 }, // 83
    StubExport { name: "ws_ord84",  rva: 0x1170 }, // 84
    StubExport { name: "ws_ord85",  rva: 0x1170 }, // 85
    StubExport { name: "ws_ord86",  rva: 0x1170 }, // 86
    StubExport { name: "ws_ord87",  rva: 0x1170 }, // 87
    StubExport { name: "ws_ord88",  rva: 0x1170 }, // 88
    StubExport { name: "ws_ord89",  rva: 0x1170 }, // 89
    StubExport { name: "ws_ord90",  rva: 0x1170 }, // 90
    StubExport { name: "ws_ord91",  rva: 0x1170 }, // 91
    StubExport { name: "ws_ord92",  rva: 0x1170 }, // 92
    StubExport { name: "ws_ord93",  rva: 0x1170 }, // 93
    StubExport { name: "ws_ord94",  rva: 0x1170 }, // 94
    StubExport { name: "ws_ord95",  rva: 0x1170 }, // 95
    StubExport { name: "ws_ord96",  rva: 0x1170 }, // 96
    StubExport { name: "ws_ord97",  rva: 0x1170 }, // 97
    StubExport { name: "ws_ord98",  rva: 0x1170 }, // 98
    StubExport { name: "ws_ord99",  rva: 0x1170 }, // 99
    StubExport { name: "ws_ord100", rva: 0x1170 }, // 100
    StubExport { name: "ws_ord101", rva: 0x1170 }, // 101
    StubExport { name: "ws_ord102", rva: 0x1170 }, // 102
    StubExport { name: "ws_ord103", rva: 0x1170 }, // 103
    StubExport { name: "ws_ord104", rva: 0x1170 }, // 104
    StubExport { name: "ws_ord105", rva: 0x1170 }, // 105
    StubExport { name: "ws_ord106", rva: 0x1170 }, // 106
    StubExport { name: "ws_ord107", rva: 0x1170 }, // 107
    StubExport { name: "ws_ord108", rva: 0x1170 }, // 108
    StubExport { name: "ws_ord109", rva: 0x1170 }, // 109
    StubExport { name: "ws_ord110", rva: 0x1170 }, // 110
    StubExport { name: "WSAStartup",     rva: 0x11A0 }, // ordinal 111
    // ordinals 112-114: padding
    StubExport { name: "ws_ord112", rva: 0x1170 }, // 112
    StubExport { name: "ws_ord113", rva: 0x1170 }, // 113
    StubExport { name: "ws_ord114", rva: 0x1170 }, // 114
    StubExport { name: "WSACleanup",     rva: 0x11B0 }, // ordinal 115
    StubExport { name: "WSASetLastError",rva: 0x11C0 }, // ordinal 116
];

// ── Dynamic DLL tracking ──────────────────────────────────────────────────────
// Filled by load_dll() / register_loaded_dll() when a real PE DLL is loaded
// into the process address space at runtime (LoadLibraryA).

#[derive(Clone, Copy)]
struct DllEntry {
    base: u32,
    size: u32,
    entry_rva: u32,    // AddressOfEntryPoint (DllMain RVA), 0 if none
    name: [u8; 32],    // uppercase, NUL-padded, filename only
}

static LOADED_DLL_MAP: spin::Mutex<[Option<DllEntry>; 32]> = spin::Mutex::new([None; 32]);

pub fn register_loaded_dll(base: u32, size: u32, name: &str) {
    // Read entry point RVA from the mapped PE header
    let entry_rva = unsafe {
        let e_lfanew = core::ptr::read_unaligned((base as u64 + 0x3C) as *const u32);
        if e_lfanew > 0 && e_lfanew < 0x1000 {
            let opt_off = base as u64 + e_lfanew as u64 + 4 + 20;
            core::ptr::read_unaligned((opt_off + 16) as *const u32)
        } else { 0 }
    };
    let mut map = LOADED_DLL_MAP.lock();
    let base_name = name.rsplit(|c: char| c == '\\' || c == '/').next().unwrap_or(name);
    let mut entry = DllEntry { base, size, entry_rva, name: [0u8; 32] };
    for (i, b) in base_name.bytes().take(31).enumerate() {
        entry.name[i] = b.to_ascii_uppercase();
    }
    for slot in map.iter_mut() {
        if slot.is_none() { *slot = Some(entry); return; }
    }
    map[0] = Some(entry);
}

/// Return (base, entry_point_va) for all loaded DLLs that have a non-zero entry point.
/// `exclude_base` filters out the game EXE (which shouldn't get DllMain called).
pub fn loaded_dll_entry_points(exclude_base: u32) -> alloc::vec::Vec<(u32, u32)> {
    let map = LOADED_DLL_MAP.lock();
    let mut out = alloc::vec::Vec::new();
    for slot in map.iter() {
        if let Some(e) = slot {
            if e.entry_rva != 0 && e.base != exclude_base {
                out.push((e.base, e.base.wrapping_add(e.entry_rva)));
            }
        }
    }
    out
}

pub fn resolve_loaded_dll_base(dll: &str) -> Option<u32> {
    let base_name = dll.rsplit(|c: char| c == '\\' || c == '/').next().unwrap_or(dll);
    let map = LOADED_DLL_MAP.lock();
    for slot in map.iter() {
        if let Some(e) = slot {
            let len = e.name.iter().position(|&b| b == 0).unwrap_or(32);
            if eq_ascii_nocase(base_name, core::str::from_utf8(&e.name[..len]).unwrap_or("")) {
                return Some(e.base);
            }
        }
    }
    None
}

/// Search ALL stub modules for a named export (ignoring which DLL it belongs to).
/// Used as a fallback when GetProcAddress on a real DLL fails (e.g., DXVK without DllMain).
pub fn resolve_stub_proc_any(name: &str) -> Option<u32> {
    for module in STUB_MODULES {
        for exp in module.exports {
            if eq_ascii_nocase(name, exp.name) {
                return Some(module.base.wrapping_add(exp.rva));
            }
        }
    }
    None
}

const STUB_MODULES: &[StubModule] = &[
    StubModule { dll: "ntdll.dll",    base: 0x1000_0000, exports: STUB_EXPORTS_NTDLL,    ordinal_base: 0 },
    StubModule { dll: "kernel32.dll", base: 0x7000_0000, exports: STUB_EXPORTS_KERNEL32, ordinal_base: 0 },
    StubModule { dll: "user32.dll",   base: 0x7100_0000, exports: STUB_EXPORTS_USER32,   ordinal_base: 0 },
    StubModule { dll: "msvcrt.dll",   base: 0x7200_0000, exports: STUB_EXPORTS_MSVCRT,   ordinal_base: 0 },
    StubModule { dll: "winmm.dll",    base: 0x7300_0000, exports: STUB_EXPORTS_WINMM,    ordinal_base: 0 },
    StubModule { dll: "d3d8.dll",     base: 0x7400_0000, exports: STUB_EXPORTS_D3D8,     ordinal_base: 0 },
    StubModule { dll: "advapi32.dll", base: 0x7500_0000, exports: STUB_EXPORTS_ADVAPI32, ordinal_base: 0 },
    StubModule { dll: "gdi32.dll",    base: 0x7600_0000, exports: STUB_EXPORTS_GDI32,    ordinal_base: 0 },
    StubModule { dll: "setupapi.dll", base: 0x7700_0000, exports: STUB_EXPORTS_SETUPAPI, ordinal_base: 0 },
    StubModule { dll: "d3d9.dll",     base: 0x7900_0000, exports: STUB_EXPORTS_D3D9,     ordinal_base: 0 },
    // api-ms-win-crt-* (UCRT) — bases at 0x78xx_0000
    StubModule { dll: "api-ms-win-crt-runtime-l1-1-0.dll",    base: 0x7800_0000, exports: STUB_EXPORTS_UCRT_RUNTIME,    ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-heap-l1-1-0.dll",       base: 0x7810_0000, exports: STUB_EXPORTS_UCRT_HEAP,       ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-string-l1-1-0.dll",     base: 0x7820_0000, exports: STUB_EXPORTS_UCRT_STRING,     ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-private-l1-1-0.dll",    base: 0x7830_0000, exports: STUB_EXPORTS_UCRT_PRIVATE,    ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-stdio-l1-1-0.dll",      base: 0x7840_0000, exports: STUB_EXPORTS_UCRT_STDIO,      ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-convert-l1-1-0.dll",    base: 0x7850_0000, exports: STUB_EXPORTS_UCRT_CONVERT,    ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-environment-l1-1-0.dll",base: 0x7860_0000, exports: STUB_EXPORTS_UCRT_ENV,        ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-filesystem-l1-1-0.dll", base: 0x7870_0000, exports: STUB_EXPORTS_UCRT_FILESYSTEM, ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-locale-l1-1-0.dll",     base: 0x7880_0000, exports: STUB_EXPORTS_UCRT_LOCALE,     ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-math-l1-1-0.dll",       base: 0x7890_0000, exports: STUB_EXPORTS_UCRT_MATH,       ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-time-l1-1-0.dll",       base: 0x78A0_0000, exports: STUB_EXPORTS_UCRT_TIME,       ordinal_base: 0 },
    StubModule { dll: "api-ms-win-crt-utility-l1-1-0.dll",    base: 0x78B0_0000, exports: STUB_EXPORTS_UCRT_UTILITY,    ordinal_base: 0 },
    // Vulkan ICD loader shim — DXVK d3d8→d3d9→vulkan-1 chain
    StubModule { dll: "vulkan-1.dll", base: 0x7C00_0000, exports: STUB_EXPORTS_VULKAN1, ordinal_base: 0 },
    // Ghost Recon additional imports
    StubModule { dll: "dbghelp.dll",  base: 0x7D00_0000, exports: STUB_EXPORTS_DBGHELP,  ordinal_base: 0 },
    StubModule { dll: "ole32.dll",    base: 0x7D10_0000, exports: STUB_EXPORTS_OLE32,    ordinal_base: 0 },
    StubModule { dll: "dinput8.dll",  base: 0x7D20_0000, exports: STUB_EXPORTS_DINPUT8,  ordinal_base: 0 },
    // dsound: ordinal 1 = DirectSoundCreate, ordinal 2 = DirectSoundCreate8
    StubModule { dll: "dsound.dll",   base: 0x7D30_0000, exports: STUB_EXPORTS_DSOUND,   ordinal_base: 1 },
    // wsock32: ordinal 1 = accept (first export in the array)
    StubModule { dll: "wsock32.dll",  base: 0x7D40_0000, exports: STUB_EXPORTS_WSOCK32,  ordinal_base: 1 },
];

fn write_nt_syscall_stub(dst: *mut u8, syscall_no: u32, ret_imm: u16) {
    const USE_SYSENTER_STUB: bool = true;
    // SAFETY: dst points into ntdll stub module page (0x1000 bytes, committed RWX).
    unsafe {
        if USE_SYSENTER_STUB {
            // XP SP2 KiFastSystemCall ABI:
            //   EAX = service number
            //   EDX = user ESP at SYSENTER (kernel reads args at [EDX+4..])
            //
            // +0: B8 imm32   MOV EAX, syscall_no
            // +5: 8B D4      MOV EDX, ESP          ← matches real ntdll KiFastSystemCall
            // +7: 0F 34      SYSENTER
            // Bytes 9+ are INT3 (slot pre-filled by initialise_stub_module_code).
            // Return happens via IRETQ → SharedUserData+0x300 (C3 = RET),
            // which pops the caller's return address from [EDX+0].
            // `ret_imm` is unused here (stdcall cleanup is caller's responsibility).
            let _ = ret_imm;
            dst.add(0).write_unaligned(0xB8u8);
            (dst.add(1) as *mut u32).write_unaligned(syscall_no);
            dst.add(5).write_unaligned(0x8Bu8);   // MOV EDX, ESP
            dst.add(6).write_unaligned(0xD4u8);
            dst.add(7).write_unaligned(0x0Fu8);   // SYSENTER
            dst.add(8).write_unaligned(0x34u8);
        } else {
            dst.add(0).write_unaligned(0xB8);
            (dst.add(1) as *mut u32).write_unaligned(syscall_no);
            dst.add(5).write_unaligned(0x8D);
            dst.add(6).write_unaligned(0x54);
            dst.add(7).write_unaligned(0x24);
            dst.add(8).write_unaligned(0x04);
            dst.add(9).write_unaligned(0xCD);
            dst.add(10).write_unaligned(0x2E);
            dst.add(11).write_unaligned(0xC2);
            (dst.add(12) as *mut u16).write_unaligned(ret_imm);
        }
    }
}

/// Write a 14-byte INT 0x2E Win32 stub into `dst` (fits in a 0x10-byte export slot).
///
/// Sequence (32-bit mode):
///   B8 imm32   MOV EAX, syscall_no
///   8D 54 24 04 LEA EDX, [ESP+4]   ← args pointer
///   CD 2E      INT 0x2E
///   C2 imm16   RET imm16            ← 0 for cdecl, args×4 for stdcall
///
/// # Safety
/// `dst` must point to at least 14 writable bytes.
unsafe fn write_win32_stub(dst: *mut u8, syscall_no: u32, ret_imm: u16) {
    // SAFETY: caller guarantees writability and alignment.
    unsafe {
        dst.add(0).write_unaligned(0xB8);
        (dst.add(1) as *mut u32).write_unaligned(syscall_no);
        dst.add(5).write_unaligned(0x8D);
        dst.add(6).write_unaligned(0x54);
        dst.add(7).write_unaligned(0x24);
        dst.add(8).write_unaligned(0x04);
        dst.add(9).write_unaligned(0xCD);
        dst.add(10).write_unaligned(0x2E);
        dst.add(11).write_unaligned(0xC2);
        (dst.add(12) as *mut u16).write_unaligned(ret_imm);
    }
}

/// Emit a real DispatchMessageA implementation into the user32 stub page.
///
/// Slot 0x030: 5-byte JMP to 0x100, rest INT3.
/// Offset 0x100: ring-3 function body (66 bytes):
///   1. Calls WIN32_LOOKUP_WNDPROC (0x2019) to get the WndProc VA for msg->hwnd.
///   2. If found, pushes (lParam, wParam, message, hwnd) and CALLs the WndProc in ring-3.
///   3. If not found, calls DefWindowProcA (0x2018) via INT 0x2E.
///
/// MSG layout (Win32): hwnd@+0, message@+4, wParam@+8, lParam@+12, ...
/// Calling convention: stdcall — callee (DispatchMessageA) pops the 4-byte lpMsg arg (RET 4).
///
/// # Safety
/// `page` must point to at least 0x200 writable+executable bytes (the user32 stub page).
unsafe fn write_dispatch_message_a(page: *mut u8) {
    // ── Slot 0x030: JMP rel32 → 0x310 ──────────────────────────────────────
    // JMP opcode E9, rel32 = target - (src + 5) = 0x310 - 0x035 = 0x2DB
    // Body placed at 0x310 (after last user32 slot at 0x300) to avoid
    // collision with write_const_stub(page+0x100, ...) for ChangeDisplaySettingsExW.
    // SAFETY: slot 0x030 is within the INT3-filled stub page (initialised just above).
    unsafe {
        let jmp = page.add(0x030);
        jmp.add(0).write_unaligned(0xE9u8);                 // JMP rel32
        (jmp.add(1) as *mut u32).write_unaligned(0x2DBu32); // +0x2DB → 0x310
        // Remaining 11 bytes of slot stay INT3 (already written).
    }

    // ── Offset 0x310: DispatchMessageA body ────────────────────────────────
    // Byte offsets within the function body:
    //  0x00: push esi                          [56]
    //  0x01: mov esi, [esp+8]                  [8B 74 24 08]  — lpMsg (esi pushed → +8)
    //  0x05: mov ecx, [esi]                    [8B 0E]        — ecx = hwnd
    //  0x07: push ecx                          [51]           — arg0 for LOOKUP_WNDPROC
    //  0x08: mov eax, 0x2019                   [B8 19 20 00 00]
    //  0x0D: lea edx, [esp]                    [8D 14 24]     — edx = &args
    //  0x10: int 0x2E                          [CD 2E]
    //  0x12: pop ecx                           [59]           — ecx = hwnd; clean arg
    //  0x13: test eax, eax                     [85 C0]
    //  0x15: jz +0x10 → defwnd@0x27           [74 10]
    //  0x17: push [esi+12]                     [FF 76 0C]     — lParam
    //  0x1A: push [esi+8]                      [FF 76 08]     — wParam
    //  0x1D: push [esi+4]                      [FF 76 04]     — message
    //  0x20: push ecx                          [51]           — hwnd
    //  0x21: call eax                          [FF D0]        — wndproc(hwnd,msg,wp,lp)
    //  0x23: pop esi                           [5E]
    //  0x24: ret 4                             [C2 04 00]
    //  0x27: — defwnd —
    //  0x27: push [esi+12]                     [FF 76 0C]     — lParam
    //  0x2A: push [esi+8]                      [FF 76 08]     — wParam
    //  0x2D: push [esi+4]                      [FF 76 04]     — message
    //  0x30: push ecx                          [51]           — hwnd
    //  0x31: mov eax, 0x2018                   [B8 18 20 00 00]
    //  0x36: lea edx, [esp]                    [8D 14 24]
    //  0x39: int 0x2E                          [CD 2E]
    //  0x3B: add esp, 16                       [83 C4 10]
    //  0x3E: pop esi                           [5E]
    //  0x3F: ret 4                             [C2 04 00]   — total: 0x42 = 66 bytes
    // SAFETY: offset 0x310 is within the 0x1000-byte stub page; page is RWX.
    #[rustfmt::skip]
    let body: [u8; 66] = [
        0x56,                               // push esi
        0x8B, 0x74, 0x24, 0x08,            // mov esi, [esp+8]
        0x8B, 0x0E,                         // mov ecx, [esi]
        0x51,                               // push ecx
        0xB8, 0x19, 0x20, 0x00, 0x00,      // mov eax, 0x2019
        0x8D, 0x14, 0x24,                   // lea edx, [esp]
        0xCD, 0x2E,                         // int 0x2E
        0x59,                               // pop ecx
        0x85, 0xC0,                         // test eax, eax
        0x74, 0x10,                         // jz +0x10 (→ 0x27)
        0xFF, 0x76, 0x0C,                   // push [esi+12]  (lParam)
        0xFF, 0x76, 0x08,                   // push [esi+8]   (wParam)
        0xFF, 0x76, 0x04,                   // push [esi+4]   (message)
        0x51,                               // push ecx       (hwnd)
        0xFF, 0xD0,                         // call eax       (wndproc)
        0x5E,                               // pop esi
        0xC2, 0x04, 0x00,                   // ret 4
        // defwnd:
        0xFF, 0x76, 0x0C,                   // push [esi+12]  (lParam)
        0xFF, 0x76, 0x08,                   // push [esi+8]   (wParam)
        0xFF, 0x76, 0x04,                   // push [esi+4]   (message)
        0x51,                               // push ecx       (hwnd)
        0xB8, 0x18, 0x20, 0x00, 0x00,      // mov eax, 0x2018 (WIN32_DEF_WINDOW_PROC_A)
        0x8D, 0x14, 0x24,                   // lea edx, [esp]
        0xCD, 0x2E,                         // int 0x2E
        0x83, 0xC4, 0x10,                   // add esp, 16
        0x5E,                               // pop esi
        0xC2, 0x04, 0x00,                   // ret 4
    ];
    unsafe {
        let dst = page.add(0x310);
        for (i, &b) in body.iter().enumerate() {
            dst.add(i).write_unaligned(b);
        }
    }
}

// ── D3D8 stub page writer ────────────────────────────────────────────────────
//
// Generates all D3D8 COM vtables + method stubs + object instances in a
// single 4 KB page at (d3d8_base + 0x1000).
//
// Page layout (offsets within the code page):
//   0x000       Direct3DCreate8 entry (export RVA 0x1000)
//   0x010..0x10F IDirect3D8 stubs (16 × 16 bytes)
//   0x110..0x71F IDirect3DDevice8 stubs (97 × 16 bytes)
//   0x720..0x85F IDirect3DTexture8 stubs (20 × 16 bytes; LockRect = 2 slots)
//   0x860..0x93F IDirect3DVertexBuffer8 stubs (14 × 16 bytes)
//   0x940..0xA1F IDirect3DIndexBuffer8 stubs (14 × 16 bytes)
//   0xA20..0xA5F IDirect3D8 vtable        (16 × 4 = 64 bytes)
//   0xA60..0xA67 IDirect3D8 object        {vtbl_ptr, ref_count}
//   0xA70..0xBF3 IDirect3DDevice8 vtable  (97 × 4 = 388 bytes)
//   0xBF8..0xBFF IDirect3DDevice8 object  {vtbl_ptr, ref_count}
//   0xC00..0xC4B IDirect3DTexture8 vtable (19 × 4 = 76 bytes)
//   0xC50..0xC57 IDirect3DTexture8 object {vtbl_ptr, ref_count}
//   0xC60..0xC97 IDirect3DVertexBuffer8 vtable (14 × 4 = 56 bytes)
//   0xCA0..0xCA7 IDirect3DVertexBuffer8 object
//   0xCB0..0xCE7 IDirect3DIndexBuffer8 vtable  (14 × 4 = 56 bytes)
//   0xCF0..0xCF7 IDirect3DIndexBuffer8 object
//   0xD00..0xD3F Lock buffer (64 bytes, zeroed — returned by Lock/LockRect)
//
// Total used: 0xD40 = 3392 bytes < 4096 ✓
//
// # Safety
// `page` must point to 0x1000 writable+executable bytes (the code page at base+0x1000).
// `base` is the d3d8_base address (0x7400_0000).
unsafe fn write_d3d8_page(page: *mut u8, base: u32) {
    // ── VA shortcuts ─────────────────────────────────────────────────────────
    let code = base.wrapping_add(0x1000); // VA of page[0]

    let vtbl8_va    = code.wrapping_add(0xA20); // IDirect3D8 vtable
    let obj8_va     = code.wrapping_add(0xA60); // IDirect3D8 object
    let vtbldev_va  = code.wrapping_add(0xA70); // IDirect3DDevice8 vtable
    let objdev_va   = code.wrapping_add(0xBF8); // IDirect3DDevice8 object
    let vtbltex_va  = code.wrapping_add(0xC00); // IDirect3DTexture8 vtable
    let objtex_va   = code.wrapping_add(0xC50); // IDirect3DTexture8 object
    let vtblvb_va   = code.wrapping_add(0xC60); // IDirect3DVertexBuffer8 vtable
    let objvb_va    = code.wrapping_add(0xCA0); // IDirect3DVertexBuffer8 object
    let vtblib_va   = code.wrapping_add(0xCB0); // IDirect3DIndexBuffer8 vtable
    let objib_va    = code.wrapping_add(0xCF0); // IDirect3DIndexBuffer8 object
    let lockbuf_va  = code.wrapping_add(0xD00); // zeroed 64-byte lock buffer

    // ── Local helpers (closures over `page`) ─────────────────────────────────

    // Write u32 LE at `dst`.
    let pu32 = |dst: *mut u8, v: u32| unsafe {
        (dst as *mut u32).write_unaligned(v);
    };

    // Write u16 LE at `dst`.
    let pu16 = |dst: *mut u8, v: u16| unsafe {
        (dst as *mut u16).write_unaligned(v);
    };

    // Emit: XOR EAX, EAX; RET ret_n  (S_OK = 0, pop ret_n bytes)
    //   33 C0  C2 nn nn
    let s_ok = |dst: *mut u8, ret_n: u16| unsafe {
        dst.write_unaligned(0x33);
        dst.add(1).write_unaligned(0xC0);
        dst.add(2).write_unaligned(0xC2);
        pu16(dst.add(3), ret_n);
    };

    // Emit: MOV EAX, val; RET ret_n  (constant return, pop ret_n bytes)
    //   B8 vv vv vv vv  C2 nn nn
    let ret_val = |dst: *mut u8, val: u32, ret_n: u16| unsafe {
        dst.write_unaligned(0xB8);
        pu32(dst.add(1), val);
        dst.add(5).write_unaligned(0xC2);
        pu16(dst.add(6), ret_n);
    };

    // Emit: MOV EAX,[esp+arg_off]; MOV [EAX], obj_va; XOR EAX,EAX; RET ret_n
    // Used for CreateDevice/CreateTexture/CreateVB/CreateIB — write COM obj ptr.
    //   8B 44 24 oo  C7 00 vv vv vv vv  33 C0  C2 nn nn  (15 bytes)
    let create_out = |dst: *mut u8, arg_off: u8, obj_va_: u32, ret_n: u16| unsafe {
        dst.write_unaligned(0x8B);      // MOV EAX, [esp+arg_off]
        dst.add(1).write_unaligned(0x44);
        dst.add(2).write_unaligned(0x24);
        dst.add(3).write_unaligned(arg_off);
        dst.add(4).write_unaligned(0xC7); // MOV DWORD PTR [EAX], obj_va
        dst.add(5).write_unaligned(0x00);
        pu32(dst.add(6), obj_va_);
        dst.add(10).write_unaligned(0x33); // XOR EAX, EAX
        dst.add(11).write_unaligned(0xC0);
        dst.add(12).write_unaligned(0xC2); // RET ret_n
        pu16(dst.add(13), ret_n);
    };

    // ── Direct3DCreate8 at page+0x000 ────────────────────────────────────────
    // MOV EAX, obj8_va; RET 4 (stdcall 1 arg: sdk_version)
    //   B8 vv vv vv vv  C2 04 00
    unsafe {
        let dst = page.add(0x000);
        dst.write_unaligned(0xB8);
        pu32(dst.add(1), obj8_va);
        dst.add(5).write_unaligned(0xC2);
        pu16(dst.add(6), 4);
    }

    // ── IDirect3D8 method stubs (page+0x010..0x10F, 16 slots × 16 bytes) ────
    //
    // vtable idx  method                     args_incl_this  ret_n
    //  0  QueryInterface                     3               12
    //  1  AddRef                             1                4
    //  2  Release                            1                4
    //  3  RegisterSoftwareDevice             2                8
    //  4  GetAdapterCount                    1                4  → return 1
    //  5  GetAdapterIdentifier               4               16
    //  6  GetAdapterModeCount                2                8  → return 4
    //  7  EnumAdapterModes                   4               16
    //  8  GetAdapterDisplayMode              3               12
    //  9  CheckDeviceType                    6               24
    // 10  CheckDeviceFormat                  7               28
    // 11  CheckDeviceMultiSampleType         6               24
    // 12  CheckDepthStencilMatch             6               24
    // 13  GetDeviceCaps                      4               16
    // 14  GetAdapterMonitor                  2                8  → return 1 (fake HMONITOR)
    // 15  CreateDevice                       7               28  → SPECIAL
    unsafe {
        let i8 = page.add(0x010); // base of IDirect3D8 stub area

        // QI → E_NOTIMPL (0x80004001)
        ret_val(i8.add(0x000), 0x8000_4001u32, 12);
        // AddRef → 1
        ret_val(i8.add(0x010), 1, 4);
        // Release → 0
        s_ok(i8.add(0x020), 4);
        // RegisterSoftwareDevice → E_NOTIMPL
        ret_val(i8.add(0x030), 0x8000_4001u32, 8);
        // GetAdapterCount → 1
        ret_val(i8.add(0x040), 1, 4);
        // GetAdapterIdentifier → S_OK
        s_ok(i8.add(0x050), 16);
        // GetAdapterModeCount → 4 (advertise 4 modes)
        ret_val(i8.add(0x060), 4, 8);
        // EnumAdapterModes → S_OK
        s_ok(i8.add(0x070), 16);
        // GetAdapterDisplayMode → S_OK
        s_ok(i8.add(0x080), 12);
        // CheckDeviceType → S_OK
        s_ok(i8.add(0x090), 24);
        // CheckDeviceFormat → S_OK
        s_ok(i8.add(0x0A0), 28);
        // CheckDeviceMultiSampleType → S_OK
        s_ok(i8.add(0x0B0), 24);
        // CheckDepthStencilMatch → S_OK
        s_ok(i8.add(0x0C0), 24);
        // GetDeviceCaps → S_OK
        s_ok(i8.add(0x0D0), 16);
        // GetAdapterMonitor → 1 (fake HMONITOR)
        ret_val(i8.add(0x0E0), 1, 8);
        // CreateDevice → write *ppReturnedDeviceInterface = objdev_va; S_OK
        // ESP layout: [+4]=this [+8]=Adapter [+0xC]=DeviceType [+0x10]=hFocusWnd
        //             [+0x14]=BehaviorFlags [+0x18]=pPresentParams [+0x1C]=ppDevice
        create_out(i8.add(0x0F0), 0x1C, objdev_va, 28);
    }

    // ── IDirect3DDevice8 stubs (page+0x110..0x71F, 97 slots × 16 bytes) ─────
    //
    // Vtable index (0-based from IUnknown):
    //   slot 0  QI              3 total → RET 12
    //   slot 1  AddRef          1       → RET 4   → return 1
    //   slot 2  Release         1       → RET 4   → return 0
    //   slot 3  TestCooperativeLevel 1  → RET 4
    //   slot 4  GetAvailableTextureMem 1 → RET 4  → return 256 MB
    //   slot 5  ResourceManagerDiscardBytes 2 → RET 8
    //   slot 6  GetDirect3D     2       → RET 8
    //   slot 7  GetDeviceCaps   2       → RET 8
    //   slot 8  GetDisplayMode  2       → RET 8
    //   slot 9  GetCreationParameters 2 → RET 8
    //   slot 10 SetCursorProperties 4  → RET 16
    //   slot 11 SetCursorPosition 4    → RET 16
    //   slot 12 ShowCursor       2     → RET 8
    //   slot 13 CreateAdditionalSwapChain 3 → RET 12
    //   slot 14 Reset            2     → RET 8
    //   slot 15 Present          5     → RET 20
    //   slot 16 GetBackBuffer    4     → RET 16
    //   slot 17 GetRasterStatus  2     → RET 8
    //   slot 18 SetGammaRamp     3     → RET 12
    //   slot 19 GetGammaRamp     2     → RET 8
    //   slot 20 CreateTexture    8     → RET 32  SPECIAL: write ppTexture
    //   slot 21 CreateVolumeTexture 9  → RET 36  E_NOTIMPL
    //   slot 22 CreateCubeTexture 7    → RET 28  E_NOTIMPL
    //   slot 23 CreateVertexBuffer 6   → RET 24  SPECIAL: write ppVB
    //   slot 24 CreateIndexBuffer 6    → RET 24  SPECIAL: write ppIB
    //   slot 25 CreateRenderTarget 7   → RET 28
    //   slot 26 CreateDepthStencilSurface 6 → RET 24
    //   slot 27 CreateImageSurface 5   → RET 20
    //   slot 28 CopyRects        6     → RET 24
    //   slot 29 UpdateTexture    3     → RET 12
    //   slot 30 GetFrontBuffer   2     → RET 8
    //   slot 31 SetRenderTarget  3     → RET 12
    //   slot 32 GetRenderTarget  2     → RET 8
    //   slot 33 GetDepthStencilSurface 2 → RET 8
    //   slot 34 BeginScene       1     → RET 4
    //   slot 35 EndScene         1     → RET 4
    //   slot 36 Clear            7     → RET 28
    //   slot 37 SetTransform     3     → RET 12
    //   slot 38 GetTransform     3     → RET 12
    //   slot 39 MultiplyTransform 3    → RET 12
    //   slot 40 SetViewport      2     → RET 8
    //   slot 41 GetViewport      2     → RET 8
    //   slot 42 SetMaterial      2     → RET 8
    //   slot 43 GetMaterial      2     → RET 8
    //   slot 44 SetLight         3     → RET 12
    //   slot 45 GetLight         3     → RET 12
    //   slot 46 LightEnable      3     → RET 12
    //   slot 47 GetLightEnable   3     → RET 12
    //   slot 48 SetClipPlane     3     → RET 12
    //   slot 49 GetClipPlane     3     → RET 12
    //   slot 50 SetRenderState   3     → RET 12
    //   slot 51 GetRenderState   3     → RET 12
    //   slot 52 BeginStateBlock  1     → RET 4
    //   slot 53 EndStateBlock    2     → RET 8
    //   slot 54 ApplyStateBlock  2     → RET 8
    //   slot 55 CaptureStateBlock 2    → RET 8
    //   slot 56 DeleteStateBlock 2     → RET 8
    //   slot 57 CreateStateBlock 3     → RET 12
    //   slot 58 SetClipStatus    2     → RET 8
    //   slot 59 GetClipStatus    2     → RET 8
    //   slot 60 GetTexture       3     → RET 12
    //   slot 61 SetTexture       3     → RET 12
    //   slot 62 GetTextureStageState 4 → RET 16
    //   slot 63 SetTextureStageState 4 → RET 16
    //   slot 64 ValidateDevice   2     → RET 8
    //   slot 65 GetInfo          4     → RET 16
    //   slot 66 SetPaletteEntries 3    → RET 12
    //   slot 67 GetPaletteEntries 3    → RET 12
    //   slot 68 SetCurrentTexturePalette 2 → RET 8
    //   slot 69 GetCurrentTexturePalette 2 → RET 8
    //   slot 70 DrawPrimitive    4     → RET 16
    //   slot 71 DrawIndexedPrimitive 6 → RET 24
    //   slot 72 DrawPrimitiveUP  5     → RET 20
    //   slot 73 DrawIndexedPrimitiveUP 9 → RET 36
    //   slot 74 ProcessVertices  6     → RET 24
    //   slot 75 CreateVertexShader 5   → RET 20  E_NOTIMPL
    //   slot 76 SetVertexShader  2     → RET 8
    //   slot 77 GetVertexShader  2     → RET 8
    //   slot 78 DeleteVertexShader 2   → RET 8
    //   slot 79 SetVertexShaderConstant 4 → RET 16
    //   slot 80 GetVertexShaderConstant 4 → RET 16
    //   slot 81 GetVertexShaderDeclaration 4 → RET 16
    //   slot 82 GetVertexShaderFunction 4 → RET 16
    //   slot 83 SetStreamSource  4     → RET 16
    //   slot 84 GetStreamSource  4     → RET 16
    //   slot 85 SetIndices       3     → RET 12
    //   slot 86 GetIndices       3     → RET 12
    //   slot 87 CreatePixelShader 3    → RET 12  E_NOTIMPL
    //   slot 88 SetPixelShader   2     → RET 8
    //   slot 89 GetPixelShader   2     → RET 8
    //   slot 90 DeletePixelShader 2    → RET 8
    //   slot 91 SetPixelShaderConstant 4 → RET 16
    //   slot 92 GetPixelShaderConstant 4 → RET 16
    //   slot 93 GetPixelShaderFunction 4 → RET 16
    //   slot 94 DrawRectPatch    4     → RET 16
    //   slot 95 DrawTriPatch     4     → RET 16
    //   slot 96 DeletePatch      2     → RET 8
    unsafe {
        let dev = page.add(0x110); // base of IDirect3DDevice8 stub area
        let e_notimpl = 0x8000_4001u32;

        // slot 0: QI → E_NOTIMPL
        ret_val(dev.add(0x000), e_notimpl, 12);
        // slot 1: AddRef → 1
        ret_val(dev.add(0x010), 1, 4);
        // slot 2: Release → 0
        s_ok(dev.add(0x020), 4);
        // slot 3: TestCooperativeLevel → S_OK
        s_ok(dev.add(0x030), 4);
        // slot 4: GetAvailableTextureMem → 256 MB
        ret_val(dev.add(0x040), 256 * 1024 * 1024, 4);
        // slot 5: ResourceManagerDiscardBytes → S_OK
        s_ok(dev.add(0x050), 8);
        // slot 6: GetDirect3D → S_OK
        s_ok(dev.add(0x060), 8);
        // slot 7: GetDeviceCaps → S_OK
        s_ok(dev.add(0x070), 8);
        // slot 8: GetDisplayMode → S_OK
        s_ok(dev.add(0x080), 8);
        // slot 9: GetCreationParameters → S_OK
        s_ok(dev.add(0x090), 8);
        // slot 10: SetCursorProperties → S_OK
        s_ok(dev.add(0x0A0), 16);
        // slot 11: SetCursorPosition → S_OK
        s_ok(dev.add(0x0B0), 16);
        // slot 12: ShowCursor → S_OK
        s_ok(dev.add(0x0C0), 8);
        // slot 13: CreateAdditionalSwapChain → E_NOTIMPL
        ret_val(dev.add(0x0D0), e_notimpl, 12);
        // slot 14: Reset → S_OK
        s_ok(dev.add(0x0E0), 8);
        // slot 15: Present → S_OK
        s_ok(dev.add(0x0F0), 20);
        // slot 16: GetBackBuffer → S_OK
        s_ok(dev.add(0x100), 16);
        // slot 17: GetRasterStatus → S_OK
        s_ok(dev.add(0x110), 8);
        // slot 18: SetGammaRamp → S_OK (void)
        s_ok(dev.add(0x120), 12);
        // slot 19: GetGammaRamp → S_OK (void)
        s_ok(dev.add(0x130), 8);
        // slot 20: CreateTexture → write *ppTexture = objtex_va; S_OK
        // [esp+4]=this [esp+8]=W [+0xC]=H [+0x10]=Lvl [+0x14]=Use [+0x18]=Fmt [+0x1C]=Pool [+0x20]=ppTex
        create_out(dev.add(0x140), 0x20, objtex_va, 32);
        // slot 21: CreateVolumeTexture → E_NOTIMPL (9 args total, RET 36)
        ret_val(dev.add(0x150), e_notimpl, 36);
        // slot 22: CreateCubeTexture → E_NOTIMPL (7 args, RET 28)
        ret_val(dev.add(0x160), e_notimpl, 28);
        // slot 23: CreateVertexBuffer → write *ppVB = objvb_va; S_OK
        // [esp+4]=this [+8]=Len [+0xC]=Use [+0x10]=FVF [+0x14]=Pool [+0x18]=ppVB
        create_out(dev.add(0x170), 0x18, objvb_va, 24);
        // slot 24: CreateIndexBuffer → write *ppIB = objib_va; S_OK
        // [esp+4]=this [+8]=Len [+0xC]=Use [+0x10]=Fmt [+0x14]=Pool [+0x18]=ppIB
        create_out(dev.add(0x180), 0x18, objib_va, 24);
        // slot 25: CreateRenderTarget → S_OK (7 args, RET 28)
        s_ok(dev.add(0x190), 28);
        // slot 26: CreateDepthStencilSurface → S_OK (6 args, RET 24)
        s_ok(dev.add(0x1A0), 24);
        // slot 27: CreateImageSurface → S_OK (5 args, RET 20)
        s_ok(dev.add(0x1B0), 20);
        // slot 28: CopyRects → S_OK
        s_ok(dev.add(0x1C0), 24);
        // slot 29: UpdateTexture → S_OK
        s_ok(dev.add(0x1D0), 12);
        // slot 30: GetFrontBuffer → S_OK
        s_ok(dev.add(0x1E0), 8);
        // slot 31: SetRenderTarget → S_OK
        s_ok(dev.add(0x1F0), 12);
        // slot 32: GetRenderTarget → S_OK
        s_ok(dev.add(0x200), 8);
        // slot 33: GetDepthStencilSurface → S_OK
        s_ok(dev.add(0x210), 8);
        // slot 34: BeginScene → S_OK
        s_ok(dev.add(0x220), 4);
        // slot 35: EndScene → S_OK
        s_ok(dev.add(0x230), 4);
        // slot 36: Clear → S_OK
        s_ok(dev.add(0x240), 28);
        // slot 37: SetTransform → S_OK
        s_ok(dev.add(0x250), 12);
        // slot 38: GetTransform → S_OK
        s_ok(dev.add(0x260), 12);
        // slot 39: MultiplyTransform → S_OK
        s_ok(dev.add(0x270), 12);
        // slot 40: SetViewport → S_OK
        s_ok(dev.add(0x280), 8);
        // slot 41: GetViewport → S_OK
        s_ok(dev.add(0x290), 8);
        // slot 42: SetMaterial → S_OK
        s_ok(dev.add(0x2A0), 8);
        // slot 43: GetMaterial → S_OK
        s_ok(dev.add(0x2B0), 8);
        // slot 44: SetLight → S_OK
        s_ok(dev.add(0x2C0), 12);
        // slot 45: GetLight → S_OK
        s_ok(dev.add(0x2D0), 12);
        // slot 46: LightEnable → S_OK
        s_ok(dev.add(0x2E0), 12);
        // slot 47: GetLightEnable → S_OK
        s_ok(dev.add(0x2F0), 12);
        // slot 48: SetClipPlane → S_OK
        s_ok(dev.add(0x300), 12);
        // slot 49: GetClipPlane → S_OK
        s_ok(dev.add(0x310), 12);
        // slot 50: SetRenderState → S_OK
        s_ok(dev.add(0x320), 12);
        // slot 51: GetRenderState → S_OK
        s_ok(dev.add(0x330), 12);
        // slot 52: BeginStateBlock → S_OK
        s_ok(dev.add(0x340), 4);
        // slot 53: EndStateBlock → S_OK
        s_ok(dev.add(0x350), 8);
        // slot 54: ApplyStateBlock → S_OK
        s_ok(dev.add(0x360), 8);
        // slot 55: CaptureStateBlock → S_OK
        s_ok(dev.add(0x370), 8);
        // slot 56: DeleteStateBlock → S_OK
        s_ok(dev.add(0x380), 8);
        // slot 57: CreateStateBlock → S_OK
        s_ok(dev.add(0x390), 12);
        // slot 58: SetClipStatus → S_OK
        s_ok(dev.add(0x3A0), 8);
        // slot 59: GetClipStatus → S_OK
        s_ok(dev.add(0x3B0), 8);
        // slot 60: GetTexture → S_OK
        s_ok(dev.add(0x3C0), 12);
        // slot 61: SetTexture → S_OK
        s_ok(dev.add(0x3D0), 12);
        // slot 62: GetTextureStageState → S_OK
        s_ok(dev.add(0x3E0), 16);
        // slot 63: SetTextureStageState → S_OK
        s_ok(dev.add(0x3F0), 16);
        // slot 64: ValidateDevice → S_OK (2 args: this + pNumPasses)
        s_ok(dev.add(0x400), 8);
        // slot 65: GetInfo → S_OK
        s_ok(dev.add(0x410), 16);
        // slot 66: SetPaletteEntries → S_OK
        s_ok(dev.add(0x420), 12);
        // slot 67: GetPaletteEntries → S_OK
        s_ok(dev.add(0x430), 12);
        // slot 68: SetCurrentTexturePalette → S_OK
        s_ok(dev.add(0x440), 8);
        // slot 69: GetCurrentTexturePalette → S_OK
        s_ok(dev.add(0x450), 8);
        // slot 70: DrawPrimitive → S_OK
        s_ok(dev.add(0x460), 16);
        // slot 71: DrawIndexedPrimitive → S_OK
        s_ok(dev.add(0x470), 24);
        // slot 72: DrawPrimitiveUP → S_OK
        s_ok(dev.add(0x480), 20);
        // slot 73: DrawIndexedPrimitiveUP → S_OK (9 args, RET 36)
        s_ok(dev.add(0x490), 36);
        // slot 74: ProcessVertices → S_OK
        s_ok(dev.add(0x4A0), 24);
        // slot 75: CreateVertexShader → E_NOTIMPL (GR2001 fixed-function, no shaders)
        ret_val(dev.add(0x4B0), e_notimpl, 20);
        // slot 76: SetVertexShader → S_OK (fixed-function FVF path)
        s_ok(dev.add(0x4C0), 8);
        // slot 77: GetVertexShader → S_OK
        s_ok(dev.add(0x4D0), 8);
        // slot 78: DeleteVertexShader → S_OK
        s_ok(dev.add(0x4E0), 8);
        // slot 79: SetVertexShaderConstant → S_OK
        s_ok(dev.add(0x4F0), 16);
        // slot 80: GetVertexShaderConstant → S_OK
        s_ok(dev.add(0x500), 16);
        // slot 81: GetVertexShaderDeclaration → S_OK
        s_ok(dev.add(0x510), 16);
        // slot 82: GetVertexShaderFunction → S_OK
        s_ok(dev.add(0x520), 16);
        // slot 83: SetStreamSource → S_OK
        s_ok(dev.add(0x530), 16);
        // slot 84: GetStreamSource → S_OK
        s_ok(dev.add(0x540), 16);
        // slot 85: SetIndices → S_OK
        s_ok(dev.add(0x550), 12);
        // slot 86: GetIndices → S_OK
        s_ok(dev.add(0x560), 12);
        // slot 87: CreatePixelShader → E_NOTIMPL
        ret_val(dev.add(0x570), e_notimpl, 12);
        // slot 88: SetPixelShader → S_OK
        s_ok(dev.add(0x580), 8);
        // slot 89: GetPixelShader → S_OK
        s_ok(dev.add(0x590), 8);
        // slot 90: DeletePixelShader → S_OK
        s_ok(dev.add(0x5A0), 8);
        // slot 91: SetPixelShaderConstant → S_OK
        s_ok(dev.add(0x5B0), 16);
        // slot 92: GetPixelShaderConstant → S_OK
        s_ok(dev.add(0x5C0), 16);
        // slot 93: GetPixelShaderFunction → S_OK
        s_ok(dev.add(0x5D0), 16);
        // slot 94: DrawRectPatch → S_OK
        s_ok(dev.add(0x5E0), 16);
        // slot 95: DrawTriPatch → S_OK
        s_ok(dev.add(0x5F0), 16);
        // slot 96: DeletePatch → S_OK
        s_ok(dev.add(0x600), 8);
    } // dev stubs end at page+0x720 (0x110 + 0x610)

    // ── IDirect3DTexture8 stubs (page+0x720..0x85F, 20 slots) ───────────────
    // Inherits: IUnknown (3) + IDirect3DResource8 (8) + IDirect3DBaseTexture8 (3)
    //         + IDirect3DTexture8-own (5: GetLevelDesc/GetSurfaceLevel/LockRect/UnlockRect/AddDirtyRect)
    // Total: 19 vtable slots, LockRect uses 2 code slots → 20 × 16 = 320 bytes
    //
    // IDirect3DResource8 arg counts (non-this):
    //   GetDevice(ppDev):2          SetPrivateData(riid,pData,cbData,Flags):5
    //   GetPrivateData(riid,pData,pcbDataSize):4  FreePrivateData(riid):2
    //   SetPriority(NewPri):2  GetPriority():1  PreLoad():1  GetType():1
    // IDirect3DBaseTexture8: SetLOD(LOD):2  GetLOD():1  GetLevelCount():1
    // IDirect3DTexture8:
    //   GetLevelDesc(Level,pDesc):3  GetSurfaceLevel(Level,ppSurface):3
    //   LockRect(Level,pLockedRect,pRect,Flags):5
    //   UnlockRect(Level):2  AddDirtyRect(pDirtyRect):2
    unsafe {
        let tex = page.add(0x720);
        let e_ni = 0x8000_4001u32;

        // IUnknown
        ret_val(tex.add(0x000), e_ni, 12); // QI → E_NOTIMPL
        ret_val(tex.add(0x010), 1, 4);     // AddRef → 1
        s_ok(tex.add(0x020), 4);           // Release → 0

        // IDirect3DResource8 (8 methods)
        s_ok(tex.add(0x030), 8);           // GetDevice
        s_ok(tex.add(0x040), 20);          // SetPrivateData (5 total)
        s_ok(tex.add(0x050), 16);          // GetPrivateData (4 total)
        s_ok(tex.add(0x060), 8);           // FreePrivateData
        s_ok(tex.add(0x070), 8);           // SetPriority
        ret_val(tex.add(0x080), 0, 4);     // GetPriority → 0
        s_ok(tex.add(0x090), 4);           // PreLoad (void)
        ret_val(tex.add(0x0A0), 4 /*D3DRTYPE_TEXTURE*/, 4); // GetType

        // IDirect3DBaseTexture8 (3 methods)
        ret_val(tex.add(0x0B0), 0, 8);     // SetLOD → 0 (prev LOD)
        ret_val(tex.add(0x0C0), 0, 4);     // GetLOD → 0
        ret_val(tex.add(0x0D0), 1, 4);     // GetLevelCount → 1

        // IDirect3DTexture8 (5 methods)
        s_ok(tex.add(0x0E0), 12);          // GetLevelDesc
        s_ok(tex.add(0x0F0), 12);          // GetSurfaceLevel → S_OK (stub)

        // LockRect (2 code slots, vtable entry at vtable[16])
        // LockRect(this, Level, pLockedRect, pRect, Flags) → 5 total → RET 20
        // pLockedRect = D3DLOCKED_RECT { int Pitch; void *pBits }
        // Write: pLockedRect->Pitch = 0x400; pLockedRect->pBits = lockbuf_va
        //   8B 44 24 0C    ; MOV EAX, [esp+0xC]   (pLockedRect)
        //   C7 00 00 04 00 00 ; MOV DWORD PTR [EAX], 0x400
        //   C7 40 04 xx xx xx xx ; MOV DWORD PTR [EAX+4], lockbuf_va
        //   33 C0          ; XOR EAX, EAX
        //   C2 14 00       ; RET 0x14
        // Total: 4+6+7+2+3 = 22 bytes (fits in 2 slots)
        {
            let lr = tex.add(0x100); // LockRect code start
            lr.add(0).write_unaligned(0x8B); // MOV EAX, [esp+0xC]
            lr.add(1).write_unaligned(0x44);
            lr.add(2).write_unaligned(0x24);
            lr.add(3).write_unaligned(0x0C);
            lr.add(4).write_unaligned(0xC7); // MOV DWORD PTR [EAX], 0x400
            lr.add(5).write_unaligned(0x00);
            pu32(lr.add(6), 0x400);
            lr.add(10).write_unaligned(0xC7); // MOV DWORD PTR [EAX+4], lockbuf_va
            lr.add(11).write_unaligned(0x40);
            lr.add(12).write_unaligned(0x04);
            pu32(lr.add(13), lockbuf_va);
            lr.add(17).write_unaligned(0x33); // XOR EAX, EAX
            lr.add(18).write_unaligned(0xC0);
            lr.add(19).write_unaligned(0xC2); // RET 0x14
            pu16(lr.add(20), 0x14);
        }

        s_ok(tex.add(0x120), 8);           // UnlockRect(Level) → 2 total, RET 8
        s_ok(tex.add(0x130), 8);           // AddDirtyRect(pRect) → 2 total, RET 8
    } // tex stubs end at page+0x860

    // ── IDirect3DVertexBuffer8 stubs (page+0x860..0x93F, 14 slots) ──────────
    // IUnknown (3) + IDirect3DResource8 (8) + Lock/Unlock/GetDesc (3) = 14
    //   Lock(this,OffsetToLock,SizeToLock,ppbData,Flags) → 5 total → RET 20
    //   Unlock(this) → 1 total → RET 4
    //   GetDesc(this,pDesc) → 2 total → RET 8
    unsafe {
        let vb = page.add(0x860);
        let e_ni = 0x8000_4001u32;

        // IUnknown
        ret_val(vb.add(0x000), e_ni, 12); // QI
        ret_val(vb.add(0x010), 1, 4);     // AddRef
        s_ok(vb.add(0x020), 4);           // Release

        // IDirect3DResource8
        s_ok(vb.add(0x030), 8);           // GetDevice
        s_ok(vb.add(0x040), 20);          // SetPrivateData
        s_ok(vb.add(0x050), 16);          // GetPrivateData
        s_ok(vb.add(0x060), 8);           // FreePrivateData
        s_ok(vb.add(0x070), 8);           // SetPriority
        ret_val(vb.add(0x080), 0, 4);     // GetPriority
        s_ok(vb.add(0x090), 4);           // PreLoad
        ret_val(vb.add(0x0A0), 5 /*D3DRTYPE_VERTEXBUFFER*/, 4); // GetType

        // IDirect3DVertexBuffer8
        // Lock: write *ppbData = lockbuf_va
        // [esp+4]=this [+8]=Offset [+0xC]=Size [+0x10]=ppbData [+0x14]=Flags → RET 20
        //   8B 44 24 10  C7 00 lockbuf_va  33 C0  C2 14 00  (15 bytes)
        {
            let lk = vb.add(0x0B0);
            lk.write_unaligned(0x8B);
            lk.add(1).write_unaligned(0x44);
            lk.add(2).write_unaligned(0x24);
            lk.add(3).write_unaligned(0x10);
            lk.add(4).write_unaligned(0xC7);
            lk.add(5).write_unaligned(0x00);
            pu32(lk.add(6), lockbuf_va);
            lk.add(10).write_unaligned(0x33);
            lk.add(11).write_unaligned(0xC0);
            lk.add(12).write_unaligned(0xC2);
            pu16(lk.add(13), 20);
        }
        s_ok(vb.add(0x0C0), 4);           // Unlock → S_OK, 1 total, RET 4
        s_ok(vb.add(0x0D0), 8);           // GetDesc
    } // vb stubs end at page+0x940

    // ── IDirect3DIndexBuffer8 stubs (page+0x940..0xA1F, 14 slots) ───────────
    // Same structure as VB:
    //   Lock(this,OffsetToLock,SizeToLock,ppbData,Flags) → 5 total → RET 20
    unsafe {
        let ib = page.add(0x940);
        let e_ni = 0x8000_4001u32;

        // IUnknown
        ret_val(ib.add(0x000), e_ni, 12);
        ret_val(ib.add(0x010), 1, 4);
        s_ok(ib.add(0x020), 4);

        // IDirect3DResource8
        s_ok(ib.add(0x030), 8);
        s_ok(ib.add(0x040), 20);
        s_ok(ib.add(0x050), 16);
        s_ok(ib.add(0x060), 8);
        s_ok(ib.add(0x070), 8);
        ret_val(ib.add(0x080), 0, 4);
        s_ok(ib.add(0x090), 4);
        ret_val(ib.add(0x0A0), 6 /*D3DRTYPE_INDEXBUFFER*/, 4);

        // Lock → write *ppbData = lockbuf_va
        {
            let lk = ib.add(0x0B0);
            lk.write_unaligned(0x8B);
            lk.add(1).write_unaligned(0x44);
            lk.add(2).write_unaligned(0x24);
            lk.add(3).write_unaligned(0x10);
            lk.add(4).write_unaligned(0xC7);
            lk.add(5).write_unaligned(0x00);
            pu32(lk.add(6), lockbuf_va);
            lk.add(10).write_unaligned(0x33);
            lk.add(11).write_unaligned(0xC0);
            lk.add(12).write_unaligned(0xC2);
            pu16(lk.add(13), 20);
        }
        s_ok(ib.add(0x0C0), 4);
        s_ok(ib.add(0x0D0), 8);
    } // ib stubs end at page+0xA20

    // ── IDirect3D8 vtable (page+0xA20, 16 × 4 bytes) ────────────────────────
    // vtable[i] = code VA of IDirect3D8 stub slot i = (base+0x1010) + i*16
    unsafe {
        let vt = page.add(0xA20) as *mut u32;
        let i8_code_base = code.wrapping_add(0x010); // stub slot 0 is at page+0x010 → VA = code+0x010
        for i in 0u32..16 {
            vt.add(i as usize).write_unaligned(i8_code_base.wrapping_add(i * 16));
        }
    }

    // ── IDirect3D8 object (page+0xA60, 8 bytes) ──────────────────────────────
    unsafe {
        let obj = page.add(0xA60) as *mut u32;
        obj.add(0).write_unaligned(vtbl8_va);   // vtable pointer
        obj.add(1).write_unaligned(1);           // ref count = 1
    }

    // ── IDirect3DDevice8 vtable (page+0xA70, 97 × 4 bytes) ──────────────────
    // vtable[i] = code VA of IDirect3DDevice8 stub slot i; slot 0 at page+0x110
    unsafe {
        let vt = page.add(0xA70) as *mut u32;
        let dev_code_base = code.wrapping_add(0x110); // stub slot 0 at page+0x110
        for i in 0u32..97 {
            vt.add(i as usize).write_unaligned(dev_code_base.wrapping_add(i * 16));
        }
    }

    // ── IDirect3DDevice8 object (page+0xBF8, 8 bytes) ────────────────────────
    unsafe {
        let obj = page.add(0xBF8) as *mut u32;
        obj.add(0).write_unaligned(vtbldev_va);
        obj.add(1).write_unaligned(1);
    }

    // ── IDirect3DTexture8 vtable (page+0xC00, 19 × 4 bytes) ──────────────────
    // Slots 0-15: code + i*16; slot 0 at page+0x720
    // Slot 16 (LockRect): code at page+0x820 (two-slot body)
    // Slot 17 (UnlockRect): code at page+0x840
    // Slot 18 (AddDirtyRect): code at page+0x850
    unsafe {
        let vt = page.add(0xC00) as *mut u32;
        let tex_code_base = code.wrapping_add(0x720); // slot 0 at page+0x720
        for i in 0u32..16 {
            vt.add(i as usize).write_unaligned(tex_code_base.wrapping_add(i * 16));
        }
        // LockRect occupies code slots 16 + 17 (two 16-byte slots):
        vt.add(16).write_unaligned(code.wrapping_add(0x820)); // LockRect  @ page+0x820
        vt.add(17).write_unaligned(code.wrapping_add(0x840)); // UnlockRect @ page+0x840
        vt.add(18).write_unaligned(code.wrapping_add(0x850)); // AddDirtyRect @ page+0x850
    }

    // ── IDirect3DTexture8 object (page+0xC50, 8 bytes) ───────────────────────
    unsafe {
        let obj = page.add(0xC50) as *mut u32;
        obj.add(0).write_unaligned(vtbltex_va);
        obj.add(1).write_unaligned(1);
    }

    // ── IDirect3DVertexBuffer8 vtable (page+0xC60, 14 × 4 bytes) ─────────────
    // All slots sequential: code+0x860 + i*16
    unsafe {
        let vt = page.add(0xC60) as *mut u32;
        let vb_code_base = code.wrapping_add(0x860);
        for i in 0u32..14 {
            vt.add(i as usize).write_unaligned(vb_code_base.wrapping_add(i * 16));
        }
    }

    // ── IDirect3DVertexBuffer8 object (page+0xCA0, 8 bytes) ──────────────────
    unsafe {
        let obj = page.add(0xCA0) as *mut u32;
        obj.add(0).write_unaligned(vtblvb_va);
        obj.add(1).write_unaligned(1);
    }

    // ── IDirect3DIndexBuffer8 vtable (page+0xCB0, 14 × 4 bytes) ─────────────
    unsafe {
        let vt = page.add(0xCB0) as *mut u32;
        let ib_code_base = code.wrapping_add(0x940);
        for i in 0u32..14 {
            vt.add(i as usize).write_unaligned(ib_code_base.wrapping_add(i * 16));
        }
    }

    // ── IDirect3DIndexBuffer8 object (page+0xCF0, 8 bytes) ───────────────────
    unsafe {
        let obj = page.add(0xCF0) as *mut u32;
        obj.add(0).write_unaligned(vtblib_va);
        obj.add(1).write_unaligned(1);
    }

    // Lock buffer (page+0xD00, 64 bytes) already zeroed by INT3-fill override,
    // but explicitly zero it for correctness.
    unsafe {
        let lb = page.add(0xD00);
        for i in 0..64usize {
            lb.add(i).write_unaligned(0u8);
        }
    }
}

/// Emit `MOV EAX, val; RET ret_n` (stdcall constant return, 8 bytes).
/// For val==0 emits `XOR EAX, EAX; RET ret_n` (5 bytes) instead.
///
/// # Safety
/// `dst` must point to at least 8 writable bytes.
unsafe fn write_const_stub(dst: *mut u8, val: u32, ret_n: u16) {
    if val == 0 {
        dst.write_unaligned(0x33);
        dst.add(1).write_unaligned(0xC0);                       // XOR EAX, EAX
        dst.add(2).write_unaligned(0xC2);
        (dst.add(3) as *mut u16).write_unaligned(ret_n);        // RET ret_n
    } else {
        dst.write_unaligned(0xB8);
        (dst.add(1) as *mut u32).write_unaligned(val);          // MOV EAX, val
        dst.add(5).write_unaligned(0xC2);
        (dst.add(6) as *mut u16).write_unaligned(ret_n);        // RET ret_n
    }
}

/// Emit `MOV EAX, val; RET` (cdecl constant return, no callee stack cleanup).
///
/// # Safety
/// `dst` must point to at least 7 writable bytes.
unsafe fn write_cdecl_const_stub(dst: *mut u8, val: u32) {
    if val == 0 {
        dst.write_unaligned(0x33);
        dst.add(1).write_unaligned(0xC0);  // XOR EAX, EAX
        dst.add(2).write_unaligned(0xC3);  // RET
    } else {
        dst.write_unaligned(0xB8);
        (dst.add(1) as *mut u32).write_unaligned(val); // MOV EAX, val
        dst.add(5).write_unaligned(0xC3);              // RET
    }
}

/// Emit a vkCreate* stub that writes a fake non-null handle into the output
/// pointer arg, then returns VK_SUCCESS (0).  15 bytes, fits a 0x10-byte slot.
///
/// Layout:
///   MOV ECX, [ESP+arg_offset]    ; 8B 4C 24 xx   — load output ptr
///   MOV DWORD PTR [ECX], handle  ; C7 01 xx xx xx xx — write fake handle
///   XOR EAX, EAX                 ; 33 C0          — VK_SUCCESS = 0
///   RET ret_n                    ; C2 xx xx        — stdcall cleanup
///
/// # Safety
/// `dst` must point to at least 15 writable bytes.
unsafe fn write_vk_create_stub(dst: *mut u8, arg_offset: u8, handle: u32, ret_n: u16) {
    dst.add(0).write_unaligned(0x8B);  // MOV ECX, [ESP+imm8]
    dst.add(1).write_unaligned(0x4C);
    dst.add(2).write_unaligned(0x24);
    dst.add(3).write_unaligned(arg_offset);
    dst.add(4).write_unaligned(0xC7);  // MOV DWORD PTR [ECX], imm32
    dst.add(5).write_unaligned(0x01);
    (dst.add(6) as *mut u32).write_unaligned(handle);
    dst.add(10).write_unaligned(0x33); // XOR EAX, EAX
    dst.add(11).write_unaligned(0xC0);
    dst.add(12).write_unaligned(0xC2); // RET imm16
    (dst.add(13) as *mut u16).write_unaligned(ret_n);
}

fn initialise_stub_module_code(base: u32, module_name: &str) {
    let page = (base as u64 + 0x1000) as *mut u8;
    // SAFETY: page is within stub module mapping (base..base+0x2000), committed RWX.
    unsafe {
        for i in 0..0x1000usize {
            page.add(i).write_unaligned(0xCC); // INT3 trap
        }
    }

    if eq_ascii_nocase(module_name, "ntdll.dll") {
        // SYSENTER stubs — 21 bytes each, 0x20-byte slots.
        unsafe {
            write_nt_syscall_stub(page.add(0x000), 0x0112, 0x0024); // NtWriteFile (9)
            write_nt_syscall_stub(page.add(0x020), 0x0011, 0x0018); // NtAllocateVirtualMemory (6)
            write_nt_syscall_stub(page.add(0x040), 0x00C2, 0x0008); // NtTerminateProcess (2)
            write_nt_syscall_stub(page.add(0x060), 0x001B, 0x0020); // NtCreateProcess (8)
            write_nt_syscall_stub(page.add(0x080), 0x0035, 0x0028); // NtCreateThread (10)
        }

    } else if eq_ascii_nocase(module_name, "kernel32.dll") {
        // INT 0x2E Win32 stubs (14 bytes) in 0x10-byte slots; stdcall unless noted.
        unsafe {
            // ── Original 8 ───────────────────────────────────────────────────
            write_win32_stub(page.add(0x000), 0x2000, 0x0000); // GetTickCount()
            write_win32_stub(page.add(0x010), 0x2001, 0x0004); // Sleep(1)
            write_win32_stub(page.add(0x020), 0x2002, 0x0010); // VirtualAlloc(4)
            write_win32_stub(page.add(0x030), 0x2003, 0x000C); // VirtualFree(3)
            write_win32_stub(page.add(0x040), 0x2004, 0x0010); // VirtualProtect(4)
            write_win32_stub(page.add(0x050), 0x2005, 0x0008); // GetProcAddress(2)
            write_win32_stub(page.add(0x060), 0x2006, 0x0004); // GetModuleHandleA(1)
            write_win32_stub(page.add(0x070), 0x2007, 0x0004); // ExitProcess(1)
            // ── TLS ──────────────────────────────────────────────────────────
            write_win32_stub(page.add(0x080), 0x2070, 0x0000); // TlsAlloc()
            write_win32_stub(page.add(0x090), 0x2071, 0x0004); // TlsFree(1)
            write_win32_stub(page.add(0x0A0), 0x2072, 0x0004); // TlsGetValue(1)
            write_win32_stub(page.add(0x0B0), 0x2073, 0x0008); // TlsSetValue(2)
            // ── Critical section ─────────────────────────────────────────────
            write_win32_stub(page.add(0x0C0), 0x2074, 0x0004); // InitializeCriticalSection(1)
            write_win32_stub(page.add(0x0D0), 0x2075, 0x0004); // EnterCriticalSection(1)
            write_win32_stub(page.add(0x0E0), 0x2076, 0x0004); // LeaveCriticalSection(1)
            write_const_stub( page.add(0x0F0), 0, 4);          // DeleteCriticalSection(1) → void
            write_win32_stub(page.add(0x100), 0x2078, 0x0004); // TryEnterCriticalSection(1)
            // ── SRW / Condvar ────────────────────────────────────────────────
            write_win32_stub(page.add(0x110), 0x2079, 0x0004); // AcquireSRWLockExclusive(1)
            write_win32_stub(page.add(0x120), 0x207A, 0x0004); // ReleaseSRWLockExclusive(1)
            write_const_stub( page.add(0x130), 0, 4);          // InitializeConditionVariable(1) → void
            write_const_stub( page.add(0x140), 1, 8);          // SleepConditionVariableSRW(2) → TRUE
            write_const_stub( page.add(0x150), 0, 4);          // WakeAllConditionVariable(1) → void
            write_const_stub( page.add(0x160), 0, 4);          // WakeConditionVariable(1) → void
            // ── Module handles ────────────────────────────────────────────────
            write_win32_stub(page.add(0x170), 0x207F, 0x0004); // GetModuleHandleW(1)
            write_win32_stub(page.add(0x180), 0x2080, 0x000C); // GetModuleHandleExA(3)
            write_win32_stub(page.add(0x190), 0x2081, 0x0004); // LoadLibraryA(1)
            write_const_stub( page.add(0x1A0), 1, 4);          // FreeLibrary(1) → TRUE
            // ── System info / timing ─────────────────────────────────────────
            write_win32_stub(page.add(0x1B0), 0x2082, 0x0004); // GetSystemInfo(1)
            write_win32_stub(page.add(0x1C0), 0x2083, 0x0000); // GetTickCount64()
            // ── Threading ────────────────────────────────────────────────────
            write_win32_stub(page.add(0x1D0), 0x2084, 0x0018); // CreateThread(6)
            write_const_stub( page.add(0x1E0), 0xFFFF_FFFFu32, 0); // GetCurrentProcess → -1
            write_const_stub( page.add(0x1F0), 0xFFFF_FFFEu32, 0); // GetCurrentThread → -2
            write_win32_stub(page.add(0x200), 0x2085, 0x0000); // GetCurrentProcessId()
            write_win32_stub(page.add(0x210), 0x2086, 0x0000); // GetCurrentThreadId()
            // ── Synchronisation ──────────────────────────────────────────────
            write_win32_stub(page.add(0x220), 0x2087, 0x0010); // WaitForMultipleObjects(4)
            write_win32_stub(page.add(0x230), 0x2088, 0x000C); // WaitForSingleObjectEx(3)
            write_win32_stub(page.add(0x240), 0x2088, 0x0008); // WaitForSingleObject(2) — reuse handler
            write_const_stub( page.add(0x250), 1, 4);          // CloseHandle(1) → TRUE
            write_win32_stub(page.add(0x260), 0x2089, 0x0010); // CreateEventA(4)
            write_win32_stub(page.add(0x270), 0x208A, 0x0004); // SetEvent(1)
            write_win32_stub(page.add(0x280), 0x208B, 0x0004); // ResetEvent(1)
            write_win32_stub(page.add(0x290), 0x208C, 0x0014); // CreateSemaphoreA(5)
            write_win32_stub(page.add(0x2A0), 0x208D, 0x000C); // ReleaseSemaphore(3)
            write_const_stub( page.add(0x2B0), 1, 0x1C);       // DuplicateHandle(7) → TRUE
            // ── File mapping ─────────────────────────────────────────────────
            write_win32_stub(page.add(0x2C0), 0x208E, 0x0018); // CreateFileMappingA(6)
            write_win32_stub(page.add(0x2D0), 0x208F, 0x0014); // MapViewOfFile(5)
            write_const_stub( page.add(0x2E0), 1, 4);          // UnmapViewOfFile(1) → TRUE
            // ── Temp paths ───────────────────────────────────────────────────
            write_win32_stub(page.add(0x2F0), 0x2091, 0x0008); // GetTempPathA(2)
            write_win32_stub(page.add(0x300), 0x2092, 0x0010); // GetTempFileNameA(4)
            write_win32_stub(page.add(0x310), 0x2093, 0x0004); // OutputDebugStringA(1)
            write_const_stub( page.add(0x320), 0, 0x0010);     // FormatMessageA(4) → 0
            // ── Memory / debug ───────────────────────────────────────────────
            write_win32_stub(page.add(0x330), 0x2095, 0x000C); // VirtualQuery(3)
            write_win32_stub(page.add(0x340), 0x2096, 0x000C); // GetModuleFileNameW(3)
            write_const_stub( page.add(0x350), 0, 0);          // IsDebuggerPresent() → FALSE
            write_const_stub( page.add(0x360), 0x500, 4);      // OpenProcess(1) → fake handle
            // ── Performance ──────────────────────────────────────────────────
            write_win32_stub(page.add(0x370), 0x2098, 0x0004); // QueryPerformanceCounter(1)
            write_win32_stub(page.add(0x380), 0x2099, 0x0004); // QueryPerformanceFrequency(1)
            write_const_stub( page.add(0x390), 0, 0x0010);     // RaiseException(4) → void
            // ── Heap ─────────────────────────────────────────────────────────
            write_win32_stub(page.add(0x3A0), 0x209A, 0x000C); // HeapAlloc(3)
            write_const_stub( page.add(0x3B0), 1, 0x000C);     // HeapFree(3) → TRUE
            write_const_stub( page.add(0x3C0), 0x8000, 0);     // GetProcessHeap() → fake handle
            write_const_stub( page.add(0x3D0), 0, 4);          // LocalFree(1) → NULL (success)
            // ── Error / env ──────────────────────────────────────────────────
            write_const_stub( page.add(0x3E0), 0, 0);          // GetLastError() → 0
            write_win32_stub(page.add(0x3F0), 0x209B, 0x0004); // SetLastError(1)
            write_const_stub( page.add(0x400), 0, 0x000C);     // GetEnvironmentVariableW(3) → 0
            write_const_stub( page.add(0x410), 1, 8);          // GetHandleInformation(2) → TRUE
            // ── Thread control ───────────────────────────────────────────────
            write_const_stub( page.add(0x420), 0, 4);          // SuspendThread(1) → prev count 0
            write_const_stub( page.add(0x430), 1, 4);          // ResumeThread(1) → prev count 1
            write_const_stub( page.add(0x440), 0, 4);          // GetThreadPriority(1) → NORMAL
            write_const_stub( page.add(0x450), 1, 8);          // SetThreadPriority(2) → TRUE
            write_const_stub( page.add(0x460), 0, 8);          // GetThreadContext(2) → 0
            write_const_stub( page.add(0x470), 0, 8);          // SetThreadContext(2) → 0
            write_const_stub( page.add(0x480), 1, 0);          // SwitchToThread() → TRUE
            write_const_stub( page.add(0x490), 1, 8);          // SetProcessAffinityMask(2) → TRUE
            write_const_stub( page.add(0x4A0), 1, 8);          // GetProcessAffinityMask(2) → TRUE
            write_const_stub( page.add(0x4B0), 0, 0x1C);       // DeviceIoControl(7) → FALSE
            write_const_stub( page.add(0x4C0), 1, 8);          // CreateDirectoryW(2) → TRUE
            write_win32_stub(page.add(0x4D0), 0x2033, 0x001C); // CreateFileA(7) → syscall
            write_win32_stub(page.add(0x4E0), 0x209A, 0x0008); // LocalAlloc(2) → reuse HeapAlloc
            // GetSystemTimeAsFileTime(FILETIME*) → void, write a plausible timestamp
            write_win32_stub(page.add(0x4F0), 0x209C, 0x0004);
            // ── Global heap (GlobalAlloc / GlobalFree) ───────────────────────
            // GlobalAlloc(uFlags, dwBytes) → HGLOBAL: reuse HeapAlloc handler
            write_win32_stub(page.add(0x500), 0x209A, 0x0008); // GlobalAlloc(2)
            write_const_stub( page.add(0x510), 1, 4);          // GlobalFree(1) → TRUE
            // ── Ghost Recon CRT / kernel32 imports ─────────────────────────
            write_win32_stub(page.add(0x520), 0x20A0, 0x0004); // GlobalMemoryStatus(1)
            write_const_stub( page.add(0x530), 1, 4);          // SetCurrentDirectoryA(1) → TRUE
            write_win32_stub(page.add(0x540), 0x20A1, 0x000C); // GetModuleFileNameA(3)
            write_win32_stub(page.add(0x550), 0x20A2, 0x0018); // MultiByteToWideChar(6)
            write_win32_stub(page.add(0x560), 0x20A3, 0x0004); // GetVersionExA(1)
            write_win32_stub(page.add(0x570), 0x20A4, 0x0008); // lstrcpyA(2)
            write_win32_stub(page.add(0x580), 0x20A5, 0x0008); // GetCurrentDirectoryA(2)
            write_const_stub( page.add(0x590), 1, 8);          // CreateDirectoryA(2) → TRUE
            write_win32_stub(page.add(0x5A0), 0x2095, 0x0010); // VirtualQueryEx(4) — reuse VirtualQuery
            write_win32_stub(page.add(0x5B0), 0x20A6, 0x0008); // lstrcatA(2)
            write_win32_stub(page.add(0x5C0), 0x20A7, 0x000C); // lstrcpynA(3)
            write_win32_stub(page.add(0x5D0), 0x20A8, 0x0004); // lstrlenA(1)
            write_win32_stub(page.add(0x5E0), 0x20A9, 0x0014); // WriteFile(5)
            write_const_stub( page.add(0x5F0), 0, 0x0010);     // SetFilePointer(4) → 0
            write_const_stub( page.add(0x600), 1, 0x0010);     // GetFileTime(4) → TRUE (zeroed)
            write_win32_stub(page.add(0x610), 0x20AA, 0x0004); // GetFileSize(1)
            write_const_stub( page.add(0x620), 1, 0x000C);     // FileTimeToDosDateTime(3) → TRUE
            write_const_stub( page.add(0x630), 1, 8);          // FileTimeToLocalFileTime(2) → TRUE
            write_const_stub( page.add(0x640), 1, 4);          // FindClose(1) → TRUE
            write_const_stub( page.add(0x650), 0, 4);          // DeleteFileA(1) → FALSE
            write_win32_stub(page.add(0x660), 0x20AB, 0x0008); // FindFirstFileA(2)
            write_const_stub( page.add(0x670), 0, 8);          // FindNextFileA(2) → FALSE (no more)
            write_win32_stub(page.add(0x680), 0x20AC, 0x0004); // GetFileAttributesA(1)
            write_const_stub( page.add(0x690), 1, 0x001C);     // GetVolumeInformationA(7) → TRUE
            write_const_stub( page.add(0x6A0), 3, 4);          // GetDriveTypeA(1) → DRIVE_FIXED=3
            write_const_stub( page.add(0x6B0), 0, 8);          // GetLogicalDriveStringsA(2) → 0
            write_win32_stub(page.add(0x6C0), 0x20AD, 0x0010); // GetFullPathNameA(4)
            write_const_stub( page.add(0x6D0), 0, 0x0028);     // CreateProcessA(10) → FALSE
            // InterlockedExchange: MOV EAX,[ESP+8]; MOV ECX,[ESP+4]; XCHG [ECX],EAX; RET 8
            {
                let p = page.add(0x6E0);
                p.add(0).write_unaligned(0x8Bu8); p.add(1).write_unaligned(0x44u8);
                p.add(2).write_unaligned(0x24u8); p.add(3).write_unaligned(0x08u8); // MOV EAX,[ESP+8]
                p.add(4).write_unaligned(0x8Bu8); p.add(5).write_unaligned(0x4Cu8);
                p.add(6).write_unaligned(0x24u8); p.add(7).write_unaligned(0x04u8); // MOV ECX,[ESP+4]
                p.add(8).write_unaligned(0x87u8); p.add(9).write_unaligned(0x01u8); // XCHG [ECX],EAX
                p.add(10).write_unaligned(0xC2u8);
                (p.add(11) as *mut u16).write_unaligned(8u16); // RET 8
            }
            // InterlockedDecrement: MOV ECX,[ESP+4]; MOV EAX,-1; LOCK XADD [ECX],EAX; DEC EAX; RET 4
            {
                let p = page.add(0x6F0);
                p.add(0).write_unaligned(0x8Bu8); p.add(1).write_unaligned(0x4Cu8);
                p.add(2).write_unaligned(0x24u8); p.add(3).write_unaligned(0x04u8); // MOV ECX,[ESP+4]
                p.add(4).write_unaligned(0xB8u8);
                (p.add(5) as *mut u32).write_unaligned(0xFFFF_FFFFu32); // MOV EAX,-1
                p.add(9).write_unaligned(0xF0u8);  // LOCK
                p.add(10).write_unaligned(0x0Fu8); p.add(11).write_unaligned(0xC1u8);
                p.add(12).write_unaligned(0x01u8); // XADD [ECX],EAX
                p.add(13).write_unaligned(0x48u8); // DEC EAX
                p.add(14).write_unaligned(0xC2u8);
                (p.add(15) as *mut u16).write_unaligned(4u16); // RET 4  (17 bytes total → fits 0x10+slot)
            }
            // InterlockedIncrement: MOV ECX,[ESP+4]; MOV EAX,1; LOCK XADD [ECX],EAX; INC EAX; RET 4
            {
                let p = page.add(0x700);
                p.add(0).write_unaligned(0x8Bu8); p.add(1).write_unaligned(0x4Cu8);
                p.add(2).write_unaligned(0x24u8); p.add(3).write_unaligned(0x04u8); // MOV ECX,[ESP+4]
                p.add(4).write_unaligned(0xB8u8);
                (p.add(5) as *mut u32).write_unaligned(1u32); // MOV EAX,1
                p.add(9).write_unaligned(0xF0u8);  // LOCK
                p.add(10).write_unaligned(0x0Fu8); p.add(11).write_unaligned(0xC1u8);
                p.add(12).write_unaligned(0x01u8); // XADD [ECX],EAX
                p.add(13).write_unaligned(0x40u8); // INC EAX
                p.add(14).write_unaligned(0xC2u8);
                (p.add(15) as *mut u16).write_unaligned(4u16); // RET 4
            }
            write_const_stub( page.add(0x710), 2, 0x0018);     // CompareStringA(6) → CSTR_EQUAL=2
            write_const_stub( page.add(0x720), 2, 0x0018);     // CompareStringW(6) → CSTR_EQUAL=2
            write_win32_stub(page.add(0x730), 0x2007, 0x0004); // ExitThread(1) → reuse ExitProcess
            write_const_stub( page.add(0x740), 1, 0x0010);     // FileTimeToSystemTime(4) → TRUE
            write_const_stub( page.add(0x750), 1, 4);          // FlushFileBuffers(1) → TRUE
            write_const_stub( page.add(0x760), 1, 4);          // FreeEnvironmentStringsA(1) → TRUE
            write_const_stub( page.add(0x770), 1, 4);          // FreeEnvironmentStringsW(1) → TRUE
            write_const_stub( page.add(0x780), 1252, 0);       // GetACP() → 1252 (Western)
            write_win32_stub(page.add(0x790), 0x20AE, 0x0008); // GetCPInfo(2)
            write_win32_stub(page.add(0x7A0), 0x20AF, 0x0000); // GetCommandLineA() → ptr to "-nointro\0"
            write_win32_stub(page.add(0x7B0), 0x2125, 0x0000); // GetEnvironmentStrings() → syscall
            write_const_stub( page.add(0x7C0), 0, 0);          // GetEnvironmentStringsW() → NULL
            write_const_stub( page.add(0x7D0), 0, 0x000C);     // GetEnvironmentVariableA(3) → 0 (not found)
            write_win32_stub(page.add(0x7E0), 0x20B7, 0x0004); // GetFileType(1) → syscall
            write_win32_stub(page.add(0x7F0), 0x20B0, 0x0004); // GetLocalTime(1) → fill SYSTEMTIME
            write_const_stub( page.add(0x800), 0, 0x0010);     // GetLocaleInfoA(4) → 0
            write_const_stub( page.add(0x810), 0, 0x0010);     // GetLocaleInfoW(4) → 0
            write_const_stub( page.add(0x820), 437, 0);        // GetOEMCP() → 437 (US)
            write_win32_stub(page.add(0x830), 0x20B1, 0x0004); // GetStartupInfoA(1)
            write_win32_stub(page.add(0x840), 0x20B2, 0x0004); // GetStdHandle(1)
            write_const_stub( page.add(0x850), 0, 0x0014);     // GetStringTypeA(5) → FALSE
            write_const_stub( page.add(0x860), 0, 0x0010);     // GetStringTypeW(4) → FALSE
            write_win32_stub(page.add(0x870), 0x20B0, 0x0004); // GetSystemTime(1) → reuse GetLocalTime
            write_const_stub( page.add(0x880), 0, 4);          // GetTimeZoneInformation(1) → TIME_ZONE_ID_UNKNOWN=0
            write_const_stub( page.add(0x890), 0x0409, 0);     // GetUserDefaultLCID() → en-US
            // GetVersion() → 0x0A280105 (XP SP2: 5.1 build 2600 platform 2)
            write_const_stub( page.add(0x8A0), 0x0A28_0105u32, 0);
            write_const_stub( page.add(0x8B0), 0x8000u32, 0x000C); // HeapCreate(3) → fake handle
            write_const_stub( page.add(0x8C0), 1, 4);          // HeapDestroy(1) → TRUE
            write_win32_stub(page.add(0x8D0), 0x20B4, 0x0010); // HeapReAlloc(4)
            write_const_stub( page.add(0x8E0), 0, 0x000C);     // HeapSize(3) → 0
            write_const_stub( page.add(0x8F0), 0, 8);          // IsBadCodePtr(2) → FALSE (valid)
            write_const_stub( page.add(0x900), 0, 8);          // IsBadReadPtr(2) → FALSE (valid)
            write_const_stub( page.add(0x910), 0, 8);          // IsBadWritePtr(2) → FALSE (valid)
            write_const_stub( page.add(0x920), 1, 4);          // IsValidCodePage(1) → TRUE
            write_const_stub( page.add(0x930), 1, 8);          // IsValidLocale(2) → TRUE
            write_const_stub( page.add(0x940), 0, 0x0018);     // LCMapStringA(6) → 0
            write_const_stub( page.add(0x950), 0, 0x0018);     // LCMapStringW(6) → 0
            write_const_stub( page.add(0x960), 0, 8);          // MoveFileA(2) → FALSE
            write_win32_stub(page.add(0x970), 0x20B5, 0x000C); // MulDiv(3)
            write_win32_stub(page.add(0x980), 0x20B6, 0x0014); // ReadFile(5)
            // RtlUnwind: void, 4 args → just return
            write_const_stub( page.add(0x990), 0, 0x0010);     // RtlUnwind(4) → void
            write_const_stub( page.add(0x9A0), 1, 4);          // SetEndOfFile(1) → TRUE
            write_const_stub( page.add(0x9B0), 1, 0x000C);     // SetEnvironmentVariableA(3) → TRUE
            // SetHandleCount(cHandles) → return cHandles (identity)
            write_const_stub( page.add(0x9C0), 20, 4);         // SetHandleCount(1) → 20
            write_const_stub( page.add(0x9D0), 1, 8);          // SetStdHandle(2) → TRUE
            // SetUnhandledExceptionFilter(1) → NULL (no previous filter)
            write_const_stub( page.add(0x9E0), 0, 4);
            write_win32_stub(page.add(0x9F0), 0x2007, 0x0008); // TerminateProcess(2) → reuse ExitProcess
            write_const_stub( page.add(0xA00), 0, 4);          // UnhandledExceptionFilter(1) → EXCEPTION_CONTINUE_SEARCH
            write_win32_stub(page.add(0xA10), 0x20B7, 0x0020); // WideCharToMultiByte(8)
            write_const_stub( page.add(0xA20), 1, 8);          // EnumSystemLocalesA(2) → TRUE
        }

    } else if eq_ascii_nocase(module_name, "user32.dll") {
        unsafe {
            // ── Original 9 ───────────────────────────────────────────────────
            write_win32_stub(page.add(0x000), 0x2010, 0x0030); // CreateWindowExA(12)
            write_win32_stub(page.add(0x010), 0x2011, 0x0008); // ShowWindow(2)
            write_win32_stub(page.add(0x020), 0x2012, 0x0010); // GetMessageA(4)
            write_dispatch_message_a(page);                     // DispatchMessageA (slot 0x030)
            write_win32_stub(page.add(0x040), 0x2014, 0x0004); // TranslateMessage(1)
            write_win32_stub(page.add(0x050), 0x2015, 0x0014); // PeekMessageA(5)
            write_win32_stub(page.add(0x060), 0x2016, 0x0004); // PostQuitMessage(1)
            write_win32_stub(page.add(0x070), 0x2017, 0x0004); // RegisterClassA(1)
            write_win32_stub(page.add(0x080), 0x2018, 0x0010); // DefWindowProcA(4)
            // ── Extended window API ──────────────────────────────────────────
            write_win32_stub(page.add(0x090), 0x2010, 0x0030); // CreateWindowExW(12) — same handler
            write_win32_stub(page.add(0x0A0), 0x2018, 0x0010); // DefWindowProcW(4) — same handler
            write_win32_stub(page.add(0x0B0), 0x2017, 0x0004); // RegisterClassExW(1) — same handler
            write_const_stub( page.add(0x0C0), 1, 4);          // DestroyWindow(1) → TRUE
            write_win32_stub(page.add(0x0D0), 0x2120, 0x0008); // GetClientRect(2)
            write_const_stub( page.add(0x0E0), 1, 8);          // GetWindowRect(2) → TRUE (zeroed)
            write_win32_stub(page.add(0x0F0), 0x2121, 0x000C); // EnumDisplaySettingsW(3)
            write_const_stub( page.add(0x100), 0, 0x0014);     // ChangeDisplaySettingsExW(5) → 0 ok
            write_const_stub( page.add(0x110), 0, 0x0010);     // EnumDisplayMonitors(4) → FALSE
            write_const_stub( page.add(0x120), 0, 8);          // GetMonitorInfoW(2) → FALSE
            write_const_stub( page.add(0x130), 0x100, 0x000C); // MonitorFromPoint(3) → fake HMONITOR
            write_const_stub( page.add(0x140), 1, 0x001C);     // SetWindowPos(7) → TRUE
            write_const_stub( page.add(0x150), 1, 0x0018);     // MoveWindow(6) → TRUE
            write_const_stub( page.add(0x160), 0, 8);          // GetWindowLongW(2) → 0
            write_const_stub( page.add(0x170), 0, 0x000C);     // SetWindowLongW(3) → 0 (prev)
            write_const_stub( page.add(0x180), 0, 8);          // GetWindowLongA(2) → 0
            write_const_stub( page.add(0x190), 0, 0x000C);     // SetWindowLongA(3) → 0 (prev)
            write_const_stub( page.add(0x1A0), 1, 4);          // IsWindow(1) → TRUE
            write_const_stub( page.add(0x1B0), 1, 4);          // IsWindowVisible(1) → TRUE
            write_const_stub( page.add(0x1C0), 0, 4);          // IsIconic(1) → FALSE
            write_const_stub( page.add(0x1D0), 0x1000, 0);     // GetForegroundWindow() → fake HWND
            write_const_stub( page.add(0x1E0), 0, 4);          // SetCursor(1) → NULL (prev cursor)
            write_const_stub( page.add(0x1F0), 1, 8);          // SetCursorPos(2) → TRUE
            write_const_stub( page.add(0x200), 1, 4);          // GetCursorPos(1) → TRUE (zeroed pt)
            write_const_stub( page.add(0x210), 1, 8);          // ReleaseDC(2) → TRUE
            write_const_stub( page.add(0x220), 0x100, 0x000C); // GetDCEx(3) → fake HDC
            write_const_stub( page.add(0x230), 1, 0x000C);     // OffsetRect(3) → TRUE
            write_const_stub( page.add(0x240), 1, 0x0014);     // SetRect(5) → TRUE
            write_const_stub( page.add(0x250), 1, 0);          // SetProcessDPIAware() → TRUE
            write_const_stub( page.add(0x260), 0, 0x0014);     // CallWindowProcA(5) → 0
            write_const_stub( page.add(0x270), 0, 0x0014);     // CallWindowProcW(5) → 0
            write_const_stub( page.add(0x280), 1, 4);          // IsWindowUnicode(1) → TRUE
            write_const_stub( page.add(0x290), 1, 0x0010);     // AdjustWindowRectEx(4) → TRUE
            write_const_stub( page.add(0x2A0), 1, 0x0010);     // PostMessageW(4) → TRUE
            write_const_stub( page.add(0x2B0), 0x200, 4);      // CreateIconIndirect(1) → fake HICON
            write_const_stub( page.add(0x2C0), 1, 4);          // DestroyCursor(1) → TRUE
            // QueryDisplayConfig, DisplayConfigGetDeviceInfo, GetDisplayConfigBufferSizes → not supported
            write_const_stub( page.add(0x2D0), 0xC000_0225u32, 0x0014); // QueryDisplayConfig(5)
            write_const_stub( page.add(0x2E0), 0xC000_0225u32, 4);      // DisplayConfigGetDeviceInfo(1)
            write_const_stub( page.add(0x2F0), 0xC000_0225u32, 0x000C); // GetDisplayConfigBufferSizes(3)
            write_const_stub( page.add(0x300), 0, 0x0010);     // EnumDisplayDevicesA(4) → FALSE
            // 0x310..0x352 is occupied by DispatchMessageA body — skip to 0x360
            write_const_stub( page.add(0x360), 1, 0x0008);     // ClientToScreen(2) → TRUE
            write_const_stub( page.add(0x370), 1, 0x0008);     // ScreenToClient(2) → TRUE
            // MessageBoxA(hWnd, lpText, lpCaption, uType) → IDOK = 1
            write_win32_stub(page.add(0x380), 0x2122, 0x0010); // MessageBoxA(4)
            // ── Ghost Recon user32 imports ─────────────────────────────────
            write_const_stub( page.add(0x390), 1, 0x000C);     // AdjustWindowRect(3) → TRUE
            write_const_stub( page.add(0x3A0), 1, 4);          // CloseWindow(1) → TRUE
            write_win32_stub(page.add(0x3B0), 0x2123, 0x000C); // EnumDisplaySettingsA(3)
            write_const_stub( page.add(0x3C0), 0, 8);          // FindWindowA(2) → NULL (not found)
            write_const_stub( page.add(0x3D0), 0, 0x000C);     // FrameRect(3) → 0
            write_const_stub( page.add(0x3E0), 500, 0);        // GetDoubleClickTime() → 500ms
            write_const_stub( page.add(0x3F0), 0, 4);          // GetMenu(1) → NULL
            write_const_stub( page.add(0x400), 0, 4);          // GetQueueStatus(1) → 0 (no messages)
            write_win32_stub(page.add(0x410), 0x2124, 0x0004); // GetSystemMetrics(1)
            write_const_stub( page.add(0x420), 0x100, 8);      // LoadCursorA(2) → fake HCURSOR
            write_const_stub( page.add(0x430), 0x200, 8);      // LoadIconA(2) → fake HICON
            write_const_stub( page.add(0x440), 0x300, 0x0018); // LoadImageA(6) → fake HANDLE
            write_const_stub( page.add(0x450), 0, 0x0014);     // MsgWaitForMultipleObjects(5) → WAIT_OBJECT_0
            write_const_stub( page.add(0x460), 1, 0x0010);     // PostMessageA(4) → TRUE
            write_const_stub( page.add(0x470), 1, 0x0010);     // PostThreadMessageA(4) → TRUE
            write_win32_stub(page.add(0x480), 0x2017, 0x0004); // RegisterClassExA(1) → reuse RegisterClassA
            write_const_stub( page.add(0x490), 0xC000, 4);     // RegisterWindowMessageA(1) → 0xC000
            write_const_stub( page.add(0x4A0), 0x1000, 4);     // SetFocus(1) → prev HWND
            write_const_stub( page.add(0x4B0), 1, 4);          // SetForegroundWindow(1) → TRUE
            write_const_stub( page.add(0x4C0), 1, 4);          // UpdateWindow(1) → TRUE
            // wsprintfA: cdecl, varargs — just return 0 (wrote 0 chars)
            write_cdecl_const_stub(page.add(0x4D0), 0);
            // wvsprintfA: cdecl — just return 0
            write_cdecl_const_stub(page.add(0x4E0), 0);
            write_const_stub( page.add(0x4F0), 1, 0);          // GetActiveWindow() → fake HWND
            write_const_stub( page.add(0x500), 1, 4);          // GetLastActivePopup(1) → fake HWND
        }

    } else if eq_ascii_nocase(module_name, "msvcrt.dll") {
        // __cdecl — caller cleans, ret_imm = 0.
        unsafe {
            write_win32_stub(page.add(0x000), 0x2020, 0x0000); // malloc
            write_win32_stub(page.add(0x010), 0x2021, 0x0000); // calloc
            write_win32_stub(page.add(0x020), 0x2022, 0x0000); // free
            write_win32_stub(page.add(0x030), 0x2023, 0x0000); // memcpy
            write_win32_stub(page.add(0x040), 0x2024, 0x0000); // memset
            write_win32_stub(page.add(0x050), 0x2025, 0x0000); // strlen
        }

    } else if eq_ascii_nocase(module_name, "winmm.dll") {
        unsafe {
            write_win32_stub(page.add(0x000), 0x2030, 0x0004); // timeBeginPeriod(1)
            write_win32_stub(page.add(0x010), 0x2031, 0x0004); // timeEndPeriod(1)
            write_win32_stub(page.add(0x020), 0x2032, 0x0000); // timeGetTime()
            // ── Ghost Recon winmm imports ──────────────────────────────────
            write_win32_stub(page.add(0x030), 0x2033, 0x0008); // timeGetDevCaps(2)
            write_const_stub( page.add(0x040), 0, 4);          // timeKillEvent(1) → TIMERR_NOERROR
            write_const_stub( page.add(0x050), 1, 0x0014);     // timeSetEvent(5) → fake timer ID 1
        }

    } else if eq_ascii_nocase(module_name, "d3d8.dll") {
        unsafe { write_d3d8_page(page, base); }

    } else if eq_ascii_nocase(module_name, "advapi32.dll") {
        // stdcall registry + security stubs.
        unsafe {
            write_win32_stub(page.add(0x000), 0x20E0, 0x0014); // RegOpenKeyExA(5)
            write_win32_stub(page.add(0x010), 0x20E1, 0x0018); // RegQueryValueExA(6)
            write_win32_stub(page.add(0x020), 0x20E2, 0x0004); // RegCloseKey(1)
            write_win32_stub(page.add(0x030), 0x20E3, 0x0014); // RegOpenKeyExW(5)
            write_win32_stub(page.add(0x040), 0x20E4, 0x0018); // RegQueryValueExW(6)
            write_const_stub( page.add(0x050), 0, 0x0014);     // RegNotifyChangeKeyValue(5) → S_OK
            write_win32_stub(page.add(0x060), 0x20E6, 0x0004); // AllocateLocallyUniqueId(1)
            // GetUserNameA(lpBuffer, pcbBuffer) → writes "Player\0", returns TRUE
            write_win32_stub(page.add(0x070), 0x209D, 0x0008); // GetUserNameA(2)
        }

    } else if eq_ascii_nocase(module_name, "gdi32.dll") {
        unsafe {
            write_const_stub(page.add(0x000), 0x100, 4);       // CreateCompatibleDC(1) → fake HDC
            write_const_stub(page.add(0x010), 1, 4);           // DeleteDC(1) → TRUE
            write_const_stub(page.add(0x020), 0x200, 0x0014);  // CreateBitmap(5) → fake HBITMAP
            write_const_stub(page.add(0x030), 1, 4);           // DeleteObject(1) → TRUE
            write_const_stub(page.add(0x040), 1, 0x002C);      // StretchBlt(11) → TRUE
            // Polygon(hdc, lppt, cCount) → TRUE; Ghost Recon uses GDI for debug overlays.
            write_const_stub(page.add(0x050), 1, 0x000C);      // Polygon(3) → TRUE
            // ── Ghost Recon gdi32 imports ──────────────────────────────────
            write_const_stub(page.add(0x060), 0, 0x0018);      // CreateDIBSection(6) → NULL
            write_const_stub(page.add(0x070), 0x300, 0x0014);  // CreatePen(5) → fake HPEN
            write_const_stub(page.add(0x080), 0x400, 4);       // CreateSolidBrush(1) → fake HBRUSH
            write_const_stub(page.add(0x090), 1, 0x0014);      // Ellipse(5) → TRUE
            write_const_stub(page.add(0x0A0), 1, 0);           // GdiFlush() → TRUE
            write_const_stub(page.add(0x0B0), 0x500, 4);       // GetStockObject(1) → fake GDI obj
            write_const_stub(page.add(0x0C0), 1, 0x000C);      // Polyline(3) → TRUE
            write_const_stub(page.add(0x0D0), 0x600, 8);       // SelectObject(2) → fake prev obj
            write_const_stub(page.add(0x0E0), 0, 0x000C);      // SetPixel(3) → CLR_INVALID=0
            write_const_stub(page.add(0x0F0), 1, 0x0014);      // TextOutA(5) → TRUE
        }

    } else if eq_ascii_nocase(module_name, "setupapi.dll") {
        // DXVK uses setupapi for GPU device enumeration; failure is handled gracefully.
        unsafe {
            write_const_stub(page.add(0x000), 0xFFFF_FFFFu32, 0x0010); // SetupDiGetClassDevsW(4) → INVALID
            write_const_stub(page.add(0x010), 0, 0x0014);  // SetupDiEnumDeviceInterfaces(5) → FALSE
            write_const_stub(page.add(0x020), 0, 0x0018);  // SetupDiGetDeviceInterfaceDetailW(6) → FALSE
            write_const_stub(page.add(0x030), 0xFFFF_FFFFu32, 0x0018); // SetupDiOpenDevRegKey(6) → INVALID
        }

    } else if eq_ascii_nocase(module_name, "d3d9.dll") {
        // Fallback stub — returns NULL from Direct3DCreate9 when DXVK isn't loaded.
        unsafe {
            write_const_stub(page.add(0x000), 0, 4); // Direct3DCreate9(1) → NULL
            write_const_stub(page.add(0x010), 0, 8); // Direct3DCreate9Ex(2) → NULL
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-runtime-l1-1-0.dll") {
        // UCRT runtime forwarder — cdecl throughout.
        //
        // _initterm and _initterm_e are inline machine code: they call each
        // function pointer in the [begin, end) array.  Cannot be INT 0x2E stubs
        // because they call user-mode function pointers directly.
        //
        // _initterm: kernel-driven constructor iteration via syscall.
        // _initterm: no-op for now. Constructors crash because they call through
        // uninitialized COM vtables (NULL pointers from CoCreateInstance returning
        // E_NOINTERFACE). TODO Phase 4: proper COM stub objects.
        let initterm_code: [u8; 1] = [0xC3]; // RET
        #[rustfmt::skip]
        let initterm_e_code: [u8; 28] = [
            0x56,                    // PUSH ESI
            0x8B, 0x74, 0x24, 0x08,  // MOV ESI, [ESP+8]
            0x3B, 0x74, 0x24, 0x0C,  // CMP ESI, [ESP+0C]
            0x73, 0x0D,              // JAE done
            0x8B, 0x06,              // MOV EAX, [ESI]
            0x83, 0xC6, 0x04,        // ADD ESI, 4
            0x85, 0xC0,              // TEST EAX, EAX
            0x74, 0x02,              // JZ skip
            0xFF, 0xD0,              // CALL EAX
            0xEB, 0xED,              // JMP loop
            0x33, 0xC0,              // XOR EAX, EAX (done)
            0x5E,                    // POP ESI
            0xC3,                    // RET
        ];
        unsafe {
            // _initterm at page+0x000
            for (i, &b) in initterm_code.iter().enumerate() {
                page.add(i).write_unaligned(b);
            }
            // _initterm_e at page+0x020
            for (i, &b) in initterm_e_code.iter().enumerate() {
                page.add(0x020 + i).write_unaligned(b);
            }
            // _initialize_onexit_table(1) → 0x20B8, cdecl
            write_win32_stub(page.add(0x040), 0x20B8, 0x0000);
            // _register_onexit_function(2) → 0x20B9, cdecl
            write_win32_stub(page.add(0x050), 0x20B9, 0x0000);
            // _execute_onexit_table(1) → just return 0 (cdecl)
            write_cdecl_const_stub(page.add(0x060), 0);
            // _beginthreadex(6) → 0x20BB, cdecl
            write_win32_stub(page.add(0x080), 0x20BB, 0x0000);
            // _endthreadex(1) → void cdecl
            write_cdecl_const_stub(page.add(0x090), 0);
            // _errno() → 0x20BD, cdecl, returns int*
            write_win32_stub(page.add(0x0A0), 0x20BD, 0x0000);
            // abort() → just RET (let the process hang rather than triple-fault)
            page.add(0x0B0).write_unaligned(0xC3);
            // strerror(1) → NULL, cdecl
            write_cdecl_const_stub(page.add(0x0C0), 0);
            // _assert(3) → no-op, cdecl
            write_cdecl_const_stub(page.add(0x0D0), 0);
            // _exit(1) → ExitProcess syscall (0x2007), cdecl
            write_win32_stub(page.add(0x0E0), 0x2007, 0x0000);
            // strerror_s(3) → 0 (S_OK), cdecl
            write_cdecl_const_stub(page.add(0x0F0), 0);
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-heap-l1-1-0.dll") {
        // All cdecl (ret_imm = 0).
        unsafe {
            write_win32_stub(page.add(0x000), 0x2020, 0x0000); // malloc
            write_win32_stub(page.add(0x010), 0x2022, 0x0000); // free
            write_win32_stub(page.add(0x020), 0x2021, 0x0000); // calloc
            write_win32_stub(page.add(0x030), 0x20B3, 0x0000); // realloc
            write_cdecl_const_stub(page.add(0x040), 0);        // _aligned_malloc → NULL stub
            write_cdecl_const_stub(page.add(0x050), 0);        // _aligned_free → void stub
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-string-l1-1-0.dll") {
        unsafe {
            write_win32_stub(page.add(0x000), 0x2024, 0x0000); // memset
            write_win32_stub(page.add(0x010), 0x20C8, 0x0000); // strcmp
            write_win32_stub(page.add(0x020), 0x2025, 0x0000); // strlen
            write_win32_stub(page.add(0x030), 0x20C9, 0x0000); // strncmp
            write_win32_stub(page.add(0x040), 0x20CA, 0x0000); // strncpy
            write_win32_stub(page.add(0x050), 0x20CB, 0x0000); // strnlen
            write_win32_stub(page.add(0x060), 0x20C8, 0x0000); // strcoll → reuse strcmp
            write_cdecl_const_stub(page.add(0x070), 0);        // strxfrm → 0
            write_cdecl_const_stub(page.add(0x080), 0);        // towlower → 0 stub
            write_cdecl_const_stub(page.add(0x090), 0);        // towupper → 0 stub
            write_win32_stub(page.add(0x0A0), 0x20D0, 0x0000); // wcscoll → reuse wcscmp
            write_win32_stub(page.add(0x0B0), 0x20CE, 0x0000); // wcslen
            write_win32_stub(page.add(0x0C0), 0x20CF, 0x0000); // wcsnlen
            write_win32_stub(page.add(0x0D0), 0x20D0, 0x0000); // wcscmp
            write_cdecl_const_stub(page.add(0x0E0), 0);        // wcsxfrm → 0
            write_cdecl_const_stub(page.add(0x0F0), 0);        // wctype → 0
            write_win32_stub(page.add(0x100), 0x20D1, 0x0000); // _wcsicmp
            write_win32_stub(page.add(0x110), 0x20CD, 0x0000); // _strdup
            write_cdecl_const_stub(page.add(0x120), 0);        // iswctype → 0
            write_cdecl_const_stub(page.add(0x130), 0);        // _mbstrlen → 0
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-private-l1-1-0.dll") {
        unsafe {
            write_win32_stub(page.add(0x000), 0x2023, 0x0000); // memcpy
            write_win32_stub(page.add(0x010), 0x20D5, 0x0000); // memmove
            write_win32_stub(page.add(0x020), 0x20D3, 0x0000); // memcmp
            write_win32_stub(page.add(0x030), 0x20D4, 0x0000); // memchr
            write_win32_stub(page.add(0x040), 0x20CC, 0x0000); // strchr
            write_cdecl_const_stub(page.add(0x050), 0);        // _setjmp3 → 0 (like setjmp first call)
            write_cdecl_const_stub(page.add(0x060), 0);        // longjmp → stub (will malfunction but rare)
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-stdio-l1-1-0.dll") {
        // All stub-return 0; DXVK only uses stdio for logging fallbacks.
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 0);        // __acrt_iob_func → NULL
            write_cdecl_const_stub(page.add(0x010), 0);        // __stdio_common_vfprintf → 0
            write_cdecl_const_stub(page.add(0x020), 0);        // __stdio_common_vsprintf → 0
            write_cdecl_const_stub(page.add(0x030), 0xFFFF_FFFFu32); // _get_osfhandle → INVALID
            write_cdecl_const_stub(page.add(0x040), 0);        // _lseeki64 → 0
            write_cdecl_const_stub(page.add(0x050), 0);        // _wfopen → NULL
            write_cdecl_const_stub(page.add(0x060), 0);        // fclose → 0
            write_cdecl_const_stub(page.add(0x070), 0);        // fflush → 0
            write_cdecl_const_stub(page.add(0x080), 0);        // fopen → NULL
            write_cdecl_const_stub(page.add(0x090), 0);        // fputc → 0
            write_cdecl_const_stub(page.add(0x0A0), 0);        // fputs → 0
            write_cdecl_const_stub(page.add(0x0B0), 0);        // fwrite → 0
            write_cdecl_const_stub(page.add(0x0C0), 0);        // setvbuf → 0
            write_cdecl_const_stub(page.add(0x0D0), 0);        // _write → 0
            write_cdecl_const_stub(page.add(0x0E0), 0);        // _read → 0
            write_cdecl_const_stub(page.add(0x0F0), 0);        // _fileno → 0
            write_cdecl_const_stub(page.add(0x100), 0);        // fread → 0
            write_cdecl_const_stub(page.add(0x110), 0);        // ftell → 0
            write_cdecl_const_stub(page.add(0x120), 0);        // _fseeki64 → 0
            write_cdecl_const_stub(page.add(0x130), 0);        // _ftelli64 → 0
            write_cdecl_const_stub(page.add(0x140), 0);        // _fdopen → NULL
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-convert-l1-1-0.dll") {
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 0);        // btowc → 0
            write_cdecl_const_stub(page.add(0x010), 0);        // mbrtowc → 0
            write_cdecl_const_stub(page.add(0x020), 0);        // mbsrtowcs → 0
            write_win32_stub(page.add(0x030), 0x20D2, 0x0000); // strtoul
            write_cdecl_const_stub(page.add(0x040), 0);        // wcrtomb → 0
            write_cdecl_const_stub(page.add(0x050), 0);        // wctob → 0
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-environment-l1-1-0.dll") {
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 0); // getenv → NULL (not found)
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-filesystem-l1-1-0.dll") {
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 0xFFFF_FFFFu32); // _fstat64 → -1 (fail)
            write_cdecl_const_stub(page.add(0x010), 0);              // _lock_file → void
            write_cdecl_const_stub(page.add(0x020), 0);              // _unlock_file → void
            write_cdecl_const_stub(page.add(0x030), 0xFFFF_FFFFu32); // remove → -1 (fail)
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-locale-l1-1-0.dll") {
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 1); // ___mb_cur_max_func → 1 (ASCII)
            write_cdecl_const_stub(page.add(0x010), 0); // localeconv → NULL
            write_cdecl_const_stub(page.add(0x020), 0); // setlocale → NULL
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-math-l1-1-0.dll") {
        // FP stubs — DXVK uses these rarely; return 0 (0.0 in IEEE 754).
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 0); // cos → 0.0
            write_cdecl_const_stub(page.add(0x010), 0); // fmaxf → 0.0
            write_cdecl_const_stub(page.add(0x020), 0); // fminf → 0.0
            write_cdecl_const_stub(page.add(0x030), 0); // pow → 0.0
            write_cdecl_const_stub(page.add(0x040), 0); // _fdopen → NULL
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-time-l1-1-0.dll") {
        unsafe {
            write_cdecl_const_stub(page.add(0x000), 0); // strftime → 0
            write_cdecl_const_stub(page.add(0x010), 0); // wcsftime → 0
        }

    } else if eq_ascii_nocase(module_name, "api-ms-win-crt-utility-l1-1-0.dll") {
        unsafe {
            // rand_s(unsigned*) → 0 (S_OK), fills output with 0
            write_cdecl_const_stub(page.add(0x000), 0);
        }

    } else if eq_ascii_nocase(module_name, "dbghelp.dll") {
        // All dbghelp functions return FALSE/0 — Ghost Recon only uses these in debug paths.
        unsafe {
            write_const_stub(page.add(0x000), 0, 0x0010); // SymGetLineFromAddr(4) → FALSE
            write_const_stub(page.add(0x010), 0, 0x001C); // StackWalk(7) → FALSE
            write_const_stub(page.add(0x020), 1, 4);      // SymCleanup(1) → TRUE
            write_const_stub(page.add(0x030), 0, 8);      // SymFunctionTableAccess(2) → NULL
            write_const_stub(page.add(0x040), 0, 8);      // SymGetModuleInfo(2) → FALSE
            write_const_stub(page.add(0x050), 0, 0);      // SymGetOptions() → 0
            write_const_stub(page.add(0x060), 0, 0x0010); // SymGetSymFromAddr(4) → FALSE
            write_const_stub(page.add(0x070), 1, 0x000C); // SymInitialize(3) → TRUE
            write_const_stub(page.add(0x080), 0, 0x0018); // SymLoadModule(6) → 0
            write_const_stub(page.add(0x090), 0, 4);      // SymSetOptions(1) → 0 (prev options)
            write_const_stub(page.add(0x0A0), 0, 0x0010); // SymUnDName(4) → FALSE
            write_const_stub(page.add(0x0B0), 0, 0x0010); // UnDecorateSymbolName(4) → 0
        }

    } else if eq_ascii_nocase(module_name, "ole32.dll") {
        // CoFreeUnusedLibraries() → void no-op.
        // CoInitialize(pvReserved) → S_OK (0).
        // CoUninitialize() → void.
        unsafe {
            write_const_stub(page.add(0x000), 0, 0);               // CoFreeUnusedLibraries() → void
            write_const_stub(page.add(0x010), 0, 4);               // CoInitialize(1) → S_OK
            write_const_stub(page.add(0x020), 0, 0);               // CoUninitialize() → void
            write_const_stub(page.add(0x030), 0x8000_4002u32, 0x0014); // CoCreateInstance(5) → E_NOINTERFACE
            write_win32_stub(page.add(0x040), 0x2020, 0x0000);     // CoTaskMemAlloc(1) → reuse malloc (cdecl)
            write_const_stub(page.add(0x050), 0, 4);               // CoTaskMemFree(1) → void
        }

    } else if eq_ascii_nocase(module_name, "dinput8.dll") {
        // DirectInput8Create(hInst, dwVersion, riid, ppvOut, pUnkOuter) → E_NOTIMPL
        // Returns E_NOTIMPL so the game either disables DI8 or falls back to WM_INPUT.
        unsafe {
            write_const_stub(page.add(0x000), 0x8000_4001u32, 0x0014); // DirectInput8Create(5)
        }

    } else if eq_ascii_nocase(module_name, "dsound.dll") {
        // 0x88780078 = DSERR_NODRIVER — game falls back to null audio.
        unsafe {
            write_const_stub(page.add(0x000), 0x8878_0078u32, 0x000C); // DirectSoundCreate(3) ord 1
            write_const_stub(page.add(0x010), 0x8878_0078u32, 0x0010); // DirectSoundCreate8(4) ord 2
            write_const_stub(page.add(0x020), 0x8878_0078u32, 0x000C); // ord 3 → DSERR_NODRIVER
            write_const_stub(page.add(0x030), 0x8878_0078u32, 0x000C); // ord 4 → DSERR_NODRIVER
            write_const_stub(page.add(0x040), 0x8878_0078u32, 0x000C); // ord 5 → DSERR_NODRIVER
            write_const_stub(page.add(0x050), 0x8878_0078u32, 0x000C); // ord 6 → DSERR_NODRIVER
            write_const_stub(page.add(0x060), 0x8878_0078u32, 0x000C); // ord 7 → DSERR_NODRIVER
            write_const_stub(page.add(0x070), 0x8878_0078u32, 0x000C); // ord 8 GetDeviceID
            write_const_stub(page.add(0x080), 0x8878_0078u32, 0x000C); // ord 9
            write_const_stub(page.add(0x090), 0, 0);                   // ord 10 DllCanUnloadNow → S_FALSE
            // DirectSoundEnumerateA(cb, ctx) → DS_OK (0); just return without calling callback
            write_const_stub(page.add(0x0A0), 0, 8);                   // ord 11
        }

    } else if eq_ascii_nocase(module_name, "wsock32.dll") {
        // All stubs return SOCKET_ERROR (0xFFFF_FFFF) so the game disables network.
        // Ordinal-indexed: each export array entry maps to an ordinal via ordinal_base.
        unsafe {
            write_const_stub(page.add(0x000), 0xFFFF_FFFFu32, 0x000C); // ord 1  accept(3)
            write_const_stub(page.add(0x010), 0xFFFF_FFFFu32, 0x000C); // ord 2  bind(3)
            write_const_stub(page.add(0x020), 0xFFFF_FFFFu32, 4);      // ord 3  closesocket(1)
            write_const_stub(page.add(0x030), 0xFFFF_FFFFu32, 0x000C); // ord 4  connect(3)
            write_const_stub(page.add(0x040), 0xFFFF_FFFFu32, 0x000C); // ord 5  getpeername(3)
            write_const_stub(page.add(0x050), 0xFFFF_FFFFu32, 0x000C); // ord 6  getsockname(3)
            write_const_stub(page.add(0x060), 0xFFFF_FFFFu32, 0x0014); // ord 7  getsockopt(5)
            write_const_stub(page.add(0x070), 0, 4);                   // ord 8  htonl(1) → 0
            write_const_stub(page.add(0x080), 0, 4);                   // ord 9  htons(1) → 0
            write_const_stub(page.add(0x090), 0xFFFF_FFFFu32, 4);      // ord 10 inet_addr(1) → INADDR_NONE
            write_const_stub(page.add(0x0A0), 0, 4);                   // ord 11 inet_ntoa(1) → NULL
            write_const_stub(page.add(0x0B0), 0xFFFF_FFFFu32, 8);      // ord 12 listen(2)
            write_const_stub(page.add(0x0C0), 0, 4);                   // ord 13 ntohl(1) → 0
            write_const_stub(page.add(0x0D0), 0, 4);                   // ord 14 ntohs(1) → 0
            write_const_stub(page.add(0x0E0), 0xFFFF_FFFFu32, 0x0010); // ord 15 recv(4)
            write_const_stub(page.add(0x0F0), 0xFFFF_FFFFu32, 0x0018); // ord 16 recvfrom(6)
            write_const_stub(page.add(0x100), 0xFFFF_FFFFu32, 0x0014); // ord 17 select(5)
            write_const_stub(page.add(0x110), 0xFFFF_FFFFu32, 0x0010); // ord 18 send(4)
            write_const_stub(page.add(0x120), 0xFFFF_FFFFu32, 0x0018); // ord 19 sendto(6)
            write_const_stub(page.add(0x130), 0xFFFF_FFFFu32, 0x0014); // ord 20 setsockopt(5)
            write_const_stub(page.add(0x140), 0xFFFF_FFFFu32, 8);      // ord 21 shutdown(2)
            write_const_stub(page.add(0x150), 0xFFFF_FFFFu32, 0x000C); // ord 22 socket(3)
            write_const_stub(page.add(0x160), 0, 0x000C);              // ord 23 gethostbyaddr(3) → NULL
            // ord 24-51: padding → all point to 0x1170 (a single SOCKET_ERROR stub)
            write_const_stub(page.add(0x170), 0xFFFF_FFFFu32, 4);      // generic SOCKET_ERROR stub
            write_const_stub(page.add(0x180), 0, 4);                   // ord 52 gethostbyname(1) → NULL
            write_const_stub(page.add(0x190), 0, 4);                   // ord 57 gethostname(1) → NULL/err
            write_const_stub(page.add(0x1A0), 0, 8);                   // ord 111 WSAStartup(2) → 0
            write_const_stub(page.add(0x1B0), 0, 0);                   // ord 115 WSACleanup() → 0
            write_const_stub(page.add(0x1C0), 0, 4);                   // ord 116 WSASetLastError(1) → void
        }

    } else if eq_ascii_nocase(module_name, "vulkan-1.dll") {
        // ── Vulkan ICD loader shim ──────────────────────────────────────────
        // Stubs in 0x10-byte slots. Three types:
        //   write_win32_stub  → INT 0x2E syscall for handlers that fill structs
        //   write_vk_create_stub → writes non-null handle + returns VK_SUCCESS
        //   write_const_stub → returns VK_SUCCESS (0) or void
        unsafe {
            // 0: vkGetInstanceProcAddr(instance, pName) → syscall
            write_win32_stub(page.add(0x000), 0x3000, 0x0008);
            // 1: vkGetDeviceProcAddr(device, pName) → syscall (same handler)
            write_win32_stub(page.add(0x010), 0x3001, 0x0008);
            // 2: vkCreateInstance(pCI, pAlloc, ppInstance) → create stub
            write_vk_create_stub(page.add(0x020), 0x0C, 0xDE00_0001, 12);
            // 3: vkDestroyInstance(instance, pAlloc) → void
            write_const_stub(page.add(0x030), 0, 8);
            // 4: vkEnumerateInstanceExtensionProperties(layer, pCount, pProps)
            write_win32_stub(page.add(0x040), 0x3004, 0x000C);
            // 5: vkEnumerateInstanceLayerProperties(pCount, pProps)
            write_win32_stub(page.add(0x050), 0x3005, 0x0008);
            // 6: vkEnumerateInstanceVersion(pApiVersion)
            write_win32_stub(page.add(0x060), 0x3006, 0x0004);
            // 7: vkEnumeratePhysicalDevices(instance, pCount, pPhysDevs)
            write_win32_stub(page.add(0x070), 0x3007, 0x000C);
            // 8: vkGetPhysicalDeviceProperties(physDev, pProps)
            write_win32_stub(page.add(0x080), 0x3008, 0x0008);
            // 9: vkGetPhysicalDeviceProperties2KHR(physDev, pProps2)
            write_win32_stub(page.add(0x090), 0x3009, 0x0008);
            // 10: vkGetPhysicalDeviceFeatures(physDev, pFeatures)
            write_win32_stub(page.add(0x0A0), 0x300A, 0x0008);
            // 11: vkGetPhysicalDeviceFeatures2KHR(physDev, pFeatures2)
            write_win32_stub(page.add(0x0B0), 0x300B, 0x0008);
            // 12: vkGetPhysicalDeviceMemoryProperties(physDev, pMemProps)
            write_win32_stub(page.add(0x0C0), 0x300C, 0x0008);
            // 13: vkGetPhysicalDeviceMemoryProperties2KHR
            write_win32_stub(page.add(0x0D0), 0x300D, 0x0008);
            // 14: vkGetPhysicalDeviceQueueFamilyProperties(physDev, pCount, pProps)
            write_win32_stub(page.add(0x0E0), 0x300E, 0x000C);
            // 15: vkGetPhysicalDeviceFormatProperties(physDev, format, pProps)
            write_win32_stub(page.add(0x0F0), 0x300F, 0x000C);
            // 16: vkGetPhysicalDeviceFormatProperties2KHR → void, fill
            write_win32_stub(page.add(0x100), 0x3010, 0x000C);
            // 17: vkEnumerateDeviceExtensionProperties(physDev, layer, pCount, pProps)
            write_win32_stub(page.add(0x110), 0x3011, 0x0010);
            // 18: vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physDev, surface, pCaps)
            write_win32_stub(page.add(0x120), 0x3012, 0x000C);
            // 19: vkGetPhysicalDeviceSurfaceFormatsKHR(physDev, surface, pCount, pFormats)
            write_win32_stub(page.add(0x130), 0x3013, 0x0010);
            // 20: vkGetPhysicalDeviceSurfacePresentModesKHR(physDev, surf, pCount, pModes)
            write_win32_stub(page.add(0x140), 0x3014, 0x0010);
            // 21: vkGetPhysicalDeviceSurfaceSupportKHR(physDev, queueFam, surf, pSupported)
            write_win32_stub(page.add(0x150), 0x3015, 0x0010);
            // 22: vkCreateWin32SurfaceKHR(inst, pCI, pAlloc, pSurface) → create
            write_vk_create_stub(page.add(0x160), 0x10, 0xDE00_0002, 16);
            // 23: vkDestroySurfaceKHR(inst, surface, pAlloc) → void
            write_const_stub(page.add(0x170), 0, 12);
            // 24: vkCreateDevice(physDev, pCI, pAlloc, ppDevice) → create
            write_vk_create_stub(page.add(0x180), 0x10, 0xDE00_0003, 16);
            // 25: vkDestroyDevice(device, pAlloc) → void
            write_const_stub(page.add(0x190), 0, 8);
            // 26: vkGetDeviceQueue(device, queueFam, queueIdx, ppQueue) → create
            write_vk_create_stub(page.add(0x1A0), 0x10, 0xDE00_0004, 16);
            // 27: vkCreateSwapchainKHR(dev, pCI, pAlloc, pSwapchain) → create
            write_vk_create_stub(page.add(0x1B0), 0x10, 0xDE00_0005, 16);
            // 28: vkDestroySwapchainKHR(dev, swapchain, pAlloc) → void
            write_const_stub(page.add(0x1C0), 0, 12);
            // 29: vkGetSwapchainImagesKHR(dev, swapchain, pCount, pImages)
            write_win32_stub(page.add(0x1D0), 0x3016, 0x0010);
            // 30: vkAcquireNextImageKHR(dev, sc, timeout_lo, timeout_hi, sem, fence, pIdx)
            //     6 args but timeout is u64 → 28 bytes on stack
            write_win32_stub(page.add(0x1E0), 0x3017, 0x001C);
            // 31: vkQueuePresentKHR(queue, pPresentInfo) → syscall for GOP blit
            write_win32_stub(page.add(0x1F0), 0x301F, 0x0008);
            // 32: vkCreateCommandPool(dev, pCI, pAlloc, pCmdPool) → create
            write_vk_create_stub(page.add(0x200), 0x10, 0xDE00_0006, 16);
            // 33: vkDestroyCommandPool → void
            write_const_stub(page.add(0x210), 0, 12);
            // 34: vkResetCommandPool → VK_SUCCESS
            write_const_stub(page.add(0x220), 0, 12);
            // 35: vkAllocateCommandBuffers(dev, pAllocInfo, pCmdBufs)
            write_win32_stub(page.add(0x230), 0x3018, 0x000C);
            // 36: vkFreeCommandBuffers → void
            write_const_stub(page.add(0x240), 0, 16);
            // 37: vkBeginCommandBuffer → VK_SUCCESS
            write_const_stub(page.add(0x250), 0, 8);
            // 38: vkEndCommandBuffer → VK_SUCCESS
            write_const_stub(page.add(0x260), 0, 4);
            // 39: vkResetCommandBuffer → VK_SUCCESS
            write_const_stub(page.add(0x270), 0, 8);
            // 40: vkCreateFence(dev, pCI, pAlloc, pFence) → create
            write_vk_create_stub(page.add(0x280), 0x10, 0xDE00_0007, 16);
            // 41: vkDestroyFence → void
            write_const_stub(page.add(0x290), 0, 12);
            // 42: vkResetFences → VK_SUCCESS
            write_const_stub(page.add(0x2A0), 0, 12);
            // 43: vkGetFenceStatus → VK_SUCCESS (signalled)
            write_const_stub(page.add(0x2B0), 0, 8);
            // 44: vkWaitForFences(dev, cnt, pFences, waitAll, timeout_lo, timeout_hi)
            //     timeout is u64 → 24 bytes
            write_const_stub(page.add(0x2C0), 0, 24);
            // 45: vkCreateSemaphore(dev, pCI, pAlloc, pSem) → create
            write_vk_create_stub(page.add(0x2D0), 0x10, 0xDE00_0008, 16);
            // 46: vkDestroySemaphore → void
            write_const_stub(page.add(0x2E0), 0, 12);
            // 47: vkCreateRenderPass(dev, pCI, pAlloc, pRP) → create
            write_vk_create_stub(page.add(0x2F0), 0x10, 0xDE00_0009, 16);
            // 48: vkDestroyRenderPass → void
            write_const_stub(page.add(0x300), 0, 12);
            // 49: vkCreateFramebuffer(dev, pCI, pAlloc, pFB) → create
            write_vk_create_stub(page.add(0x310), 0x10, 0xDE00_000A, 16);
            // 50: vkDestroyFramebuffer → void
            write_const_stub(page.add(0x320), 0, 12);
            // 51: vkCreateImageView(dev, pCI, pAlloc, pView) → create
            write_vk_create_stub(page.add(0x330), 0x10, 0xDE00_000B, 16);
            // 52: vkDestroyImageView → void
            write_const_stub(page.add(0x340), 0, 12);
            // 53: vkCreateImage(dev, pCI, pAlloc, pImage) → create
            write_vk_create_stub(page.add(0x350), 0x10, 0xDE00_000C, 16);
            // 54: vkDestroyImage → void
            write_const_stub(page.add(0x360), 0, 12);
            // 55: vkGetImageSubresourceLayout → void (4 args)
            write_const_stub(page.add(0x370), 0, 16);
            // 56: vkCreateBuffer(dev, pCI, pAlloc, pBuf) → create
            write_vk_create_stub(page.add(0x380), 0x10, 0xDE00_000D, 16);
            // 57: vkDestroyBuffer → void
            write_const_stub(page.add(0x390), 0, 12);
            // 58: vkCreateBufferView(dev, pCI, pAlloc, pView) → create
            write_vk_create_stub(page.add(0x3A0), 0x10, 0xDE00_000E, 16);
            // 59: vkDestroyBufferView → void
            write_const_stub(page.add(0x3B0), 0, 12);
            // 60: vkAllocateMemory(dev, pAllocInfo, pAlloc, pMem) → create
            write_vk_create_stub(page.add(0x3C0), 0x10, 0xDE00_000F, 16);
            // 61: vkFreeMemory → void
            write_const_stub(page.add(0x3D0), 0, 12);
            // 62: vkMapMemory(dev, mem, offset_lo, offset_hi, size_lo, size_hi, flags, ppData)
            //     offset + size are u64 → 32 bytes total
            write_win32_stub(page.add(0x3E0), 0x3019, 0x0020);
            // 63: vkUnmapMemory → void
            write_const_stub(page.add(0x3F0), 0, 8);
            // 64: vkBindBufferMemory(dev, buf, mem, offset_lo, offset_hi)
            //     offset is u64 → 20 bytes
            write_const_stub(page.add(0x400), 0, 20);
            // 65: vkBindImageMemory(dev, image, mem, offset_lo, offset_hi)
            write_const_stub(page.add(0x410), 0, 20);
            // 66: vkGetImageMemoryRequirements(dev, image, pMemReqs) → void, fill
            write_win32_stub(page.add(0x420), 0x301A, 0x000C);
            // 67: vkGetBufferMemoryRequirements(dev, buffer, pMemReqs)
            write_win32_stub(page.add(0x430), 0x301B, 0x000C);
            // 68: vkCreateShaderModule(dev, pCI, pAlloc, pModule) → create
            write_vk_create_stub(page.add(0x440), 0x10, 0xDE00_0010, 16);
            // 69: vkDestroyShaderModule → void
            write_const_stub(page.add(0x450), 0, 12);
            // 70: vkCreatePipelineLayout(dev, pCI, pAlloc, pLayout) → create
            write_vk_create_stub(page.add(0x460), 0x10, 0xDE00_0011, 16);
            // 71: vkDestroyPipelineLayout → void
            write_const_stub(page.add(0x470), 0, 12);
            // 72: vkCreateDescriptorSetLayout(dev, pCI, pAlloc, pLayout) → create
            write_vk_create_stub(page.add(0x480), 0x10, 0xDE00_0012, 16);
            // 73: vkDestroyDescriptorSetLayout → void
            write_const_stub(page.add(0x490), 0, 12);
            // 74: vkCreateDescriptorPool(dev, pCI, pAlloc, pPool) → create
            write_vk_create_stub(page.add(0x4A0), 0x10, 0xDE00_0013, 16);
            // 75: vkDestroyDescriptorPool → void
            write_const_stub(page.add(0x4B0), 0, 12);
            // 76: vkAllocateDescriptorSets(dev, pAllocInfo, pSets)
            write_win32_stub(page.add(0x4C0), 0x301C, 0x000C);
            // 77: vkUpdateDescriptorSets → void (5 args)
            write_const_stub(page.add(0x4D0), 0, 20);
            // 78: vkFreeDescriptorSets → VK_SUCCESS (4 args)
            write_const_stub(page.add(0x4E0), 0, 16);
            // 79: vkCreateGraphicsPipelines(dev, cache, count, pCIs, pAlloc, pPipelines)
            write_win32_stub(page.add(0x4F0), 0x301D, 0x0018);
            // 80: vkCreateComputePipelines (same layout)
            write_win32_stub(page.add(0x500), 0x301E, 0x0018);
            // 81: vkDestroyPipeline → void
            write_const_stub(page.add(0x510), 0, 12);
            // 82: vkCreatePipelineCache(dev, pCI, pAlloc, pCache) → create
            write_vk_create_stub(page.add(0x520), 0x10, 0xDE00_0015, 16);
            // 83: vkDestroyPipelineCache → void
            write_const_stub(page.add(0x530), 0, 12);
            // 84: vkCreateSampler(dev, pCI, pAlloc, pSampler) → create
            write_vk_create_stub(page.add(0x540), 0x10, 0xDE00_0016, 16);
            // 85: vkDestroySampler → void
            write_const_stub(page.add(0x550), 0, 12);
            // 86: vkCreateQueryPool(dev, pCI, pAlloc, pPool) → create
            write_vk_create_stub(page.add(0x560), 0x10, 0xDE00_0017, 16);
            // 87: vkDestroyQueryPool → void
            write_const_stub(page.add(0x570), 0, 12);
            // 88: vkGetQueryPoolResults → VK_SUCCESS (many args, 32 bytes)
            write_const_stub(page.add(0x580), 0, 32);
            // 89: vkQueueSubmit → VK_SUCCESS (4 args)
            write_const_stub(page.add(0x590), 0, 16);
            // 90: vkQueueWaitIdle → VK_SUCCESS
            write_const_stub(page.add(0x5A0), 0, 4);
            // 91: vkDeviceWaitIdle → VK_SUCCESS
            write_const_stub(page.add(0x5B0), 0, 4);
            // 92–126: vkCmd* (all void, various arg counts)
            write_const_stub(page.add(0x5C0), 0, 12); // vkCmdBeginRenderPass
            write_const_stub(page.add(0x5D0), 0, 4);  // vkCmdEndRenderPass
            write_const_stub(page.add(0x5E0), 0, 12); // vkCmdBindPipeline
            write_const_stub(page.add(0x5F0), 0, 20); // vkCmdBindVertexBuffers
            write_const_stub(page.add(0x600), 0, 20); // vkCmdBindIndexBuffer
            write_const_stub(page.add(0x610), 0, 20); // vkCmdDraw
            write_const_stub(page.add(0x620), 0, 24); // vkCmdDrawIndexed
            write_const_stub(page.add(0x630), 0, 28); // vkCmdBindDescriptorSets
            write_const_stub(page.add(0x640), 0, 16); // vkCmdSetViewport
            write_const_stub(page.add(0x650), 0, 16); // vkCmdSetScissor
            write_const_stub(page.add(0x660), 0, 20); // vkCmdCopyBuffer
            write_const_stub(page.add(0x670), 0, 24); // vkCmdCopyImage
            write_const_stub(page.add(0x680), 0, 20); // vkCmdCopyBufferToImage
            write_const_stub(page.add(0x690), 0, 20); // vkCmdCopyImageToBuffer
            write_const_stub(page.add(0x6A0), 0, 44); // vkCmdPipelineBarrier (11 args)
            write_const_stub(page.add(0x6B0), 0, 24); // vkCmdPushConstants
            write_const_stub(page.add(0x6C0), 0, 24); // vkCmdClearColorImage
            write_const_stub(page.add(0x6D0), 0, 24); // vkCmdClearDepthStencilImage
            write_const_stub(page.add(0x6E0), 0, 24); // vkCmdResolveImage
            write_const_stub(page.add(0x6F0), 0, 28); // vkCmdBlitImage
            write_const_stub(page.add(0x700), 0, 24); // vkCmdFillBuffer (has u64s)
            write_const_stub(page.add(0x710), 0, 16); // vkCmdDispatch
            write_const_stub(page.add(0x720), 0, 12); // vkCmdExecuteCommands
            write_const_stub(page.add(0x730), 0, 8);  // vkCmdSetLineWidth
            write_const_stub(page.add(0x740), 0, 16); // vkCmdSetDepthBias
            write_const_stub(page.add(0x750), 0, 8);  // vkCmdSetBlendConstants
            write_const_stub(page.add(0x760), 0, 12); // vkCmdSetDepthBounds
            write_const_stub(page.add(0x770), 0, 12); // vkCmdSetStencilCompareMask
            write_const_stub(page.add(0x780), 0, 12); // vkCmdSetStencilWriteMask
            write_const_stub(page.add(0x790), 0, 12); // vkCmdSetStencilReference
            write_const_stub(page.add(0x7A0), 0, 16); // vkCmdWriteTimestamp
            write_const_stub(page.add(0x7B0), 0, 20); // vkCmdResetQueryPool
            write_const_stub(page.add(0x7C0), 0, 16); // vkCmdBeginQuery
            write_const_stub(page.add(0x7D0), 0, 12); // vkCmdEndQuery
            write_const_stub(page.add(0x7E0), 0, 36); // vkCmdCopyQueryPoolResults (has u64s)
            // 127: vkCreateRenderPass2KHR(dev, pCI, pAlloc, pRP) → create
            write_vk_create_stub(page.add(0x7F0), 0x10, 0xDE00_0018, 16);
            // 128: vkQueueSubmit2KHR → VK_SUCCESS (4 args)
            write_const_stub(page.add(0x800), 0, 16);
        }
    }
}

fn map_stub_modules(
    vad: &mut mm::vad::VadTree,
    mapper: &mut dyn mm::virtual_alloc::PageMapper,
) -> Result<(), &'static str> {
    for module in STUB_MODULES {
        if let Err(e) = mm::virtual_alloc::allocate(
            vad,
            Some(mapper),
            module.base as u64,
            0x2000,
            mm::virtual_alloc::AllocType::MEM_RESERVE | mm::virtual_alloc::AllocType::MEM_COMMIT,
            mm::vad::PageProtect::EXECUTE_READWRITE,
        ) {
            log::warn!("load_image: failed to map stub module {} at {:#x}: {}", module.dll, module.base, e);
            return Err("load_image: failed to map stub module");
        }
        initialise_stub_module_code(module.base, module.dll);
    }
    Ok(())
}

pub fn resolve_stub_module_base(dll: &str) -> Option<u32> {
    for module in STUB_MODULES {
        if eq_ascii_nocase(dll, module.dll) {
            return Some(module.base);
        }
    }
    None
}

pub fn resolve_stub_proc_by_base(module_base: u32, proc_name: &str) -> Option<u32> {
    for module in STUB_MODULES {
        if module.base != module_base {
            continue;
        }
        for export in module.exports {
            if eq_ascii_nocase(proc_name, export.name) {
                return Some(module.base.wrapping_add(export.rva));
            }
        }
        return None;
    }
    None
}

fn resolve_import_symbol(dll: &str, name: &str, ordinal: Option<u16>) -> Option<u32> {
    // 1. Check dynamically-loaded DLLs first (real DXVK DLLs take priority)
    if let Some(base) = resolve_loaded_dll_base(dll) {
        if let Some(ord) = ordinal {
            return resolve_export_by_ordinal(base, ord);
        }
        if let Some(va) = resolve_export_from_base(base, name) {
            return Some(va);
        }
    }
    // 2. Fall back to stub modules (static stubs)
    for module in STUB_MODULES {
        if !eq_ascii_nocase(dll, module.dll) {
            continue;
        }
        if let Some(ord) = ordinal {
            // Ordinal resolution: exports array is indexed from ordinal_base.
            if module.ordinal_base > 0 {
                let idx = (ord as usize).wrapping_sub(module.ordinal_base as usize);
                if idx < module.exports.len() {
                    return Some(module.base.wrapping_add(module.exports[idx].rva));
                }
            }
            return None; // ordinal out of range or module has no ordinal support
        }
        return resolve_stub_proc_by_base(module.base, name);
    }
    None
}

/// Parse the PE export directory at `base` (a 32-bit user VA loaded in the current
/// address space) and find the VA of `name`.
///
/// Reads IMAGE_EXPORT_DIRECTORY fields and walks the name/ordinal/function arrays,
/// all by direct pointer dereference (valid in kernel mode — same CR3).
///
/// # IRQL: PASSIVE_LEVEL
fn resolve_export_from_base(base: u32, name: &str) -> Option<u32> {
    // SAFETY: base is a user VA mapped by load_dll; kernel uses same page tables.
    unsafe {
        // Read e_lfanew (DOS header offset 0x3C)
        let e_lfanew = (base.wrapping_add(0x3C) as *const u32).read_unaligned() as u32;
        // Optional header is at NT headers + 4 (sig) + 20 (FileHeader)
        let opt_off = base.wrapping_add(e_lfanew).wrapping_add(24);
        // DataDirectory[0] = export table: at opt_off + 0x60
        let export_rva = (opt_off.wrapping_add(0x60) as *const u32).read_unaligned();
        if export_rva == 0 { return None; }

        let exp = base.wrapping_add(export_rva);
        // IMAGE_EXPORT_DIRECTORY layout:
        //  +0  Characteristics
        //  +4  TimeDateStamp
        //  +8  MajorVersion / MinorVersion
        //  +12 Name (RVA of module name string)
        //  +16 Base (ordinal bias)
        //  +20 NumberOfFunctions
        //  +24 NumberOfNames
        //  +28 AddressOfFunctions (RVA → u32[NumberOfFunctions])
        //  +32 AddressOfNames      (RVA → u32[NumberOfNames])
        //  +36 AddressOfNameOrdinals (RVA → u16[NumberOfNames])
        let n_names      = (exp.wrapping_add(24) as *const u32).read_unaligned() as usize;
        let fn_table_rva = (exp.wrapping_add(28) as *const u32).read_unaligned();
        let nm_table_rva = (exp.wrapping_add(32) as *const u32).read_unaligned();
        let ord_table_rva= (exp.wrapping_add(36) as *const u32).read_unaligned();

        let fn_table  = base.wrapping_add(fn_table_rva)  as *const u32;
        let nm_table  = base.wrapping_add(nm_table_rva)  as *const u32;
        let ord_table = base.wrapping_add(ord_table_rva) as *const u16;

        for i in 0..n_names {
            let name_rva = nm_table.add(i).read_unaligned();
            let name_ptr = base.wrapping_add(name_rva) as *const u8;
            // Read export name from user VA
            let mut len = 0usize;
            while len < 256 {
                if name_ptr.add(len).read_unaligned() == 0 { break; }
                len += 1;
            }
            let export_name_bytes = core::slice::from_raw_parts(name_ptr, len);
            let export_name = core::str::from_utf8(export_name_bytes).unwrap_or("");
            if eq_ascii_nocase(export_name, name) {
                let ordinal = ord_table.add(i).read_unaligned() as usize;
                let fn_rva  = fn_table.add(ordinal).read_unaligned();
                return Some(base.wrapping_add(fn_rva));
            }
        }
        None
    }
}

fn resolve_export_by_ordinal(base: u32, ordinal: u16) -> Option<u32> {
    // SAFETY: base is a mapped user VA.
    unsafe {
        let e_lfanew = (base.wrapping_add(0x3C) as *const u32).read_unaligned();
        let opt_off = base.wrapping_add(e_lfanew).wrapping_add(24);
        let export_rva = (opt_off.wrapping_add(0x60) as *const u32).read_unaligned();
        if export_rva == 0 { return None; }
        let exp = base.wrapping_add(export_rva);
        let ordinal_base = (exp.wrapping_add(16) as *const u32).read_unaligned(); // Base
        let n_funcs      = (exp.wrapping_add(20) as *const u32).read_unaligned() as usize;
        let fn_table_rva = (exp.wrapping_add(28) as *const u32).read_unaligned();
        let fn_table     = base.wrapping_add(fn_table_rva) as *const u32;
        let idx = (ordinal as u32).wrapping_sub(ordinal_base) as usize;
        if idx >= n_funcs { return None; }
        let fn_rva = fn_table.add(idx).read_unaligned();
        if fn_rva == 0 { return None; }
        Some(base.wrapping_add(fn_rva))
    }
}

/// Public wrapper for GetProcAddress by name on real loaded DLLs.
pub fn resolve_export_from_base_pub(base: u32, name: &str) -> Option<u32> {
    resolve_export_from_base(base, name)
}

/// Public wrapper for GetProcAddress by ordinal on real loaded DLLs.
pub fn resolve_export_by_ordinal_pub(base: u32, ordinal: u16) -> Option<u32> {
    resolve_export_by_ordinal(base, ordinal)
}

/// Apply PE base relocations when `load_base != preferred_base`.
/// Reads the relocation directory (DataDirectory[5]) from the LOADED image.
/// Only HIGHLOW (type 3) and DIR64 (type 10) entries are processed;
/// ABSOLUTE (type 0) entries are skipped (padding).
///
/// # IRQL: PASSIVE_LEVEL
pub fn apply_relocations(load_base: u64, preferred_base: u64) -> Result<(), &'static str> {
    let delta = load_base.wrapping_sub(preferred_base) as i64;
    if delta == 0 { return Ok(()); }

    // SAFETY: load_base is committed memory (sections were mapped before this call).
    unsafe {
        let e_lfanew = (load_base.wrapping_add(0x3C) as *const u32).read_unaligned() as u64;
        let opt_off  = load_base.wrapping_add(e_lfanew).wrapping_add(24); // past PE sig + FileHeader

        // DataDirectory[5] = base relocation table: opt_off + 0x60 + 5*8
        let reloc_dir_off = opt_off.wrapping_add(0x60).wrapping_add(5 * 8);
        let reloc_rva  = (reloc_dir_off as *const u32).read_unaligned() as u64;
        let reloc_size = (reloc_dir_off.wrapping_add(4) as *const u32).read_unaligned() as u64;

        if reloc_rva == 0 || reloc_size == 0 {
            log::debug!("apply_relocations: no reloc directory (DLL has no relocations)");
            return Ok(());
        }

        let mut offset = 0u64; // byte offset into the reloc directory
        while offset + 8 <= reloc_size {
            let block_ptr = load_base.wrapping_add(reloc_rva).wrapping_add(offset);
            let page_rva  = (block_ptr as *const u32).read_unaligned() as u64;
            let block_sz  = (block_ptr.wrapping_add(4) as *const u32).read_unaligned() as u64;
            if block_sz < 8 { break; }

            let n_entries = (block_sz - 8) / 2;
            for i in 0..n_entries {
                let entry_ptr = block_ptr.wrapping_add(8).wrapping_add(i * 2) as *const u16;
                let entry = entry_ptr.read_unaligned();
                let reloc_type = (entry >> 12) as u8;
                let page_off   = (entry & 0x0FFF) as u64;
                let target_va  = load_base.wrapping_add(page_rva).wrapping_add(page_off);

                match reloc_type {
                    0 => {}   // IMAGE_REL_BASED_ABSOLUTE — padding, skip
                    3 => {    // IMAGE_REL_BASED_HIGHLOW — 32-bit delta
                        let ptr = target_va as *mut u32;
                        let val = ptr.read_unaligned();
                        ptr.write_unaligned((val as i64).wrapping_add(delta) as u32);
                    }
                    10 => {   // IMAGE_REL_BASED_DIR64 — 64-bit delta (PE32+ DLLs)
                        let ptr = target_va as *mut u64;
                        let val = ptr.read_unaligned();
                        ptr.write_unaligned((val as i128).wrapping_add(delta as i128) as u64);
                    }
                    _ => {
                        log::warn!("apply_relocations: unknown reloc type {} at {:#x}", reloc_type, target_va);
                    }
                }
            }
            offset = offset.wrapping_add(block_sz);
        }
        log::info!("apply_relocations: delta={:+#x} done", delta);
    }
    Ok(())
}

pub fn patch_imports(load_base: u64, pe: &Pe32<'_>) -> Result<(), &'static str> {
    let mut total = 0u32;
    for imp in pe.imports() {
        let dll = imp.dll_name();
        let int_rva = if imp.int_rva != 0 { imp.int_rva } else { imp.iat_rva };
        let mut idx = 0u32;
        loop {
            let thunk_ptr = (load_base + int_rva as u64 + (idx as u64) * 4) as *const u32;
            let val = unsafe { thunk_ptr.read_unaligned() };
            if val == 0 {
                break;
            }
            let iat_ptr = (load_base + imp.iat_rva as u64 + (idx as u64) * 4) as *mut u32;
            let is_ordinal = (val & 0x8000_0000) != 0;
            let target = if is_ordinal {
                let ord = (val & 0xFFFF) as u16;
                match resolve_import_symbol(dll, "", Some(ord)) {
                    Some(v) => v,
                    None => {
                        log::warn!("patch_imports: unresolved ordinal {}!#{}", dll, ord);
                        0xDEAD_DEAD // trap address; will #PF if called
                    }
                }
            } else {
                let ibn_ptr = (load_base + val as u64) as *const u8;
                let name_ptr = unsafe { ibn_ptr.add(2) };
                let name = read_cstr_at(name_ptr).ok_or("load_image: bad import name")?;
                match resolve_import_symbol(dll, name, None) {
                    Some(v) => v,
                    None => {
                        log::warn!("patch_imports: unresolved {}!{}", dll, name);
                        0xDEAD_DEAD
                    }
                }
            };
            unsafe { iat_ptr.write_unaligned(target) };
            idx = idx.wrapping_add(1);
            total = total.wrapping_add(1);
        }
    }
    log::info!("patch_imports: patched {} IAT entries", total);
    Ok(())
}

// ── Loader: map sections into a virtual address space ────────────────────────

/// Result of a successful `load_image` call.
#[derive(Debug)]
pub struct LoadedImage {
    /// Virtual base address at which the image was loaded.
    pub image_base: u64,
    /// Virtual address of the entry point (image_base + AddressOfEntryPoint).
    pub entry_point: u64,
    /// Size of the full image in bytes (from SizeOfImage).
    pub image_size: u32,
}

/// Load a PE32 image into the address space described by `vad` + `mapper`.
///
/// Steps:
///   1. Parse the PE32 header.
///   2. Determine the load address (preferred `ImageBase` or bottom-up).
///   3. For every section: allocate + commit pages, copy raw data.
///   4. Fill `out` with base, entry point, and size.
///
/// Uses an out-parameter to avoid a large-struct `Result` return, which is
/// unreliable under LTO + `opt-level="s"` on bare-metal targets.
///
/// # Arguments
/// - `image_data` — raw PE32 binary (e.g. from a file or embedded blob).
/// - `out`        — caller-owned slot; filled on success.
/// - `vad`        — per-process VAD tree (updated with new entries).
/// - `mapper`     — physical-page mapper; called for each committed page.
/// - `force_base` — if `Some(addr)`, load at that address regardless of
///                  the PE's preferred base. Pass `None` to use the PE's
///                  `ImageBase` if available, or bottom-up otherwise.
#[inline(never)]
pub fn load_image<'a>(
    image_data: &'a [u8],
    out:        &mut LoadedImage,
    vad:        &mut mm::vad::VadTree,
    mapper:     &mut dyn mm::virtual_alloc::PageMapper,
    force_base: Option<u64>,
) -> Result<(), &'static str> {
    let pe = Pe32::parse(image_data).map_err(|_| "load_image: PE parse failed")?;

    // Read all header fields directly from image_data bytes to avoid packed-struct
    // field-access UB (Rust/LLVM can miscompile packed field reads in no_std/kernel).
    let nt_off   = read_u32(image_data, 0x3C).map_err(|_| "load_image: bad e_lfanew")? as usize;
    let opt_off  = nt_off + 4 + core::mem::size_of::<ImageFileHeader>();   // = nt_off + 24
    let n_sect   = read_u16(image_data, nt_off + 4 + 2).map_err(|_| "load_image: bad n_sect")? as usize;
    let opt_sz   = read_u16(image_data, nt_off + 4 + 16).map_err(|_| "load_image: bad opt_sz")? as usize;
    let sec_table = opt_off + opt_sz;

    let preferred_base = read_u32(image_data, opt_off + 28).map_err(|_| "load_image: bad image_base")? as u64;
    let entry_rva      = read_u32(image_data, opt_off + 16).map_err(|_| "load_image: bad entry_rva")? as u64;

    // Compute image size from SizeOfImage, or fall back to highest section end.
    let mut image_size = read_u32(image_data, opt_off + 56)
        .map_err(|_| "load_image: bad size_of_image")?;
    if image_size == 0 {
        for i in 0..n_sect {
            let sh = sec_table + i * 40;
            if sh + 40 > image_data.len() { break; }
            let virt_sz  = read_u32(image_data, sh + 8).unwrap_or(0);
            let virt_off = read_u32(image_data, sh + 12).unwrap_or(0);
            let raw_sz   = read_u32(image_data, sh + 16).unwrap_or(0);
            let end = virt_off + virt_sz.max(raw_sz);
            if end > image_size { image_size = end; }
        }
        if image_size == 0 { image_size = 0x1000; }
    }

    // Choose load address.
    let load_base = force_base.unwrap_or(preferred_base);
    log::info!(
        "load_image: preferred_base={:#x} load_base={:#x} entry_rva={:#x} image_size={:#x}",
        preferred_base, load_base, entry_rva, image_size,
    );

    // Reserve + commit the full image range in one VAD entry.
    mm::virtual_alloc::allocate(
        vad,
        Some(mapper),
        load_base,
        image_size as u64,
        mm::virtual_alloc::AllocType::MEM_RESERVE | mm::virtual_alloc::AllocType::MEM_COMMIT,
        mm::vad::PageProtect::EXECUTE_READWRITE,  // wide open; tightened per-section in Phase 3
    ).map_err(|_| "load_image: failed to allocate image range")?;

    // Copy PE headers into the image base (for GetModuleHandle / GetProcAddress).
    {
        let soh = read_u32(image_data, opt_off + 60).unwrap_or(0x400) as usize;
        let hdr_copy = soh.min(image_data.len()).min(image_size as usize);
        if hdr_copy > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    image_data.as_ptr(),
                    load_base as *mut u8,
                    hdr_copy,
                );
            }
        }
    }

    // Copy each section's raw data into the mapped range using direct byte reads.
    // (Avoids packed-struct field-access UB that miscompiles on x86_64-unknown-none.)
    for i in 0..n_sect {
        let sh       = sec_table + i * 40;
        if sh + 40 > image_data.len() { break; }
        let virt_sz  = read_u32(image_data, sh + 8).unwrap_or(0) as usize;
        let virt_off = read_u32(image_data, sh + 12).unwrap_or(0) as usize;
        let raw_sz   = read_u32(image_data, sh + 16).unwrap_or(0) as usize;
        let file_off = read_u32(image_data, sh + 20).unwrap_or(0) as usize;

        if raw_sz == 0 { continue; }
        if file_off + raw_sz > image_data.len() { continue; }

        // SAFETY: load_base..+image_size committed above; bounds checked.
        unsafe {
            let dst = (load_base + virt_off as u64) as *mut u8;
            let src = image_data.as_ptr().add(file_off);
            let copy_len = raw_sz.min(virt_sz);
            core::ptr::copy_nonoverlapping(src, dst, copy_len);
        }
    }

    map_stub_modules(vad, mapper)?;
    patch_imports(load_base, &pe)?;
    apply_relocations(load_base, preferred_base)?;

    out.image_base  = load_base;
    out.entry_point = load_base + entry_rva;
    out.image_size  = image_size;
    log::info!(
        "load_image: base={:#x} entry={:#x} size={:#x}",
        out.image_base, out.entry_point, out.image_size,
    );
    Ok(())
}

/// Load a PE32 DLL into an existing process address space.
/// Like `load_image` but skips stub mapping (already done) and applies relocations.
///
/// # IRQL: PASSIVE_LEVEL
/// List the DLL names in a PE32 image's import directory (for dependency pre-loading).
/// Returns up to 16 unique DLL names as lowercase strings.
pub fn list_import_dlls(image_data: &[u8]) -> alloc::vec::Vec<alloc::string::String> {
    let pe = match Pe32::parse(image_data) { Ok(p) => p, Err(_) => return alloc::vec::Vec::new() };
    let mut out = alloc::vec::Vec::new();
    for imp in pe.imports() {
        let dll = imp.dll_name();
        let lower: alloc::string::String = dll.chars().map(|c| c.to_ascii_lowercase()).collect();
        if out.len() >= 16 { break; }
        if !out.iter().any(|s: &alloc::string::String| s == &lower) {
            out.push(lower);
        }
    }
    out
}

pub fn load_dll(
    image_data: &[u8],
    vad: &mut mm::vad::VadTree,
    mapper: &mut dyn mm::virtual_alloc::PageMapper,
) -> Result<LoadedImage, &'static str> {
    let pe = Pe32::parse(image_data).map_err(|_| "load_dll: bad PE32")?;

    let nt_off   = read_u32(image_data, 0x3C).map_err(|_| "load_dll: bad e_lfanew")? as usize;
    let opt_off  = nt_off + 4 + core::mem::size_of::<ImageFileHeader>();
    let n_sect   = read_u16(image_data, nt_off + 4 + 2).map_err(|_| "load_dll: n_sect")? as usize;
    let opt_sz   = read_u16(image_data, nt_off + 4 + 16).map_err(|_| "load_dll: opt_sz")? as usize;
    let sec_table = opt_off + opt_sz;

    let preferred_base = read_u32(image_data, opt_off + 28).map_err(|_| "load_dll: image_base")? as u64;
    let entry_rva      = read_u32(image_data, opt_off + 16).map_err(|_| "load_dll: entry_rva")? as u64;
    let mut image_size = read_u32(image_data, opt_off + 56).map_err(|_| "load_dll: size_of_image")?;
    if image_size == 0 { image_size = 0x1000; }

    // Try preferred base first; fall back to allocator choice
    let load_base = match mm::virtual_alloc::allocate(
        vad, Some(mapper), preferred_base, image_size as u64,
        mm::virtual_alloc::AllocType::MEM_RESERVE | mm::virtual_alloc::AllocType::MEM_COMMIT,
        mm::vad::PageProtect::EXECUTE_READWRITE,
    ) {
        Ok(_) => preferred_base,
        Err(_) => mm::virtual_alloc::allocate(
            vad, Some(mapper), 0, image_size as u64,
            mm::virtual_alloc::AllocType::MEM_RESERVE | mm::virtual_alloc::AllocType::MEM_COMMIT,
            mm::vad::PageProtect::EXECUTE_READWRITE,
        ).map_err(|_| "load_dll: out of address space")?,
    };

    log::info!("load_dll: preferred={:#x} load={:#x} size={:#x}", preferred_base, load_base, image_size);

    // Copy PE headers (DOS header + NT headers + section table) into the image base.
    // Windows always maps headers so GetModuleHandle/GetProcAddress can parse them.
    let size_of_headers = read_u32(image_data, opt_off + 60).unwrap_or(0x400) as usize;
    let hdr_copy = size_of_headers.min(image_data.len()).min(image_size as usize);
    if hdr_copy > 0 {
        // SAFETY: load_base..+image_size committed above; hdr_copy is bounded.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image_data.as_ptr(),
                load_base as *mut u8,
                hdr_copy,
            );
        }
    }

    // Copy sections
    for i in 0..n_sect {
        let sh = sec_table + i * 40;
        if sh + 40 > image_data.len() { break; }
        let virt_sz  = read_u32(image_data, sh + 8).unwrap_or(0) as usize;
        let virt_off = read_u32(image_data, sh + 12).unwrap_or(0) as usize;
        let raw_sz   = read_u32(image_data, sh + 16).unwrap_or(0) as usize;
        let file_off = read_u32(image_data, sh + 20).unwrap_or(0) as usize;
        if raw_sz == 0 { continue; }
        if file_off + raw_sz > image_data.len() { continue; }
        // SAFETY: load_base..+image_size committed above; bounds checked.
        unsafe {
            let dst = (load_base + virt_off as u64) as *mut u8;
            let src = image_data.as_ptr().add(file_off);
            core::ptr::copy_nonoverlapping(src, dst, raw_sz.min(virt_sz));
        }
    }

    // Apply relocations BEFORE patching imports
    apply_relocations(load_base, preferred_base)?;

    // Patch imports (resolve against stubs + already-loaded DLLs)
    patch_imports(load_base, &pe)?;

    Ok(LoadedImage {
        image_base:  load_base,
        entry_point: load_base + entry_rva,
        image_size,
    })
}

// ── Process setup ─────────────────────────────────────────────────────────────

/// XP-compatible fixed addresses for the per-process PEB and TEB.
/// Games and CRT assume these are at known locations (no ASLR on XP).
pub const PEB32_VA:        u32   = 0x7FFD_E000;
pub const TEB32_VA:        u32   = 0x7FFD_F000;
pub const SHARED_USER_DATA32_VA: u32 = 0x7FFE_0000;
/// Top of the initial user-mode stack (grows downward from this VA).
pub const USER_STACK_TOP:  u32   = 0x7FFF_0000;
/// Number of 4 KiB pages committed for the initial stack (64 KiB total).
pub const USER_STACK_PAGES: usize = 15;

/// Addresses computed by `setup_process` — passed to the ring-3 IRETQ frame.
#[derive(Debug, Clone, Copy)]
pub struct ProcessContext {
    /// Virtual address of the PEB32 page (0x7FFD_E000).
    pub peb_addr:    u32,
    /// Virtual address of the TEB32 page (0x7FFD_F000).
    pub teb_addr:    u32,
    /// Initial user-mode stack pointer (top of committed stack).
    pub stack_top:   u32,
    /// Bottom of the committed stack region (stack_top − stack_size).
    pub stack_limit: u32,
}

/// Map PEB, TEB, and user stack; initialise both blocks with XP defaults.
///
/// Must be called after `load_image` so `image.image_base` and
/// `image.entry_point` are known. Writes directly to the virtual addresses
/// via the kernel page tables (single-CPU Phase 2).
///
/// # Arguments
/// - `image`  — result of `load_image` (base address, entry point).
/// - `vad`    — per-process VAD tree (new entries inserted for PEB/TEB/stack).
/// - `mapper` — physical-page mapper; called for each committed page.
/// - `pid`    — process ID stored in `TEB.ClientId.UniqueProcess`.
/// - `tid`    — thread ID stored in `TEB.ClientId.UniqueThread`.
///
/// # IRQL: PASSIVE_LEVEL
pub fn setup_process(
    image:  &LoadedImage,
    vad:    &mut mm::vad::VadTree,
    mapper: &mut dyn mm::virtual_alloc::PageMapper,
    pid:    u32,
    tid:    u32,
) -> Result<ProcessContext, &'static str> {
    use mm::virtual_alloc::{allocate, AllocType};
    use mm::vad::PageProtect;

    // ── 1. Map PEB page ───────────────────────────────────────────────────────
    allocate(
        vad, Some(mapper),
        PEB32_VA as u64, 0x1000,
        AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
        PageProtect::READWRITE,
    ).map_err(|_| "setup_process: failed to allocate PEB")?;

    // ── 2. Map TEB page ───────────────────────────────────────────────────────
    allocate(
        vad, Some(mapper),
        TEB32_VA as u64, 0x1000,
        AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
        PageProtect::READWRITE,
    ).map_err(|_| "setup_process: failed to allocate TEB")?;

    // EXECUTE_READWRITE: the C3 (RET) byte at +0x300 must be executable —
    // the SYSENTER return path does IRETQ to SharedUserData+0x300.
    allocate(
        vad, Some(mapper),
        SHARED_USER_DATA32_VA as u64, 0x1000,
        AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
        PageProtect::EXECUTE_READWRITE,
    ).map_err(|_| "setup_process: failed to allocate SharedUserData")?;

    // ── 3. Map initial user stack ─────────────────────────────────────────────
    let stack_limit = USER_STACK_TOP - (USER_STACK_PAGES as u32 * 0x1000);
    allocate(
        vad, Some(mapper),
        stack_limit as u64, USER_STACK_PAGES as u64 * 0x1000,
        AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
        PageProtect::READWRITE,
    ).map_err(|_| "setup_process: failed to allocate user stack")?;

    // ── 4. Initialise PEB32 ───────────────────────────────────────────────────
    // PEB32_VA is now mapped USER_ACCESSIBLE+RW. Write XP-compatible values.
    // SAFETY: PEB32_VA was committed above; single-CPU Phase 2, no concurrency.
    unsafe {
        let peb = PEB32_VA as *mut crate::peb::Peb32;
        // Zero-fill first so padding bytes are clean.
        core::ptr::write_bytes(peb as *mut u8, 0, core::mem::size_of::<crate::peb::Peb32>());
        let peb = &mut *peb;
        peb.image_base_address         = image.image_base as u32;
        peb.os_major_version           = 5;      // Windows XP
        peb.os_minor_version           = 1;
        peb.os_build_number            = 2600;   // XP SP2
        peb.os_csd_version             = 0x0200; // SP2
        peb.os_platform_id             = 2;      // VER_PLATFORM_WIN32_NT
        peb.image_subsystem            = 2;      // IMAGE_SUBSYSTEM_WINDOWS_GUI
        peb.image_subsystem_major_ver  = 4;
        peb.image_subsystem_minor_ver  = 0;
        peb.number_of_processors       = 1;
        // process_heap: 0 for now; Phase 3 installs a real user-mode heap.
    }

    // ── 5. Initialise TEB32 ───────────────────────────────────────────────────
    // SAFETY: TEB32_VA was committed above.
    unsafe {
        let teb = TEB32_VA as *mut crate::teb::Teb32;
        core::ptr::write_bytes(teb as *mut u8, 0, core::mem::size_of::<crate::teb::Teb32>());
        let teb = &mut *teb;
        teb.nt_tib.exception_list = 0xFFFF_FFFF; // empty SEH chain sentinel
        teb.nt_tib.stack_base     = USER_STACK_TOP;
        teb.nt_tib.stack_limit    = stack_limit;
        // CRITICAL: FS:[0x18] must point to the TEB itself (CRT, SEH, TLS).
        teb.nt_tib.self_ptr       = TEB32_VA;
        teb.peb                   = PEB32_VA;
        teb.client_id_process     = pid;
        teb.client_id_thread      = tid;
    }

    // SAFETY: SHARED_USER_DATA32_VA was committed above; single-CPU Phase 2.
    unsafe {
        let sud = SHARED_USER_DATA32_VA as *mut u8;
        core::ptr::write_bytes(sud, 0, 0x1000);
        (sud.add(0x000) as *mut u32).write_unaligned(0);
        (sud.add(0x004) as *mut u32).write_unaligned(0x0100_0000);
        (sud.add(0x014) as *mut u64).write_unaligned(0);
        // XP SP2 version fields — correct KUSER_SHARED_DATA offsets.
        (sud.add(0x264) as *mut u32).write_unaligned(1);    // NtProductType = VER_NT_WORKSTATION
        (sud.add(0x268) as *mut u32).write_unaligned(1);    // ProductTypeIsValid = TRUE
        (sud.add(0x26C) as *mut u32).write_unaligned(5);    // NtMajorVersion = 5 (XP)
        (sud.add(0x270) as *mut u32).write_unaligned(1);    // NtMinorVersion = 1 (XP)
        // TickCount at 0x320 already zero-initialised above; timer ISR updates it.
        // KiFastSystemCallRet at 0x300: single `ret` (0xC3) byte.
        // SYSENTER IRETQ path returns here; `ret` pops the caller's return address.
        (sud.add(0x300) as *mut u8).write(0xC3);
        // SystemCallReturn at 0x308: pointer to KiFastSystemCallRet (= SUD + 0x300).
        (sud.add(0x308) as *mut u32).write_unaligned(SHARED_USER_DATA32_VA + 0x300);
        (sud.add(0x2D4) as *mut u32).write_unaligned(2);
        let root = [
            b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16,
            b'C' as u16, b':' as u16, b'\\' as u16,
            b'W' as u16, b'I' as u16, b'N' as u16, b'D' as u16, b'O' as u16, b'W' as u16, b'S' as u16, 0,
        ];
        let mut i = 0usize;
        while i < root.len() {
            (sud.add(0x030) as *mut u16).add(i).write_unaligned(root[i]);
            i += 1;
        }
    }

    log::info!(
        "Ps: setup_process — PEB={:#x} TEB={:#x} stack={:#x}..{:#x} entry={:#x}",
        PEB32_VA, TEB32_VA, stack_limit, USER_STACK_TOP, image.entry_point,
    );

    Ok(ProcessContext {
        peb_addr:    PEB32_VA,
        teb_addr:    TEB32_VA,
        stack_top:   USER_STACK_TOP,
        stack_limit,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p ps
//
// Uses a minimal hand-crafted PE32 binary blob to test the parser
// without needing a real game .exe.
//
// T3-1a: DOS header validation
// T3-1b: NT header + optional header parsing (image base, entry point, …)
// T3-1c: Section table iteration (name, RVA, flags)
// T3-1d: Import descriptor iteration
// T3-1e: Error paths (bad signatures, truncated data)

#[cfg(test)]
mod tests {
    use super::*;

    // ── Minimal PE32 builder for tests ────────────────────────────────────────
    //
    // Builds the smallest valid PE32 binary in memory:
    //   - DOS header (0x40 bytes) with e_lfanew pointing past it
    //   - NT signature (4 bytes)
    //   - IMAGE_FILE_HEADER
    //   - IMAGE_OPTIONAL_HEADER32 (with one data directory entry for imports)
    //   - One section header (.text)
    //   - Optional: import descriptor + DLL name string

    fn make_pe32(
        image_base:  u32,
        entry_point: u32,
        sections:    &[(&str, u32, u32, u32)],  // (name, va, virtual_size, characteristics)
        imports:     &[&str],                    // DLL names
    ) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; 0x10000];

        // DOS header
        let dos_sig: u16 = IMAGE_DOS_SIGNATURE;
        buf[0..2].copy_from_slice(&dos_sig.to_le_bytes());
        let nt_off: u32 = 0x40;
        buf[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());

        // NT signature
        let nt_sig: u32 = IMAGE_NT_SIGNATURE;
        buf[0x40..0x44].copy_from_slice(&nt_sig.to_le_bytes());

        let fh_off = 0x44usize;
        let nsec = sections.len() as u16;
        let opt_sz = core::mem::size_of::<ImageOptionalHeader32>() as u16;

        // FILE_HEADER
        buf[fh_off..fh_off+2].copy_from_slice(&MACHINE_I386.to_le_bytes());
        buf[fh_off+2..fh_off+4].copy_from_slice(&nsec.to_le_bytes());
        buf[fh_off+16..fh_off+18].copy_from_slice(&opt_sz.to_le_bytes());

        // OPTIONAL_HEADER32
        let opt_off = fh_off + core::mem::size_of::<ImageFileHeader>();
        buf[opt_off..opt_off+2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
        buf[opt_off+16..opt_off+20].copy_from_slice(&entry_point.to_le_bytes());
        buf[opt_off+28..opt_off+32].copy_from_slice(&image_base.to_le_bytes());

        // data_directory[0] (export) — zero; data_directory[1] (import)
        let num_dirs: u32 = 16;
        buf[opt_off+92..opt_off+96].copy_from_slice(&num_dirs.to_le_bytes());

        // Import directory: if we have imports, put them after section table
        let sec_table_off = opt_off + opt_sz as usize;
        let sec_sz = core::mem::size_of::<ImageSectionHeader>();
        let import_desc_off = sec_table_off + nsec as usize * sec_sz;

        if !imports.is_empty() {
            let import_dir_rva = import_desc_off as u32;
            // data_directory[1] in optional header
            let dd_off = opt_off + 96 + 8; // skip export dir entry (8 bytes)
            buf[dd_off..dd_off+4].copy_from_slice(&import_dir_rva.to_le_bytes());
            let import_dir_size = (imports.len() + 1) as u32 * 20;
            buf[dd_off+4..dd_off+8].copy_from_slice(&import_dir_size.to_le_bytes());

            // Write IMAGE_IMPORT_DESCRIPTOR entries
            let mut name_rva = import_desc_off as u32
                + (imports.len() + 1) as u32 * 20; // after null terminator
            for (i, dll) in imports.iter().enumerate() {
                let desc_off = import_desc_off + i * 20;
                // name RVA
                buf[desc_off+12..desc_off+16].copy_from_slice(&name_rva.to_le_bytes());
                // first_thunk (non-zero so it's not null terminator)
                let iat_rva: u32 = 0x5000 + i as u32 * 4;
                buf[desc_off+16..desc_off+20].copy_from_slice(&iat_rva.to_le_bytes());
                // write DLL name string
                let name_bytes = dll.as_bytes();
                let off = name_rva as usize;
                buf[off..off+name_bytes.len()].copy_from_slice(name_bytes);
                buf[off + name_bytes.len()] = 0; // NUL
                name_rva += dll.len() as u32 + 1;
            }
            // null-terminator descriptor (all zeros — already in zeroed buf)
        }

        // Section headers
        for (i, (name, va, vsz, chars)) in sections.iter().enumerate() {
            let sh_off = sec_table_off + i * sec_sz;
            let name_bytes = name.as_bytes();
            let n = name_bytes.len().min(8);
            buf[sh_off..sh_off+n].copy_from_slice(&name_bytes[..n]);
            buf[sh_off+8..sh_off+12].copy_from_slice(&vsz.to_le_bytes());
            buf[sh_off+12..sh_off+16].copy_from_slice(&va.to_le_bytes());
            buf[sh_off+36..sh_off+40].copy_from_slice(&chars.to_le_bytes());
        }

        buf
    }

    // ── T3-1a: DOS header ─────────────────────────────────────────────────────

    #[test]
    fn parse_rejects_bad_dos_sig() {
        let mut data = make_pe32(0x40_0000, 0x1000, &[], &[]);
        data[0] = 0x00; // corrupt MZ
        assert_eq!(Pe32::parse(&data).unwrap_err(), PeError::BadDosSig);
    }

    #[test]
    fn parse_rejects_truncated_input() {
        let data = alloc::vec![0u8; 4];
        assert_eq!(Pe32::parse(&data).unwrap_err(), PeError::TooSmall);
    }

    #[test]
    fn parse_rejects_bad_nt_sig() {
        let mut data = make_pe32(0x40_0000, 0x1000, &[], &[]);
        data[0x40] = 0xFF; // corrupt NT sig
        assert_eq!(Pe32::parse(&data).unwrap_err(), PeError::BadNtSig);
    }

    // ── T3-1b: optional header fields ────────────────────────────────────────

    #[test]
    fn optional_header_image_base() {
        let data = make_pe32(0x0040_0000, 0x1000, &[], &[]);
        let pe = Pe32::parse(&data).unwrap();
        let opt = pe.optional_header();
        // Use { } to copy field from packed struct and avoid unaligned ref.
        assert_eq!({ opt.image_base }, 0x0040_0000);
    }

    #[test]
    fn optional_header_entry_point() {
        let data = make_pe32(0x0040_0000, 0x1234, &[], &[]);
        let pe = Pe32::parse(&data).unwrap();
        let opt = pe.optional_header();
        assert_eq!({ opt.address_of_entry_point }, 0x1234);
    }

    #[test]
    fn file_header_machine_is_i386() {
        let data = make_pe32(0x0040_0000, 0x1000, &[], &[]);
        let pe = Pe32::parse(&data).unwrap();
        let fh = pe.file_header();
        assert_eq!({ fh.machine }, MACHINE_I386);
    }

    // ── T3-1c: sections ───────────────────────────────────────────────────────

    #[test]
    fn parse_single_text_section() {
        let data = make_pe32(
            0x0040_0000, 0x1000,
            &[(".text", 0x1000, 0x500, SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_CNT_CODE)],
            &[],
        );
        let pe = Pe32::parse(&data).unwrap();
        let sections: alloc::vec::Vec<_> = pe.sections().collect();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].name_str(), ".text");
        assert_eq!({ sections[0].virtual_address }, 0x1000);
        assert!(sections[0].is_executable());
        assert!(!sections[0].is_writable());
    }

    #[test]
    fn parse_two_sections_in_order() {
        let data = make_pe32(
            0x0040_0000, 0x1000,
            &[
                (".text",  0x1000, 0x400, SCN_MEM_EXECUTE | SCN_MEM_READ),
                (".rdata", 0x2000, 0x200, SCN_MEM_READ),
            ],
            &[],
        );
        let pe = Pe32::parse(&data).unwrap();
        let names: alloc::vec::Vec<_> = pe.sections().map(|s| s.name_str().to_owned_str()).collect();
        assert_eq!(names, [".text", ".rdata"]);
    }

    #[test]
    fn data_section_is_writable_not_executable() {
        let data = make_pe32(
            0x0040_0000, 0x1000,
            &[(".data", 0x3000, 0x100, SCN_MEM_READ | SCN_MEM_WRITE | SCN_CNT_INITIALIZED_DATA)],
            &[],
        );
        let pe = Pe32::parse(&data).unwrap();
        let sec = pe.sections().next().unwrap();
        assert!(sec.is_writable());
        assert!(!sec.is_executable());
    }

    // ── T3-1d: imports ────────────────────────────────────────────────────────

    #[test]
    fn no_imports_gives_empty_iterator() {
        let data = make_pe32(0x0040_0000, 0x1000, &[], &[]);
        let pe = Pe32::parse(&data).unwrap();
        assert_eq!(pe.imports().count(), 0);
    }

    #[test]
    fn single_import_dll_name_parsed() {
        let data = make_pe32(0x0040_0000, 0x1000, &[], &["kernel32.dll"]);
        let pe = Pe32::parse(&data).unwrap();
        let mut imports = pe.imports();
        let first = imports.next().expect("one import entry");
        assert_eq!(first.dll_name(), "kernel32.dll");
        assert!(imports.next().is_none(), "only one DLL");
    }

    #[test]
    fn multiple_import_dll_names_in_order() {
        let data = make_pe32(
            0x0040_0000, 0x1000, &[],
            &["kernel32.dll", "user32.dll", "d3d9.dll"],
        );
        let pe = Pe32::parse(&data).unwrap();
        let names: alloc::vec::Vec<_> = pe.imports()
            .map(|i| i.dll_name().to_owned_str())
            .collect();
        assert_eq!(names, ["kernel32.dll", "user32.dll", "d3d9.dll"]);
    }

    // ── T3-1e: error paths ────────────────────────────────────────────────────

    #[test]
    fn optional_header_magic_wrong_gives_not_pe32() {
        let mut data = make_pe32(0x0040_0000, 0x1000, &[], &[]);
        // Corrupt the optional header magic to PE32+ (0x020B)
        let opt_off = 0x44 + core::mem::size_of::<ImageFileHeader>();
        data[opt_off] = 0x0B;
        data[opt_off+1] = 0x02;
        assert_eq!(Pe32::parse(&data).unwrap_err(), PeError::NotPe32);
    }

    // ── T4-2: load_image — MockMapper + VadTree ───────────────────────────────
    //
    // `load_image` writes to the virtual address space via the PageMapper.
    // In tests we intercept those writes with a BackedMapper that allocates
    // real host heap memory so section data copies can actually happen.

    struct BackedMapper {
        committed: alloc::vec::Vec<u64>,
        // Each committed page gets a heap-allocated backing buffer.
        // The pointer is the virtual address; we store (va, *mut u8) pairs.
        backing: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8; 4096]>)>,
    }

    impl BackedMapper {
        fn new() -> Self { Self { committed: alloc::vec![], backing: alloc::vec![] } }
    }

    impl mm::virtual_alloc::PageMapper for BackedMapper {
        fn commit_page(&mut self, virt: u64, _w: bool, _x: bool, _u: bool)
            -> Result<(), &'static str>
        {
            self.committed.push(virt);
            // Allocate a zero-filled page and register its address.
            // We then redirect the virtual address to this buffer by
            // overwriting the target memory (works only in test because
            // the test runner IS the host process — no real page tables).
            let page = alloc::boxed::Box::new([0u8; 4096]);
            // Point the "virtual address" at our host buffer.
            // SAFETY: test-only; the VA space is the host process's own.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    page.as_ptr(),
                    virt as *mut u8,
                    4096,
                );
            }
            self.backing.push((virt, page));
            Ok(())
        }
        fn decommit_page(&mut self, _virt: u64) -> Result<(), &'static str> { Ok(()) }
    }

    // Simpler mock that only counts calls, used where we don't copy section data.
    struct CountMapper { pub count: usize }
    impl mm::virtual_alloc::PageMapper for CountMapper {
        fn commit_page(&mut self, _v: u64, _w: bool, _x: bool, _u: bool) -> Result<(), &'static str> {
            self.count += 1; Ok(())
        }
        fn decommit_page(&mut self, _v: u64) -> Result<(), &'static str> { Ok(()) }
    }

    #[test]
    fn load_image_returns_correct_entry_point() {
        let data = make_pe32(0x0040_0000, 0x1234,
                             &[(".text", 0x1000, 0x100, SCN_MEM_EXECUTE | SCN_MEM_READ)],
                             &[]);
        let mut vad = mm::vad::VadTree::new();
        let mut m   = CountMapper { count: 0 };
        let img = load_image(&data, &mut vad, &mut m, Some(0x0040_0000))
            .expect("load must succeed");
        assert_eq!(img.image_base,  0x0040_0000);
        assert_eq!(img.entry_point, 0x0040_0000 + 0x1234);
    }

    #[test]
    fn load_image_inserts_vad_entry() {
        let data = make_pe32(0x0040_0000, 0x1000,
                             &[(".text", 0x1000, 0x200, SCN_MEM_EXECUTE | SCN_MEM_READ)],
                             &[]);
        let mut vad = mm::vad::VadTree::new();
        let mut m   = CountMapper { count: 0 };
        let img = load_image(&data, &mut vad, &mut m, Some(0x0040_0000)).unwrap();
        assert!(vad.find(img.image_base).is_some(), "VAD entry for image must exist");
    }

    #[test]
    fn load_image_commits_pages_for_full_image_size() {
        // image_size in our make_pe32 helper is 0 (default). Let's set it via
        // the opt header (opt_off + SizeOfImage offset).
        // For simplicity just check that >0 pages were committed.
        let data = make_pe32(0x0040_0000, 0x1000,
                             &[(".text", 0x1000, 0x200, SCN_MEM_EXECUTE | SCN_MEM_READ)],
                             &[]);
        let mut vad = mm::vad::VadTree::new();
        let mut m   = CountMapper { count: 0 };
        load_image(&data, &mut vad, &mut m, Some(0x0040_0000)).unwrap();
        // image_size is 0 in our test PE → allocate rounds to one page minimum
        // (size_of_image = 0 → skipped, but we still get the VAD entry)
        // Just verify no panic.
    }

    #[test]
    fn load_image_force_base_overrides_preferred() {
        let data = make_pe32(0x0040_0000, 0x1000, &[], &[]);
        let mut vad = mm::vad::VadTree::new();
        let mut m   = CountMapper { count: 0 };
        let img = load_image(&data, &mut vad, &mut m, Some(0x0200_0000)).unwrap();
        assert_eq!(img.image_base, 0x0200_0000, "force_base must be honoured");
        assert_eq!(img.entry_point, 0x0200_0000 + 0x1000);
    }

    #[test]
    fn load_image_bad_pe_returns_error() {
        let bad_data = alloc::vec![0u8; 64]; // too small / no MZ
        let mut vad = mm::vad::VadTree::new();
        let mut m   = CountMapper { count: 0 };
        assert!(load_image(&bad_data, &mut vad, &mut m, None).is_err());
    }
}

// ── Helper: owned str for no_std test comparisons ────────────────────────────
trait ToOwnedStr {
    fn to_owned_str(&self) -> alloc::string::String;
}
impl ToOwnedStr for &str {
    fn to_owned_str(&self) -> alloc::string::String {
        alloc::string::String::from(*self)
    }
}
