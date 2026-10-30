//! PE32 parser (02 §10, `libs/pe`): no_std and without allocation, for the
//! host and the kernel.
//!
//! Parses a PE32 image (32-bit, `IMAGE_NT_OPTIONAL_HDR32_MAGIC`, i386) from the
//! bytes of its file and borrows everything from them: headers, section table,
//! import descriptors. PE32+ is not needed by an XP-compatible i386 userland.
//!
//! Moved from `ps::loader` (audit §6, step 4), which re-exports it for the old
//! loader. Image sections (`mm::section`) use it.
//!
//! # References
//! - Microsoft PE/COFF specification (public format documentation)
//! - ReactOS ntdll/ldr/ldrutils.c
//! - WI7e Ch.6 §Image Loader

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "builder")]
extern crate alloc;

#[cfg(feature = "builder")]
pub mod builder;

// ── Compile-time PE32 constants ──────────────────────────────────────────────

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;

/// IMAGE_FILE_MACHINE_I386
pub const MACHINE_I386: u16 = 0x014C;

/// IMAGE_FILE_RELOCS_STRIPPED: the image cannot leave its preferred base.
pub const FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// IMAGE_FILE_EXECUTABLE_IMAGE
pub const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// IMAGE_FILE_32BIT_MACHINE
pub const FILE_32BIT_MACHINE: u16 = 0x0100;

/// Section characteristic flags (matches IMAGE_SCN_* in winnt.h)
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

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
    pub e_magic: u16, // 0x00  "MZ"
    _reserved: [u8; 0x3A],
    pub e_lfanew: u32, // 0x3C  offset to IMAGE_NT_HEADERS
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader32 {
    pub magic: u16, // IMAGE_NT_OPTIONAL_HDR32_MAGIC
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32, // RVA
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32, // RVA
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32, // RVA
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32, // file offset
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
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
    pub original_first_thunk: u32, // RVA to INT (Import Name Table)
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,        // RVA to DLL name string
    pub first_thunk: u32, // RVA to IAT (Import Address Table)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// A parsed view of a PE32 image.
///
/// All data is borrowed from the backing byte slice — no allocations.
#[derive(Debug)]
pub struct Pe32<'a> {
    data: &'a [u8],
    nt_off: usize, // offset of IMAGE_NT_HEADERS in data
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

    fn file_header_offset(&self) -> usize {
        self.nt_off + 4
    }
    fn opt_header_offset(&self) -> usize {
        self.nt_off + 4 + core::mem::size_of::<ImageFileHeader>()
    }
    fn section_table_offset(&self) -> usize {
        // Read size_of_optional_header directly to avoid packed-struct field-access UB.
        let opt_sz = read_u16(self.data, self.file_header_offset() + 16).unwrap_or(0) as usize;
        self.opt_header_offset() + opt_sz
    }

    pub fn file_header(&self) -> ImageFileHeader {
        read_struct::<ImageFileHeader>(self.data, self.file_header_offset()).expect("file_header: already validated")
    }

    pub fn optional_header(&self) -> ImageOptionalHeader32 {
        read_struct::<ImageOptionalHeader32>(self.data, self.opt_header_offset())
            .expect("opt_header: already validated")
    }

    /// Iterator over section headers.
    pub fn sections(&self) -> impl Iterator<Item = ImageSectionHeader> + '_ {
        // Read number_of_sections directly from image bytes to avoid packed-struct UB.
        let n = read_u16(self.data, self.file_header_offset() + 2).unwrap_or(0) as usize;
        let base = self.section_table_offset();
        let sz = core::mem::size_of::<ImageSectionHeader>();
        (0..n).filter_map(move |i| read_struct::<ImageSectionHeader>(self.data, base + i * sz).ok())
    }

    /// Iterator over import descriptors (stops at the null terminator).
    pub fn imports(&self) -> impl Iterator<Item = ImportEntry<'_>> + '_ {
        let opt = self.optional_header();
        // Directory entry 1 = import table
        let dir = if opt.number_of_rva_and_sizes > 1 { opt.data_directory[1] } else { ImageDataDirectory::default() };

        let rva = dir.virtual_address;
        let data = self.data;
        let base = self.nt_off; // unused; rva is absolute from image base
        let _ = base;

        ImportIter { data, rva, index: 0 }
    }
}

/// A single import descriptor (one DLL worth of imports).
pub struct ImportEntry<'a> {
    pub dll_name_rva: u32,
    pub int_rva: u32, // Import Name Table RVA
    pub iat_rva: u32, // Import Address Table RVA
    data: &'a [u8],
}

impl<'a> ImportEntry<'a> {
    /// Name of the imported DLL (NUL-terminated ASCII at RVA).
    pub fn dll_name(&self) -> &str {
        rva_to_str(self.data, self.dll_name_rva).unwrap_or("?")
    }
}

struct ImportIter<'a> {
    data: &'a [u8],
    rva: u32, // RVA of the first IMAGE_IMPORT_DESCRIPTOR
    index: usize,
}

impl<'a> Iterator for ImportIter<'a> {
    type Item = ImportEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rva == 0 {
            return None;
        }
        let base_off = rva_to_file_offset(self.data, self.rva)?;
        let off = base_off + self.index * core::mem::size_of::<ImageImportDescriptor>();
        let desc = read_struct::<ImageImportDescriptor>(self.data, off).ok()?;
        // The list ends at the first descriptor without a name or an IAT, as
        // in the ReactOS and Wine loaders. This covers the all-zero terminator
        // and a terminator overlapped by the next table.
        if desc.name == 0 || desc.first_thunk == 0 {
            return None;
        }
        self.index += 1;
        Some(ImportEntry {
            dll_name_rva: desc.name,
            int_rva: desc.original_first_thunk,
            iat_rva: desc.first_thunk,
            data: self.data,
        })
    }
}

// ── Read helpers ──────────────────────────────────────────────────────────────

/// Convert an RVA to a file (raw-data) offset by walking the section table.
/// Falls back to `rva as usize` for the PE header range (RVA < first section VA).
fn rva_to_file_offset(data: &[u8], rva: u32) -> Option<usize> {
    // Parse e_lfanew to locate the section table.
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data.get(0x3C..0x40)?.try_into().ok()?) as usize;
    // FileHeader at e_lfanew+4; n_sections at +2, size_of_optional_header at +16.
    if e_lfanew + 4 + 20 > data.len() {
        return None;
    }
    let n_sec = u16::from_le_bytes(data.get(e_lfanew + 4 + 2..e_lfanew + 4 + 4)?.try_into().ok()?) as usize;
    let opt_sz = u16::from_le_bytes(data.get(e_lfanew + 4 + 16..e_lfanew + 4 + 18)?.try_into().ok()?) as usize;
    let sec_table = e_lfanew + 4 + 20 + opt_sz;
    // Each IMAGE_SECTION_HEADER is 40 bytes.
    for i in 0..n_sec {
        let sh = sec_table + i * 40;
        if sh + 40 > data.len() {
            break;
        }
        let vsz = u32::from_le_bytes(data[sh + 8..sh + 12].try_into().ok()?) as usize;
        let va = u32::from_le_bytes(data[sh + 12..sh + 16].try_into().ok()?) as usize;
        let raw_sz = u32::from_le_bytes(data[sh + 16..sh + 20].try_into().ok()?) as usize;
        let raw_off = u32::from_le_bytes(data[sh + 20..sh + 24].try_into().ok()?) as usize;
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
    if off + sz > data.len() {
        return Err(PeError::OffsetOutOfRange);
    }
    // SAFETY: bounds checked above; T is repr(C, packed) — any bit pattern valid.
    Ok(unsafe { core::ptr::read_unaligned(data.as_ptr().add(off) as *const T) })
}

/// The little-endian `u32` at `off` in `data`.
pub fn read_u32(data: &[u8], off: usize) -> Result<u32, PeError> {
    if off + 4 > data.len() {
        return Err(PeError::OffsetOutOfRange);
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

/// The little-endian `u16` at `off` in `data`.
pub fn read_u16(data: &[u8], off: usize) -> Result<u16, PeError> {
    if off + 2 > data.len() {
        return Err(PeError::OffsetOutOfRange);
    }
    Ok(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

/// Read a NUL-terminated ASCII string from a PE RVA (file offset resolved via section table).
fn rva_to_str(data: &[u8], rva: u32) -> Option<&str> {
    let off = rva_to_file_offset(data, rva)?;
    if off >= data.len() {
        return None;
    }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(0);
    core::str::from_utf8(&data[off..off + end]).ok()
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p pe
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
    extern crate alloc;

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
        image_base: u32,
        entry_point: u32,
        sections: &[(&str, u32, u32, u32)], // (name, va, virtual_size, characteristics)
        imports: &[&str],                   // DLL names
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
        buf[fh_off..fh_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
        buf[fh_off + 2..fh_off + 4].copy_from_slice(&nsec.to_le_bytes());
        buf[fh_off + 16..fh_off + 18].copy_from_slice(&opt_sz.to_le_bytes());

        // OPTIONAL_HEADER32
        let opt_off = fh_off + core::mem::size_of::<ImageFileHeader>();
        buf[opt_off..opt_off + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_point.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());

        // data_directory[0] (export) — zero; data_directory[1] (import)
        let num_dirs: u32 = 16;
        buf[opt_off + 92..opt_off + 96].copy_from_slice(&num_dirs.to_le_bytes());

        // Import directory: if we have imports, put them after section table
        let sec_table_off = opt_off + opt_sz as usize;
        let sec_sz = core::mem::size_of::<ImageSectionHeader>();
        let import_desc_off = sec_table_off + nsec as usize * sec_sz;

        if !imports.is_empty() {
            let import_dir_rva = import_desc_off as u32;
            // data_directory[1] in optional header
            let dd_off = opt_off + 96 + 8; // skip export dir entry (8 bytes)
            buf[dd_off..dd_off + 4].copy_from_slice(&import_dir_rva.to_le_bytes());
            let import_dir_size = (imports.len() + 1) as u32 * 20;
            buf[dd_off + 4..dd_off + 8].copy_from_slice(&import_dir_size.to_le_bytes());

            // Write IMAGE_IMPORT_DESCRIPTOR entries
            let mut name_rva = import_desc_off as u32 + (imports.len() + 1) as u32 * 20; // after null terminator
            for (i, dll) in imports.iter().enumerate() {
                let desc_off = import_desc_off + i * 20;
                // name RVA
                buf[desc_off + 12..desc_off + 16].copy_from_slice(&name_rva.to_le_bytes());
                // first_thunk (non-zero so it's not null terminator)
                let iat_rva: u32 = 0x5000 + i as u32 * 4;
                buf[desc_off + 16..desc_off + 20].copy_from_slice(&iat_rva.to_le_bytes());
                // write DLL name string
                let name_bytes = dll.as_bytes();
                let off = name_rva as usize;
                buf[off..off + name_bytes.len()].copy_from_slice(name_bytes);
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
            buf[sh_off..sh_off + n].copy_from_slice(&name_bytes[..n]);
            buf[sh_off + 8..sh_off + 12].copy_from_slice(&vsz.to_le_bytes());
            buf[sh_off + 12..sh_off + 16].copy_from_slice(&va.to_le_bytes());
            buf[sh_off + 36..sh_off + 40].copy_from_slice(&chars.to_le_bytes());
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
            0x0040_0000,
            0x1000,
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
            0x0040_0000,
            0x1000,
            &[(".text", 0x1000, 0x400, SCN_MEM_EXECUTE | SCN_MEM_READ), (".rdata", 0x2000, 0x200, SCN_MEM_READ)],
            &[],
        );
        let pe = Pe32::parse(&data).unwrap();
        let names: alloc::vec::Vec<_> = pe.sections().map(|s| alloc::string::String::from(s.name_str())).collect();
        assert_eq!(names, [".text", ".rdata"]);
    }

    #[test]
    fn data_section_is_writable_not_executable() {
        let data = make_pe32(
            0x0040_0000,
            0x1000,
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
        let data = make_pe32(0x0040_0000, 0x1000, &[], &["kernel32.dll", "user32.dll", "d3d9.dll"]);
        let pe = Pe32::parse(&data).unwrap();
        let names: alloc::vec::Vec<_> = pe.imports().map(|i| alloc::string::String::from(i.dll_name())).collect();
        assert_eq!(names, ["kernel32.dll", "user32.dll", "d3d9.dll"]);
    }

    #[test]
    fn import_list_ends_at_descriptor_without_iat() {
        // The smoke test's PEs put their INT over the terminator's Name field:
        // the list must end there, not yield a descriptor with INT = IAT = 0.
        let mut data = make_pe32(0x0040_0000, 0x1000, &[], &["ntdll.dll"]);
        let dir = { Pe32::parse(&data).unwrap().optional_header().data_directory[1] };
        let terminator = dir.virtual_address as usize + 20;
        data[terminator + 12..terminator + 16].copy_from_slice(&0x1234u32.to_le_bytes());
        let pe = Pe32::parse(&data).unwrap();
        assert_eq!(pe.imports().count(), 1);
    }

    // ── T3-1e: error paths ────────────────────────────────────────────────────

    #[test]
    fn optional_header_magic_wrong_gives_not_pe32() {
        let mut data = make_pe32(0x0040_0000, 0x1000, &[], &[]);
        // Corrupt the optional header magic to PE32+ (0x020B)
        let opt_off = 0x44 + core::mem::size_of::<ImageFileHeader>();
        data[opt_off] = 0x0B;
        data[opt_off + 1] = 0x02;
        assert_eq!(Pe32::parse(&data).unwrap_err(), PeError::NotPe32);
    }
}
