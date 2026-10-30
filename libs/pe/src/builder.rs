//! A builder of minimal PE32 images, for tests (feature `builder`): the
//! headers and sections an image section needs, and exports (no imports, no
//! relocations).

use alloc::vec::Vec;

use crate::{
    ImageFileHeader, ImageOptionalHeader32, ImageSectionHeader, FILE_32BIT_MACHINE, FILE_EXECUTABLE_IMAGE,
    FILE_RELOCS_STRIPPED, IMAGE_DOS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_SIGNATURE, MACHINE_I386,
};

/// Where the NT headers start.
const NT_OFFSET: usize = 0x40;

struct Section {
    name: &'static str,
    virtual_address: u32,
    virtual_size: u32,
    data: Vec<u8>,
    characteristics: u32,
}

/// A PE32 image under construction.
pub struct Pe32Builder {
    image_base: u32,
    entry_point: u32,
    section_alignment: u32,
    file_alignment: u32,
    relocs_stripped: bool,
    stack: (u32, u32),
    sections: Vec<Section>,
    exports: Option<(&'static str, Vec<(&'static str, u32)>)>,
}

impl Pe32Builder {
    /// An image at `image_base`, aligned on 0x1000 in memory and 0x200 in the
    /// file, with a 1 MiB stack of which 4 KiB committed, without sections.
    pub fn new(image_base: u32) -> Self {
        Self {
            image_base,
            entry_point: 0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            relocs_stripped: false,
            stack: (0x10_0000, 0x1000),
            sections: Vec::new(),
            exports: None,
        }
    }

    /// The entry point's RVA.
    pub fn entry_point(mut self, rva: u32) -> Self {
        self.entry_point = rva;
        self
    }

    /// The section and file alignments.
    pub fn alignments(mut self, section: u32, file: u32) -> Self {
        self.section_alignment = section;
        self.file_alignment = file;
        self
    }

    /// The stack of its threads: `reserve` bytes, `commit` of them committed.
    pub fn stack(mut self, reserve: u32, commit: u32) -> Self {
        self.stack = (reserve, commit);
        self
    }

    /// Marks the image IMAGE_FILE_RELOCS_STRIPPED.
    pub fn relocs_stripped(mut self) -> Self {
        self.relocs_stripped = true;
        self
    }

    /// Adds a section at RVA `virtual_address`, `virtual_size` bytes in
    /// memory, initialized from `data` (its raw data, padded to the file
    /// alignment), with `characteristics` (`SCN_*`).
    pub fn section(
        mut self,
        name: &'static str,
        virtual_address: u32,
        virtual_size: u32,
        data: &[u8],
        characteristics: u32,
    ) -> Self {
        self.sections.push(Section { name, virtual_address, virtual_size, data: data.to_vec(), characteristics });
        self
    }

    /// Exports `(name, rva)` under the DLL name `dll`, in an `.edata`
    /// section after the others; the name table is sorted.
    pub fn exports(mut self, dll: &'static str, exports: &[(&'static str, u32)]) -> Self {
        self.exports = Some((dll, exports.to_vec()));
        self
    }

    /// The bytes of the image file.
    pub fn build(&self) -> Vec<u8> {
        let align = |value: usize, to: u32| value.next_multiple_of(to as usize);
        let mut sections: Vec<&Section> = self.sections.iter().collect();
        let edata = self.exports.as_ref().map(|(dll, exports)| {
            let end = self
                .sections
                .iter()
                .map(|s| s.virtual_address + s.virtual_size.max(s.data.len() as u32))
                .max()
                .unwrap_or(self.section_alignment);
            let rva = end.next_multiple_of(self.section_alignment);
            let data = export_directory(rva, dll, exports);
            let size = data.len() as u32;
            (Section { name: ".edata", virtual_address: rva, virtual_size: size, data, characteristics: EDATA }, size)
        });
        if let Some((section, _)) = &edata {
            sections.push(section);
        }
        let file_header = NT_OFFSET + 4;
        let optional_header = file_header + core::mem::size_of::<ImageFileHeader>();
        let section_table = optional_header + core::mem::size_of::<ImageOptionalHeader32>();
        let headers_end = section_table + sections.len() * core::mem::size_of::<ImageSectionHeader>();
        let size_of_headers = align(headers_end, self.file_alignment);
        let size_of_image = sections
            .iter()
            .map(|s| s.virtual_address as usize + s.virtual_size.max(s.data.len() as u32) as usize)
            .max()
            .unwrap_or(size_of_headers);
        let size_of_image = align(size_of_image, self.section_alignment);

        let mut file = alloc::vec![0u8; size_of_headers];
        put16(&mut file, 0, IMAGE_DOS_SIGNATURE);
        put32(&mut file, 0x3C, NT_OFFSET as u32);
        put32(&mut file, NT_OFFSET, IMAGE_NT_SIGNATURE);

        let mut characteristics = FILE_EXECUTABLE_IMAGE | FILE_32BIT_MACHINE;
        if self.relocs_stripped {
            characteristics |= FILE_RELOCS_STRIPPED;
        }
        put16(&mut file, file_header, MACHINE_I386);
        put16(&mut file, file_header + 2, sections.len() as u16);
        put16(&mut file, file_header + 16, core::mem::size_of::<ImageOptionalHeader32>() as u16);
        put16(&mut file, file_header + 18, characteristics);

        put16(&mut file, optional_header, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        put32(&mut file, optional_header + 16, self.entry_point);
        put32(&mut file, optional_header + 28, self.image_base);
        put32(&mut file, optional_header + 32, self.section_alignment);
        put32(&mut file, optional_header + 36, self.file_alignment);
        put16(&mut file, optional_header + 40, 5); // OS version 5.1
        put16(&mut file, optional_header + 42, 1);
        put16(&mut file, optional_header + 48, 4); // subsystem version 4.0
        put32(&mut file, optional_header + 56, size_of_image as u32);
        put32(&mut file, optional_header + 60, size_of_headers as u32);
        put16(&mut file, optional_header + 68, 3); // IMAGE_SUBSYSTEM_WINDOWS_CUI
        put32(&mut file, optional_header + 72, self.stack.0);
        put32(&mut file, optional_header + 76, self.stack.1);
        put32(&mut file, optional_header + 92, 16); // NumberOfRvaAndSizes
        if let Some((section, size)) = &edata {
            put32(&mut file, optional_header + 96, section.virtual_address); // export directory
            put32(&mut file, optional_header + 100, *size);
        }

        for (i, section) in sections.iter().enumerate() {
            let raw_size = align(section.data.len(), self.file_alignment);
            let raw_offset = if raw_size == 0 { 0 } else { file.len() };
            let header = section_table + i * core::mem::size_of::<ImageSectionHeader>();
            let name = section.name.as_bytes();
            file[header..header + name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
            put32(&mut file, header + 8, section.virtual_size);
            put32(&mut file, header + 12, section.virtual_address);
            put32(&mut file, header + 16, raw_size as u32);
            put32(&mut file, header + 20, raw_offset as u32);
            put32(&mut file, header + 36, section.characteristics);
            if raw_size != 0 {
                file.extend_from_slice(&section.data);
                file.resize(raw_offset + raw_size, 0);
            }
        }
        file
    }
}

/// `.edata`: initialized, readable data.
const EDATA: u32 = crate::SCN_CNT_INITIALIZED_DATA | crate::SCN_MEM_READ;

/// An export directory at `rva`: IMAGE_EXPORT_DIRECTORY, then the function,
/// name and ordinal tables, then the strings. Names sorted, ordinals from 1.
fn export_directory(rva: u32, dll: &str, exports: &[(&str, u32)]) -> Vec<u8> {
    let mut sorted: Vec<(usize, &str)> = exports.iter().enumerate().map(|(i, &(name, _))| (i, name)).collect();
    sorted.sort_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));
    let count = exports.len();
    let functions = 40;
    let names = functions + 4 * count;
    let ordinals = names + 4 * count;
    let strings = ordinals + 2 * count;
    let mut data = alloc::vec![0u8; strings];
    let string = |data: &mut Vec<u8>, text: &str| {
        let at = rva + data.len() as u32;
        data.extend_from_slice(text.as_bytes());
        data.push(0);
        at
    };
    let dll_name = string(&mut data, dll);
    put32(&mut data, 12, dll_name);
    put32(&mut data, 16, 1); // Base
    put32(&mut data, 20, count as u32); // NumberOfFunctions
    put32(&mut data, 24, count as u32); // NumberOfNames
    put32(&mut data, 28, rva + functions as u32);
    put32(&mut data, 32, rva + names as u32);
    put32(&mut data, 36, rva + ordinals as u32);
    for (i, &(_, target)) in exports.iter().enumerate() {
        put32(&mut data, functions + 4 * i, target);
    }
    for (slot, &(index, name)) in sorted.iter().enumerate() {
        let at = string(&mut data, name);
        put32(&mut data, names + 4 * slot, at);
        put16(&mut data, ordinals + 2 * slot, index as u16);
    }
    data
}

fn put16(file: &mut [u8], offset: usize, value: u16) {
    file[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(file: &mut [u8], offset: usize, value: u32) {
    file[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExportTarget, Pe32, SCN_MEM_EXECUTE, SCN_MEM_READ, SCN_MEM_WRITE};

    #[test]
    fn a_built_image_parses_back() {
        let file = Pe32Builder::new(0x40_0000)
            .entry_point(0x1000)
            .section(".text", 0x1000, 0x10, &[0xC3; 0x10], SCN_MEM_EXECUTE | SCN_MEM_READ)
            .section(".bss", 0x2000, 0x3000, &[], SCN_MEM_READ | SCN_MEM_WRITE)
            .relocs_stripped()
            .stack(0x4_0000, 0x2000)
            .build();
        let pe = Pe32::parse(&file).unwrap();
        let (fh, opt) = (pe.file_header(), pe.optional_header());
        assert_eq!({ opt.image_base }, 0x40_0000);
        assert_eq!(({ opt.size_of_stack_reserve }, { opt.size_of_stack_commit }), (0x4_0000, 0x2000));
        assert_eq!({ opt.address_of_entry_point }, 0x1000);
        assert_eq!({ opt.size_of_image }, 0x5000);
        assert_eq!({ opt.size_of_headers }, 0x200);
        assert_ne!({ fh.characteristics } & FILE_RELOCS_STRIPPED, 0);
        let sections: Vec<_> = pe.sections().collect();
        assert_eq!(sections.len(), 2);
        let text = sections[0];
        assert_eq!(
            ({ text.virtual_address }, { text.size_of_raw_data }, { text.pointer_to_raw_data }),
            (0x1000, 0x200, 0x200)
        );
        assert_eq!(&file[0x200..0x210], &[0xC3; 0x10]);
        assert_eq!(({ sections[1].size_of_raw_data }, { sections[1].pointer_to_raw_data }), (0, 0), "no raw data");
        assert_eq!(file.len(), 0x400);
    }

    #[test]
    fn exports_are_found_by_name_and_forwarders_told_apart() {
        let file = Pe32Builder::new(0x7C90_0000)
            .section(".text", 0x1000, 0x100, &[0xC3; 0x100], SCN_MEM_EXECUTE | SCN_MEM_READ)
            .exports("ntdll.dll", &[("NtClose", 0x1010), ("KiUserApcDispatcher", 0x1000), ("RtlAlloc", 0x1020)])
            .build();
        let pe = Pe32::parse(&file).unwrap();
        assert_eq!(pe.export("KiUserApcDispatcher"), Some(ExportTarget::Rva(0x1000)));
        assert_eq!(pe.export("NtClose"), Some(ExportTarget::Rva(0x1010)));
        assert_eq!(pe.export("RtlAlloc"), Some(ExportTarget::Rva(0x1020)));
        assert_eq!(pe.export("NtOpen"), None);
        assert_eq!(pe.export("ntclose"), None, "names match with their case");
        assert_eq!({ pe.optional_header().size_of_image }, 0x3000, ".edata after .text");
        let no_exports =
            Pe32Builder::new(0x40_0000).section(".text", 0x1000, 0x10, &[0xC3; 0x10], SCN_MEM_EXECUTE).build();
        assert_eq!(Pe32::parse(&no_exports).unwrap().export("NtClose"), None);
        // A target inside the export directory is a forwarder string.
        let edata = 0x2000;
        let forwarded = Pe32Builder::new(0x7C80_0000)
            .section(".text", 0x1000, 0x10, &[0xC3; 0x10], SCN_MEM_EXECUTE)
            .exports("kernel32.dll", &[("HeapAlloc", edata + 0x28 + 4 + 4 + 2 + 13)])
            .build();
        let pe = Pe32::parse(&forwarded).unwrap();
        assert_eq!(pe.export("HeapAlloc"), Some(ExportTarget::Forwarder("HeapAlloc")), "the name, standing in");
    }
}
