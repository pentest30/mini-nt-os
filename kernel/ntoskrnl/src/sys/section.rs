//! Les services des sections de Mm : créer une section (adossée au fichier
//! d'échange, ou d'un fichier ouvert : données ou image), l'ouvrir par son
//! nom, en projeter une vue dans un processus et la retirer.
//!
//! Une section de fichier prend une copie des octets du fichier
//! (`io_manager::File::read_all`, `mm::section`) : ce qui s'écrit dans une
//! vue n'y retourne pas.
//!
//! Pas encore : `SEC_RESERVE` (`STATUS_NOT_IMPLEMENTED`, journalisé une
//! fois), `SEC_BASED`, `ZeroBits` d'une vue, NtExtendSection, NtQuerySection.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::file::{FILE_EXECUTE, FILE_READ_DATA, FILE_WRITE_DATA};
use abi::memory::{SEC_BASED, SEC_COMMIT, SEC_IMAGE, SEC_NOCACHE, SEC_NO_CHANGE, SEC_RESERVE, VIEW_SHARE, VIEW_UNMAP};
use abi::ntstatus::{
    NtStatus, STATUS_INVALID_FILE_FOR_SECTION, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER_4,
    STATUS_INVALID_PARAMETER_6, STATUS_INVALID_PARAMETER_8, STATUS_INVALID_PARAMETER_9, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS,
};
use io_manager::{File, FILE_TYPE};
use ke::usermem::UserPtr;
use mm::section::{
    create_section_object, Section, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_TYPE,
};
use mm::vad::PageProtect;
use ob::{AccessMask, Handle, ObjectRef};
use ps::eprocess::PROCESS_VM_OPERATION;

use super::object::{create_named, open_by_name};

/// Au plus 21 bits du haut à zéro (ZeroBits).
const MAX_ZERO_BITS: u32 = 21;
/// MEM_TOP_DOWN et MEM_RESERVE, les seuls types d'allocation d'une vue.
const VIEW_ALLOCATION_TYPES: u32 = 0x0010_0000 | 0x0000_2000;

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// La protection de base `protect`, seule (ni garde ni `NOCACHE`).
fn base_protection(protect: u32) -> Result<PageProtect, NtStatus> {
    PageProtect::from_bits(protect)
        .filter(|p| p.bits().count_ones() == 1 && !p.intersects(PageProtect::GUARD | PageProtect::NOCACHE))
        .ok_or(STATUS_INVALID_PAGE_PROTECTION)
}

/// Les droits qu'une protection demande sur le fichier d'une section.
fn file_access(protect: PageProtect) -> u32 {
    let mut access = 0;
    if protect.executable() {
        access |= FILE_EXECUTE;
    }
    if protect.intersects(
        PageProtect::READONLY
            | PageProtect::READWRITE
            | PageProtect::WRITECOPY
            | PageProtect::EXECUTE_READ
            | PageProtect::EXECUTE_READWRITE
            | PageProtect::EXECUTE_WRITECOPY,
    ) {
        access |= FILE_READ_DATA;
    }
    if protect.intersects(PageProtect::READWRITE | PageProtect::EXECUTE_READWRITE) {
        access |= FILE_WRITE_DATA;
    }
    access
}

/// Les droits qu'une vue de protection `protect` demande sur la section.
fn section_access(protect: PageProtect) -> AccessMask {
    let mut access = AccessMask::NONE;
    if protect.executable() {
        access = access | SECTION_MAP_EXECUTE;
    }
    if file_access(protect) & FILE_READ_DATA != 0 {
        access = access | SECTION_MAP_READ;
    }
    if file_access(protect) & FILE_WRITE_DATA != 0 {
        access = access | SECTION_MAP_WRITE;
    }
    access
}

/// `SEC_RESERVE` a déjà été demandé.
static RESERVE_REPORTED: AtomicBool = AtomicBool::new(false);

/// NtCreateSection(*SectionHandle, DesiredAccess, ObjectAttributes,
/// MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle) :
/// une section adossée au fichier d'échange (sans fichier, `MaximumSize`
/// requis), de données (`SEC_COMMIT` avec un fichier) ou d'image
/// (`SEC_IMAGE`), nommée ou non d'après les attributs (qui peuvent manquer).
/// Le fichier doit permettre la protection (`FILE_EXECUTE`, `FILE_READ_DATA`,
/// `FILE_WRITE_DATA`) ; un répertoire rend `STATUS_INVALID_FILE_FOR_SECTION`.
pub(super) fn nt_create_section(arguments: &[u32]) -> NtStatus {
    status(create_section(arguments))
}

fn create_section(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [out, desired, attributes, maximum_size, protect, allocation, file_handle] = arguments[..7] else {
        unreachable!("7 arguments")
    };
    let valid = SEC_COMMIT | SEC_RESERVE | SEC_BASED | SEC_IMAGE | SEC_NOCACHE | SEC_NO_CHANGE;
    let kinds = allocation & (SEC_COMMIT | SEC_RESERVE | SEC_IMAGE);
    if allocation & !valid != 0
        || kinds.count_ones() != 1
        || (allocation & SEC_IMAGE != 0 && allocation & (SEC_NOCACHE | SEC_NO_CHANGE) != 0)
    {
        return Err(STATUS_INVALID_PARAMETER_6);
    }
    if allocation & (SEC_RESERVE | SEC_BASED) != 0 {
        if !RESERVE_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtCreateSection with SEC_RESERVE or SEC_BASED ({allocation:#x}) is not implemented");
        }
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let protect = base_protection(protect)?;
    if protect == PageProtect::NOACCESS {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    let size = match maximum_size {
        0 => 0,
        at => UserPtr::<u64>::new(at).read()?,
    };
    let section = match file_handle {
        0 if allocation & SEC_IMAGE != 0 => return Err(STATUS_INVALID_FILE_FOR_SECTION),
        0 if size == 0 => return Err(STATUS_INVALID_PARAMETER_4),
        0 => Section::create_pagefile(size, protect)?,
        handle => {
            let file = super::current_process().handle_table.reference_as::<File>(
                Handle(handle),
                &FILE_TYPE,
                AccessMask(file_access(protect)),
            )?;
            if file.is_directory() {
                return Err(STATUS_INVALID_FILE_FOR_SECTION);
            }
            let bytes: Arc<[u8]> = Arc::from(file.read_all()?);
            if allocation & SEC_IMAGE != 0 {
                Section::create_image(bytes)?
            } else {
                Section::create_data_file(bytes, size, protect)?
            }
        }
    };
    let object: ObjectRef = create_section_object(section);
    if attributes == 0 {
        let out = UserPtr::<u32>::new(out);
        out.write(&0)?;
        let handle = super::current_process().handle_table.insert(object, AccessMask(desired), Default::default())?;
        super::object::give_handle(&out, handle)?;
        return Ok(STATUS_SUCCESS);
    }
    create_named(out, desired, attributes, object)
}

/// NtOpenSection(*SectionHandle, DesiredAccess, ObjectAttributes) : un
/// handle sur la section que désignent les attributs.
pub(super) fn nt_open_section(arguments: &[u32]) -> NtStatus {
    status(open_by_name(arguments[0], arguments[1], arguments[2], &SECTION_TYPE).map(|()| STATUS_SUCCESS))
}

/// NtMapViewOfSection(SectionHandle, ProcessHandle, *BaseAddress, ZeroBits,
/// CommitSize, *SectionOffset, *ViewSize, InheritDisposition,
/// AllocationType, Win32Protect) : une vue de la section dans le processus
/// (`PROCESS_VM_OPERATION`), en `*BaseAddress` (0 : où il y a la place ; sa
/// base pour une image), de `*ViewSize` octets (0 : jusqu'au bout) depuis
/// `*SectionOffset` ; rend la base et la taille de la vue.
/// `STATUS_IMAGE_NOT_AT_BASE` pour une image projetée ailleurs, que `ntdll`
/// reloge.
pub(super) fn nt_map_view_of_section(arguments: &[u32]) -> NtStatus {
    status(map_view(arguments))
}

fn map_view(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [section_handle, process_handle, base_address, zero_bits, _commit, offset, view_size, inherit, allocation, protect] =
        arguments[..10]
    else {
        unreachable!("10 arguments")
    };
    if zero_bits > MAX_ZERO_BITS {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    if inherit != VIEW_SHARE && inherit != VIEW_UNMAP {
        return Err(STATUS_INVALID_PARAMETER_8);
    }
    if allocation & !VIEW_ALLOCATION_TYPES != 0 {
        return Err(STATUS_INVALID_PARAMETER_9);
    }
    let protect = base_protection(protect)?;
    let section = super::current_process().handle_table.reference_as::<Arc<Section>>(
        Handle(section_handle),
        &SECTION_TYPE,
        section_access(protect),
    )?;
    let process = super::reference_process(process_handle, PROCESS_VM_OPERATION)?;
    let (base_address, view_size) = (UserPtr::<u32>::new(base_address), UserPtr::<u32>::new(view_size));
    let base = u64::from(base_address.read()?);
    let size = u64::from(view_size.read()?);
    let offset = match offset {
        0 => 0,
        at => UserPtr::<u64>::new(at).read()?,
    };
    let view = process.with_space(|space| space.map_view(&section, base, offset, size, protect))??;
    let written = base_address.write(&(view.base as u32)).and_then(|()| view_size.write(&(view.size as u32)));
    if let Err(fault) = written {
        let _ = process.with_space(|space| space.unmap_view(view.base));
        return Err(fault);
    }
    Ok(view.status)
}

/// NtUnmapViewOfSection(ProcessHandle, BaseAddress) : retire du processus
/// (`PROCESS_VM_OPERATION`) la vue qui contient l'adresse.
pub(super) fn nt_unmap_view_of_section(arguments: &[u32]) -> NtStatus {
    status(super::reference_process(arguments[0], PROCESS_VM_OPERATION).and_then(|process| {
        process.with_space(|space| space.unmap_view(u64::from(arguments[1])))??;
        Ok(STATUS_SUCCESS)
    }))
}
