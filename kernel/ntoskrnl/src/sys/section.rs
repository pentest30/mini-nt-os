//! Les services des sections de Mm : créer une section (adossée au fichier
//! d'échange, ou d'un fichier ouvert : données ou image), l'ouvrir par son
//! nom, en projeter une vue dans un processus et la retirer, dire ce qu'elle
//! est (NtQuerySection).
//!
//! Une section de fichier prend une copie des octets du fichier
//! (`io_manager::File::read_all`, `mm::section`) : ce qui s'écrit dans une
//! vue n'y retourne pas.
//!
//! Une section du fichier d'échange peut être réservée (`SEC_RESERVE` : ses
//! pages se commitent par NtAllocateVirtualMemory dans une vue) et basée
//! (`SEC_BASED` : à la même adresse dans chaque processus), comme la section
//! partagée de `csrss`.
//!
//! Pas encore : `SEC_BASED` pour un fichier (`STATUS_NOT_IMPLEMENTED`,
//! journalisé une fois), `ZeroBits` d'une vue, NtExtendSection.

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
/// MEM_TOP_DOWN : la vue va le plus haut où il y a la place.
const MEM_TOP_DOWN: u32 = 0x0010_0000;
/// MEM_TOP_DOWN et MEM_RESERVE, les seuls types d'allocation d'une vue.
const VIEW_ALLOCATION_TYPES: u32 = MEM_TOP_DOWN | 0x0000_2000;

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

/// `SEC_BASED` pour un fichier a déjà été demandé.
static BASED_FILE_REPORTED: AtomicBool = AtomicBool::new(false);

/// NtCreateSection(*SectionHandle, DesiredAccess, ObjectAttributes,
/// MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle) :
/// une section adossée au fichier d'échange (sans fichier, `MaximumSize`
/// requis ; ses pages réservées avec `SEC_RESERVE`, basée avec `SEC_BASED`),
/// de données (`SEC_COMMIT` avec un fichier, `SEC_RESERVE` n'y change rien)
/// ou d'image (`SEC_IMAGE`), nommée ou non d'après les attributs (qui peuvent
/// manquer).
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
    if allocation & SEC_BASED != 0 && file_handle != 0 {
        if !BASED_FILE_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtCreateSection with SEC_BASED for a file ({allocation:#x}) is not implemented");
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
        0 => Section::create_shared(size, protect, allocation & SEC_RESERVE != 0, allocation & SEC_BASED != 0)?,
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
                Section::create_image_of(bytes, file.path())?
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
    let view = if allocation & MEM_TOP_DOWN != 0 {
        process.with_space(|space| space.map_view_top_down(&section, base, offset, size, protect))??
    } else {
        process.with_space(|space| space.map_view(&section, base, offset, size, protect))??
    };
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

/// Les classes de NtQuerySection demandées sans être implémentées.
static UNSUPPORTED_SECTION_CLASSES: super::ClassReport = super::ClassReport::new("NtQuerySection");

/// NtQuerySection(SectionHandle, SectionInformationClass, SectionInformation,
/// SectionInformationLength, ResultLength) : ce que sait la section
/// (`SECTION_QUERY`). `SectionBasicInformation` : son adresse si elle est
/// basée, ses attributs (`SEC_IMAGE` et `SEC_FILE` pour une image, `SEC_FILE`
/// pour un fichier de données, `SEC_COMMIT` ou `SEC_RESERVE` pour le fichier
/// d'échange, avec `SEC_BASED`) et sa taille ;
/// `SectionImageInformation`, pour une image seulement
/// (`STATUS_SECTION_NOT_IMAGE` sinon) : son point d'entrée à sa base
/// préférée, sa pile, son sous-système et les champs de son PE. Les autres
/// classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur premier appel.
pub(super) fn nt_query_section(arguments: &[u32]) -> NtStatus {
    use abi::memory::{
        SectionBasicInformation32, SectionImageInformation32, SECTION_BASIC_INFORMATION, SECTION_IMAGE_INFORMATION,
        SEC_FILE,
    };
    use mm::section::{SectionKind, SECTION_QUERY};

    let (handle, class, buffer, length, return_length) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    if class != SECTION_BASIC_INFORMATION && class != SECTION_IMAGE_INFORMATION {
        return UNSUPPORTED_SECTION_CLASSES.report(class);
    }
    let section = match super::current_process().handle_table.reference_as::<Arc<Section>>(
        Handle(handle),
        &SECTION_TYPE,
        SECTION_QUERY,
    ) {
        Ok(section) => section,
        Err(status) => return status,
    };
    if class == SECTION_BASIC_INFORMATION {
        let mut attributes = match section.kind() {
            SectionKind::Image => SEC_IMAGE | SEC_FILE,
            SectionKind::DataFile => SEC_FILE,
            SectionKind::Pagefile if section.is_reserve() => SEC_RESERVE,
            SectionKind::Pagefile => SEC_COMMIT,
        };
        if section.based_address().is_some() {
            attributes |= SEC_BASED;
        }
        let base_address = section.based_address().unwrap_or(0) as u32;
        let information = SectionBasicInformation32 { base_address, attributes, size: section.size() as i64 };
        return super::return_information(information.as_bytes(), buffer, length, return_length);
    }
    let Some(image) = section.image() else { return abi::ntstatus::STATUS_SECTION_NOT_IMAGE };
    let info = image.info;
    let information = SectionImageInformation32 {
        transfer_address: (info.image_base + info.entry_point) as u32,
        zero_bits: 0,
        maximum_stack_size: info.stack_reserve as u32,
        committed_stack_size: info.stack_commit as u32,
        sub_system_type: u32::from(info.subsystem),
        sub_system_minor_version: info.subsystem_version.1,
        sub_system_major_version: info.subsystem_version.0,
        gp_value: 0,
        image_characteristics: info.characteristics,
        dll_characteristics: info.dll_characteristics,
        machine: info.machine,
        image_contains_code: u8::from(info.contains_code),
        image_flags: 0,
        loader_flags: info.loader_flags,
        image_file_size: info.file_size as u32,
        reserved: 0,
    };
    super::return_information(information.as_bytes(), buffer, length, return_length)
}
