//! Les services de Mm.

use abi::memory::{MemoryBasicInformation32, MEMORY_BASIC_INFORMATION};
use abi::ntstatus::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
    STATUS_INVALID_PARAMETER_3, STATUS_NO_MEMORY, STATUS_SUCCESS,
};
use ke::usermem::UserPtr;
use mm::vad::PageProtect;
use mm::virtual_alloc::{AllocType, FreeType, PAGE_SIZE};
use ps::eprocess::{PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION};

/// Les classes de NtQueryVirtualMemory demandées sans être implémentées.
static UNSUPPORTED_MEMORY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryVirtualMemory");

/// Au plus 21 bits du haut à zéro (ZeroBits).
const MAX_ZERO_BITS: u32 = 21;

/// NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits,
/// *RegionSize, AllocationType, Protect) : réserve ou commite dans le
/// processus (`PROCESS_VM_OPERATION`), puis rend la base et la taille de la
/// plage, en pages. Avec `ZeroBits`, une nouvelle plage doit finir sous
/// 2^(32 - ZeroBits) : sinon elle est rendue et l'appel échoue avec
/// `STATUS_NO_MEMORY`.
pub(super) fn nt_allocate_virtual_memory(arguments: &[u32]) -> NtStatus {
    match allocate(arguments) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn allocate(arguments: &[u32]) -> Result<(), NtStatus> {
    let (base_address, region_size) = (UserPtr::<u32>::new(arguments[1]), UserPtr::<u32>::new(arguments[3]));
    let zero_bits = arguments[2];
    if zero_bits > MAX_ZERO_BITS {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    let alloc_type = AllocType::from_bits(arguments[4]).ok_or(STATUS_INVALID_PARAMETER)?;
    let protect = PageProtect::from_bits(arguments[5]).ok_or(STATUS_INVALID_PAGE_PROTECTION)?;
    let process = super::reference_process(arguments[0], PROCESS_VM_OPERATION)?;
    let base = u64::from(base_address.read()?);
    let size = u64::from(region_size.read()?);
    let start = process.with_space(|space| space.allocate(base, size, alloc_type, protect))??;
    let end =
        if base == 0 { start + size.next_multiple_of(PAGE_SIZE) } else { (base + size).next_multiple_of(PAGE_SIZE) };
    let new_range = base == 0 || alloc_type.contains(AllocType::MEM_RESERVE);
    if zero_bits != 0 && new_range && end > 1u64 << (32 - zero_bits) {
        let _ = process.with_space(|space| space.free(start, 0, FreeType::MEM_RELEASE));
        return Err(STATUS_NO_MEMORY);
    }
    base_address.write(&(start as u32))?;
    region_size.write(&((end - start) as u32))
}

/// NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, FreeType) :
/// décommite ou libère dans le processus (`PROCESS_VM_OPERATION`), puis rend
/// la base et la taille de la plage traitée.
pub(super) fn nt_free_virtual_memory(arguments: &[u32]) -> NtStatus {
    match free(arguments) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn free(arguments: &[u32]) -> Result<(), NtStatus> {
    let (base_address, region_size) = (UserPtr::<u32>::new(arguments[1]), UserPtr::<u32>::new(arguments[2]));
    let free_type = FreeType::from_bits(arguments[3]).ok_or(STATUS_INVALID_PARAMETER)?;
    let process = super::reference_process(arguments[0], PROCESS_VM_OPERATION)?;
    let base = u64::from(base_address.read()?);
    let size = u64::from(region_size.read()?);
    let (start, length) = process.with_space(|space| space.free(base, size, free_type))??;
    base_address.write(&(start as u32))?;
    region_size.write(&(length as u32))
}

/// NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *NumberOfBytesToProtect,
/// NewAccessProtection, *OldAccessProtection) : donne la protection aux pages
/// de la plage, toutes commitées et d'une même réservation, dans le processus
/// (`PROCESS_VM_OPERATION`) ; rend la plage arrondie aux pages et l'ancienne
/// protection de sa première page. Sur une vue d'image, une protection en
/// écriture devient de la copie sur écriture (`mm::section::view_protection`).
pub(super) fn nt_protect_virtual_memory(arguments: &[u32]) -> NtStatus {
    match protect(arguments) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn protect(arguments: &[u32]) -> Result<(), NtStatus> {
    let (base_address, region_size) = (UserPtr::<u32>::new(arguments[1]), UserPtr::<u32>::new(arguments[2]));
    let old_protect = UserPtr::<u32>::new(arguments[4]);
    let new_protect = PageProtect::from_bits(arguments[3]).ok_or(STATUS_INVALID_PAGE_PROTECTION)?;
    let process = super::reference_process(arguments[0], PROCESS_VM_OPERATION)?;
    let base = u64::from(base_address.read()?);
    let size = u64::from(region_size.read()?);
    let old = process.with_space(|space| space.protect(base, size, new_protect))??;
    // The range Mm changed: whole pages.
    let start = base & !(PAGE_SIZE - 1);
    let end = (base + size).next_multiple_of(PAGE_SIZE);
    base_address.write(&(start as u32))?;
    region_size.write(&((end - start) as u32))?;
    old_protect.write(&old.bits())
}

/// NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
/// MemoryInformation, MemoryInformationLength, ReturnLength) : décrit, dans le
/// processus (`PROCESS_QUERY_INFORMATION`), la plage de pages de même état et
/// de même protection qui commence à la page de `BaseAddress`
/// (`MemoryBasicInformation`, `mm::virtual_alloc::query`).
/// `STATUS_INFO_LENGTH_MISMATCH` pour un tampon plus petit que
/// MEMORY_BASIC_INFORMATION ; `STATUS_INVALID_PARAMETER` au-delà de la moitié
/// utilisateur. Les autres classes rendent `STATUS_NOT_IMPLEMENTED`,
/// journalisé à leur premier appel.
pub(super) fn nt_query_virtual_memory(arguments: &[u32]) -> NtStatus {
    match query(arguments) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn query(arguments: &[u32]) -> Result<(), NtStatus> {
    let (address, class, buffer, length, return_length) =
        (arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    if class != MEMORY_BASIC_INFORMATION {
        return Err(UNSUPPORTED_MEMORY_CLASSES.report(class));
    }
    let size = core::mem::size_of::<MemoryBasicInformation32>();
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    ke::usermem::probe_for_write(u64::from(buffer), size, 4)?;
    let process = super::reference_process(arguments[0], PROCESS_QUERY_INFORMATION)?;
    let region = process.with_space(|space| space.query(u64::from(address)))??;
    let info = MemoryBasicInformation32 {
        base_address: region.base_address as u32,
        allocation_base: region.allocation_base as u32,
        allocation_protect: region.allocation_protect.bits(),
        region_size: region.region_size as u32,
        state: region.state as u32,
        protect: region.protect.bits(),
        kind: region.kind.map_or(0, |kind| kind as u32),
    };
    ke::usermem::copy_to_user(u64::from(buffer), info.as_bytes())?;
    if return_length != 0 {
        UserPtr::<u32>::new(return_length).write(&(size as u32))?;
    }
    Ok(())
}

/// Ce que copient NtReadVirtualMemory et NtWriteVirtualMemory, au plus, par
/// passage.
const COPY_CHUNK: u64 = PAGE_SIZE;

/// Les vérifications communes de NtReadVirtualMemory et NtWriteVirtualMemory,
/// comme XP : les deux plages de `size` octets en `address` et en `buffer`
/// tiennent dans la moitié utilisateur (`STATUS_ACCESS_VIOLATION` sinon), et
/// le compte rendu, s'il est demandé, s'écrit.
fn check_copy(address: u32, buffer: u32, size: u32, done: u32) -> Result<(), NtStatus> {
    let fits = |at: u32| u64::from(at) + u64::from(size) <= ke::usermem::USER_PROBE_ADDRESS;
    if !fits(address) || !fits(buffer) {
        return Err(abi::ntstatus::STATUS_ACCESS_VIOLATION);
    }
    if done != 0 {
        ke::usermem::probe_for_write(u64::from(done), 4, 4)?;
    }
    Ok(())
}

/// Copie `size` octets depuis ou vers l'adresse `address` d'un processus,
/// page par page de ce processus, avec `step(offset, chunk)`, qui copie
/// `chunk` octets à `offset` du début ; rend le statut (`STATUS_SUCCESS`, ou
/// `STATUS_PARTIAL_COPY` dès qu'une page échoue, comme MmCopyVirtualMemory)
/// et écrit en `done`, s'il n'est pas nul, le nombre d'octets copiés : ceux
/// des pages d'avant.
fn copy_in_chunks(
    address: u32,
    size: u32,
    done: u32,
    mut step: impl FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
) -> NtStatus {
    let size = u64::from(size);
    let mut chunk = alloc::vec![0u8; size.min(COPY_CHUNK) as usize];
    let mut copied = 0;
    let mut status = STATUS_SUCCESS;
    while copied < size {
        let in_page = COPY_CHUNK - (u64::from(address) + copied) % COPY_CHUNK;
        let length = (size - copied).min(in_page) as usize;
        if step(copied, &mut chunk[..length]).is_err() {
            status = abi::ntstatus::STATUS_PARTIAL_COPY;
            break;
        }
        copied += length as u64;
    }
    if done != 0 {
        if let Err(fault) = UserPtr::<u32>::new(done).write(&(copied as u32)) {
            return fault;
        }
    }
    status
}

/// NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead,
/// NumberOfBytesRead) : copie de la mémoire du processus (`PROCESS_VM_READ`)
/// dans le tampon du processus courant, comme le processus la lirait (une
/// page réservée arrête la copie) ; rend le nombre d'octets copiés s'il est
/// demandé. Rien à copier : `STATUS_SUCCESS`, sans regarder le handle.
pub(super) fn nt_read_virtual_memory(arguments: &[u32]) -> NtStatus {
    let (address, buffer, size, done) = (arguments[1], arguments[2], arguments[3], arguments[4]);
    let read = || {
        check_copy(address, buffer, size, done)?;
        if size == 0 {
            return Ok(STATUS_SUCCESS);
        }
        let process = super::reference_process(arguments[0], ps::eprocess::PROCESS_VM_READ)?;
        Ok(copy_in_chunks(address, size, done, |offset, chunk| {
            process.read_memory(u64::from(address) + offset, chunk)?;
            ke::usermem::copy_to_user(u64::from(buffer) + offset, chunk)
        }))
    };
    read().unwrap_or_else(|status| status)
}

/// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite,
/// NumberOfBytesWritten) : copie le tampon du processus courant dans la
/// mémoire du processus (`PROCESS_VM_WRITE`), comme le processus l'écrirait
/// (copie sur écriture comprise ; une page en lecture seule arrête la copie) ;
/// rend le nombre d'octets copiés s'il est demandé. Rien à copier :
/// `STATUS_SUCCESS`, sans regarder le handle.
pub(super) fn nt_write_virtual_memory(arguments: &[u32]) -> NtStatus {
    let (address, buffer, size, done) = (arguments[1], arguments[2], arguments[3], arguments[4]);
    let write = || {
        check_copy(address, buffer, size, done)?;
        if size == 0 {
            return Ok(STATUS_SUCCESS);
        }
        let process = super::reference_process(arguments[0], ps::eprocess::PROCESS_VM_WRITE)?;
        Ok(copy_in_chunks(address, size, done, |offset, chunk| {
            ke::usermem::copy_from_user(chunk, u64::from(buffer) + offset)?;
            process.write_memory(u64::from(address) + offset, chunk)
        }))
    };
    write().unwrap_or_else(|status| status)
}
