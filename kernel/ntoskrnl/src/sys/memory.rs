//! Les services de Mm.

use abi::ntstatus::{
    NtStatus, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER_3, STATUS_NO_MEMORY,
    STATUS_SUCCESS,
};
use ke::usermem::UserPtr;
use mm::vad::PageProtect;
use mm::virtual_alloc::{AllocType, FreeType, PAGE_SIZE};
use ps::eprocess::PROCESS_VM_OPERATION;

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
