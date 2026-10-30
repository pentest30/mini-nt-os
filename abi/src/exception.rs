//! The x86 `EXCEPTION_RECORD` of an exception delivered to user mode
//! (`ntdll!KiUserExceptionDispatcher`, `NtRaiseException`).

use core::mem::{offset_of, size_of};

/// At most this many parameters (`EXCEPTION_MAXIMUM_PARAMETERS`).
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// `ExceptionFlags`: execution cannot continue after the exception.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x01;

/// First parameter of an access violation: the access was a read.
pub const EXCEPTION_READ_FAULT: u32 = 0;
/// … a write.
pub const EXCEPTION_WRITE_FAULT: u32 = 1;
/// … an instruction fetch (DEP).
pub const EXCEPTION_EXECUTE_FAULT: u32 = 8;

/// First parameter of a breakpoint (`BREAKPOINT_BREAK`).
pub const BREAKPOINT_BREAK: u32 = 0;

/// `EXCEPTION_RECORD` (x86).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExceptionRecord32 {
    pub exception_code: u32,
    pub exception_flags: u32,
    /// A nested record, in user memory; 0 for none.
    pub exception_record: u32,
    pub exception_address: u32,
    pub number_parameters: u32,
    pub exception_information: [u32; EXCEPTION_MAXIMUM_PARAMETERS],
}

const _: () = {
    assert!(offset_of!(ExceptionRecord32, exception_address) == 0x0C);
    assert!(offset_of!(ExceptionRecord32, number_parameters) == 0x10);
    assert!(offset_of!(ExceptionRecord32, exception_information) == 0x14);
    assert!(size_of::<ExceptionRecord32>() == 0x50);
};

impl ExceptionRecord32 {
    /// A record of `code` at `address`, with `parameters` (at most 15).
    pub fn new(code: u32, address: u32, parameters: &[u32]) -> Self {
        assert!(parameters.len() <= EXCEPTION_MAXIMUM_PARAMETERS, "too many exception parameters");
        let mut exception_information = [0; EXCEPTION_MAXIMUM_PARAMETERS];
        exception_information[..parameters.len()].copy_from_slice(parameters);
        Self {
            exception_code: code,
            exception_flags: 0,
            exception_record: 0,
            exception_address: address,
            number_parameters: parameters.len() as u32,
            exception_information,
        }
    }

    /// Its bytes.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integers only, without padding (size checked above).
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }

    /// Its bytes, to fill from user memory.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above; any bytes are integers.
        unsafe { core::slice::from_raw_parts_mut((self as *mut Self).cast::<u8>(), size_of::<Self>()) }
    }

    /// The bytes it takes on the user stack: the header and its parameters,
    /// rounded up to 4.
    pub fn stack_size(&self) -> usize {
        let parameters = (self.number_parameters as usize).min(EXCEPTION_MAXIMUM_PARAMETERS);
        offset_of!(ExceptionRecord32, exception_information) + 4 * parameters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_keeps_its_parameters_and_their_size() {
        let record = ExceptionRecord32::new(0xC000_0005, 0x40_1000, &[EXCEPTION_WRITE_FAULT, 0]);
        assert_eq!((record.number_parameters, record.exception_information[..2].to_vec()), (2, [1, 0].to_vec()));
        assert_eq!(record.stack_size(), 0x14 + 8);
        assert_eq!(ExceptionRecord32::new(0x8000_0003, 0, &[]).stack_size(), 0x14);
    }

    #[test]
    fn its_bytes_are_the_xp_layout() {
        let mut record = ExceptionRecord32::new(0xC000_0005, 0x40_1000, &[EXCEPTION_WRITE_FAULT, 0x1234]);
        assert_eq!(record.as_bytes()[..4], 0xC000_0005u32.to_le_bytes());
        assert_eq!(record.as_bytes()[0x0C..0x10], 0x40_1000u32.to_le_bytes());
        assert_eq!(record.as_bytes()[0x18..0x1C], 0x1234u32.to_le_bytes());
        record.as_bytes_mut()[0x10] = 1;
        assert_eq!(record.number_parameters, 1);
    }
}
