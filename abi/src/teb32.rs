//! TEB32 (CLAUDE.md, rule 5): the Thread Environment Block that an i386
//! thread reaches through FS, laid out as on XP SP2, up to
//! `TlsExpansionSlots`; the kernel never writes beyond. ReactOS's NDK headers
//! serve as the specification of the format; offsets are checked at compile
//! time.
//!
//! A TEB has a page of its own, zero where the kernel writes nothing.
//!
//! Moved from `ps::teb` (audit §3.2) and completed.

use core::mem::{offset_of, size_of};

use crate::peb32::UnicodeString32;

/// The SEH chain's end (`EXCEPTION_CHAIN_END`).
pub const EXCEPTION_CHAIN_END: u32 = 0xFFFF_FFFF;

/// NT_TIB, the head of the TEB.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NtTib32 {
    pub exception_list: u32,
    /// One past the highest address of the stack.
    pub stack_base: u32,
    /// The lowest committed address of the stack.
    pub stack_limit: u32,
    pub sub_system_tib: u32,
    pub fiber_data: u32,
    pub arbitrary_user_pointer: u32,
    /// The TEB itself (`FS:[0x18]`).
    pub self_: u32,
}

/// CLIENT_ID.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientId32 {
    pub unique_process: u32,
    pub unique_thread: u32,
}

/// LIST_ENTRY.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListEntry32 {
    pub flink: u32,
    pub blink: u32,
}

/// The XP x86 TEB, up to `TlsExpansionSlots`.
#[repr(C)]
pub struct Teb32 {
    pub nt_tib: NtTib32,
    pub environment_pointer: u32,
    pub client_id: ClientId32,
    pub active_rpc_handle: u32,
    pub thread_local_storage_pointer: u32,
    pub process_environment_block: u32,
    /// GetLastError.
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    pub csr_client_thread: u32,
    pub win32_thread_info: u32,
    pub user32_reserved: [u32; 26],
    pub user_reserved: [u32; 5],
    pub wow32_reserved: u32,
    pub current_locale: u32,
    pub fp_software_status_register: u32,
    pub system_reserved1: [u32; 54],
    pub exception_code: u32,
    pub activation_context_stack: [u32; 5],
    pub spare_bytes1: [u8; 24],
    pub gdi_teb_batch: [u8; 0x4E0],
    pub real_client_id: ClientId32,
    pub gdi_cached_process_handle: u32,
    pub gdi_client_pid: u32,
    pub gdi_client_tid: u32,
    pub gdi_thread_local_info: u32,
    pub win32_client_info: [u32; 62],
    pub gl_dispatch_table: [u32; 233],
    pub gl_reserved1: [u32; 29],
    pub gl_reserved2: u32,
    pub gl_section_info: u32,
    pub gl_section: u32,
    pub gl_table: u32,
    pub gl_current_rc: u32,
    pub gl_context: u32,
    pub last_status_value: u32,
    pub static_unicode_string: UnicodeString32,
    pub static_unicode_buffer: [u16; 261],
    _align: u16,
    /// The base of the stack's reservation.
    pub deallocation_stack: u32,
    pub tls_slots: [u32; 64],
    pub tls_links: ListEntry32,
    pub vdm: u32,
    pub reserved_for_nt_rpc: u32,
    pub dbg_ss_reserved: [u32; 2],
    pub hard_errors_are_disabled: u32,
    pub instrumentation: [u32; 16],
    pub win_sock_data: u32,
    pub gdi_batch_count: u32,
    pub in_dbg_print: u8,
    pub free_stack_on_termination: u8,
    pub has_fiber_data: u8,
    pub ideal_processor: u8,
    pub spare3: u32,
    pub reserved_for_perf: u32,
    pub reserved_for_ole: u32,
    pub waiting_on_loader_lock: u32,
    pub wx86_thread: [u32; 3],
    pub tls_expansion_slots: u32,
}

const _: () = {
    assert!(size_of::<NtTib32>() == 0x1C);
    assert!(offset_of!(Teb32, nt_tib) + offset_of!(NtTib32, self_) == 0x18);
    assert!(offset_of!(Teb32, client_id) == 0x20);
    assert!(offset_of!(Teb32, thread_local_storage_pointer) == 0x2C);
    assert!(offset_of!(Teb32, process_environment_block) == 0x30);
    assert!(offset_of!(Teb32, last_error_value) == 0x34);
    assert!(offset_of!(Teb32, count_of_owned_critical_sections) == 0x38);
    assert!(offset_of!(Teb32, win32_thread_info) == 0x40);
    assert!(offset_of!(Teb32, current_locale) == 0xC4);
    assert!(offset_of!(Teb32, exception_code) == 0x1A4);
    assert!(offset_of!(Teb32, gdi_teb_batch) == 0x1D4);
    assert!(offset_of!(Teb32, real_client_id) == 0x6B4);
    assert!(offset_of!(Teb32, win32_client_info) == 0x6CC);
    assert!(offset_of!(Teb32, gl_dispatch_table) == 0x7C4);
    assert!(offset_of!(Teb32, last_status_value) == 0xBF4);
    assert!(offset_of!(Teb32, static_unicode_string) == 0xBF8);
    assert!(offset_of!(Teb32, static_unicode_buffer) == 0xC00);
    assert!(offset_of!(Teb32, deallocation_stack) == 0xE0C);
    assert!(offset_of!(Teb32, tls_slots) == 0xE10);
    assert!(offset_of!(Teb32, tls_links) == 0xF10);
    assert!(offset_of!(Teb32, vdm) == 0xF18);
    assert!(offset_of!(Teb32, hard_errors_are_disabled) == 0xF28);
    assert!(offset_of!(Teb32, in_dbg_print) == 0xF74);
    assert!(offset_of!(Teb32, tls_expansion_slots) == 0xF94);
    assert!(size_of::<Teb32>() == 0xF98);
};

impl Teb32 {
    /// A TEB with every field zero.
    pub fn zeroed() -> Self {
        // SAFETY: every field is an integer or an array of integers, for
        // which all-zero bytes are a valid value.
        unsafe { core::mem::zeroed() }
    }

    /// The TEB of a new thread at `teb`, of process `pid`, thread `tid`,
    /// whose PEB is at `peb`, on a stack whose reservation starts at
    /// `deallocation_stack` and whose committed part is `[stack_limit,
    /// stack_base)`.
    pub fn new(
        teb: u32,
        pid: u32,
        tid: u32,
        peb: u32,
        stack_base: u32,
        stack_limit: u32,
        deallocation_stack: u32,
    ) -> Self {
        let mut t = Self::zeroed();
        t.nt_tib =
            NtTib32 { exception_list: EXCEPTION_CHAIN_END, stack_base, stack_limit, self_: teb, ..NtTib32::default() };
        t.client_id = ClientId32 { unique_process: pid, unique_thread: tid };
        t.real_client_id = t.client_id;
        t.process_environment_block = peb;
        t.deallocation_stack = deallocation_stack;
        // StaticUnicodeString describes StaticUnicodeBuffer, empty.
        t.static_unicode_string = UnicodeString32 {
            length: 0,
            maximum_length: core::mem::size_of_val(&t.static_unicode_buffer) as u16,
            buffer: teb + offset_of!(Teb32, static_unicode_buffer) as u32,
        };
        t
    }

    /// Its bytes, as they go into the process.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: the struct has no implicit padding (explicit `_align`, size
        // checked above) and only integer fields: every byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_teb_points_at_itself_its_peb_and_its_stack() {
        let teb = Teb32::new(0x7FFD_E000, 8, 12, 0x7FFD_F000, 0x0013_0000, 0x0012_E000, 0x0003_0000);
        let bytes = teb.as_bytes();
        let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        assert_eq!(u32_at(0x00), EXCEPTION_CHAIN_END, "empty SEH chain");
        assert_eq!((u32_at(0x04), u32_at(0x08)), (0x0013_0000, 0x0012_E000), "StackBase, StackLimit");
        assert_eq!(u32_at(0x18), 0x7FFD_E000, "Self");
        assert_eq!((u32_at(0x20), u32_at(0x24)), (8, 12), "ClientId");
        assert_eq!(u32_at(0x30), 0x7FFD_F000, "ProcessEnvironmentBlock");
        assert_eq!((u32_at(0x6B4), u32_at(0x6B8)), (8, 12), "RealClientId");
        assert_eq!(u32_at(0xE0C), 0x0003_0000, "DeallocationStack");
        assert_eq!(u32_at(0xBFC), 0x7FFD_E000 + 0xC00, "StaticUnicodeString.Buffer");
        assert_eq!(u16::from_le_bytes([bytes[0xBFA], bytes[0xBFB]]), 522, "its MaximumLength");
    }
}
