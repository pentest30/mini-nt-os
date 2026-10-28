//! TEB — Thread Environment Block (XP x86 layout, selected fields).
//!
//! Accessed via FS:[0] in 32-bit user mode.
//! GetLastError / SetLastError read/write TEB.LastErrorValue directly.

#[repr(C, packed)]
pub struct Teb32 {
    pub nt_tib:                 NtTib,        // 0x00 — NT_TIB (SEH chain, stack limits)
    pub environment_pointer:    u32,          // 0x1C
    pub client_id_process:      u32,          // 0x20
    pub client_id_thread:       u32,          // 0x24
    pub active_rpc_handle:      u32,          // 0x28
    pub thread_local_storage:   u32,          // 0x2C → TLS array pointer
    pub peb:                    u32,          // 0x30 → PEB *
    pub last_error_value:       u32,          // 0x34 ← GetLastError()
    pub count_of_owned_cs:      u32,          // 0x38
    pub csr_client_thread:      u32,          // 0x3C
    // … (truncated; add fields on demand)
}

/// NT_TIB — Thread Information Block (head of TEB, also used in SEH).
#[repr(C, packed)]
pub struct NtTib {
    pub exception_list:  u32,  // 0x00 — SEH chain head
    pub stack_base:      u32,  // 0x04
    pub stack_limit:     u32,  // 0x08
    pub sub_system_tib:  u32,  // 0x0C
    pub fiber_data:      u32,  // 0x10
    pub arbitrary:       u32,  // 0x14
    pub self_ptr:        u32,  // 0x18 → TEB * (TEB points to itself)
}

impl Teb32 {
    pub fn new(pid: u32, tid: u32, peb_addr: u32, stack_base: u32, stack_limit: u32) -> Self {
        let mut teb: Teb32 = unsafe { core::mem::zeroed() };
        teb.nt_tib.exception_list = 0xFFFF_FFFFu32; // empty SEH chain sentinel
        teb.nt_tib.stack_base     = stack_base;
        teb.nt_tib.stack_limit    = stack_limit;
        // self_ptr filled in after we know the TEB's address.
        teb.client_id_process     = pid;
        teb.client_id_thread      = tid;
        teb.peb                   = peb_addr;
        teb
    }
}
