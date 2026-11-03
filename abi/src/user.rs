//! USER, the window part of win32k (02 §7.2), as its i386 clients see it
//! (CLAUDE.md, rule 5): what `NtUserProcessConnect` returns (`USERCONNECT`,
//! `SHAREDINFO`), the start of the shared `SERVERINFO`, the handle table, and
//! the `CLIENTINFO` that win32k keeps in each GUI thread's TEB. ReactOS's
//! `win32ss/include/ntuser.h` (the pinned version) serves as the
//! specification of the formats (ADR-002); offsets are checked at compile
//! time.
//!
//! A pointer in these structures is 32 bits wide. `psi` and `aheList`, in
//! `SHAREDINFO`, are already addresses in the client's read-only view of the
//! shared section; the pointers stored *in* the section (the handle table's
//! `handles`, its entries' objects) are *server addresses*, from which the
//! client subtracts `ulSharedDelta` (`SharedPtrToUser`). Those to a
//! `PROCESSINFO` or a `THREADINFO` are server addresses that the client only
//! compares.

use core::mem::{offset_of, size_of};

/// USER_VERSION: the version of the USER interface, 5.0
/// (`MAKELONG(0x0000, 0x0005)`), that `user32` puts in `ulVersion`.
pub const USER_VERSION: u32 = 0x0005_0000;

/// TWOPARAM_ROUTINE_REGISTERLOGONPROCESS: the routine of NtUserCallTwoParam
/// that registers the logon process (its PID, TRUE) or unregisters it
/// (`SIMPLECALLROUTINES` of ReactOS's `ntuser.h`, before Vista).
pub const TWOPARAM_ROUTINE_REGISTERLOGONPROCESS: u32 = 0x69;

/// UserThreadCsrApiPort: the class of NtUserSetInformationThread by which
/// csrss gives win32k its API port (`USERTHREADINFOCLASS`).
pub const USER_THREAD_CSR_API_PORT: u32 = 10;

/// FNID_FIRST: the first window function identifier (the scroll bar's).
pub const FNID_FIRST: u32 = 0x029A;
/// FNID_NUM: the window function identifiers, `FNID_SCROLLBAR` to
/// `FNID_SENDMESSAGECALLBACK`.
pub const FNID_NUM: usize = 31;
/// FNID_NUMSERVERPROC: those with a server procedure, up to `FNID_SWITCH`.
pub const FNID_NUMSERVERPROC: usize = 7;

/// SRVINFO_IMM32 (`SERVERINFO.dwSRVIFlags`): input method editors are on;
/// `user32` then loads `imm32`.
pub const SRVINFO_IMM32: u32 = 0x0004;

/// CI_INITTHREAD (`CLIENTINFO.CI_flags`): `user32` has set the thread up.
pub const CI_INITTHREAD: u32 = 0x0008;

/// TIF_SYSTEMTHREAD (`THREADINFO` flags): a system thread of win32k.
pub const TIF_SYSTEMTHREAD: u32 = 0x0000_0004;
/// TIF_CSRSSTHREAD (`THREADINFO` flags, `CLIENTINFO.dwTIFlags`): a thread
/// of `csrss`.
pub const TIF_CSRSSTHREAD: u32 = 0x0000_0008;
/// TIF_DONTATTACHQUEUE: its input queue is never attached to another's.
pub const TIF_DONTATTACHQUEUE: u32 = 0x0000_0040;

/// USER_HANDLE_ENTRY: an entry of the USER handle table.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserHandleEntry32 {
    /// The object, a server address; 0 when free.
    pub ptr: u32,
    /// Its owner: a `THREADINFO` or a `PROCESSINFO`, as a server address.
    pub owner: u32,
    /// Its `TYPE_*`; 0 (`TYPE_FREE`) when free.
    pub kind: u8,
    /// `HANDLEENTRY_DESTROY`, `HANDLEENTRY_INDESTROY`.
    pub flags: u8,
    /// The high word of the handles of this entry.
    pub generation: u16,
}

/// USER_HANDLE_TABLE (ReactOS): the head of the handle table, in the shared
/// section.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserHandleTable32 {
    /// The first entry, a server address.
    pub handles: u32,
    /// The first free entry, a server address; 0 when none was freed.
    pub freelist: u32,
    /// The entries in use or freed so far.
    pub nb_handles: i32,
    /// The entries the table has room for.
    pub allocated_handles: i32,
}

/// WNDMSG: the messages a window class handles, a bit each.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WndMsg32 {
    pub max_msgs: u32,
    /// A bit array, a server address; 0 with `max_msgs` 0.
    pub ab_msgs: u32,
}

/// SHAREDINFO: where a client finds what USER shares with it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedInfo32 {
    /// The `SERVERINFO`, in the client's view.
    pub psi: u32,
    /// The handle table (`USER_HANDLE_TABLE`), in the client's view.
    pub ahe_list: u32,
    /// The `DISPLAYINFO`, a server address; 0 for none yet.
    pub disp_info: u32,
    /// ulSharedDelta: a server address less this is the address of the same
    /// byte in the client's view of the shared section.
    pub shared_delta: u32,
    pub aw_control: [WndMsg32; FNID_NUM],
    pub def_window_msgs: WndMsg32,
    pub def_window_spec_msgs: WndMsg32,
}

/// USERCONNECT: the buffer of `NtUserProcessConnect`, 0x124 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserConnect32 {
    /// The client's [`USER_VERSION`].
    pub version: u32,
    pub current_version: u32,
    pub dispatch_count: u32,
    pub si_client: SharedInfo32,
}

/// PFNCLIENT: the client's window procedures, from the scroll bar's to
/// `MDIActivateDlgProc`, that `NtUserInitializeClientPfnArrays` records.
pub type PfnClient32 = [u32; 23];
/// PFNCLIENTWORKER: the client's worker procedures of the controls.
pub type PfnClientWorker32 = [u32; 11];

/// The start of SERVERINFO, the first structure of the shared section, up to
/// `cbHandleTable`: what the kernel writes so far. The rest (class atoms,
/// message box strings, code page tables, then `PERUSERSERVERINFO`: system
/// metrics, colours, brushes…) follows in the same page, zero until written.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerInfoHead32 {
    /// `SRVINFO_*`.
    pub srvi_flags: u32,
    /// The entries of the handle table.
    pub handle_entries: u32,
    pub mp_fnid_pfn: [u32; FNID_NUM],
    pub a_sto_cid_pfn: [u32; FNID_NUMSERVERPROC],
    pub mp_fnid_server_cb_wnd_proc: [u16; FNID_NUM],
    /// The alignment of the next field, written as 0.
    pub padding: u16,
    pub apfn_client_a: PfnClient32,
    pub apfn_client_w: PfnClient32,
    pub apfn_client_worker: PfnClientWorker32,
    /// The size of the handle table, in bytes.
    pub cb_handle_table: u32,
}

/// MSG, as the client keeps it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Msg32 {
    pub hwnd: u32,
    pub message: u32,
    pub w_param: u32,
    pub l_param: u32,
    pub time: u32,
    pub pt_x: i32,
    pub pt_y: i32,
}

/// CALLBACKWND.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackWnd32 {
    pub hwnd: u32,
    pub pwnd: u32,
    pub act_ctx: u32,
}

/// CLIENTINFO: what win32k keeps for `user32` in a GUI thread's TEB
/// (`Win32ClientInfo`, 62 words), set when the thread becomes a GUI thread.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientInfo32 {
    /// `CI_*`.
    pub ci_flags: u32,
    pub c_spins: u32,
    /// dwExpWinVer: the version of the system the program expects,
    /// `MAKEWORD(minor, major)` of its image's subsystem version.
    pub exp_win_ver: u32,
    pub compat_flags: u32,
    pub compat_flags2: u32,
    /// The thread's `TIF_*`.
    pub ti_flags: u32,
    /// Its desktop's `DESKTOPINFO`, in its process's view of the desktop
    /// heap (the server address less `client_delta`); 0 without a desktop.
    pub desk_info: u32,
    /// ulClientDelta: its desktop heap's server address less its view's.
    pub client_delta: u32,
    pub phk_current: u32,
    pub fs_hooks: u32,
    pub callback_wnd: CallbackWnd32,
    pub hook_current: u32,
    pub in_ddeml_callback: i32,
    /// Its `CLIENTTHREADINFO`, in the view of its desktop heap.
    pub client_thread_info: u32,
    pub hook_data: u32,
    pub key_cache: u32,
    pub af_key_state: [u8; 8],
    pub async_key_cache: u32,
    pub af_async_key_state: [u8; 8],
    pub af_async_key_state_recent_down: [u8; 8],
    /// Its keyboard layout.
    pub hkl: u32,
    /// Its ANSI code page.
    pub code_page: u16,
    pub ach_dbcs_cf: [u8; 2],
    pub msg_dbcs_cb: Msg32,
    pub registered_classes: u32,
    pub win32_client_info3: [u32; 26],
    /// Its process's `PROCESSINFO`, a server address that `user32` only
    /// compares.
    pub ppi: u32,
}

/// NB_HOOKS: the hook types, `WH_MSGFILTER` (-1) to `WH_MOUSE_LL` (14).
pub const NB_HOOKS: usize = 16;

/// LIST_ENTRY, 32-bit: two server addresses in the desktop heap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListEntry32 {
    pub flink: u32,
    pub blink: u32,
}

/// DESKTOPINFO up to its name (`szDesktopName`, at its end): what a
/// desktop shares with the GUI threads on it, at the start of its desktop
/// heap. Its pointers are server addresses.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeskInfoHead32 {
    /// pvDesktopBase, pvDesktopLimit: the desktop heap's server addresses,
    /// by which `user32` tells a pointer into it (DesktopPtrToUser).
    pub desktop_base: u32,
    pub desktop_limit: u32,
    /// spwnd: the desktop window.
    pub spwnd: u32,
    pub fs_hooks: u32,
    /// aphkStart: the hook chains, one per hook type, empty lists.
    pub aphk_start: [ListEntry32; NB_HOOKS],
    pub task_man_window: u32,
    pub progman_window: u32,
    pub shell_window: u32,
    pub spwnd_shell: u32,
    pub spwnd_bk_gnd: u32,
    pub ppi_shell_process: u32,
    /// LastInputWasKbd, bit 0.
    pub flags: u32,
}

/// CLIENTTHREADINFO: a GUI thread's queue state that `user32` reads, in
/// its desktop's heap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientThreadInfo32 {
    pub cti_flags: u32,
    pub fs_change_bits: u16,
    pub fs_wake_bits: u16,
    pub fs_wake_bits_journal: u16,
    pub fs_wake_mask: u16,
    pub time_last_read: u32,
    pub dwc_pump_hook: u32,
}

const _: () = {
    assert!(offset_of!(DeskInfoHead32, aphk_start) == 0x10);
    assert!(offset_of!(DeskInfoHead32, task_man_window) == 0x90);
    assert!(offset_of!(DeskInfoHead32, ppi_shell_process) == 0xA4);
    // szDesktopName follows, at 0xAC; sizeof(DESKTOPINFO) is 0xB0.
    assert!(size_of::<DeskInfoHead32>() == 0xAC);
    assert!(offset_of!(ClientThreadInfo32, time_last_read) == 0x0C);
    assert!(size_of::<ClientThreadInfo32>() == 0x14);
    assert!(size_of::<UserHandleEntry32>() == 12);
    assert!(size_of::<UserHandleTable32>() == 16);
    assert!(size_of::<WndMsg32>() == 8);
    assert!(offset_of!(SharedInfo32, shared_delta) == 0x0C);
    assert!(offset_of!(SharedInfo32, aw_control) == 0x10);
    assert!(offset_of!(SharedInfo32, def_window_msgs) == 0x108);
    assert!(size_of::<SharedInfo32>() == 0x118);
    assert!(offset_of!(UserConnect32, si_client) == 0x0C);
    // C_ASSERT(sizeof(USERCONNECT) == 0x124) in ntuser.h.
    assert!(size_of::<UserConnect32>() == 0x124);
    assert!(offset_of!(ServerInfoHead32, mp_fnid_pfn) == 0x08);
    assert!(offset_of!(ServerInfoHead32, a_sto_cid_pfn) == 0x84);
    assert!(offset_of!(ServerInfoHead32, mp_fnid_server_cb_wnd_proc) == 0xA0);
    assert!(offset_of!(ServerInfoHead32, padding) == 0xDE);
    assert!(offset_of!(ServerInfoHead32, apfn_client_a) == 0xE0);
    assert!(offset_of!(ServerInfoHead32, apfn_client_w) == 0x13C);
    assert!(offset_of!(ServerInfoHead32, apfn_client_worker) == 0x198);
    assert!(offset_of!(ServerInfoHead32, cb_handle_table) == 0x1C4);
    assert!(size_of::<ServerInfoHead32>() == 0x1C8);
    assert!(size_of::<Msg32>() == 28);
    assert!(offset_of!(ClientInfo32, ti_flags) == 0x14);
    assert!(offset_of!(ClientInfo32, desk_info) == 0x18);
    assert!(offset_of!(ClientInfo32, callback_wnd) == 0x28);
    assert!(offset_of!(ClientInfo32, client_thread_info) == 0x3C);
    assert!(offset_of!(ClientInfo32, hkl) == 0x64);
    assert!(offset_of!(ClientInfo32, code_page) == 0x68);
    assert!(offset_of!(ClientInfo32, msg_dbcs_cb) == 0x6C);
    assert!(offset_of!(ClientInfo32, registered_classes) == 0x88);
    assert!(offset_of!(ClientInfo32, ppi) == 0xF4);
    // The 62 words of the TEB's Win32ClientInfo.
    assert!(size_of::<ClientInfo32>() == 62 * 4);
};

/// `as_bytes` for records of integers whose sizes, checked above, leave no
/// padding.
macro_rules! as_bytes {
    ($($record:ty),*) => {$(
        impl $record {
            /// Its bytes, as they go to user mode or to the shared section.
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: a `#[repr(C)]` record of integers without padding
                // (its size is checked above): every byte is initialised.
                unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
            }
        }
    )*};
}

as_bytes!(
    UserHandleEntry32,
    UserHandleTable32,
    SharedInfo32,
    UserConnect32,
    ServerInfoHead32,
    ClientInfo32,
    DeskInfoHead32,
    ClientThreadInfo32
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_info_is_its_bytes() {
        let info = ClientInfo32 { ppi: 0xBC00_1234, ti_flags: TIF_CSRSSTHREAD, ..ClientInfo32::default() };
        let bytes = info.as_bytes();
        assert_eq!(bytes.len(), 0xF8);
        assert_eq!(&bytes[0xF4..], &0xBC00_1234u32.to_le_bytes());
        assert_eq!(&bytes[0x14..0x18], &8u32.to_le_bytes());
    }
}
