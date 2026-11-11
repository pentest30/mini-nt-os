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

// CONSOLECONTROL: what consrv asks of NtUserConsoleControl.
/// The console input thread of a desktop (DESKTOP_CONSOLE_THREAD).
pub const CONSOLE_CTRL_DESKTOP_CONSOLE_THREAD: u32 = 0;
/// The atom of the console window class (an ATOM).
pub const GUI_CONSOLE_WND_CLASS_ATOM: u32 = 1;
/// A palette of consrv made public (an HPALETTE).
pub const CONSOLE_MAKE_PALETTE_PUBLIC: u32 = 5;
/// The display taken for a full-screen console.
pub const CONSOLE_ACQUIRE_DISPLAY_OWNERSHIP: u32 = 6;

/// DESKTOP_CONSOLE_THREAD: a desktop and the ID of its console input thread
/// (`INVALID_HANDLE_VALUE` to only read it); win32k gives back the previous
/// one.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DesktopConsoleThread32 {
    pub desktop_handle: u32,
    pub thread_id: u32,
}

/// KLF_*: how LoadKeyboardLayout loads a layout.
pub const KLF_ACTIVATE: u32 = 0x0001;
pub const KLF_SUBSTITUTE_OK: u32 = 0x0002;
pub const KLF_UNLOADPREVIOUS: u32 = 0x0004;
pub const KLF_REORDER: u32 = 0x0008;
pub const KLF_REPLACELANG: u32 = 0x0010;
pub const KLF_NOTELLSHELL: u32 = 0x0080;
pub const KLF_SETFORPROCESS: u32 = 0x0100;
pub const KLF_SHIFTLOCK: u32 = 0x0001_0000;
pub const KLF_RESET: u32 = 0x4000_0000;
/// KL_NAMELENGTH: a layout's name (KLID, 8 hexadecimal digits) and its NUL.
pub const KL_NAMELENGTH: usize = 9;

/// The routines of `user32`'s `PEB.KernelCallbackTable` that win32k calls
/// back (USER32_CALLBACK_*, `u32cb.h` of ReactOS): ClientThreadSetup.
pub const USER32_CALLBACK_CLIENTTHREADSTARTUP: u32 = 7;
/// GetCharsetInfo: TranslateCharsetInfo(`TCI_SRCLOCALE`) for a locale.
pub const USER32_CALLBACK_GETCHARSETINFO: u32 = 9;
/// LoadMenu: LoadMenuW of a menu resource of a module (co_IntCallLoadMenu),
/// the argument a LOADMENU_CALLBACK_ARGUMENTS (the module, an identifier,
/// or 0 and the name from offset 8), the result the menu's handle.
pub const USER32_CALLBACK_LOADMENU: u32 = 6;
/// ANSI_CHARSET.
pub const ANSI_CHARSET: u32 = 0;
/// FS_LATIN1: the font signature of code page 1252.
pub const FS_LATIN1: u32 = 0x0000_0001;
/// CP_ACP: the system's ANSI code page.
pub const CP_ACP: u32 = 0;

/// CHARSETINFO: a character set, its ANSI code page, its font signature
/// (FONTSIGNATURE: `fsUsb[4]`, `fsCsb[2]`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CharsetInfo32 {
    pub charset: u32,
    pub ansi_code_page: u32,
    pub unicode_subset: [u32; 4],
    pub code_page_bits: [u32; 2],
}

/// GET_CHARSET_INFO: the argument and the result of the GetCharsetInfo
/// callback.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetCharsetInfo32 {
    pub locale: u32,
    pub charset_info: CharsetInfo32,
}

const _: () = {
    assert!(size_of::<CharsetInfo32>() == 0x20);
    assert!(offset_of!(CharsetInfo32, code_page_bits) == 0x18);
    assert!(size_of::<GetCharsetInfo32>() == 0x24);
    assert!(offset_of!(GetCharsetInfo32, charset_info) == 4);
};

impl GetCharsetInfo32 {
    /// The record in `bytes`, as the callback leaves it; `None` if they are
    /// too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let words: [u32; 9] = core::array::from_fn(|i| {
            bytes.get(4 * i..4 * i + 4).map_or(0, |w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        });
        (bytes.len() >= size_of::<Self>()).then_some(Self {
            locale: words[0],
            charset_info: CharsetInfo32 {
                charset: words[1],
                ansi_code_page: words[2],
                unicode_subset: [words[3], words[4], words[5], words[6]],
                code_page_bits: [words[7], words[8]],
            },
        })
    }
}

/// SM_CMETRICS: the system metrics in `SERVERINFO.aiSysMet` (those of
/// `_WIN32_WINNT` 0x0600, as the pinned `user32` was built: its
/// GetSystemMetrics answers indices up to 92).
pub const SM_CMETRICS: usize = 93;
/// NUM_SYSCOLORS: the system colours, `COLOR_SCROLLBAR` to `COLOR_MENUBAR`.
pub const NUM_SYSCOLORS: usize = 31;
/// ICLS_NOTUSED: the window classes of `SERVERINFO.atomSysClass` (one more
/// slot follows them).
pub const ICLS_NOTUSED: usize = 25;
/// MAX_MB_STRINGS: the message box button strings in `SERVERINFO`.
pub const MAX_MB_STRINGS: usize = 11;

/// SM_*, indices in `aiSysMet` (GetSystemMetrics).
pub mod sm {
    pub const CXSCREEN: usize = 0;
    pub const CYSCREEN: usize = 1;
    pub const CXVSCROLL: usize = 2;
    pub const CYHSCROLL: usize = 3;
    pub const CYCAPTION: usize = 4;
    pub const CXBORDER: usize = 5;
    pub const CYBORDER: usize = 6;
    pub const CXDLGFRAME: usize = 7;
    pub const CYDLGFRAME: usize = 8;
    pub const CYVTHUMB: usize = 9;
    pub const CXHTHUMB: usize = 10;
    pub const CXICON: usize = 11;
    pub const CYICON: usize = 12;
    pub const CXCURSOR: usize = 13;
    pub const CYCURSOR: usize = 14;
    pub const CYMENU: usize = 15;
    pub const CXFULLSCREEN: usize = 16;
    pub const CYFULLSCREEN: usize = 17;
    pub const CYKANJIWINDOW: usize = 18;
    pub const MOUSEPRESENT: usize = 19;
    pub const CYVSCROLL: usize = 20;
    pub const CXHSCROLL: usize = 21;
    pub const DEBUG: usize = 22;
    pub const SWAPBUTTON: usize = 23;
    pub const CXMIN: usize = 28;
    pub const CYMIN: usize = 29;
    pub const CXSIZE: usize = 30;
    pub const CYSIZE: usize = 31;
    pub const CXFRAME: usize = 32;
    pub const CYFRAME: usize = 33;
    pub const CXMINTRACK: usize = 34;
    pub const CYMINTRACK: usize = 35;
    pub const CXDOUBLECLK: usize = 36;
    pub const CYDOUBLECLK: usize = 37;
    pub const CXICONSPACING: usize = 38;
    pub const CYICONSPACING: usize = 39;
    pub const MENUDROPALIGNMENT: usize = 40;
    pub const PENWINDOWS: usize = 41;
    pub const DBCSENABLED: usize = 42;
    pub const CMOUSEBUTTONS: usize = 43;
    pub const SECURE: usize = 44;
    pub const CXEDGE: usize = 45;
    pub const CYEDGE: usize = 46;
    pub const CXMINSPACING: usize = 47;
    pub const CYMINSPACING: usize = 48;
    pub const CXSMICON: usize = 49;
    pub const CYSMICON: usize = 50;
    pub const CYSMCAPTION: usize = 51;
    pub const CXSMSIZE: usize = 52;
    pub const CYSMSIZE: usize = 53;
    pub const CXMENUSIZE: usize = 54;
    pub const CYMENUSIZE: usize = 55;
    pub const ARRANGE: usize = 56;
    pub const CXMINIMIZED: usize = 57;
    pub const CYMINIMIZED: usize = 58;
    pub const CXMAXTRACK: usize = 59;
    pub const CYMAXTRACK: usize = 60;
    pub const CXMAXIMIZED: usize = 61;
    pub const CYMAXIMIZED: usize = 62;
    pub const NETWORK: usize = 63;
    pub const CLEANBOOT: usize = 67;
    pub const CXDRAG: usize = 68;
    pub const CYDRAG: usize = 69;
    pub const SHOWSOUNDS: usize = 70;
    pub const CXMENUCHECK: usize = 71;
    pub const CYMENUCHECK: usize = 72;
    pub const SLOWMACHINE: usize = 73;
    pub const MIDEASTENABLED: usize = 74;
    pub const MOUSEWHEELPRESENT: usize = 75;
    pub const XVIRTUALSCREEN: usize = 76;
    pub const YVIRTUALSCREEN: usize = 77;
    pub const CXVIRTUALSCREEN: usize = 78;
    pub const CYVIRTUALSCREEN: usize = 79;
    pub const CMONITORS: usize = 80;
    pub const SAMEDISPLAYFORMAT: usize = 81;
    pub const IMMENABLED: usize = 82;
    pub const CXFOCUSBORDER: usize = 83;
    pub const CYFOCUSBORDER: usize = 84;
    pub const TABLETPC: usize = 86;
    pub const MEDIACENTER: usize = 87;
    pub const STARTER: usize = 88;
    pub const SERVERR2: usize = 89;
    pub const MOUSEHORIZONTALWHEELPRESENT: usize = 91;
    pub const CXPADDEDBORDER: usize = 92;
}

/// MBSTRING: a message box button's string, its identifier and its
/// string resource.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MbString32 {
    pub name: [u16; 16],
    pub id: u32,
    pub string: u32,
}

/// SERVERINFO up to `hbrGray` of `PERUSERSERVERINFO` (the rest follows,
/// zero until written): what [`ServerInfoHead32`] holds, the system
/// classes' atoms, … then the system metrics (`aiSysMet`), colours, their
/// brushes and the gray brush. The offsets of `aiSysMet`, `argbSystem`,
/// `ahbrSystem` and `hbrGray` are those the pinned `user32` reads
/// (GetSystemMetrics, GetSysColor, GetSysColorBrush, DrawFocusRect).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerInfo32 {
    pub head: ServerInfoHead32,
    pub atom_sys_class: [u16; ICLS_NOTUSED + 1],
    pub default_heap_base: u32,
    pub default_heap_size: u32,
    pub shell_msg: u32,
    pub mb_strings: [MbString32; MAX_MB_STRINGS],
    pub atom_icon_sm_prop: u16,
    pub atom_icon_prop: u16,
    pub atom_context_help_id_prop: u16,
    pub atom_frosted_window_prop: u16,
    pub oem_to_ansi: [u8; 256],
    pub ansi_to_oem: [u8; 256],
    pub installed_event_hooks: u32,
    /// PERUSERSERVERINFO from here.
    pub sys_met: [i32; SM_CMETRICS],
    pub argb_system_unmatched: [u32; NUM_SYSCOLORS],
    pub argb_system: [u32; NUM_SYSCOLORS],
    /// The system colours' brushes (GetSysColorBrush), stock objects.
    pub ahbr_system: [u32; NUM_SYSCOLORS],
    /// The gray brush: a 0x55AA monochrome pattern, one pixel in two, a
    /// stock object (DrawFocusRect, the background of a scroll bar).
    pub hbr_gray: u32,
}

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

/// FIRST_USER_HANDLE: the low word of the handle of entry 0; entry `i` is
/// `FIRST_USER_HANDLE + 2 i`, its generation in the high word.
pub const FIRST_USER_HANDLE: u32 = 0x0020;
/// TYPE_WINDOW: a handle entry of a window (`HANDLE_TYPE`).
pub const TYPE_WINDOW: u8 = 1;

/// TYPE_MENU: a handle entry of a menu (`HANDLE_TYPE`).
pub const TYPE_MENU: u8 = 2;

/// FNID_*: the window function identifiers of the system classes; those
/// up to `FNID_SWITCH` have a server procedure.
pub const FNID_SCROLLBAR: u32 = 0x029A;
pub const FNID_ICONTITLE: u32 = 0x029B;
pub const FNID_MENU: u32 = 0x029C;
/// FNID_DESKTOP: the function identifier of the desktop window.
pub const FNID_DESKTOP: u32 = 0x029D;
pub const FNID_MESSAGEWND: u32 = 0x029F;
pub const FNID_SWITCH: u32 = 0x02A0;
pub const FNID_BUTTON: u32 = 0x02A1;
/// FNID_DIALOG: a dialog (SetDialogPointer, DefDlgProc).
pub const FNID_DIALOG: u32 = 0x02A4;
/// DLGWINDOWEXTRA: the extra bytes of a dialog's window (the dialog
/// class's), the least SetDialogPointer accepts.
pub const DLGWINDOWEXTRA: u32 = 30;
pub const FNID_GHOST: u32 = 0x02AA;
/// FNID_SENDMESSAGE, FNID_SENDMESSAGEWTOOPTION, FNID_SENDNOTIFYMESSAGE: the
/// kinds of NtUserMessageCall behind SendMessage, SendMessageTimeout (its
/// `ResultInfo` a DOSENDMESSAGE) and SendNotifyMessage (read from the pinned
/// `user32`).
pub const FNID_SENDMESSAGE: u32 = 0x02B1;
pub const FNID_SENDMESSAGEWTOOPTION: u32 = 0x02B3;
pub const FNID_SENDNOTIFYMESSAGE: u32 = 0x02B7;
/// FNID_DESTROY: set on a window being destroyed.
pub const FNID_DESTROY: u32 = 0x4000;
/// FNID_FREED: set on a window once destroyed (co_UserFreeWindow); no
/// message reaches it any more.
pub const FNID_FREED: u32 = 0x8000;
/// The desktop window's class, an integer atom (`WC_DESKTOP`, `#32769`).
pub const WC_DESKTOP: u16 = 0x8001;
/// The other system classes named by an integer atom: menus (`#32768`),
/// the task switch window (`#32771`), icon titles (`#32772`).
pub const WC_MENU: u16 = 0x8000;
pub const WC_SWITCH: u16 = 0x8003;
pub const WC_ICONTITLE: u16 = 0x8004;
/// CS_*, class styles: CS_DBLCLKS, and CS_GLOBALCLASS (an application
/// global class, found whatever the instance).
pub const CS_DBLCLKS: u32 = 0x0008;
pub const CS_GLOBALCLASS: u32 = 0x4000;
/// CSF_ANSIPROC: the class procedure takes ANSI messages.
pub const CSF_ANSIPROC: u32 = 0x0002;
/// CSF_WOWDEFERDESTROY: a class whose destruction waits for its windows.
pub const CSF_WOWDEFERDESTROY: u32 = 0x0004;

/// WNDCLASSEXW, 32-bit: what RegisterClassEx gives win32k.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WndClassExW32 {
    pub size: u32,
    pub style: u32,
    pub wnd_proc: u32,
    pub cls_extra: i32,
    pub wnd_extra: i32,
    pub instance: u32,
    pub icon: u32,
    pub cursor: u32,
    pub background: u32,
    pub menu_name: u32,
    pub class_name: u32,
    pub icon_sm: u32,
}

/// CLSMENUNAME, 32-bit: a class's menu name, as `user32` keeps it (ANSI and
/// Unicode, in the client), and its `UNICODE_STRING`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClsMenuName32 {
    pub client_ansi: u32,
    pub client_unicode: u32,
    pub us_menu_name: u32,
}

const _: () = {
    assert!(size_of::<WndClassExW32>() == 0x30);
    assert!(offset_of!(WndClassExW32, menu_name) == 0x24);
    assert!(size_of::<ClsMenuName32>() == 12);
};

/// WNDS_*, `WND.state`.
pub const WNDS_SENDERASEBACKGROUND: u32 = 0x0000_0200;
pub const WNDS_ERASEBACKGROUND: u32 = 0x0000_0400;
/// WNDS_SERVERSIDEWINDOWPROC: its window procedure runs in win32k.
pub const WNDS_SERVERSIDEWINDOWPROC: u32 = 0x0004_0000;
/// WNDS_DIALOGWINDOW: a dialog, its DIALOGINFO in `DialogPointer`.
pub const WNDS_DIALOGWINDOW: u32 = 0x0001_0000;
/// CSF_*, `CLS.CSF_flags`.
pub const CSF_SERVERSIDEPROC: u32 = 0x0001;
pub const CSF_SYSTEMCLASS: u32 = 0x0008;
/// CLS bits: Unicode, Global, MenuNameIsString.
pub const CLS_UNICODE: u32 = 0x1;
pub const CLS_GLOBAL: u32 = 0x2;
pub const CLS_MENU_NAME_IS_STRING: u32 = 0x4;

/// WNDS_HAS*: what WM_NCCALCSIZE found in the non-client area.
pub const WNDS_HASMENU: u32 = 0x0000_0001;
pub const WNDS_HASVERTICALSCROOLLBAR: u32 = 0x0000_0002;
pub const WNDS_HASHORIZONTALSCROLLBAR: u32 = 0x0000_0004;
pub const WNDS_HASCAPTION: u32 = 0x0000_0008;
/// WNDS_ACTIVEFRAME: the frame is painted active (WM_NCACTIVATE).
pub const WNDS_ACTIVEFRAME: u32 = 0x0000_0040;
/// WVR_*: what WM_NCCALCSIZE with valid rectangles answers.
pub const WVR_HREDRAW: u32 = 0x0100;
pub const WVR_VREDRAW: u32 = 0x0200;
pub const WVR_VALIDRECTS: u32 = 0x0400;
/// CS_VREDRAW, CS_HREDRAW: redraw the whole window when its height (width)
/// changes.
pub const CS_VREDRAW: u32 = 0x0001;
pub const CS_HREDRAW: u32 = 0x0002;
/// CS_OWNDC, CS_CLASSDC: each window (the class) has a DC of its own;
/// CS_PARENTDC: a child draws with its parent's DC.
pub const CS_OWNDC: u32 = 0x0020;
pub const CS_CLASSDC: u32 = 0x0040;
pub const CS_PARENTDC: u32 = 0x0080;
/// DCX_*: what GetDCEx gives (the window or its client area) and how it
/// clips it.
pub const DCX_WINDOW: u32 = 0x0000_0001;
pub const DCX_CACHE: u32 = 0x0000_0002;
pub const DCX_NORESETATTRS: u32 = 0x0000_0004;
pub const DCX_CLIPCHILDREN: u32 = 0x0000_0008;
pub const DCX_CLIPSIBLINGS: u32 = 0x0000_0010;
pub const DCX_PARENTCLIP: u32 = 0x0000_0020;
pub const DCX_EXCLUDERGN: u32 = 0x0000_0040;
pub const DCX_INTERSECTRGN: u32 = 0x0000_0080;
pub const DCX_EXCLUDEUPDATE: u32 = 0x0000_0100;
pub const DCX_INTERSECTUPDATE: u32 = 0x0000_0200;
pub const DCX_LOCKWINDOWUPDATE: u32 = 0x0000_0400;
/// DCX_USESTYLE: clip by the window's and its class's styles.
pub const DCX_USESTYLE: u32 = 0x0001_0000;
/// DCX_KEEPCLIPRGN: the clip region stays the caller's.
pub const DCX_KEEPCLIPRGN: u32 = 0x0004_0000;
/// DCX_NOCLIPCHILDREN: from the cache, without clipping the children.
pub const DCX_NOCLIPCHILDREN: u32 = 0x0008_0000;
/// RDW_*: what RedrawWindow does. RDW_CLIPCHILDREN and RDW_NOUPDATEDIRTY are
/// win32k's own.
pub const RDW_INVALIDATE: u32 = 0x0001;
pub const RDW_INTERNALPAINT: u32 = 0x0002;
pub const RDW_ERASE: u32 = 0x0004;
pub const RDW_VALIDATE: u32 = 0x0008;
pub const RDW_NOINTERNALPAINT: u32 = 0x0010;
pub const RDW_NOERASE: u32 = 0x0020;
pub const RDW_NOCHILDREN: u32 = 0x0040;
pub const RDW_ALLCHILDREN: u32 = 0x0080;
pub const RDW_UPDATENOW: u32 = 0x0100;
pub const RDW_ERASENOW: u32 = 0x0200;
pub const RDW_FRAME: u32 = 0x0400;
pub const RDW_NOFRAME: u32 = 0x0800;
pub const RDW_CLIPCHILDREN: u32 = 0x1000;
pub const RDW_NOUPDATEDIRTY: u32 = 0x8000;
/// The flags RedrawWindow accepts (the others: ERROR_INVALID_FLAGS).
pub const RDW_VALID_FLAGS: u32 = RDW_ERASE
    | RDW_FRAME
    | RDW_INTERNALPAINT
    | RDW_INVALIDATE
    | RDW_NOERASE
    | RDW_NOFRAME
    | RDW_NOINTERNALPAINT
    | RDW_VALIDATE
    | RDW_ERASENOW
    | RDW_UPDATENOW
    | RDW_ALLCHILDREN
    | RDW_NOCHILDREN;
/// HWNDLOCK_ROUTINE_UPDATEWINDOW: the routine of NtUserCallHwndLock behind
/// UpdateWindow (user32!UpdateWindow pushes 0x5E).
pub const HWNDLOCK_ROUTINE_UPDATEWINDOW: u32 = 0x5E;
/// HWNDLOCK_ROUTINE_DRAWMENUBAR: DrawMenuBar, by NtUserCallHwndLock (XP's
/// order of the enum, as the routines above).
pub const HWNDLOCK_ROUTINE_DRAWMENUBAR: u32 = 0x55;

/// SPI_*: the actions of SystemParametersInfo that win32k answers.
/// SPI_GETICONTITLELOGFONT: the font of the icon titles (`pvParam` a
/// LOGFONTW of `uiParam` bytes), the ListView's default font.
pub const SPI_GETICONTITLELOGFONT: u32 = 0x001F;
/// SPI_GETNONCLIENTMETRICS: fills a NONCLIENTMETRICSW (`uiParam` its size
/// or 0, `pvParam` it, its `cbSize` set).
pub const SPI_GETNONCLIENTMETRICS: u32 = 0x0029;
/// SPI_GETFOCUSBORDERWIDTH: the width of the sides of a focus rectangle
/// (`pvParam` a UINT), which DrawFocusRect reads.
pub const SPI_GETFOCUSBORDERWIDTH: u32 = 0x200E;
/// SPI_GETFOCUSBORDERHEIGHT: the height of its top and bottom.
pub const SPI_GETFOCUSBORDERHEIGHT: u32 = 0x2010;

/// NONCLIENTMETRICSW: the sizes of the frames, captions, menus and scroll
/// bars, and the system's fonts.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonClientMetricsW32 {
    pub cb_size: u32,
    pub border_width: i32,
    pub scroll_width: i32,
    pub scroll_height: i32,
    pub caption_width: i32,
    pub caption_height: i32,
    pub caption_font: crate::gdi::LogFontW32,
    pub sm_caption_width: i32,
    pub sm_caption_height: i32,
    pub sm_caption_font: crate::gdi::LogFontW32,
    pub menu_width: i32,
    pub menu_height: i32,
    pub menu_font: crate::gdi::LogFontW32,
    pub status_font: crate::gdi::LogFontW32,
    pub message_font: crate::gdi::LogFontW32,
}

const _: () = {
    assert!(size_of::<NonClientMetricsW32>() == 500);
    assert!(offset_of!(NonClientMetricsW32, caption_font) == 24);
    assert!(offset_of!(NonClientMetricsW32, sm_caption_font) == 124);
    assert!(offset_of!(NonClientMetricsW32, menu_font) == 224);
    assert!(offset_of!(NonClientMetricsW32, message_font) == 408);
};
/// HWNDPARAM_ROUTINE_KILLSYSTEMTIMER: the routine of NtUserCallHwndParam
/// behind KillSystemTimer (read from the pinned `user32`).
pub const HWNDPARAM_ROUTINE_KILLSYSTEMTIMER: u32 = 0x4E;
/// HWNDPARAM_ROUTINE_SETDIALOGPOINTER: the routine behind `user32`'s
/// SETDLGINFO, which gives a dialog its DIALOGINFO (the next one).
pub const HWNDPARAM_ROUTINE_SETDIALOGPOINTER: u32 = 0x4F;
/// FNID_DEFWINDOWPROC: NtUserMessageCall's DefWindowProc.
pub const FNID_DEFWINDOWPROC: u32 = 0x029E;
/// WM_USER: the first message of an application.
pub const WM_USER: u32 = 0x0400;

/// MINMAXINFO, 32-bit: five points (x, y), `ptReserved` first.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinMaxInfo32 {
    pub reserved: [i32; 2],
    pub max_size: [i32; 2],
    pub max_position: [i32; 2],
    pub min_track_size: [i32; 2],
    pub max_track_size: [i32; 2],
}

const _: () = assert!(size_of::<MinMaxInfo32>() == 40);

/// WINDOWPOS, 32-bit: what WM_WINDOWPOSCHANGING and WM_WINDOWPOSCHANGED
/// carry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowPos32 {
    pub hwnd: u32,
    pub insert_after: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub flags: u32,
}

/// NCCALCSIZE_PARAMS, 32-bit: three rectangles (left, top, right, bottom),
/// then the address of a WINDOWPOS (packed after it in a message).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NcCalcSizeParams32 {
    pub rects: [[i32; 4]; 3],
    pub pos: u32,
}

/// MONITORINFO, 32-bit; MONITORINFOEXW adds the device name
/// (`CCHDEVICENAME` characters).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonitorInfo32 {
    pub size: u32,
    pub monitor: [i32; 4],
    pub work: [i32; 4],
    pub flags: u32,
}

/// CCHDEVICENAME: the characters of a display device name.
pub const CCHDEVICENAME: usize = 32;
/// The size of MONITORINFOEXW.
pub const MONITORINFOEXW_SIZE: u32 = size_of::<MonitorInfo32>() as u32 + 2 * CCHDEVICENAME as u32;
/// MONITORINFOF_PRIMARY: the primary monitor.
pub const MONITORINFOF_PRIMARY: u32 = 1;
/// MONITOR_DEFAULTTO*: what MonitorFromWindow gives outside the monitors.
pub const MONITOR_DEFAULTTONULL: u32 = 0;
pub const MONITOR_DEFAULTTOPRIMARY: u32 = 1;
pub const MONITOR_DEFAULTTONEAREST: u32 = 2;
/// TYPE_MONITOR: a handle entry of a monitor (`HANDLE_TYPE`).
pub const TYPE_MONITOR: u8 = 12;

const _: () = {
    assert!(size_of::<WindowPos32>() == 28);
    assert!(size_of::<NcCalcSizeParams32>() == 52);
    assert!(offset_of!(NcCalcSizeParams32, pos) == 48);
    assert!(size_of::<MonitorInfo32>() == 40);
    assert!(MONITORINFOEXW_SIZE == 104);
};

/// SWP_*, SetWindowPos flags; SWP_NOCLIENTSIZE, SWP_NOCLIENTMOVE and
/// SWP_STATECHANGED are win32k's own (ReactOS `undocuser.h`).
pub const SWP_NOSIZE: u32 = 0x0001;
pub const SWP_NOMOVE: u32 = 0x0002;
pub const SWP_NOZORDER: u32 = 0x0004;
pub const SWP_NOREDRAW: u32 = 0x0008;
pub const SWP_NOACTIVATE: u32 = 0x0010;
pub const SWP_FRAMECHANGED: u32 = 0x0020;
pub const SWP_SHOWWINDOW: u32 = 0x0040;
pub const SWP_HIDEWINDOW: u32 = 0x0080;
pub const SWP_NOCOPYBITS: u32 = 0x0100;
pub const SWP_NOOWNERZORDER: u32 = 0x0200;
pub const SWP_NOSENDCHANGING: u32 = 0x0400;
pub const SWP_NOCLIENTSIZE: u32 = 0x0800;
pub const SWP_NOCLIENTMOVE: u32 = 0x1000;
pub const SWP_DEFERERASE: u32 = 0x2000;
pub const SWP_ASYNCWINDOWPOS: u32 = 0x4000;
pub const SWP_STATECHANGED: u32 = 0x8000;
/// HWND_*, the places SetWindowPos takes in the Z order besides a sibling.
pub const HWND_TOP: u32 = 0;
pub const HWND_BOTTOM: u32 = 1;
pub const HWND_TOPMOST: u32 = 0xFFFF_FFFF;
pub const HWND_NOTOPMOST: u32 = 0xFFFF_FFFE;
/// STARTF_*, the `WindowFlags` of the process parameters that give the
/// first overlapped window its show command, place and size.
pub const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
pub const STARTF_USESIZE: u32 = 0x0000_0002;
pub const STARTF_USEPOSITION: u32 = 0x0000_0004;

/// WNDS_SENDSIZEMOVEMSGS: WM_SIZE and WM_MOVE wait for the window to be
/// shown (an overlapped window).
pub const WNDS_SENDSIZEMOVEMSGS: u32 = 0x0000_0010;
/// WNDS_SENDNCPAINT: the frame is to be painted (WM_NCPAINT).
pub const WNDS_SENDNCPAINT: u32 = 0x0000_0800;
/// WNDS_INTERNALPAINT: WM_PAINT asked without anything to paint
/// (RDW_INTERNALPAINT); WNDS_UPDATEDIRTY: invalidated again while painting.
pub const WNDS_INTERNALPAINT: u32 = 0x0000_1000;
pub const WNDS_UPDATEDIRTY: u32 = 0x0000_2000;
/// WNDS_PAINTNOTPROCESSED: WM_PAINT dispatched, BeginPaint not called yet.
pub const WNDS_PAINTNOTPROCESSED: u32 = 0x0040_0000;
/// WNDS_MAXIMIZESTOMONITOR: maximized, it covers its monitor.
pub const WNDS_MAXIMIZESTOMONITOR: u32 = 0x4000_0000;
/// WNDS_DESTROYED: the window is destroyed, after its WM_NCDESTROY; no
/// message reaches it any more (`user32`'s IsWindow reads it).
pub const WNDS_DESTROYED: u32 = 0x8000_0000;
/// WNDS_ANSIWINDOWPROC: its procedure takes ANSI messages.
pub const WNDS_ANSIWINDOWPROC: u32 = 0x0008_0000;
/// WNDS_ANSICREATOR: created by CreateWindowExA.
pub const WNDS_ANSICREATOR: u32 = 0x2000_0000;
/// WNDS2_*, `WND.state2`: the version its module expects, and WM_CREATE
/// processed.
pub const WNDS2_WIN31COMPAT: u32 = 0x0000_0100;
pub const WNDS2_WIN40COMPAT: u32 = 0x0000_0200;
pub const WNDS2_WIN50COMPAT: u32 = 0x0000_0400;
pub const WNDS2_WMCREATEMSGPROCESSED: u32 = 0x8000_0000;
/// WNDS2_WMPAINTSENT: WM_PAINT given to the window; WNDS2_ENDPAINTINVALIDATE:
/// invalidated by another thread while painting; WNDS2_STARTPAINT: between
/// BeginPaint and EndPaint.
pub const WNDS2_WMPAINTSENT: u32 = 0x0000_0001;
pub const WNDS2_ENDPAINTINVALIDATE: u32 = 0x0000_0002;
pub const WNDS2_STARTPAINT: u32 = 0x0000_0004;
/// WNDS2_INDESTROY: its destruction has begun (co_UserFreeWindow).
pub const WNDS2_INDESTROY: u32 = 0x0000_0080;
/// The `WND.bits` of a Unicode window.
pub const WND_UNICODE: u32 = 0x1;

/// WS_*, window styles.
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_MINIMIZE: u32 = 0x2000_0000;
pub const WS_DISABLED: u32 = 0x0800_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_CLIPSIBLINGS: u32 = 0x0400_0000;
pub const WS_CLIPCHILDREN: u32 = 0x0200_0000;
pub const WS_MAXIMIZE: u32 = 0x0100_0000;
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
pub const WS_VSCROLL: u32 = 0x0020_0000;
pub const WS_HSCROLL: u32 = 0x0010_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
/// WS_OVERLAPPEDWINDOW: a caption, a system menu, a sizing border and both
/// boxes.
pub const WS_OVERLAPPEDWINDOW: u32 = WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
/// WS_EX_*, extended window styles; WS_EX_SETANSICREATOR (ReactOS) marks
/// a window CreateWindowExA creates.
pub const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
pub const WS_EX_NOPARENTNOTIFY: u32 = 0x0000_0004;
pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_MDICHILD: u32 = 0x0000_0040;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
pub const WS_EX_LEFTSCROLLBAR: u32 = 0x0000_4000;
pub const WS_EX_LAYOUTRTL: u32 = 0x0040_0000;
pub const WS_EX_WINDOWEDGE: u32 = 0x0000_0100;
pub const WS_EX_STATICEDGE: u32 = 0x0002_0000;
pub const WS_EX_SETANSICREATOR: u32 = 0x8000_0000;
/// CW_USEDEFAULT: a default position or size.
pub const CW_USEDEFAULT: u32 = 0x8000_0000;
/// HWND_MESSAGE: the parent of message-only windows.
pub const HWND_MESSAGE: u32 = 0xFFFF_FFFD;
/// The expected Windows versions of a module (`WINVER`): 3.1, NT 4, 2000.
pub const WINVER_WIN31: u32 = 0x030A;
pub const WINVER_WINNT4: u32 = 0x0400;
pub const WINVER_WIN2K: u32 = 0x0500;
/// USER32_CALLBACK_WINDOWPROC: a window procedure of the client.
pub const USER32_CALLBACK_WINDOWPROC: u32 = 0;

/// CREATESTRUCTW, 32-bit; packed for WM_NCCREATE and WM_CREATE, its two
/// strings follow it and `name` and `class` are their offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateStructW32 {
    pub create_params: u32,
    pub instance: u32,
    pub menu: u32,
    pub parent: u32,
    pub cy: i32,
    pub cx: i32,
    pub y: i32,
    pub x: i32,
    pub style: u32,
    pub name: u32,
    pub class: u32,
    pub ex_style: u32,
}

/// WINDOWPROC_CALLBACK_ARGUMENTS: what win32k gives `user32` to call a
/// window procedure (USER32_CALLBACK_WINDOWPROC), followed by the
/// `lparam_buffer_size` bytes `lparam` designates (-1: none).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowProcArguments32 {
    pub proc: u32,
    pub is_ansi_proc: u32,
    pub wnd: u32,
    pub msg: u32,
    pub w_param: u32,
    pub l_param: u32,
    pub l_param_buffer_size: i32,
    pub result: u32,
}

const _: () = {
    assert!(size_of::<CreateStructW32>() == 0x30);
    assert!(offset_of!(CreateStructW32, name) == 0x24);
    assert!(size_of::<WindowProcArguments32>() == 0x20);
    assert!(offset_of!(WindowProcArguments32, result) == 0x1C);
};

/// WM_*, window messages.
pub const WM_CREATE: u32 = 0x0001;
/// WM_DESTROY: sent to a window, then to its children, before they go;
/// WM_NCDESTROY: the last message of a window, its children's first.
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_PAINT: u32 = 0x000F;
/// WM_PAINTICON: WM_PAINT of a minimised window of a 3.x module.
pub const WM_PAINTICON: u32 = 0x0026;
/// WM_TIMER, WM_SYSTIMER: a timer's message, its procedure in `lParam`.
pub const WM_TIMER: u32 = 0x0113;
pub const WM_SYSTIMER: u32 = 0x0118;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_CHILDACTIVATE: u32 = 0x0022;
pub const WM_GETMINMAXINFO: u32 = 0x0024;
pub const WM_WINDOWPOSCHANGING: u32 = 0x0046;
pub const WM_WINDOWPOSCHANGED: u32 = 0x0047;
/// COLOR_*, the indices of the system colours (GetSysColor): `LIGHT_3D` is
/// COLOR_3DLIGHT, `DKSHADOW_3D` COLOR_3DDKSHADOW; COLOR_3DFACE is `BTNFACE`.
pub mod color {
    pub const SCROLLBAR: usize = 0;
    pub const BACKGROUND: usize = 1;
    pub const ACTIVECAPTION: usize = 2;
    pub const INACTIVECAPTION: usize = 3;
    pub const MENU: usize = 4;
    pub const WINDOW: usize = 5;
    pub const WINDOWFRAME: usize = 6;
    pub const MENUTEXT: usize = 7;
    pub const WINDOWTEXT: usize = 8;
    pub const CAPTIONTEXT: usize = 9;
    pub const ACTIVEBORDER: usize = 10;
    pub const INACTIVEBORDER: usize = 11;
    pub const APPWORKSPACE: usize = 12;
    pub const HIGHLIGHT: usize = 13;
    pub const HIGHLIGHTTEXT: usize = 14;
    pub const BTNFACE: usize = 15;
    pub const BTNSHADOW: usize = 16;
    pub const GRAYTEXT: usize = 17;
    pub const BTNTEXT: usize = 18;
    pub const INACTIVECAPTIONTEXT: usize = 19;
    pub const BTNHIGHLIGHT: usize = 20;
    pub const DKSHADOW_3D: usize = 21;
    pub const LIGHT_3D: usize = 22;
    pub const INFOTEXT: usize = 23;
    pub const INFOBK: usize = 24;
    pub const HOTLIGHT: usize = 26;
    pub const GRADIENTACTIVECAPTION: usize = 27;
    pub const GRADIENTINACTIVECAPTION: usize = 28;
    pub const MENUHILIGHT: usize = 29;
    pub const MENUBAR: usize = 30;
}

/// WM_CTLCOLORMSGBOX to WM_CTLCOLORSTATIC: a control asks its parent the
/// brush of its background (`wParam` the DC, `lParam` the control); the
/// CTLCOLOR_* type is the message's distance from WM_CTLCOLORMSGBOX.
pub const WM_CTLCOLORMSGBOX: u32 = 0x0132;
pub const WM_CTLCOLORSTATIC: u32 = 0x0138;
pub const CTLCOLOR_EDIT: u32 = 1;
pub const CTLCOLOR_LISTBOX: u32 = 2;
pub const CTLCOLOR_SCROLLBAR: u32 = 5;
/// CTLCOLOR_MAX: the number of CTLCOLOR_* types.
pub const CTLCOLOR_MAX: u32 = 7;

/// HRGN_WINDOW: the whole window, the `wParam` of WM_NCPAINT.
pub const HRGN_WINDOW: u32 = 1;
pub const WM_NCPAINT: u32 = 0x0085;
pub const WS_EX_TRANSPARENT: u32 = 0x0000_0020;
/// WNDS_NONCPAINT: no WM_NCPAINT until the frame is invalidated again.
pub const WNDS_NONCPAINT: u32 = 0x0000_0100;

/// SW_*, the commands of ShowWindow; SW_MAX the last one.
pub const SW_HIDE: u32 = 0;
pub const SW_SHOWNORMAL: u32 = 1;
pub const SW_SHOWMINIMIZED: u32 = 2;
pub const SW_SHOWMAXIMIZED: u32 = 3;
pub const SW_SHOWNOACTIVATE: u32 = 4;
pub const SW_SHOW: u32 = 5;
pub const SW_MINIMIZE: u32 = 6;
pub const SW_SHOWMINNOACTIVE: u32 = 7;
pub const SW_SHOWNA: u32 = 8;
pub const SW_RESTORE: u32 = 9;
pub const SW_SHOWDEFAULT: u32 = 10;
pub const SW_FORCEMINIMIZE: u32 = 11;
pub const SW_MAX: u32 = 11;

/// GWL_* and GWLP_*: the negative indices of SetWindowLong (a non-negative
/// index is an offset in the window's extra bytes).
pub const GWLP_WNDPROC: i32 = -4;
pub const GWLP_HINSTANCE: i32 = -6;
pub const GWLP_HWNDPARENT: i32 = -8;
pub const GWLP_ID: i32 = -12;
pub const GWL_STYLE: i32 = -16;
pub const GWL_EXSTYLE: i32 = -20;
pub const GWLP_USERDATA: i32 = -21;
/// SIZE_*, the `wParam` of WM_SIZE: restored, minimized, maximized.
pub const SIZE_RESTORED: u32 = 0;
pub const SIZE_MINIMIZED: u32 = 1;
pub const SIZE_MAXIMIZED: u32 = 2;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_PARENTNOTIFY: u32 = 0x0210;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_DEVICECHANGE: u32 = 0x0219;
/// The keyboard messages: a key down or up, the character it gives
/// (TranslateMessage), and their system variants (Alt down, F10).
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_DEADCHAR: u32 = 0x0103;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;
pub const WM_SYSDEADCHAR: u32 = 0x0107;
/// The first and last keyboard messages (a range of PeekMessage).
pub const WM_KEYFIRST: u32 = 0x0100;
pub const WM_KEYLAST: u32 = 0x0109;
/// The mouse messages in the client area: a move, a button down, up, a
/// second click (CS_DBLCLKS), the wheel. `wParam` holds MK_*, `lParam` the
/// point in the client area (the wheel: its amount in the high word of
/// `wParam`, the point on the screen in `lParam`).
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_RBUTTONDBLCLK: u32 = 0x0206;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MBUTTONDBLCLK: u32 = 0x0209;
pub const WM_MOUSEWHEEL: u32 = 0x020A;
pub const WM_MOUSEFIRST: u32 = 0x0200;
pub const WM_MOUSELAST: u32 = 0x020A;
/// The same outside the client area: `wParam` holds the hit code (HT*),
/// `lParam` the point on the screen. WM_NCLBUTTONDOWN is WM_LBUTTONDOWN
/// less this offset.
pub const WM_NCMOUSEMOVE: u32 = 0x00A0;
pub const WM_NC_MOUSE_OFFSET: u32 = WM_MOUSEMOVE - WM_NCMOUSEMOVE;
/// MK_*: the buttons and keys down, in `wParam`.
pub const MK_LBUTTON: u32 = 0x0001;
pub const MK_RBUTTON: u32 = 0x0002;
pub const MK_SHIFT: u32 = 0x0004;
pub const MK_CONTROL: u32 = 0x0008;
pub const MK_MBUTTON: u32 = 0x0010;
/// HT*: where a point falls in a window (WM_NCHITTEST).
/// HTTRANSPARENT (-1): the window lets the point through to the one under it.
pub const HTTRANSPARENT: u32 = u32::MAX;
pub const HTNOWHERE: u32 = 0;
pub const HTCLIENT: u32 = 1;
pub const HTCAPTION: u32 = 2;
pub const HTSYSMENU: u32 = 3;
pub const HTSIZE: u32 = 4;
pub const HTMENU: u32 = 5;
pub const HTHSCROLL: u32 = 6;
pub const HTVSCROLL: u32 = 7;
pub const HTMINBUTTON: u32 = 8;
pub const HTMAXBUTTON: u32 = 9;
pub const HTLEFT: u32 = 10;
pub const HTRIGHT: u32 = 11;
pub const HTTOP: u32 = 12;
pub const HTTOPLEFT: u32 = 13;
pub const HTTOPRIGHT: u32 = 14;
pub const HTBOTTOM: u32 = 15;
pub const HTBOTTOMLEFT: u32 = 16;
pub const HTBOTTOMRIGHT: u32 = 17;
pub const HTBORDER: u32 = 18;
pub const HTCLOSE: u32 = 20;
/// WM_NCHITTEST: `lParam` a point on the screen; the window answers HT*.
pub const WM_NCHITTEST: u32 = 0x0084;
/// WM_MOUSEACTIVATE: a button goes down in a window whose top-level window
/// is not active; `wParam` that top-level window, `lParam` the hit code and
/// the message; the answer is MA_*.
pub const WM_MOUSEACTIVATE: u32 = 0x0021;
pub const MA_ACTIVATE: u32 = 1;
pub const MA_ACTIVATEANDEAT: u32 = 2;
pub const MA_NOACTIVATE: u32 = 3;
pub const MA_NOACTIVATEANDEAT: u32 = 4;
/// WM_CAPTURECHANGED: the window loses the mouse capture; `lParam` the
/// window that takes it.
pub const WM_CAPTURECHANGED: u32 = 0x0215;
/// WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE: a move or size loop starts, ends.
pub const WM_ENTERSIZEMOVE: u32 = 0x0231;
pub const WM_EXITSIZEMOVE: u32 = 0x0232;
/// WM_CLOSE: the window is asked to close (DefWindowProc destroys it).
pub const WM_CLOSE: u32 = 0x0010;
/// WM_SYSCOMMAND: a command of the window menu or of the frame; `wParam`
/// SC_* in its upper 12 bits, `lParam` the point on the screen.
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const SC_SIZE: u32 = 0xF000;
pub const SC_MOVE: u32 = 0xF010;
pub const SC_MINIMIZE: u32 = 0xF020;
pub const SC_MAXIMIZE: u32 = 0xF030;
pub const SC_CLOSE: u32 = 0xF060;
/// A click on a scroll bar (plus HTVSCROLL or HTHSCROLL): `user32` follows
/// the mouse (DefWndTrackScrollBar).
pub const SC_VSCROLL: u32 = 0xF070;
pub const SC_HSCROLL: u32 = 0xF080;
/// A click on the menu bar (plus HTMENU, or HTSYSMENU for the window menu):
/// DefWindowProc tracks the bar (MENU_TrackMouseMenuBar).
pub const SC_MOUSEMENU: u32 = 0xF090;
/// The menu bar from the keyboard (Alt, F10, Alt and a letter in `lParam`):
/// MENU_TrackKbdMenuBar.
pub const SC_KEYMENU: u32 = 0xF100;
pub const SC_RESTORE: u32 = 0xF120;
/// WMSZ_*: the edge SC_SIZE drags, in the low 4 bits of `wParam`; WMSZ_LEFT
/// (1) to WMSZ_BOTTOMRIGHT (8) follow HTLEFT (10) to HTBOTTOMRIGHT (17).
pub const WMSZ_LEFT: u32 = 1;
pub const WMSZ_BOTTOMRIGHT: u32 = 8;
/// NOPARAM_ROUTINE_RELEASECAPTURE: ReleaseCapture, by NtUserCallNoParam
/// (user32!ReleaseCapture pushes 0xD).
pub const NOPARAM_ROUTINE_RELEASECAPTURE: u32 = 0x0D;
/// NOPARAM_ROUTINE_DESTROY_CARET: DestroyCaret (XP's order of the enum).
pub const NOPARAM_ROUTINE_DESTROY_CARET: u32 = 0x05;
/// ONEPARAM_ROUTINE_SETCARETBLINKTIME: SetCaretBlinkTime.
pub const ONEPARAM_ROUTINE_SETCARETBLINKTIME: u32 = 0x3B;
/// TWOPARAM_ROUTINE_SETCARETPOS: SetCaretPos.
pub const TWOPARAM_ROUTINE_SETCARETPOS: u32 = 0x6E;
/// IDCARETTIMER: the system timer that makes the caret blink.
pub const IDCARETTIMER: u32 = 0xFFFF;
/// ONEPARAM_ROUTINE_GETCURSORPOS: GetCursorPos, by NtUserCallOneParam with
/// the POINT (user32!GetCursorPos pushes 0x26).
pub const ONEPARAM_ROUTINE_GETCURSORPOS: u32 = 0x26;
/// THREADSTATE_*: what NtUserGetThreadState gives (user32!GetFocus pushes
/// 0, GetActiveWindow 1, GetCapture 2).
pub const THREADSTATE_FOCUSWINDOW: u32 = 0;
pub const THREADSTATE_ACTIVEWINDOW: u32 = 1;
pub const THREADSTATE_CAPTUREWINDOW: u32 = 2;
pub const THREADSTATE_GETCURSOR: u32 = 6;
/// WM_ACTIVATE, WM_SETFOCUS, WM_KILLFOCUS: a window activated or not,
/// taking or losing the keyboard.
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
/// WA_INACTIVE, WA_ACTIVE: the `wParam` of WM_ACTIVATE.
/// WM_NCACTIVATE: the frame of the window goes active (`wParam` TRUE) or
/// inactive; DefWindowProc paints it again, unless `lParam` is -1.
pub const WM_NCACTIVATE: u32 = 0x0086;
/// WM_ACTIVATEAPP: the foreground goes to another thread; each top-level
/// window of the thread that gains it gets TRUE and the TID of the thread
/// that loses it, each of the other FALSE and the TID of the gaining one.
pub const WM_ACTIVATEAPP: u32 = 0x001C;
pub const WA_INACTIVE: u32 = 0;
pub const WA_ACTIVE: u32 = 1;
/// KF_*: the bits of the high word of a keyboard message's `lParam`.
pub const KF_EXTENDED: u32 = 0x0100;
pub const KF_ALTDOWN: u32 = 0x2000;
pub const KF_REPEAT: u32 = 0x4000;
pub const KF_UP: u32 = 0x8000;

/// The virtual keys (VK_*) that win32k looks at.
pub mod vk {
    pub const VK_TAB: u8 = 0x09;
    pub const VK_CLEAR: u8 = 0x0C;
    pub const VK_RETURN: u8 = 0x0D;
    pub const VK_SHIFT: u8 = 0x10;
    pub const VK_CONTROL: u8 = 0x11;
    pub const VK_MENU: u8 = 0x12;
    pub const VK_CAPITAL: u8 = 0x14;
    pub const VK_ESCAPE: u8 = 0x1B;
    pub const VK_PRIOR: u8 = 0x21;
    pub const VK_NEXT: u8 = 0x22;
    pub const VK_END: u8 = 0x23;
    pub const VK_HOME: u8 = 0x24;
    pub const VK_LEFT: u8 = 0x25;
    pub const VK_UP: u8 = 0x26;
    pub const VK_RIGHT: u8 = 0x27;
    pub const VK_DOWN: u8 = 0x28;
    pub const VK_INSERT: u8 = 0x2D;
    pub const VK_DELETE: u8 = 0x2E;
    pub const VK_NUMPAD0: u8 = 0x60;
    pub const VK_DECIMAL: u8 = 0x6E;
    pub const VK_F10: u8 = 0x79;
    pub const VK_NUMLOCK: u8 = 0x90;
    pub const VK_LSHIFT: u8 = 0xA0;
    pub const VK_RSHIFT: u8 = 0xA1;
    pub const VK_LCONTROL: u8 = 0xA2;
    pub const VK_RCONTROL: u8 = 0xA3;
    pub const VK_LMENU: u8 = 0xA4;
    pub const VK_RMENU: u8 = 0xA5;
}

/// WM_MAXIMUM (ReactOS): the highest message a filter can name.
pub const WM_MAXIMUM: u32 = 0x0001_FFFF;

/// The messages that carry a pointer, which cannot be posted (WM_DEVICECHANGE
/// only when bit 15 of its wParam is set): the `message_pointer_flags` table
/// of ReactOS (`win32ss/user/ntuser/message.c`, from Wine), its values from
/// `winuser.h` and `undocuser.h`.
pub const POINTER_MESSAGES: [u32; 63] = [
    0x001, 0x00C, 0x00D, 0x01A, 0x01B, 0x024, 0x02B, 0x02C, 0x02D, 0x039, 0x046, 0x047, 0x049, 0x04A, 0x053, 0x07C,
    0x07D, 0x081, 0x083, 0x087, 0x0B0, 0x0B2, 0x0B3, 0x0B4, 0x0C2, 0x0C4, 0x0CB, 0x0E3, 0x0E9, 0x0EA, 0x0EB, 0x140,
    0x143, 0x145, 0x148, 0x14A, 0x14C, 0x14D, 0x152, 0x158, 0x180, 0x181, 0x189, 0x18C, 0x18D, 0x18F, 0x191, 0x192,
    0x196, 0x198, 0x1A2, 0x213, 0x214, 0x216, 0x219, 0x220, 0x229, 0x22A, 0x22B, 0x22D, 0x22E, 0x22F, 0x30C,
];

/// QS_*, the kinds of messages in a queue (`fsWakeBits`, `fsChangeBits`).
/// QS_KEY: a keyboard message (WM_KEYDOWN, WM_CHAR...).
pub const QS_KEY: u16 = 0x0001;
/// QS_MOUSEMOVE, QS_MOUSEBUTTON: a move, a button (WM_MOUSEMOVE,
/// WM_LBUTTONDOWN...).
pub const QS_MOUSEMOVE: u16 = 0x0002;
pub const QS_MOUSEBUTTON: u16 = 0x0004;
pub const QS_POSTMESSAGE: u16 = 0x0008;
/// QS_TIMER: a timer of the thread is due (WM_TIMER, WM_SYSTIMER).
pub const QS_TIMER: u16 = 0x0010;
/// QS_PAINT: a window of the thread has something to paint (`cPaintsReady`).
pub const QS_PAINT: u16 = 0x0020;
/// QS_SENDMESSAGE: a message sent by another thread waits (SendMessage).
pub const QS_SENDMESSAGE: u16 = 0x0040;
pub const QS_ALLPOSTMESSAGE: u16 = 0x0100;
/// QS_ALLINPUT, QS_SMRESULT: what GetQueueStatus can ask.
pub const QS_ALLINPUT: u16 = 0x04FF;
pub const QS_SMRESULT: u16 = 0x8000;
/// PM_REMOVE, and the flags PeekMessage accepts (PM_BADMSGFLAGS refuses
/// the others).
pub const PM_REMOVE: u32 = 0x0001;
pub const PM_VALID_FLAGS: u32 = 0x0001 | 0x0002 | (0x0407 | 0x0040 | 0x0020 | 0x0098 | 0x0400) << 16;

/// ONEPARAM_ROUTINE_GETQUEUESTATUS, ONEPARAM_ROUTINE_POSTQUITMESSAGE: the
/// routines of NtUserCallOneParam (`SIMPLECALLROUTINES`, before Vista).
pub const ONEPARAM_ROUTINE_GETQUEUESTATUS: u32 = 0x2B;
pub const ONEPARAM_ROUTINE_POSTQUITMESSAGE: u32 = 0x33;
/// ONEPARAM_ROUTINE_RELEASEDC: ReleaseDC (user32!ReleaseDC pushes 0x39).
pub const ONEPARAM_ROUTINE_RELEASEDC: u32 = 0x39;
/// TWOPARAM_ROUTINE_VALIDATERGN: ValidateRgn, by NtUserCallHwndParamLock
/// (user32!ValidateRgn pushes 0x65).
pub const TWOPARAM_ROUTINE_VALIDATERGN: u32 = 0x65;

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

/// RECT, in pixels.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect32 {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// PAINTSTRUCT: what BeginPaint gives (NtUserBeginPaint writes it whole) and
/// EndPaint takes back.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaintStruct32 {
    pub hdc: u32,
    /// The background is still to erase (WM_ERASEBKGND returned 0).
    pub erase: i32,
    /// What to paint, in client coordinates.
    pub paint: Rect32,
    pub restore: i32,
    pub inc_update: i32,
    pub reserved: [u8; 32],
}

impl PaintStruct32 {
    /// The structure in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let mut reserved = [0u8; 32];
        reserved.copy_from_slice(&bytes[0x20..0x40]);
        Some(Self {
            hdc: word(0),
            erase: word(4) as i32,
            paint: Rect32 {
                left: word(8) as i32,
                top: word(0xC) as i32,
                right: word(0x10) as i32,
                bottom: word(0x14) as i32,
            },
            restore: word(0x18) as i32,
            inc_update: word(0x1C) as i32,
            reserved,
        })
    }
}

/// LARGE_UNICODE_STRING: a length, a maximum length and `bAnsi` (bit 31),
/// a buffer (a server address).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LargeUnicodeString32 {
    pub length: u32,
    pub maximum_length_ansi: u32,
    pub buffer: u32,
}

/// WND: a window, in its desktop's heap, which `user32` reads. Its
/// pointers are server addresses (`head.pSelf`: its own).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wnd32 {
    /// THRDESKHEAD: its handle, its lock count, its thread (`THREADINFO`),
    /// its desktop, itself.
    pub handle: u32,
    pub lock_count: u32,
    pub pti: u32,
    pub rpdesk: u32,
    pub self_address: u32,
    /// WNDS_*, WNDS2_*.
    pub state: u32,
    pub state2: u32,
    pub ex_style: u32,
    pub style: u32,
    pub module: u32,
    pub fnid: u32,
    pub spwnd_next: u32,
    pub spwnd_prev: u32,
    pub spwnd_parent: u32,
    pub spwnd_child: u32,
    pub spwnd_owner: u32,
    pub rc_window: Rect32,
    pub rc_client: Rect32,
    pub wnd_proc: u32,
    /// Its class (`CLS`).
    pub pcls: u32,
    pub hrgn_update: u32,
    pub prop_list_head: ListEntry32,
    pub prop_list_items: u32,
    pub sb_info: u32,
    pub system_menu: u32,
    pub id_menu: u32,
    pub hrgn_clip: u32,
    pub hrgn_new_frame: u32,
    pub name: LargeUnicodeString32,
    pub cb_wnd_extra: u32,
    pub spwnd_last_active: u32,
    pub imc: u32,
    pub user_data: u32,
    pub act_ctx: u32,
    pub spwnd_clipboard_listener: u32,
    pub ex_style2: u32,
    /// InternalPos (ReactOS): NormalRect, IconPos, MaxPos, flags.
    pub normal_rect: Rect32,
    pub icon_pos: [i32; 2],
    pub max_pos: [i32; 2],
    pub internal_pos_flags: u32,
    /// Unicode, InternalPosInitialized, HideFocus, HideAccel.
    pub bits: u32,
    pub sb_info_ex: u32,
    pub thread_list_entry: ListEntry32,
    pub dialog_pointer: u32,
}

/// CLS: a window class, which `user32` reads. Its pointers are server
/// addresses.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cls32 {
    pub next: u32,
    pub atom_class_name: u16,
    pub atom_nv_class_name: u16,
    pub fnid: u32,
    pub rpdesk_parent: u32,
    pub pdce: u32,
    /// CSF_*.
    pub csf_flags: u32,
    pub client_ansi_menu_name: u32,
    pub client_unicode_menu_name: u32,
    pub spcpd_first: u32,
    pub base: u32,
    pub clone: u32,
    pub wnd_reference_count: u32,
    pub style: u32,
    pub wnd_proc: u32,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub module: u32,
    pub spicn: u32,
    pub spcur: u32,
    /// hbrBackground: a brush, or a system colour plus one.
    pub background: u32,
    pub menu_name: u32,
    pub ansi_class_name: u32,
    pub spicn_sm: u32,
    /// Unicode, Global, MenuNameIsString.
    pub bits: u32,
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
    assert!(size_of::<DesktopConsoleThread32>() == 8);
    assert!(offset_of!(DesktopConsoleThread32, thread_id) == 4);
    assert!(offset_of!(Wnd32, state) == 0x14);
    // user32!UpdateWindow: `cmp [pwnd + 0x68], 0` (hrgnUpdate), then
    // `cmp [pwnd + 0x38], 0` (spwndChild).
    assert!(offset_of!(Wnd32, spwnd_child) == 0x38);
    assert!(offset_of!(Wnd32, hrgn_update) == 0x68);
    assert!(offset_of!(Wnd32, fnid) == 0x28);
    assert!(offset_of!(Wnd32, spwnd_next) == 0x2C);
    assert!(offset_of!(Wnd32, rc_window) == 0x40);
    assert!(offset_of!(Wnd32, rc_client) == 0x50);
    assert!(offset_of!(Wnd32, wnd_proc) == 0x60);
    assert!(offset_of!(Wnd32, pcls) == 0x64);
    assert!(offset_of!(Wnd32, name) == 0x8C);
    assert!(offset_of!(Wnd32, cb_wnd_extra) == 0x98);
    assert!(offset_of!(Wnd32, ex_style2) == 0xB0);
    assert!(offset_of!(Wnd32, bits) == 0xD8);
    assert!(offset_of!(Wnd32, dialog_pointer) == 0xE8);
    assert!(size_of::<Wnd32>() == 0xEC);
    assert!(offset_of!(Cls32, fnid) == 0x08);
    assert!(offset_of!(Cls32, csf_flags) == 0x14);
    assert!(offset_of!(Cls32, style) == 0x30);
    assert!(offset_of!(Cls32, wnd_proc) == 0x34);
    assert!(offset_of!(Cls32, background) == 0x4C);
    assert!(size_of::<Cls32>() == 0x60);
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
    assert!(size_of::<MbString32>() == 40);
    assert!(offset_of!(ServerInfo32, default_heap_base) == 0x1FC);
    assert!(offset_of!(ServerInfo32, mb_strings) == 0x208);
    assert!(offset_of!(ServerInfo32, oem_to_ansi) == 0x3C8);
    assert!(offset_of!(ServerInfo32, installed_event_hooks) == 0x5C8);
    // user32!RealGetSystemMetrics: mov eax, [gpsi + 0x5CC + 4 * index].
    assert!(offset_of!(ServerInfo32, sys_met) == 0x5CC);
    // user32!GetSysColor: mov eax, [gpsi + 0x7BC + 4 * index].
    assert!(offset_of!(ServerInfo32, argb_system) == 0x7BC);
    // user32!GetSysColorBrush: mov eax, [gpsi + 0x838 + 4 * index].
    assert!(offset_of!(ServerInfo32, ahbr_system) == 0x838);
    // user32!DrawFocusRect: mov eax, [eax + 0x8B4], gpsi in eax.
    assert!(offset_of!(ServerInfo32, hbr_gray) == 0x8B4);
    assert!(size_of::<Msg32>() == 28);
    assert!(size_of::<PaintStruct32>() == 64);
    assert!(offset_of!(PaintStruct32, paint) == 8);
    assert!(offset_of!(PaintStruct32, reserved) == 0x20);
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

/// TYPE_CURSOR: a cursor or an icon in the USER handle table.
pub const TYPE_CURSOR: u8 = 3;

/// WM_SETCURSOR: the window under the cursor may set its shape (`wParam` the
/// window, `lParam` the hit-test code and the mouse message).
pub const WM_SETCURSOR: u32 = 0x0020;

/// ONEPARAM_ROUTINE_CREATEEMPTYCUROBJECT: NtUserxCreateEmptyCurObject, an
/// empty cursor or icon object (`param`: an animated one).
pub const ONEPARAM_ROUTINE_CREATEEMPTYCUROBJECT: u32 = 0x21;

/// USER32_CALLBACK_LOADDEFAULTCURSORS: `user32` loads the system cursors
/// (User32SetupDefaultCursors, LoadSystemCursors).
pub const USER32_CALLBACK_LOADDEFAULTCURSORS: u32 = 3;

/// CURSORF_*, `CURSORDATA.CURSORF_flags`.
pub mod cursorf {
    /// Loaded from a module's resources.
    pub const FROMRESOURCE: u32 = 0x0001;
    /// A system cursor, of no process.
    pub const GLOBAL: u32 = 0x0002;
    /// Loaded with LR_SHARED: the process keeps it for the next load.
    pub const LRSHARED: u32 = 0x0004;
    /// An animated cursor.
    pub const ACON: u32 = 0x0008;
    /// The cursor of a thread (SetCursor).
    pub const CURRENT: u32 = 0x0200;
}

/// OCR_*: the system cursors, by their identifiers (SetSystemCursor), with
/// their index in the system table.
pub const OCR_CURSORS: [u32; 16] = [
    32512, // OCR_NORMAL
    32513, // OCR_IBEAM
    32514, // OCR_WAIT
    32515, // OCR_CROSS
    32516, // OCR_UP
    32640, // OCR_SIZE
    32641, // OCR_ICON
    32642, // OCR_SIZENWSE
    32643, // OCR_SIZENESW
    32644, // OCR_SIZEWE
    32645, // OCR_SIZENS
    32646, // OCR_SIZEALL
    32648, // OCR_NO
    32649, // OCR_HAND
    32650, // OCR_APPSTARTING
    32651, // OCR_HELP
];
pub const OCR_NORMAL: u32 = 32512;
pub const OCR_SIZENWSE: u32 = 32642;
pub const OCR_SIZENESW: u32 = 32643;
pub const OCR_SIZEWE: u32 = 32644;
pub const OCR_SIZENS: u32 = 32645;

/// USER32_CALLBACK_SETWNDICONS: `user32` loads the system icons
/// (User32CallSetWndIconsFromKernel) and gives them back
/// ([`SetWndIconsArguments32`]).
pub const USER32_CALLBACK_SETWNDICONS: u32 = 11;

/// SETWNDICONS_CALLBACK_ARGUMENTS, 32-bit: the system icons `user32` loads,
/// in the order of [`OIC_ICONS`] (the window icon, then its small form).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetWndIconsArguments32 {
    pub icons: [u32; 7],
}

const _: () = assert!(size_of::<SetWndIconsArguments32>() == 28);

/// OIC_*: the system icons, in the order of [`SetWndIconsArguments32`]:
/// OIC_SAMPLE (IDI_APPLICATION), OIC_HAND, OIC_QUES, OIC_BANG, OIC_NOTE,
/// OIC_WINLOGO, and the small window icon (OIC_INTERNAL_WINSMALL, which
/// ReactOS keeps apart).
pub const OIC_ICONS: [u32; 7] = [32512, 32513, 32514, 32515, 32516, 32517, 32518];

/// WM_GETICON, WM_SETICON: a window's icons (`wParam` ICON_SMALL, ICON_BIG
/// or ICON_SMALL2).
pub const WM_GETICON: u32 = 0x007F;
pub const WM_SETICON: u32 = 0x0080;
pub const ICON_SMALL: u32 = 0;
pub const ICON_BIG: u32 = 1;
pub const ICON_SMALL2: u32 = 2;

/// DI_*: what DrawIconEx draws.
pub mod di {
    /// The AND mask.
    pub const MASK: u32 = 0x0001;
    /// The colours (the XOR mask).
    pub const IMAGE: u32 = 0x0002;
    /// Both: the icon as it shows.
    pub const NORMAL: u32 = 0x0003;
    /// No size given: the system's (SM_CXICON, SM_CYICON).
    pub const DEFAULTSIZE: u32 = 0x0008;
}

/// PROPERTY, 32-bit: a window property (SetProp) in its desktop's heap,
/// which `user32` reads itself (GetProp, IntGetProp): its entry in the list
/// of the `WND` (`PropListHead`, `PropListItems`), its data, its atom.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Property32 {
    pub entry: ListEntry32,
    pub data: u32,
    pub atom: u16,
    /// PROPERTY_FLAG_SYSTEM for a property of the system (the icons of
    /// WM_SETICON).
    pub fs: u16,
}

pub const PROPERTY_FLAG_SYSTEM: u16 = 1;

const _: () = {
    assert!(size_of::<Property32>() == 16);
    assert!(offset_of!(Property32, data) == 8);
    assert!(offset_of!(Property32, atom) == 12);
};

/// WM_HSCROLL, WM_VSCROLL: a scroll bar's request (`LOWORD(wParam)`, `sb`).
pub const WM_HSCROLL: u32 = 0x0114;
pub const WM_VSCROLL: u32 = 0x0115;

/// SB_*: which scroll bar (GetScrollInfo, SetScrollInfo, ShowScrollBar,
/// EnableScrollBar), and the requests of WM_HSCROLL and WM_VSCROLL.
pub mod sb {
    pub const HORZ: u32 = 0;
    pub const VERT: u32 = 1;
    /// A scroll bar control (the ScrollBar class).
    pub const CTL: u32 = 2;
    pub const BOTH: u32 = 3;
    pub const LINEUP: u32 = 0;
    pub const LINEDOWN: u32 = 1;
    pub const PAGEUP: u32 = 2;
    pub const PAGEDOWN: u32 = 3;
    pub const THUMBPOSITION: u32 = 4;
    pub const THUMBTRACK: u32 = 5;
    pub const ENDSCROLL: u32 = 8;
}

/// SIF_*: what a `SCROLLINFO` carries.
pub mod sif {
    pub const RANGE: u32 = 0x0001;
    pub const PAGE: u32 = 0x0002;
    pub const POS: u32 = 0x0004;
    /// A bar left with nothing to scroll is disabled, not hidden.
    pub const DISABLENOSCROLL: u32 = 0x0008;
    pub const TRACKPOS: u32 = 0x0010;
    pub const ALL: u32 = RANGE | PAGE | POS | TRACKPOS;
    /// ReactOS's: the bar is drawn by a theme.
    pub const THEMED: u32 = 0x0080;
    /// ReactOS's (`undocuser.h`): SetScrollInfo returns the position before
    /// (SetScrollPos).
    pub const PREVIOUSPOS: u32 = 0x1000;
}

/// ESB_*: the arrows of a scroll bar that are disabled (EnableScrollBar,
/// `SBINFO.WSBflags`).
pub mod esb {
    pub const ENABLE_BOTH: u32 = 0;
    /// The left or top arrow.
    pub const DISABLE_LTUP: u32 = 1;
    /// The right or bottom arrow.
    pub const DISABLE_RTDN: u32 = 2;
    pub const DISABLE_BOTH: u32 = 3;
}

/// OBJID_*: the object GetScrollBarInfo is about (`SBOBJ_TO_SBID`: minus
/// OBJID_HSCROLL gives SB_HORZ, SB_VERT, SB_CTL).
pub const OBJID_HSCROLL: i32 = -6;
pub const OBJID_VSCROLL: i32 = -5;
pub const OBJID_CLIENT: i32 = -4;
/// OBJID_MENU: a window's menu bar (GetMenuBarInfo).
pub const OBJID_MENU: i32 = -3;
/// OBJID_SYSMENU: a window's system menu.
pub const OBJID_SYSMENU: i32 = -1;

/// STATE_SYSTEM_*: the state of a part of a scroll bar (`rgstate`).
pub mod state_system {
    pub const UNAVAILABLE: u32 = 0x0000_0001;
    pub const PRESSED: u32 = 0x0000_0008;
    pub const INVISIBLE: u32 = 0x0000_8000;
    pub const OFFSCREEN: u32 = 0x0001_0000;
}

/// The parts of a scroll bar (CCHILDREN_SCROLLBAR), and so `rgstate` has one
/// more entry, the bar's own: the top or left arrow (1), the page above or
/// left of the thumb (2), the thumb (3), the page below or right of it (4),
/// the bottom or right arrow (5).
pub const CCHILDREN_SCROLLBAR: usize = 5;

/// SBS_VERT: a vertical scroll bar control.
pub const SBS_VERT: u32 = 0x0001;

/// SW_*: what ScrollWindowEx does besides scrolling.
pub mod sw_scroll {
    /// The children move too (WM_MOVE), and are scrolled with the client
    /// area.
    pub const SCROLLCHILDREN: u32 = 0x0001;
    /// What the scroll uncovers is invalidated.
    pub const INVALIDATE: u32 = 0x0002;
    /// And erased (with INVALIDATE: WM_ERASEBKGND at the next paint).
    pub const ERASE: u32 = 0x0004;
    /// Smoothly (ignored, as in ReactOS).
    pub const SMOOTHSCROLL: u32 = 0x0010;
    /// ReactOS's (`undocuser.h`): ScrollWindow, with the window's DC.
    pub const SCROLLWNDDCE: u32 = 0x8000;
}

/// SBDATA, 32-bit: the range, page and position of a scroll bar, which
/// `user32` reads itself (GetScrollPos, GetScrollRange).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SbData32 {
    pub pos_min: i32,
    pub pos_max: i32,
    pub page: i32,
    pub pos: i32,
}

/// SBINFO, 32-bit: the scroll bars of a window, in its desktop's heap
/// (`WND.pSBInfo`): the disabled arrows (`ESB_*`), then the horizontal and
/// the vertical bar.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SbInfo32 {
    pub wsb_flags: i32,
    pub horz: SbData32,
    pub vert: SbData32,
}

/// SCROLLINFO, 32-bit (SetScrollInfo, GetScrollInfo); an application may
/// give it without `nTrackPos`, 24 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrollInfo32 {
    pub cb_size: u32,
    pub f_mask: u32,
    pub n_min: i32,
    pub n_max: i32,
    pub n_page: u32,
    pub n_pos: i32,
    pub n_track_pos: i32,
}

/// SCROLLBARINFO, 32-bit (GetScrollBarInfo): the bar's rectangle (in the
/// window's coordinates from NtUserGetScrollBarInfo, `user32` moves it to
/// the screen), the length of its arrows, its thumb, the state of each part.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrollBarInfo32 {
    pub cb_size: u32,
    pub rc_scroll_bar: Rect32,
    pub dxy_line_button: i32,
    pub xy_thumb_top: i32,
    pub xy_thumb_bottom: i32,
    pub reserved: i32,
    pub rgstate: [u32; CCHILDREN_SCROLLBAR + 1],
}

/// SETSCROLLBARINFO, 32-bit (NtUserSetScrollBarInfo, ReactOS's): what
/// `user32` keeps of a bar while it follows the mouse on it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetScrollBarInfo32 {
    pub n_track_pos: i32,
    pub reserved: i32,
    pub rgstate: [u32; CCHILDREN_SCROLLBAR + 1],
}

const _: () = {
    assert!(size_of::<SbData32>() == 16);
    assert!(size_of::<SbInfo32>() == 36);
    assert!(offset_of!(SbInfo32, horz) == 4);
    assert!(offset_of!(SbInfo32, vert) == 20);
    assert!(size_of::<ScrollInfo32>() == 28);
    assert!(offset_of!(ScrollInfo32, n_track_pos) == 24);
    assert!(size_of::<ScrollBarInfo32>() == 60);
    assert!(offset_of!(ScrollBarInfo32, dxy_line_button) == 20);
    assert!(offset_of!(ScrollBarInfo32, rgstate) == 36);
    assert!(size_of::<SetScrollBarInfo32>() == 32);
};

/// The little-endian words of `bytes`, if they are at least `N` of them.
fn words<const N: usize>(bytes: &[u8]) -> Option<[u32; N]> {
    let mut words = [0u32; N];
    for (index, word) in words.iter_mut().enumerate() {
        let at = index * 4;
        *word = u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?);
    }
    Some(words)
}

impl ScrollInfo32 {
    /// The record in `bytes`, whose first 24 bytes (without `nTrackPos`,
    /// 0 then) are enough; `None` if they are fewer.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let [cb_size, f_mask, n_min, n_max, n_page, n_pos] = words::<6>(bytes)?;
        let n_track_pos = words::<7>(bytes).map_or(0, |w| w[6] as i32);
        Some(Self {
            cb_size,
            f_mask,
            n_min: n_min as i32,
            n_max: n_max as i32,
            n_page,
            n_pos: n_pos as i32,
            n_track_pos,
        })
    }
}

impl ScrollBarInfo32 {
    /// The record in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let w = words::<15>(bytes)?;
        Some(Self {
            cb_size: w[0],
            rc_scroll_bar: Rect32 { left: w[1] as i32, top: w[2] as i32, right: w[3] as i32, bottom: w[4] as i32 },
            dxy_line_button: w[5] as i32,
            xy_thumb_top: w[6] as i32,
            xy_thumb_bottom: w[7] as i32,
            reserved: w[8] as i32,
            rgstate: [w[9], w[10], w[11], w[12], w[13], w[14]],
        })
    }
}

impl SetScrollBarInfo32 {
    /// The record in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let w = words::<8>(bytes)?;
        Some(Self { n_track_pos: w[0] as i32, reserved: w[1] as i32, rgstate: [w[2], w[3], w[4], w[5], w[6], w[7]] })
    }
}

/// RT_CURSOR, RT_ICON: `CURSORDATA.rt`.
pub const RT_CURSOR: u16 = 1;
pub const RT_ICON: u16 = 3;

/// CURSORDATA, 32-bit: what `user32` gives NtUserSetCursorIconData for a
/// cursor or an icon it has made (its bitmaps, its hot spot).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CursorData32 {
    pub name: u32,
    pub module_name: u32,
    /// RT_CURSOR or RT_ICON.
    pub rt: u16,
    pub dummy: u16,
    /// `cursorf::*`.
    pub flags: u32,
    pub x_hotspot: i16,
    pub y_hotspot: i16,
    /// The AND mask; for a monochrome one, the AND mask over the XOR mask
    /// (twice the height).
    pub hbm_mask: u32,
    /// The colors; 0 for a monochrome one.
    pub hbm_color: u32,
    pub hbm_alpha: u32,
    pub bounds: Rect32,
    pub hbm_user_alpha: u32,
    pub bpp: u32,
    pub cx: u32,
    pub cy: u32,
    /// An animated cursor: its frames, its steps.
    pub cpcur: u32,
    pub cicur: u32,
    pub aspcur: u32,
    pub aicur: u32,
    pub ajif_rate: u32,
    pub iicur: u32,
}

/// FINDEXISTINGCURICONPARAM, 32-bit: what NtUserFindExistingCursorIcon
/// looks for.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FindExistingCurIconParam32 {
    pub icon: i32,
    pub cx: i32,
    pub cy: i32,
}

const _: () = {
    assert!(size_of::<CursorData32>() == 88);
    assert!(offset_of!(CursorData32, rt) == 8);
    assert!(offset_of!(CursorData32, flags) == 12);
    assert!(offset_of!(CursorData32, x_hotspot) == 16);
    assert!(offset_of!(CursorData32, hbm_mask) == 20);
    assert!(offset_of!(CursorData32, hbm_alpha) == 28);
    assert!(offset_of!(CursorData32, bounds) == 32);
    assert!(offset_of!(CursorData32, bpp) == 52);
    assert!(offset_of!(CursorData32, cx) == 56);
    assert!(offset_of!(CursorData32, cpcur) == 64);
    assert!(offset_of!(CursorData32, iicur) == 84);
    assert!(size_of::<FindExistingCurIconParam32>() == 12);
};

impl CursorData32 {
    /// The record in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let half = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        Some(Self {
            name: word(0),
            module_name: word(4),
            rt: half(8),
            dummy: half(10),
            flags: word(12),
            x_hotspot: half(16) as i16,
            y_hotspot: half(18) as i16,
            hbm_mask: word(20),
            hbm_color: word(24),
            hbm_alpha: word(28),
            bounds: Rect32 {
                left: word(32) as i32,
                top: word(36) as i32,
                right: word(40) as i32,
                bottom: word(44) as i32,
            },
            hbm_user_alpha: word(48),
            bpp: word(52),
            cx: word(56),
            cy: word(60),
            cpcur: word(64),
            cicur: word(68),
            aspcur: word(72),
            aicur: word(76),
            ajif_rate: word(80),
            iicur: word(84),
        })
    }
}

impl FindExistingCurIconParam32 {
    /// The record in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        let word = |at: usize| i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        Some(Self { icon: word(0), cx: word(4), cy: word(8) })
    }
}

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
    NonClientMetricsW32,
    Msg32,
    UserHandleEntry32,
    UserHandleTable32,
    SharedInfo32,
    UserConnect32,
    ServerInfoHead32,
    ClientInfo32,
    DeskInfoHead32,
    ClientThreadInfo32,
    Wnd32,
    Cls32,
    GetCharsetInfo32,
    WndClassExW32,
    CreateStructW32,
    WindowProcArguments32,
    CallbackWnd32,
    MinMaxInfo32,
    WindowPos32,
    NcCalcSizeParams32,
    MonitorInfo32,
    PaintStruct32,
    CursorData32,
    FindExistingCurIconParam32,
    SetWndIconsArguments32,
    Property32,
    SbInfo32,
    ScrollInfo32,
    ScrollBarInfo32
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_records_read_back_from_their_bytes() {
        let info =
            ScrollInfo32 { cb_size: 28, f_mask: sif::ALL, n_min: -5, n_max: 99, n_page: 10, n_pos: 30, n_track_pos: 7 };
        assert_eq!(ScrollInfo32::from_bytes(info.as_bytes()), Some(info));
        let short = ScrollInfo32::from_bytes(&info.as_bytes()[..24]).unwrap();
        assert_eq!((short.n_pos, short.n_track_pos), (30, 0), "without nTrackPos");
        assert_eq!(ScrollInfo32::from_bytes(&info.as_bytes()[..20]), None);
        let bar = ScrollBarInfo32 {
            cb_size: 60,
            rc_scroll_bar: Rect32 { left: 1, top: -2, right: 3, bottom: 4 },
            dxy_line_button: 16,
            xy_thumb_top: 20,
            xy_thumb_bottom: 43,
            reserved: 0,
            rgstate: [1, 2, 3, 4, 5, 6],
        };
        assert_eq!(ScrollBarInfo32::from_bytes(bar.as_bytes()), Some(bar));
        let set = SetScrollBarInfo32::from_bytes(&bar.as_bytes()[20..52]).unwrap();
        assert_eq!((set.n_track_pos, set.reserved, set.rgstate), (16, 20, [43, 0, 1, 2, 3, 4]), "eight words");
        assert_eq!(SetScrollBarInfo32::from_bytes(&[0; 31]), None);
    }

    #[test]
    fn cursor_data_reads_back_from_its_bytes() {
        let data = CursorData32 {
            name: 0x7F00,
            module_name: 0x0012_3400,
            rt: RT_CURSOR,
            flags: cursorf::FROMRESOURCE | cursorf::LRSHARED,
            x_hotspot: -1,
            y_hotspot: 7,
            hbm_mask: 0x0405_0011,
            hbm_color: 0x0405_0012,
            bounds: Rect32 { left: 1, top: 2, right: 3, bottom: 4 },
            bpp: 32,
            cx: 32,
            cy: 32,
            iicur: 9,
            ..CursorData32::default()
        };
        assert_eq!(CursorData32::from_bytes(data.as_bytes()), Some(data));
        assert_eq!(CursorData32::from_bytes(&data.as_bytes()[..87]), None, "one byte short");
        let param = FindExistingCurIconParam32 { icon: 1, cx: 16, cy: -16 };
        assert_eq!(FindExistingCurIconParam32::from_bytes(param.as_bytes()), Some(param));
    }

    #[test]
    fn a_charset_record_reads_back_from_its_bytes() {
        let record = GetCharsetInfo32 {
            locale: 0x409,
            charset_info: CharsetInfo32 {
                charset: 0,
                ansi_code_page: 1252,
                unicode_subset: [1, 2, 3, 4],
                code_page_bits: [FS_LATIN1, 6],
            },
        };
        assert_eq!(GetCharsetInfo32::from_bytes(record.as_bytes()), Some(record));
        assert_eq!(GetCharsetInfo32::from_bytes(&record.as_bytes()[..0x23]), None, "one byte short");
    }

    #[test]
    fn a_paint_struct_reads_back_from_its_bytes() {
        let ps = PaintStruct32 {
            hdc: 0x0001_000B,
            erase: 1,
            paint: Rect32 { left: -1, top: 2, right: 952, bottom: 572 },
            restore: 3,
            inc_update: 4,
            reserved: [7; 32],
        };
        assert_eq!(PaintStruct32::from_bytes(ps.as_bytes()), Some(ps));
        assert_eq!(PaintStruct32::from_bytes(&ps.as_bytes()[..63]), None, "one byte short");
    }

    #[test]
    fn a_client_info_is_its_bytes() {
        let info = ClientInfo32 { ppi: 0xBC00_1234, ti_flags: TIF_CSRSSTHREAD, ..ClientInfo32::default() };
        let bytes = info.as_bytes();
        assert_eq!(bytes.len(), 0xF8);
        assert_eq!(&bytes[0xF4..], &0xBC00_1234u32.to_le_bytes());
        assert_eq!(&bytes[0x14..0x18], &8u32.to_le_bytes());
    }
}
