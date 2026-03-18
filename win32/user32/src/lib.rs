//! user32.dll — Window management and message loop.
//!
//! XP-era games use user32 for:
//!   CreateWindowEx  — create the game window
//!   ShowWindow      — show/hide
//!   GetMessage /
//!   PeekMessage     — message pump (frame loop)
//!   DispatchMessage — route WM_* to WndProc
//!   ShowCursor      — hide the cursor in full-screen
//!   SetCursorPos    — lock cursor to centre (FPS games)
//!   ClipCursor      — confine cursor to window rect
//!   SetWindowPos    — resize/move window
//!   GetClientRect   — get drawable area dimensions
//!   RegisterRawInputDevices — raw keyboard/mouse (Phase 4)
//!   MessageBox      — error dialogs

#![no_std]
extern crate alloc;

pub type Bool   = i32;
pub type DWord  = u32;
pub type Handle = *mut u8;
pub type HWnd   = *mut u8;
pub type HInstance = *mut u8;
pub type LpVoid = *mut u8;

pub const FALSE: Bool = 0;
pub const TRUE:  Bool = 1;

// Window styles most games use
pub const WS_OVERLAPPEDWINDOW: DWord = 0x00CF_0000;
pub const WS_POPUP:            DWord = 0x8000_0000;
pub const WS_VISIBLE:          DWord = 0x1000_0000;

// ShowWindow commands
pub const SW_SHOW:     i32 = 5;
pub const SW_HIDE:     i32 = 0;
pub const SW_MAXIMIZE: i32 = 3;

#[repr(C)]
pub struct Rect {
    pub left:   i32,
    pub top:    i32,
    pub right:  i32,
    pub bottom: i32,
}

#[repr(C)]
pub struct Msg {
    pub hwnd:    HWnd,
    pub message: DWord,
    pub w_param: usize,
    pub l_param: isize,
    pub time:    DWord,
    pub pt_x:    i32,
    pub pt_y:    i32,
}

// ── Window creation ───────────────────────────────────────────────────────────

/// CreateWindowExA — create the game's main window.
#[no_mangle]
pub unsafe extern "C" fn CreateWindowExA(
    dw_ex_style:     DWord,
    lp_class_name:   *const u8,
    lp_window_name:  *const u8,
    dw_style:        DWord,
    x: i32, y: i32, n_width: i32, n_height: i32,
    h_wnd_parent: HWnd, _h_menu: Handle, _h_instance: HInstance, _lp_param: LpVoid,
) -> HWnd {
    log::info!("CreateWindowExA: {}x{} at ({},{})", n_width, n_height, x, y);
    // TODO Phase 3: create a real framebuffer-backed window object.
    // Return a fake non-null HWND so the game proceeds.
    0x0001 as HWnd
}

/// ShowWindow.
#[no_mangle]
pub extern "C" fn ShowWindow(_h_wnd: HWnd, _n_cmd_show: i32) -> Bool { TRUE }

/// SetWindowPos.
#[no_mangle]
pub unsafe extern "C" fn SetWindowPos(
    _h_wnd: HWnd, _h_wnd_insert_after: HWnd,
    _x: i32, _y: i32, _cx: i32, _cy: i32, _u_flags: DWord,
) -> Bool { TRUE }

/// GetClientRect — return the window's client area.
#[no_mangle]
pub unsafe extern "C" fn GetClientRect(h_wnd: HWnd, lp_rect: *mut Rect) -> Bool {
    if lp_rect.is_null() { return FALSE; }
    // Default: 800×600 until we have a real window manager.
    unsafe {
        (*lp_rect) = Rect { left: 0, top: 0, right: 800, bottom: 600 };
    }
    TRUE
}

// ── Message pump ──────────────────────────────────────────────────────────────

pub const WM_QUIT:    DWord = 0x0012;
pub const WM_DESTROY: DWord = 0x0002;
pub const WM_KEYDOWN: DWord = 0x0100;
pub const WM_KEYUP:   DWord = 0x0101;

/// PeekMessageA — non-blocking message check (used by every game loop).
#[no_mangle]
pub unsafe extern "C" fn PeekMessageA(
    lp_msg:    *mut Msg,
    _h_wnd:    HWnd,
    _wMsg_filter_min: DWord,
    _wMsg_filter_max: DWord,
    _w_remove_msg:    DWord,
) -> Bool {
    // TODO Phase 3: drain the window event queue from the input driver.
    // Phase 1: always report no messages → game runs its render loop.
    FALSE
}

/// GetMessageA — blocking message wait.
///
/// Phase 2.5: returns -1 (error) immediately so `while GetMessageA(...) > 0`
/// loops in games exit cleanly. Phase 3 will block on a real message queue.
#[no_mangle]
pub unsafe extern "C" fn GetMessageA(
    _lp_msg: *mut Msg,
    _h_wnd: HWnd,
    _wMsg_filter_min: DWord,
    _wMsg_filter_max: DWord,
) -> Bool {
    -1 // error / no message queue — breaks `while (GetMessageA(...) > 0)` loops
}

/// DispatchMessageA — send message to the window procedure.
#[no_mangle]
pub unsafe extern "C" fn DispatchMessageA(_lp_msg: *const Msg) -> isize { 0 }

/// TranslateMessage — translate virtual-key messages to character messages.
#[no_mangle]
pub unsafe extern "C" fn TranslateMessage(_lp_msg: *const Msg) -> Bool { TRUE }

/// PostQuitMessage — post WM_QUIT to the message queue.
#[no_mangle]
pub extern "C" fn PostQuitMessage(_n_exit_code: i32) {
    log::info!("PostQuitMessage — game requested exit");
}

// ── Cursor ────────────────────────────────────────────────────────────────────

/// ShowCursor — hide (FALSE) or show (TRUE) the mouse cursor.
#[no_mangle]
pub extern "C" fn ShowCursor(_b_show: Bool) -> i32 { 0 }

/// SetCursorPos — move the cursor (FPS mouse-lock).
#[no_mangle]
pub extern "C" fn SetCursorPos(_x: i32, _y: i32) -> Bool { TRUE }

/// ClipCursor — confine cursor movement to a rect.
#[no_mangle]
pub unsafe extern "C" fn ClipCursor(_lp_rect: *const Rect) -> Bool { TRUE }

// ── Miscellaneous ─────────────────────────────────────────────────────────────

/// MessageBoxA — display a dialog box (stub: just log).
#[no_mangle]
pub unsafe extern "C" fn MessageBoxA(
    _h_wnd:    HWnd,
    lp_text:   *const u8,
    lp_caption: *const u8,
    _u_type:   DWord,
) -> i32 {
    log::warn!("MessageBoxA called");
    1 // IDOK
}

/// GetSystemMetrics — screen dimensions and UI parameters.
pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;

#[no_mangle]
pub extern "C" fn GetSystemMetrics(n_index: i32) -> i32 {
    match n_index {
        0 => 1920, // SM_CXSCREEN
        1 => 1080, // SM_CYSCREEN
        _ => 0,
    }
}
