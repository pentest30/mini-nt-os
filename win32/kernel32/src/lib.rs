//! kernel32.dll — Core Win32 API for process, memory, file, and timing.
//!
//! This is the most important Win32 DLL for game compatibility.
//! Every game imports it. We implement the ~50 APIs that 95% of
//! XP-era games actually use, in priority order.
//!
//! Calling convention: stdcall (__stdcall) for all exports.
//! Return values: BOOL = i32 (0 = FALSE, nonzero = TRUE), HANDLE = *mut c_void.

#![no_std]
extern crate alloc;

// ── Win32 type aliases ────────────────────────────────────────────────────────
pub type Bool    = i32;
pub type DWord   = u32;
pub type Handle  = *mut u8;
pub type LpVoid  = *mut u8;
pub type LpcVoid = *const u8;

pub const FALSE:           Bool   = 0;
pub const TRUE:            Bool   = 1;
pub const INVALID_HANDLE:  Handle = usize::MAX as Handle;

// ── NTSTATUS helpers ─────────────────────────────────────────────────────────
pub const STATUS_SUCCESS:        i32 = 0;
pub const STATUS_ACCESS_DENIED:  i32 = 0xC000_0022u32 as i32;
pub const STATUS_NO_MEMORY:      i32 = 0xC000_0017u32 as i32;
pub const ERROR_SUCCESS:         DWord = 0;
pub const ERROR_INVALID_HANDLE:  DWord = 6;
pub const ERROR_NOT_ENOUGH_MEM:  DWord = 8;

// ── Thread-local last error ───────────────────────────────────────────────────
// In a real implementation this lives in TEB.LastErrorValue.
// Phase 1: global placeholder (single-threaded).
static LAST_ERROR: spin::Mutex<DWord> = spin::Mutex::new(0);

fn set_last_error(code: DWord) { *LAST_ERROR.lock() = code; }
fn get_last_error_val() -> DWord { *LAST_ERROR.lock() }

unsafe fn c_str_to_str<'a>(ptr: *const u8) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < 260 {
        let b = unsafe { ptr.add(len).read_unaligned() };
        if b == 0 {
            let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
            return core::str::from_utf8(bytes).ok();
        }
        len += 1;
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// Timing — CRITICAL for games (frame pacing, physics, audio sync)
// ═══════════════════════════════════════════════════════════════════════════════

/// GetTickCount — milliseconds since boot. Wraps at 49.7 days.
///
/// Games use this for rough timing. Accuracy: ≤ timer period (aim for 1 ms).
#[no_mangle]
pub extern "C" fn GetTickCount() -> DWord {
    hal::timer::get_tick_count() as DWord
}

/// QueryPerformanceFrequency — returns the QPC tick frequency.
/// Games use this with QueryPerformanceCounter for high-res timing.
/// Return TRUE; frequency stored at *lpFrequency.
#[no_mangle]
pub unsafe extern "C" fn QueryPerformanceFrequency(lp_frequency: *mut i64) -> Bool {
    if lp_frequency.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return FALSE;
    }
    // Expose 1 MHz (10^6 ticks/sec) — easy to implement with HPET/TSC.
    // TODO: calibrate against actual hardware timer frequency.
    unsafe { *lp_frequency = 1_000_000; }
    TRUE
}

/// QueryPerformanceCounter — high-resolution timestamp.
/// CRITICAL: must be monotonic and accurate to ≤ 1 µs.
#[no_mangle]
pub unsafe extern "C" fn QueryPerformanceCounter(lp_counter: *mut i64) -> Bool {
    if lp_counter.is_null() {
        set_last_error(87);
        return FALSE;
    }
    // TODO: read RDTSC or HPET and convert to QPC units.
    unsafe { *lp_counter = 0; }
    TRUE
}

/// timeBeginPeriod — request timer resolution in milliseconds.
///
/// Almost every XP game calls timeBeginPeriod(1) at startup.
/// If we return TIMERR_NOERROR (0) they proceed; if we lie about
/// the actual resolution their sleep/wait loops will stutter.
#[no_mangle]
pub extern "C" fn timeBeginPeriod(u_period: DWord) -> DWord {
    hal::timer::set_resolution(u_period * 10_000); // ms → 100-ns units
    0 // TIMERR_NOERROR
}

/// timeEndPeriod — release a timer resolution request.
#[no_mangle]
pub extern "C" fn timeEndPeriod(_u_period: DWord) -> DWord { 0 }

/// Sleep — suspend the calling thread for dwMilliseconds.
#[no_mangle]
pub extern "C" fn Sleep(dw_milliseconds: DWord) {
    // TODO Phase 2: KeDelayExecutionThread via scheduler wait.
    // Phase 1: spin (acceptable for testing only).
    let _ = dw_milliseconds;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Memory — VirtualAlloc / VirtualFree / HeapAlloc
// ═══════════════════════════════════════════════════════════════════════════════

pub const MEM_COMMIT:   DWord = 0x1000;
pub const MEM_RESERVE:  DWord = 0x2000;
pub const MEM_RELEASE:  DWord = 0x8000;
pub const PAGE_READWRITE:         DWord = 0x04;
pub const PAGE_EXECUTE_READWRITE: DWord = 0x40;
pub const PAGE_NOACCESS:          DWord = 0x01;

/// VirtualAlloc — reserve/commit virtual memory.
///
/// Returns NULL on failure (sets LastError to ERROR_NOT_ENOUGH_MEMORY).
#[no_mangle]
pub unsafe extern "C" fn VirtualAlloc(
    lp_address:    LpVoid,
    dw_size:       usize,
    fl_allocation: DWord,
    fl_protect:    DWord,
) -> LpVoid {
    use mm::virtual_alloc::{AllocType, allocate};
    use mm::vad::PageProtect;

    // TODO Phase 2: get VAD from current process context.
    // Phase 1: return stub address.
    log::debug!("VirtualAlloc({:p}, {:#x}, {:#x}, {:#x})",
        lp_address, dw_size, fl_allocation, fl_protect);

    set_last_error(ERROR_NOT_ENOUGH_MEM);
    core::ptr::null_mut()
}

/// VirtualFree — decommit / release virtual memory.
#[no_mangle]
pub unsafe extern "C" fn VirtualFree(
    lp_address: LpVoid,
    dw_size:    usize,
    dw_type:    DWord,
) -> Bool {
    log::debug!("VirtualFree({:p}, {:#x}, {:#x})", lp_address, dw_size, dw_type);
    // TODO Phase 2: remove VAD node, release physical pages.
    TRUE
}

/// VirtualProtect — change protection on a committed region.
#[no_mangle]
pub unsafe extern "C" fn VirtualProtect(
    lp_address:          LpVoid,
    dw_size:             usize,
    fl_new_protect:      DWord,
    lp_old_protect:      *mut DWord,
) -> Bool {
    // TODO Phase 2: update page table entries and VAD node.
    if !lp_old_protect.is_null() {
        unsafe { *lp_old_protect = PAGE_READWRITE; }
    }
    TRUE
}

// ═══════════════════════════════════════════════════════════════════════════════
// Process / Thread
// ═══════════════════════════════════════════════════════════════════════════════

/// GetCurrentProcess — returns a pseudo-handle (-1) for the current process.
#[no_mangle]
pub extern "C" fn GetCurrentProcess() -> Handle {
    usize::MAX as Handle // (HANDLE)-1
}

/// GetCurrentThread — returns a pseudo-handle (-2) for the current thread.
#[no_mangle]
pub extern "C" fn GetCurrentThread() -> Handle {
    (usize::MAX - 1) as Handle // (HANDLE)-2
}

/// GetCurrentProcessId.
#[no_mangle]
pub extern "C" fn GetCurrentProcessId() -> DWord {
    // TODO: read from TEB → PEB → process PID.
    4
}

/// GetCurrentThreadId.
#[no_mangle]
pub extern "C" fn GetCurrentThreadId() -> DWord {
    // TODO: read from TEB.
    1
}

/// ExitProcess — terminate the current process.
#[no_mangle]
pub extern "C" fn ExitProcess(u_exit_code: DWord) -> ! {
    log::info!("ExitProcess({})", u_exit_code);
    // TODO Phase 2: NtTerminateProcess, clean up handles, signal exit event.
    loop { x86_64::instructions::hlt(); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error handling
// ═══════════════════════════════════════════════════════════════════════════════

/// GetLastError — return thread-local error code.
#[no_mangle]
pub extern "C" fn GetLastError() -> DWord { get_last_error_val() }

/// SetLastError.
#[no_mangle]
pub extern "C" fn SetLastError(dw_err_code: DWord) { set_last_error(dw_err_code); }

// ═══════════════════════════════════════════════════════════════════════════════
// Module handling (needed by GetModuleHandle / LoadLibrary)
// ═══════════════════════════════════════════════════════════════════════════════

/// GetModuleHandleA — returns the base address of the named module.
/// NULL = the .exe itself.
#[no_mangle]
pub unsafe extern "C" fn GetModuleHandleA(lp_module_name: *const u8) -> Handle {
    if lp_module_name.is_null() {
        return 0x0040_0000 as Handle; // typical XP default base
    }
    let name = match unsafe { c_str_to_str(lp_module_name) } {
        Some(v) => v,
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            return core::ptr::null_mut();
        }
    };
    if let Some(base) = ps::loader::resolve_stub_module_base(name) {
        set_last_error(ERROR_SUCCESS);
        return base as usize as Handle;
    }
    set_last_error(ERROR_INVALID_HANDLE);
    core::ptr::null_mut()
}

/// GetProcAddress — resolve an exported symbol by name.
#[no_mangle]
pub unsafe extern "C" fn GetProcAddress(
    h_module: Handle,
    lp_proc_name: *const u8,
) -> *mut u8 {
    if h_module.is_null() || lp_proc_name.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return core::ptr::null_mut();
    }
    if (lp_proc_name as usize) <= 0xFFFF {
        set_last_error(ERROR_INVALID_HANDLE);
        return core::ptr::null_mut();
    }
    let name = match unsafe { c_str_to_str(lp_proc_name) } {
        Some(v) => v,
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            return core::ptr::null_mut();
        }
    };
    let module_base = h_module as usize as u32;
    if let Some(addr) = ps::loader::resolve_stub_proc_by_base(module_base, name) {
        set_last_error(ERROR_SUCCESS);
        return addr as usize as *mut u8;
    }
    set_last_error(ERROR_INVALID_HANDLE);
    core::ptr::null_mut()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Synchronisation primitives (games use these for multi-threaded rendering)
// ═══════════════════════════════════════════════════════════════════════════════

/// CreateEventA — create a named or anonymous event object.
#[no_mangle]
pub unsafe extern "C" fn CreateEventA(
    _lp_event_attrs: LpVoid,
    b_manual_reset:  Bool,
    b_initial_state: Bool,
    _lp_name:        *const u8,
) -> Handle {
    use ke::event::{KEvent, EventType};
    use alloc::sync::Arc;

    let kind = if b_manual_reset != 0 {
        EventType::Notification
    } else {
        EventType::Synchronization
    };
    let ev = Arc::new(KEvent::new(kind, b_initial_state != 0));
    // TODO Phase 2: store in process handle table, return a real handle.
    // Phase 1: leak the Arc and return its raw pointer as a fake handle.
    let ptr = Arc::into_raw(ev) as Handle;
    set_last_error(ERROR_SUCCESS);
    ptr
}

/// SetEvent — signal an event.
#[no_mangle]
pub unsafe extern "C" fn SetEvent(h_event: Handle) -> Bool {
    if h_event.is_null() {
        set_last_error(ERROR_INVALID_HANDLE); return FALSE;
    }
    // TODO Phase 2: look up real event object from handle table.
    TRUE
}

/// ResetEvent — clear an event.
#[no_mangle]
pub unsafe extern "C" fn ResetEvent(h_event: Handle) -> Bool {
    if h_event.is_null() {
        set_last_error(ERROR_INVALID_HANDLE); return FALSE;
    }
    TRUE
}

/// WaitForSingleObject — wait on a handle with optional timeout.
pub const WAIT_OBJECT_0:  DWord = 0x0000_0000;
pub const WAIT_TIMEOUT:   DWord = 0x0000_0102;
pub const WAIT_FAILED:    DWord = 0xFFFF_FFFF;
pub const INFINITE:       DWord = 0xFFFF_FFFF;

#[no_mangle]
pub unsafe extern "C" fn WaitForSingleObject(
    h_handle:        Handle,
    dw_milliseconds: DWord,
) -> DWord {
    // TODO Phase 2: KeWaitForSingleObject via scheduler.
    // Phase 1: return immediately as if signalled.
    if h_handle.is_null() {
        set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    }
    WAIT_OBJECT_0
}

/// CloseHandle — decrement reference count on a kernel object.
#[no_mangle]
pub unsafe extern "C" fn CloseHandle(h_object: Handle) -> Bool {
    if h_object.is_null() {
        set_last_error(ERROR_INVALID_HANDLE); return FALSE;
    }
    // TODO Phase 2: ObCloseHandle — remove from handle table, drop Arc.
    TRUE
}
