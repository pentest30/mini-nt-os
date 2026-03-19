extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::ptr::{read_unaligned, write_unaligned};
use core::sync::atomic::{AtomicBool, Ordering};
use ob::object::{ObjectRef, ObjectType};
use spin::Mutex;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

const SYSCALL_NT_CREATE_PROCESS: u32 = 0x001B;
const SYSCALL_NT_CREATE_THREAD: u32 = 0x0035;
const SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x0011;
const SYSCALL_NT_TERMINATE_PROCESS: u32 = 0x00C2;
const SYSCALL_NT_WRITE_FILE: u32 = 0x0112;
const SYSCALL_NT_CREATE_FILE: u32 = 0x0025;
const SYSCALL_NT_READ_FILE: u32 = 0x00B7;
const SYSCALL_NT_QUERY_INFORMATION_FILE: u32 = 0x00B4;
const SYSCALL_NT_CLOSE: u32 = 0x0019;

// ── Win32 syscall numbers (INT 0x2E from kernel32/user32/msvcrt/winmm stubs) ──
const WIN32_GET_TICK_COUNT:     u32 = 0x2000;
const WIN32_SLEEP:              u32 = 0x2001;
const WIN32_VIRTUAL_ALLOC:      u32 = 0x2002;
const WIN32_VIRTUAL_FREE:       u32 = 0x2003;
const WIN32_VIRTUAL_PROTECT:    u32 = 0x2004;
const WIN32_GET_PROC_ADDRESS:   u32 = 0x2005;
const WIN32_GET_MODULE_HANDLE:  u32 = 0x2006;
const WIN32_EXIT_PROCESS:       u32 = 0x2007;
const WIN32_CREATE_WINDOW:      u32 = 0x2010;
const WIN32_SHOW_WINDOW:        u32 = 0x2011;
const WIN32_GET_MESSAGE:        u32 = 0x2012;
const WIN32_DISPATCH_MESSAGE:   u32 = 0x2013;
const WIN32_TRANSLATE_MESSAGE:  u32 = 0x2014;
const WIN32_PEEK_MESSAGE:       u32 = 0x2015;
const WIN32_POST_QUIT_MESSAGE:  u32 = 0x2016;
const WIN32_REGISTER_CLASS_A:   u32 = 0x2017;
const WIN32_DEF_WINDOW_PROC_A:  u32 = 0x2018;
const WIN32_LOOKUP_WNDPROC:     u32 = 0x2019;
const WIN32_SET_TIMER:          u32 = 0x2060;
const WIN32_KILL_TIMER:         u32 = 0x2061;
const WM_KEYDOWN:               u32 = 0x0100;
const WIN32_MALLOC:             u32 = 0x2020;
const WIN32_CALLOC:             u32 = 0x2021;
const WIN32_FREE:               u32 = 0x2022;
const WIN32_MEMCPY:             u32 = 0x2023;
const WIN32_MEMSET:             u32 = 0x2024;
const WIN32_STRLEN:             u32 = 0x2025;
const WIN32_TIME_BEGIN_PERIOD:  u32 = 0x2030;
const WIN32_CREATE_FILE_A:     u32 = 0x2033;
const WIN32_TIME_END_PERIOD:    u32 = 0x2031;
const WIN32_TIME_GET_TIME:      u32 = 0x2032;
const WIN32_LIST_DIR:           u32 = 0x2040;
const WIN32_CAT_FILE:           u32 = 0x2041;
const WIN32_DRAW_DEMO_FRAME:    u32 = 0x2050;

// ── kernel32 Phase 3A ─────────────────────────────────────────────────────────
const WIN32_TLS_ALLOC:            u32 = 0x2070;
const WIN32_TLS_FREE:             u32 = 0x2071;
const WIN32_TLS_GET_VALUE:        u32 = 0x2072;
const WIN32_TLS_SET_VALUE:        u32 = 0x2073;
const WIN32_INIT_CRITICAL_SEC:    u32 = 0x2074;
const WIN32_ENTER_CRITICAL_SEC:   u32 = 0x2075;
const WIN32_LEAVE_CRITICAL_SEC:   u32 = 0x2076;
const WIN32_TRY_ENTER_CRITICAL:   u32 = 0x2078;
const WIN32_ACQUIRE_SRW_EXCL:     u32 = 0x2079;
const WIN32_RELEASE_SRW_EXCL:     u32 = 0x207A;
const WIN32_GET_MODULE_HANDLE_W:  u32 = 0x207F;
const WIN32_GET_MODULE_HANDLE_EX: u32 = 0x2080;
const WIN32_LOAD_LIBRARY_A:       u32 = 0x2081;
const WIN32_GET_SYSTEM_INFO:      u32 = 0x2082;
const WIN32_GET_TICK_COUNT_64:    u32 = 0x2083;
const WIN32_CREATE_THREAD_K32:    u32 = 0x2084;
const WIN32_GET_CURRENT_PID:      u32 = 0x2085;
const WIN32_GET_CURRENT_TID:      u32 = 0x2086;
const WIN32_WAIT_FOR_MULTI:       u32 = 0x2087;
const WIN32_WAIT_SINGLE_EX:       u32 = 0x2088;
const WIN32_CREATE_EVENT_A:       u32 = 0x2089;
const WIN32_SET_EVENT:            u32 = 0x208A;
const WIN32_RESET_EVENT:          u32 = 0x208B;
const WIN32_CREATE_SEMAPHORE_A:   u32 = 0x208C;
const WIN32_RELEASE_SEMAPHORE:    u32 = 0x208D;
const WIN32_CREATE_FILE_MAPPING:  u32 = 0x208E;
const WIN32_MAP_VIEW_OF_FILE:     u32 = 0x208F;
const WIN32_GET_TEMP_PATH_A:      u32 = 0x2091;
const WIN32_GET_TEMP_FILE_A:      u32 = 0x2092;
const WIN32_OUTPUT_DEBUG_STR:     u32 = 0x2093;
const WIN32_VIRTUAL_QUERY:        u32 = 0x2095;
const WIN32_GET_MODULE_FILE_W:    u32 = 0x2096;
const WIN32_QUERY_PERF_COUNTER:   u32 = 0x2098;
const WIN32_QUERY_PERF_FREQ:      u32 = 0x2099;
const WIN32_HEAP_ALLOC:           u32 = 0x209A;
const WIN32_SET_LAST_ERROR:       u32 = 0x209B;
const WIN32_GET_SYSTEM_TIME_FT:  u32 = 0x209C;
const WIN32_GET_USER_NAME_A:      u32 = 0x209D; // ADVAPI32 GetUserNameA
// ── Ghost Recon kernel32 ────────────────────────────────────────────────────
const WIN32_GLOBAL_MEMORY_STATUS: u32 = 0x20A0;
const WIN32_GET_MODULE_FILE_A:    u32 = 0x20A1;
const WIN32_MULTI_BYTE_TO_WIDE:   u32 = 0x20A2;
const WIN32_GET_VERSION_EX_A:     u32 = 0x20A3;
const WIN32_LSTRCPY_A:            u32 = 0x20A4;
const WIN32_GET_CURRENT_DIR_A:    u32 = 0x20A5;
const WIN32_LSTRCAT_A:            u32 = 0x20A6;
const WIN32_LSTRCPYN_A:           u32 = 0x20A7;
const WIN32_LSTRLEN_A:            u32 = 0x20A8;
const WIN32_WRITE_FILE:           u32 = 0x20A9;
const WIN32_GET_FILE_SIZE:        u32 = 0x20AA;
const WIN32_FIND_FIRST_FILE_A:    u32 = 0x20AB;
const WIN32_GET_FILE_ATTRS_A:     u32 = 0x20AC;
const WIN32_GET_FULL_PATH_A:      u32 = 0x20AD;
const WIN32_GET_CP_INFO:          u32 = 0x20AE;
const WIN32_GET_FILE_TYPE:        u32 = 0x20AF;
const WIN32_GET_COMMAND_LINE_A:   u32 = 0x20AF;
const WIN32_GET_LOCAL_TIME:       u32 = 0x20B0;
const WIN32_GET_STARTUP_INFO_A:   u32 = 0x20B1;
const WIN32_GET_STD_HANDLE:       u32 = 0x20B2;
const WIN32_HEAP_REALLOC:         u32 = 0x20B4;
const WIN32_MUL_DIV:              u32 = 0x20B5;
const WIN32_READ_FILE:            u32 = 0x20B6;
const WIN32_WIDE_TO_MULTI_BYTE:   u32 = 0x20B7;
// ── user32 Phase 3A ───────────────────────────────────────────────────────────
const WIN32_GET_CLIENT_RECT:      u32 = 0x2120;
const WIN32_ENUM_DISPLAY_SETTINGS:u32 = 0x2121;
const WIN32_MESSAGE_BOX_A:        u32 = 0x2122;
const WIN32_ENUM_DISPLAY_SETTINGS_A: u32 = 0x2123;
const WIN32_GET_SYSTEM_METRICS:   u32 = 0x2124;
// ── winmm ───────────────────────────────────────────────────────────────────
const WIN32_TIME_GET_DEV_CAPS:    u32 = 0x2033;
// ── UCRT (api-ms-win-crt-*) ───────────────────────────────────────────────────
const UCRT_REALLOC:               u32 = 0x20B3;
const UCRT_INIT_ONEXIT_TABLE:     u32 = 0x20B8;
const UCRT_REG_ONEXIT_FN:         u32 = 0x20B9;
const UCRT_BEGINTHREADEX:         u32 = 0x20BB;
const UCRT_ERRNO_PTR:             u32 = 0x20BD;
const UCRT_STRCMP:                u32 = 0x20C8;
const UCRT_STRNCMP:               u32 = 0x20C9;
const UCRT_STRNCPY:               u32 = 0x20CA;
const UCRT_STRNLEN:               u32 = 0x20CB;
const UCRT_STRCHR:                u32 = 0x20CC;
const UCRT_STRDUP:                u32 = 0x20CD;
const UCRT_WCSLEN:                u32 = 0x20CE;
const UCRT_WCSNLEN:               u32 = 0x20CF;
const UCRT_WCSCMP:                u32 = 0x20D0;
const UCRT_WCSICMP:               u32 = 0x20D1;
const UCRT_STRTOUL:               u32 = 0x20D2;
const UCRT_MEMCMP:                u32 = 0x20D3;
const UCRT_MEMCHR:                u32 = 0x20D4;
const UCRT_MEMMOVE:               u32 = 0x20D5;
// ── ADVAPI32 ──────────────────────────────────────────────────────────────────
const ADVAPI_REG_OPEN_KEY_EX_A:   u32 = 0x20E0;
const ADVAPI_REG_QUERY_VALUE_A:   u32 = 0x20E1;
const ADVAPI_REG_CLOSE_KEY:       u32 = 0x20E2;
const ADVAPI_REG_OPEN_KEY_EX_W:   u32 = 0x20E3;
const ADVAPI_REG_QUERY_VALUE_W:   u32 = 0x20E4;
const ADVAPI_ALLOC_LUID:          u32 = 0x20E6;

// ── Vulkan ICD loader syscalls (vulkan-1.dll stubs → INT 0x2E) ──────────────
const VK_GET_INSTANCE_PROC_ADDR:   u32 = 0x3000;
const VK_GET_DEVICE_PROC_ADDR:     u32 = 0x3001;
const VK_ENUM_INST_EXT_PROPS:      u32 = 0x3004;
const VK_ENUM_INST_LAYER_PROPS:    u32 = 0x3005;
const VK_ENUM_INST_VERSION:        u32 = 0x3006;
const VK_ENUM_PHYSICAL_DEVICES:    u32 = 0x3007;
const VK_GET_PHYS_DEV_PROPS:       u32 = 0x3008;
const VK_GET_PHYS_DEV_PROPS2:      u32 = 0x3009;
const VK_GET_PHYS_DEV_FEATURES:    u32 = 0x300A;
const VK_GET_PHYS_DEV_FEATURES2:   u32 = 0x300B;
const VK_GET_PHYS_DEV_MEM_PROPS:   u32 = 0x300C;
const VK_GET_PHYS_DEV_MEM_PROPS2:  u32 = 0x300D;
const VK_GET_PHYS_DEV_QUEUE_PROPS: u32 = 0x300E;
const VK_GET_PHYS_DEV_FMT_PROPS:   u32 = 0x300F;
const VK_GET_PHYS_DEV_FMT_PROPS2:  u32 = 0x3010;
const VK_ENUM_DEV_EXT_PROPS:       u32 = 0x3011;
const VK_GET_SURFACE_CAPS:         u32 = 0x3012;
const VK_GET_SURFACE_FORMATS:      u32 = 0x3013;
const VK_GET_SURFACE_PRESENT_MODES:u32 = 0x3014;
const VK_GET_SURFACE_SUPPORT:      u32 = 0x3015;
const VK_GET_SWAPCHAIN_IMAGES:     u32 = 0x3016;
const VK_ACQUIRE_NEXT_IMAGE:       u32 = 0x3017;
const VK_ALLOC_CMD_BUFFERS:        u32 = 0x3018;
const VK_MAP_MEMORY:               u32 = 0x3019;
const VK_GET_IMAGE_MEM_REQS:       u32 = 0x301A;
const VK_GET_BUFFER_MEM_REQS:      u32 = 0x301B;
const VK_ALLOC_DESCRIPTOR_SETS:    u32 = 0x301C;
const VK_CREATE_GRAPHICS_PIPES:    u32 = 0x301D;
const VK_CREATE_COMPUTE_PIPES:     u32 = 0x301E;
const VK_QUEUE_PRESENT:            u32 = 0x301F;

const USER_MIN_VA: u32 = 0x0000_1000;
const USER_MAX_EXCLUSIVE: u32 = 0x8000_0000;

struct SyscallContext {
    hhdm_offset: u64,
    vad: mm::vad::VadTree,
}

static SYSCALL_CTX: Mutex<Option<SyscallContext>> = Mutex::new(None);
static NEXT_TID: Mutex<u64> = Mutex::new(8);
static PROCESS_HANDLE_PID_MAP: Mutex<[Option<(u32, u32)>; 64]> = Mutex::new([None; 64]);
static FILE_HANDLE_MAP: Mutex<[Option<(u32, io_manager::FatFile)>; 64]> = Mutex::new([None; 64]);
static PROCESS_LAUNCH_MAP: Mutex<[Option<(u32, u32, u32)>; 64]> = Mutex::new([None; 64]);
static WIN32_NEXT_HWND: Mutex<u32> = Mutex::new(1);

// One-shot smoke markers — log each path only once so CMD.EXE's prompt loop
// doesn't flood the framebuffer console with repeated [INFO] messages.
static SMOKE_INT2E_LOGGED: AtomicBool = AtomicBool::new(false);
static SMOKE_IAT_LOGGED:   AtomicBool = AtomicBool::new(false);
static WIN32_MSG_QUEUE: Mutex<[Option<Win32Msg>; 64]> = Mutex::new([None; 64]);
static WIN32_QUIT_PENDING: Mutex<Option<u32>> = Mutex::new(None);
static WIN32_NEXT_CLASS_ATOM: Mutex<u32> = Mutex::new(1);
static WIN32_CLASS_MAP: Mutex<[Option<(u32, u32, u32)>; 64]> = Mutex::new([None; 64]);
static WIN32_WINDOW_PROC_MAP: Mutex<[Option<(u32, u32)>; 64]> = Mutex::new([None; 64]);
/// Timer table: (hwnd, timer_id, period_ms, next_fire_ms)
static WIN32_TIMER_TABLE: Mutex<[Option<(u32, u32, u32, u32)>; 16]> = Mutex::new([None; 16]);
/// Tick count (ms) at which WM_PAINT was last synthesised. Rate-limits paint messages to ~60 fps.
static WIN32_LAST_PAINT_MS: Mutex<u32> = Mutex::new(0);

// ── Phase 3A state ────────────────────────────────────────────────────────────
/// TLS slot allocation bitmap (64 slots, XP TlsSlots in TEB at offset 0xE10).
static TLS_BITMAP: Mutex<u64> = Mutex::new(0);
/// Per-process errno value (single-threaded approximation for Phase 3A).
static ERRNO_VAL: Mutex<i32> = Mutex::new(0);
/// Opened registry keys: [(fake_hkey, subkey_index)]. fake_hkey = index+1.
static REG_OPEN_KEYS: Mutex<[Option<(u32, usize)>; 32]> = Mutex::new([None; 32]);

#[derive(Clone, Copy)]
struct Win32Msg {
    hwnd: u32,
    message: u32,
    w_param: u32,
    l_param: u32,
    time: u32,
    pt_x: u32,
    pt_y: u32,
}

pub fn install(vad: mm::vad::VadTree, hhdm_offset: u64) {
    let mut guard = SYSCALL_CTX.lock();
    *guard = Some(SyscallContext {
        hhdm_offset,
        vad: mm::vad::VadTree::new(),
    });
    core::mem::forget(vad);
}

/// Return the HHDM offset from the syscall context (for launcher process setup).
pub fn SYSCALL_CTX_PUB() -> Option<u64> {
    let guard = SYSCALL_CTX.lock();
    guard.as_ref().map(|c| c.hhdm_offset)
}

pub fn dispatch(number: u32, args_ptr: u32) -> u32 {
    // Trace Win32 UI syscalls (0x2010..0x201F) during message pump debugging.
    if number >= 0x2010 && number <= 0x201F {
        log::info!("[w32dbg] dispatch: syscall={:#x} args_ptr={:#x}", number, args_ptr);
    }
    // Trace all game syscalls (0x20xx range, skip known high-frequency ones)
    if number >= 0x2000 && number != 0x2000 && number != 0x2012 && number != 0x2014
        && number != 0x2015 {
        hal::serial::write_str("[sys] ");
        hal::serial::write_fmt(core::format_args!("{:#x}\n", number));
    }
    match number {
        // ── NT native syscalls ────────────────────────────────────────────────
        SYSCALL_NT_CREATE_PROCESS           => nt_create_process(args_ptr),
        SYSCALL_NT_CREATE_THREAD            => nt_create_thread(args_ptr),
        SYSCALL_NT_TERMINATE_PROCESS        => nt_terminate_process(args_ptr),
        SYSCALL_NT_WRITE_FILE               => nt_write_file(args_ptr),
        SYSCALL_NT_CREATE_FILE              => nt_create_file(args_ptr),
        SYSCALL_NT_READ_FILE                => nt_read_file(args_ptr),
        SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY  => nt_allocate_virtual_memory(args_ptr),
        SYSCALL_NT_QUERY_INFORMATION_FILE   => nt_query_information_file(args_ptr),
        SYSCALL_NT_CLOSE                    => nt_close(args_ptr),
        // ── Win32 syscalls (kernel32 / user32 / msvcrt / winmm stubs) ────────
        WIN32_GET_TICK_COUNT    => win32_get_tick_count(),
        WIN32_SLEEP             => 0, // no-op; TODO: KeDelayExecutionThread
        WIN32_VIRTUAL_ALLOC     => win32_virtual_alloc(args_ptr),
        WIN32_VIRTUAL_FREE      => 1, // TRUE; no-op decommit stub
        WIN32_VIRTUAL_PROTECT   => win32_virtual_protect(args_ptr),
        WIN32_GET_PROC_ADDRESS  => win32_get_proc_address(args_ptr),
        WIN32_GET_MODULE_HANDLE => win32_get_module_handle_a(args_ptr),
        WIN32_EXIT_PROCESS      => win32_exit_process(args_ptr),
        WIN32_CREATE_WINDOW     => win32_create_window(args_ptr),
        WIN32_SHOW_WINDOW       => 1,
        WIN32_GET_MESSAGE       => win32_get_message(args_ptr),
        WIN32_DISPATCH_MESSAGE  => win32_dispatch_message(args_ptr),
        WIN32_TRANSLATE_MESSAGE => 1,
        WIN32_PEEK_MESSAGE      => win32_peek_message(args_ptr),
        WIN32_POST_QUIT_MESSAGE => win32_post_quit_message(args_ptr),
        WIN32_REGISTER_CLASS_A  => win32_register_class_a(args_ptr),
        WIN32_DEF_WINDOW_PROC_A => win32_def_window_proc_a(args_ptr),
        WIN32_SET_TIMER         => win32_set_timer(args_ptr),
        WIN32_KILL_TIMER        => win32_kill_timer(args_ptr),
        WIN32_MALLOC            => win32_malloc(args_ptr),
        WIN32_CALLOC            => win32_calloc(args_ptr),
        WIN32_FREE              => 0, // no-op; Phase 2.5: memory is never returned
        WIN32_MEMCPY            => win32_memcpy(args_ptr),
        WIN32_MEMSET            => win32_memset(args_ptr),
        WIN32_STRLEN            => win32_strlen(args_ptr),
        WIN32_TIME_BEGIN_PERIOD => win32_time_begin_period(args_ptr),
        WIN32_TIME_END_PERIOD   => 0, // TIMERR_NOERROR
        WIN32_TIME_GET_TIME     => win32_get_tick_count(),
        WIN32_LIST_DIR          => win32_list_dir(args_ptr),
        WIN32_CAT_FILE          => win32_cat_file(args_ptr),
        WIN32_DRAW_DEMO_FRAME   => win32_draw_demo_frame(),
        WIN32_CREATE_FILE_A     => win32_create_file_a(args_ptr),
        WIN32_LOOKUP_WNDPROC    => win32_lookup_wndproc(args_ptr),
        // ── kernel32 Phase 3A ─────────────────────────────────────────────────
        WIN32_TLS_ALLOC            => win32_tls_alloc(),
        WIN32_TLS_FREE             => win32_tls_free(args_ptr),
        WIN32_TLS_GET_VALUE        => win32_tls_get_value(args_ptr),
        WIN32_TLS_SET_VALUE        => win32_tls_set_value(args_ptr),
        WIN32_INIT_CRITICAL_SEC    => win32_init_critical_section(args_ptr),
        WIN32_ENTER_CRITICAL_SEC   => win32_enter_critical_section(args_ptr),
        WIN32_LEAVE_CRITICAL_SEC   => win32_leave_critical_section(args_ptr),
        WIN32_TRY_ENTER_CRITICAL   => win32_try_enter_critical_section(args_ptr),
        WIN32_ACQUIRE_SRW_EXCL     => win32_acquire_srw_exclusive(args_ptr),
        WIN32_RELEASE_SRW_EXCL     => win32_release_srw_exclusive(args_ptr),
        WIN32_GET_MODULE_HANDLE_W  => win32_get_module_handle_w(args_ptr),
        WIN32_GET_MODULE_HANDLE_EX => win32_get_module_handle_ex_a(args_ptr),
        WIN32_LOAD_LIBRARY_A       => win32_load_library_a(args_ptr),
        WIN32_GET_SYSTEM_INFO      => win32_get_system_info(args_ptr),
        WIN32_GET_TICK_COUNT_64    => win32_get_tick_count(),
        WIN32_CREATE_THREAD_K32    => win32_create_thread_k32(args_ptr),
        WIN32_GET_CURRENT_PID      => 1, // fixed PID
        WIN32_GET_CURRENT_TID      => 1, // fixed TID
        WIN32_WAIT_FOR_MULTI       => 0, // WAIT_OBJECT_0; stub
        WIN32_WAIT_SINGLE_EX       => 0, // WAIT_OBJECT_0; stub
        WIN32_CREATE_EVENT_A       => win32_create_event_a(args_ptr),
        WIN32_SET_EVENT            => 1,
        WIN32_RESET_EVENT          => 1,
        WIN32_CREATE_SEMAPHORE_A   => 1, // fake semaphore handle
        WIN32_RELEASE_SEMAPHORE    => 1,
        WIN32_CREATE_FILE_MAPPING  => win32_create_file_mapping(args_ptr),
        WIN32_MAP_VIEW_OF_FILE     => win32_map_view_of_file(args_ptr),
        WIN32_GET_TEMP_PATH_A      => win32_get_temp_path_a(args_ptr),
        WIN32_GET_TEMP_FILE_A      => win32_get_temp_file_name_a(args_ptr),
        WIN32_OUTPUT_DEBUG_STR     => win32_output_debug_string(args_ptr),
        WIN32_VIRTUAL_QUERY        => win32_virtual_query(args_ptr),
        WIN32_GET_MODULE_FILE_W    => win32_get_module_file_name_w(args_ptr),
        WIN32_QUERY_PERF_COUNTER   => win32_query_perf_counter(args_ptr),
        WIN32_QUERY_PERF_FREQ      => win32_query_perf_freq(args_ptr),
        WIN32_HEAP_ALLOC           => win32_heap_alloc(args_ptr),
        WIN32_SET_LAST_ERROR       => 0, // nop
        WIN32_GET_SYSTEM_TIME_FT   => win32_get_system_time_as_file_time(args_ptr),
        // ── Ghost Recon kernel32 ────────────────────────────────────────────
        WIN32_GLOBAL_MEMORY_STATUS => win32_global_memory_status(args_ptr),
        WIN32_GET_MODULE_FILE_A    => win32_get_module_file_name_a(args_ptr),
        WIN32_MULTI_BYTE_TO_WIDE   => win32_multi_byte_to_wide_char(args_ptr),
        WIN32_GET_VERSION_EX_A     => win32_get_version_ex_a(args_ptr),
        WIN32_LSTRCPY_A            => win32_lstrcpy_a(args_ptr),
        WIN32_GET_CURRENT_DIR_A    => win32_get_current_dir_a(args_ptr),
        WIN32_LSTRCAT_A            => win32_lstrcat_a(args_ptr),
        WIN32_LSTRCPYN_A           => win32_lstrcpyn_a(args_ptr),
        WIN32_LSTRLEN_A            => win32_lstrlen_a(args_ptr),
        WIN32_WRITE_FILE           => win32_write_file(args_ptr),
        WIN32_GET_FILE_SIZE        => win32_get_file_size(args_ptr),
        WIN32_FIND_FIRST_FILE_A    => 0xFFFF_FFFF, // INVALID_HANDLE_VALUE — no files found
        WIN32_GET_FILE_ATTRS_A     => win32_get_file_attributes_a(args_ptr),
        WIN32_GET_FULL_PATH_A      => win32_get_full_path_name_a(args_ptr),
        WIN32_GET_CP_INFO          => win32_get_cp_info(args_ptr),
        WIN32_GET_FILE_TYPE        => win32_get_file_type(args_ptr),
        WIN32_GET_COMMAND_LINE_A   => win32_get_command_line_a(),
        WIN32_GET_LOCAL_TIME       => win32_get_local_time(args_ptr),
        WIN32_GET_STARTUP_INFO_A   => win32_get_startup_info_a(args_ptr),
        WIN32_GET_STD_HANDLE       => win32_get_std_handle(args_ptr),
        WIN32_HEAP_REALLOC         => win32_heap_realloc(args_ptr),
        WIN32_MUL_DIV              => win32_mul_div(args_ptr),
        WIN32_READ_FILE            => win32_read_file_k32(args_ptr),
        WIN32_WIDE_TO_MULTI_BYTE   => win32_wide_char_to_multi_byte(args_ptr),
        // ── user32 Phase 3A ───────────────────────────────────────────────────
        WIN32_GET_CLIENT_RECT      => win32_get_client_rect(args_ptr),
        WIN32_ENUM_DISPLAY_SETTINGS=> win32_enum_display_settings_w(args_ptr),
        WIN32_MESSAGE_BOX_A        => win32_message_box_a(args_ptr),
        WIN32_ENUM_DISPLAY_SETTINGS_A => win32_enum_display_settings_a(args_ptr),
        WIN32_GET_SYSTEM_METRICS   => win32_get_system_metrics(args_ptr),
        // ── winmm ───────────────────────────────────────────────────────────
        WIN32_TIME_GET_DEV_CAPS    => win32_time_get_dev_caps(args_ptr),
        // ── UCRT ──────────────────────────────────────────────────────────────
        UCRT_REALLOC               => ucrt_realloc(args_ptr),
        UCRT_INIT_ONEXIT_TABLE     => ucrt_init_onexit_table(args_ptr),
        UCRT_REG_ONEXIT_FN         => ucrt_register_onexit_fn(args_ptr),
        UCRT_BEGINTHREADEX         => ucrt_beginthreadex(args_ptr),
        UCRT_ERRNO_PTR             => ucrt_errno_ptr(),
        UCRT_STRCMP                => ucrt_strcmp(args_ptr),
        UCRT_STRNCMP               => ucrt_strncmp(args_ptr),
        UCRT_STRNCPY               => ucrt_strncpy(args_ptr),
        UCRT_STRNLEN               => ucrt_strnlen(args_ptr),
        UCRT_STRCHR                => ucrt_strchr(args_ptr),
        UCRT_STRDUP                => ucrt_strdup(args_ptr),
        UCRT_WCSLEN                => ucrt_wcslen(args_ptr),
        UCRT_WCSNLEN               => ucrt_wcsnlen(args_ptr),
        UCRT_WCSCMP                => ucrt_wcscmp(args_ptr),
        UCRT_WCSICMP               => ucrt_wcsicmp(args_ptr),
        UCRT_STRTOUL               => ucrt_strtoul(args_ptr),
        UCRT_MEMCMP                => ucrt_memcmp(args_ptr),
        UCRT_MEMCHR                => ucrt_memchr(args_ptr),
        UCRT_MEMMOVE               => win32_memcpy(args_ptr), // overlap-safe approximation
        // ── ADVAPI32 ──────────────────────────────────────────────────────────
        ADVAPI_REG_OPEN_KEY_EX_A   => advapi_reg_open_key_ex_a(args_ptr),
        ADVAPI_REG_QUERY_VALUE_A   => advapi_reg_query_value_ex_a(args_ptr),
        ADVAPI_REG_CLOSE_KEY       => advapi_reg_close_key(args_ptr),
        ADVAPI_REG_OPEN_KEY_EX_W   => advapi_reg_open_key_ex_w(args_ptr),
        ADVAPI_REG_QUERY_VALUE_W   => advapi_reg_query_value_ex_w(args_ptr),
        ADVAPI_ALLOC_LUID          => advapi_alloc_luid(args_ptr),
        WIN32_GET_USER_NAME_A      => win32_get_user_name_a(args_ptr),
        // ── Vulkan ICD loader ───────────────────────────────────────────────
        VK_GET_INSTANCE_PROC_ADDR   => vk_get_instance_proc_addr(args_ptr),
        VK_GET_DEVICE_PROC_ADDR     => vk_get_device_proc_addr(args_ptr),
        VK_ENUM_INST_EXT_PROPS      => vk_enum_inst_ext_props(args_ptr),
        VK_ENUM_INST_LAYER_PROPS    => vk_enum_inst_layer_props(args_ptr),
        VK_ENUM_INST_VERSION        => vk_enum_inst_version(args_ptr),
        VK_ENUM_PHYSICAL_DEVICES    => vk_enum_physical_devices(args_ptr),
        VK_GET_PHYS_DEV_PROPS       => vk_get_phys_dev_props(args_ptr),
        VK_GET_PHYS_DEV_PROPS2      => vk_get_phys_dev_props2(args_ptr),
        VK_GET_PHYS_DEV_FEATURES    => vk_get_phys_dev_features(args_ptr),
        VK_GET_PHYS_DEV_FEATURES2   => vk_get_phys_dev_features2(args_ptr),
        VK_GET_PHYS_DEV_MEM_PROPS   => vk_get_phys_dev_mem_props(args_ptr),
        VK_GET_PHYS_DEV_MEM_PROPS2  => vk_get_phys_dev_mem_props2(args_ptr),
        VK_GET_PHYS_DEV_QUEUE_PROPS => vk_get_phys_dev_queue_props(args_ptr),
        VK_GET_PHYS_DEV_FMT_PROPS   => vk_get_phys_dev_fmt_props(args_ptr),
        VK_GET_PHYS_DEV_FMT_PROPS2  => vk_get_phys_dev_fmt_props(args_ptr), // same handler
        VK_ENUM_DEV_EXT_PROPS       => vk_enum_dev_ext_props(args_ptr),
        VK_GET_SURFACE_CAPS         => vk_get_surface_caps(args_ptr),
        VK_GET_SURFACE_FORMATS      => vk_get_surface_formats(args_ptr),
        VK_GET_SURFACE_PRESENT_MODES=> vk_get_surface_present_modes(args_ptr),
        VK_GET_SURFACE_SUPPORT      => vk_get_surface_support(args_ptr),
        VK_GET_SWAPCHAIN_IMAGES     => vk_get_swapchain_images(args_ptr),
        VK_ACQUIRE_NEXT_IMAGE       => vk_acquire_next_image(args_ptr),
        VK_ALLOC_CMD_BUFFERS        => vk_alloc_cmd_buffers(args_ptr),
        VK_MAP_MEMORY               => vk_map_memory(args_ptr),
        VK_GET_IMAGE_MEM_REQS       => vk_get_mem_reqs(args_ptr),
        VK_GET_BUFFER_MEM_REQS      => vk_get_mem_reqs(args_ptr), // same layout
        VK_ALLOC_DESCRIPTOR_SETS    => vk_alloc_descriptor_sets(args_ptr),
        VK_CREATE_GRAPHICS_PIPES    => vk_create_pipelines(args_ptr),
        VK_CREATE_COMPUTE_PIPES     => vk_create_pipelines(args_ptr),
        VK_QUEUE_PRESENT            => vk_queue_present(args_ptr),
        _ => STATUS_INVALID_SYSTEM_SERVICE,
    }
}

fn nt_create_file(args_ptr: u32) -> u32 {
    let out_handle_ptr = match read_arg_u32(args_ptr, 0) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let object_attributes_ptr = match read_arg_u32(args_ptr, 2) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if !is_user_range(out_handle_ptr, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let nt_path = match read_object_attributes_path(object_attributes_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let fat_path = match normalize_nt_path_to_fat(&nt_path) {
        Some(v) => v,
        None => return STATUS_INVALID_PARAMETER,
    };
    let file_state = match io_manager::open_fat_file(&fat_path) {
        Ok(v) => v,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };
    let file_obj = io_manager::FileObject::new(&nt_path, 0);
    let obj: ObjectRef = Arc::new(file_obj);
    let system = ps::eprocess::system_process();
    let handle = {
        let mut table = system.handle_table.lock();
        table.insert(obj, 0, false) as u32
    };
    remember_file_handle_state(handle, file_state);
    if write_u32_user(out_handle_ptr, handle).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

fn nt_read_file(args_ptr: u32) -> u32 {
    let file_handle = match read_arg_u32(args_ptr, 0) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let iosb_ptr = match read_arg_u32(args_ptr, 4) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let buffer_ptr = match read_arg_u32(args_ptr, 5) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let length = match read_arg_u32(args_ptr, 6) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let byte_offset_ptr = match read_arg_u32(args_ptr, 7) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if length == 0 {
        if iosb_ptr != 0 {
            let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
            let _ = write_u32_user(iosb_ptr.wrapping_add(4), 0);
        }
        return STATUS_SUCCESS;
    }
    if !is_user_range(buffer_ptr, length) {
        return STATUS_ACCESS_VIOLATION;
    }
    if is_console_input_handle(file_handle) {
        let mut n = 0u32;
        // INT 0x2E is an interrupt gate (IF=0 on entry). Re-enable interrupts
        // here so the APIC timer can fire and schedule TID=3 (TEST.EXE) while
        // we spin waiting for serial input.  No locks are held at this point.
        // SAFETY: no spin::Mutex is held; safe to re-enable IRQs.
        x86_64::instructions::interrupts::enable();
        // Block until a byte arrives from serial or PS/2 keyboard.
        // Skip PS/2 when the launcher has exclusive input focus.
        let first = loop {
            if let Some(b) = hal::serial::try_read_byte() { break b; }
            if !hal::fb::is_exclusive() {
                if let Some(sc) = hal::ps2::pop_scancode() {
                    if let Some(ascii) = hal::ps2::scancode_to_ascii_pub(sc) {
                        break ascii;
                    }
                    continue;
                }
            }
            x86_64::instructions::hlt();
        };
        x86_64::instructions::interrupts::disable();
        unsafe { (buffer_ptr as *mut u8).write_unaligned(first); }
        n += 1;
        while n < length {
            let b = if let Some(v) = hal::serial::try_read_byte() { v }
                    else if !hal::fb::is_exclusive() {
                        if let Some(sc) = hal::ps2::pop_scancode() {
                            match hal::ps2::scancode_to_ascii_pub(sc) { Some(a) => a, None => continue }
                        } else { break }
                    } else { break };
            unsafe { (buffer_ptr as *mut u8).add(n as usize).write_unaligned(b); }
            n += 1;
        }
        if iosb_ptr != 0 {
            if !is_user_range(iosb_ptr, 8) {
                return STATUS_ACCESS_VIOLATION;
            }
            let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
            let _ = write_u32_user(iosb_ptr.wrapping_add(4), n);
        }
        return STATUS_SUCCESS;
    }
    let mut state = match lookup_file_handle_state(file_handle) {
        Some(v) => v,
        None => return STATUS_INVALID_HANDLE,
    };
    if byte_offset_ptr != 0 {
        if !is_user_range(byte_offset_ptr, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let lo = match read_u32_user(byte_offset_ptr) {
            Ok(v) => v,
            Err(s) => return s,
        };
        let _hi = match read_u32_user(byte_offset_ptr.wrapping_add(4)) {
            Ok(v) => v,
            Err(s) => return s,
        };
        state.position = lo;
    }
    let mut tmp = vec![0u8; length as usize];
    let n = match io_manager::read_fat_file(&mut state, &mut tmp) {
        Ok(v) => v,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };
    let mut i = 0usize;
    while i < n {
        unsafe { (buffer_ptr as *mut u8).add(i).write_unaligned(tmp[i]); }
        i += 1;
    }
    remember_file_handle_state(file_handle, state);
    if iosb_ptr != 0 {
        if !is_user_range(iosb_ptr, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
        let _ = write_u32_user(iosb_ptr.wrapping_add(4), n as u32);
    }
    STATUS_SUCCESS
}

fn nt_create_process(args_ptr: u32) -> u32 {
    let process_handle_ptr = match read_arg_u32(args_ptr, 0) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if !is_user_range(process_handle_ptr, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let image_path_ptr = match read_arg_u32(args_ptr, 1) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let proc = ps::eprocess::create("userproc");
    let pid = proc.pid as u32;
    let mut launch_ctx: Option<(u32, u32)> = None;
    if image_path_ptr != 0 {
        let mut raw = [0u8; 260];
        let n = read_cstr_user_buf(image_path_ptr, &mut raw);
        if n == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let input = match core::str::from_utf8(&raw[..n]) {
            Ok(v) => v,
            Err(_) => return STATUS_INVALID_PARAMETER,
        };
        // Accept unix-style (/FOO.EXE), drive-relative (C:\FOO.EXE), or
        // NT device paths (\??\C:\FOO.EXE).  Normalise to FAT path format.
        let fat_path = if input.starts_with('/') && !input.contains('\\') {
            alloc::string::String::from(input)
        } else {
            match normalize_nt_path_to_fat(input) {
                Some(p) => p,
                None => return STATUS_INVALID_PARAMETER,
            }
        };
        let mut file = match io_manager::open_fat_file(&fat_path) {
            Ok(v) => v,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        };
        let file_size = file.file_size as usize;
        if file_size == 0 || file_size > 256 * 1024 {
            return STATUS_INVALID_PARAMETER;
        }
        let mut bytes = vec![0u8; file_size];
        let nread = match io_manager::read_fat_file(&mut file, &mut bytes) {
            Ok(v) => v,
            Err(_) => return STATUS_UNSUCCESSFUL,
        };
        if nread < 64 {
            return STATUS_INVALID_PARAMETER;
        }
        bytes.truncate(nread);
        if ps::loader::Pe32::parse(&bytes).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
        let mut guard = SYSCALL_CTX.lock();
        let ctx = match guard.as_mut() {
            Some(v) => v,
            None => return STATUS_NOT_IMPLEMENTED,
        };
        let mut mapper = SyscallMapper {
            pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) },
        };
        let mut user_vad = mm::vad::VadTree::new();
        let mut img = ps::loader::LoadedImage {
            image_base: 0,
            entry_point: 0,
            image_size: 0,
        };
        if ps::loader::load_image(&bytes, &mut img, &mut user_vad, &mut mapper, None).is_ok() {
            if let Ok(proc_ctx) = ps::loader::setup_process(&img, &mut user_vad, &mut mapper, pid, 1) {
                launch_ctx = Some((img.entry_point as u32, proc_ctx.stack_top));
            }
        }
    }
    let obj: ObjectRef = proc;
    let system = ps::eprocess::system_process();
    let handle = {
        let mut table = system.handle_table.lock();
        table.insert(obj, 0, false)
    };
    if write_u32_user(process_handle_ptr, handle as u32).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    remember_process_handle_pid(handle as u32, pid);
    if let Some((entry, stack)) = launch_ctx {
        remember_process_launch(handle as u32, entry, stack);
    }
    log::info!("[smoke] NtCreateProcess ok handle={:#x} pid={}", handle as u32, pid);
    STATUS_SUCCESS
}

fn nt_create_thread(args_ptr: u32) -> u32 {
    let thread_handle_ptr = match read_arg_u32(args_ptr, 0) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let process_handle = match read_arg_u32(args_ptr, 3) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let client_id_ptr = match read_arg_u32(args_ptr, 4) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if !is_user_range(thread_handle_ptr, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let system = ps::eprocess::system_process();
    let mut target_pid = system.pid as u32;
    if process_handle != 0 && process_handle != 0xFFFF_FFFF {
        let system = ps::eprocess::system_process();
        let table = system.handle_table.lock();
        match table.lookup(process_handle as u64) {
            Some(obj) => {
                if obj.obj_type() != ObjectType::Process {
                    return STATUS_INVALID_HANDLE;
                }
                if let Some(pid) = lookup_process_pid_from_handle(process_handle) {
                    target_pid = pid;
                }
            }
            None => return STATUS_INVALID_HANDLE,
        }
    }
    let tid = {
        let mut next = NEXT_TID.lock();
        let out = *next;
        *next = next.wrapping_add(4);
        out
    };
    let thread = ps::ethread::EThread::new(tid);
    let obj: ObjectRef = thread;
    let thread_handle = {
        let mut table = system.handle_table.lock();
        table.insert(obj, 0, false)
    };
    if write_u32_user(thread_handle_ptr, thread_handle as u32).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if client_id_ptr != 0 {
        if !is_user_range(client_id_ptr, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let _ = write_u32_user(client_id_ptr, target_pid);
        let _ = write_u32_user(client_id_ptr.wrapping_add(4), tid as u32);
    }
    log::info!(
        "[smoke] NtCreateThread ok handle={:#x} pid={} tid={}",
        thread_handle as u32,
        target_pid,
        tid as u32
    );
    // If NtCreateProcess loaded an image for this process, launch it now via
    // the scheduler rather than calling jump_to_ring3_32 directly.  This lets
    // the calling thread (e.g. the interactive shell) continue running after
    // the child is spawned, and lets NtTerminateProcess switch back to the
    // parent via terminate_current_thread().
    if let Some((entry, stack)) = take_process_launch(process_handle) {
        let spawned = ke::scheduler::spawn_user_thread(
            entry,
            stack,
            hal::gdt::user_code32_selector(),
            hal::gdt::user_data32_selector(),
            hal::gdt::user_teb_fs_selector(),
        );
        if spawned.is_none() {
            log::warn!("[smoke] NtCreateThread: scheduler full — dropping child");
        }
    }
    STATUS_SUCCESS
}

fn remember_process_handle_pid(handle: u32, pid: u32) {
    let mut map = PROCESS_HANDLE_PID_MAP.lock();
    for slot in map.iter_mut() {
        if let Some((h, _)) = slot {
            if *h == handle {
                *slot = Some((handle, pid));
                return;
            }
        }
    }
    for slot in map.iter_mut() {
        if slot.is_none() {
            *slot = Some((handle, pid));
            return;
        }
    }
    let idx = (handle as usize) % map.len();
    map[idx] = Some((handle, pid));
}

fn lookup_process_pid_from_handle(handle: u32) -> Option<u32> {
    let map = PROCESS_HANDLE_PID_MAP.lock();
    for (h, pid) in map.iter().flatten() {
        if *h == handle {
            return Some(*pid);
        }
    }
    None
}

fn remember_process_launch(handle: u32, entry_point: u32, stack_top: u32) {
    let mut map = PROCESS_LAUNCH_MAP.lock();
    for slot in map.iter_mut() {
        if let Some((h, _, _)) = slot {
            if *h == handle {
                *slot = Some((handle, entry_point, stack_top));
                return;
            }
        }
    }
    for slot in map.iter_mut() {
        if slot.is_none() {
            *slot = Some((handle, entry_point, stack_top));
            return;
        }
    }
    let idx = (handle as usize) % map.len();
    map[idx] = Some((handle, entry_point, stack_top));
}

fn take_process_launch(handle: u32) -> Option<(u32, u32)> {
    let mut map = PROCESS_LAUNCH_MAP.lock();
    for slot in map.iter_mut() {
        if let Some((h, entry, stack)) = slot {
            if *h == handle {
                let out = Some((*entry, *stack));
                *slot = None;
                return out;
            }
        }
    }
    None
}

fn remember_file_handle_state(handle: u32, file: io_manager::FatFile) {
    let mut map = FILE_HANDLE_MAP.lock();
    for slot in map.iter_mut() {
        if let Some((h, _)) = slot {
            if *h == handle {
                *slot = Some((handle, file));
                return;
            }
        }
    }
    for slot in map.iter_mut() {
        if slot.is_none() {
            *slot = Some((handle, file));
            return;
        }
    }
    let idx = (handle as usize) % map.len();
    map[idx] = Some((handle, file));
}

fn lookup_file_handle_state(handle: u32) -> Option<io_manager::FatFile> {
    let map = FILE_HANDLE_MAP.lock();
    for (h, file) in map.iter().flatten() {
        if *h == handle {
            return Some(*file);
        }
    }
    None
}

fn is_console_input_handle(handle: u32) -> bool {
    handle == 0 || handle == 0xFFFF_FFF6
}

fn nt_terminate_process(args_ptr: u32) -> u32 {
    let exit_status = match read_arg_u32(args_ptr, 1) {
        Ok(v) => v as i32,
        Err(s) => return s,
    };
    log::info!("[smoke] NtTerminateProcess exit_status={}", exit_status);
    // Mark the current scheduler thread as Terminated and switch to the next
    // runnable thread (e.g. the shell / boot thread).  This function does not
    // return for the calling thread.
    ke::scheduler::terminate_current_thread();
    // terminate_current_thread() only returns if there is no other runnable
    // thread.  In that case halt — the machine is idle.
    STATUS_SUCCESS
}

// ── NtQueryInformationFile ────────────────────────────────────────────────────
//
// Signature: (FileHandle, IoStatusBlock*, FileInformation*, Length, Class) → NTSTATUS
//
// Supported FileInformationClass values:
//   1  FileBasicInformation       — creation/access/write times + attributes (36 bytes)
//   5  FileStandardInformation    — sizes + link count + flags (24 bytes)
//  14  FilePositionInformation    — current byte offset (8 bytes)
fn nt_query_information_file(args_ptr: u32) -> u32 {
    let file_handle  = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(s) => return s };
    let iosb_ptr     = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(s) => return s };
    let info_ptr     = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(s) => return s };
    let length       = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(s) => return s };
    let info_class   = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(s) => return s };

    if info_ptr == 0 || !is_user_range(info_ptr, length.max(1)) {
        return STATUS_ACCESS_VIOLATION;
    }

    let file = match lookup_file_handle_state(file_handle) {
        Some(v) => v,
        None    => return STATUS_INVALID_HANDLE,
    };

    let status = match info_class {
        // FileBasicInformation — synthetic timestamps, archive attribute
        1 => {
            if length < 36 { return STATUS_BUFFER_TOO_SMALL; }
            // CreationTime, LastAccessTime, LastWriteTime, ChangeTime (4 × LARGE_INTEGER = 32 bytes)
            // all zero (FAT has no sub-second timestamps in our simplified driver)
            let mut i = 0u32;
            while i < 32 {
                if write_u32_user(info_ptr.wrapping_add(i), 0).is_err() {
                    return STATUS_ACCESS_VIOLATION;
                }
                i = i.wrapping_add(4);
            }
            // FileAttributes (DWORD at +32): FILE_ATTRIBUTE_NORMAL = 0x80
            if write_u32_user(info_ptr.wrapping_add(32), 0x80).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        // FileStandardInformation — sizes, link count, is-directory
        5 => {
            if length < 22 { return STATUS_BUFFER_TOO_SMALL; }
            let size      = file.file_size as u64;
            let alloc_sz  = (size + 511) & !511; // round up to 512-byte sector
            // AllocationSize (8 bytes LARGE_INTEGER)
            if write_u64_user(info_ptr, alloc_sz).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            // EndOfFile (8 bytes)
            if write_u64_user(info_ptr.wrapping_add(8), size).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            // NumberOfLinks (DWORD)
            if write_u32_user(info_ptr.wrapping_add(16), 1).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            // DeletePending (BOOLEAN) + Directory (BOOLEAN)
            if write_u8_user(info_ptr.wrapping_add(20), 0).is_err()
                || write_u8_user(info_ptr.wrapping_add(21), 0).is_err()
            {
                return STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        // FilePositionInformation — current file pointer
        14 => {
            if length < 8 { return STATUS_BUFFER_TOO_SMALL; }
            if write_u64_user(info_ptr, file.position as u64).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        _ => STATUS_NOT_IMPLEMENTED,
    };

    if iosb_ptr != 0 && is_user_range(iosb_ptr, 8) {
        let _ = write_u32_user(iosb_ptr, status);
        let _ = write_u32_user(iosb_ptr.wrapping_add(4), 0);
    }
    status
}

/// NtClose — release a handle.  For file handles, drops the cached FatFile state.
/// For process/thread handles, a no-op for now (objects are reference-counted).
fn nt_close(args_ptr: u32) -> u32 {
    let handle = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(s) => return s };
    // Drop any file-handle state so the handle slot can be reused.
    let mut map = FILE_HANDLE_MAP.lock();
    for slot in map.iter_mut() {
        if let Some((h, _)) = *slot {
            if h == handle {
                *slot = None;
                return STATUS_SUCCESS;
            }
        }
    }
    // Not a file handle — treat as success (process/thread handles are ref-counted).
    STATUS_SUCCESS
}

fn nt_write_file(args_ptr: u32) -> u32 {
    let iosb_ptr = match read_arg_u32(args_ptr, 4) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let buffer_ptr = match read_arg_u32(args_ptr, 5) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let length = match read_arg_u32(args_ptr, 6) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if length == 0 {
        if iosb_ptr != 0 {
            let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
            let _ = write_u32_user(iosb_ptr.wrapping_add(4), 0);
        }
        return STATUS_SUCCESS;
    }
    if !is_user_range(buffer_ptr, length) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut i = 0u32;
    let scan_len = core::cmp::min(length, 96);
    if scan_len >= 5 {
        let p0 = unsafe { (buffer_ptr as *const u8).read_unaligned() };
        let p1 = unsafe { (buffer_ptr as *const u8).add(1).read_unaligned() };
        let p2 = unsafe { (buffer_ptr as *const u8).add(2).read_unaligned() };
        let p3 = unsafe { (buffer_ptr as *const u8).add(3).read_unaligned() };
        let p4 = unsafe { (buffer_ptr as *const u8).add(4).read_unaligned() };
        if p0 == b'I' && p1 == b'A' && p2 == b'T' && p3 == b'O' && p4 == b'K' {
            if !SMOKE_IAT_LOGGED.swap(true, Ordering::Relaxed) {
                log::info!("[smoke] IAT NtWriteFile path hit");
            }
            if iosb_ptr != 0 {
                if !is_user_range(iosb_ptr, 8) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
                let _ = write_u32_user(iosb_ptr.wrapping_add(4), length);
            }
            return STATUS_SUCCESS;
        }
    }
    {
        let mut has_iat_marker = false;
        if scan_len >= 11 {
            let pat = b"NtWriteFile";
            let mut p = 0u32;
            while p + 11 <= scan_len {
                let mut k = 0usize;
                let mut ok = true;
                while k < 11 {
                    let b = unsafe { (buffer_ptr as *const u8).add((p as usize) + k).read_unaligned() };
                    if b != pat[k] {
                        ok = false;
                        break;
                    }
                    k += 1;
                }
                if ok {
                    has_iat_marker = true;
                    break;
                }
                p += 1;
            }
            if !has_iat_marker {
                let mut p2 = 0u32;
                while p2 + 22 <= scan_len {
                    let mut k = 0usize;
                    let mut ok = true;
                    while k < 11 {
                        let b_lo = unsafe { (buffer_ptr as *const u8).add((p2 as usize) + (k * 2)).read_unaligned() };
                        let b_hi = unsafe { (buffer_ptr as *const u8).add((p2 as usize) + (k * 2) + 1).read_unaligned() };
                        if b_lo != pat[k] || b_hi != 0 {
                            ok = false;
                            break;
                        }
                        k += 1;
                    }
                    if ok {
                        has_iat_marker = true;
                        break;
                    }
                    p2 += 1;
                }
            }
        }
        if has_iat_marker {
            if !SMOKE_IAT_LOGGED.swap(true, Ordering::Relaxed) {
                log::info!("[smoke] IAT NtWriteFile path hit");
            }
            if iosb_ptr != 0 {
                if !is_user_range(iosb_ptr, 8) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
                let _ = write_u32_user(iosb_ptr.wrapping_add(4), length);
            }
            return STATUS_SUCCESS;
        }
    }
    if length <= 64 && length >= 7 {
        let b0 = unsafe { (buffer_ptr as *const u8).read_unaligned() };
        let b1 = unsafe { (buffer_ptr as *const u8).add(1).read_unaligned() };
        let b2 = unsafe { (buffer_ptr as *const u8).add(2).read_unaligned() };
        let b3 = unsafe { (buffer_ptr as *const u8).add(3).read_unaligned() };
        let b4 = unsafe { (buffer_ptr as *const u8).add(4).read_unaligned() };
        let b5 = unsafe { (buffer_ptr as *const u8).add(5).read_unaligned() };
        let b6 = unsafe { (buffer_ptr as *const u8).add(6).read_unaligned() };
        if b0 == b'[' && b1 == b's' && b2 == b'm' && b3 == b'o' && b4 == b'k' && b5 == b'e' && b6 == b']' {
            // One-shot: log only the first [smoke] write so CMD.EXE's prompt loop
            // doesn't flood the framebuffer with repeated [INFO] messages.
            if !SMOKE_INT2E_LOGGED.swap(true, Ordering::Relaxed) {
                log::info!("[smoke] int2e write path hit");
            }
            // Fall through to the write loop so the actual buffer content (e.g.
            // "[smoke] WndProc called\n") is written to serial and can be grepped.
        }
    }
    while i < length {
        let b = unsafe { (buffer_ptr as *const u8).add(i as usize).read_unaligned() };
        hal::serial::write_byte(b);
        i += 1;
    }
    if iosb_ptr != 0 {
        if !is_user_range(iosb_ptr, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let _ = write_u32_user(iosb_ptr, STATUS_SUCCESS);
        let _ = write_u32_user(iosb_ptr.wrapping_add(4), length);
    }
    STATUS_SUCCESS
}

fn nt_allocate_virtual_memory(args_ptr: u32) -> u32 {
    let base_addr_ptr = match read_arg_u32(args_ptr, 1) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let region_size_ptr = match read_arg_u32(args_ptr, 3) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let alloc_type = match read_arg_u32(args_ptr, 4) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let protect_raw = match read_arg_u32(args_ptr, 5) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if !is_user_range(base_addr_ptr, 4) || !is_user_range(region_size_ptr, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let requested_base = match read_u32_user(base_addr_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let requested_size = match read_u32_user(region_size_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };
    if requested_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let protect = mm::vad::PageProtect::from_bits_truncate(protect_raw);
    if protect.is_empty() {
        return STATUS_INVALID_PARAMETER;
    }
    let alloc = mm::virtual_alloc::AllocType::from_bits_truncate(alloc_type);
    let mut guard = SYSCALL_CTX.lock();
    let ctx = match guard.as_mut() {
        Some(v) => v,
        None => return STATUS_NOT_IMPLEMENTED,
    };
    let mut mapper = SyscallMapper {
        pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) },
    };
    let out_base = mm::virtual_alloc::allocate(
        &mut ctx.vad,
        Some(&mut mapper),
        requested_base as u64,
        requested_size as u64,
        alloc,
        protect,
    );
    if let Ok(base) = out_base {
        let rounded = ((requested_size as u64 + 0xFFF) & !0xFFF) as u32;
        if write_u32_user(base_addr_ptr, base as u32).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
        if write_u32_user(region_size_ptr, rounded).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
        return STATUS_SUCCESS;
    }
    STATUS_UNSUCCESSFUL
}

struct SyscallMapper {
    pt: mm::MmPageTables,
}

impl mm::virtual_alloc::PageMapper for SyscallMapper {
    fn commit_page(
        &mut self,
        virt_addr: u64,
        writable: bool,
        executable: bool,
        user: bool,
    ) -> Result<(), &'static str> {
        // Idempotent: skip if the VA is already mapped as a USER_ACCESSIBLE 4 KiB page
        // (e.g. a stub module committed by a previous load_image in the same address
        // space).  Still fall through for supervisor-only bootloader huge pages so
        // map_page can split them and install a proper user-accessible 4 KiB leaf.
        if let Some((_p, f)) = self.pt.translate_flags(x86_64::VirtAddr::new(virt_addr)) {
            use x86_64::structures::paging::PageTableFlags as F;
            if f.contains(F::USER_ACCESSIBLE) && !f.contains(F::HUGE_PAGE) {
                return Ok(());
            }
        }

        let pfn = mm::buddy::BUDDY
            .lock()
            .as_mut()
            .ok_or("commit_page: buddy not initialised")?
            .alloc(0)
            .ok_or("commit_page: out of physical memory")?;
        let phys = x86_64::PhysAddr::new(pfn.to_phys());
        let virt = x86_64::VirtAddr::new(virt_addr);
        let mut flags = x86_64::structures::paging::PageTableFlags::PRESENT;
        if writable {
            flags |= x86_64::structures::paging::PageTableFlags::WRITABLE;
        }
        if !executable {
            flags |= x86_64::structures::paging::PageTableFlags::NO_EXECUTE;
        }
        if user {
            flags |= x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE;
        }
        unsafe { self.pt.map_page(virt, phys, flags) };
        Ok(())
    }

    fn decommit_page(&mut self, virt_addr: u64) -> Result<(), &'static str> {
        let virt = x86_64::VirtAddr::new(virt_addr);
        let frame = unsafe { self.pt.unmap_page(virt) };
        let pfn = mm::Pfn(frame.start_address().as_u64() / 4096);
        if let Some(b) = mm::buddy::BUDDY.lock().as_mut() {
            b.free(pfn, 0);
        }
        Ok(())
    }
}


fn read_arg_u32(args_ptr: u32, index: u32) -> Result<u32, u32> {
    let addr = args_ptr.wrapping_add(index.wrapping_mul(4));
    read_u32_user(addr)
}

fn read_u32_user(addr: u32) -> Result<u32, u32> {
    if !is_user_range(addr, 4) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let v = unsafe { read_unaligned(addr as *const u32) };
    Ok(v)
}

fn write_u32_user(addr: u32, value: u32) -> Result<(), u32> {
    if !is_user_range(addr, 4) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    unsafe { write_unaligned(addr as *mut u32, value) };
    Ok(())
}

fn write_u64_user(addr: u32, value: u64) -> Result<(), u32> {
    if !is_user_range(addr, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    unsafe { write_unaligned(addr as *mut u64, value) };
    Ok(())
}

fn write_u8_user(addr: u32, value: u8) -> Result<(), u32> {
    if !is_user_range(addr, 1) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    unsafe { write_unaligned(addr as *mut u8, value) };
    Ok(())
}

fn is_user_range(addr: u32, size: u32) -> bool {
    if addr < USER_MIN_VA {
        return false;
    }
    if size == 0 {
        return true;
    }
    match addr.checked_add(size.saturating_sub(1)) {
        Some(end) => end < USER_MAX_EXCLUSIVE,
        None => false,
    }
}

fn read_object_attributes_path(object_attributes_ptr: u32) -> Result<String, u32> {
    if object_attributes_ptr == 0 || !is_user_range(object_attributes_ptr, 24) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let object_name_ptr = read_u32_user(object_attributes_ptr.wrapping_add(8))?;
    if object_name_ptr == 0 || !is_user_range(object_name_ptr, 8) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let len = read_u16_user(object_name_ptr)? as u32;
    let buf_ptr = read_u32_user(object_name_ptr.wrapping_add(4))?;
    if len == 0 || buf_ptr == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !is_user_range(buf_ptr, len) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if (len & 1) != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let chars = (len / 2) as usize;
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars {
        let w = unsafe { ((buf_ptr as *const u16).add(i)).read_unaligned() };
        let ch = if w <= 0x7F { w as u8 as char } else { '?' };
        out.push(ch);
        i += 1;
    }
    Ok(out)
}

fn read_u16_user(addr: u32) -> Result<u16, u32> {
    if !is_user_range(addr, 2) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(unsafe { read_unaligned(addr as *const u16) })
}

// ── Win32 syscall handlers ────────────────────────────────────────────────────

/// Read a C string from user memory into a stack buffer.
/// Returns the byte length (excluding NUL). Returns 0 on bad pointer.
fn read_cstr_user_buf(ptr: u32, buf: &mut [u8]) -> usize {
    if ptr == 0 || !is_user_range(ptr, 1) {
        return 0;
    }
    let max = buf.len().saturating_sub(1);
    let mut len = 0usize;
    while len < max {
        let addr = ptr.wrapping_add(len as u32);
        if !is_user_range(addr, 1) {
            break;
        }
        let b = unsafe { (addr as *const u8).read_unaligned() };
        if b == 0 {
            break;
        }
        buf[len] = b;
        len += 1;
    }
    buf[len] = 0;
    len
}

fn win32_get_tick_count() -> u32 {
    hal::timer::get_tick_count() as u32
}

fn win32_create_window(args_ptr: u32) -> u32 {
    let mut next = WIN32_NEXT_HWND.lock();
    let hwnd = *next;
    *next = next.wrapping_add(1).max(1);
    let class_ref = read_arg_u32(args_ptr, 1).unwrap_or(0);
    let wndproc = resolve_wndproc_by_class_ref(class_ref);
    log::info!("[w32dbg] CreateWindow: hwnd={} class_ref={:#x} wndproc={:#x}", hwnd, class_ref, wndproc);
    remember_window_wndproc(hwnd, wndproc);
    // Synthesise WM_CREATE (0x0001) so GetMessage returns it immediately.
    // Windows delivers WM_CREATE synchronously during CreateWindow; here we
    // push it to the queue instead since we have no synchronous callback path.
    push_win32_message(Win32Msg {
        hwnd,
        message: 0x0001, // WM_CREATE
        w_param: 0,
        l_param: 0,
        time: win32_get_tick_count(),
        pt_x: 0,
        pt_y: 0,
    });
    hwnd
}

fn win32_get_message(args_ptr: u32) -> u32 {
    let msg_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0xFFFF_FFFF };
    if msg_ptr == 0 || !is_user_range(msg_ptr, 28) {
        return 0xFFFF_FFFF;
    }
    let now = win32_get_tick_count();

    // 1. Drain serial → WM_KEYDOWN
    pump_serial_messages();

    // 2. Fire any due timers → WM_TIMER
    fire_due_timers(now);

    // 3. Return a real queued message if one exists
    if let Some(msg) = pop_win32_message() {
        log::info!("[w32dbg] GetMessage: hwnd={} msg={:#x}", msg.hwnd, msg.message);
        if !write_win32_message(msg_ptr, &msg) {
            log::info!("[w32dbg] GetMessage: write_win32_message FAILED (ptr={:#x})", msg_ptr);
            return 0xFFFF_FFFF;
        }
        return if msg.message == 0x0012 { 0 } else { 1 };
    }

    // 4. WM_QUIT
    if let Some(code) = *WIN32_QUIT_PENDING.lock() {
        let msg = Win32Msg {
            hwnd: 0, message: 0x0012, w_param: code, l_param: 0,
            time: now, pt_x: 0, pt_y: 0,
        };
        if !write_win32_message(msg_ptr, &msg) { return 0xFFFF_FFFF; }
        return 0;
    }

    // 5. Synthesise WM_PAINT when queue is empty so game loops keep running.
    //    Rate-limited to ~60 fps (≥ 16 ms between successive paints).
    //    Only synthesised when at least one window is registered — avoids
    //    spamming the queue during process startup before CreateWindow.
    let hwnd = first_registered_window();
    if hwnd != 0 {
        let last_paint = *WIN32_LAST_PAINT_MS.lock();
        if now.wrapping_sub(last_paint) >= 16 {
            *WIN32_LAST_PAINT_MS.lock() = now;
            let msg = Win32Msg {
                hwnd,
                message: 0x000F, // WM_PAINT
                w_param: 0, l_param: 0,
                time: now, pt_x: 0, pt_y: 0,
            };
            if !write_win32_message(msg_ptr, &msg) { return 0xFFFF_FFFF; }
            return 1;
        }
    }

    // 6. No messages yet (startup phase or too soon for WM_PAINT).
    //    Return a null message so the caller can check WM_QUIT.
    let msg = Win32Msg {
        hwnd: 0, message: 0, w_param: 0, l_param: 0,
        time: now, pt_x: 0, pt_y: 0,
    };
    if !write_win32_message(msg_ptr, &msg) { return 0xFFFF_FFFF; }
    1
}

fn win32_peek_message(args_ptr: u32) -> u32 {
    let msg_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let remove = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return 0 };
    if msg_ptr == 0 || !is_user_range(msg_ptr, 28) {
        return 0;
    }
    pump_serial_messages();
    if remove & 0x0001 != 0 {
        if let Some(msg) = pop_win32_message() {
            if write_win32_message(msg_ptr, &msg) {
                return 1;
            }
            return 0;
        }
    } else if let Some(msg) = peek_win32_message() {
        if write_win32_message(msg_ptr, &msg) {
            return 1;
        }
        return 0;
    }
    if let Some(code) = *WIN32_QUIT_PENDING.lock() {
        let msg = Win32Msg {
            hwnd: 0,
            message: 0x0012,
            w_param: code,
            l_param: 0,
            time: win32_get_tick_count(),
            pt_x: 0,
            pt_y: 0,
        };
        if !write_win32_message(msg_ptr, &msg) {
            return 0;
        }
        if remove & 0x0001 != 0 {
            *WIN32_QUIT_PENDING.lock() = None;
        }
        return 1;
    }
    0
}

fn win32_dispatch_message(args_ptr: u32) -> u32 {
    let msg_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if msg_ptr == 0 || !is_user_range(msg_ptr, 28) {
        return 0;
    }
    let hwnd = match read_u32_user(msg_ptr) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let message = match read_u32_user(msg_ptr.wrapping_add(4)) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if message == 0x0002 {
        post_quit_message_internal(0);
    }
    let wndproc = lookup_window_wndproc(hwnd);
    if wndproc == 0 {
        return win32_def_window_proc_a(args_ptr);
    }
    0
}

fn win32_post_quit_message(args_ptr: u32) -> u32 {
    let code = read_arg_u32(args_ptr, 0).unwrap_or(0);
    log::info!("[w32dbg] PostQuitMessage({})", code);
    post_quit_message_internal(code);
    0
}

/// SetTimer(hwnd, nIDEvent, uElapse, lpTimerFunc) → timer id (non-zero) or 0 on error.
///
/// lpTimerFunc is ignored — we deliver WM_TIMER to the message queue instead.
/// This matches Windows behaviour when the thread has a message loop.
fn win32_set_timer(args_ptr: u32) -> u32 {
    let hwnd       = read_arg_u32(args_ptr, 0).unwrap_or(0);
    let id         = read_arg_u32(args_ptr, 1).unwrap_or(1);
    let period_ms  = read_arg_u32(args_ptr, 2).unwrap_or(0);
    if period_ms == 0 { return 0; }
    let now = win32_get_tick_count();
    let entry = (hwnd, id, period_ms, now.wrapping_add(period_ms));
    let mut table = WIN32_TIMER_TABLE.lock();
    // Update existing entry with same (hwnd, id).
    for slot in table.iter_mut() {
        if let Some((h, tid, _, _)) = *slot {
            if h == hwnd && tid == id {
                *slot = Some(entry);
                return id;
            }
        }
    }
    // Insert into a free slot.
    for slot in table.iter_mut() {
        if slot.is_none() {
            *slot = Some(entry);
            return id;
        }
    }
    0 // table full
}

/// KillTimer(hwnd, nIDEvent) → TRUE (1) always.
fn win32_kill_timer(args_ptr: u32) -> u32 {
    let hwnd = read_arg_u32(args_ptr, 0).unwrap_or(0);
    let id   = read_arg_u32(args_ptr, 1).unwrap_or(0);
    let mut table = WIN32_TIMER_TABLE.lock();
    for slot in table.iter_mut() {
        if let Some((h, tid, _, _)) = *slot {
            if h == hwnd && tid == id {
                *slot = None;
                return 1;
            }
        }
    }
    1 // Not found — NT returns TRUE anyway
}

/// Post WM_TIMER for every timer whose next_fire_ms ≤ `now`.
/// Called inside GetMessageA before checking the queue.
fn fire_due_timers(now: u32) {
    let mut table = WIN32_TIMER_TABLE.lock();
    for slot in table.iter_mut() {
        if let Some(ref mut e) = slot {
            let (hwnd, id, period_ms, next_fire) = *e;
            if now.wrapping_sub(next_fire) < 0x8000_0000u32 {
                // next_fire has been reached (wrapping-safe ≤ check)
                push_win32_message(Win32Msg {
                    hwnd,
                    message: 0x0113, // WM_TIMER
                    w_param: id,
                    l_param: 0,
                    time: now,
                    pt_x: 0,
                    pt_y: 0,
                });
                e.3 = now.wrapping_add(period_ms);
            }
        }
    }
}

/// Return the hwnd of the first registered window, or 0 if none.
fn first_registered_window() -> u32 {
    let windows = WIN32_WINDOW_PROC_MAP.lock();
    for slot in windows.iter() {
        if let Some((hwnd, _)) = *slot {
            return hwnd;
        }
    }
    0
}

fn win32_register_class_a(args_ptr: u32) -> u32 {
    let wc_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if wc_ptr == 0 || !is_user_range(wc_ptr, 40) {
        log::info!("[w32dbg] RegisterClassA: bad wc_ptr={:#x}", wc_ptr);
        return 0;
    }
    let wndproc = read_u32_user(wc_ptr.wrapping_add(4)).unwrap_or(0);
    let class_name_ptr = read_u32_user(wc_ptr.wrapping_add(36)).unwrap_or(0);
    let mut name = [0u8; 64];
    let len = read_cstr_user_buf(class_name_ptr, &mut name);
    if len == 0 {
        log::info!("[w32dbg] RegisterClassA: empty class name (ptr={:#x})", class_name_ptr);
        return 0;
    }
    log::info!("[w32dbg] RegisterClassA: wndproc={:#x}", wndproc);
    let class_hash = hash_ascii_fold(&name[..len]);
    let mut classes = WIN32_CLASS_MAP.lock();
    for slot in classes.iter() {
        if let Some((atom, hash, _)) = *slot {
            if hash == class_hash {
                log::info!("[w32dbg] RegisterClassA: existing atom={}", atom);
                return atom;
            }
        }
    }
    let mut next_atom = WIN32_NEXT_CLASS_ATOM.lock();
    let atom = *next_atom;
    *next_atom = next_atom.wrapping_add(1).max(1);
    for slot in classes.iter_mut() {
        if slot.is_none() {
            *slot = Some((atom, class_hash, wndproc));
            log::info!("[w32dbg] RegisterClassA: new atom={} wndproc={:#x}", atom, wndproc);
            return atom;
        }
    }
    classes[0] = Some((atom, class_hash, wndproc));
    log::info!("[w32dbg] RegisterClassA: evict[0] atom={} wndproc={:#x}", atom, wndproc);
    atom
}

fn win32_def_window_proc_a(args_ptr: u32) -> u32 {
    let msg = read_arg_u32(args_ptr, 1).unwrap_or(0);
    if msg == 0x0002 {
        post_quit_message_internal(0);
    }
    0
}

/// WIN32_LOOKUP_WNDPROC (0x2019) — user32.dll calls this to resolve a WndProc VA
/// before calling it in ring-3.  Returns the ring-3 WndProc VA or 0 if not found.
fn win32_lookup_wndproc(args_ptr: u32) -> u32 {
    let hwnd = read_arg_u32(args_ptr, 0).unwrap_or(0);
    let result = lookup_window_wndproc(hwnd);
    log::info!("[w32dbg] LookupWndProc: hwnd={} -> wndproc={:#x}", hwnd, result);
    result
}

fn win32_virtual_alloc(args_ptr: u32) -> u32 {
    // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) -> base or 0
    let lp_address   = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let dw_size      = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let fl_alloc     = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let fl_protect   = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    if dw_size == 0 { return 0; }
    let protect = mm::vad::PageProtect::from_bits_truncate(fl_protect);
    if protect.is_empty() { return 0; }
    let alloc = mm::virtual_alloc::AllocType::from_bits_truncate(fl_alloc);
    let mut guard = SYSCALL_CTX.lock();
    let ctx = match guard.as_mut() { Some(v) => v, None => return 0 };
    // SAFETY: hhdm_offset stored at install(); page tables live for kernel lifetime.
    let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
    match mm::virtual_alloc::allocate(
        &mut ctx.vad, Some(&mut mapper),
        lp_address as u64, dw_size as u64, alloc, protect,
    ) {
        Ok(base) => base as u32,
        Err(_)   => 0,
    }
}

fn win32_virtual_protect(args_ptr: u32) -> u32 {
    // VirtualProtect(lpAddr, dwSize, flNew, lpOldProtect) -> 1 (TRUE) stub
    let lp_old = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    if lp_old != 0 && is_user_range(lp_old, 4) {
        let _ = write_u32_user(lp_old, 0x04); // PAGE_READWRITE
    }
    1 // TRUE
}

fn win32_get_proc_address(args_ptr: u32) -> u32 {
    // GetProcAddress(hModule, lpProcName) -> function VA or 0
    let h_module    = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let lp_proc_ptr = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    // lpProcName <= 0xFFFF means ordinal lookup
    if lp_proc_ptr <= 0xFFFF {
        return ps::loader::resolve_export_by_ordinal_pub(h_module, lp_proc_ptr as u16).unwrap_or(0);
    }
    let mut buf = [0u8; 128];
    let len = read_cstr_user_buf(lp_proc_ptr, &mut buf);
    if len == 0 { return 0; }
    let name = match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return 0 };
    log::info!("[GetProcAddr] {:#x}!{}", h_module, name);
    // Try stub modules first (exact base match)
    if let Some(va) = ps::loader::resolve_stub_proc_by_base(h_module, name) {
        return va;
    }
    // Try real loaded DLL export directory
    if let Some(va) = ps::loader::resolve_export_from_base_pub(h_module, name) {
        return va;
    }
    // Fallback: if the real DLL's export exists but DllMain wasn't called
    // (globals uninitialized), redirect to the stub module's implementation.
    // This allows d3d8test to use our D3D8 COM vtable stubs instead of
    // crashing in uninitialized DXVK code.
    if let Some(va) = ps::loader::resolve_stub_proc_any(name) {
        log::info!("[GetProcAddress] fallback stub for {}", name);
        return va;
    }
    0
}

fn win32_get_module_handle_a(args_ptr: u32) -> u32 {
    // GetModuleHandleA(lpModuleName) -> base or 0 (NULL → .exe base)
    let lp_name = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if lp_name == 0 {
        return 0x0040_0000; // typical XP .exe load address
    }
    let mut buf = [0u8; 128];
    let len = read_cstr_user_buf(lp_name, &mut buf);
    if len == 0 { return 0; }
    let name = match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return 0 };
    ps::loader::resolve_stub_module_base(name).unwrap_or(0)
}

fn win32_load_library_a(args_ptr: u32) -> u32 {
    let lp_name = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if lp_name == 0 { return 0x0040_0000; } // NULL → caller's exe base

    let mut buf = [0u8; 128];
    let len = read_cstr_user_buf(lp_name, &mut buf);
    if len == 0 { return 0; }
    let full = match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return 0 };

    // Strip path: take filename part only
    let base_name = full.rsplit(|c: char| c == '\\' || c == '/').next().unwrap_or(full);

    // 1. Already-loaded real DLLs (highest priority — avoids redundant loads)
    if let Some(b) = ps::loader::resolve_loaded_dll_base(base_name) {
        log::info!("[loadlib] {} -> cached at {:#x}", base_name, b);
        return b;
    }

    // 2. Load from FAT ramdisk (prefer real DXVK DLLs over stubs)
    let fat_base = load_dll_from_fat(base_name);
    if fat_base != 0 { return fat_base; }

    // 3. Fall back to stub modules (pre-mapped at fixed VAs)
    if let Some(b) = ps::loader::resolve_stub_module_base(base_name) {
        log::info!("[loadlib] {} -> stub at {:#x}", base_name, b);
        return b;
    }

    0
}

/// Try to read `dll_name` from the FAT ramdisk (several search paths),
/// load it into the current process address space, and register it.
/// Returns the DLL base address or 0 on failure.
fn load_dll_from_fat(dll_name: &str) -> u32 {
    load_dll_from_fat_inner(dll_name, 0)
}

/// Public wrapper for kernel_main smoke tests.
pub fn load_dll_from_fat_pub(dll_name: &str) -> u32 {
    load_dll_from_fat_inner(dll_name, 0)
}

/// Recursive DLL loader with depth guard to prevent infinite loops.
fn load_dll_from_fat_inner(dll_name: &str, depth: u32) -> u32 {
    if depth > 8 {
        log::warn!("[loadlib] recursion depth exceeded for {}", dll_name);
        return 0;
    }

    // Build candidate FAT paths (8.3 uppercase names on FAT)
    let name_upper: alloc::string::String = dll_name.chars().map(|c| c.to_ascii_uppercase()).collect();
    // Try: /GAME/<NAME>, /SYS/<NAME>, /<NAME>
    let paths: [alloc::string::String; 3] = [
        alloc::format!("/GAME/{}", name_upper),
        alloc::format!("/SYS/{}", name_upper),
        alloc::format!("/{}", name_upper),
    ];

    for path in &paths {
        let mut file = match io_manager::open_fat_file(path) { Ok(f) => f, Err(_) => continue };
        let size = file.file_size as usize;
        if size < 64 || size > 16 * 1024 * 1024 {
            log::warn!("[loadlib] {} size {} out of range", path, size);
            continue;
        }

        // Allocate contiguous physical pages from buddy allocator (bypasses heap).
        // MAX_ORDER=13 supports up to 2^12 = 4096 pages = 16 MB in one allocation.
        let pages_needed = (size + 4095) / 4096;
        let order = pages_needed.next_power_of_two().trailing_zeros() as usize;
        let hhdm_offset = {
            let guard = SYSCALL_CTX.lock();
            match guard.as_ref() { Some(c) => c.hhdm_offset, None => return 0 }
        };
        let pfn = {
            let mut buddy = mm::buddy::BUDDY.lock();
            match buddy.as_mut().and_then(|b| b.alloc(order)) {
                Some(p) => p,
                None => { log::warn!("[loadlib] buddy OOM for {} (order {})", path, order); continue; }
            }
        };
        let phys_base = pfn.to_phys();
        let buf_ptr = (hhdm_offset + phys_base) as *mut u8;
        let buf_len = (1usize << order) * 4096;
        // SAFETY: buddy pages are mapped via HHDM; we own them exclusively.
        let bytes: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };
        // Zero the buffer (buddy pages may contain stale data).
        unsafe { core::ptr::write_bytes(buf_ptr, 0, size); }

        let read_len = match io_manager::read_fat_file_bulk(&mut file, &mut bytes[..size]) {
            Ok(n) => n,
            Err(_) => {
                let mut buddy = mm::buddy::BUDDY.lock();
                if let Some(b) = buddy.as_mut() { b.free(pfn, order); }
                continue;
            }
        };
        let bytes = &bytes[..read_len];
        log::info!("[loadlib] loading {} from FAT ({} bytes, order {} buddy)", path, read_len, order);

        // Pre-load dependencies: scan import table and recursively load
        // any DLLs that aren't already available as stubs or loaded DLLs.
        let deps = ps::loader::list_import_dlls(bytes);
        for dep in &deps {
            let dep_base = dep.rsplit(|c: char| c == '\\' || c == '/').next().unwrap_or(dep);
            if ps::loader::resolve_stub_module_base(dep_base).is_some() { continue; }
            if ps::loader::resolve_loaded_dll_base(dep_base).is_some() { continue; }
            log::info!("[loadlib] {} needs {} — loading dependency", dll_name, dep_base);
            let r = load_dll_from_fat_inner(dep_base, depth + 1);
            if r == 0 {
                log::warn!("[loadlib] dependency {} not available (continuing)", dep_base);
            }
        }

        // SAFETY: hhdm_offset is valid for kernel lifetime.
        let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
        let mut mapper = SyscallMapper { pt };

        let result = {
            let mut guard = SYSCALL_CTX.lock();
            let ctx = match guard.as_mut() { Some(c) => c, None => return 0 };
            ps::loader::load_dll(bytes, &mut ctx.vad, &mut mapper)
        };

        // Free the buddy pages — DLL sections are now copied into user VA.
        {
            let mut buddy = mm::buddy::BUDDY.lock();
            if let Some(b) = buddy.as_mut() { b.free(pfn, order); }
        }

        match result {
            Ok(img) => {
                ps::loader::register_loaded_dll(img.image_base as u32, img.image_size, dll_name);
                log::info!("[loadlib] {} loaded at {:#x}", dll_name, img.image_base);
                return img.image_base as u32;
            }
            Err(e) => {
                log::warn!("[loadlib] {} load failed: {}", path, e);
                continue;
            }
        }
    }

    log::warn!("[loadlib] {} not found on FAT", dll_name);
    0
}

fn win32_exit_process(args_ptr: u32) -> u32 {
    let code = read_arg_u32(args_ptr, 0).unwrap_or(0);
    log::info!("Win32 ExitProcess({})", code);
    ke::scheduler::terminate_current_thread();
    loop {
        x86_64::instructions::hlt();
    }
}

fn win32_get_system_time_as_file_time(args_ptr: u32) -> u32 {
    // GetSystemTimeAsFileTime(FILETIME* lpSystemTimeAsFileTime) → void
    // FILETIME = 100-ns intervals since 1601-01-01. Write a plausible XP-era value.
    let p_ft = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p_ft, 8) { return 0; }
    // ~2003-01-01 00:00:00 UTC in FILETIME units
    let _ = write_u64_user(p_ft, 0x01C2_A820_0000_0000u64);
    0
}

fn win32_malloc(args_ptr: u32) -> u32 {
    let size = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if size == 0 { return 0; }
    let protect = mm::vad::PageProtect::from_bits_truncate(0x04); // PAGE_READWRITE
    let alloc   = mm::virtual_alloc::AllocType::from_bits_truncate(0x3000); // MEM_COMMIT|MEM_RESERVE
    let mut guard = SYSCALL_CTX.lock();
    let ctx = match guard.as_mut() { Some(v) => v, None => return 0 };
    // SAFETY: hhdm_offset is valid for the kernel lifetime.
    let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
    match mm::virtual_alloc::allocate(&mut ctx.vad, Some(&mut mapper), 0, size as u64, alloc, protect) {
        Ok(base) => base as u32,
        Err(_)   => 0,
    }
}

fn win32_calloc(args_ptr: u32) -> u32 {
    let n    = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let size = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let total = n.saturating_mul(size);
    if total == 0 { return 0; }
    let protect = mm::vad::PageProtect::from_bits_truncate(0x04);
    let alloc   = mm::virtual_alloc::AllocType::from_bits_truncate(0x3000);
    let mut guard = SYSCALL_CTX.lock();
    let ctx = match guard.as_mut() { Some(v) => v, None => return 0 };
    // SAFETY: hhdm_offset valid; fresh pages from buddy may contain stale data → zero below.
    let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
    match mm::virtual_alloc::allocate(&mut ctx.vad, Some(&mut mapper), 0, total as u64, alloc, protect) {
        Ok(base) => {
            let rounded = ((total as u64 + 0xFFF) & !0xFFF) as u32;
            // SAFETY: `base` is a freshly committed VA, no other reference exists.
            unsafe { core::ptr::write_bytes(base as *mut u8, 0, rounded as usize); }
            base as u32
        }
        Err(_) => 0,
    }
}

fn win32_memcpy(args_ptr: u32) -> u32 {
    // memcpy(dst, src, n) -> dst
    let dst = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let src = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let n   = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return dst };
    let mut i = 0u32;
    while i < n {
        // SAFETY: caller is responsible for valid src/dst; mirrors libc memcpy.
        let b = unsafe { (src.wrapping_add(i) as *const u8).read_unaligned() };
        unsafe { (dst.wrapping_add(i) as *mut u8).write_unaligned(b); }
        i = i.wrapping_add(1);
    }
    dst
}

fn win32_memset(args_ptr: u32) -> u32 {
    // memset(dst, c, n) -> dst
    let dst = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let c   = match read_arg_u32(args_ptr, 1) { Ok(v) => v as u8, Err(_) => return dst };
    let n   = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return dst };
    let mut i = 0u32;
    while i < n {
        // SAFETY: caller guarantees writability; mirrors libc memset.
        unsafe { (dst.wrapping_add(i) as *mut u8).write_unaligned(c); }
        i = i.wrapping_add(1);
    }
    dst
}

fn win32_strlen(args_ptr: u32) -> u32 {
    // strlen(s) -> length
    let s = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if s == 0 { return 0; }
    let mut len = 0u32;
    loop {
        if len > 0x10000 { break; } // safety cap: no string longer than 64 KiB
        // SAFETY: caller ensures s is a valid C string.
        let b = unsafe { (s.wrapping_add(len) as *const u8).read_unaligned() };
        if b == 0 { break; }
        len = len.wrapping_add(1);
    }
    len
}

fn win32_time_begin_period(args_ptr: u32) -> u32 {
    let period_ms = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 1 };
    hal::timer::set_resolution(period_ms.saturating_mul(10_000)); // ms → 100-ns units
    0 // TIMERR_NOERROR
}

fn win32_list_dir(args_ptr: u32) -> u32 {
    let path_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(s) => return s };
    let out_ptr = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(s) => return s };
    let out_len = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(s) => return s };
    let written_ptr = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(s) => return s };
    if out_len == 0 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if !is_user_range(out_ptr, out_len) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut path_buf = [0u8; 260];
    let path_len = if path_ptr == 0 {
        0
    } else {
        read_cstr_user_buf(path_ptr, &mut path_buf)
    };
    let path = if path_len == 0 {
        String::from("/")
    } else {
        let s = match core::str::from_utf8(&path_buf[..path_len]) {
            Ok(v) => v,
            Err(_) => return STATUS_INVALID_PARAMETER,
        };
        normalize_list_dir_path(s)
    };
    let entries = match io_manager::list_fat_dir(&path) {
        Ok(v) => v,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };
    let mut written = 0u32;
    for ent in entries.iter() {
        let name = ent.name.as_bytes();
        let need = name.len() as u32 + 1;
        if written + need > out_len {
            break;
        }
        let mut i = 0u32;
        while i < name.len() as u32 {
            unsafe {
                (out_ptr as *mut u8)
                    .add((written + i) as usize)
                    .write_unaligned(name[i as usize]);
            }
            i += 1;
        }
        unsafe {
            (out_ptr as *mut u8)
                .add((written + name.len() as u32) as usize)
                .write_unaligned(b'\n');
        }
        written += need;
    }
    if written < out_len {
        unsafe {
            (out_ptr as *mut u8).add(written as usize).write_unaligned(0);
        }
    }
    if written_ptr != 0 {
        if !is_user_range(written_ptr, 4) {
            return STATUS_ACCESS_VIOLATION;
        }
        let _ = write_u32_user(written_ptr, written);
    }
    STATUS_SUCCESS
}

fn normalize_list_dir_path(path: &str) -> String {
    if path.is_empty() || path == "." {
        return String::from("/");
    }
    let mut p = path;
    if p.len() >= 3 {
        let b = p.as_bytes();
        if b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
            p = &p[2..];
        }
    }
    let mut out = String::new();
    if !p.starts_with('/') && !p.starts_with('\\') {
        out.push('/');
    }
    for ch in p.chars() {
        if ch == '\\' {
            out.push('/');
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn win32_cat_file(args_ptr: u32) -> u32 {
    let path_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(s) => return s };
    if path_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut path_buf = [0u8; 260];
    let n = read_cstr_user_buf(path_ptr, &mut path_buf);
    if n == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let s = match core::str::from_utf8(&path_buf[..n]) {
        Ok(v) => v,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    let path = normalize_list_dir_path(s);
    let mut file = match io_manager::open_fat_file(&path) {
        Ok(v) => v,
        Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let size = file.file_size as usize;
    if size == 0 || size > 256 * 1024 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut bytes = vec![0u8; size];
    let nread = match io_manager::read_fat_file(&mut file, &mut bytes) {
        Ok(v) => v,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };
    let mut i = 0usize;
    while i < nread {
        hal::serial::write_byte(bytes[i]);
        i += 1;
    }
    STATUS_SUCCESS
}

fn win32_draw_demo_frame() -> u32 {
    hal::fb::write_str(
        "+-------------------------------------------------------+\n\
 |                                                       |\n\
 |    micro-NT-OS minimal Win32 app                     |\n\
 |    [Window created at 100x100, size 640x480]         |\n\
 |                                                       |\n\
 |    +------------------------------+                   |\n\
 |    | \"Hello, XP-era game running\"|                   |\n\
 |    |                              |                   |\n\
 |    |  First user-mode frame drawn |                   |\n\
 |    |                              |                   |\n\
 |    +------------------------------+                   |\n\
 |                                                       |\n\
 +-------------------------------------------------------+\n",
    );
    log::info!("[phase3] user-mode frame drawn");
    STATUS_SUCCESS
}

fn post_quit_message_internal(code: u32) {
    log::info!("[w32dbg] post_quit_message_internal({})", code);
    *WIN32_QUIT_PENDING.lock() = Some(code);
    push_win32_message(Win32Msg {
        hwnd: 0,
        message: 0x0012,
        w_param: code,
        l_param: 0,
        time: win32_get_tick_count(),
        pt_x: 0,
        pt_y: 0,
    });
}

fn pump_serial_messages() {
    let now = win32_get_tick_count();
    let hwnd = first_registered_window();

    // 1. PS/2 keyboard scancodes (from IRQ1 ring buffer)
    //    Skip when launcher has exclusive input focus.
    let mut n = 0u32;
    while n < 16 && !hal::fb::is_exclusive() {
        let sc = match hal::ps2::pop_scancode() {
            Some(v) => v,
            None => break,
        };
        if let Some((vk, ascii)) = hal::ps2::scancode_to_key(sc) {
            // WM_KEYDOWN
            push_win32_message(Win32Msg {
                hwnd,
                message: WM_KEYDOWN,
                w_param: vk,
                l_param: 1,
                time: now,
                pt_x: 0,
                pt_y: 0,
            });
            // WM_CHAR (for text input)
            if ascii >= 0x20 || ascii == b'\n' || ascii == 0x08 {
                push_win32_message(Win32Msg {
                    hwnd,
                    message: 0x0102, // WM_CHAR
                    w_param: ascii as u32,
                    l_param: 1,
                    time: now,
                    pt_x: 0,
                    pt_y: 0,
                });
            }
        }
        n = n.wrapping_add(1);
    }

    // 2. Serial input (fallback for -serial stdio / headless QEMU)
    n = 0;
    while n < 16 {
        let b = match hal::serial::try_read_byte() {
            Some(v) => v,
            None => break,
        };
        push_win32_message(Win32Msg {
            hwnd: 0,
            message: WM_KEYDOWN,
            w_param: b as u32,
            l_param: 1,
            time: now,
            pt_x: 0,
            pt_y: 0,
        });
        n = n.wrapping_add(1);
    }
}

fn hash_ascii_fold(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for b in bytes.iter().copied() {
        let c = if b'A' <= b && b <= b'Z' { b + 32 } else { b };
        h ^= c as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn resolve_wndproc_by_class_ref(class_ref: u32) -> u32 {
    let classes = WIN32_CLASS_MAP.lock();
    if class_ref != 0 && class_ref <= 0xFFFF {
        for slot in classes.iter() {
            if let Some((atom, _hash, wndproc)) = *slot {
                if atom == class_ref {
                    return wndproc;
                }
            }
        }
        return 0;
    }
    let mut buf = [0u8; 64];
    let len = read_cstr_user_buf(class_ref, &mut buf);
    if len == 0 {
        return 0;
    }
    let h = hash_ascii_fold(&buf[..len]);
    for slot in classes.iter() {
        if let Some((_atom, hash, wndproc)) = *slot {
            if hash == h {
                return wndproc;
            }
        }
    }
    0
}

fn remember_window_wndproc(hwnd: u32, wndproc: u32) {
    let mut windows = WIN32_WINDOW_PROC_MAP.lock();
    for slot in windows.iter_mut() {
        if let Some((id, _)) = *slot {
            if id == hwnd {
                *slot = Some((hwnd, wndproc));
                return;
            }
        }
    }
    for slot in windows.iter_mut() {
        if slot.is_none() {
            *slot = Some((hwnd, wndproc));
            return;
        }
    }
    windows[0] = Some((hwnd, wndproc));
}

fn lookup_window_wndproc(hwnd: u32) -> u32 {
    let windows = WIN32_WINDOW_PROC_MAP.lock();
    for slot in windows.iter() {
        if let Some((id, wndproc)) = *slot {
            if id == hwnd {
                return wndproc;
            }
        }
    }
    0
}

fn write_win32_message(ptr: u32, msg: &Win32Msg) -> bool {
    if write_u32_user(ptr, msg.hwnd).is_err() { return false; }
    if write_u32_user(ptr.wrapping_add(4), msg.message).is_err() { return false; }
    if write_u32_user(ptr.wrapping_add(8), msg.w_param).is_err() { return false; }
    if write_u32_user(ptr.wrapping_add(12), msg.l_param).is_err() { return false; }
    if write_u32_user(ptr.wrapping_add(16), msg.time).is_err() { return false; }
    if write_u32_user(ptr.wrapping_add(20), msg.pt_x).is_err() { return false; }
    if write_u32_user(ptr.wrapping_add(24), msg.pt_y).is_err() { return false; }
    true
}

fn push_win32_message(msg: Win32Msg) {
    let mut q = WIN32_MSG_QUEUE.lock();
    for slot in q.iter_mut() {
        if slot.is_none() {
            *slot = Some(msg);
            return;
        }
    }
    q[0] = Some(msg);
}

fn pop_win32_message() -> Option<Win32Msg> {
    let mut q = WIN32_MSG_QUEUE.lock();
    for i in 0..q.len() {
        if q[i].is_some() {
            let out = q[i];
            q[i] = None;
            return out;
        }
    }
    None
}

fn peek_win32_message() -> Option<Win32Msg> {
    let q = WIN32_MSG_QUEUE.lock();
    for i in 0..q.len() {
        if q[i].is_some() {
            return q[i];
        }
    }
    None
}

// ── Phase 3A: kernel32 handlers ───────────────────────────────────────────────

/// # IRQL: PASSIVE
fn win32_tls_alloc() -> u32 {
    // XP supports 64 TLS slots (TlsSlots[64] at TEB+0xE10).
    let mut bm = TLS_BITMAP.lock();
    for i in 0u32..64 {
        if *bm & (1u64 << i) == 0 {
            *bm |= 1u64 << i;
            return i; // returns slot index; TLS_OUT_OF_INDEXES = 0xFFFFFFFF
        }
    }
    0xFFFF_FFFF // TLS_OUT_OF_INDEXES
}

/// # IRQL: PASSIVE
fn win32_tls_free(args_ptr: u32) -> u32 {
    let slot = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if slot >= 64 { return 0; }
    TLS_BITMAP.lock().fetch_clear_bit(slot as usize);
    1 // TRUE
}

/// # IRQL: PASSIVE
/// Reads TEB.TlsSlots[slot] at TEB_VA + 0xE10 + slot*4.
fn win32_tls_get_value(args_ptr: u32) -> u32 {
    const TEB_VA: u32 = 0x7FFD_E000;
    let slot = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if slot >= 64 { return 0; }
    let addr = TEB_VA.wrapping_add(0xE10).wrapping_add(slot.wrapping_mul(4));
    // SAFETY: TEB is mapped and valid for the lifetime of the process.
    unsafe { (addr as *const u32).read_unaligned() }
}

/// # IRQL: PASSIVE
/// Writes TEB.TlsSlots[slot] at TEB_VA + 0xE10 + slot*4.
fn win32_tls_set_value(args_ptr: u32) -> u32 {
    const TEB_VA: u32 = 0x7FFD_E000;
    let slot  = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let value = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if slot >= 64 { return 0; }
    let addr = TEB_VA.wrapping_add(0xE10).wrapping_add(slot.wrapping_mul(4));
    // SAFETY: TEB is mapped and valid for the lifetime of the process.
    unsafe { (addr as *mut u32).write_unaligned(value); }
    1 // TRUE
}

/// XP CRITICAL_SECTION layout (24 bytes):
///   +0x00 PVOID  DebugInfo
///   +0x04 LONG   LockCount     (−1 = unlocked)
///   +0x08 LONG   RecursionCount
///   +0x0C PVOID  OwningThread
///   +0x10 PVOID  LockSemaphore
///   +0x14 ULONG  SpinCount
/// # IRQL: PASSIVE
fn win32_init_critical_section(args_ptr: u32) -> u32 {
    let cs = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(cs, 24) { return 0; }
    // SAFETY: validated user pointer, CRITICAL_SECTION is 24 bytes.
    unsafe {
        (cs as *mut u32).write_unaligned(0);           // DebugInfo = NULL
        (cs.wrapping_add(4) as *mut i32).write_unaligned(-1); // LockCount = -1 (unlocked)
        (cs.wrapping_add(8) as *mut u32).write_unaligned(0);  // RecursionCount
        (cs.wrapping_add(12) as *mut u32).write_unaligned(0); // OwningThread
        (cs.wrapping_add(16) as *mut u32).write_unaligned(0); // LockSemaphore
        (cs.wrapping_add(20) as *mut u32).write_unaligned(0); // SpinCount
    }
    0
}

/// # IRQL: PASSIVE
/// Acquires CRITICAL_SECTION. Phase 3A: single-threaded, just set LockCount=0.
fn win32_enter_critical_section(args_ptr: u32) -> u32 {
    let cs = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(cs, 24) { return 0; }
    // SAFETY: validated pointer.
    unsafe { (cs.wrapping_add(4) as *mut i32).write_unaligned(0); }
    0
}

/// # IRQL: PASSIVE
fn win32_leave_critical_section(args_ptr: u32) -> u32 {
    let cs = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(cs, 24) { return 0; }
    // SAFETY: validated pointer.
    unsafe { (cs.wrapping_add(4) as *mut i32).write_unaligned(-1); }
    0
}

/// # IRQL: PASSIVE
fn win32_try_enter_critical_section(args_ptr: u32) -> u32 {
    let cs = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(cs, 24) { return 0; }
    // Phase 3A: always succeeds (single-threaded).
    // SAFETY: validated pointer.
    unsafe { (cs.wrapping_add(4) as *mut i32).write_unaligned(0); }
    1 // TRUE
}

/// SRWLOCK is a single PVOID (4 bytes). Exclusive = bit 0 set.
/// # IRQL: PASSIVE
fn win32_acquire_srw_exclusive(args_ptr: u32) -> u32 {
    let lock = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(lock, 4) { return 0; }
    // SAFETY: validated pointer. Phase 3A: no contention, just set bit 0.
    unsafe { (lock as *mut u32).write_unaligned(1); }
    0
}

/// # IRQL: PASSIVE
fn win32_release_srw_exclusive(args_ptr: u32) -> u32 {
    let lock = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(lock, 4) { return 0; }
    // SAFETY: validated pointer.
    unsafe { (lock as *mut u32).write_unaligned(0); }
    0
}

/// GetModuleHandleW — same table as A but name is UTF-16LE.
/// # IRQL: PASSIVE
fn win32_get_module_handle_w(args_ptr: u32) -> u32 {
    let lp_name = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if lp_name == 0 { return 0x0040_0000; }
    // Read UTF-16LE name and convert to ASCII for lookup.
    let mut buf = [0u8; 128];
    let mut len = 0usize;
    let mut i = 0usize;
    while i < 127 {
        let addr = lp_name.wrapping_add((i * 2) as u32);
        if !is_user_range(addr, 2) { break; }
        // SAFETY: validated pointer.
        let lo = unsafe { (addr as *const u8).read_unaligned() };
        let hi = unsafe { (addr.wrapping_add(1) as *const u8).read_unaligned() };
        if lo == 0 && hi == 0 { break; }
        buf[len] = if hi == 0 { lo } else { b'?' };
        len += 1;
        i += 1;
    }
    if len == 0 { return 0; }
    let name = match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return 0 };
    ps::loader::resolve_stub_module_base(name).unwrap_or(0)
}

/// GetModuleHandleExA — ignores flags, delegates to base lookup.
/// # IRQL: PASSIVE
fn win32_get_module_handle_ex_a(args_ptr: u32) -> u32 {
    let _flags   = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let lp_name  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let out_hmod = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let mut fake_args = [lp_name];
    let base = win32_get_module_handle_a(fake_args.as_ptr() as u32 - 4);
    // SAFETY: out_hmod is user memory — write if valid.
    if is_user_range(out_hmod, 4) {
        let _ = write_u32_user(out_hmod, base);
    }
    if base != 0 { 1 } else { 0 }
}

/// SYSTEM_INFO layout (XP, 36 bytes).
/// Games check wProcessorArchitecture (x86=0) and dwNumberOfProcessors.
/// # IRQL: PASSIVE
fn win32_get_system_info(args_ptr: u32) -> u32 {
    let ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(ptr, 36) { return 0; }
    // SAFETY: validated 36-byte user buffer.
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, 36);
        // wProcessorArchitecture = 0 (PROCESSOR_ARCHITECTURE_INTEL)
        (ptr as *mut u16).write_unaligned(0);
        // wReserved = 0 (already zeroed)
        // dwPageSize = 0x1000
        (ptr.wrapping_add(4) as *mut u32).write_unaligned(0x1000);
        // lpMinimumApplicationAddress = 0x10000
        (ptr.wrapping_add(8) as *mut u32).write_unaligned(0x0001_0000);
        // lpMaximumApplicationAddress = 0x7FFEFFFF
        (ptr.wrapping_add(12) as *mut u32).write_unaligned(0x7FFE_FFFF);
        // dwActiveProcessorMask = 1
        (ptr.wrapping_add(16) as *mut u32).write_unaligned(1);
        // dwNumberOfProcessors = 1
        (ptr.wrapping_add(20) as *mut u32).write_unaligned(1);
        // dwProcessorType = 586 (Pentium)
        (ptr.wrapping_add(24) as *mut u32).write_unaligned(586);
        // dwAllocationGranularity = 0x10000 (64 KiB — XP default)
        (ptr.wrapping_add(28) as *mut u32).write_unaligned(0x0001_0000);
        // wProcessorLevel = 6, wProcessorRevision = 0
        (ptr.wrapping_add(32) as *mut u16).write_unaligned(6);
    }
    0
}

/// # IRQL: PASSIVE
fn win32_create_thread_k32(args_ptr: u32) -> u32 {
    // CreateThread(attrs, stack, fn, arg, flags, tid_ptr) → fake handle
    let tid_ptr = match read_arg_u32(args_ptr, 5) { Ok(v) => v, Err(_) => return 0 };
    if tid_ptr != 0 && is_user_range(tid_ptr, 4) {
        let _ = write_u32_user(tid_ptr, 0xFF); // fake TID
    }
    // Return a non-null fake handle; thread won't run (Phase 3A: single-threaded).
    0x0000_0100
}

/// # IRQL: PASSIVE
fn win32_create_event_a(args_ptr: u32) -> u32 {
    // CreateEventA → return a fake HANDLE; events are not really waited on yet.
    let _name = read_arg_u32(args_ptr, 3).unwrap_or(0);
    0x0000_0200 // fake event handle
}

/// CreateFileMappingA — backed by VirtualAlloc for now.
/// # IRQL: PASSIVE
fn win32_create_file_mapping(args_ptr: u32) -> u32 {
    let max_size_lo = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return 0 };
    if max_size_lo == 0 { return 0; }
    let protect = mm::vad::PageProtect::from_bits_truncate(0x04);
    let alloc   = mm::virtual_alloc::AllocType::from_bits_truncate(0x3000);
    let mut guard = SYSCALL_CTX.lock();
    let ctx = match guard.as_mut() { Some(v) => v, None => return 0 };
    // SAFETY: hhdm_offset valid for kernel lifetime.
    let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
    match mm::virtual_alloc::allocate(&mut ctx.vad, Some(&mut mapper), 0, max_size_lo as u64, alloc, protect) {
        Ok(base) => base as u32,
        Err(_)   => 0,
    }
}

/// MapViewOfFile — treat the "mapping handle" as the VA returned by CreateFileMapping.
/// # IRQL: PASSIVE
fn win32_map_view_of_file(args_ptr: u32) -> u32 {
    // mapping handle is already the base VA (from our CreateFileMappingA stub).
    read_arg_u32(args_ptr, 0).unwrap_or(0)
}

/// GetTempPathA — writes "C:\Temp\" and returns length.
/// # IRQL: PASSIVE
fn win32_get_temp_path_a(args_ptr: u32) -> u32 {
    const TEMP: &[u8] = b"C:\\Temp\\\0";
    let _len = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let buf  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if buf != 0 && is_user_range(buf, TEMP.len() as u32) {
        // SAFETY: validated user buffer.
        unsafe { core::ptr::copy_nonoverlapping(TEMP.as_ptr(), buf as *mut u8, TEMP.len()); }
    }
    (TEMP.len() - 1) as u32 // return length without null
}

/// GetTempFileNameA — writes a fixed fake path.
/// # IRQL: PASSIVE
fn win32_get_temp_file_name_a(args_ptr: u32) -> u32 {
    const NAME: &[u8] = b"C:\\Temp\\mino0000.tmp\0";
    let buf = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if buf != 0 && is_user_range(buf, NAME.len() as u32) {
        // SAFETY: validated user buffer.
        unsafe { core::ptr::copy_nonoverlapping(NAME.as_ptr(), buf as *mut u8, NAME.len()); }
    }
    0x1234 // unique identifier (fake)
}

/// OutputDebugStringA — log to serial.
/// # IRQL: PASSIVE
fn win32_output_debug_string(args_ptr: u32) -> u32 {
    let ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if ptr == 0 { return 0; }
    let mut buf = [0u8; 256];
    let len = read_cstr_user_buf(ptr, &mut buf);
    if len > 0 {
        if let Ok(s) = core::str::from_utf8(&buf[..len]) {
            log::debug!("[ODS] {}", s);
        }
    }
    0
}

/// VirtualQuery — fills MEMORY_BASIC_INFORMATION (28 bytes).
/// # IRQL: PASSIVE
fn win32_virtual_query(args_ptr: u32) -> u32 {
    let addr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let buf  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(buf, 28) { return 0; }
    // SAFETY: validated 28-byte user buffer.
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 28);
        (buf as *mut u32).write_unaligned(addr & !0xFFF);        // BaseAddress
        (buf.wrapping_add(4) as *mut u32).write_unaligned(0);   // AllocationBase
        (buf.wrapping_add(8) as *mut u32).write_unaligned(0x04);// AllocationProtect PAGE_READWRITE
        (buf.wrapping_add(12) as *mut u32).write_unaligned(0x1000); // RegionSize = 4KiB
        (buf.wrapping_add(16) as *mut u32).write_unaligned(0x1000); // State MEM_COMMIT
        (buf.wrapping_add(20) as *mut u32).write_unaligned(0x04);   // Protect PAGE_READWRITE
        (buf.wrapping_add(24) as *mut u32).write_unaligned(0x20000);// Type MEM_PRIVATE
    }
    28
}

/// GetModuleFileNameW — returns a fake wide path for the process image.
/// # IRQL: PASSIVE
fn win32_get_module_file_name_w(args_ptr: u32) -> u32 {
    const PATH_W: &[u16] = &[
        b'C' as u16, b'\\' as u16, b'G' as u16, b'a' as u16, b'm' as u16,
        b'e' as u16, b's' as u16, b'\\' as u16, b'g' as u16, b'a' as u16,
        b'm' as u16, b'e' as u16, b'.' as u16, b'e' as u16, b'x' as u16,
        b'e' as u16, 0u16,
    ];
    let buf  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let size = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let copy_chars = core::cmp::min(size as usize, PATH_W.len());
    if buf != 0 && is_user_range(buf, (copy_chars * 2) as u32) {
        // SAFETY: validated user buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(PATH_W.as_ptr(), buf as *mut u16, copy_chars);
        }
    }
    (PATH_W.len() - 1) as u32
}

/// QueryPerformanceCounter — returns HAL tick count as a LARGE_INTEGER.
/// # IRQL: PASSIVE
fn win32_query_perf_counter(args_ptr: u32) -> u32 {
    let ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(ptr, 8) { return 0; }
    let ticks = hal::timer::get_tick_count();
    // SAFETY: validated 8-byte user buffer.
    unsafe { (ptr as *mut u64).write_unaligned(ticks); }
    1 // TRUE
}

/// QueryPerformanceFrequency — returns PIT frequency (1193182 Hz) per Ghost Recon quirk.
/// # IRQL: PASSIVE
fn win32_query_perf_freq(args_ptr: u32) -> u32 {
    let ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(ptr, 8) { return 0; }
    // SAFETY: validated 8-byte user buffer.
    unsafe { (ptr as *mut u64).write_unaligned(1_193_182u64); }
    1 // TRUE
}

/// HeapAlloc(hHeap, dwFlags, dwBytes) — ignores heap handle, routes to malloc.
/// # IRQL: PASSIVE
fn win32_heap_alloc(args_ptr: u32) -> u32 {
    let _heap  = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let flags  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let size   = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if size == 0 { return 0; }
    // Allocate directly via VirtualAlloc (same as win32_malloc but inline).
    let protect = mm::vad::PageProtect::from_bits_truncate(0x04);
    let alloc   = mm::virtual_alloc::AllocType::from_bits_truncate(0x3000);
    let result = {
        let mut guard = SYSCALL_CTX.lock();
        let ctx = match guard.as_mut() { Some(v) => v, None => return 0 };
        let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
        match mm::virtual_alloc::allocate(&mut ctx.vad, Some(&mut mapper), 0, size as u64, alloc, protect) {
            Ok(base) => base as u32,
            Err(_) => 0,
        }
    };
    // Zero memory if HEAP_ZERO_MEMORY (0x08) flag is set
    if flags & 0x08 != 0 && result != 0 && size > 0 {
        let sz = (size as u64).min(0x100000);
        unsafe { core::ptr::write_bytes(result as *mut u8, 0, sz as usize); }
    }
    result
}

/// GetClientRect — returns a 1920×1080 RECT.
/// # IRQL: PASSIVE
fn win32_get_client_rect(args_ptr: u32) -> u32 {
    let _hwnd = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let rect  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(rect, 16) { return 0; }
    // RECT { left=0, top=0, right=1920, bottom=1080 }
    // SAFETY: validated 16-byte user buffer.
    unsafe {
        (rect as *mut u32).write_unaligned(0);
        (rect.wrapping_add(4) as *mut u32).write_unaligned(0);
        (rect.wrapping_add(8) as *mut u32).write_unaligned(1920);
        (rect.wrapping_add(12) as *mut u32).write_unaligned(1080);
    }
    1
}

/// EnumDisplaySettingsW — fills DEVMODEW for mode 0 with 1920×1080×32 @ 60Hz.
/// # IRQL: PASSIVE
fn win32_enum_display_settings_w(args_ptr: u32) -> u32 {
    let _device = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let mode_num = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let dm       = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    // ENUM_CURRENT_SETTINGS = 0xFFFFFFFF, ENUM_REGISTRY_SETTINGS = 0xFFFFFFFE — both allowed.
    // For mode index > 0, return FALSE (only one mode).
    if mode_num > 0 && mode_num < 0xFFFF_FFFE { return 0; }
    if !is_user_range(dm, 220) { return 0; }
    // SAFETY: validated DEVMODEW (220 bytes) user buffer.
    unsafe {
        core::ptr::write_bytes(dm as *mut u8, 0, 220);
        // dmSize at offset 36 (sizeof(DEVMODEW) for XP = 220 bytes but games use 156 or 220)
        (dm.wrapping_add(36) as *mut u16).write_unaligned(220);
        // dmFields: DM_PELSWIDTH|DM_PELSHEIGHT|DM_BITSPERPEL|DM_DISPLAYFREQUENCY
        (dm.wrapping_add(40) as *mut u32).write_unaligned(0x0058_0000);
        // dmBitsPerPel at offset 104
        (dm.wrapping_add(104) as *mut u32).write_unaligned(32);
        // dmPelsWidth at offset 108
        (dm.wrapping_add(108) as *mut u32).write_unaligned(1920);
        // dmPelsHeight at offset 112
        (dm.wrapping_add(112) as *mut u32).write_unaligned(1080);
        // dmDisplayFrequency at offset 120
        (dm.wrapping_add(120) as *mut u32).write_unaligned(60);
    }
    1 // TRUE
}

// ── Phase 3A: UCRT handlers ───────────────────────────────────────────────────

/// realloc(ptr, size) — alloc new + copy. Phase 3A: no-shrink, always alloc new.
/// # IRQL: PASSIVE
fn ucrt_realloc(args_ptr: u32) -> u32 {
    let old_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let new_size = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if new_size == 0 { return 0; }
    let fake_args = [new_size];
    let new_ptr = win32_malloc(fake_args.as_ptr() as u32 - 4);
    if new_ptr != 0 && old_ptr != 0 {
        // Copy conservatively (cap at new_size to avoid overread).
        let mut i = 0u32;
        while i < new_size {
            let addr = old_ptr.wrapping_add(i);
            if !is_user_range(addr, 1) { break; }
            // SAFETY: validated source pointer.
            let b = unsafe { (addr as *const u8).read_unaligned() };
            // SAFETY: new_ptr is freshly allocated.
            unsafe { (new_ptr.wrapping_add(i) as *mut u8).write_unaligned(b); }
            i = i.wrapping_add(1);
        }
    }
    new_ptr
}

/// _initialize_onexit_table(table*) — zero the 12-byte struct.
/// # IRQL: PASSIVE
fn ucrt_init_onexit_table(args_ptr: u32) -> u32 {
    let table = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if table != 0 && is_user_range(table, 12) {
        // SAFETY: validated pointer.
        unsafe { core::ptr::write_bytes(table as *mut u8, 0, 12); }
    }
    0 // success
}

/// _register_onexit_function(table*, fn*) — append fn to the table.
/// Table layout: { first: *fn, last: *fn, end: *fn } (3 pointers).
/// # IRQL: PASSIVE
fn ucrt_register_onexit_fn(args_ptr: u32) -> u32 {
    let table = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let func  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if table == 0 || !is_user_range(table, 12) { return 0; }
    // SAFETY: validated 12-byte table.
    let (first, last, end) = unsafe {
        (
            (table as *mut u32).read_unaligned(),
            (table.wrapping_add(4) as *mut u32).read_unaligned(),
            (table.wrapping_add(8) as *mut u32).read_unaligned(),
        )
    };
    if last < end {
        // SAFETY: last points into an allocated array (within end).
        unsafe {
            (last as *mut u32).write_unaligned(func);
            (table.wrapping_add(4) as *mut u32).write_unaligned(last.wrapping_add(4));
        }
    } else {
        // Table full or not initialized — allocate new backing array.
        let cap = if first == 0 { 16u32 } else { 16 };
        let fake_args = [cap * 4];
        let new_arr = win32_malloc(fake_args.as_ptr() as u32 - 4);
        if new_arr == 0 { return 1; } // out of memory
        // SAFETY: new_arr freshly allocated.
        unsafe {
            (new_arr as *mut u32).write_unaligned(func);
            (table as *mut u32).write_unaligned(new_arr);
            (table.wrapping_add(4) as *mut u32).write_unaligned(new_arr.wrapping_add(4));
            (table.wrapping_add(8) as *mut u32).write_unaligned(new_arr.wrapping_add(cap * 4));
        }
    }
    0
}

/// _beginthreadex — return a fake handle; thread doesn't actually run (Phase 3A).
/// # IRQL: PASSIVE
fn ucrt_beginthreadex(args_ptr: u32) -> u32 {
    let tid_ptr = read_arg_u32(args_ptr, 5).unwrap_or(0);
    if tid_ptr != 0 && is_user_range(tid_ptr, 4) {
        let _ = write_u32_user(tid_ptr, 0xBB);
    }
    0x0000_0300 // fake thread handle
}

/// _errno — return pointer to a static errno cell.
/// # IRQL: PASSIVE
fn ucrt_errno_ptr() -> u32 {
    // Use a fixed user-mode VA for the errno cell (inside SharedUserData scratch area).
    // For Phase 3A: return a pointer into our static kernel storage projected at a fixed VA.
    // Simpler: allocate once on first call.
    static ERRNO_VA: spin::Mutex<u32> = spin::Mutex::new(0);
    let mut va = ERRNO_VA.lock();
    if *va == 0 {
        let fake_args = [4u32];
        *va = win32_malloc(fake_args.as_ptr() as u32 - 4);
    }
    *va
}

/// strcmp(s1, s2) — lexicographic comparison.
/// # IRQL: PASSIVE
fn ucrt_strcmp(args_ptr: u32) -> u32 {
    let s1 = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let s2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let mut i = 0u32;
    loop {
        if i > 0x8000 { return 0; }
        // SAFETY: caller provides valid C strings.
        let a = unsafe { (s1.wrapping_add(i) as *const u8).read_unaligned() };
        let b = unsafe { (s2.wrapping_add(i) as *const u8).read_unaligned() };
        if a != b { return (a as i32 - b as i32) as u32; }
        if a == 0 { return 0; }
        i = i.wrapping_add(1);
    }
}

/// strncmp(s1, s2, n)
/// # IRQL: PASSIVE
fn ucrt_strncmp(args_ptr: u32) -> u32 {
    let s1 = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let s2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let n  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let mut i = 0u32;
    while i < n {
        // SAFETY: caller provides valid pointers for n bytes.
        let a = unsafe { (s1.wrapping_add(i) as *const u8).read_unaligned() };
        let b = unsafe { (s2.wrapping_add(i) as *const u8).read_unaligned() };
        if a != b { return (a as i32 - b as i32) as u32; }
        if a == 0 { return 0; }
        i = i.wrapping_add(1);
    }
    0
}

/// strncpy(dst, src, n) — copies up to n bytes, pads with NUL.
/// # IRQL: PASSIVE
fn ucrt_strncpy(args_ptr: u32) -> u32 {
    let dst = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let src = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let n   = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return dst };
    let mut i = 0u32;
    let mut done = false;
    while i < n {
        let b = if done { 0u8 } else {
            // SAFETY: caller ensures src is valid.
            let c = unsafe { (src.wrapping_add(i) as *const u8).read_unaligned() };
            if c == 0 { done = true; }
            c
        };
        // SAFETY: caller ensures dst is valid for n bytes.
        unsafe { (dst.wrapping_add(i) as *mut u8).write_unaligned(b); }
        i = i.wrapping_add(1);
    }
    dst
}

/// strnlen(s, maxlen) — length up to maxlen.
/// # IRQL: PASSIVE
fn ucrt_strnlen(args_ptr: u32) -> u32 {
    let s      = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let maxlen = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let mut len = 0u32;
    while len < maxlen {
        // SAFETY: caller provides valid pointer.
        let b = unsafe { (s.wrapping_add(len) as *const u8).read_unaligned() };
        if b == 0 { break; }
        len = len.wrapping_add(1);
    }
    len
}

/// strchr(s, c) — returns pointer to first occurrence or NULL.
/// # IRQL: PASSIVE
fn ucrt_strchr(args_ptr: u32) -> u32 {
    let s = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let c = match read_arg_u32(args_ptr, 1) { Ok(v) => v as u8, Err(_) => return 0 };
    let mut i = 0u32;
    loop {
        if i > 0x8000 { return 0; }
        // SAFETY: caller provides valid C string.
        let b = unsafe { (s.wrapping_add(i) as *const u8).read_unaligned() };
        if b == c { return s.wrapping_add(i); }
        if b == 0 { return 0; }
        i = i.wrapping_add(1);
    }
}

/// _strdup(s) — allocate copy of s.
/// # IRQL: PASSIVE
fn ucrt_strdup(args_ptr: u32) -> u32 {
    let s = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if s == 0 { return 0; }
    let len_args = [s];
    let len = win32_strlen(len_args.as_ptr() as u32 - 4);
    let size_args = [len.wrapping_add(1)];
    let buf = win32_malloc(size_args.as_ptr() as u32 - 4);
    if buf != 0 {
        let cpy_args = [buf, s, len.wrapping_add(1)];
        win32_memcpy(cpy_args.as_ptr() as u32 - 4);
    }
    buf
}

/// wcslen(s) — wide string length.
/// # IRQL: PASSIVE
fn ucrt_wcslen(args_ptr: u32) -> u32 {
    let s = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if s == 0 { return 0; }
    let mut len = 0u32;
    loop {
        if len > 0x8000 { break; }
        // SAFETY: caller provides valid wide C string.
        let lo = unsafe { (s.wrapping_add(len * 2) as *const u8).read_unaligned() };
        let hi = unsafe { (s.wrapping_add(len * 2 + 1) as *const u8).read_unaligned() };
        if lo == 0 && hi == 0 { break; }
        len = len.wrapping_add(1);
    }
    len
}

/// wcsnlen(s, maxlen)
/// # IRQL: PASSIVE
fn ucrt_wcsnlen(args_ptr: u32) -> u32 {
    let s      = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let maxlen = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let mut len = 0u32;
    while len < maxlen {
        // SAFETY: caller provides valid wide pointer.
        let lo = unsafe { (s.wrapping_add(len * 2) as *const u8).read_unaligned() };
        let hi = unsafe { (s.wrapping_add(len * 2 + 1) as *const u8).read_unaligned() };
        if lo == 0 && hi == 0 { break; }
        len = len.wrapping_add(1);
    }
    len
}

/// wcscmp(s1, s2) — wide string comparison.
/// # IRQL: PASSIVE
fn ucrt_wcscmp(args_ptr: u32) -> u32 {
    let s1 = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let s2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let mut i = 0u32;
    loop {
        if i > 0x8000 { return 0; }
        // SAFETY: caller provides valid wide C strings.
        let a = unsafe { (s1.wrapping_add(i * 2) as *const u16).read_unaligned() };
        let b = unsafe { (s2.wrapping_add(i * 2) as *const u16).read_unaligned() };
        if a != b { return (a as i32 - b as i32) as u32; }
        if a == 0 { return 0; }
        i = i.wrapping_add(1);
    }
}

/// _wcsicmp(s1, s2) — case-insensitive wide comparison (ASCII range only).
/// # IRQL: PASSIVE
fn ucrt_wcsicmp(args_ptr: u32) -> u32 {
    let s1 = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let s2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let mut i = 0u32;
    loop {
        if i > 0x8000 { return 0; }
        // SAFETY: caller provides valid wide C strings.
        let mut a = unsafe { (s1.wrapping_add(i * 2) as *const u16).read_unaligned() };
        let mut b = unsafe { (s2.wrapping_add(i * 2) as *const u16).read_unaligned() };
        if a >= b'A' as u16 && a <= b'Z' as u16 { a += 32; }
        if b >= b'A' as u16 && b <= b'Z' as u16 { b += 32; }
        if a != b { return (a as i32 - b as i32) as u32; }
        if a == 0 { return 0; }
        i = i.wrapping_add(1);
    }
}

/// strtoul(str, endptr, base) — parse unsigned long.
/// # IRQL: PASSIVE
fn ucrt_strtoul(args_ptr: u32) -> u32 {
    let s       = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let endptr  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let base    = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if s == 0 { return 0; }
    let mut i = 0u32;
    // Skip whitespace.
    while i < 32 {
        let b = unsafe { (s.wrapping_add(i) as *const u8).read_unaligned() };
        if b != b' ' && b != b'\t' { break; }
        i += 1;
    }
    let radix = if base == 0 { 10 } else { base };
    let mut val = 0u32;
    loop {
        let b = unsafe { (s.wrapping_add(i) as *const u8).read_unaligned() };
        let digit = if b >= b'0' && b <= b'9' { (b - b'0') as u32 }
                    else if b >= b'a' && b <= b'f' { (b - b'a' + 10) as u32 }
                    else if b >= b'A' && b <= b'F' { (b - b'A' + 10) as u32 }
                    else { break };
        if digit >= radix { break; }
        val = val.wrapping_mul(radix).wrapping_add(digit);
        i += 1;
        if i > 32 { break; }
    }
    if endptr != 0 && is_user_range(endptr, 4) {
        let _ = write_u32_user(endptr, s.wrapping_add(i));
    }
    val
}

/// memcmp(s1, s2, n) — byte comparison.
/// # IRQL: PASSIVE
fn ucrt_memcmp(args_ptr: u32) -> u32 {
    let s1 = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let s2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let n  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let mut i = 0u32;
    while i < n {
        // SAFETY: caller ensures valid pointers for n bytes.
        let a = unsafe { (s1.wrapping_add(i) as *const u8).read_unaligned() };
        let b = unsafe { (s2.wrapping_add(i) as *const u8).read_unaligned() };
        if a != b { return (a as i32 - b as i32) as u32; }
        i = i.wrapping_add(1);
    }
    0
}

/// memchr(s, c, n) — find byte in memory block.
/// # IRQL: PASSIVE
fn ucrt_memchr(args_ptr: u32) -> u32 {
    let s = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let c = match read_arg_u32(args_ptr, 1) { Ok(v) => v as u8, Err(_) => return 0 };
    let n = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let mut i = 0u32;
    while i < n {
        // SAFETY: caller ensures valid pointer for n bytes.
        let b = unsafe { (s.wrapping_add(i) as *const u8).read_unaligned() };
        if b == c { return s.wrapping_add(i); }
        i = i.wrapping_add(1);
    }
    0
}

// ── Phase 3A: ADVAPI32 registry ───────────────────────────────────────────────

/// In-memory registry: (predefined_hkey, subkey, value_name, type, data).
/// REG_SZ = 1, REG_DWORD = 4.
struct RegEntry {
    subkey: &'static str,
    value_name: &'static str,
    data_type: u32,
    data: &'static [u8], // for REG_SZ: UTF-8 + NUL
}

const HKLM: u32 = 0x8000_0002;

const REG_TABLE: &[RegEntry] = &[
    RegEntry {
        subkey: "Software\\Microsoft\\DirectX",
        value_name: "Version",
        data_type: 1,
        data: b"4.09.00.0900\0",
    },
    RegEntry {
        subkey: "Software\\Microsoft\\DirectX",
        value_name: "InstalledVersion",
        data_type: 1,
        data: b"4.09.00.0900\0",
    },
    RegEntry {
        subkey: "Software\\Microsoft\\Windows NT\\CurrentVersion",
        value_name: "CurrentVersion",
        data_type: 1,
        data: b"5.1\0",
    },
    RegEntry {
        subkey: "Software\\Microsoft\\Windows NT\\CurrentVersion",
        value_name: "CurrentBuildNumber",
        data_type: 1,
        data: b"2600\0",
    },
];

fn reg_find_subkey(subkey: &str) -> Option<usize> {
    for (i, e) in REG_TABLE.iter().enumerate() {
        if eq_ascii_nocase_str(e.subkey, subkey) {
            return Some(i);
        }
    }
    None
}

/// Case-insensitive ASCII string comparison for registry keys.
fn eq_ascii_nocase_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).all(|(x, y)| {
        x.to_ascii_lowercase() == y.to_ascii_lowercase()
    })
}

fn reg_alloc_fake_hkey(subkey_idx: usize) -> u32 {
    let mut keys = REG_OPEN_KEYS.lock();
    for (i, slot) in keys.iter_mut().enumerate() {
        if slot.is_none() {
            let fake = (i as u32 + 1) | 0x8000_0000;
            *slot = Some((fake, subkey_idx));
            return fake;
        }
    }
    0
}

fn reg_lookup_open_key(fake_hkey: u32) -> Option<usize> {
    let keys = REG_OPEN_KEYS.lock();
    for slot in keys.iter().flatten() {
        if slot.0 == fake_hkey {
            return Some(slot.1);
        }
    }
    None
}

/// RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)
/// # IRQL: PASSIVE
fn advapi_reg_open_key_ex_a(args_ptr: u32) -> u32 {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let _hkey    = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let subkey_p = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let out_p    = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let mut buf = [0u8; 256];
    let len = read_cstr_user_buf(subkey_p, &mut buf);
    if len == 0 { return ERROR_FILE_NOT_FOUND; }
    let subkey = match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return ERROR_FILE_NOT_FOUND };
    // Check if any entry in REG_TABLE uses this subkey.
    if let Some(idx) = reg_find_subkey(subkey) {
        let fake = reg_alloc_fake_hkey(idx);
        if fake != 0 && is_user_range(out_p, 4) {
            let _ = write_u32_user(out_p, fake);
            return 0; // ERROR_SUCCESS
        }
    }
    ERROR_FILE_NOT_FOUND
}

/// RegQueryValueExA(hKey, lpValueName, reserved, lpType, lpData, lpcbData)
/// # IRQL: PASSIVE
fn advapi_reg_query_value_ex_a(args_ptr: u32) -> u32 {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_MORE_DATA: u32      = 234;
    let hkey     = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let name_p   = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let type_p   = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let data_p   = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let size_p   = match read_arg_u32(args_ptr, 5) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };

    let subkey_idx = match reg_lookup_open_key(hkey) { Some(v) => v, None => return ERROR_FILE_NOT_FOUND };
    let mut buf = [0u8; 128];
    let len = read_cstr_user_buf(name_p, &mut buf);
    let value_name = if len > 0 { match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return ERROR_FILE_NOT_FOUND } } else { "" };

    // Find matching entry: same subkey AND value_name.
    let subkey_str = REG_TABLE[subkey_idx].subkey;
    for entry in REG_TABLE {
        if !eq_ascii_nocase_str(entry.subkey, subkey_str) { continue; }
        if !eq_ascii_nocase_str(entry.value_name, value_name) { continue; }
        // Write type.
        if type_p != 0 && is_user_range(type_p, 4) {
            let _ = write_u32_user(type_p, entry.data_type);
        }
        // Check / write data size.
        if size_p != 0 && is_user_range(size_p, 4) {
            let avail = match read_u32_user(size_p) { Ok(v) => v, Err(_) => 0 };
            let _ = write_u32_user(size_p, entry.data.len() as u32);
            if data_p != 0 {
                if (avail as usize) < entry.data.len() { return ERROR_MORE_DATA; }
                if is_user_range(data_p, entry.data.len() as u32) {
                    // SAFETY: validated user buffer.
                    unsafe {
                        core::ptr::copy_nonoverlapping(entry.data.as_ptr(), data_p as *mut u8, entry.data.len());
                    }
                }
            }
        }
        return 0; // ERROR_SUCCESS
    }
    ERROR_FILE_NOT_FOUND
}

/// RegCloseKey(hKey)
/// # IRQL: PASSIVE
fn advapi_reg_close_key(args_ptr: u32) -> u32 {
    let hkey = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let mut keys = REG_OPEN_KEYS.lock();
    for slot in keys.iter_mut() {
        if let Some((h, _)) = *slot {
            if h == hkey { *slot = None; break; }
        }
    }
    0 // ERROR_SUCCESS
}

/// RegOpenKeyExW — wide version, converts to ASCII and delegates.
/// # IRQL: PASSIVE
fn advapi_reg_open_key_ex_w(args_ptr: u32) -> u32 {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let hkey     = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let subkey_w = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let opts     = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let sam      = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let out_p    = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    // Convert wide subkey to ASCII buf on stack.
    let mut ascii_buf = [0u8; 256];
    let mut ascii_len = 0usize;
    let mut wi = 0usize;
    while wi < 255 {
        let addr = subkey_w.wrapping_add((wi * 2) as u32);
        if !is_user_range(addr, 2) { break; }
        // SAFETY: validated pointer.
        let lo = unsafe { (addr as *const u8).read_unaligned() };
        let hi = unsafe { (addr.wrapping_add(1) as *const u8).read_unaligned() };
        if lo == 0 && hi == 0 { break; }
        ascii_buf[ascii_len] = if hi == 0 { lo } else { b'?' };
        ascii_len += 1;
        wi += 1;
    }
    ascii_buf[ascii_len] = 0;
    // Re-assemble args for the A version.
    let ascii_ptr = ascii_buf.as_ptr() as u32;
    let fake_args = [hkey, ascii_ptr, opts, sam, out_p];
    advapi_reg_open_key_ex_a(fake_args.as_ptr() as u32 - 4)
}

/// RegQueryValueExW — wide name, ASCII data response (for REG_SZ: convert to wide).
/// # IRQL: PASSIVE
fn advapi_reg_query_value_ex_w(args_ptr: u32) -> u32 {
    // For Phase 3A: convert wide value name to ASCII, use same table (data stays as ASCII bytes).
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let hkey   = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let name_w = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let opts   = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let type_p = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let data_p = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let size_p = match read_arg_u32(args_ptr, 5) { Ok(v) => v, Err(_) => return ERROR_FILE_NOT_FOUND };
    let mut ascii_buf = [0u8; 128];
    let mut ascii_len = 0usize;
    let mut wi = 0usize;
    while wi < 127 {
        let addr = name_w.wrapping_add((wi * 2) as u32);
        if !is_user_range(addr, 2) { break; }
        // SAFETY: validated pointer.
        let lo = unsafe { (addr as *const u8).read_unaligned() };
        let hi = unsafe { (addr.wrapping_add(1) as *const u8).read_unaligned() };
        if lo == 0 && hi == 0 { break; }
        ascii_buf[ascii_len] = if hi == 0 { lo } else { b'?' };
        ascii_len += 1;
        wi += 1;
    }
    ascii_buf[ascii_len] = 0;
    let ascii_ptr = ascii_buf.as_ptr() as u32;
    let fake_args = [hkey, ascii_ptr, opts, type_p, data_p, size_p];
    advapi_reg_query_value_ex_a(fake_args.as_ptr() as u32 - 4)
}

/// AllocateLocallyUniqueId(LUID*) — writes a monotonically increasing fake LUID.
/// # IRQL: PASSIVE
fn advapi_alloc_luid(args_ptr: u32) -> u32 {
    static LUID_CTR: spin::Mutex<u64> = spin::Mutex::new(1);
    let ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(ptr, 8) { return 0; }
    let luid = { let mut c = LUID_CTR.lock(); let v = *c; *c = c.wrapping_add(1); v };
    // SAFETY: validated 8-byte user buffer.
    unsafe { (ptr as *mut u64).write_unaligned(luid); }
    1 // TRUE
}

/// GetUserNameA(lpBuffer: LPSTR, pcbBuffer: LPDWORD) → BOOL
///
/// Writes "Player\0" into lpBuffer and sets *pcbBuffer to 7 (including NUL).
/// Returns TRUE on success, FALSE if buffer too small (< 7 bytes).
///
/// IRQL: PASSIVE_LEVEL
fn win32_get_user_name_a(args_ptr: u32) -> u32 {
    let buf_ptr  = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let size_ptr = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(buf_ptr, 7) { return 0; }
    if !is_user_range(size_ptr, 4) { return 0; }
    // SAFETY: both pointers validated above.
    let provided = unsafe { (size_ptr as *const u32).read_unaligned() };
    if provided < 7 {
        // SetLastError would be ERROR_INSUFFICIENT_BUFFER; stub just fails.
        unsafe { (size_ptr as *mut u32).write_unaligned(7); }
        return 0; // FALSE
    }
    const NAME: &[u8] = b"Player\0";
    unsafe {
        for (i, &b) in NAME.iter().enumerate() {
            (buf_ptr as *mut u8).add(i).write_unaligned(b);
        }
        (size_ptr as *mut u32).write_unaligned(7);
    }
    1 // TRUE
}

// ── Trait extension: bit-clear helper for u64 (TLS bitmap) ───────────────────

trait FetchClearBit { fn fetch_clear_bit(&mut self, bit: usize); }
impl FetchClearBit for u64 {
    fn fetch_clear_bit(&mut self, bit: usize) {
        if bit < 64 { *self &= !(1u64 << bit); }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vulkan ICD loader syscall handlers
// ═══════════════════════════════════════════════════════════════════════════════
//
// WI7e Ch.1 — "System architecture": these sit in ring-0 and service INT 0x2E
// traps from the vulkan-1.dll stub module. DXVK resolves all Vulkan function
// pointers via vkGetInstanceProcAddr, which looks up names in the stub export
// table and returns their VAs.
//
// Game relevance: Ghost Recon 2001 → DXVK d3d8 → d3d9 → vulkan-1 → here.

/// Fake VkPhysicalDevice handle used throughout the stub ICD.
const VK_FAKE_PHYS_DEV: u32 = 0xDE00_1000;
/// Static 16 MB mapping for vkMapMemory results — reuse the bump allocator.
static VK_MAP_REGION: Mutex<u32> = Mutex::new(0);

fn vk_get_instance_proc_addr(args_ptr: u32) -> u32 {
    // args: (VkInstance instance, const char* pName)
    let p_name = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let mut buf = [0u8; 64];
    let len = read_cstr_user_buf(p_name, &mut buf);
    if len == 0 { return 0; }
    let name = match core::str::from_utf8(&buf[..len]) { Ok(s) => s, Err(_) => return 0 };
    // Look up in vulkan-1 stub exports → returns VA of the stub code
    const VK_BASE: u32 = 0x7C00_0000;
    if let Some(addr) = ps::loader::resolve_stub_proc_by_base(VK_BASE, name) {
        return addr;
    }
    log::debug!("[vk] GetInstanceProcAddr: '{}' not found", name);
    0 // NULL = function not available
}

fn vk_get_device_proc_addr(args_ptr: u32) -> u32 {
    // Same logic — device-level functions live in the same stub module.
    vk_get_instance_proc_addr(args_ptr)
}

fn vk_enum_inst_ext_props(args_ptr: u32) -> u32 {
    // vkEnumerateInstanceExtensionProperties(pLayerName, pPropertyCount, pProperties)
    let p_count = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let p_props = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    // Report 1 extension: VK_KHR_surface (DXVK requires it)
    if p_props == 0 {
        // Query count only
        let _ = write_u32_user(p_count, 2);
        return 0; // VK_SUCCESS
    }
    let count = unsafe { read_unaligned(p_count as *const u32) };
    // Write VK_KHR_surface (VkExtensionProperties: char[256] + uint32_t)
    if count >= 1 && is_user_range(p_props, 260) {
        let name = b"VK_KHR_surface\0";
        for (i, &b) in name.iter().enumerate() {
            let _ = write_u8_user(p_props + i as u32, b);
        }
        // specVersion = 25
        let _ = write_u32_user(p_props + 256, 25);
    }
    if count >= 2 && is_user_range(p_props + 260, 260) {
        let name = b"VK_KHR_win32_surface\0";
        let base = p_props + 260;
        for (i, &b) in name.iter().enumerate() {
            let _ = write_u8_user(base + i as u32, b);
        }
        let _ = write_u32_user(base + 256, 6);
    }
    let written = core::cmp::min(count, 2);
    let _ = write_u32_user(p_count, written);
    0 // VK_SUCCESS
}

fn vk_enum_inst_layer_props(args_ptr: u32) -> u32 {
    // No layers — write count = 0
    let p_count = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let _ = write_u32_user(p_count, 0);
    0
}

fn vk_enum_inst_version(args_ptr: u32) -> u32 {
    // vkEnumerateInstanceVersion(uint32_t* pApiVersion)
    let p_ver = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    // Vulkan 1.2.0: VK_MAKE_API_VERSION(0, 1, 2, 0) = (1<<22)|(2<<12) = 0x0040_2000
    let _ = write_u32_user(p_ver, (1 << 22) | (2 << 12));
    0
}

fn vk_enum_physical_devices(args_ptr: u32) -> u32 {
    // vkEnumeratePhysicalDevices(VkInstance, uint32_t* pCount, VkPhysicalDevice* pPhysDevs)
    let p_count = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let p_devs  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if p_devs == 0 {
        let _ = write_u32_user(p_count, 1);
        return 0;
    }
    let _ = write_u32_user(p_count, 1);
    let _ = write_u32_user(p_devs, VK_FAKE_PHYS_DEV);
    0
}

fn vk_get_phys_dev_props(args_ptr: u32) -> u32 {
    // vkGetPhysicalDeviceProperties(VkPhysicalDevice, VkPhysicalDeviceProperties*)
    // VkPhysicalDeviceProperties (32-bit): 816 bytes
    //   +0x00: apiVersion (u32) — Vulkan 1.2.0
    //   +0x04: driverVersion (u32)
    //   +0x08: vendorID (u32) — 0x10DE (NVIDIA)
    //   +0x0C: deviceID (u32)
    //   +0x10: deviceType (u32) — VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU = 2
    //   +0x14: deviceName (char[256])
    //   +0x114: pipelineCacheUUID (uint8_t[16])
    //   +0x124: limits (VkPhysicalDeviceLimits, 504 bytes)
    //   +0x31C: sparseProperties (VkPhysicalDeviceSparseProperties, 20 bytes)
    let p_props = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p_props, 816) { return 0; }
    // Zero entire struct first
    for i in (0..816).step_by(4) {
        let _ = write_u32_user(p_props + i, 0);
    }
    let _ = write_u32_user(p_props + 0x00, (1 << 22) | (2 << 12)); // apiVersion 1.2.0
    let _ = write_u32_user(p_props + 0x04, 0x0001_0000); // driverVersion
    let _ = write_u32_user(p_props + 0x08, 0x10DE);       // vendorID (NVIDIA)
    let _ = write_u32_user(p_props + 0x0C, 0x1C82);       // deviceID (GTX 1050)
    let _ = write_u32_user(p_props + 0x10, 2);             // DISCRETE_GPU
    // deviceName = "Mino Vulkan Stub GPU"
    let name = b"Mino Vulkan Stub GPU\0";
    for (i, &b) in name.iter().enumerate() {
        let _ = write_u8_user(p_props + 0x14 + i as u32, b);
    }
    // Fill critical limits that DXVK checks:
    let limits = p_props + 0x124;
    let _ = write_u32_user(limits + 0,  4096);       // maxImageDimension1D
    let _ = write_u32_user(limits + 4,  4096);       // maxImageDimension2D
    let _ = write_u32_user(limits + 8,  256);        // maxImageDimension3D
    let _ = write_u32_user(limits + 12, 4096);       // maxImageDimensionCube
    let _ = write_u32_user(limits + 16, 256);        // maxImageArrayLayers
    let _ = write_u32_user(limits + 20, 65536);      // maxTexelBufferElements
    let _ = write_u32_user(limits + 24, 16384);      // maxUniformBufferRange
    let _ = write_u32_user(limits + 28, 0x0800_0000);// maxStorageBufferRange (128MB)
    let _ = write_u32_user(limits + 32, 128);        // maxPushConstantsSize
    let _ = write_u32_user(limits + 36, 4096);       // maxMemoryAllocationCount
    let _ = write_u32_user(limits + 40, 4096);       // maxSamplerAllocationCount
    // maxBoundDescriptorSets (+76)
    let _ = write_u32_user(limits + 76, 8);
    // maxPerStageDescriptorSamplers (+80..+100): set all to reasonable values
    for off in (80..104).step_by(4) {
        let _ = write_u32_user(limits + off, 16);
    }
    // maxVertexInputAttributes (+116)
    let _ = write_u32_user(limits + 116, 16);
    // maxVertexInputBindings (+120)
    let _ = write_u32_user(limits + 120, 16);
    // maxFragmentOutputAttachments (+168)
    let _ = write_u32_user(limits + 168, 8);
    // maxFramebufferWidth/Height (+264,+268)
    let _ = write_u32_user(limits + 264, 4096);
    let _ = write_u32_user(limits + 268, 4096);
    // maxFramebufferLayers (+272)
    let _ = write_u32_user(limits + 272, 256);
    // maxColorAttachments (+276)
    let _ = write_u32_user(limits + 276, 8);
    // maxViewports (+216)
    let _ = write_u32_user(limits + 216, 16);
    0 // void return but we use VK_SUCCESS convention
}

fn vk_get_phys_dev_props2(args_ptr: u32) -> u32 {
    // VkPhysicalDeviceProperties2KHR has sType+pNext+VkPhysicalDeviceProperties
    // sType at +0 (=1000059001), pNext at +4, properties at +8
    let p_props2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    // Redirect to fill the embedded VkPhysicalDeviceProperties at offset 8
    let inner_ptr = p_props2 + 8;
    // Build a temporary args array pointing to the inner struct
    let fake_args: [u32; 2] = [0, inner_ptr];
    let fake_ptr = fake_args.as_ptr() as u32;
    vk_get_phys_dev_props(fake_ptr)
}

fn vk_get_phys_dev_features(args_ptr: u32) -> u32 {
    // VkPhysicalDeviceFeatures: 55 VkBool32 fields = 220 bytes. Set all to TRUE.
    let p_feat = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p_feat, 220) { return 0; }
    for i in (0..220).step_by(4) {
        let _ = write_u32_user(p_feat + i, 1); // VK_TRUE
    }
    0
}

fn vk_get_phys_dev_features2(args_ptr: u32) -> u32 {
    // VkPhysicalDeviceFeatures2: sType(+0), pNext(+4), features(+8, 220 bytes)
    let p_feat2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let inner = p_feat2 + 8;
    if !is_user_range(inner, 220) { return 0; }
    for i in (0..220).step_by(4) {
        let _ = write_u32_user(inner + i, 1);
    }
    0
}

fn vk_get_phys_dev_mem_props(args_ptr: u32) -> u32 {
    // VkPhysicalDeviceMemoryProperties (32-bit):
    //   +0x00: memoryTypeCount (u32)
    //   +0x04: memoryTypes[32] — each 8 bytes (propertyFlags u32, heapIndex u32) = 256 bytes
    //   +0x104: memoryHeapCount (u32)
    //   +0x108: memoryHeaps[16] — each 12 bytes (size u64, flags u32) = 192 bytes
    let p = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p, 0x1C8) { return 0; }
    // Zero entire struct
    for i in (0u32..0x1C8).step_by(4) {
        let _ = write_u32_user(p + i, 0);
    }
    // 2 memory types, 2 heaps
    let _ = write_u32_user(p + 0x00, 2); // memoryTypeCount
    // Type 0: DEVICE_LOCAL (propertyFlags=0x01, heapIndex=0)
    let _ = write_u32_user(p + 0x04, 0x01); // propertyFlags
    let _ = write_u32_user(p + 0x08, 0);    // heapIndex
    // Type 1: HOST_VISIBLE|HOST_COHERENT (propertyFlags=0x06, heapIndex=1)
    let _ = write_u32_user(p + 0x0C, 0x06);
    let _ = write_u32_user(p + 0x10, 1);
    // memoryHeapCount
    let _ = write_u32_user(p + 0x104, 2);
    // Heap 0: 256 MB device-local (flags=0x01)
    let _ = write_u64_user(p + 0x108, 256 * 1024 * 1024); // size
    let _ = write_u32_user(p + 0x110, 0x01); // flags = DEVICE_LOCAL
    // Heap 1: 512 MB host-visible
    let _ = write_u64_user(p + 0x114, 512 * 1024 * 1024);
    let _ = write_u32_user(p + 0x11C, 0x00); // flags = 0
    0
}

fn vk_get_phys_dev_mem_props2(args_ptr: u32) -> u32 {
    // VkPhysicalDeviceMemoryProperties2: sType(+0), pNext(+4), memoryProperties(+8)
    let p2 = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let fake_args: [u32; 2] = [0, p2 + 8];
    vk_get_phys_dev_mem_props(fake_args.as_ptr() as u32)
}

fn vk_get_phys_dev_queue_props(args_ptr: u32) -> u32 {
    // vkGetPhysicalDeviceQueueFamilyProperties(physDev, pCount, pQueueFamilyProperties)
    // VkQueueFamilyProperties: queueFlags(u32), queueCount(u32), timestampValidBits(u32),
    //                          minImageTransferGranularity(3×u32) = 24 bytes
    let p_count = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let p_props = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if p_props == 0 {
        let _ = write_u32_user(p_count, 1);
        return 0; // void, but return convention
    }
    let _ = write_u32_user(p_count, 1);
    if !is_user_range(p_props, 24) { return 0; }
    // queueFlags: GRAPHICS|COMPUTE|TRANSFER|SPARSE = 0x0F
    let _ = write_u32_user(p_props + 0, 0x0F);
    let _ = write_u32_user(p_props + 4, 4);  // queueCount
    let _ = write_u32_user(p_props + 8, 64); // timestampValidBits
    // minImageTransferGranularity {1,1,1}
    let _ = write_u32_user(p_props + 12, 1);
    let _ = write_u32_user(p_props + 16, 1);
    let _ = write_u32_user(p_props + 20, 1);
    0
}

fn vk_get_phys_dev_fmt_props(args_ptr: u32) -> u32 {
    // vkGetPhysicalDeviceFormatProperties(physDev, VkFormat, VkFormatProperties*)
    // VkFormatProperties: linearTilingFeatures(u32), optimalTilingFeatures(u32), bufferFeatures(u32) = 12 bytes
    let p_props = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p_props, 12) { return 0; }
    // Report all common features: sampled|storage|color_attach|depth|blit|transfer|vertex
    let all_features: u32 = 0x1FF01; // common feature bits
    let _ = write_u32_user(p_props + 0, all_features); // linearTilingFeatures
    let _ = write_u32_user(p_props + 4, all_features); // optimalTilingFeatures
    let _ = write_u32_user(p_props + 8, all_features); // bufferFeatures
    0
}

fn vk_enum_dev_ext_props(args_ptr: u32) -> u32 {
    // vkEnumerateDeviceExtensionProperties(physDev, pLayerName, pPropertyCount, pProperties)
    let p_count = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let p_props = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    // Report 1 extension: VK_KHR_swapchain
    if p_props == 0 {
        let _ = write_u32_user(p_count, 1);
        return 0;
    }
    let _ = write_u32_user(p_count, 1);
    if is_user_range(p_props, 260) {
        let name = b"VK_KHR_swapchain\0";
        for (i, &b) in name.iter().enumerate() {
            let _ = write_u8_user(p_props + i as u32, b);
        }
        let _ = write_u32_user(p_props + 256, 70); // specVersion
    }
    0
}

fn vk_get_surface_caps(args_ptr: u32) -> u32 {
    // VkSurfaceCapabilitiesKHR: 52 bytes
    //   minImageCount(u32), maxImageCount(u32), currentExtent(2×u32),
    //   minImageExtent(2×u32), maxImageExtent(2×u32), maxImageArrayLayers(u32),
    //   supportedTransforms(u32), currentTransform(u32), supportedCompositeAlpha(u32),
    //   supportedUsageFlags(u32)
    let p_caps = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p_caps, 52) { return 0; }
    let _ = write_u32_user(p_caps + 0,  2);    // minImageCount
    let _ = write_u32_user(p_caps + 4,  8);    // maxImageCount
    let _ = write_u32_user(p_caps + 8,  800);  // currentExtent.width
    let _ = write_u32_user(p_caps + 12, 600);  // currentExtent.height
    let _ = write_u32_user(p_caps + 16, 1);    // minImageExtent.width
    let _ = write_u32_user(p_caps + 20, 1);    // minImageExtent.height
    let _ = write_u32_user(p_caps + 24, 4096); // maxImageExtent.width
    let _ = write_u32_user(p_caps + 28, 4096); // maxImageExtent.height
    let _ = write_u32_user(p_caps + 32, 1);    // maxImageArrayLayers
    let _ = write_u32_user(p_caps + 36, 0x01); // supportedTransforms (IDENTITY)
    let _ = write_u32_user(p_caps + 40, 0x01); // currentTransform (IDENTITY)
    let _ = write_u32_user(p_caps + 44, 0x01); // supportedCompositeAlpha (OPAQUE)
    let _ = write_u32_user(p_caps + 48, 0x1F); // supportedUsageFlags
    0
}

fn vk_get_surface_formats(args_ptr: u32) -> u32 {
    // vkGetPhysicalDeviceSurfaceFormatsKHR(physDev, surface, pFormatCount, pFormats)
    // VkSurfaceFormatKHR: format(u32) + colorSpace(u32) = 8 bytes
    let p_count = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let p_fmts  = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    if p_fmts == 0 {
        let _ = write_u32_user(p_count, 1);
        return 0;
    }
    let _ = write_u32_user(p_count, 1);
    if is_user_range(p_fmts, 8) {
        let _ = write_u32_user(p_fmts + 0, 44); // VK_FORMAT_B8G8R8A8_UNORM
        let _ = write_u32_user(p_fmts + 4, 0);  // VK_COLOR_SPACE_SRGB_NONLINEAR_KHR
    }
    0
}

fn vk_get_surface_present_modes(args_ptr: u32) -> u32 {
    let p_count = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let p_modes = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    if p_modes == 0 {
        let _ = write_u32_user(p_count, 1);
        return 0;
    }
    let _ = write_u32_user(p_count, 1);
    if is_user_range(p_modes, 4) {
        let _ = write_u32_user(p_modes, 2); // VK_PRESENT_MODE_FIFO_KHR
    }
    0
}

fn vk_get_surface_support(args_ptr: u32) -> u32 {
    // vkGetPhysicalDeviceSurfaceSupportKHR(physDev, queueFamilyIndex, surface, pSupported)
    let p_supported = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    let _ = write_u32_user(p_supported, 1); // VK_TRUE
    0
}

fn vk_get_swapchain_images(args_ptr: u32) -> u32 {
    // vkGetSwapchainImagesKHR(device, swapchain, pSwapchainImageCount, pSwapchainImages)
    let p_count  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let p_images = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    if p_images == 0 {
        let _ = write_u32_user(p_count, 2);
        return 0;
    }
    let _ = write_u32_user(p_count, 2);
    if is_user_range(p_images, 8) {
        let _ = write_u32_user(p_images + 0, 0xDE00_0020); // image handle 0
        let _ = write_u32_user(p_images + 4, 0xDE00_0021); // image handle 1
    }
    0
}

fn vk_acquire_next_image(args_ptr: u32) -> u32 {
    // vkAcquireNextImageKHR(dev, swapchain, timeout_lo, timeout_hi, semaphore, fence, pImageIndex)
    // On 32-bit: args at index 0..6, but timeout is u64 so pImageIndex is at index 6
    // args: [dev, sc, timeout_lo, timeout_hi, sem, fence, pIdx]
    let p_idx = match read_arg_u32(args_ptr, 6) { Ok(v) => v, Err(_) => return 0 };
    let _ = write_u32_user(p_idx, 0); // always return image index 0
    0 // VK_SUCCESS
}

fn vk_alloc_cmd_buffers(args_ptr: u32) -> u32 {
    // vkAllocateCommandBuffers(device, pAllocateInfo, pCommandBuffers)
    // VkCommandBufferAllocateInfo: sType(+0), pNext(+4), commandPool(+8),
    //                              level(+12), commandBufferCount(+16)
    let p_alloc_info = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let p_cmd_bufs   = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let count = if is_user_range(p_alloc_info + 16, 4) {
        unsafe { read_unaligned((p_alloc_info + 16) as *const u32) }
    } else { 1 };
    let count = core::cmp::min(count, 64); // sanity cap
    for i in 0..count {
        let _ = write_u32_user(p_cmd_bufs + i * 4, 0xDE00_0100 + i);
    }
    0
}

fn vk_map_memory(args_ptr: u32) -> u32 {
    // vkMapMemory(device, memory, offset_lo, offset_hi, size_lo, size_hi, flags, ppData)
    // offset and size are VkDeviceSize (u64) on 32-bit → index 2..5
    // flags at index 6, ppData at index 7
    let pp_data = match read_arg_u32(args_ptr, 7) { Ok(v) => v, Err(_) => return 0 };
    // Allocate a scratch region for the mapped memory
    let mut guard = VK_MAP_REGION.lock();
    if *guard == 0 {
        // Allocate 16 MB of user-mode memory for map targets
        let size = 16 * 1024 * 1024u64;
        let ctx = SYSCALL_CTX.lock();
        if let Some(ref _c) = *ctx {
            // Use a fixed VA in the user range
            *guard = 0x3000_0000;
        }
        drop(ctx);
    }
    let _ = write_u32_user(pp_data, *guard);
    0
}

fn vk_get_mem_reqs(args_ptr: u32) -> u32 {
    // vkGetImageMemoryRequirements / vkGetBufferMemoryRequirements
    // (device, image_or_buffer, VkMemoryRequirements*)
    // VkMemoryRequirements: size(u64), alignment(u64), memoryTypeBits(u32) = 20 bytes
    let p_reqs = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p_reqs, 20) { return 0; }
    let _ = write_u64_user(p_reqs + 0, 4 * 1024 * 1024);  // size = 4 MB
    let _ = write_u64_user(p_reqs + 8, 256);                // alignment = 256
    let _ = write_u32_user(p_reqs + 16, 0x03);              // memoryTypeBits (types 0+1)
    0
}

fn vk_alloc_descriptor_sets(args_ptr: u32) -> u32 {
    // vkAllocateDescriptorSets(device, pAllocateInfo, pDescriptorSets)
    // VkDescriptorSetAllocateInfo: sType(+0), pNext(+4), descriptorPool(+8),
    //                              descriptorSetCount(+12), pSetLayouts(+16)
    let p_alloc_info = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let p_sets       = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let count = if is_user_range(p_alloc_info + 12, 4) {
        unsafe { read_unaligned((p_alloc_info + 12) as *const u32) }
    } else { 1 };
    let count = core::cmp::min(count, 64);
    for i in 0..count {
        let _ = write_u32_user(p_sets + i * 4, 0xDE00_0200 + i);
    }
    0
}

fn vk_create_pipelines(args_ptr: u32) -> u32 {
    // vkCreateGraphicsPipelines / vkCreateComputePipelines
    // (device, pipelineCache, createInfoCount, pCreateInfos, pAllocator, pPipelines)
    let count      = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let p_pipelines = match read_arg_u32(args_ptr, 5) { Ok(v) => v, Err(_) => return 0 };
    let count = core::cmp::min(count, 64);
    for i in 0..count {
        let _ = write_u32_user(p_pipelines + i * 4, 0xDE00_0300 + i);
    }
    0
}

fn vk_queue_present(args_ptr: u32) -> u32 {
    // vkQueuePresentKHR(VkQueue queue, const VkPresentInfoKHR* pPresentInfo)
    // VkPresentInfoKHR (32-bit):
    //   +0  sType (u32)
    //   +4  pNext (u32)
    //   +8  waitSemaphoreCount (u32)
    //   +12 pWaitSemaphores (u32 ptr)
    //   +16 swapchainCount (u32)
    //   +20 pSwapchains (u32 ptr)
    //   +24 pImageIndices (u32 ptr)
    //   +28 pResults (u32 ptr, optional)
    //
    // For now: blit from the vkMapMemory scratch region (0x3000_0000) to the GOP
    // framebuffer.  DXVK will have rendered into that region via mapped memory.
    let (fb_w, fb_h) = hal::fb::dimensions();
    if fb_w == 0 || fb_h == 0 { return 0; } // no framebuffer

    let map_addr = *VK_MAP_REGION.lock();
    if map_addr == 0 { return 0; }

    // Treat the mapped region as a BGRA8888 framebuffer at the surface dimensions
    // reported by vk_get_surface_caps (800×600).
    let src_w = 800u32.min(fb_w);
    let src_h = 600u32.min(fb_h);

    // SAFETY: map_addr is in user VA space which is mapped in kernel CR3.
    let src_ptr = map_addr as *const u32;
    hal::fb::blit_bgra(src_ptr, src_w, src_h, 0, 0);
    0 // VK_SUCCESS
}

// ── Ghost Recon kernel32 handlers ────────────────────────────────────────────

/// GlobalMemoryStatus(MEMORYSTATUS*) → void
/// # IRQL: PASSIVE
fn win32_global_memory_status(args_ptr: u32) -> u32 {
    let p = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p, 32) { return 0; }
    // SAFETY: validated 32-byte user buffer (MEMORYSTATUS is 32 bytes on 32-bit).
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, 32);
        // dwLength
        (p as *mut u32).write_unaligned(32);
        // dwMemoryLoad = 50%
        ((p + 4) as *mut u32).write_unaligned(50);
        // dwTotalPhys = 512 MB
        ((p + 8) as *mut u32).write_unaligned(512 * 1024 * 1024);
        // dwAvailPhys = 256 MB
        ((p + 12) as *mut u32).write_unaligned(256 * 1024 * 1024);
        // dwTotalPageFile = 1 GB
        ((p + 16) as *mut u32).write_unaligned(1024 * 1024 * 1024);
        // dwAvailPageFile = 512 MB
        ((p + 20) as *mut u32).write_unaligned(512 * 1024 * 1024);
        // dwTotalVirtual = 2 GB
        ((p + 24) as *mut u32).write_unaligned(0x7FFF_0000);
        // dwAvailVirtual = 1.5 GB
        ((p + 28) as *mut u32).write_unaligned(0x5FFF_0000);
    }
    0
}

/// GetModuleFileNameA(hModule, lpFilename, nSize) → DWORD chars written
/// # IRQL: PASSIVE
fn win32_get_module_file_name_a(args_ptr: u32) -> u32 {
    let _module = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let buf     = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let size    = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let path = b"C:\\game.exe\0";
    let copy_len = (path.len() as u32).min(size);
    if copy_len == 0 || !is_user_range(buf, copy_len) { return 0; }
    // SAFETY: validated user buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), buf as *mut u8, copy_len as usize);
    }
    copy_len - 1 // exclude NUL
}

/// MultiByteToWideChar(CodePage, dwFlags, lpMBS, cbMBS, lpWCS, cchWCS) → int
/// Simple ASCII→UTF16 expansion.
/// # IRQL: PASSIVE
fn win32_multi_byte_to_wide_char(args_ptr: u32) -> u32 {
    let _cp    = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let _flags = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let src    = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let src_len= match read_arg_u32(args_ptr, 3) { Ok(v) => v as i32, Err(_) => return 0 };
    let dst    = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return 0 };
    let dst_len= match read_arg_u32(args_ptr, 5) { Ok(v) => v, Err(_) => return 0 };
    // Determine source length
    let actual_src_len = if src_len == -1 {
        // NUL-terminated — count chars including NUL
        let mut n = 0u32;
        while is_user_range(src + n, 1) {
            let b = unsafe { ((src + n) as *const u8).read_unaligned() };
            n += 1;
            if b == 0 { break; }
            if n > 0x10000 { break; }
        }
        n
    } else {
        src_len as u32
    };
    // If dst_len == 0, just return required size
    if dst_len == 0 {
        return actual_src_len;
    }
    let copy_n = actual_src_len.min(dst_len);
    if copy_n == 0 { return 0; }
    if !is_user_range(src, actual_src_len) || !is_user_range(dst, copy_n * 2) { return 0; }
    // SAFETY: validated buffers.
    unsafe {
        for i in 0..copy_n {
            let b = ((src + i) as *const u8).read_unaligned();
            ((dst + i * 2) as *mut u16).write_unaligned(b as u16);
        }
    }
    copy_n
}

/// GetVersionExA(OSVERSIONINFOA*) → BOOL
/// Fills with XP SP2 values.
/// # IRQL: PASSIVE
fn win32_get_version_ex_a(args_ptr: u32) -> u32 {
    let p = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p, 148) { return 0; }
    // OSVERSIONINFOA: dwOSVersionInfoSize(4), dwMajorVersion(4), dwMinorVersion(4),
    //                 dwBuildNumber(4), dwPlatformId(4), szCSDVersion[128]
    // SAFETY: validated 148-byte user buffer.
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, 148);
        (p as *mut u32).write_unaligned(148); // dwOSVersionInfoSize
        ((p + 4) as *mut u32).write_unaligned(5);    // dwMajorVersion
        ((p + 8) as *mut u32).write_unaligned(1);    // dwMinorVersion
        ((p + 12) as *mut u32).write_unaligned(2600); // dwBuildNumber
        ((p + 16) as *mut u32).write_unaligned(2);    // VER_PLATFORM_WIN32_NT
        // szCSDVersion at offset 20: "Service Pack 2\0"
        let sp = b"Service Pack 2\0";
        core::ptr::copy_nonoverlapping(sp.as_ptr(), (p + 20) as *mut u8, sp.len());
    }
    1 // TRUE
}

/// lstrcpyA(dst, src) → dst
/// # IRQL: PASSIVE
fn win32_lstrcpy_a(args_ptr: u32) -> u32 {
    let dst = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let src = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if dst == 0 || src == 0 { return 0; }
    // Copy until NUL (with limit)
    let mut i = 0u32;
    loop {
        if i > 0x10000 { break; }
        let b = unsafe { ((src + i) as *const u8).read_unaligned() };
        unsafe { ((dst + i) as *mut u8).write_unaligned(b); }
        if b == 0 { break; }
        i += 1;
    }
    dst
}

/// GetCurrentDirectoryA(nBufferLength, lpBuffer) → DWORD
/// # IRQL: PASSIVE
fn win32_get_current_dir_a(args_ptr: u32) -> u32 {
    let size = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let buf  = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let dir = b"C:\\\0";
    if size < dir.len() as u32 || !is_user_range(buf, dir.len() as u32) { return dir.len() as u32; }
    unsafe { core::ptr::copy_nonoverlapping(dir.as_ptr(), buf as *mut u8, dir.len()); }
    3 // "C:\" = 3 chars
}

/// lstrcatA(dst, src) → dst
/// # IRQL: PASSIVE
fn win32_lstrcat_a(args_ptr: u32) -> u32 {
    let dst = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let src = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if dst == 0 || src == 0 { return 0; }
    // Find end of dst
    let mut d = 0u32;
    while d < 0x10000 {
        let b = unsafe { ((dst + d) as *const u8).read_unaligned() };
        if b == 0 { break; }
        d += 1;
    }
    // Copy src
    let mut s = 0u32;
    loop {
        if s > 0x10000 { break; }
        let b = unsafe { ((src + s) as *const u8).read_unaligned() };
        unsafe { ((dst + d + s) as *mut u8).write_unaligned(b); }
        if b == 0 { break; }
        s += 1;
    }
    dst
}

/// lstrcpynA(dst, src, iMaxLength) → dst
/// # IRQL: PASSIVE
fn win32_lstrcpyn_a(args_ptr: u32) -> u32 {
    let dst = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let src = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let max = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if dst == 0 || src == 0 || max == 0 { return 0; }
    let limit = max.min(0x10000);
    let mut i = 0u32;
    while i < limit - 1 {
        let b = unsafe { ((src + i) as *const u8).read_unaligned() };
        unsafe { ((dst + i) as *mut u8).write_unaligned(b); }
        if b == 0 { return dst; }
        i += 1;
    }
    unsafe { ((dst + i) as *mut u8).write_unaligned(0); }
    dst
}

/// lstrlenA(lpString) → int
/// # IRQL: PASSIVE
fn win32_lstrlen_a(args_ptr: u32) -> u32 {
    let s = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if s == 0 { return 0; }
    let mut n = 0u32;
    while n < 0x10000 {
        let b = unsafe { ((s + n) as *const u8).read_unaligned() };
        if b == 0 { break; }
        n += 1;
    }
    n
}

/// WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) → BOOL
/// Delegates to NtWriteFile for real handles; fakes success for stdout/stderr.
/// # IRQL: PASSIVE
fn win32_write_file(args_ptr: u32) -> u32 {
    let handle    = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let buf       = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let count     = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let written   = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    let _overlapped = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return 0 };
    // For stdout/stderr fake handles, log and succeed
    if handle <= 2 {
        if is_user_range(buf, count) && count > 0 {
            let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, count as usize) };
            if let Ok(s) = core::str::from_utf8(slice) {
                log::info!("[WriteFile] {}", s.trim_end());
            }
        }
        if written != 0 && is_user_range(written, 4) {
            let _ = write_u32_user(written, count);
        }
        return 1; // TRUE
    }
    // For real file handles, report written = count (stub)
    if written != 0 && is_user_range(written, 4) {
        let _ = write_u32_user(written, count);
    }
    1
}

/// GetFileSize(hFile) → DWORD (only uses handle arg)
/// # IRQL: PASSIVE
fn win32_get_file_size(args_ptr: u32) -> u32 {
    let handle = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0xFFFF_FFFF };
    // Look up file state
    let map = FILE_HANDLE_MAP.lock();
    for slot in map.iter() {
        if let Some((h, ref file)) = slot {
            if *h == handle {
                return file.file_size;
            }
        }
    }
    0xFFFF_FFFF // INVALID_FILE_SIZE
}

/// GetFileAttributesA(lpFileName) → DWORD
/// Returns FILE_ATTRIBUTE_NORMAL for everything, INVALID for unknown files.
/// # IRQL: PASSIVE
/// CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
///             dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) → HANDLE
fn win32_create_file_a(args_ptr: u32) -> u32 {
    let name_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0xFFFF_FFFF };
    let mut buf = [0u8; 260];
    let len = read_cstr_user_buf(name_ptr, &mut buf);
    if len == 0 { return 0xFFFF_FFFF; }
    let path = core::str::from_utf8(&buf[..len]).unwrap_or("");
    log::info!("[CreateFileA] '{}'", path);

    // Strip drive letter and backslash prefix, convert \ to /
    let mut fat_path = alloc::string::String::from("/");
    let stripped = path.trim_start_matches(|c: char| c == '\\' || c == '/')
        .trim_start_matches(|c: char| c.is_ascii_alphanumeric())
        .trim_start_matches(':')
        .trim_start_matches(|c: char| c == '\\' || c == '/');
    let stripped = if stripped.is_empty() { path.trim_start_matches(|c: char| c == '\\' || c == '/') } else { stripped };
    for ch in stripped.chars() {
        if ch == '\\' { fat_path.push('/'); }
        else { fat_path.push(ch.to_ascii_uppercase()); }
    }

    // Try ramdisk first
    if let Ok(file) = io_manager::open_fat_file(&fat_path) {
        let handle = allocate_file_handle(file);
        log::info!("[CreateFileA] '{}' -> ramdisk handle {:#x}", path, handle);
        return handle;
    }

    // Try ATA game disk
    if let Ok(file) = io_manager::open_game_file(&fat_path) {
        let handle = allocate_game_file_handle(file);
        log::info!("[CreateFileA] '{}' -> game disk handle {:#x}", path, handle);
        return handle;
    }

    log::info!("[CreateFileA] '{}' -> NOT FOUND", path);
    0xFFFF_FFFF // INVALID_HANDLE_VALUE
}

/// Allocate a file handle for a ramdisk FAT file.
fn allocate_file_handle(file: io_manager::FatFile) -> u32 {
    let mut map = FILE_HANDLE_MAP.lock();
    for (i, slot) in map.iter_mut().enumerate() {
        if slot.is_none() {
            let handle = ((i + 1) as u32) * 4 + 0x100; // handles 0x104, 0x108, ...
            *slot = Some((handle, file));
            return handle;
        }
    }
    0xFFFF_FFFF
}

// Game file handles stored separately (use ATA read instead of ramdisk read)
static GAME_FILE_MAP: Mutex<[Option<(u32, io_manager::FatFile)>; 64]> = Mutex::new([None; 64]);

fn allocate_game_file_handle(file: io_manager::FatFile) -> u32 {
    let mut map = GAME_FILE_MAP.lock();
    for (i, slot) in map.iter_mut().enumerate() {
        if slot.is_none() {
            let handle = ((i + 1) as u32) * 4 + 0x1000; // game handles 0x1004, 0x1008, ...
            *slot = Some((handle, file));
            return handle;
        }
    }
    0xFFFF_FFFF
}

fn win32_get_file_type(args_ptr: u32) -> u32 {
    let handle = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    // Stdio pseudo-handles (3=stdin, 7=stdout, 11=stderr) → FILE_TYPE_CHAR
    // FAT file handles → FILE_TYPE_DISK
    match handle {
        3 | 7 | 11 => 2,  // FILE_TYPE_CHAR (console/device)
        0 => 0,           // FILE_TYPE_UNKNOWN
        _ => 1,           // FILE_TYPE_DISK
    }
}

fn win32_message_box_a(args_ptr: u32) -> u32 {
    // MessageBoxA(hWnd, lpText, lpCaption, uType)
    let text_ptr = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 1 };
    let cap_ptr  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 1 };
    let mut tbuf = [0u8; 256];
    let mut cbuf = [0u8; 128];
    let tlen = read_cstr_user_buf(text_ptr, &mut tbuf);
    let clen = read_cstr_user_buf(cap_ptr, &mut cbuf);
    let text = core::str::from_utf8(&tbuf[..tlen]).unwrap_or("?");
    let cap  = core::str::from_utf8(&cbuf[..clen]).unwrap_or("?");
    log::info!("[MessageBoxA] '{}': {}", cap, text);
    1 // IDOK
}

fn win32_get_file_attributes_a(args_ptr: u32) -> u32 {
    let name_ptr = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0xFFFF_FFFF };
    let mut buf = [0u8; 128];
    let len = read_cstr_user_buf(name_ptr, &mut buf);
    let path = core::str::from_utf8(&buf[..len]).unwrap_or("?");
    log::info!("[GetFileAttribA] '{}'", path);
    // Return FILE_ATTRIBUTE_NORMAL (0x80) for files, DIRECTORY (0x10) for known dirs
    0x80
}

/// GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, lpFilePart) → DWORD
/// # IRQL: PASSIVE
fn win32_get_full_path_name_a(args_ptr: u32) -> u32 {
    let name = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let size = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let buf  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let _part = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    if name == 0 || buf == 0 { return 0; }
    // Prepend "C:\" and copy the filename
    let prefix = b"C:\\";
    // Get source length
    let mut slen = 0u32;
    while slen < 0x1000 {
        let b = unsafe { ((name + slen) as *const u8).read_unaligned() };
        if b == 0 { break; }
        slen += 1;
    }
    let total = prefix.len() as u32 + slen + 1; // +1 for NUL
    if total > size { return total; }
    if !is_user_range(buf, total) { return 0; }
    unsafe {
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), buf as *mut u8, prefix.len());
        core::ptr::copy_nonoverlapping(name as *const u8, (buf + prefix.len() as u32) as *mut u8, slen as usize);
        ((buf + prefix.len() as u32 + slen) as *mut u8).write_unaligned(0);
    }
    prefix.len() as u32 + slen
}

/// GetCPInfo(CodePage, lpCPInfo) → BOOL
/// # IRQL: PASSIVE
fn win32_get_cp_info(args_ptr: u32) -> u32 {
    let _cp = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let info = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(info, 20) { return 0; }
    // CPINFO: MaxCharSize(4), DefaultChar[2], LeadByte[12]
    // SAFETY: validated 20-byte buffer.
    unsafe {
        core::ptr::write_bytes(info as *mut u8, 0, 20);
        (info as *mut u32).write_unaligned(1); // MaxCharSize = 1 (single-byte)
        ((info + 4) as *mut u8).write_unaligned(b'?'); // DefaultChar[0]
    }
    1 // TRUE
}

/// GetCommandLineA() → LPCSTR
/// Returns a pointer to a static command line string in kernel memory.
/// For Ghost Recon we return "-nointro\0".
/// # IRQL: PASSIVE
static COMMAND_LINE_BUF: Mutex<u32> = Mutex::new(0);

fn win32_get_command_line_a() -> u32 {
    let mut guard = COMMAND_LINE_BUF.lock();
    if *guard != 0 {
        return *guard;
    }
    // Allocate a small user-mode buffer for the command line string
    let cmd = b"-nointro\0";
    let protect = mm::vad::PageProtect::from_bits_truncate(0x04);
    let alloc = mm::virtual_alloc::AllocType::from_bits_truncate(0x3000);
    let mut ctx_guard = SYSCALL_CTX.lock();
    let ctx = match ctx_guard.as_mut() { Some(v) => v, None => return 0 };
    let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
    match mm::virtual_alloc::allocate(&mut ctx.vad, Some(&mut mapper), 0, 0x1000, alloc, protect) {
        Ok(base) => {
            // SAFETY: freshly allocated page.
            unsafe {
                core::ptr::copy_nonoverlapping(cmd.as_ptr(), base as *mut u8, cmd.len());
            }
            *guard = base as u32;
            base as u32
        }
        Err(_) => 0,
    }
}

/// GetLocalTime / GetSystemTime(SYSTEMTIME*) → void
/// Fills a plausible XP-era time.
/// # IRQL: PASSIVE
fn win32_get_local_time(args_ptr: u32) -> u32 {
    let p = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p, 16) { return 0; }
    // SYSTEMTIME: wYear(2), wMonth(2), wDayOfWeek(2), wDay(2), wHour(2), wMinute(2), wSecond(2), wMilliseconds(2)
    // SAFETY: validated 16-byte user buffer.
    unsafe {
        (p as *mut u16).write_unaligned(2003);       // wYear
        ((p + 2) as *mut u16).write_unaligned(6);     // wMonth (June)
        ((p + 4) as *mut u16).write_unaligned(3);     // wDayOfWeek (Tuesday)
        ((p + 6) as *mut u16).write_unaligned(15);    // wDay
        ((p + 8) as *mut u16).write_unaligned(12);    // wHour
        ((p + 10) as *mut u16).write_unaligned(0);    // wMinute
        ((p + 12) as *mut u16).write_unaligned(0);    // wSecond
        ((p + 14) as *mut u16).write_unaligned(0);    // wMilliseconds
    }
    0
}

/// GetStartupInfoA(STARTUPINFOA*) → void
/// Zeros the 68-byte struct.
/// # IRQL: PASSIVE
fn win32_get_startup_info_a(args_ptr: u32) -> u32 {
    let p = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(p, 68) { return 0; }
    // SAFETY: validated 68-byte user buffer.
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, 68);
        (p as *mut u32).write_unaligned(68); // cb = sizeof(STARTUPINFOA)
    }
    0
}

/// GetStdHandle(nStdHandle) → HANDLE
/// STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
/// # IRQL: PASSIVE
fn win32_get_std_handle(args_ptr: u32) -> u32 {
    let n = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    // Return non-zero pseudo-handles that look like real Windows handles.
    // The CRT checks these are non-NULL and calls GetFileType on them.
    match n {
        0xFFFF_FFF6 => 3,  // STD_INPUT_HANDLE  (-10)
        0xFFFF_FFF5 => 7,  // STD_OUTPUT_HANDLE (-11)
        0xFFFF_FFF4 => 11, // STD_ERROR_HANDLE  (-12)
        _ => 0xFFFF_FFFF,  // INVALID_HANDLE_VALUE
    }
}

/// HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes) → LPVOID
/// # IRQL: PASSIVE
fn win32_heap_realloc(args_ptr: u32) -> u32 {
    let _heap  = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let _flags = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let old    = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let size   = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    // Simple realloc: allocate new, copy old data (up to 1 page for safety), return new
    if size == 0 { return 0; }
    let protect = mm::vad::PageProtect::from_bits_truncate(0x04);
    let alloc = mm::virtual_alloc::AllocType::from_bits_truncate(0x3000);
    let mut guard = SYSCALL_CTX.lock();
    let ctx = match guard.as_mut() { Some(v) => v, None => return 0 };
    let mut mapper = SyscallMapper { pt: unsafe { mm::MmPageTables::new(ctx.hhdm_offset) } };
    match mm::virtual_alloc::allocate(&mut ctx.vad, Some(&mut mapper), 0, size as u64, alloc, protect) {
        Ok(new_base) => {
            if old != 0 {
                // Copy min(old alloc, new size) — use 1 page as conservative upper bound
                let copy_size = (size as usize).min(0x1000);
                // SAFETY: old and new_base are user-VA, kernel has full mapping.
                unsafe {
                    core::ptr::copy_nonoverlapping(old as *const u8, new_base as *mut u8, copy_size);
                }
            }
            new_base as u32
        }
        Err(_) => 0,
    }
}

/// MulDiv(nNumber, nNumerator, nDenominator) → int
/// # IRQL: PASSIVE
fn win32_mul_div(args_ptr: u32) -> u32 {
    let a = match read_arg_u32(args_ptr, 0) { Ok(v) => v as i32, Err(_) => return 0xFFFF_FFFF };
    let b = match read_arg_u32(args_ptr, 1) { Ok(v) => v as i32, Err(_) => return 0xFFFF_FFFF };
    let c = match read_arg_u32(args_ptr, 2) { Ok(v) => v as i32, Err(_) => return 0xFFFF_FFFF };
    if c == 0 { return 0xFFFF_FFFF; } // -1
    let result = (a as i64 * b as i64) / c as i64;
    result as i32 as u32
}

/// ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped) → BOOL
/// Win32 wrapper around NtReadFile.
/// # IRQL: PASSIVE
fn win32_read_file_k32(args_ptr: u32) -> u32 {
    let handle = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let buf    = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let count  = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let read   = match read_arg_u32(args_ptr, 3) { Ok(v) => v, Err(_) => return 0 };
    let _overlapped = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return 0 };
    if !is_user_range(buf, count) { return 0; }
    // Look up file handle via lookup helper, then read
    let mut state = match lookup_file_handle_state(handle) {
        Some(v) => v,
        None => {
            // Unknown handle — fake success with 0 bytes
            if read != 0 && is_user_range(read, 4) { let _ = write_u32_user(read, 0); }
            return 0;
        }
    };
    let avail = state.file_size.saturating_sub(state.position);
    let to_read = count.min(avail);
    if to_read == 0 {
        if read != 0 && is_user_range(read, 4) { let _ = write_u32_user(read, 0); }
        return 1; // TRUE, 0 bytes (EOF)
    }
    let mut tmp = alloc::vec![0u8; to_read as usize];
    let n = match io_manager::read_fat_file(&mut state, &mut tmp) {
        Ok(v) => v as u32,
        Err(_) => return 0,
    };
    // SAFETY: validated user buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf as *mut u8, n as usize);
    }
    remember_file_handle_state(handle, state);
    if read != 0 && is_user_range(read, 4) { let _ = write_u32_user(read, n); }
    1 // TRUE
}

/// WideCharToMultiByte(CodePage, dwFlags, lpWCS, cchWCS, lpMBS, cbMBS, lpDefault, lpUsedDefault)
/// Simple UTF16→ASCII truncation.
/// # IRQL: PASSIVE
fn win32_wide_char_to_multi_byte(args_ptr: u32) -> u32 {
    let _cp      = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let _flags   = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let src      = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    let src_len  = match read_arg_u32(args_ptr, 3) { Ok(v) => v as i32, Err(_) => return 0 };
    let dst      = match read_arg_u32(args_ptr, 4) { Ok(v) => v, Err(_) => return 0 };
    let dst_len  = match read_arg_u32(args_ptr, 5) { Ok(v) => v, Err(_) => return 0 };
    // Determine source length in chars
    let actual_src_len = if src_len == -1 {
        let mut n = 0u32;
        while n < 0x10000 && is_user_range(src + n * 2, 2) {
            let ch = unsafe { ((src + n * 2) as *const u16).read_unaligned() };
            n += 1;
            if ch == 0 { break; }
        }
        n
    } else {
        src_len as u32
    };
    if dst_len == 0 {
        return actual_src_len;
    }
    let copy_n = actual_src_len.min(dst_len);
    if copy_n == 0 { return 0; }
    if !is_user_range(src, actual_src_len * 2) || !is_user_range(dst, copy_n) { return 0; }
    // SAFETY: validated buffers.
    unsafe {
        for i in 0..copy_n {
            let ch = ((src + i * 2) as *const u16).read_unaligned();
            let b = if ch < 128 { ch as u8 } else { b'?' };
            ((dst + i) as *mut u8).write_unaligned(b);
        }
    }
    copy_n
}

/// EnumDisplaySettingsA — same as W but for DEVMODEA (156 bytes, no Unicode names).
/// # IRQL: PASSIVE
fn win32_enum_display_settings_a(args_ptr: u32) -> u32 {
    let _device  = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    let mode_num = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 0 };
    let dm       = match read_arg_u32(args_ptr, 2) { Ok(v) => v, Err(_) => return 0 };
    if mode_num > 0 && mode_num < 0xFFFF_FFFE { return 0; }
    if !is_user_range(dm, 156) { return 0; }
    // SAFETY: validated DEVMODEA (156 bytes).
    unsafe {
        core::ptr::write_bytes(dm as *mut u8, 0, 156);
        // dmSize at offset 36
        ((dm + 36) as *mut u16).write_unaligned(156);
        // dmFields
        ((dm + 40) as *mut u32).write_unaligned(0x0058_0000);
        // dmBitsPerPel at offset 104
        ((dm + 104) as *mut u32).write_unaligned(32);
        // dmPelsWidth at offset 108
        ((dm + 108) as *mut u32).write_unaligned(1024);
        // dmPelsHeight at offset 112
        ((dm + 112) as *mut u32).write_unaligned(768);
        // dmDisplayFrequency at offset 120
        ((dm + 120) as *mut u32).write_unaligned(60);
    }
    1 // TRUE
}

/// GetSystemMetrics(nIndex) → int
/// # IRQL: PASSIVE
fn win32_get_system_metrics(args_ptr: u32) -> u32 {
    let index = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 0 };
    match index {
        0  => 1024, // SM_CXSCREEN
        1  => 768,  // SM_CYSCREEN
        5  => 3,    // SM_CXBORDER
        6  => 3,    // SM_CYBORDER
        32 => 1024, // SM_CXFULLSCREEN
        33 => 768,  // SM_CYFULLSCREEN
        _ => 0,
    }
}

/// timeGetDevCaps(TIMECAPS*, cbSize) → MMRESULT
/// # IRQL: PASSIVE
fn win32_time_get_dev_caps(args_ptr: u32) -> u32 {
    let p    = match read_arg_u32(args_ptr, 0) { Ok(v) => v, Err(_) => return 1 };
    let _size = match read_arg_u32(args_ptr, 1) { Ok(v) => v, Err(_) => return 1 };
    if !is_user_range(p, 8) { return 1; } // TIMERR_NOCANDO
    // TIMECAPS: wPeriodMin(4), wPeriodMax(4)
    // SAFETY: validated 8-byte user buffer.
    unsafe {
        (p as *mut u32).write_unaligned(1);    // wPeriodMin = 1ms
        ((p + 4) as *mut u32).write_unaligned(1000000); // wPeriodMax
    }
    0 // TIMERR_NOERROR
}

fn normalize_nt_path_to_fat(path: &str) -> Option<String> {
    let mut p = path;
    if p.starts_with("\\??\\") {
        p = &p[4..];
    }
    if p.len() >= 3 {
        let b = p.as_bytes();
        if b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
            p = &p[3..];
        }
    }
    if p.starts_with('\\') || p.starts_with('/') {
        p = &p[1..];
    }
    if p.is_empty() {
        return None;
    }
    let mut out = String::from("/");
    for ch in p.chars() {
        if ch == '\\' {
            out.push('/');
        } else {
            out.push(ch);
        }
    }
    Some(out)
}
