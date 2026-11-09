//! Les services système (02 §6.2) : KiSystemService pour les threads de Ps,
//! sur les tables générées à partir de ReactOS (`abi::services`).
//!
//! Un appel système arrive par `int 2Eh` ou SYSENTER ([`gates`], sur la
//! trame de trap) avec le numéro du service dans EAX et ses arguments dans
//! la pile utilisateur. [`dispatch`] trouve le service, copie
//! ses arguments (`ke::usermem`) et appelle son handler, interruptions
//! actives, à PASSIVE_LEVEL : il peut attendre ou être préempté. Un numéro
//! hors des tables rend `STATUS_INVALID_SYSTEM_SERVICE` ; un service sans
//! handler, journalisé à son premier appel, rend `STATUS_NOT_IMPLEMENTED`
//! s'il rend un `NTSTATUS`, et sinon (un BOOL, un HANDLE, un compte… de
//! win32k) 0, son échec, avec `ERROR_CALL_NOT_IMPLEMENTED` comme dernière
//! erreur du thread, comme le ferait win32k (`Service::returns_status`).
//!
//! Un service peut aussi donner au thread un nouveau contexte, dans sa trame
//! de trap ([`Handler::Frame`] : NtContinue, NtRaiseException).
//!
//! Le premier appel d'un thread à win32k en fait un thread GUI
//! (PsConvertToGuiThread, `win32k::convert_current_thread`) ; s'il échoue,
//! l'appel rend son statut. Avant chaque appel à win32k, les appels de GDI
//! que le thread a mis en lot dans son TEB sont exécutés
//! (KeGdiFlushUserBatch, `win32k::gdi::batch::flush`).
//!
//! Chaque appel est compté, par service ; [`service_calls`] rend les
//! services appelés depuis [`reset_service_calls`], dans l'ordre de leur
//! premier appel, avec ce qu'il a rendu (spike S1 : les appels système que
//! fait `ntdll`).
//!
//! Les threads de l'ancien chargeur gardent leur dispatcher (`syscall.rs`),
//! qui a ses propres numéros, jusqu'à sa suppression.

pub mod apc;
mod atom;
mod callback;
mod class;
mod console;
mod desktop;
mod event;
pub mod exceptions;
mod file;
pub mod gates;
mod gdi;
mod input;
pub mod locale;
mod memory;
mod message;
mod monitor;
mod mouse;
mod mutant;
mod object;
mod pipe;
mod port;
mod process;
mod registry;
mod section;
mod security;
mod system;
mod time;
mod timer;
mod user;
mod wait;
mod window;
mod winsta;

pub(crate) use system::processor_information;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_SYSTEM_SERVICE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS,
};
use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
use abi::service::{lookup, Service, Table};
use abi::services::{self, NTOSKRNL, WIN32K};
use hal::trap::KTrapFrame;
use ob::{AccessMask, Handle, Object};
use ps::{EProcess, EThread, PROCESS_TYPE, THREAD_TYPE};

/// Le handler d'un service, qui reçoit ses arguments, un mot de 32 bits
/// chacun.
#[derive(Clone, Copy)]
pub enum Handler {
    /// Rend un statut, pour EAX.
    Status(fn(&[u32]) -> NtStatus),
    /// Met dans la trame de trap le nouveau contexte du thread, ou rend un
    /// statut d'erreur pour EAX.
    Frame(fn(&[u32], &mut KTrapFrame) -> Result<(), NtStatus>),
}

/// Ce qu'un service laisse au thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Un statut, pour EAX.
    Status(NtStatus),
    /// Sa trame de trap tient son nouveau contexte.
    Frame,
}

/// Les services implémentés, par numéro. `tools/syscall-gen` en tire le
/// rapport de couverture (`docs/compat/syscalls.md`) : une entrée par ligne,
/// `(services::NtNom, Handler::…(module::handler)),`.
pub const IMPLEMENTED: &[(u32, Handler)] = &[
    (services::NtAcceptConnectPort, Handler::Status(port::nt_accept_connect_port)),
    (services::NtAdjustPrivilegesToken, Handler::Status(security::nt_adjust_privileges_token)),
    (services::NtAddAtom, Handler::Status(atom::nt_add_atom)),
    (services::NtAllocateVirtualMemory, Handler::Status(memory::nt_allocate_virtual_memory)),
    (services::NtCallbackReturn, Handler::Status(callback::nt_callback_return)),
    (services::NtCancelIoFile, Handler::Status(pipe::nt_cancel_io_file)),
    (services::NtClearEvent, Handler::Status(event::nt_clear_event)),
    (services::NtClose, Handler::Status(object::nt_close)),
    (services::NtCompleteConnectPort, Handler::Status(port::nt_complete_connect_port)),
    (services::NtConnectPort, Handler::Status(port::nt_connect_port)),
    (services::NtContinue, Handler::Frame(exceptions::nt_continue)),
    (services::NtCreateDirectoryObject, Handler::Status(object::nt_create_directory_object)),
    (services::NtCreateEvent, Handler::Status(event::nt_create_event)),
    (services::NtCreateFile, Handler::Status(file::nt_create_file)),
    (services::NtCreateKey, Handler::Status(registry::nt_create_key)),
    (services::NtCreateMutant, Handler::Status(mutant::nt_create_mutant)),
    (services::NtCreateNamedPipeFile, Handler::Status(pipe::nt_create_named_pipe_file)),
    (services::NtCreateKeyedEvent, Handler::Status(event::nt_create_keyed_event)),
    (services::NtCreatePort, Handler::Status(port::nt_create_port)),
    (services::NtCreateProcess, Handler::Status(process::nt_create_process)),
    (services::NtCreateProcessEx, Handler::Status(process::nt_create_process_ex)),
    (services::NtCreateSection, Handler::Status(section::nt_create_section)),
    (services::NtCreateSemaphore, Handler::Status(event::nt_create_semaphore)),
    (services::NtCreateSymbolicLinkObject, Handler::Status(object::nt_create_symbolic_link_object)),
    (services::NtCreateThread, Handler::Status(process::nt_create_thread)),
    (services::NtDelayExecution, Handler::Status(wait::nt_delay_execution)),
    (services::NtDeleteAtom, Handler::Status(atom::nt_delete_atom)),
    (services::NtDeleteValueKey, Handler::Status(registry::nt_delete_value_key)),
    (services::NtDeviceIoControlFile, Handler::Status(file::nt_device_io_control_file)),
    (services::NtDuplicateObject, Handler::Status(object::nt_duplicate_object)),
    (services::NtEnumerateKey, Handler::Status(registry::nt_enumerate_key)),
    (services::NtEnumerateValueKey, Handler::Status(registry::nt_enumerate_value_key)),
    (services::NtFindAtom, Handler::Status(atom::nt_find_atom)),
    (services::NtFlushBuffersFile, Handler::Status(file::nt_flush_buffers_file)),
    (services::NtFlushInstructionCache, Handler::Status(process::nt_flush_instruction_cache)),
    (services::NtFlushKey, Handler::Status(registry::nt_flush_key)),
    (services::NtFreeVirtualMemory, Handler::Status(memory::nt_free_virtual_memory)),
    (services::NtFsControlFile, Handler::Status(pipe::nt_fs_control_file)),
    (services::NtGdiBitBlt, Handler::Status(gdi::nt_gdi_bit_blt)),
    (services::NtGdiCombineRgn, Handler::Status(gdi::nt_gdi_combine_rgn)),
    (services::NtGdiCreateBitmap, Handler::Status(gdi::nt_gdi_create_bitmap)),
    (services::NtGdiCreateCompatibleDC, Handler::Status(gdi::nt_gdi_create_compatible_dc)),
    (services::NtGdiCreateDIBSection, Handler::Status(gdi::nt_gdi_create_dib_section)),
    (services::NtGdiCreatePatternBrushInternal, Handler::Status(gdi::nt_gdi_create_pattern_brush_internal)),
    (services::NtGdiCreatePen, Handler::Status(gdi::nt_gdi_create_pen)),
    (services::NtGdiCreateRectRgn, Handler::Status(gdi::nt_gdi_create_rect_rgn)),
    (services::NtGdiCreateSolidBrush, Handler::Status(gdi::nt_gdi_create_solid_brush)),
    (services::NtGdiDeleteObjectApp, Handler::Status(gdi::nt_gdi_delete_object_app)),
    (services::NtGdiExtSelectClipRgn, Handler::Status(gdi::nt_gdi_ext_select_clip_rgn)),
    (services::NtGdiExtTextOutW, Handler::Status(gdi::nt_gdi_ext_text_out_w)),
    (services::NtGdiFlush, Handler::Status(gdi::nt_gdi_flush)),
    (services::NtGdiGetAppClipBox, Handler::Status(gdi::nt_gdi_get_app_clip_box)),
    (services::NtGdiGetDCObject, Handler::Status(gdi::nt_gdi_get_dc_object)),
    (services::NtGdiGetFontFamilyInfo, Handler::Status(gdi::nt_gdi_get_font_family_info)),
    (services::NtGdiGetRandomRgn, Handler::Status(gdi::nt_gdi_get_random_rgn)),
    (services::NtGdiGetRgnBox, Handler::Status(gdi::nt_gdi_get_rgn_box)),
    (services::NtGdiGetStockObject, Handler::Status(gdi::nt_gdi_get_stock_object)),
    (services::NtGdiGetTextExtent, Handler::Status(gdi::nt_gdi_get_text_extent)),
    (services::NtGdiGetTextExtentExW, Handler::Status(gdi::nt_gdi_get_text_extent_ex_w)),
    (services::NtGdiGetTextMetricsW, Handler::Status(gdi::nt_gdi_get_text_metrics_w)),
    (services::NtGdiHfontCreate, Handler::Status(gdi::nt_gdi_hfont_create)),
    (services::NtGdiInit, Handler::Status(user::nt_gdi_init)),
    (services::NtGdiIntersectClipRect, Handler::Status(gdi::nt_gdi_intersect_clip_rect)),
    (services::NtGdiLineTo, Handler::Status(gdi::nt_gdi_line_to)),
    (services::NtGdiMoveTo, Handler::Status(gdi::nt_gdi_move_to)),
    (services::NtGdiOpenDCW, Handler::Status(gdi::nt_gdi_open_dc_w)),
    (services::NtGdiPatBlt, Handler::Status(gdi::nt_gdi_pat_blt)),
    (services::NtGdiRectVisible, Handler::Status(gdi::nt_gdi_rect_visible)),
    (services::NtGdiRectangle, Handler::Status(gdi::nt_gdi_rectangle)),
    (services::NtGdiSelectBitmap, Handler::Status(gdi::nt_gdi_select_bitmap)),
    (services::NtGdiSelectFont, Handler::Status(gdi::nt_gdi_select_font)),
    (services::NtGdiSelectPen, Handler::Status(gdi::nt_gdi_select_pen)),
    (services::NtGdiTransformPoints, Handler::Status(gdi::nt_gdi_transform_points)),
    (services::NtImpersonateThread, Handler::Status(security::nt_impersonate_thread)),
    (services::NtInitializeRegistry, Handler::Status(registry::nt_initialize_registry)),
    (services::NtListenPort, Handler::Status(port::nt_listen_port)),
    (services::NtMapViewOfSection, Handler::Status(section::nt_map_view_of_section)),
    (services::NtOpenDirectoryObject, Handler::Status(object::nt_open_directory_object)),
    (services::NtOpenEvent, Handler::Status(event::nt_open_event)),
    (services::NtOpenFile, Handler::Status(file::nt_open_file)),
    (services::NtOpenKey, Handler::Status(registry::nt_open_key)),
    (services::NtOpenMutant, Handler::Status(mutant::nt_open_mutant)),
    (services::NtOpenKeyedEvent, Handler::Status(event::nt_open_keyed_event)),
    (services::NtOpenProcess, Handler::Status(process::nt_open_process)),
    (services::NtOpenProcessToken, Handler::Status(security::nt_open_process_token)),
    (services::NtOpenProcessTokenEx, Handler::Status(security::nt_open_process_token_ex)),
    (services::NtOpenSection, Handler::Status(section::nt_open_section)),
    (services::NtOpenSemaphore, Handler::Status(event::nt_open_semaphore)),
    (services::NtOpenSymbolicLinkObject, Handler::Status(object::nt_open_symbolic_link_object)),
    (services::NtOpenThread, Handler::Status(process::nt_open_thread)),
    (services::NtOpenThreadToken, Handler::Status(security::nt_open_thread_token)),
    (services::NtOpenThreadTokenEx, Handler::Status(security::nt_open_thread_token_ex)),
    (services::NtProtectVirtualMemory, Handler::Status(memory::nt_protect_virtual_memory)),
    (services::NtPulseEvent, Handler::Status(event::nt_pulse_event)),
    (services::NtQueryAttributesFile, Handler::Status(file::nt_query_attributes_file)),
    (services::NtQueryDebugFilterState, Handler::Status(gates::nt_query_debug_filter_state)),
    (services::NtQueryDefaultLocale, Handler::Status(locale::nt_query_default_locale)),
    (services::NtQueryDirectoryFile, Handler::Status(file::nt_query_directory_file)),
    (services::NtQueryEvent, Handler::Status(event::nt_query_event)),
    (services::NtQueryFullAttributesFile, Handler::Status(file::nt_query_full_attributes_file)),
    (services::NtQueryInformationAtom, Handler::Status(atom::nt_query_information_atom)),
    (services::NtQueryInformationFile, Handler::Status(file::nt_query_information_file)),
    (services::NtQueryInformationProcess, Handler::Status(process::nt_query_information_process)),
    (services::NtQueryInformationThread, Handler::Status(process::nt_query_information_thread)),
    (services::NtQueryInformationToken, Handler::Status(security::nt_query_information_token)),
    (services::NtQueryKey, Handler::Status(registry::nt_query_key)),
    (services::NtQueryObject, Handler::Status(object::nt_query_object)),
    (services::NtQueryPerformanceCounter, Handler::Status(time::nt_query_performance_counter)),
    (services::NtQuerySection, Handler::Status(section::nt_query_section)),
    (services::NtQuerySecurityObject, Handler::Status(security::nt_query_security_object)),
    (services::NtQuerySemaphore, Handler::Status(event::nt_query_semaphore)),
    (services::NtQuerySymbolicLinkObject, Handler::Status(object::nt_query_symbolic_link_object)),
    (services::NtQuerySystemInformation, Handler::Status(system::nt_query_system_information)),
    (services::NtQuerySystemTime, Handler::Status(time::nt_query_system_time)),
    (services::NtQueryValueKey, Handler::Status(registry::nt_query_value_key)),
    (services::NtQueryVirtualMemory, Handler::Status(memory::nt_query_virtual_memory)),
    (services::NtQueryVolumeInformationFile, Handler::Status(file::nt_query_volume_information_file)),
    (services::NtQueueApcThread, Handler::Status(apc::nt_queue_apc_thread)),
    (services::NtRaiseException, Handler::Frame(exceptions::nt_raise_exception)),
    (services::NtReadFile, Handler::Status(file::nt_read_file)),
    (services::NtReadVirtualMemory, Handler::Status(memory::nt_read_virtual_memory)),
    (services::NtRegisterThreadTerminatePort, Handler::Status(process::nt_register_thread_terminate_port)),
    (services::NtReleaseKeyedEvent, Handler::Status(event::nt_release_keyed_event)),
    (services::NtReleaseMutant, Handler::Status(mutant::nt_release_mutant)),
    (services::NtReleaseSemaphore, Handler::Status(event::nt_release_semaphore)),
    (services::NtReplyPort, Handler::Status(port::nt_reply_port)),
    (services::NtReplyWaitReceivePort, Handler::Status(port::nt_reply_wait_receive_port)),
    (services::NtReplyWaitReceivePortEx, Handler::Status(port::nt_reply_wait_receive_port_ex)),
    (services::NtRequestPort, Handler::Status(port::nt_request_port)),
    (services::NtRequestWaitReplyPort, Handler::Status(port::nt_request_wait_reply_port)),
    (services::NtResetEvent, Handler::Status(event::nt_reset_event)),
    (services::NtResumeThread, Handler::Status(process::nt_resume_thread)),
    (services::NtSecureConnectPort, Handler::Status(port::nt_secure_connect_port)),
    (services::NtSetDefaultHardErrorPort, Handler::Status(port::nt_set_default_hard_error_port)),
    (services::NtSetDefaultLocale, Handler::Status(locale::nt_set_default_locale)),
    (services::NtSetEvent, Handler::Status(event::nt_set_event)),
    (services::NtSetInformationFile, Handler::Status(file::nt_set_information_file)),
    (services::NtSetInformationObject, Handler::Status(object::nt_set_information_object)),
    (services::NtSetInformationProcess, Handler::Status(process::nt_set_information_process)),
    (services::NtSetInformationThread, Handler::Status(process::nt_set_information_thread)),
    (services::NtSetSecurityObject, Handler::Status(security::nt_set_security_object)),
    (services::NtSetSystemInformation, Handler::Status(system::nt_set_system_information)),
    (services::NtSetValueKey, Handler::Status(registry::nt_set_value_key)),
    (services::NtShutdownSystem, Handler::Status(system::nt_shutdown_system)),
    (services::NtSuspendThread, Handler::Status(process::nt_suspend_thread)),
    (services::NtTerminateProcess, Handler::Status(process::nt_terminate_process)),
    (services::NtTerminateThread, Handler::Status(process::nt_terminate_thread)),
    (services::NtTestAlert, Handler::Status(apc::nt_test_alert)),
    (services::NtUnmapViewOfSection, Handler::Status(section::nt_unmap_view_of_section)),
    (services::NtUserBeginPaint, Handler::Status(window::nt_user_begin_paint)),
    (services::NtUserBuildHwndList, Handler::Status(desktop::nt_user_build_hwnd_list)),
    (services::NtUserCallHwndLock, Handler::Status(window::nt_user_call_hwnd_lock)),
    (services::NtUserCallHwndParam, Handler::Status(timer::nt_user_call_hwnd_param)),
    (services::NtUserCallHwndParamLock, Handler::Status(window::nt_user_call_hwnd_param_lock)),
    (services::NtUserCallNoParam, Handler::Status(mouse::nt_user_call_no_param)),
    (services::NtUserCallOneParam, Handler::Status(message::nt_user_call_one_param)),
    (services::NtUserCallTwoParam, Handler::Status(user::nt_user_call_two_param)),
    (services::NtUserCloseDesktop, Handler::Status(desktop::nt_user_close_desktop)),
    (services::NtUserCloseWindowStation, Handler::Status(winsta::nt_user_close_window_station)),
    (services::NtUserConsoleControl, Handler::Status(console::nt_user_console_control)),
    (services::NtUserCreateDesktop, Handler::Status(desktop::nt_user_create_desktop)),
    (services::NtUserCreateWindowEx, Handler::Status(window::nt_user_create_window_ex)),
    (services::NtUserCreateWindowStation, Handler::Status(winsta::nt_user_create_window_station)),
    (services::NtUserDefSetText, Handler::Status(window::nt_user_def_set_text)),
    (services::NtUserDispatchMessage, Handler::Status(message::nt_user_dispatch_message)),
    (services::NtUserEndPaint, Handler::Status(window::nt_user_end_paint)),
    (services::NtUserEnumDisplaySettings, Handler::Status(user::nt_user_enum_display_settings)),
    (services::NtUserGetAsyncKeyState, Handler::Status(input::nt_user_get_async_key_state)),
    (services::NtUserGetClassInfo, Handler::Status(class::nt_user_get_class_info)),
    (services::NtUserGetControlBrush, Handler::Status(window::nt_user_get_control_brush)),
    (services::NtUserGetControlColor, Handler::Status(window::nt_user_get_control_color)),
    (services::NtUserGetDC, Handler::Status(window::nt_user_get_dc)),
    (services::NtUserGetDCEx, Handler::Status(window::nt_user_get_dc_ex)),
    (services::NtUserGetKeyState, Handler::Status(input::nt_user_get_key_state)),
    (services::NtUserGetAtomName, Handler::Status(atom::nt_user_get_atom_name)),
    (services::NtUserGetGuiResources, Handler::Status(user::nt_user_get_gui_resources)),
    (services::NtUserGetKeyboardLayoutList, Handler::Status(user::nt_user_get_keyboard_layout_list)),
    (services::NtUserGetKeyboardState, Handler::Status(input::nt_user_get_keyboard_state)),
    (services::NtUserGetMessage, Handler::Status(message::nt_user_get_message)),
    (services::NtUserGetMonitorInfo, Handler::Status(monitor::nt_user_get_monitor_info)),
    (services::NtUserGetProcessWindowStation, Handler::Status(winsta::nt_user_get_process_window_station)),
    (services::NtUserGetThreadState, Handler::Status(mouse::nt_user_get_thread_state)),
    (services::NtUserGetUpdateRect, Handler::Status(window::nt_user_get_update_rect)),
    (services::NtUserGetUpdateRgn, Handler::Status(window::nt_user_get_update_rgn)),
    (services::NtUserGetWindowDC, Handler::Status(window::nt_user_get_window_dc)),
    (services::NtUserInitialize, Handler::Status(user::nt_user_initialize)),
    (services::NtUserInitializeClientPfnArrays, Handler::Status(user::nt_user_initialize_client_pfn_arrays)),
    (services::NtUserInvalidateRect, Handler::Status(window::nt_user_invalidate_rect)),
    (services::NtUserInternalGetWindowText, Handler::Status(window::nt_user_internal_get_window_text)),
    (services::NtUserInvalidateRgn, Handler::Status(window::nt_user_invalidate_rgn)),
    (services::NtUserKillTimer, Handler::Status(timer::nt_user_kill_timer)),
    (services::NtUserLoadKeyboardLayoutEx, Handler::Status(user::nt_user_load_keyboard_layout_ex)),
    (services::NtUserMessageCall, Handler::Status(message::nt_user_message_call)),
    (services::NtUserMonitorFromPoint, Handler::Status(monitor::nt_user_monitor_from_point)),
    (services::NtUserMonitorFromRect, Handler::Status(monitor::nt_user_monitor_from_rect)),
    (services::NtUserMonitorFromWindow, Handler::Status(monitor::nt_user_monitor_from_window)),
    (services::NtUserMoveWindow, Handler::Status(window::nt_user_move_window)),
    (services::NtUserOpenDesktop, Handler::Status(desktop::nt_user_open_desktop)),
    (services::NtUserOpenWindowStation, Handler::Status(winsta::nt_user_open_window_station)),
    (services::NtUserPeekMessage, Handler::Status(message::nt_user_peek_message)),
    (services::NtUserPostMessage, Handler::Status(message::nt_user_post_message)),
    (services::NtUserPostThreadMessage, Handler::Status(message::nt_user_post_thread_message)),
    (services::NtUserProcessConnect, Handler::Status(user::nt_user_process_connect)),
    (services::NtUserRedrawWindow, Handler::Status(window::nt_user_redraw_window)),
    (services::NtUserRegisterClassExWOW, Handler::Status(class::nt_user_register_class_ex_wow)),
    (services::NtUserResolveDesktop, Handler::Status(console::nt_user_resolve_desktop)),
    (services::NtUserSetCapture, Handler::Status(mouse::nt_user_set_capture)),
    (services::NtUserSetFocus, Handler::Status(input::nt_user_set_focus)),
    (services::NtUserSetLogonNotifyWindow, Handler::Status(window::nt_user_set_logon_notify_window)),
    (services::NtUserSetInformationThread, Handler::Status(user::nt_user_set_information_thread)),
    (services::NtUserSetProcessWindowStation, Handler::Status(winsta::nt_user_set_process_window_station)),
    (services::NtUserSetProp, Handler::Status(user::nt_user_set_prop)),
    (services::NtUserSetSystemTimer, Handler::Status(timer::nt_user_set_system_timer)),
    (services::NtUserSetThreadDesktop, Handler::Status(desktop::nt_user_set_thread_desktop)),
    (services::NtUserSetTimer, Handler::Status(timer::nt_user_set_timer)),
    (services::NtUserSetWindowFNID, Handler::Status(user::nt_user_set_window_fnid)),
    (services::NtUserSetWindowLong, Handler::Status(window::nt_user_set_window_long)),
    (services::NtUserSetWindowPos, Handler::Status(window::nt_user_set_window_pos)),
    (services::NtUserSetWindowStationUser, Handler::Status(winsta::nt_user_set_window_station_user)),
    (services::NtUserShowWindow, Handler::Status(window::nt_user_show_window)),
    (services::NtUserShowWindowAsync, Handler::Status(window::nt_user_show_window_async)),
    (services::NtUserSwitchDesktop, Handler::Status(desktop::nt_user_switch_desktop)),
    (services::NtUserSystemParametersInfo, Handler::Status(user::nt_user_system_parameters_info)),
    (services::NtUserToUnicodeEx, Handler::Status(input::nt_user_to_unicode_ex)),
    (services::NtUserTranslateMessage, Handler::Status(input::nt_user_translate_message)),
    (services::NtUserValidateRect, Handler::Status(window::nt_user_validate_rect)),
    (services::NtUserValidateTimerCallback, Handler::Status(timer::nt_user_validate_timer_callback)),
    (services::NtUserWaitMessage, Handler::Status(message::nt_user_wait_message)),
    (services::NtWaitForKeyedEvent, Handler::Status(event::nt_wait_for_keyed_event)),
    (services::NtWaitForMultipleObjects, Handler::Status(wait::nt_wait_for_multiple_objects)),
    (services::NtWaitForSingleObject, Handler::Status(wait::nt_wait_for_single_object)),
    (services::NtWriteFile, Handler::Status(file::nt_write_file)),
    (services::NtWriteVirtualMemory, Handler::Status(memory::nt_write_virtual_memory)),
];

/// Au plus 63 arguments par service (`tools/syscall-gen`).
const MAX_ARGUMENTS: usize = 63;

/// Le handler de chaque service de ntoskrnl, par numéro.
static HANDLERS: [Option<Handler>; NTOSKRNL.len()] = handlers(0);
/// Le handler de chaque service de win32k, par numéro moins `0x1000`.
static WIN32K_HANDLERS: [Option<Handler>; WIN32K.len()] = handlers(WIN32K_BASE);

/// La table des handlers des services de [`IMPLEMENTED`] dont le numéro est
/// `base` plus leur indice.
const fn handlers<const N: usize>(base: u32) -> [Option<Handler>; N] {
    let mut table: [Option<Handler>; N] = [None; N];
    let mut i = 0;
    while i < IMPLEMENTED.len() {
        let (number, handler) = IMPLEMENTED[i];
        let index = (number & abi::service::INDEX_MASK) as usize;
        assert!(number >> abi::service::TABLE_SHIFT <= 1, "an implemented service outside the tables");
        if number & !abi::service::INDEX_MASK == base {
            assert!(index < N, "an implemented service outside its table");
            assert!(table[index].is_none(), "a service implemented twice");
            table[index] = Some(handler);
        }
        i += 1;
    }
    table
}

/// Le handler du service d'indice `index` de `table`.
fn handler(table: Table, index: usize) -> Option<Handler> {
    match table {
        Table::Ntoskrnl => HANDLERS.get(index).copied().flatten(),
        Table::Win32k => WIN32K_HANDLERS.get(index).copied().flatten(),
    }
}

/// Le service `number` a un handler.
pub fn is_implemented(number: u32) -> bool {
    lookup(number).is_some_and(|(table, _)| handler(table, (number & abi::service::INDEX_MASK) as usize).is_some())
}

/// Les services sans handler déjà appelés : un bit par service, ntoskrnl
/// puis win32k.
static REPORTED: [AtomicU32; (NTOSKRNL.len() + WIN32K.len()).div_ceil(32)] =
    [const { AtomicU32::new(0) }; (NTOSKRNL.len() + WIN32K.len()).div_ceil(32)];

/// Autant de services, ntoskrnl puis win32k.
const SERVICES: usize = NTOSKRNL.len() + WIN32K.len();

/// Les appels de chaque service, ntoskrnl puis win32k.
static CALLS: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
/// Ce qu'a rendu son premier appel : un statut, [`NEW_CONTEXT`] ou
/// [`NOT_RETURNED`].
static FIRST_COMPLETION: [AtomicU64; SERVICES] = [const { AtomicU64::new(0) }; SERVICES];
/// Dans `FIRST_COMPLETION`, hors des statuts : un nouveau contexte.
const NEW_CONTEXT: u64 = 1 << 32;
/// Dans `FIRST_COMPLETION`, hors des statuts : le premier appel n'est pas
/// revenu (encore en cours, ou le thread s'est terminé dedans).
const NOT_RETURNED: u64 = 2 << 32;
/// Les services, dans l'ordre de leur premier appel : les `FIRST_COUNT`
/// premières entrées.
static FIRST_CALLS: [AtomicU16; SERVICES] = [const { AtomicU16::new(0) }; SERVICES];
static FIRST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Un service appelé : son nom, son numéro, ses appels et ce qu'a rendu le
/// premier ; `None` s'il n'est pas revenu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceCalls {
    pub name: &'static str,
    pub number: u32,
    pub calls: u32,
    pub first: Option<Completion>,
}

/// Remet à zéro les compteurs de [`service_calls`].
///
/// # IRQL
/// <= DISPATCH_LEVEL, quand aucun thread de Ps n'appelle de service.
pub fn reset_service_calls() {
    for calls in &CALLS {
        calls.store(0, Ordering::Relaxed);
    }
    FIRST_COUNT.store(0, Ordering::Release);
}

/// Les services appelés depuis [`reset_service_calls`], dans l'ordre de leur
/// premier appel.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn service_calls() -> Vec<ServiceCalls> {
    let count = FIRST_COUNT.load(Ordering::Acquire).min(SERVICES);
    FIRST_CALLS[..count]
        .iter()
        .map(|slot| {
            let bit = usize::from(slot.load(Ordering::Relaxed));
            let number = if bit < NTOSKRNL.len() { bit as u32 } else { WIN32K_BASE | (bit - NTOSKRNL.len()) as u32 };
            let name = lookup(number).map_or("?", |(_, service)| service.name);
            let first = match FIRST_COMPLETION[bit].load(Ordering::Relaxed) {
                NOT_RETURNED => None,
                NEW_CONTEXT => Some(Completion::Frame),
                status => Some(Completion::Status(NtStatus(status as u32))),
            };
            ServiceCalls { name, number, calls: CALLS[bit].load(Ordering::Relaxed), first }
        })
        .collect()
}

/// Le premier numéro de la table de win32k.
const WIN32K_BASE: u32 = 1 << abi::service::TABLE_SHIFT;

/// Compte un appel du service d'indice `bit` ; `true` pour le premier.
fn count_call(bit: usize) -> bool {
    if CALLS[bit].fetch_add(1, Ordering::Relaxed) != 0 {
        return false;
    }
    FIRST_COMPLETION[bit].store(NOT_RETURNED, Ordering::Relaxed);
    let at = FIRST_COUNT.fetch_add(1, Ordering::AcqRel);
    if let Some(slot) = FIRST_CALLS.get(at) {
        slot.store(bit as u16, Ordering::Relaxed);
    }
    true
}

/// Note ce qu'a rendu le premier appel du service d'indice `bit`.
fn note_first(bit: usize, completion: Completion) {
    let value = match completion {
        Completion::Status(status) => u64::from(status.0),
        Completion::Frame => NEW_CONTEXT,
    };
    FIRST_COMPLETION[bit].store(value, Ordering::Relaxed);
}

/// KiSystemService : le service `number`, avec ses arguments copiés depuis
/// l'adresse utilisateur `arguments` ; `frame` est la trame de trap du
/// thread.
///
/// # IRQL
/// PASSIVE_LEVEL, interruptions actives, dans un thread de Ps.
pub fn dispatch(number: u32, arguments: u32, frame: &mut KTrapFrame) -> Completion {
    let Some((table, service)) = lookup(number) else {
        return Completion::Status(STATUS_INVALID_SYSTEM_SERVICE);
    };
    let count = service.argument_bytes as usize / 4;
    let mut bytes = [0u8; MAX_ARGUMENTS * 4];
    if let Err(status) = ke::usermem::copy_from_user(&mut bytes[..count * 4], u64::from(arguments)) {
        return Completion::Status(status);
    }
    let mut words = [0u32; MAX_ARGUMENTS];
    for (word, chunk) in words.iter_mut().zip(bytes[..count * 4].chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let index = (number & abi::service::INDEX_MASK) as usize;
    let bit = if table == Table::Ntoskrnl { index } else { NTOSKRNL.len() + index };
    let first = count_call(bit);
    let words = &words[..count];
    // A first call to win32k makes a GUI thread (PsConvertToGuiThread);
    // GDI calls batched in the TEB run before any call to win32k
    // (KeGdiFlushUserBatch).
    let converted = match table {
        Table::Win32k => win32k::convert_current_thread().map(|_| win32k::gdi::batch::flush()),
        Table::Ntoskrnl => Ok(()),
    };
    let completion = match (converted, handler(table, index)) {
        (Err(status), _) => Completion::Status(status),
        (Ok(()), Some(Handler::Status(handler))) => Completion::Status(handler(words)),
        (Ok(()), Some(Handler::Frame(handler))) => {
            handler(words, frame).map_or_else(Completion::Status, |()| Completion::Frame)
        }
        (Ok(()), None) => {
            let mask = 1 << (bit % 32);
            if REPORTED[bit / 32].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
                // In both ABIs, the return address into the caller of the
                // `Zw` stub sits just under the arguments.
                let caller = arguments.checked_sub(4).and_then(|at| ke::usermem::UserPtr::<u32>::new(at).read().ok());
                log::warn!(
                    "sys: {} ({number:#06x}) is not implemented; called from {:#x?} with {:x?}{}",
                    service.name,
                    caller.unwrap_or(0),
                    words,
                    if service.returns_status { "" } else { "; 0 returned" }
                );
            }
            not_implemented(service)
        }
    };
    if first {
        note_first(bit, completion);
    }
    completion
}

/// Ce que rend un service sans handler : `STATUS_NOT_IMPLEMENTED` s'il rend
/// un `NTSTATUS` ; sinon 0, son échec (FALSE, NULL, un compte nul), et
/// `ERROR_CALL_NOT_IMPLEMENTED` comme dernière erreur du thread.
fn not_implemented(service: &Service) -> Completion {
    if service.returns_status {
        return Completion::Status(STATUS_NOT_IMPLEMENTED);
    }
    // A TEB that cannot be written: the caller's GetLastError is stale.
    let _ = win32k::set_last_error(abi::winerror::ERROR_CALL_NOT_IMPLEMENTED);
    Completion::Status(NtStatus(0))
}

/// Les classes d'information d'un service demandées sans être
/// implémentées : chacune est journalisée à son premier appel.
pub(super) struct ClassReport {
    service: &'static str,
    /// Un bit par classe ; la dernière vaut pour toutes celles au-delà.
    seen: [AtomicU32; 4],
}

impl ClassReport {
    pub(super) const fn new(service: &'static str) -> Self {
        Self { service, seen: [const { AtomicU32::new(0) }; 4] }
    }

    /// La classe `class` n'est pas implémentée : journalisée la première
    /// fois ; rend `STATUS_NOT_IMPLEMENTED`.
    pub(super) fn report(&self, class: u32) -> NtStatus {
        let bit = class.min(127) as usize;
        let mask = 1 << (bit % 32);
        if self.seen[bit / 32].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
            log::warn!("sys: {} class {class:#x} is not implemented", self.service);
        }
        STATUS_NOT_IMPLEMENTED
    }
}

/// Rend l'information `information`, d'une taille fixe, dans le tampon
/// utilisateur de `length` octets en `buffer`, et sa taille en
/// `return_length` s'il n'est pas nul. `STATUS_INFO_LENGTH_MISMATCH` si
/// `length` n'est pas sa taille, la taille étant rendue quand même ;
/// `STATUS_DATATYPE_MISALIGNMENT` pour un tampon qui n'est pas aligné sur 4
/// octets ; `STATUS_ACCESS_VIOLATION` si l'écriture faute.
fn return_information(information: &[u8], buffer: u32, length: u32, return_length: u32) -> NtStatus {
    return_aligned_information(information, buffer, length, return_length, 4)
}

/// [`return_information`], pour les listes dont le tampon du appelant peut
/// dépasser les données : `STATUS_SUCCESS` dès qu'il les tient (seules les
/// données se copient), `STATUS_INFO_LENGTH_MISMATCH` quand il est trop
/// petit, la taille nécessaire rendue quand même.
fn return_information_flexible(information: &[u8], buffer: u32, length: u32, return_length: u32) -> NtStatus {
    let size = information.len() as u32;
    let status = if length < size {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        match ke::usermem::probe_for_write(u64::from(buffer), information.len(), 4)
            .and_then(|()| ke::usermem::copy_to_user(u64::from(buffer), information))
        {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => return status,
        }
    };
    if return_length != 0 {
        if let Err(fault) = ke::usermem::UserPtr::<u32>::new(return_length).write(&size) {
            return fault;
        }
    }
    status
}

/// [`return_information`], pour un tampon aligné sur `alignment` octets.
fn return_aligned_information(
    information: &[u8],
    buffer: u32,
    length: u32,
    return_length: u32,
    alignment: usize,
) -> NtStatus {
    let size = information.len() as u32;
    let status = if length != size {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        match ke::usermem::probe_for_write(u64::from(buffer), information.len(), alignment)
            .and_then(|()| ke::usermem::copy_to_user(u64::from(buffer), information))
        {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => return status,
        }
    };
    if return_length != 0 {
        if let Err(fault) = ke::usermem::UserPtr::<u32>::new(return_length).write(&size) {
            return fault;
        }
    }
    status
}

/// Le processus du thread courant, un thread de Ps.
fn current_process() -> Arc<Object<EProcess>> {
    ps::ethread::current_thread().expect("a system service outside a Ps thread").process().clone()
}

/// Le processus que désigne `handle` dans le processus courant, avec les
/// droits `access` ; `NtCurrentProcess()` désigne le processus courant.
fn reference_process(handle: u32, access: AccessMask) -> Result<Arc<Object<EProcess>>, NtStatus> {
    let current = current_process();
    if handle == NT_CURRENT_PROCESS {
        return Ok(current);
    }
    current.handle_table.reference_as::<EProcess>(Handle(handle), &PROCESS_TYPE, access)
}

/// Le thread que désigne `handle` dans le processus courant, avec les droits
/// `access` ; `NtCurrentThread()` désigne le thread courant.
fn reference_thread(handle: u32, access: AccessMask) -> Result<Arc<Object<EThread>>, NtStatus> {
    if handle == NT_CURRENT_THREAD {
        return Ok(ps::ethread::current_thread().expect("a system service outside a Ps thread"));
    }
    current_process().handle_table.reference_as::<EThread>(Handle(handle), &THREAD_TYPE, access)
}
