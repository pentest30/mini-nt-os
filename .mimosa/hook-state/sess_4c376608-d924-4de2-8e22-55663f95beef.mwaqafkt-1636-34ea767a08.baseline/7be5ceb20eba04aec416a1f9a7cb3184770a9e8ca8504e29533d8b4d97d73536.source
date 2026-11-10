//! Les services de win32k (la seconde table) : NtUserProcessConnect,
//! NtUserInitializeClientPfnArrays, NtUserInitialize, NtGdiInit,
//! NtUserCallTwoParam (RegisterLogonProcess), NtUserSetInformationThread
//! (le port d'API de `csrss`), NtUserLoadKeyboardLayoutEx,
//! NtUserGetKeyboardLayoutList, NtUserSystemParametersInfo.
//!
//! Le thread qui les appelle est déjà un thread GUI (`super::dispatch`).

use abi::ntstatus::{NtStatus, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use abi::user::{TWOPARAM_ROUTINE_REGISTERLOGONPROCESS, USER_THREAD_CSR_API_PORT};
use abi::winerror::ERROR_CALL_NOT_IMPLEMENTED;
use ex::{Event, EVENT_ALL_ACCESS, EVENT_TYPE};
use ke::usermem::UserPtr;
use lpc::port::PORT_TYPE;
use ob::{AccessMask, Handle};
use ps::eprocess::PROCESS_VM_OPERATION;
use ps::ethread::THREAD_SET_INFORMATION;

/// Les routines de NtUserCallTwoParam demandées sans être implémentées.
static UNSUPPORTED_TWO_PARAM_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallTwoParam");
/// Les classes de NtUserSetInformationThread demandées sans être
/// implémentées.
static UNSUPPORTED_USER_THREAD_CLASSES: super::ClassReport = super::ClassReport::new("NtUserSetInformationThread");

/// NtUserProcessConnect(ProcessHandle, UserConnect, Size) : le processus
/// (`PROCESS_VM_OPERATION`) devient un processus GUI, et le `USERCONNECT` de
/// l'appelant reçoit ce qu'il partage avec USER (`win32k::process_connect`) :
/// le `SERVERINFO`, la table des handles, l'écart vers sa vue de la section
/// partagée. `STATUS_UNSUCCESSFUL` pour un tampon nul ou d'une autre taille
/// que 0x124 octets, avant le handle.
pub(super) fn nt_user_process_connect(arguments: &[u32]) -> NtStatus {
    let (handle, buffer, size) = (arguments[0], arguments[1], arguments[2]);
    let connect = || {
        win32k::check_connect_buffer(buffer, size)?;
        let process = super::reference_process(handle, PROCESS_VM_OPERATION)?;
        win32k::process_connect(&process, buffer)
    };
    connect().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtUserInitializeClientPfnArrays(pfnClientA, pfnClientW, pfnClientWorker,
/// hmodUser) : au premier appel, les procédures de fenêtre de `user32` vont
/// dans le `SERVERINFO` partagé (`win32k::client`).
pub(super) fn nt_user_initialize_client_pfn_arrays(arguments: &[u32]) -> NtStatus {
    win32k::client::initialize_client_pfn_arrays(arguments[0], arguments[1], arguments[2], arguments[3])
        .map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtUserInitialize(dwWinVersion, hPowerRequestEvent, hMediaRequestEvent),
/// dans `csrss` : USER démarre (`win32k::csrss::initialize`) avec
/// l'événement des demandes d'alimentation (`EVENT_ALL_ACCESS`) ; celui des
/// changements de média n'est pas gardé (ReactOS non plus).
pub(super) fn nt_user_initialize(arguments: &[u32]) -> NtStatus {
    let (version, power_event) = (arguments[0], arguments[1]);
    let reference = || {
        super::current_process().handle_table.reference_as::<Event>(Handle(power_event), &EVENT_TYPE, EVENT_ALL_ACCESS)
    };
    win32k::csrss::initialize(version, reference).map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// Les actions de NtUserSystemParametersInfo demandées sans être
/// implémentées.
static UNSUPPORTED_SPI_ACTIONS: super::ClassReport = super::ClassReport::new("NtUserSystemParametersInfo");

/// Écrit en `pv` les `bytes` d'une structure que l'appelant dit faire `size`
/// octets (`uiParam`, 0 : pas dit) et dont il a rempli le `cbSize`
/// (`with_cb_size`) ; FALSE et `ERROR_INVALID_PARAMETER` sinon.
fn give_parameter(pv: u32, size: u32, bytes: &[u8], with_cb_size: bool) -> NtStatus {
    let fail = || {
        let _ = win32k::set_last_error(abi::winerror::ERROR_INVALID_PARAMETER);
        NtStatus(0)
    };
    let length = bytes.len() as u32;
    if size != 0 && size != length {
        return fail();
    }
    if with_cb_size {
        let mut cb_size = [0u8; 4];
        if ke::usermem::copy_from_user(&mut cb_size, u64::from(pv)).is_err() || u32::from_le_bytes(cb_size) != length {
            return fail();
        }
    }
    NtStatus(u32::from(ke::usermem::copy_to_user(u64::from(pv), bytes).is_ok()))
}

/// NtUserSystemParametersInfo(uiAction, uiParam, pvParam, fWinIni) : BOOL
/// (UserSystemParametersInfo).
/// - SPI_GETNONCLIENTMETRICS : les tailles du cadre et les polices du système
///   (`win32k::metrics::non_client_metrics`) ; le `cbSize` lu en `pvParam`
///   doit être la taille de NONCLIENTMETRICSW ;
/// - SPI_GETICONTITLELOGFONT : la police des titres d'icônes, Tahoma de 8
///   points, la police par défaut d'une ListView ;
/// - SPI_GETFOCUSBORDERWIDTH, SPI_GETFOCUSBORDERHEIGHT : l'épaisseur d'un
///   rectangle de focus (un UINT en `pvParam`, `uiParam` ignoré), que
///   DrawFocusRect lit avant ses quatre PatBlt.
///
/// FALSE et `ERROR_INVALID_PARAMETER` pour une taille fausse. Une autre
/// action est journalisée une fois et rend FALSE
/// (`ERROR_CALL_NOT_IMPLEMENTED`).
pub(super) fn nt_user_system_parameters_info(arguments: &[u32]) -> NtStatus {
    let [action, param, pv, _win_ini] = arguments[..4] else { unreachable!("4 arguments") };
    match action {
        abi::user::SPI_GETNONCLIENTMETRICS => {
            let metrics = win32k::metrics::non_client_metrics(&win32k::metrics::Parameters::DEFAULT);
            give_parameter(pv, param, metrics.as_bytes(), true)
        }
        abi::user::SPI_GETICONTITLELOGFONT => {
            give_parameter(pv, param, win32k::metrics::system_font(400).as_bytes(), false)
        }
        abi::user::SPI_GETFOCUSBORDERWIDTH | abi::user::SPI_GETFOCUSBORDERHEIGHT => {
            let parameters = &win32k::metrics::Parameters::DEFAULT;
            let value = if action == abi::user::SPI_GETFOCUSBORDERWIDTH {
                parameters.focus_border_width
            } else {
                parameters.focus_border_height
            };
            give_parameter(pv, 0, &value.to_le_bytes(), false)
        }
        _ => {
            UNSUPPORTED_SPI_ACTIONS.report(action);
            let _ = win32k::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
            NtStatus(0)
        }
    }
}

/// NtUserCallTwoParam(Param1, Param2, Routine) : la routine `Routine`,
/// qui rend une valeur. `TWOPARAM_ROUTINE_REGISTERLOGONPROCESS` : inscrit
/// le processus `Param1` comme processus de logon (`Param2` TRUE), ou le
/// désinscrit (`win32k::logon`). Une autre routine rend 0, avec
/// `ERROR_CALL_NOT_IMPLEMENTED` comme dernière erreur, journalisée une fois.
pub(super) fn nt_user_call_two_param(arguments: &[u32]) -> NtStatus {
    let (first, second, routine) = (arguments[0], arguments[1], arguments[2]);
    if routine == TWOPARAM_ROUTINE_REGISTERLOGONPROCESS {
        return NtStatus(u32::from(win32k::logon::register_logon_process(first, second != 0)));
    }
    UNSUPPORTED_TWO_PARAM_ROUTINES.report(routine);
    let _ = win32k::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    NtStatus(0)
}

/// NtUserSetInformationThread(ThreadHandle, ThreadInformationClass,
/// ThreadInformation, ThreadInformationLength), pour `csrss` seul
/// (`STATUS_ACCESS_DENIED` sinon), sur un thread ouvert avec
/// `THREAD_SET_INFORMATION`. `UserThreadCsrApiPort` : le handle d'un port
/// LPC (4 octets) devient le port d'API de `csrss` pour win32k
/// (`win32k::csrss::set_api_port`). Les autres classes rendent
/// `STATUS_NOT_IMPLEMENTED`, journalisées une fois.
pub(super) fn nt_user_set_information_thread(arguments: &[u32]) -> NtStatus {
    let [handle, class, information, length] = arguments[..4] else { unreachable!("4 arguments") };
    let set = || {
        let process = super::current_process();
        if process.pid() != win32k::csrss::csrss() {
            return Err(STATUS_ACCESS_DENIED);
        }
        super::reference_thread(handle, THREAD_SET_INFORMATION)?;
        if class != USER_THREAD_CSR_API_PORT {
            return Err(UNSUPPORTED_USER_THREAD_CLASSES.report(class));
        }
        if length != 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let port = UserPtr::<u32>::new(information).read()?;
        let port = process.handle_table.reference(Handle(port), Some(&PORT_TYPE), AccessMask(0))?;
        win32k::csrss::set_api_port(port);
        Ok(())
    };
    set().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// Les drapeaux qu'accepte NtUserLoadKeyboardLayoutEx.
const KLF_VALID: u32 = abi::user::KLF_ACTIVATE
    | abi::user::KLF_NOTELLSHELL
    | abi::user::KLF_REORDER
    | abi::user::KLF_REPLACELANG
    | abi::user::KLF_SUBSTITUTE_OK
    | abi::user::KLF_SETFORPROCESS
    | abi::user::KLF_UNLOADPREVIOUS
    | abi::user::KLF_RESET
    | abi::user::KLF_SHIFTLOCK;

/// La clé du registre des dispositions de clavier.
const KEYBOARD_LAYOUTS: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts";

/// Le fichier de la disposition `klid` (UserLoadKbdFile) : sa valeur
/// `Layout File` sous `Keyboard Layouts\<KLID>`, un nom de fichier de
/// `\SystemRoot\System32` (`STATUS_OBJECT_NAME_INVALID` s'il désigne
/// autre chose), lu en entier.
fn read_layout_file(klid: &str) -> Result<alloc::vec::Vec<u8>, NtStatus> {
    use abi::object::OBJ_CASE_INSENSITIVE;
    let path = alloc::format!("{KEYBOARD_LAYOUTS}\\{klid}");
    let key = ob::namespace().open(&path, None, Some(&cm::KEY_TYPE), OBJ_CASE_INSENSITIVE)?;
    let key = ob::downcast::<cm::Key>(&key).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH)?;
    let name: alloc::vec::Vec<u16> = "Layout File".encode_utf16().collect();
    let value = key.value(&name)?.ok_or(abi::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)?;
    let file = win32k::keyboard::layout_file_name(value.data_type, &value.data)?;
    let path = alloc::format!("\\SystemRoot\\System32\\{file}");
    let object = ob::namespace().open(&path, None, Some(&io_manager::FILE_TYPE), OBJ_CASE_INSENSITIVE)?;
    ob::downcast::<io_manager::File>(&object).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH)?.read_all()
}

/// NtUserLoadKeyboardLayoutEx(hFile, offTable, pTables, hOldKL, puszKLID,
/// dwNewKL, Flags) : la disposition `dwNewKL` du KLID (8 caractères au
/// plus), chargée si besoin depuis son fichier (`read_layout_file`), puis
/// activée selon les drapeaux (`win32k::keyboard::load`) ; rend son HKL.
/// NULL pour un HKL nul, sans station ou hors de la station interactive ;
/// `ERROR_INVALID_FLAGS` pour un drapeau inconnu. Le fichier donné
/// (`hFile`, que ReactOS vérifie puis ignore) et la disposition à décharger
/// (`hOldKL`) sont ignorés.
pub(super) fn nt_user_load_keyboard_layout_ex(arguments: &[u32]) -> NtStatus {
    let (klid, hkl, flags) = (arguments[4], arguments[5], arguments[6]);
    if flags & !KLF_VALID != 0 {
        let _ = win32k::set_last_error(abi::winerror::ERROR_INVALID_FLAGS);
        return NtStatus(0);
    }
    let load = || {
        let units = super::object::capture_unicode_string(klid)?;
        let units = &units[..units.len().min(abi::user::KL_NAMELENGTH - 1)];
        let klid = alloc::string::String::from_utf16(units).map_err(|_| abi::ntstatus::STATUS_OBJECT_NAME_INVALID)?;
        let no_io = {
            let process = super::current_process();
            let info = win32k::process_info(&process)?;
            info.window_station().is_none_or(|station| station.station.no_io())
        };
        // GetCharsetInfo calls back into user mode: nothing held but the
        // name.
        let charset = win32k::callback::get_charset_info;
        let loaded = win32k::keyboard::load(no_io, &klid, hkl, flags, charset, read_layout_file)?;
        Ok(loaded.unwrap_or(0))
    };
    load().map_or_else(
        |status| {
            let _ = win32k::set_last_error(abi::winerror::dos_error(status));
            NtStatus(0)
        },
        NtStatus,
    )
}

/// NtUserGetKeyboardLayoutList(nBuff, pHklBuff) : le nombre des
/// dispositions chargées pour un tampon vide (ou nul) ; sinon leurs HKL,
/// `nBuff` au plus, et leur nombre. 0 et l'erreur Win32 si l'écriture faute.
pub(super) fn nt_user_get_keyboard_layout_list(arguments: &[u32]) -> NtStatus {
    let (count, buffer) = (arguments[0], arguments[1]);
    let layouts = win32k::keyboard::layouts();
    if count == 0 || buffer == 0 {
        return NtStatus(layouts.len() as u32);
    }
    let copied: alloc::vec::Vec<u8> = layouts.iter().take(count as usize).flat_map(|hkl| hkl.to_le_bytes()).collect();
    match ke::usermem::copy_to_user(u64::from(buffer), &copied) {
        Ok(()) => NtStatus((copied.len() / 4) as u32),
        Err(status) => {
            let _ = win32k::set_last_error(abi::winerror::dos_error(status));
            NtStatus(0)
        }
    }
}

/// GR_GDIOBJECTS, GR_USEROBJECTS : ce que compte GetGuiResources (les
/// valeurs du SDK ; les pics, 2 et 4, viennent après XP).
const GR_GDIOBJECTS: u32 = 0;
const GR_USEROBJECTS: u32 = 1;

/// NtUserGetGuiResources(hProcess, uiFlags) : le nombre d'objets GDI
/// (GR_GDIOBJECTS) ou USER (GR_USEROBJECTS, ses fenêtres comprises :
/// `ppi->UserHandleCount`) du processus, même fini. 0 pour un autre drapeau
/// (`ERROR_INVALID_PARAMETER`) ou sans processus.
pub(super) fn nt_user_get_gui_resources(arguments: &[u32]) -> NtStatus {
    let (handle, flags) = (arguments[0], arguments[1]);
    let count = || -> Result<u32, NtStatus> {
        let process = super::reference_process(handle, ps::eprocess::PROCESS_QUERY_INFORMATION)?;
        match flags {
            GR_GDIOBJECTS => Ok(win32k::gdi::handles::count_of(process.pid())),
            GR_USEROBJECTS => Ok(win32k::handles::count_for_process(process.pid())),
            _ => Err(abi::ntstatus::STATUS_INVALID_PARAMETER),
        }
    };
    count().map_or_else(
        |status| {
            let _ = win32k::set_last_error(abi::winerror::dos_error(status));
            NtStatus(0)
        },
        NtStatus,
    )
}

/// NtUserSetWindowFNID(hWnd, fnID) : l'identifiant interne de la fenêtre,
/// celui de sa classe de contrôle ; TRUE, FALSE sans fenêtre.
pub(super) fn nt_user_set_window_fnid(arguments: &[u32]) -> NtStatus {
    let (handle, fnid) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        let _ = win32k::set_last_error(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
        return NtStatus(0);
    };
    win32k::window::set_fnid(&window, fnid);
    NtStatus(1)
}

/// NtUserSetProp(hWnd, AtomOrString, hData) : la propriété de la fenêtre —
/// un atome et sa donnée, remplacée si l'atome y est déjà ; FALSE sans
/// fenêtre ou sans mémoire pour le nom.
pub(super) fn nt_user_set_prop(arguments: &[u32]) -> NtStatus {
    let (handle, name, data) = (arguments[0], arguments[1], arguments[2]);
    let set = || -> Result<(), NtStatus> {
        let atom = if name <= 0xFFFF {
            name as u16
        } else {
            let units = super::object::capture_unicode_string(name)?;
            win32k::atom::add(win32k::atom::AtomName::String(&units))?
        };
        let window = win32k::window::get(handle).ok_or(abi::ntstatus::STATUS_INVALID_HANDLE)?;
        win32k::window::set_property(&window, atom, data);
        Ok(())
    };
    NtStatus(u32::from(set().is_ok()))
}

/// NtUserEnumDisplaySettings(lpszDevice, iMode, lpDevMode, dwFlags) : le
/// mode d'affichage `iMode` dans le DEVMODEW de l'appelant — le mode
/// courant seul (ENUM_CURRENT_SETTINGS ou 0) : le périphérique de Mino
/// n'en a qu'un, celui du framebuffer. TRUE écrit, FALSE autrement.
pub(super) fn nt_user_enum_display_settings(arguments: &[u32]) -> NtStatus {
    let [_device, mode, devmode, _flags] = arguments[..4] else { unreachable!("4 arguments") };
    const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
    if devmode == 0 || mode != 0 && mode != ENUM_CURRENT_SETTINGS {
        let _ = win32k::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
        return NtStatus(0);
    }
    let Some((width, height)) = win32k::display::mode().map(|mode| (mode.width, mode.height)) else {
        return NtStatus(0);
    };
    /// La taille d'un DEVMODEW de XP (212 octets), tout champs compris.
    const DEVMODEW_SIZE: usize = 212;
    let mut out = alloc::vec![0u8; DEVMODEW_SIZE];
    let word = |out: &mut [u8], at: usize, value: u16| out[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let dword = |out: &mut [u8], at: usize, value: u32| out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    for (at, unit) in "MINO".encode_utf16().enumerate() {
        word(&mut out, at * 2, unit);
    }
    word(&mut out, 64, 0x0401); // dmSpecVersion
    word(&mut out, 68, DEVMODEW_SIZE as u16); // dmSize
    dword(&mut out, 72, 0x80000 | 0x100000 | 0x40000 | 0x400000); // Pels W/H, BPP, Frequency
    dword(&mut out, 160, 32); // dmBitsPerPel
    dword(&mut out, 164, width); // dmPelsWidth
    dword(&mut out, 168, height); // dmPelsHeight
    dword(&mut out, 176, 60); // dmDisplayFrequency
    NtStatus(u32::from(ke::usermem::copy_to_user(u64::from(devmode), &out).is_ok()))
}

/// NtGdiInit() : TRUE, GDI n'a rien à préparer pour le client (ReactOS non
/// plus).
pub(super) fn nt_gdi_init(_arguments: &[u32]) -> NtStatus {
    NtStatus(1)
}
