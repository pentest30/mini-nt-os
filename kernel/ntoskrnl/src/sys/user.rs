//! Les services de win32k (la seconde table) : NtUserProcessConnect,
//! NtUserInitializeClientPfnArrays, NtUserInitialize, NtGdiInit,
//! NtUserCallTwoParam (RegisterLogonProcess), NtUserSetInformationThread
//! (le port d'API de `csrss`), NtUserLoadKeyboardLayoutEx,
//! NtUserGetKeyboardLayoutList.
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
        let process = super::current_process();
        let info = win32k::process_info(&process)?;
        let no_io = info.window_station().is_none_or(|station| station.station.no_io());
        let code_page = ps::nls::current().map_or(0, |tables| tables.ansi_code_page);
        let loaded = win32k::keyboard::load(no_io, &klid, hkl, flags, code_page, read_layout_file)?;
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

/// NtGdiInit() : TRUE, GDI n'a rien à préparer pour le client (ReactOS non
/// plus).
pub(super) fn nt_gdi_init(_arguments: &[u32]) -> NtStatus {
    NtStatus(1)
}
