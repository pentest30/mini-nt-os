//! Les classes de fenêtres (`win32k::class`) : NtUserRegisterClassExWOW,
//! NtUserGetClassInfo. Comme dans win32k, un échec rend 0 et met l'erreur
//! Win32 dans le TEB du thread.

use alloc::vec::Vec;
use core::mem::size_of;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::peb32::UnicodeString32;
use abi::user::{ClsMenuName32, WndClassExW32, CSF_ANSIPROC, CS_GLOBALCLASS};
use abi::winerror::{dos_error, ERROR_CLASS_DOES_NOT_EXIST, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER};
use ke::usermem::{copy_from_user, probe_for_read, probe_for_write, UserPtr};
use win32k::class::{ClassInfo, ClassName, MenuName};

/// IS_ATOM : une adresse sous 64 Kio est un atome entier.
fn is_atom(address: u32) -> bool {
    address >> 16 == 0
}

/// Les `length` octets de la chaîne en `buffer`, en unités de 16 bits.
fn read_units(buffer: u32, length: u16) -> Result<Vec<u16>, NtStatus> {
    let mut bytes = alloc::vec![0u8; usize::from(length)];
    probe_for_read(u64::from(buffer), bytes.len(), 2)?;
    copy_from_user(&mut bytes, u64::from(buffer))?;
    Ok(bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect())
}

/// Le nom de classe d'un `UNICODE_STRING` de RegisterClassEx : une chaîne,
/// ou, de longueur nulle, un atome entier dans le pointeur (un autre
/// pointeur : `ERROR_INVALID_PARAMETER`).
fn class_name(string: &UnicodeString32) -> Result<Result<ClassName, u32>, NtStatus> {
    if string.length != 0 {
        return Ok(Ok(ClassName::String(read_units(string.buffer, string.length)?)));
    }
    if is_atom(string.buffer) {
        return Ok(Ok(ClassName::Atom(string.buffer as u16)));
    }
    Ok(Err(ERROR_INVALID_PARAMETER))
}

/// Ce qu'un service de classe rend : sa valeur, ou 0 et l'erreur Win32
/// (celle d'un statut d'une faute, d'une lecture refusée…).
fn answer(result: Result<Result<u32, u32>, NtStatus>) -> NtStatus {
    let error = match result {
        Ok(Ok(value)) => return NtStatus(value),
        Ok(Err(error)) => error,
        Err(status) => dos_error(status),
    };
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// NtUserRegisterClassExWOW(lpwcx, ClassName, ClsVersion, pClassMenuName,
/// fnID, Flags, pdwWowData) : enregistre la classe ; rend l'atome de son
/// nom. Refusés : un drapeau autre que `CSF_ANSIPROC`
/// (`ERROR_INVALID_FLAGS`), une taille de `WNDCLASSEXW` fausse, une
/// longueur de nom impaire, des octets de plus négatifs ou qui débordent,
/// une instance nulle, un nom de longueur nulle qui n'est pas un atome, un
/// nom de menu de longueur nulle qui n'est ni nul ni une ressource
/// (`ERROR_INVALID_PARAMETER`).
pub(super) fn nt_user_register_class_ex_wow(arguments: &[u32]) -> NtStatus {
    let (wcx, name, version, menu, fnid, flags) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    if flags & !CSF_ANSIPROC != 0 {
        return answer(Ok(Err(ERROR_INVALID_FLAGS)));
    }
    let register = || -> Result<Result<u32, u32>, NtStatus> {
        let process = super::current_process();
        let info = win32k::process_info(&process)?;
        drop(process);
        info.classes.lock().register_system_classes(win32k::client::client_module());
        if UserPtr::<u32>::new(wcx).read()? != size_of::<WndClassExW32>() as u32 {
            return Ok(Err(ERROR_INVALID_PARAMETER));
        }
        let wc = UserPtr::<WndClassExW32>::new(wcx).read()?;
        let name = UserPtr::<UnicodeString32>::new(name).read()?;
        let version = UserPtr::<UnicodeString32>::new(version).read()?;
        let menu = UserPtr::<ClsMenuName32>::new(menu).read()?;
        let menu_name = UserPtr::<UnicodeString32>::new(menu.us_menu_name).read()?;
        let header = size_of::<abi::user::Cls32>() as u32;
        let extra = wc.cls_extra as u32;
        if name.length % 2 != 0
            || menu_name.length % 2 != 0
            || wc.cls_extra < 0
            || extra.wrapping_add(u32::from(name.length)).wrapping_add(u32::from(menu_name.length)).wrapping_add(header)
                < extra
            || wc.wnd_extra < 0
            || wc.instance == 0
        {
            return Ok(Err(ERROR_INVALID_PARAMETER));
        }
        let (name, version) = match (class_name(&name)?, class_name(&version)?) {
            (Ok(name), Ok(version)) => (name, version),
            _ => return Ok(Err(ERROR_INVALID_PARAMETER)),
        };
        let menu = if menu_name.length != 0 {
            let name = read_units(menu_name.buffer, menu_name.length)?;
            MenuName { unicode: menu.client_unicode, ansi: menu.client_ansi, is_string: true, name }
        } else if menu_name.buffer != 0 && !is_atom(menu_name.buffer) {
            return Ok(Err(ERROR_INVALID_PARAMETER));
        } else {
            MenuName { unicode: menu_name.buffer, ansi: menu_name.buffer, is_string: false, name: Vec::new() }
        };
        let class = ClassInfo {
            style: wc.style,
            wnd_proc: wc.wnd_proc,
            cls_extra: wc.cls_extra,
            wnd_extra: wc.wnd_extra,
            instance: wc.instance,
            icon: wc.icon,
            cursor: wc.cursor,
            background: wc.background,
            icon_sm: wc.icon_sm,
        };
        let registered = info.classes.lock().register(&name, &version, class, menu, fnid, flags);
        Ok(registered.map(u32::from))
    };
    answer(register())
}

/// NtUserGetClassInfo(hInstance, ClassName, lpWndClassEx, ppszMenuName,
/// bAnsi) : remplit le `WNDCLASSEXW` (sauf sa taille et son nom) de la
/// classe que CreateWindowEx trouverait pour l'instance (celle de `user32`
/// si elle est nulle), et le nom de menu en `ppszMenuName` ; rend l'atome du
/// nom de la classe (comme XP, au lieu de TRUE). 0 et
/// `ERROR_CLASS_DOES_NOT_EXIST` sans classe.
pub(super) fn nt_user_get_class_info(arguments: &[u32]) -> NtStatus {
    let (instance, name, wcx, menu_out, ansi) = (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    let get = || -> Result<Result<u32, u32>, NtStatus> {
        probe_for_write(u64::from(wcx), size_of::<WndClassExW32>(), 4)?;
        let mut wc = UserPtr::<WndClassExW32>::new(wcx).read()?;
        if menu_out != 0 {
            probe_for_write(u64::from(menu_out), 4, 4)?;
        }
        let name = UserPtr::<UnicodeString32>::new(name).read()?;
        if name.length % 2 != 0 || name.buffer == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let name = if is_atom(name.buffer) {
            ClassName::Atom(name.buffer as u16)
        } else {
            ClassName::String(read_units(name.buffer, name.length)?)
        };
        let client_module = win32k::client::client_module();
        let instance = if instance == 0 { client_module } else { instance };
        let process = super::current_process();
        let info = win32k::process_info(&process)?;
        drop(process);
        let class = {
            let mut classes = info.classes.lock();
            classes.register_system_classes(client_module);
            classes.find(&name, instance, client_module)
        };
        let Some(class) = class else { return Ok(Err(ERROR_CLASS_DOES_NOT_EXIST)) };
        let ansi = ansi != 0;
        wc.style = if class.fnid != 0 { class.info.style & !CS_GLOBALCLASS } else { class.info.style };
        wc.wnd_proc = class.procedure(ansi);
        wc.cls_extra = class.info.cls_extra;
        wc.wnd_extra = class.info.wnd_extra;
        wc.icon = class.info.icon;
        wc.cursor = class.info.cursor;
        wc.icon_sm = class.info.icon_sm;
        wc.background = class.info.background;
        wc.menu_name = if ansi { class.menu.ansi } else { class.menu.unicode };
        wc.instance = if instance == client_module { 0 } else { instance };
        UserPtr::<WndClassExW32>::new(wcx).write(&wc)?;
        if menu_out != 0 {
            UserPtr::<u32>::new(menu_out).write(&wc.menu_name)?;
        }
        Ok(Ok(u32::from(class.nv_atom)))
    };
    answer(get())
}
