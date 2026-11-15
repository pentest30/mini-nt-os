//! Les services des curseurs et des icônes (`win32k::cursor`) :
//! NtUserFindExistingCursorIcon, NtUserSetCursorIconData,
//! NtUserDestroyCursor, NtUserSetCursor, NtUserSetSystemCursor,
//! NtUserGetIconSize, NtUserGetIconInfo, NtUserDrawIconEx, et
//! NtUserCallOneParam(CREATEEMPTYCUROBJECT).

use alloc::vec::Vec;

use abi::ntstatus::NtStatus;
use abi::peb32::UnicodeString32;
use abi::user::{CursorData32, FindExistingCurIconParam32};
use abi::winerror::{dos_error, ERROR_INVALID_CURSOR_HANDLE, ERROR_INVALID_PARAMETER};
use ke::usermem::{copy_from_user, copy_to_user, UserPtr};
use win32k::cursor::{NameReply, Resource};

/// Met l'erreur de Win32 `error` du thread et rend `value`.
fn fail(error: u32, value: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(value)
}

/// Un caractère en majuscule (la comparaison des noms ignore la casse).
fn upper(unit: u16) -> u16 {
    char::from_u32(u32::from(unit))
        .and_then(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) if (u as u32) <= 0xFFFF => Some(u as u32 as u16),
                _ => None,
            }
        })
        .unwrap_or(unit)
}

/// Le chemin du module du UNICODE_STRING en `address`, en majuscules ;
/// `None` sans lui.
fn capture_module(address: u32) -> Result<Option<Vec<u16>>, NtStatus> {
    if address == 0 {
        return Ok(None);
    }
    let units = super::object::capture_unicode_string(address)?;
    Ok(Some(units.into_iter().map(upper).collect()))
}

/// ProbeAndCaptureUnicodeStringOrAtom : le nom de ressource du
/// UNICODE_STRING en `address`, dont le tampon peut être un identifiant
/// (MAKEINTRESOURCE : sous 0x10000) ; `None` sans lui.
fn capture_resource(address: u32) -> Result<Option<Resource>, NtStatus> {
    if address == 0 {
        return Ok(None);
    }
    let string = UserPtr::<UnicodeString32>::new(address).read()?;
    if string.buffer < 0x1_0000 {
        return Ok(Some(Resource::Id(string.buffer as u16)));
    }
    let units = super::object::capture_unicode_string(address)?;
    Ok(Some(Resource::Name(units.into_iter().map(upper).collect())))
}

/// NtUserFindExistingCursorIcon(pustrModule, pustrRsrc, param) : HICON, le
/// curseur (ou l'icône) de cette ressource que le processus a déjà chargé
/// (LR_SHARED), sinon un curseur du système qui en vient
/// (`win32k::cursor::find_existing`) ; NULL sinon.
pub(super) fn nt_user_find_existing_cursor_icon(arguments: &[u32]) -> NtStatus {
    let [module, resource, param] = arguments[..3] else { unreachable!("3 arguments") };
    let find = || -> Result<Option<u32>, NtStatus> {
        let mut bytes = [0u8; core::mem::size_of::<FindExistingCurIconParam32>()];
        copy_from_user(&mut bytes, u64::from(param))?;
        let param = FindExistingCurIconParam32::from_bytes(&bytes).ok_or(abi::ntstatus::STATUS_INVALID_PARAMETER)?;
        let (Some(module), Some(resource)) = (capture_module(module)?, capture_resource(resource)?) else {
            return Ok(None);
        };
        Ok(win32k::cursor::find_existing(&module, &resource, param.icon != 0))
    };
    NtStatus(find().ok().flatten().unwrap_or(0))
}

/// NtUserSetCursorIconData(hCursor, pustrModule, pustrRsrc, pCursorData) :
/// BOOL, le curseur vide reçoit ce que `user32` a fait
/// (`win32k::cursor::set_data`) ; FALSE pour des données refusées ou
/// illisibles.
pub(super) fn nt_user_set_cursor_icon_data(arguments: &[u32]) -> NtStatus {
    let [handle, module, resource, data] = arguments[..4] else { unreachable!("4 arguments") };
    let set = || -> Result<bool, NtStatus> {
        let mut bytes = [0u8; core::mem::size_of::<CursorData32>()];
        copy_from_user(&mut bytes, u64::from(data))?;
        let data = CursorData32::from_bytes(&bytes).ok_or(abi::ntstatus::STATUS_INVALID_PARAMETER)?;
        let (module, resource) = (capture_module(module)?, capture_resource(resource)?);
        Ok(win32k::cursor::set_data(handle, module, resource, &data))
    };
    NtStatus(u32::from(set().unwrap_or(false)))
}

/// NtUserDestroyCursor(hCurIcon, bForce) : BOOL (`win32k::cursor::destroy`).
pub(super) fn nt_user_destroy_cursor(arguments: &[u32]) -> NtStatus {
    NtStatus(u32::from(win32k::cursor::destroy(arguments[0], arguments[1] != 0)))
}

/// NtUserSetCursor(hCursor) : HCURSOR, l'ancien curseur du thread ; le
/// nouveau (NULL : aucun) devient le sien, et celui de l'écran si le
/// pointeur est sur une de ses fenêtres (`win32k::cursor::set_cursor`).
/// NULL pour un curseur qui n'existe pas (`ERROR_INVALID_CURSOR_HANDLE`).
pub(super) fn nt_user_set_cursor(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    if handle != 0 && win32k::cursor::get(handle).is_none() {
        return fail(ERROR_INVALID_CURSOR_HANDLE, 0);
    }
    let Ok(thread) = win32k::convert_current_thread() else { return NtStatus(0) };
    let old = win32k::cursor::set_cursor(&thread, handle);
    NtStatus(if win32k::cursor::get(old).is_some() { old } else { 0 })
}

/// NtUserSetSystemCursor(hcur, id) : BOOL (`win32k::cursor::set_system_cursor`) ;
/// FALSE pour un curseur qui n'existe pas (`ERROR_INVALID_CURSOR_HANDLE`).
pub(super) fn nt_user_set_system_cursor(arguments: &[u32]) -> NtStatus {
    let [handle, id] = arguments[..2] else { unreachable!("2 arguments") };
    if win32k::cursor::get(handle).is_none() {
        return fail(ERROR_INVALID_CURSOR_HANDLE, 0);
    }
    NtStatus(u32::from(win32k::cursor::set_system_cursor(handle, id)))
}

/// NtUserGetIconSize(hCurIcon, istepIfAniCur, plcx, plcy) : BOOL, la taille
/// du curseur en `*plcx` et `*plcy` ; FALSE pour un curseur sans données ou
/// une adresse qui faute.
pub(super) fn nt_user_get_icon_size(arguments: &[u32]) -> NtStatus {
    let [handle, _step, cx, cy] = arguments[..4] else { unreachable!("4 arguments") };
    let Some((width, height)) = win32k::cursor::get(handle).and_then(|cursor| cursor.size()) else {
        return NtStatus(0);
    };
    let written = UserPtr::<u32>::new(cx).write(&width).and_then(|()| UserPtr::<u32>::new(cy).write(&height));
    NtStatus(u32::from(written.is_ok()))
}

/// Le UNICODE_STRING de l'appelant en `address` reçoit ce que `reply` en
/// fait : d'abord les octets dans son tampon, puis ses champs.
fn give_name(address: u32, reply: impl FnOnce(UnicodeString32) -> NameReply) -> Result<(), NtStatus> {
    let string = UserPtr::<UnicodeString32>::new(address);
    let NameReply { string: answer, bytes } = reply(string.read()?);
    if !bytes.is_empty() {
        copy_to_user(u64::from(answer.buffer), &bytes)?;
    }
    string.write(&answer)
}

/// NtUserGetIconInfo(hCurIcon, IconInfo, lpModule, lpResName, pbpp,
/// bInternal) : BOOL. `IconInfo` reçoit l'ICONINFO du curseur, avec des
/// copies de ses bitmaps données au processus (`win32k::cursor::icon_info`),
/// et `pbpp` la profondeur de ses couleurs ; `lpModule` et `lpResName` le
/// module et le nom de la ressource dont il vient, ou la place qu'il leur
/// faut (`win32k::cursor::module_reply`, `resource_reply`). FALSE sans rien
/// à remplir (`ERROR_INVALID_PARAMETER`), pour un curseur qui n'existe pas
/// (`ERROR_INVALID_CURSOR_HANDLE`), une adresse qui faute (les copies sont
/// alors supprimées), un nom demandé d'un curseur qui ne vient pas d'une
/// ressource (sans erreur, comme ReactOS : CopyImage passe alors à une copie
/// par GetIconInfo).
pub(super) fn nt_user_get_icon_info(arguments: &[u32]) -> NtStatus {
    let [handle, info, module, resource, bpp, _internal] = arguments[..6] else { unreachable!("6 arguments") };
    if info == 0 && module == 0 && resource == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(cursor) = win32k::cursor::get(handle) else { return fail(ERROR_INVALID_CURSOR_HANDLE, 0) };
    if info != 0 {
        let icon = win32k::cursor::icon_info(&cursor);
        let written = copy_to_user(u64::from(info), icon.record.as_bytes()).and_then(|()| {
            if bpp != 0 {
                UserPtr::<u32>::new(bpp).write(&icon.bpp)
            } else {
                Ok(())
            }
        });
        if let Err(status) = written {
            for copy in [icon.record.hbm_mask, icon.record.hbm_color].into_iter().filter(|&copy| copy != 0) {
                win32k::gdi::delete_object(copy);
            }
            return fail(dos_error(status), 0);
        }
    }
    if module != 0 {
        let Some(name) = cursor.module() else { return NtStatus(0) };
        if let Err(status) = give_name(module, |asked| win32k::cursor::module_reply(asked, &name)) {
            return fail(dos_error(status), 0);
        }
    }
    if resource != 0 {
        let Some(name) = cursor.resource() else { return NtStatus(0) };
        if let Err(status) = give_name(resource, |asked| win32k::cursor::resource_reply(asked, &name)) {
            return fail(dos_error(status), 0);
        }
    }
    NtStatus(1)
}

/// NtUserDrawIconEx(hdc, xLeft, yTop, hIcon, cxWidth, cyWidth,
/// istepIfAniCur, hbrFlickerFreeDraw, diFlags, bMetaHDC, pDIXData) : BOOL,
/// l'icône dessinée dans le DC (`win32k::cursor::draw_icon_ex`) ; FALSE
/// pour une icône qui n'existe pas (`ERROR_INVALID_CURSOR_HANDLE`) ou un DC
/// qui n'est pas au processus. Le pinceau qui efface le fond n'est pas
/// encore suivi (journalisé une fois).
pub(super) fn nt_user_draw_icon_ex(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y, icon, width, height, _step, brush, flags] = arguments[..9] else { unreachable!("11 arguments") };
    if brush != 0 {
        static REPORTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        if !REPORTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
            log::warn!("sys: NtUserDrawIconEx with a brush to erase the background: not yet (the icon is drawn alone)");
        }
    }
    match win32k::cursor::draw_icon_ex(hdc, (x as i32, y as i32), icon, (width as i32, height as i32), flags) {
        Ok(drawn) => NtStatus(u32::from(drawn)),
        Err(error) => fail(error, 0),
    }
}

/// NtUserCallOneParam(animated, ONEPARAM_ROUTINE_CREATEEMPTYCUROBJECT) :
/// HCURSOR, un curseur vide du processus (`win32k::cursor::create_empty`) ;
/// NULL sans place ou pour un curseur animé.
pub(super) fn create_empty_cur_object(animated: u32) -> NtStatus {
    NtStatus(win32k::cursor::create_empty(animated != 0).unwrap_or(0))
}
