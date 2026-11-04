//! Les services de GDI (`win32k::gdi`) : NtGdiPatBlt, NtGdiGetAppClipBox et
//! NtGdiFlush. Les appels que `gdi32` met en lot dans le TEB sont exécutés
//! avant chaque service de win32k ([`super::dispatch`]) : NtGdiFlush n'a
//! plus rien à faire.

use abi::gdi::ERROR;
use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use ke::usermem::copy_to_user;

/// NtGdiPatBlt(hdc, x, y, cx, cy, rop) : BOOL. Un DC qui n'est pas au
/// processus met `ERROR_INVALID_HANDLE` ; un ROP avec une source rend FALSE
/// sans erreur.
pub(super) fn nt_gdi_pat_blt(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y, width, height, rop] = arguments[..6] else { unreachable!("6 arguments") };
    match win32k::gdi::dc::pat_blt(hdc, x as i32, y as i32, width as i32, height as i32, rop) {
        Ok(done) => NtStatus(u32::from(done)),
        Err(error) => {
            let _ = win32k::set_last_error(error);
            NtStatus(0)
        }
    }
}

/// NtGdiGetAppClipBox(hdc, prc) : la complexité de la région où le DC peint
/// (NULLREGION, SIMPLEREGION, COMPLEXREGION) et le rectangle qui la tient,
/// depuis l'origine du DC ; ERROR (0) pour un DC qui n'est pas au processus
/// ou un `prc` qu'on ne peut écrire.
pub(super) fn nt_gdi_get_app_clip_box(arguments: &[u32]) -> NtStatus {
    let [hdc, rect] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return NtStatus(ERROR as u32) };
    let (complexity, bounds) = win32k::gdi::dc::clip_box(&dc.state());
    let mut bytes = [0u8; 16];
    for (slot, value) in bytes.chunks_exact_mut(4).zip([bounds.left, bounds.top, bounds.right, bounds.bottom]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    match copy_to_user(u64::from(rect), &bytes) {
        Ok(()) => NtStatus(complexity as u32),
        Err(_) => NtStatus(ERROR as u32),
    }
}

/// NtGdiFlush() : STATUS_SUCCESS ; le lot du thread est déjà exécuté.
pub(super) fn nt_gdi_flush(_arguments: &[u32]) -> NtStatus {
    STATUS_SUCCESS
}
