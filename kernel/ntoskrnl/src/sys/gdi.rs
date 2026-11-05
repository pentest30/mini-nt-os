//! Les services de GDI (`win32k::gdi`) : NtGdiPatBlt, NtGdiGetAppClipBox,
//! NtGdiFlush ; les régions (NtGdiCreateRectRgn, NtGdiCombineRgn,
//! NtGdiGetRgnBox), NtGdiDeleteObjectApp et la région de découpage d'un DC
//! (NtGdiExtSelectClipRgn). `gdi32` change lui-même une région qui a ses
//! attributs (SetRectRgn) : NtGdiSetRectRgn, pour une région sans eux,
//! attend. Le texte : NtGdiGetStockObject, NtGdiHfontCreate,
//! NtGdiSelectFont, NtGdiGetTextMetricsW, NtGdiGetTextExtent,
//! NtGdiExtTextOutW (`win32k::gdi::fontobj`, `win32k::gdi::text`). Les appels que `gdi32` met en
//! lot dans le TEB sont exécutés avant chaque service de win32k
//! ([`super::dispatch`]) : NtGdiFlush n'a plus rien à faire.

use abi::gdi::{rgn, ERROR, GDI_HANDLE_STOCK_MASK, GDI_HANDLE_TYPE_MASK, LO_DC_TYPE};
use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use abi::winerror::{ERROR_INVALID_HANDLE, ERROR_NOT_ENOUGH_MEMORY};
use ke::usermem::copy_to_user;
use win32k::gdi::dib::Rect;
use win32k::gdi::{region, rgnobj};

/// Met l'erreur de Win32 `error` du thread et rend `value`.
fn fail(error: u32, value: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(value)
}

/// Écrit `rect` (un RECT) en `at`.
fn write_rect(at: u32, rect: Rect) -> Result<(), NtStatus> {
    let mut bytes = [0u8; 16];
    for (slot, value) in bytes.chunks_exact_mut(4).zip([rect.left, rect.top, rect.right, rect.bottom]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    copy_to_user(u64::from(at), &bytes)
}

/// NtGdiPatBlt(hdc, x, y, cx, cy, rop) : BOOL. Un DC qui n'est pas au
/// processus met `ERROR_INVALID_HANDLE` ; un ROP avec une source rend FALSE
/// sans erreur.
pub(super) fn nt_gdi_pat_blt(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y, width, height, rop] = arguments[..6] else { unreachable!("6 arguments") };
    match win32k::gdi::dc::pat_blt(hdc, x as i32, y as i32, width as i32, height as i32, rop) {
        Ok(done) => NtStatus(u32::from(done)),
        Err(error) => fail(error, 0),
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
    match write_rect(rect, bounds) {
        Ok(()) => NtStatus(complexity as u32),
        Err(_) => NtStatus(ERROR as u32),
    }
}

/// Les caractères d'un texte que le noyau accepte en un appel.
const MAX_TEXT: u32 = 0x1_0000;

/// Les `count` caractères en `at`, chez le processus courant.
fn read_text(at: u32, count: u32) -> Result<alloc::vec::Vec<u16>, NtStatus> {
    if count > MAX_TEXT {
        return Err(abi::ntstatus::STATUS_INVALID_PARAMETER);
    }
    let mut bytes = alloc::vec![0u8; 2 * count as usize];
    ke::usermem::copy_from_user(&mut bytes, u64::from(at))?;
    Ok(bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect())
}

/// NtGdiGetStockObject(iObject) : le handle de l'objet de stock `iObject`
/// (pinceaux, polices) ; NULL pour un autre.
pub(super) fn nt_gdi_get_stock_object(arguments: &[u32]) -> NtStatus {
    NtStatus(win32k::gdi::brush::stock_object(arguments[0] as usize))
}

/// NtGdiHfontCreate(pelfw, cjElfw, lft, fl, pvCliData) : HFONT, une police
/// du processus d'après le LOGFONTW au début de `pelfw` (`gdi32` donne un
/// ENUMLOGFONTEXDVW sans dire sa taille : seul son LOGFONTW compte) ; NULL
/// pour un LOGFONTW qu'on ne peut lire.
pub(super) fn nt_gdi_hfont_create(arguments: &[u32]) -> NtStatus {
    let mut bytes = [0u8; core::mem::size_of::<abi::gdi::LogFontW32>()];
    if ke::usermem::copy_from_user(&mut bytes, u64::from(arguments[0])).is_err() {
        return fail(abi::winerror::ERROR_INVALID_PARAMETER, 0);
    }
    let Some(logfont) = abi::gdi::LogFontW32::from_bytes(&bytes) else { return NtStatus(0) };
    match win32k::gdi::fontobj::create(logfont, win32k::gdi::dc::current_pid()) {
        Ok(handle) => NtStatus(handle),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiSelectFont(hdc, hfont) : HFONT, l'ancienne police du DC ; NULL pour
/// un DC qui n'est pas au processus ou un `hfont` qui n'est pas une police.
pub(super) fn nt_gdi_select_font(arguments: &[u32]) -> NtStatus {
    let [hdc, hfont] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return NtStatus(0) };
    NtStatus(win32k::gdi::dc::select_font(&dc, hfont).unwrap_or(0))
}

/// La police du DC `hdc` et ses attributs de texte ; `None` pour un DC qui
/// n'est pas au processus.
fn dc_font(
    hdc: u32,
) -> Option<(alloc::sync::Arc<win32k::gdi::dc::Dc>, win32k::gdi::text::TextAttrs, abi::gdi::LogFontW32)> {
    let dc = win32k::gdi::dc::lock(hdc)?;
    let attrs = win32k::gdi::dc::text_attrs(&dc)?;
    let logfont = win32k::gdi::fontobj::get_or_system(attrs.font, win32k::gdi::dc::current_pid());
    Some((dc, attrs, logfont))
}

/// NtGdiGetTextMetricsW(hdc, pUnsafeTmwi, cj) : BOOL ; écrit le
/// TMW_INTERNAL de la police du DC (`cj` octets au plus). FALSE et
/// `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au processus, FALSE sans
/// la police installée ou pour un tampon qu'on ne peut écrire.
pub(super) fn nt_gdi_get_text_metrics_w(arguments: &[u32]) -> NtStatus {
    let [hdc, out, size] = arguments[..3] else { unreachable!("3 arguments") };
    let Some((_, _, logfont)) = dc_font(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let Some(metrics) = win32k::gdi::fontobj::text_metrics(&logfont) else { return NtStatus(0) };
    let bytes = metrics.as_bytes();
    let bytes = &bytes[..bytes.len().min(size as usize)];
    NtStatus(u32::from(copy_to_user(u64::from(out), bytes).is_ok()))
}

/// NtGdiGetTextExtent(hdc, lpwsz, cwc, psize, flOpts) : BOOL ; écrit en
/// `psize` la largeur des `cwc` caractères dans la police du DC et la hauteur
/// de celle-ci. FALSE et `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au
/// processus ; FALSE sans la police installée ou pour un texte ou un SIZE
/// inaccessible.
pub(super) fn nt_gdi_get_text_extent(arguments: &[u32]) -> NtStatus {
    let [hdc, text, count, out, _options] = arguments[..5] else { unreachable!("5 arguments") };
    let Some((_, _, logfont)) = dc_font(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let Ok(text) = read_text(text, count) else { return NtStatus(0) };
    let (width, height) = if text.is_empty() {
        (0, 0)
    } else {
        match win32k::gdi::fontobj::text_extent(&logfont, &text) {
            Some(extent) => extent,
            None => return NtStatus(0),
        }
    };
    let mut size = [0u8; 8];
    size[..4].copy_from_slice(&width.to_le_bytes());
    size[4..].copy_from_slice(&height.to_le_bytes());
    NtStatus(u32::from(copy_to_user(u64::from(out), &size).is_ok()))
}

/// NtGdiExtTextOutW(hdc, x, y, flOpts, prcl, pwsz, cwc, pdx, dwCodePage) :
/// BOOL ; le texte dans la police et les attributs du DC
/// (`win32k::gdi::text::ext_text_out`), avec le rectangle `prcl` s'il est
/// donné (ETO_OPAQUE, ETO_CLIPPED) et les avances `pdx` (des paires avec
/// ETO_PDY, dont seules les horizontales comptent). FALSE et
/// `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au processus ; FALSE pour
/// un texte, un rectangle ou des avances inaccessibles, ou sans la police.
pub(super) fn nt_gdi_ext_text_out_w(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y, options, rect, text, count, dx, _code_page] = arguments[..9] else { unreachable!("9 arguments") };
    let Some((dc, attrs, _)) = dc_font(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let read = || -> Result<_, NtStatus> {
        let rect = if rect == 0 {
            None
        } else {
            let mut bytes = [0u8; 16];
            ke::usermem::copy_from_user(&mut bytes, u64::from(rect))?;
            let word = |at: usize| i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            Some(Rect::new(word(0), word(4), word(8), word(12)))
        };
        let text = read_text(text, count)?;
        let dx = if dx == 0 {
            None
        } else {
            let pairs = if options & abi::gdi::eto::PDY != 0 { 2 } else { 1 };
            let mut bytes = alloc::vec![0u8; 4 * pairs * count as usize];
            ke::usermem::copy_from_user(&mut bytes, u64::from(dx))?;
            let all = bytes.chunks_exact(4).map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]));
            Some(all.step_by(pairs).collect::<alloc::vec::Vec<_>>())
        };
        Ok((rect, text, dx))
    };
    let Ok((rect, text, dx)) = read() else { return NtStatus(0) };
    let pid = win32k::gdi::dc::current_pid();
    let done = win32k::gdi::text::ext_text_out(
        &dc.state(),
        pid,
        (x as i32, y as i32),
        options,
        rect,
        &text,
        dx.as_deref(),
        &attrs,
    );
    NtStatus(u32::from(done))
}

/// NtGdiCreateRectRgn(x1, y1, x2, y2) : HRGN, une région du processus,
/// avec ses attributs chez lui ; NULL et `ERROR_NOT_ENOUGH_MEMORY` sans
/// place.
pub(super) fn nt_gdi_create_rect_rgn(arguments: &[u32]) -> NtStatus {
    let [x1, y1, x2, y2] = arguments[..4] else { unreachable!("4 arguments") };
    match rgnobj::create_rect(x1 as i32, y1 as i32, x2 as i32, y2 as i32) {
        Ok(hrgn) => NtStatus(hrgn),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiCombineRgn(hrgnDst, hrgnSrc1, hrgnSrc2, iMode) : la complexité de
/// `hrgnDst` devenue la combinaison des deux autres (`RGN_COPY` : la copie
/// de la première), ou ERROR : un mode inconnu, une région manquante
/// (`ERROR_INVALID_HANDLE`), une région qui n'est pas au processus.
pub(super) fn nt_gdi_combine_rgn(arguments: &[u32]) -> NtStatus {
    let [dst, src1, src2, mode] = arguments[..4] else { unreachable!("4 arguments") };
    let mode = mode as i32;
    if !(rgn::AND..=rgn::COPY).contains(&mode) {
        return NtStatus(ERROR as u32);
    }
    if dst == 0 || src1 == 0 || (mode != rgn::COPY && src2 == 0) {
        return fail(ERROR_INVALID_HANDLE, ERROR as u32);
    }
    let second = if mode == rgn::COPY { None } else { rgnobj::lock(src2).map(Some) };
    let (Some(dst), Some(src1), Some(src2)) = (rgnobj::lock(dst), rgnobj::lock(src1), second) else {
        return NtStatus(ERROR as u32);
    };
    let (first, second) = (src1.get(), src2.map(|src2| src2.get()));
    let Some(combined) = region::combine(&first, second.as_ref(), mode) else { return NtStatus(ERROR as u32) };
    let complexity = combined.complexity();
    dst.set(combined);
    NtStatus(complexity as u32)
}

/// NtGdiGetRgnBox(hrgn, prc) : la complexité de la région et le rectangle
/// qui la tient ; ERROR pour une région qui n'est pas au processus ou un
/// `prc` qu'on ne peut écrire.
pub(super) fn nt_gdi_get_rgn_box(arguments: &[u32]) -> NtStatus {
    let [hrgn, rect] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(object) = rgnobj::lock(hrgn) else { return NtStatus(ERROR as u32) };
    let region = object.get();
    match write_rect(rect, region.bounds()) {
        Ok(()) => NtStatus(region.complexity() as u32),
        Err(_) => NtStatus(ERROR as u32),
    }
}

/// NtGdiDeleteObjectApp(hobj) : BOOL. Un objet de stock reste (TRUE) ; un
/// objet qui n'est pas au processus met `ERROR_INVALID_HANDLE` ; un DC de
/// fenêtre est rendu au cache (DeleteDC, IntGdiDeleteDC : UserReleaseDC) ;
/// les autres objets quittent la table (GreDeleteObject : `gdi32` ne
/// l'appelle pas encore, il met en lot la suppression d'une région).
pub(super) fn nt_gdi_delete_object_app(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    if handle & GDI_HANDLE_STOCK_MASK != 0 {
        return NtStatus(1);
    }
    let owned =
        win32k::gdi::handles::get_with_owner(handle).is_some_and(|(_, owner)| owner == win32k::gdi::dc::current_pid());
    if !owned {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    let deleted = if handle & GDI_HANDLE_TYPE_MASK == LO_DC_TYPE {
        win32k::dce::release_dc(handle)
    } else {
        rgnobj::delete_object(handle)
    };
    NtStatus(u32::from(deleted))
}

/// NtGdiExtSelectClipRgn(hdc, hrgn, iMode) : la complexité de là où le DC
/// peint, sa région de découpage changée (`win32k::gdi::dc::select_clip` ;
/// une région qui n'est pas au processus compte comme aucune), ou ERROR.
pub(super) fn nt_gdi_ext_select_clip_rgn(arguments: &[u32]) -> NtStatus {
    let [hdc, hrgn, mode] = arguments[..3] else { unreachable!("3 arguments") };
    let region = rgnobj::lock(hrgn).map(|object| object.get());
    match win32k::gdi::dc::ext_select_clip_rgn(hdc, region.as_ref(), mode as i32) {
        Ok(complexity) => NtStatus(complexity as u32),
        Err(error) => fail(error, ERROR as u32),
    }
}

/// NtGdiFlush() : STATUS_SUCCESS ; le lot du thread est déjà exécuté.
pub(super) fn nt_gdi_flush(_arguments: &[u32]) -> NtStatus {
    STATUS_SUCCESS
}
