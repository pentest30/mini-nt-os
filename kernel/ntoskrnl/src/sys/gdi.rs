//! Les services de GDI (`win32k::gdi`) : NtGdiPatBlt, NtGdiGetAppClipBox,
//! NtGdiFlush ; les régions (NtGdiCreateRectRgn, NtGdiCombineRgn,
//! NtGdiGetRgnBox), NtGdiDeleteObjectApp et la région de découpage d'un DC
//! (NtGdiExtSelectClipRgn). `gdi32` change lui-même une région qui a ses
//! attributs (SetRectRgn) : NtGdiSetRectRgn, pour une région sans eux,
//! attend. Le texte : NtGdiGetStockObject, NtGdiHfontCreate,
//! NtGdiSelectFont, NtGdiGetTextMetricsW, NtGdiGetTextExtent,
//! NtGdiGetTextExtentExW, NtGdiExtTextOutW (`win32k::gdi::fontobj`,
//! `win32k::gdi::text`) ; pour DrawText, NtGdiIntersectClipRect et
//! NtGdiGetRandomRgn. Les DC en mémoire et les bitmaps : NtGdiCreateCompatibleDC,
//! NtGdiCreateDIBSection, NtGdiSelectBitmap, NtGdiBitBlt
//! (`win32k::gdi::surface`, `win32k::gdi::bitblt`) ; NtGdiCreateSolidBrush.
//! Les appels que `gdi32` met en lot dans le TEB sont exécutés avant chaque
//! service de win32k ([`super::dispatch`]) : NtGdiFlush n'a plus rien à
//! faire.

use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::{rgn, BitmapInfoHeader32, BI_BITFIELDS, ERROR, GDI_HANDLE_STOCK_MASK, GDI_HANDLE_TYPE_MASK, LO_DC_TYPE};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use abi::winerror::{
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_SYSTEM_RESOURCES,
};
use ke::usermem::{copy_from_user, copy_to_user};
use win32k::gdi::dib::Rect;
use win32k::gdi::{region, rgnobj, surface};

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

/// NtGdiGetFontFamilyInfo(Dc, LogFont, Info, *InfoCount) : les polices
/// qu'énumère EnumFontFamiliesEx pour le LOGFONTW `LogFont`
/// (`win32k::gdi::fontobj::family_info`) : autant de FONTFAMILYINFO que
/// `Info` en tient (`*InfoCount` en entrée) ; rend leur nombre et, s'il y en
/// a, écrit en `*InfoCount` combien il y en a en tout (0 d'abord). -1 et
/// `ERROR_INVALID_PARAMETER` pour un pointeur nul, un compte qui n'est pas
/// positif ou une mémoire inaccessible. Le DC n'est pas lu.
pub(super) fn nt_gdi_get_font_family_info(arguments: &[u32]) -> NtStatus {
    let [_dc, logfont, info, count] = arguments[..4] else { unreachable!("4 arguments") };
    let failed = || fail(ERROR_INVALID_PARAMETER, -1i32 as u32);
    if logfont == 0 || info == 0 || count == 0 {
        return failed();
    }
    let enumerate = || -> Result<u32, NtStatus> {
        let room = ke::usermem::UserPtr::<i32>::new(count).read()?;
        ke::usermem::UserPtr::<i32>::new(count).write(&0)?;
        let mut bytes = [0u8; core::mem::size_of::<abi::gdi::LogFontW32>()];
        ke::usermem::copy_from_user(&mut bytes, u64::from(logfont))?;
        let logfont = abi::gdi::LogFontW32::from_bytes(&bytes).ok_or(STATUS_INVALID_PARAMETER)?;
        let room = usize::try_from(room).ok().filter(|&room| room > 0).ok_or(STATUS_INVALID_PARAMETER)?;
        let entries = win32k::gdi::fontobj::family_info(&logfont);
        let given = entries.len().min(room);
        if given > 0 {
            let bytes: alloc::vec::Vec<u8> =
                entries[..given].iter().flat_map(|entry| entry.as_bytes()).copied().collect();
            copy_to_user(u64::from(info), &bytes)?;
            ke::usermem::UserPtr::<i32>::new(count).write(&(entries.len() as i32))?;
        }
        Ok(given as u32)
    };
    enumerate().map_or_else(|_| failed(), NtStatus)
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

/// GTEF_INDICES : des index de glyphes à la place des caractères.
const GTEF_INDICES: u32 = 1;

/// NtGdiGetTextExtentExW(hdc, lpwsz, cwc, dxMax, pcCh, pdxOut, psize,
/// flOpts) : BOOL ; écrit en `psize` l'étendue des `cwc` caractères dans la
/// police du DC, en `pdxOut` (s'il est donné) l'étendue cumulée de chacun, en
/// `pcCh` (s'il est donné) combien d'entre eux tiennent dans `dxMax` (non
/// signé : -1, tous). Sans caractère, une étendue nulle. FALSE et
/// `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au processus ; FALSE sans
/// la police installée, pour une mémoire inaccessible, et pour des index de
/// glyphes (GTEF_INDICES, GetTextExtentExPointI : pas encore).
pub(super) fn nt_gdi_get_text_extent_ex_w(arguments: &[u32]) -> NtStatus {
    let [hdc, text, count, max, fit, dx, out, options] = arguments[..8] else { unreachable!("8 arguments") };
    if options & GTEF_INDICES != 0 {
        return NtStatus(0);
    }
    let write_size = |width: i32, height: i32| {
        let mut size = [0u8; 8];
        size[..4].copy_from_slice(&width.to_le_bytes());
        size[4..].copy_from_slice(&height.to_le_bytes());
        copy_to_user(u64::from(out), &size)
    };
    if count as i32 <= 0 {
        return NtStatus(u32::from(count == 0 && write_size(0, 0).is_ok()));
    }
    let Some((_, _, logfont)) = dc_font(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let Ok(text) = read_text(text, count) else { return NtStatus(0) };
    let Some((extents, height)) = win32k::gdi::fontobj::text_extents(&logfont, &text) else { return NtStatus(0) };
    let width = extents.last().copied().unwrap_or(0);
    let write = || -> Result<(), NtStatus> {
        if fit != 0 {
            let fitting = extents.iter().take_while(|&&extent| extent as u32 <= max).count() as u32;
            ke::usermem::UserPtr::<u32>::new(fit).write(&fitting)?;
        }
        if dx != 0 {
            let bytes: alloc::vec::Vec<u8> = extents.iter().flat_map(|extent| extent.to_le_bytes()).collect();
            copy_to_user(u64::from(dx), &bytes)?;
        }
        write_size(width, height)
    };
    NtStatus(u32::from(write().is_ok()))
}

/// NtGdiIntersectClipRect(hdc, xLeft, yTop, xRight, yBottom) : la complexité
/// de la région où le DC peint, sa région de découpage coupée par ce
/// rectangle (sans région de découpage, elle devient ce rectangle) ; ERROR
/// pour un DC qui n'est pas au processus.
pub(super) fn nt_gdi_intersect_clip_rect(arguments: &[u32]) -> NtStatus {
    let [hdc, left, top, right, bottom] = arguments[..5] else { unreachable!("5 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return NtStatus(ERROR as u32) };
    let rect = Rect::new(left as i32, top as i32, right as i32, bottom as i32);
    NtStatus(dc.change(|state| win32k::gdi::dc::select_clip_rect(state, Some(rect), rgn::AND)) as u32)
}

/// GetRandomRgn : CLIPRGN.
const CLIPRGN: u32 = 1;
/// METARGN.
const METARGN: u32 = 2;
/// APIRGN : la région de découpage et celle de méta.
const APIRGN: u32 = 3;
/// SYSRGN : la région visible, à l'écran.
const SYSRGN: u32 = 4;

/// NtGdiGetRandomRgn(hdc, hrgn, iCode) : 1 et la région `hrgn` devient la
/// région demandée du DC (CLIPRGN et APIRGN : sa région de découpage, depuis
/// son origine, faute de région de méta ; SYSRGN : sa région visible, à
/// l'écran) ; 0 sans elle (pas de région de découpage, ni de méta) ; -1 pour
/// un DC ou une région qui ne sont pas au processus, ou un code inconnu.
pub(super) fn nt_gdi_get_random_rgn(arguments: &[u32]) -> NtStatus {
    let [hdc, hrgn, code] = arguments[..3] else { unreachable!("3 arguments") };
    let (Some(dc), Some(region)) = (win32k::gdi::dc::lock(hdc), rgnobj::lock(hrgn)) else {
        return NtStatus(-1i32 as u32);
    };
    let state = dc.state();
    let wanted = match code {
        CLIPRGN | APIRGN => state.clip,
        METARGN => None,
        SYSRGN => Some(state.vis),
        _ => return NtStatus(-1i32 as u32),
    };
    match wanted {
        Some(wanted) => {
            region.set(wanted);
            NtStatus(1)
        }
        None => NtStatus(0),
    }
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
/// fenêtre est rendu au cache (DeleteDC, IntGdiDeleteDC : UserReleaseDC),
/// un DC en mémoire supprimé ; les autres objets quittent la table
/// (GreDeleteObject ; FALSE pour un bitmap choisi dans un DC).
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
        win32k::dce::release_dc(handle) || win32k::gdi::dc::delete_memory_dc(handle)
    } else {
        win32k::gdi::delete_object(handle)
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

/// NtGdiCreateCompatibleDC(hdc) : HDC, un DC en mémoire du processus
/// (`win32k::gdi::dc::create_memory_dc`), compatible avec l'écran ; NULL
/// pour un `hdc` qui n'est pas au processus (sans erreur, comme ReactOS) ou
/// sans place.
/// NtGdiCreateBitmap(Width, Height, Planes, BitsPixel, Bits) : le handle
/// du bitmap que `surface::create_from_bits` convertit en BGRA (la
/// monochrome 8×8 du pinceau de taskmgr passe ici).
pub(super) fn nt_gdi_create_bitmap(arguments: &[u32]) -> NtStatus {
    let [width, height, planes, bits_pixel, bits] = arguments[..5] else { unreachable!("5 arguments") };
    if bits == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // Les lignes que l'appelant donne sont alignées sur 16 bits.
    let stride = ((width * planes * bits_pixel + 15) / 16) * 2;
    let mut bytes = alloc::vec![0u8; stride as usize * height as usize];
    if ke::usermem::copy_from_user(&mut bytes, u64::from(bits)).is_err() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    match surface::create_from_bits(width, height, planes, bits_pixel, &bytes) {
        Ok(handle) => NtStatus(handle),
        Err(STATUS_INVALID_PARAMETER) => fail(ERROR_INVALID_PARAMETER, 0),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiCreatePatternBrushInternal(hbmp, ...) : HBRUSH, le pinceau à motif
/// du bitmap `hbmp` (`win32k::gdi::brush::create_pattern`), au processus
/// courant ; NULL sans bitmap ou sans place.
pub(super) fn nt_gdi_create_pattern_brush_internal(arguments: &[u32]) -> NtStatus {
    match win32k::gdi::brush::create_pattern(arguments[0]) {
        Ok(handle) => NtStatus(handle),
        Err(STATUS_INVALID_PARAMETER) => fail(ERROR_INVALID_PARAMETER, 0),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiOpenDCW(...) : le DC de l'écran — le seul périphérique que le
/// moteur a —, les noms de périphérique que l'appelant passe étant
/// ignorés. NULL sans place.
pub(super) fn nt_gdi_open_dc_w(_arguments: &[u32]) -> NtStatus {
    match win32k::gdi::dc::create_display_dc() {
        Ok((handle, _attrs)) => NtStatus(handle),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

pub(super) fn nt_gdi_create_compatible_dc(arguments: &[u32]) -> NtStatus {
    let hdc = arguments[0];
    if hdc != 0 && win32k::gdi::dc::lock(hdc).is_none() {
        return NtStatus(0);
    }
    NtStatus(win32k::gdi::dc::create_memory_dc().unwrap_or(0))
}

/// NtGdiCreateDIBSection(hdc, hSection, dwOffset, pbmi, iUsage, cjHeader,
/// fl, dwColorSpace, ppvBits) : HBITMAP, une DIB section du processus
/// (`win32k::gdi::surface`), dont l'adresse des pixels chez lui va en
/// `*ppvBits`. NULL sans `pbmi` ; `ERROR_INVALID_HANDLE` pour un `hdc` qui
/// n'est pas au processus ; l'erreur de `dib_geometry` pour un en-tête
/// refusé ; `ERROR_NO_SYSTEM_RESOURCES` sans mémoire. Une section de
/// l'application (`hSection`) : pas encore (`ERROR_INVALID_PARAMETER`,
/// journalisé une fois).
pub(super) fn nt_gdi_create_dib_section(arguments: &[u32]) -> NtStatus {
    let [hdc, section, _offset, info, _usage, _header_size, _fl, _color_space, bits] = arguments[..9] else {
        unreachable!("9 arguments")
    };
    if info == 0 {
        return NtStatus(0);
    }
    if hdc != 0 && win32k::gdi::dc::lock(hdc).is_none() {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    if section != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtGdiCreateDIBSection on an application's section: not yet");
        }
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let read = || -> Result<_, NtStatus> {
        let mut bytes = [0u8; core::mem::size_of::<BitmapInfoHeader32>()];
        copy_from_user(&mut bytes, u64::from(info))?;
        let header = BitmapInfoHeader32::from_bytes(&bytes).ok_or(STATUS_INVALID_PARAMETER)?;
        // The masks follow a BITMAPINFOHEADER, and are where a V4 or V5
        // header has them: from byte 40 either way.
        let masks = if header.compression == BI_BITFIELDS {
            let mut masks = [0u8; 12];
            copy_from_user(&mut masks, u64::from(info) + bytes.len() as u64)?;
            let word = |at: usize| u32::from_le_bytes([masks[at], masks[at + 1], masks[at + 2], masks[at + 3]]);
            Some([word(0), word(4), word(8)])
        } else {
            None
        };
        Ok((header, masks))
    };
    let Ok((header, masks)) = read() else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let geometry = match surface::dib_geometry(&header, masks) {
        Ok(geometry) => geometry,
        Err(error) => return fail(error, 0),
    };
    let Ok((hbitmap, base)) = surface::create_dib_section(geometry) else {
        return fail(ERROR_NO_SYSTEM_RESOURCES, 0);
    };
    if bits != 0 {
        // As ReactOS: a `ppvBits` that cannot be written leaves the bitmap.
        let _ = copy_to_user(u64::from(bits), &base.to_le_bytes());
    }
    NtStatus(hbitmap)
}

/// NtGdiSelectBitmap(hdc, hbmp) : HBITMAP, l'ancien bitmap du DC en mémoire
/// (`win32k::gdi::dc::select_bitmap`) ; NULL sinon.
pub(super) fn nt_gdi_select_bitmap(arguments: &[u32]) -> NtStatus {
    let [hdc, hbmp] = arguments[..2] else { unreachable!("2 arguments") };
    NtStatus(win32k::gdi::dc::select_bitmap(hdc, hbmp).unwrap_or(0))
}

/// NtGdiBitBlt(hdcDst, x, y, cx, cy, hdcSrc, xSrc, ySrc, rop4, crBackColor,
/// fl) : BOOL (`win32k::gdi::bitblt`). `crBackColor` ne sert qu'à une source
/// monochrome (pas encore).
pub(super) fn nt_gdi_bit_blt(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y, width, height, hdc_src, x_src, y_src, rop, _back, _fl] = arguments[..11] else {
        unreachable!("11 arguments")
    };
    let rect = (x as i32, y as i32, width as i32, height as i32);
    match win32k::gdi::bitblt::bit_blt(hdc, rect, hdc_src, (x_src as i32, y_src as i32), rop) {
        Ok(done) => NtStatus(u32::from(done)),
        Err(error) => fail(error, 0),
    }
}

/// NtGdiCreateSolidBrush(cr, hbr) : HBRUSH, un pinceau plein du processus
/// (`win32k::gdi::brush::create_solid`) ; NULL sans place. `hbr` (un
/// pinceau à reprendre) est ignoré, comme dans ReactOS.
pub(super) fn nt_gdi_create_solid_brush(arguments: &[u32]) -> NtStatus {
    NtStatus(win32k::gdi::brush::create_solid(arguments[0]).unwrap_or(0))
}

/// NtGdiFlush() : STATUS_SUCCESS ; le lot du thread est déjà exécuté.
pub(super) fn nt_gdi_flush(_arguments: &[u32]) -> NtStatus {
    STATUS_SUCCESS
}
