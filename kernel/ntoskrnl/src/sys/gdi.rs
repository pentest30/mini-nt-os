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

/// NtGdiRectangle(hdc, left, top, right, bottom) : BOOL, le rectangle peint
/// du pinceau du DC, son contour d'un pixel (`win32k::gdi::dc::rectangle`) ;
/// FALSE et `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au processus.
pub(super) fn nt_gdi_rectangle(arguments: &[u32]) -> NtStatus {
    let [hdc, left, top, right, bottom] = arguments[..5] else { unreachable!("5 arguments") };
    match win32k::gdi::dc::rectangle(hdc, left as i32, top as i32, right as i32, bottom as i32) {
        Ok(done) => NtStatus(u32::from(done)),
        Err(error) => fail(error, 0),
    }
}

/// NtGdiGetDCObject(hdc, ObjectType) : HANDLE, l'objet du type
/// GDI_OBJECT_TYPE_* choisi dans le DC (`win32k::gdi::dc::get_dc_object`) ;
/// NULL et `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au processus,
/// `ERROR_INVALID_PARAMETER` pour un type qu'il ne tient pas.
pub(super) fn nt_gdi_get_dc_object(arguments: &[u32]) -> NtStatus {
    match win32k::gdi::dc::get_dc_object(arguments[0], arguments[1]) {
        Ok(handle) => NtStatus(handle),
        Err(error) => fail(error, 0),
    }
}

/// Les points qu'une transformation accepte en un appel.
const MAX_POINTS: u32 = 0x1_0000;

/// NtGdiTransformPoints(hdc, pptIn, pptOut, Count, iMode) : BOOL, les
/// `Count` points de `pptIn` (GdiDpToLp : du périphérique vers le logique ;
/// GdiLpToDp : l'inverse) dans `pptOut`, par la translation MM_TEXT des
/// origines de la vue et de la fenêtre du DC
/// (`win32k::gdi::dc::logical_offset` ; pas encore les étendues). FALSE pour
/// un DC qui n'est pas au processus (`ERROR_INVALID_HANDLE`), un autre mode,
/// un compte nul ou trop grand (`ERROR_INVALID_PARAMETER`), une mémoire
/// illisible.
pub(super) fn nt_gdi_transform_points(arguments: &[u32]) -> NtStatus {
    let [hdc, points_in, points_out, count, mode] = arguments[..5] else { unreachable!("5 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    if !matches!(mode, abi::gdi::GDI_DP_TO_LP | abi::gdi::GDI_LP_TO_DP) || count as i32 <= 0 || count > MAX_POINTS {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut points = alloc::vec![0u8; 8 * count as usize];
    if copy_from_user(&mut points, u64::from(points_in)).is_err() {
        return NtStatus(0);
    }
    let (dx, dy) = win32k::gdi::dc::logical_offset(&dc.state());
    let (dx, dy) = if mode == abi::gdi::GDI_LP_TO_DP { (dx, dy) } else { (dx.wrapping_neg(), dy.wrapping_neg()) };
    for point in points.chunks_exact_mut(8) {
        let x = i32::from_le_bytes([point[0], point[1], point[2], point[3]]).wrapping_add(dx);
        let y = i32::from_le_bytes([point[4], point[5], point[6], point[7]]).wrapping_add(dy);
        point[..4].copy_from_slice(&x.to_le_bytes());
        point[4..].copy_from_slice(&y.to_le_bytes());
    }
    NtStatus(u32::from(copy_to_user(u64::from(points_out), &points).is_ok()))
}

/// NtGdiRectVisible(hdc, prc) : BOOL, une partie du rectangle en `prc`
/// tombe là où le DC peint (`win32k::gdi::dc::rect_visible`) ; FALSE pour un
/// DC qui n'est pas au processus (`ERROR_INVALID_HANDLE`) ou un rectangle
/// qu'on ne peut lire. L'en-tête et la ListView de `comctl32` ne peignent
/// que les éléments qu'il dit visibles.
pub(super) fn nt_gdi_rect_visible(arguments: &[u32]) -> NtStatus {
    let [hdc, rect] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let mut bytes = [0u8; 16];
    if ke::usermem::copy_from_user(&mut bytes, u64::from(rect)).is_err() {
        return NtStatus(0);
    }
    let word = |at: usize| i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let rect = Rect::new(word(0), word(4), word(8), word(12));
    NtStatus(u32::from(win32k::gdi::dc::rect_visible(&dc.state(), rect)))
}

/// NtGdiGetPixel(hdc, x, y) : COLORREF, la couleur du point logique là où
/// le DC peint (`win32k::gdi::dc::get_pixel`) ; CLR_INVALID ailleurs, ou
/// pour un DC qui n'est pas au processus (`ERROR_INVALID_HANDLE`).
pub(super) fn nt_gdi_get_pixel(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else {
        return fail(ERROR_INVALID_HANDLE, win32k::gdi::dc::CLR_INVALID);
    };
    NtStatus(win32k::gdi::dc::get_pixel(&dc.state(), x as i32, y as i32))
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

/// NtGdiExtGetObjectW(hgdiobj, cjBufferSize, lpBuffer) : ce que l'objet dit
/// de lui-même (GreGetObject, `win32k::gdi::object`) : sans tampon, la taille
/// de sa description ; sinon, elle écrite (au plus `cjBufferSize` octets, un
/// nombre négatif comptant comme un grand) et sa taille rendue. 0 pour un
/// objet sans description, et pour un tampon qu'on ne peut écrire, sans
/// dernière erreur (comme ReactOS).
pub(super) fn nt_gdi_ext_get_object_w(arguments: &[u32]) -> NtStatus {
    let [handle, size, buffer] = arguments[..3] else { unreachable!("3 arguments") };
    let count = size.min(win32k::gdi::object::MAX_OBJECT_SIZE);
    let pid = win32k::gdi::dc::current_pid();
    let (result, bytes) = win32k::gdi::object::get_object(handle, pid, count, buffer != 0);
    if buffer == 0 || result == 0 {
        return NtStatus(result);
    }
    let length = (count.min(result) as usize).min(bytes.len());
    match copy_to_user(u64::from(buffer), &bytes[..length]) {
        Ok(()) => NtStatus(result),
        Err(_) => NtStatus(0),
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

/// GDI_ERROR : ce que rendent GetFontData et GetGlyphIndicesW en échec.
const GDI_ERROR: u32 = 0xFFFF_FFFF;
/// MAX_TEXT_BUFFER de ReactOS : le plus d'octets qu'un service de texte copie.
const MAX_TEXT_BUFFER: usize = 0x0271_0000;

/// La police installée du DC `hdc` et sa hauteur de LOGFONT ; `Err` avec ce
/// que le service rend : `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au
/// processus ou sans police installée.
fn dc_face(hdc: u32, failure: u32) -> Result<(win32k::font::Face, i32), NtStatus> {
    let Some((_, _, logfont)) = dc_font(hdc) else { return Err(fail(ERROR_INVALID_HANDLE, failure)) };
    win32k::gdi::fontobj::realize(&logfont).ok_or_else(|| fail(ERROR_INVALID_HANDLE, failure))
}

/// NtGdiGetFontData(hdc, Table, Offset, Buffer, Size) : DWORD (ftGdiGetFontData)
/// ; la table `Table` (MS_MAKE_TAG ; 0 : le fichier entier) de la police du
/// DC. Sans `Buffer` ou avec `Size` nul, sa taille ; sinon ses octets depuis
/// `Offset` (au plus sa taille) écrits en `Buffer`, et leur nombre.
/// GDI_ERROR : un DC qui n'est pas au processus (`ERROR_INVALID_HANDLE`),
/// une table absente, une place au-delà de la table, un tampon inaccessible.
pub(super) fn nt_gdi_get_font_data(arguments: &[u32]) -> NtStatus {
    let [hdc, table, offset, buffer, size] = arguments[..5] else { unreachable!("5 arguments") };
    let (face, _) = match dc_face(hdc, GDI_ERROR) {
        Ok(found) => found,
        Err(status) => return status,
    };
    let Some((data, range)) = win32k::font::font_data(face, table) else { return NtStatus(GDI_ERROR) };
    if buffer == 0 || size == 0 {
        return NtStatus(range.len() as u32);
    }
    // As FT_Load_Sfnt_Table: at most the table's size, from `Offset`.
    let length = (size as usize).min(range.len());
    let Some(start) = range.start.checked_add(offset as usize) else { return NtStatus(GDI_ERROR) };
    let Some(bytes) = start.checked_add(length).filter(|&end| end <= range.end).map(|end| &data[start..end]) else {
        return NtStatus(GDI_ERROR);
    };
    match ke::usermem::copy_to_user(u64::from(buffer), bytes) {
        Ok(()) => NtStatus(length as u32),
        Err(_) => NtStatus(GDI_ERROR),
    }
}

/// NtGdiGetGlyphIndicesW(hdc, pwc, cwc, pgi, iMode) : DWORD
/// (GreGetGlyphIndicesW) ; le glyphe de chacun des `cwc` caractères de
/// `pwc` dans la police du DC, écrits en `pgi`, et leur nombre ; un
/// caractère absent a 0xFFFF avec GGI_MARK_NONEXISTING_GLYPHS (1), sinon le
/// glyphe du caractère par défaut de la police. Sans rien (`pwc`, `pgi`,
/// `cwc` et `iMode` nuls), le nombre de glyphes de la police. GDI_ERROR : un
/// `cwc` négatif ou nul (hors ce cas), trop grand, un DC qui n'est pas au
/// processus, une mémoire inaccessible.
pub(super) fn nt_gdi_get_glyph_indices_w(arguments: &[u32]) -> NtStatus {
    let [hdc, text, count, out, mode] = arguments[..5] else { unreachable!("5 arguments") };
    let count = count as i32;
    if count < 0 {
        return NtStatus(GDI_ERROR);
    }
    let (face, _) = match dc_face(hdc, GDI_ERROR) {
        Ok(found) => found,
        Err(status) => return status,
    };
    if count == 0 {
        if text == 0 && out == 0 && mode == 0 {
            return NtStatus(win32k::font::glyph_count(face).map_or(GDI_ERROR, u32::from));
        }
        return NtStatus(GDI_ERROR);
    }
    if count as usize > MAX_TEXT_BUFFER / 4 {
        return NtStatus(GDI_ERROR);
    }
    let Ok(units) = read_text(text, count as u32) else { return NtStatus(GDI_ERROR) };
    let missing = (mode & GGI_MARK_NONEXISTING_GLYPHS != 0).then_some(0xFFFF);
    let Some(glyphs) = win32k::font::glyph_indices(face, &units, missing) else { return NtStatus(GDI_ERROR) };
    let bytes: alloc::vec::Vec<u8> = glyphs.iter().flat_map(|glyph| glyph.to_le_bytes()).collect();
    match ke::usermem::copy_to_user(u64::from(out), &bytes) {
        Ok(()) => NtStatus(count as u32),
        Err(_) => NtStatus(GDI_ERROR),
    }
}

/// GGI_MARK_NONEXISTING_GLYPHS : GetGlyphIndices marque un caractère absent
/// de 0xFFFF.
const GGI_MARK_NONEXISTING_GLYPHS: u32 = 0x0001;
/// GCABCW_INDICES : des indices de glyphes (sinon des caractères). Les
/// largeurs sont des entiers (ABC) pour tout drapeau, GCABCW_NOFLOAT (1)
/// comme celui-ci, et des ABCFLOAT sans drapeau, comme ReactOS.
const GCABCW_INDICES: u32 = 0x0002;

/// NtGdiGetCharABCWidthsW(hdc, FirstChar, Count, pwch, fl, Buffer) : BOOL
/// (GreGetCharABCWidthsW) ; les largeurs A, B, C des `Count` codes (ceux de
/// `pwch`, sinon `FirstChar` et les suivants) dans la police du DC, en
/// `Buffer` : des ABC entiers pour `fl` non nul, des ABCFLOAT pour 0 (comme
/// ReactOS) ; des indices de glyphes avec GCABCW_INDICES. FALSE sans
/// `Buffer`, avec `pwch` et aucun code, pour trop de codes, un DC qui n'est
/// pas au processus (`ERROR_INVALID_HANDLE`) ou une mémoire inaccessible.
pub(super) fn nt_gdi_get_char_abc_widths_w(arguments: &[u32]) -> NtStatus {
    let [hdc, first, count, codes, flags, buffer] = arguments[..6] else { unreachable!("6 arguments") };
    if buffer == 0 || (codes != 0 && count == 0) || count as usize > MAX_TEXT_BUFFER / 12 {
        return NtStatus(0);
    }
    let codes: alloc::vec::Vec<u32> = if codes != 0 {
        let Ok(units) = read_text(codes, count) else { return NtStatus(0) };
        units.into_iter().map(u32::from).collect()
    } else {
        (0..count).map(|at| first.wrapping_add(at)).collect()
    };
    let (face, height) = match dc_face(hdc, 0) {
        Ok(found) => found,
        Err(status) => return status,
    };
    let indices = flags & GCABCW_INDICES != 0;
    let Some(widths) = win32k::font::abc_widths(face, height, &codes, indices) else { return NtStatus(0) };
    let integers = flags != 0;
    let bytes: alloc::vec::Vec<u8> = widths
        .iter()
        .flat_map(|&(a, b, c)| {
            let words = if integers {
                [a as u32, b as u32, c as u32]
            } else {
                [(a as f32).to_bits(), (b as f32).to_bits(), (c as f32).to_bits()]
            };
            words.into_iter().flat_map(u32::to_le_bytes)
        })
        .collect();
    NtStatus(u32::from(ke::usermem::copy_to_user(u64::from(buffer), &bytes).is_ok()))
}

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
    // A logical rectangle: to the DC's device coordinates.
    let (dx, dy) = win32k::gdi::dc::logical_offset(&dc.state());
    let rect = Rect::new(left as i32 + dx, top as i32 + dy, right as i32 + dx, bottom as i32 + dy);
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
        None,
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
        win32k::dce::release_dc(handle) || win32k::gdi::dc::delete_dc(handle)
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

/// NtGdiCreateBitmap(Width, Height, Planes, BitsPixel, Bits) : le handle
/// du bitmap que `surface::create_from_bits` convertit en BGRA (la
/// monochrome 8×8 du pinceau de taskmgr passe ici) ; sans `Bits`, un bitmap
/// noir (les masques d'un curseur que `user32` remplit par StretchDIBits).
pub(super) fn nt_gdi_create_bitmap(arguments: &[u32]) -> NtStatus {
    let [width, height, planes, bits_pixel, bits] = arguments[..5] else { unreachable!("5 arguments") };
    // La géométrie d'abord, avant toute allocation : les dimensions que le
    // moteur tient (celles de `surface::create_from_bits`), la profondeur
    // qu'il convertit (la monochrome et le 32 bits), le pas et la taille
    // totale en arithmétique contrôlée et bornée — un appelant pourrait
    // autrement demander des gigaoctets pour une hauteur sans fond.
    let Some(depth) = planes.checked_mul(bits_pixel).filter(|&depth| depth == 1 || depth == 32) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // Les lignes que l'appelant donne sont alignées sur 16 bits.
    let Some(total) = width
        .checked_mul(depth)
        .and_then(|bits| bits.checked_add(15))
        .map(|bits| bits / 16 * 2)
        .and_then(|stride| stride.checked_mul(height))
        .filter(|total| *total <= 16 * 1024 * 1024)
    else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    let mut bytes = alloc::vec![0u8; if bits == 0 { 0 } else { total as usize }];
    if bits != 0 && ke::usermem::copy_from_user(&mut bytes, u64::from(bits)).is_err() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let given = (bits != 0).then_some(&bytes[..]);
    match surface::create_from_bits(width, height, planes, bits_pixel, given) {
        Ok(handle) => NtStatus(handle),
        Err(STATUS_INVALID_PARAMETER) => fail(ERROR_INVALID_PARAMETER, 0),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiCreatePen(iStyle, cjWidth, crColor, hpen) : le stylo du processus
/// courant (`win32k::gdi::pen::Pen::create`) ; NULL sans place. Les styles
/// que le moteur ne tient pas encore se dessinent pleins.
pub(super) fn nt_gdi_create_pen(arguments: &[u32]) -> NtStatus {
    let [style, width, color, _hpen] = arguments[..4] else { unreachable!("4 arguments") };
    match win32k::gdi::pen::Pen::create(style, width as i32, color) {
        Ok(handle) => NtStatus(handle),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiSelectPen(hdc, hpen) : le stylo du DC ; rend l'ancien handle.
pub(super) fn nt_gdi_select_pen(arguments: &[u32]) -> NtStatus {
    let [hdc, hpen] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    NtStatus(win32k::gdi::dc::select_pen(&dc, hpen).unwrap_or_else(|| {
        let _ = win32k::set_last_error(ERROR_INVALID_HANDLE);
        0
    }))
}

/// NtGdiMoveTo(hdc, x, y, pptOut) : la position courante du DC ; rend
/// l'ancienne en `pptOut` et TRUE, FALSE sans DC.
pub(super) fn nt_gdi_move_to(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y, out] = arguments[..4] else { unreachable!("4 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    NtStatus(u32::from(win32k::gdi::dc::move_to(&dc, x as i32, y as i32, out).is_some()))
}

/// NtGdiLineTo(hdc, x, y) : le trait de la position courante à `(x, y)`,
/// du stylo du DC ; TRUE dessiné, FALSE sans DC ou sans où peindre.
pub(super) fn nt_gdi_line_to(arguments: &[u32]) -> NtStatus {
    let [hdc, x, y] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    NtStatus(u32::from(win32k::gdi::dc::line_to(&dc, x as i32, y as i32)))
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

/// NtGdiOpenDCW(...) : un DC de l'écran — le seul périphérique que le
/// moteur a —, au processus (`win32k::gdi::dc::open_display_dc`), les noms
/// de périphérique que l'appelant passe étant ignorés. NULL sans place.
pub(super) fn nt_gdi_open_dc_w(_arguments: &[u32]) -> NtStatus {
    match win32k::gdi::dc::open_display_dc() {
        Ok(handle) => NtStatus(handle),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// NtGdiCreateCompatibleDC(hdc) : HDC, un DC en mémoire du processus
/// (`win32k::gdi::dc::create_memory_dc`), compatible avec l'écran ; NULL
/// pour un `hdc` qui n'est pas au processus (sans erreur, comme ReactOS) ou
/// sans place.
pub(super) fn nt_gdi_create_compatible_dc(arguments: &[u32]) -> NtStatus {
    let hdc = arguments[0];
    if hdc != 0 && win32k::gdi::dc::lock(hdc).is_none() {
        return NtStatus(0);
    }
    NtStatus(win32k::gdi::dc::create_memory_dc().unwrap_or(0))
}

/// NtGdiCreateCompatibleBitmap(hdc, cx, cy) : HBITMAP, un bitmap noir du
/// processus (`win32k::gdi::surface::create_compatible`) : monochrome pour
/// un DC en mémoire dont le bitmap l'est (le bitmap par défaut compris),
/// de la couleur de l'écran sinon. NULL pour un DC qui n'est pas au
/// processus (`ERROR_INVALID_HANDLE`), une taille nulle, négative ou trop
/// grande (`ERROR_INVALID_PARAMETER`), sans place.
pub(super) fn nt_gdi_create_compatible_bitmap(arguments: &[u32]) -> NtStatus {
    let [hdc, width, height] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(dc) = win32k::gdi::dc::lock(hdc) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let (width, height) = (width as i32, height as i32);
    if !(1..=4096).contains(&width) || !(1..=4096).contains(&height) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let monochrome = dc.state().bitmap.as_ref().is_some_and(|selected| selected.surface.is_monochrome());
    match surface::create_compatible(width as u32, height as u32, monochrome) {
        Ok(handle) => NtStatus(handle),
        Err(_) => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// Le BITMAPINFO d'un appelant tient au plus en-tête V5 et table de 256
/// couleurs.
const MAX_BITMAP_INFO: u32 = 124 + 256 * 4;

/// NtGdiStretchDIBitsInternal(hdc, xDst, yDst, cxDst, cyDst, xSrc, ySrc,
/// cxSrc, cySrc, pjInit, pbmi, dwUsage, dwRop4, cjMaxInfo, cjMaxBits,
/// hcmXform) : le nombre de lignes peintes de la DIB (`pbmi`, `pjInit`)
/// dans le DC (`win32k::gdi::dibits`), 0 en cas d'échec, l'erreur de Win32
/// posée.
pub(super) fn nt_gdi_stretch_dibits_internal(arguments: &[u32]) -> NtStatus {
    use win32k::gdi::dibits::{self, Dib, DibFormat};
    let [hdc, x, y, width, height, x_src, y_src, width_src, height_src, bits, info, usage, rop, info_size, bits_size, _xform] =
        arguments[..16]
    else {
        unreachable!("16 arguments")
    };
    if info == 0 || bits == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let info_size = info_size.min(MAX_BITMAP_INFO);
    let mut info_bytes = alloc::vec![0u8; info_size as usize];
    if copy_from_user(&mut info_bytes, u64::from(info)).is_err() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let format = match DibFormat::parse(&info_bytes, usage) {
        Ok(format) => format,
        Err(error) => return fail(error, 0),
    };
    let needed = format.bits_size();
    if (bits_size as usize) < needed {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut bits_bytes = alloc::vec![0u8; needed];
    if copy_from_user(&mut bits_bytes, u64::from(bits)).is_err() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(dib) = Dib::decode(&format, &bits_bytes) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let dst = (x as i32, y as i32, width as i32, height as i32);
    let src = (x_src as i32, y_src as i32, width_src as i32, height_src as i32);
    match dibits::stretch_dibits(hdc, dst, src, &dib, rop) {
        Ok(lines) => NtStatus(lines as u32),
        Err(error) => fail(error, 0),
    }
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
