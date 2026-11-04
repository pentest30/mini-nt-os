//! Les contextes de périphérique des fenêtres (`windc.c` de ReactOS, comme
//! spécification) : un cache de DC de l'écran (DCE), pris par
//! [`get_dc_ex`] pour peindre une fenêtre ou sa zone cliente et rendus par
//! [`release_dc`]. Un DC pris est au processus qui le prend, coupé à ce
//! qu'on voit de la fenêtre (VIS_ComputeVisibleRegion,
//! [`crate::paint::visible_region`]) et, à la demande, à une région donnée
//! (`DCX_INTERSECTRGN`, `DCX_EXCLUDERGN`) ; ses coordonnées partent du coin
//! de ce qu'il peint. Le cache grandit d'un DC quand tous sont pris.
//!
//! Pas encore, journalisé une fois : les DC d'une fenêtre ou d'une classe
//! (`CS_OWNDC`, `CS_CLASSDC` : un DC du cache à la place), le DC du parent
//! (`CS_PARENTDC`, `DCX_PARENTCLIP` : la fenêtre seule), NtUserGetDCEx et
//! NtUserReleaseDC, BeginPaint, les DC dont la fenêtre bouge ou disparaît
//! pendant qu'ils sont pris (DceResetActiveDCEs).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    CS_CLASSDC, CS_OWNDC, CS_PARENTDC, DCX_CACHE, DCX_CLIPCHILDREN, DCX_CLIPSIBLINGS, DCX_EXCLUDERGN, DCX_INTERSECTRGN,
    DCX_PARENTCLIP, DCX_USESTYLE, DCX_WINDOW, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_MINIMIZE,
};
use hal::sync::KSpinLock;

use crate::gdi::dc::{self, Dc};
use crate::gdi::region::Region;
use crate::window::Window;

/// Un DC du cache (DCE).
struct Dce {
    hdc: u32,
    dc: Arc<Dc>,
    /// La fenêtre de sa prise, 0 au repos.
    window: u32,
    /// Ses `DCX_*` à sa prise.
    flags: u32,
    busy: bool,
}

/// Le cache.
static CACHE: KSpinLock<Vec<Dce>> = KSpinLock::new(Vec::new());

/// Une fois, journalise ce que les DC des fenêtres ne font pas encore.
fn report_missing(what: &str, reported: &AtomicBool) {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: window DCs: {what}: not yet");
    }
}

/// Les `DCX_*` de UserGetDCEx pour une fenêtre de style `style` et de
/// classe de style `class_style` : avec `DCX_USESTYLE`, la fenêtre et sa
/// classe disent ce qui coupe le DC (ses enfants, ses sœurs).
pub fn effective_flags(flags: u32, style: u32, class_style: u32) -> u32 {
    if flags & DCX_USESTYLE == 0 {
        return flags;
    }
    let mut flags = flags & !(DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS | DCX_PARENTCLIP);
    if style & WS_CLIPSIBLINGS != 0 {
        flags |= DCX_CLIPSIBLINGS;
    }
    if flags & DCX_WINDOW != 0 {
        return flags | DCX_CACHE;
    }
    if class_style & CS_PARENTDC != 0 {
        flags |= DCX_PARENTCLIP;
    }
    if class_style & (CS_OWNDC | CS_CLASSDC) == 0 {
        flags |= DCX_CACHE;
    }
    if style & WS_CLIPCHILDREN != 0 && style & WS_MINIMIZE == 0 {
        flags |= DCX_CLIPCHILDREN;
    }
    flags
}

/// DceUpdateVisRgn : `visible` coupé à `clip` (`DCX_INTERSECTRGN` : rien
/// sans région) ou privé de lui (`DCX_EXCLUDERGN`).
pub fn cut(visible: Region, flags: u32, clip: Option<&Region>) -> Region {
    if flags & DCX_INTERSECTRGN != 0 {
        return clip.map_or_else(Region::default, |clip| visible.intersect(clip));
    }
    let mut visible = visible;
    if let Some(clip) = clip.filter(|_| flags & DCX_EXCLUDERGN != 0) {
        visible.subtract(clip);
    }
    visible
}

/// La région d'un DC de `window` pris avec `flags` (`DCX_*` déjà
/// effectifs) : ce qu'on en voit, sa zone cliente sans `DCX_WINDOW`, coupé
/// par `clip` (à l'écran, [`cut`]). Rend aussi l'origine du DC.
fn visible(window: &Window, flags: u32, clip: Option<&Region>) -> (Region, (i32, i32)) {
    let client = flags & DCX_WINDOW == 0;
    let region =
        crate::paint::visible_region(window, client, flags & DCX_CLIPCHILDREN != 0, flags & DCX_CLIPSIBLINGS != 0);
    let region = cut(region, flags, clip);
    let state = window.state();
    let corner = if client { state.client } else { state.window };
    (region, (corner.left, corner.top))
}

/// UserGetDCEx : un DC du cache pour `window`, au processus courant, coupé
/// selon `flags` (`DCX_*`) et `clip` (à l'écran) ; rend son handle.
///
/// # Errors
/// Ceux de la création d'un DC et de l'allocation de ses attributs.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn get_dc_ex(window: &Window, clip: Option<&Region>, flags: u32) -> Result<u32, NtStatus> {
    let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
    let flags = effective_flags(flags, window.state().style, class_style);
    if flags & DCX_CACHE == 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the DC of a window or of its class (a cache DC instead)", &REPORTED);
    }
    if flags & DCX_PARENTCLIP != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the parent's DC (CS_PARENTDC)", &REPORTED);
    }
    let (hdc, dc) = take_cache_entry(window.handle, flags)?;
    let (vis, origin) = visible(window, flags, clip);
    if let Err(status) = dc::take(hdc, &dc, vis, origin) {
        set_free(hdc);
        return Err(status);
    }
    Ok(hdc)
}

/// Un DC du cache au repos, pris pour `window` ; un neuf s'il n'y en a pas.
fn take_cache_entry(window: u32, flags: u32) -> Result<(u32, Arc<Dc>), NtStatus> {
    {
        let mut cache = CACHE.lock();
        if let Some(entry) = cache.iter_mut().find(|entry| !entry.busy) {
            (entry.window, entry.flags, entry.busy) = (window, flags, true);
            return Ok((entry.hdc, entry.dc.clone()));
        }
    }
    let (hdc, dc) = dc::create_display_dc()?;
    CACHE.lock().push(Dce { hdc, dc: dc.clone(), window, flags, busy: true });
    Ok((hdc, dc))
}

/// Le DC `hdc` du cache est de nouveau au repos.
fn set_free(hdc: u32) {
    if let Some(entry) = CACHE.lock().iter_mut().find(|entry| entry.hdc == hdc) {
        (entry.window, entry.flags, entry.busy) = (0, 0, false);
    }
}

/// UserReleaseDC : le DC `hdc` du cache, pris, retourne au repos et n'est
/// plus à personne. `false` pour un DC qui n'est pas un DC pris du cache.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn release_dc(hdc: u32) -> bool {
    let dc = {
        let cache = CACHE.lock();
        match cache.iter().find(|entry| entry.hdc == hdc && entry.busy) {
            Some(entry) => entry.dc.clone(),
            None => return false,
        }
    };
    dc::give_back(hdc, &dc);
    set_free(hdc);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::{DCX_KEEPCLIPRGN, WS_CHILD};

    const ERASE: u32 = DCX_CACHE | DCX_USESTYLE | DCX_INTERSECTRGN | DCX_KEEPCLIPRGN;

    #[test]
    fn the_style_says_what_clips_a_client_dc() {
        assert_eq!(effective_flags(ERASE, 0, 0), ERASE);
        let both = effective_flags(ERASE, WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0);
        assert_eq!(both, ERASE | DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS);
        assert_eq!(effective_flags(ERASE, WS_CLIPCHILDREN | WS_MINIMIZE, 0), ERASE, "a minimised window");
        assert_eq!(effective_flags(DCX_USESTYLE | DCX_CLIPCHILDREN, WS_CHILD, 0), DCX_USESTYLE | DCX_CACHE);
    }

    #[test]
    fn without_usestyle_the_flags_stay() {
        let flags = DCX_CLIPCHILDREN | DCX_PARENTCLIP;
        assert_eq!(effective_flags(flags, WS_CLIPSIBLINGS, CS_OWNDC), flags);
    }

    #[test]
    fn a_window_dc_is_from_the_cache_and_clips_only_siblings() {
        let flags = DCX_WINDOW | DCX_USESTYLE;
        assert_eq!(effective_flags(flags, WS_CLIPCHILDREN, CS_PARENTDC | CS_OWNDC), flags | DCX_CACHE);
        assert_eq!(effective_flags(flags, WS_CLIPSIBLINGS, 0), flags | DCX_CACHE | DCX_CLIPSIBLINGS);
    }

    #[test]
    fn a_dc_is_cut_to_a_region_or_without_it() {
        use crate::gdi::dib::Rect;
        let visible = || Region::from_rect(Rect::new(0, 0, 100, 100));
        let clip = Region::from_rect(Rect::new(50, 50, 200, 200));
        assert_eq!(cut(visible(), DCX_INTERSECTRGN, Some(&clip)).rects(), [Rect::new(50, 50, 100, 100)]);
        assert!(cut(visible(), DCX_INTERSECTRGN, None).is_empty(), "nothing to intersect with: nothing");
        assert_eq!(cut(visible(), DCX_EXCLUDERGN, Some(&clip)).area(), 100 * 100 - 50 * 50);
        assert_eq!(cut(visible(), DCX_EXCLUDERGN, None), visible(), "nothing to exclude");
        assert_eq!(cut(visible(), 0, Some(&clip)), visible(), "the region unused");
    }

    #[test]
    fn class_dcs_and_the_parent_dc() {
        let flags = DCX_USESTYLE;
        assert_eq!(effective_flags(flags, 0, CS_OWNDC), flags, "a DC of its own: not the cache");
        assert_eq!(effective_flags(flags, 0, CS_CLASSDC), flags);
        assert_eq!(effective_flags(flags, 0, CS_PARENTDC), flags | DCX_PARENTCLIP | DCX_CACHE);
    }
}
