//! Les contextes de périphérique des fenêtres (`windc.c` de ReactOS, comme
//! spécification) : un cache de DC de l'écran (DCE), pris par
//! [`get_dc_ex`] (GetDC, GetDCEx, GetWindowDC, BeginPaint, WM_ERASEBKGND)
//! pour peindre une fenêtre, sa zone cliente ou tout l'écran (sans
//! fenêtre), et rendus par [`release_dc`] (ReleaseDC, EndPaint). Un DC pris
//! est au processus qui le prend, coupé à ce qu'on voit de la fenêtre
//! (VIS_ComputeVisibleRegion, [`crate::paint::visible_region`]) selon ses
//! `DCX_*` ([`effective_flags`]) et, à la demande, à une région donnée
//! (`DCX_INTERSECTRGN`, `DCX_EXCLUDERGN`, [`Clip`]) ; ses coordonnées partent
//! du coin de ce qu'il peint. La région d'un client donnée à GetDCEx est au
//! DC jusqu'à sa remise, où elle est supprimée (sauf `DCX_KEEPCLIPRGN`). Le
//! cache grandit d'un DC quand tous sont pris. Seul le processus qui a pris
//! un DC le rend (ReactOS ne le vérifie pas). Sans `DCX_CACHE`, une fenêtre
//! qui n'a pas de DC à elle a un DC du cache, comme dans XP (`DCX_CACHE`
//! ne fait que passer outre `CS_OWNDC` et `CS_CLASSDC`) et dans Wine ;
//! ReactOS rend alors NULL.
//!
//! Les DC pris pour une fenêtre détruite retournent au repos
//! ([`free_window_dcs`], DceFreeWindowDCE), comme ceux d'un processus qui se
//! termine ([`free_process_dcs`]).
//!
//! Pas encore, journalisé une fois : les DC d'une fenêtre ou d'une classe
//! (`CS_OWNDC`, `CS_CLASSDC` : un DC du cache à la place), le DC du parent
//! (`CS_PARENTDC`, `DCX_PARENTCLIP` : la fenêtre seule), `DCX_INTERSECTUPDATE`
//! (ignoré), les DC dont la fenêtre bouge pendant qu'ils sont pris
//! (DceResetActiveDCEs).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    CS_CLASSDC, CS_OWNDC, CS_PARENTDC, DCX_CACHE, DCX_CLIPCHILDREN, DCX_CLIPSIBLINGS, DCX_EXCLUDERGN, DCX_INTERSECTRGN,
    DCX_INTERSECTUPDATE, DCX_KEEPCLIPRGN, DCX_NOCLIPCHILDREN, DCX_PARENTCLIP, DCX_USESTYLE, DCX_WINDOW, WS_CHILD,
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_MINIMIZE, WS_VISIBLE,
};
use hal::sync::KSpinLock;

use crate::gdi::dc::{self, Dc};
use crate::gdi::dib::Rect;
use crate::gdi::region::Region;
use crate::window::Window;

/// Un DC du cache (DCE).
struct Dce {
    hdc: u32,
    dc: Arc<Dc>,
    /// La fenêtre de sa prise, 0 au repos ou sans fenêtre.
    window: u32,
    /// Ses `DCX_*` à sa prise.
    flags: u32,
    /// La région d'un client qui le coupe (`hrgnClip`), à supprimer à sa
    /// remise.
    clip_region: Option<u32>,
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

/// Ce que UserGetDCEx regarde d'une fenêtre.
#[derive(Clone, Copy, Debug, Default)]
pub struct Styles {
    pub style: u32,
    /// Le style de sa classe.
    pub class_style: u32,
    /// Le style de son parent, pour un enfant (`WS_CHILD`) qui en a un.
    pub parent: Option<u32>,
}

impl Styles {
    /// Ceux de `window`.
    pub fn of(window: &Window) -> Self {
        let state = window.state();
        let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
        let parent = if state.style & WS_CHILD != 0 {
            crate::window::get(state.parent).map(|parent| parent.state().style)
        } else {
            None
        };
        Self { style: state.style, class_style, parent }
    }
}

/// Les `DCX_*` de UserGetDCEx pour `window` (aucune : tout l'écran, du
/// cache) : avec `DCX_USESTYLE`, la fenêtre et sa classe disent ce qui coupe
/// le DC (ses enfants, ses sœurs) ; une fenêtre qui n'est pas un enfant
/// coupe toujours ses sœurs ; le DC du parent ne sert qu'à qui ne coupe ni
/// ses sœurs ni ses enfants.
pub fn effective_flags(flags: u32, window: Option<&Styles>) -> u32 {
    let mut flags = flags;
    if window.is_none() {
        flags = flags & !DCX_USESTYLE | DCX_CACHE;
    }
    if flags & DCX_PARENTCLIP != 0 {
        flags |= DCX_CACHE;
    }
    if let Some(window) = window.filter(|_| flags & DCX_USESTYLE != 0) {
        flags &= !(DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS | DCX_PARENTCLIP);
        if window.style & WS_CLIPSIBLINGS != 0 {
            flags |= DCX_CLIPSIBLINGS;
        }
        if flags & DCX_WINDOW != 0 {
            flags |= DCX_CACHE;
        } else {
            if window.class_style & CS_PARENTDC != 0 {
                flags |= DCX_PARENTCLIP;
            }
            if window.class_style & (CS_OWNDC | CS_CLASSDC) == 0 {
                flags |= DCX_CACHE;
            }
            if window.style & WS_CLIPCHILDREN != 0 && window.style & WS_MINIMIZE == 0 {
                flags |= DCX_CLIPCHILDREN;
            }
        }
    }
    if flags & DCX_WINDOW != 0 {
        flags &= !DCX_CLIPCHILDREN;
    }
    if flags & DCX_NOCLIPCHILDREN != 0 {
        flags = flags & !(DCX_PARENTCLIP | DCX_CLIPCHILDREN) | DCX_CACHE;
    }
    let parent = window.and_then(|window| window.parent);
    if parent.is_none() {
        flags = flags & !DCX_PARENTCLIP | DCX_CLIPSIBLINGS;
    }
    if flags & (DCX_CLIPSIBLINGS | DCX_CLIPCHILDREN) != 0 {
        flags &= !DCX_PARENTCLIP;
    }
    if let (Some(window), Some(parent)) = (window, parent) {
        if flags & DCX_PARENTCLIP != 0 && window.style & WS_VISIBLE != 0 && parent & WS_VISIBLE != 0 {
            flags &= !DCX_CLIPCHILDREN;
            if parent & WS_CLIPSIBLINGS != 0 {
                flags |= DCX_CLIPSIBLINGS;
            }
        }
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

/// La région qui coupe un DC (`DCX_INTERSECTRGN`, `DCX_EXCLUDERGN`), à
/// l'écran.
#[derive(Clone, Copy, Debug)]
pub enum Clip<'a> {
    None,
    /// Une région du noyau, qui reste à l'appelant.
    Kernel(&'a Region),
    /// La région de GDI `hrgnClip` d'un client, au DC jusqu'à sa remise.
    Handle(u32),
    /// `HRGN_WINDOW` : la fenêtre, ou sa zone cliente sans `DCX_WINDOW`.
    Window,
}

/// Le rectangle de l'écran : celui de la fenêtre du bureau du thread.
fn screen() -> Rect {
    crate::convert_current_thread()
        .ok()
        .and_then(|thread| thread.desktop())
        .map(|desktop| desktop.desktop.window.state().window)
        .unwrap_or_default()
}

/// La région d'un DC de `window` (aucune : tout l'écran) pris avec `flags`
/// (`DCX_*` déjà effectifs) : ce qu'on en voit, sa zone cliente sans
/// `DCX_WINDOW`, coupé par `clip` (à l'écran, [`cut`]). Rend aussi
/// l'origine du DC.
fn visible(window: Option<&Window>, flags: u32, clip: Option<&Region>) -> (Region, (i32, i32)) {
    let Some(window) = window else { return (cut(Region::from_rect(screen()), flags, clip), (0, 0)) };
    let client = flags & DCX_WINDOW == 0;
    let region =
        crate::paint::visible_region(window, client, flags & DCX_CLIPCHILDREN != 0, flags & DCX_CLIPSIBLINGS != 0);
    let region = cut(region, flags, clip);
    let state = window.state();
    let corner = if client { state.client } else { state.window };
    (region, (corner.left, corner.top))
}

/// UserGetDCEx : un DC du cache pour `window` (aucune : tout l'écran), au
/// processus courant, coupé selon `flags` (`DCX_*`) et `clip` ; rend son
/// handle.
///
/// # Errors
/// Ceux de la création d'un DC et de l'allocation de ses attributs.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn get_dc(window: Option<&Window>, clip: Clip<'_>, flags: u32) -> Result<u32, NtStatus> {
    let styles = window.map(Styles::of);
    let flags = effective_flags(flags, styles.as_ref());
    let own_dc = styles.is_some_and(|styles| styles.class_style & (CS_OWNDC | CS_CLASSDC) != 0);
    if flags & DCX_CACHE == 0 && own_dc {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the DC of a window or of its class (a cache DC instead)", &REPORTED);
    }
    if flags & DCX_PARENTCLIP != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the parent's DC (CS_PARENTDC)", &REPORTED);
    }
    if flags & DCX_INTERSECTUPDATE != 0 && matches!(clip, Clip::None) {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("DCX_INTERSECTUPDATE (ignored)", &REPORTED);
    }
    let (region, clip_region) = match clip {
        Clip::None => (None, None),
        Clip::Kernel(region) => (Some(region.clone()), None),
        Clip::Handle(hrgn) => (crate::gdi::rgnobj::lock(hrgn).map(|object| object.get()), Some(hrgn)),
        Clip::Window => {
            let rect = window.map(|window| {
                let state = window.state();
                if flags & DCX_WINDOW == 0 {
                    state.client
                } else {
                    state.window
                }
            });
            (rect.map(Region::from_rect), None)
        }
    };
    let handle = window.map_or(0, |window| window.handle);
    let (hdc, dc) = take_cache_entry(handle, flags, clip_region)?;
    let (vis, origin) = visible(window, flags, region.as_ref());
    if let Err(status) = dc::take(hdc, &dc, vis, origin) {
        set_free(hdc);
        return Err(status);
    }
    Ok(hdc)
}

/// [`get_dc`] pour le noyau : `window`, coupée par une région du noyau.
///
/// # Errors
/// Comme [`get_dc`].
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn get_dc_ex(window: &Window, clip: Option<&Region>, flags: u32) -> Result<u32, NtStatus> {
    get_dc(Some(window), clip.map_or(Clip::None, Clip::Kernel), flags)
}

/// Un DC du cache au repos, pris pour `window` ; un neuf s'il n'y en a pas.
fn take_cache_entry(window: u32, flags: u32, clip_region: Option<u32>) -> Result<(u32, Arc<Dc>), NtStatus> {
    {
        let mut cache = CACHE.lock();
        if let Some(entry) = cache.iter_mut().find(|entry| !entry.busy) {
            (entry.window, entry.flags, entry.clip_region, entry.busy) = (window, flags, clip_region, true);
            return Ok((entry.hdc, entry.dc.clone()));
        }
    }
    let (hdc, dc) = dc::create_display_dc()?;
    CACHE.lock().push(Dce { hdc, dc: dc.clone(), window, flags, clip_region, busy: true });
    Ok((hdc, dc))
}

/// Le DC `hdc` du cache est de nouveau au repos ; rend la région d'un
/// client qui le coupait, à supprimer (DceDeleteClipRgn).
fn set_free(hdc: u32) -> Option<u32> {
    let mut cache = CACHE.lock();
    let entry = cache.iter_mut().find(|entry| entry.hdc == hdc)?;
    let cut = entry.flags & (DCX_INTERSECTRGN | DCX_EXCLUDERGN) != 0 && entry.flags & DCX_KEEPCLIPRGN == 0;
    let clip_region = entry.clip_region.take().filter(|_| cut);
    (entry.window, entry.flags, entry.busy) = (0, 0, false);
    clip_region
}

/// UserReleaseDC : le DC `hdc` du cache, pris par le processus courant,
/// retourne au repos et n'est plus à personne ; la région d'un client qui
/// le coupait est supprimée (sauf `DCX_KEEPCLIPRGN`). `false` pour un DC
/// qui n'est pas un DC du cache pris par ce processus.
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
    if dc.state().owner.map(|(pid, _)| pid) != Some(dc::current_pid()) {
        return false;
    }
    dc::give_back(hdc, &dc);
    if let Some(hrgn) = set_free(hdc) {
        crate::gdi::delete_object(hrgn);
    }
    true
}

/// Les DC du cache pris que `taken` reconnaît (leur fenêtre, le PID de leur
/// processus), et leurs handles.
fn taken_dcs(taken: impl Fn(u32, Option<u32>) -> bool) -> Vec<(u32, Arc<Dc>)> {
    CACHE
        .lock()
        .iter()
        .filter(|entry| entry.busy && taken(entry.window, entry.dc.state().owner.map(|(pid, _)| pid)))
        .map(|entry| (entry.hdc, entry.dc.clone()))
        .collect()
}

/// DceFreeWindowDCE : les DC du cache pris pour la fenêtre `hwnd`, qui est
/// détruite, retournent au repos (un GetDC sans ReleaseDC, journalisé une
/// fois). Leurs attributs et la région d'un client qui les coupait sont
/// rendus au processus courant s'ils sont à lui ; sinon, son processus les
/// garde. Rend leur nombre.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn free_window_dcs(hwnd: u32) -> usize {
    let taken = taken_dcs(|window, _| window == hwnd);
    if !taken.is_empty() {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: a window destroyed with a DC taken (GetDC without ReleaseDC)");
        }
    }
    let current = dc::current_pid();
    for (hdc, dc) in &taken {
        if dc.state().owner.is_some_and(|(pid, _)| pid == current) {
            dc::give_back(*hdc, dc);
            if let Some(hrgn) = set_free(*hdc) {
                crate::gdi::delete_object(hrgn);
            }
        } else {
            dc::disown(*hdc, dc);
            set_free(*hdc);
        }
    }
    taken.len()
}

/// Les DC du cache pris par le processus `pid`, qui se termine, retournent
/// au repos, sans toucher à sa mémoire (ses attributs et ses régions partent
/// avec elle et avec ses objets GDI). Rend leur nombre.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn free_process_dcs(pid: u32) -> usize {
    let taken = taken_dcs(|_, owner| owner == Some(pid));
    for (hdc, dc) in &taken {
        dc::disown(*hdc, dc);
        set_free(*hdc);
    }
    taken.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERASE: u32 = DCX_CACHE | DCX_USESTYLE | DCX_INTERSECTRGN | DCX_KEEPCLIPRGN;

    fn top(style: u32, class_style: u32) -> Styles {
        Styles { style, class_style, parent: None }
    }

    fn child(style: u32, class_style: u32, parent: u32) -> Styles {
        Styles { style: style | WS_CHILD, class_style, parent: Some(parent) }
    }

    #[test]
    fn the_style_says_what_clips_a_client_dc() {
        assert_eq!(effective_flags(ERASE, Some(&child(0, 0, 0))), ERASE);
        let both = effective_flags(ERASE, Some(&child(WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0)));
        assert_eq!(both, ERASE | DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS);
        let minimised = child(WS_CLIPCHILDREN | WS_MINIMIZE, 0, 0);
        assert_eq!(effective_flags(ERASE, Some(&minimised)), ERASE, "a minimised window");
        let flags = DCX_USESTYLE | DCX_CLIPCHILDREN;
        assert_eq!(effective_flags(flags, Some(&child(0, 0, 0))), DCX_USESTYLE | DCX_CACHE);
    }

    #[test]
    fn a_window_that_is_not_a_child_clips_its_siblings() {
        assert_eq!(effective_flags(ERASE, Some(&top(0, 0))), ERASE | DCX_CLIPSIBLINGS);
        let orphan = Styles { style: WS_CHILD, class_style: 0, parent: None };
        assert_eq!(effective_flags(DCX_CACHE, Some(&orphan)), DCX_CACHE | DCX_CLIPSIBLINGS, "a child without a parent");
    }

    #[test]
    fn without_a_window_the_dc_is_from_the_cache() {
        let flags = DCX_USESTYLE | DCX_WINDOW;
        assert_eq!(effective_flags(flags, None), DCX_WINDOW | DCX_CACHE | DCX_CLIPSIBLINGS);
        assert_eq!(effective_flags(DCX_PARENTCLIP, None), DCX_CACHE | DCX_CLIPSIBLINGS);
    }

    #[test]
    fn without_usestyle_the_flags_stay_but_for_the_rules() {
        let flags = DCX_CLIPCHILDREN | DCX_PARENTCLIP;
        let clipped = effective_flags(flags, Some(&child(0, CS_OWNDC, 0)));
        assert_eq!(clipped, DCX_CLIPCHILDREN | DCX_CACHE, "no parent DC for who clips its children");
        assert_eq!(effective_flags(DCX_CLIPCHILDREN, Some(&child(0, 0, 0))), DCX_CLIPCHILDREN);
        assert_eq!(effective_flags(DCX_WINDOW | DCX_CLIPCHILDREN, Some(&child(0, 0, 0))), DCX_WINDOW, "a window DC");
        let no_children = effective_flags(DCX_NOCLIPCHILDREN | DCX_CLIPCHILDREN, Some(&child(0, 0, 0)));
        assert_eq!(no_children, DCX_NOCLIPCHILDREN | DCX_CACHE);
    }

    #[test]
    fn a_window_dc_is_from_the_cache_and_clips_only_siblings() {
        let flags = DCX_WINDOW | DCX_USESTYLE;
        let window = child(WS_CLIPCHILDREN, CS_PARENTDC | CS_OWNDC, 0);
        assert_eq!(effective_flags(flags, Some(&window)), flags | DCX_CACHE);
        let siblings = child(WS_CLIPSIBLINGS, 0, 0);
        assert_eq!(effective_flags(flags, Some(&siblings)), flags | DCX_CACHE | DCX_CLIPSIBLINGS);
    }

    #[test]
    fn a_dc_is_cut_to_a_region_or_without_it() {
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
        assert_eq!(effective_flags(flags, Some(&child(0, CS_OWNDC, 0))), flags, "a DC of its own: not the cache");
        assert_eq!(effective_flags(flags, Some(&child(0, CS_CLASSDC, 0))), flags);
        let parent_dc = flags | DCX_PARENTCLIP | DCX_CACHE;
        assert_eq!(effective_flags(flags, Some(&child(0, CS_PARENTDC, 0))), parent_dc);
        let shown = child(WS_VISIBLE, CS_PARENTDC, WS_VISIBLE | WS_CLIPSIBLINGS);
        assert_eq!(effective_flags(flags, Some(&shown)), parent_dc | DCX_CLIPSIBLINGS, "the parent's siblings");
        let clipping = child(WS_CLIPSIBLINGS, CS_PARENTDC, 0);
        assert_eq!(effective_flags(flags, Some(&clipping)), flags | DCX_CACHE | DCX_CLIPSIBLINGS, "not the parent's");
        assert_eq!(effective_flags(flags, Some(&top(0, CS_PARENTDC))), flags | DCX_CACHE | DCX_CLIPSIBLINGS);
    }
}
