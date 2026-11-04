//! La peinture des fenêtres (`painting.c`, `vis.c`, `defwnd.c` de ReactOS,
//! comme spécification).
//!
//! - [`visible_region`] : ce qu'on voit d'une fenêtre (VIS_ComputeVisibleRegion) :
//!   son rectangle coupé à la zone cliente de chacun de ses parents, sans les
//!   sœurs visibles au-dessus d'elle (et de ses parents), ni, à la demande,
//!   ses enfants visibles ;
//! - [`invalidate`] (IntInvalidateWindows) : la fenêtre entière, cadre et
//!   fond, est à repeindre, et ses enfants visibles ;
//! - [`sync_and_paint`] (UserSyncAndPaintWindows, `RDW_ERASENOW`) : son cadre
//!   se repeint aussitôt (WM_NCPAINT), puis le fond de sa région à mettre à
//!   jour s'efface (WM_ERASEBKGND, avec un DC du cache coupé à elle :
//!   `DefWindowProc` de `user32` la remplit du pinceau de la classe), si
//!   aucun parent n'attend de l'être ;
//! - [`nc_paint`] (DefWindowProc de WM_NCPAINT) : le cadre se dessine
//!   ([`crate::nonclient`]) dans sa région visible, à l'écran ;
//! - [`expose`] : ce qu'une fenêtre découvre en se cachant ou en bougeant ;
//!   le bureau s'y repeint aussitôt, ses sœurs y sont invalidées
//!   (co_VIS_WindowLayoutChanged).
//!
//! La région à mettre à jour d'une fenêtre est un rectangle (celui qui
//! tient tout ce qui a été invalidé), non une région.
//!
//! Pas encore, journalisé une fois : WM_PAINT des fenêtres du client (pas
//! encore de WM_PAINT tiré de la file, ni BeginPaint : la région à mettre à
//! jour reste, effacée), les sœurs découvertes ne se repeignent qu'à leur
//! prochaine invalidation, la fenêtre active (tout cadre est inactif), les
//! fenêtres d'un autre thread (WM_NCPAINT et WM_ERASEBKGND ne leur sont pas
//! envoyés), les régions de fenêtre (SetWindowRgn) et `WS_EX_TRANSPARENT`
//! (ignoré). Le bureau n'a pas de thread : il se repeint dans le thread qui
//! le découvre.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::user::{
    color, DCX_CACHE, DCX_INTERSECTRGN, DCX_KEEPCLIPRGN, DCX_USESTYLE, HRGN_WINDOW, WM_ERASEBKGND, WM_NCPAINT,
    WNDS_ERASEBACKGROUND, WNDS_NONCPAINT, WNDS_SENDERASEBACKGROUND, WNDS_SENDNCPAINT, WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
    WS_EX_TRANSPARENT, WS_MINIMIZE, WS_VISIBLE,
};

use crate::gdi::dib::{ColorRef, Rect};
use crate::gdi::region::Region;
use crate::window::{self, LParam, Window};

/// Une fois, journalise ce que la peinture ne fait pas encore.
fn report_missing(what: &str, reported: &AtomicBool) {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: painting: {what}: not yet");
    }
}

/// Les fenêtres visibles de la liste des enfants de `parent`, dans l'ordre
/// Z, jusqu'à `until` exclu (toutes si `until` n'y est pas).
fn visible_children_until(parent: &Window, until: u32) -> Vec<Rect> {
    let mut rects = Vec::new();
    let mut child = window::get(parent.state().child);
    while let Some(current) = child {
        if current.handle == until {
            break;
        }
        let state = current.state();
        if state.style & WS_VISIBLE != 0 && state.ex_style & WS_EX_TRANSPARENT == 0 {
            rects.push(state.window);
        }
        child = window::get(state.next);
    }
    rects
}

/// VIS_ComputeVisibleRegion : ce qu'on voit de `window` (sa zone cliente si
/// `client`), à l'écran : vide si elle ou un parent est caché.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn visible_region(window: &Window, client: bool, clip_children: bool, clip_siblings: bool) -> Region {
    let state = window.state();
    if state.style & WS_VISIBLE == 0 {
        return Region::default();
    }
    let mut region = Region::from_rect(if client { state.client } else { state.window });
    let mut previous = (window.handle, state.style);
    let mut current = window::get(state.parent);
    while let Some(parent) = current {
        let parent_state = parent.state();
        if parent_state.style & WS_VISIBLE == 0 {
            return Region::default();
        }
        region.intersect_rect(parent_state.client);
        if previous.1 & WS_CLIPSIBLINGS != 0 || (previous.0 == window.handle && clip_siblings) {
            for above in visible_children_until(&parent, previous.0) {
                region.subtract_rect(above);
            }
        }
        previous = (parent.handle, parent_state.style);
        current = window::get(parent_state.parent);
    }
    if clip_children {
        for child in visible_children_until(window, 0) {
            region.subtract_rect(child);
        }
    }
    region
}

/// IntInvalidateWindows(`RDW_INVALIDATE | RDW_ERASE | RDW_FRAME |
/// RDW_ALLCHILDREN`) sur toute la fenêtre : son cadre (`WNDS_SENDNCPAINT`)
/// et sa zone cliente, à effacer, sont à repeindre ; de même pour ses
/// enfants visibles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn invalidate(window: &Window) {
    let state = window::change(window, |state| {
        state.state &= !WNDS_NONCPAINT;
        state.state |= WNDS_SENDNCPAINT;
        let client = state.client;
        state.invalidate(Rect::new(0, 0, client.right - client.left, client.bottom - client.top), true);
    });
    if state.style & WS_MINIMIZE != 0 {
        return;
    }
    let mut child = window::get(state.child);
    while let Some(current) = child {
        let child_state = current.state();
        if child_state.style & WS_VISIBLE != 0 {
            invalidate(&current);
        }
        child = window::get(child_state.next);
    }
}

/// co_IntPaintWindows(`RDW_ERASENOW`) pour `window` seule : un cadre à
/// repeindre l'est (WM_NCPAINT, dans le thread de la fenêtre), puis le fond
/// à effacer ([`erase_background`]).
fn paint_windows(window: &Arc<Window>) {
    let state = window.state();
    if state.state & (WNDS_SENDNCPAINT | WNDS_SENDERASEBACKGROUND) == 0 {
        return;
    }
    if state.style & WS_VISIBLE == 0 {
        window::change(window, |state| {
            state.state &= !(WNDS_SENDNCPAINT | WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
        });
        return;
    }
    if state.update.is_empty() {
        window::change(window, |state| state.state &= !(WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND));
    }
    let Ok(thread) = crate::convert_current_thread() else { return };
    if thread.server != window.pti {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("painting a window of another thread", &REPORTED);
        return;
    }
    if state.state & WNDS_SENDNCPAINT != 0 {
        // IntSendNCPaint: the whole frame.
        window::change(window, |state| state.state &= !WNDS_SENDNCPAINT);
        let _ = window::send_message(window, WM_NCPAINT, HRGN_WINDOW, LParam::Value(0));
    }
    if window.state().state & WNDS_SENDERASEBACKGROUND != 0 {
        erase_background(window);
    }
}

/// co_IntPaintWindows : le fond de la région à mettre à jour de `window`
/// s'efface (WM_ERASEBKGND, avec un DC du cache coupé à elle,
/// `DCX_INTERSECTRGN`) ; une fenêtre qui ne l'efface pas (elle rend 0)
/// garde son fond à effacer. Les appels de GDI qu'elle met en lot sont
/// exécutés au retour du rappel, avant que le DC soit rendu.
fn erase_background(window: &Arc<Window>) {
    let state = window.state();
    if state.update.is_empty() {
        return;
    }
    let (dx, dy) = (state.client.left, state.client.top);
    let update = state.update;
    let update = Region::from_rect(Rect::new(update.left + dx, update.top + dy, update.right + dx, update.bottom + dy));
    let flags = DCX_CACHE | DCX_USESTYLE | DCX_INTERSECTRGN | DCX_KEEPCLIPRGN;
    let hdc = match crate::dce::get_dc_ex(window, Some(&update), flags) {
        Ok(hdc) => hdc,
        Err(status) => {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("win32k: no DC to erase a window's background ({status:?})");
            }
            return;
        }
    };
    window::change(window, |state| state.state &= !(WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND));
    let erased = window::send_message(window, WM_ERASEBKGND, hdc, LParam::Value(0));
    if !matches!(erased, Ok(result) if result != 0) {
        window::change(window, |state| state.state |= WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
    }
    crate::dce::release_dc(hdc);
}

/// UserSyncAndPaintWindows(`RDW_ERASENOW`) : si aucun parent (jusqu'au
/// premier à `WS_CLIPCHILDREN`) n'attend d'être repeint, `window` se
/// repeint aussitôt.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn sync_and_paint(window: &Arc<Window>) {
    let mut parent = window::get(window.state().parent);
    while let Some(current) = parent {
        let state = current.state();
        if state.style & WS_CLIPCHILDREN != 0 {
            break;
        }
        if !state.update.is_empty() {
            return;
        }
        parent = window::get(state.parent);
    }
    paint_windows(window);
}

/// La couleur système `index`.
fn system_color(index: usize) -> ColorRef {
    ColorRef(crate::metrics::SYSTEM_COLORS.get(index).copied().unwrap_or(0))
}

/// DefWindowProc de WM_NCPAINT (NC_DoNCPaint) : le cadre de `window`, dans
/// sa région visible (`hrgn` : `HRGN_WINDOW`, la fenêtre entière ; une autre
/// région, pas encore, compte pour elle). Rien pour une fenêtre invisible ou
/// sans cadre.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn nc_paint(window: &Window, hrgn: u32) {
    let state = window.state();
    if !window::is_visible(window) || state.window == state.client {
        return;
    }
    if hrgn != HRGN_WINDOW {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("WM_NCPAINT for a part of the frame (region handles)", &REPORTED);
    }
    let size = (state.window.right - state.window.left, state.window.bottom - state.window.top);
    // No active window yet: every frame is inactive.
    let (ops, unpainted) = crate::nonclient::frame_ops(
        state.style,
        state.ex_style,
        size,
        false,
        true,
        &crate::metrics::get,
        &system_color,
    );
    if unpainted.text || unpainted.icon {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the caption's text, icon and button symbols (fonts, icons)", &REPORTED);
    }
    if unpainted.scroll_bars {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("scroll bars", &REPORTED);
    }
    let clip = visible_region(window, false, state.style & WS_CLIPCHILDREN != 0, state.style & WS_CLIPSIBLINGS != 0);
    let origin = (state.window.left, state.window.top);
    crate::display::draw(|screen| crate::gdi::draw::paint(screen, &ops, origin, &clip));
}

/// Ce que `window` découvre (`exposed`, à l'écran) en se cachant ou en
/// bougeant (co_VIS_WindowLayoutChanged) : le bureau s'y repeint aussitôt,
/// les autres enfants de son parent qui y sont visibles sont invalidés.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn expose(window: &Window, exposed: &Region) {
    if exposed.is_empty() {
        return;
    }
    let Some(parent) = window::get(window.state().parent) else { return };
    let mut child = window::get(parent.state().child);
    while let Some(current) = child {
        let state = current.state();
        if current.handle != window.handle
            && state.style & WS_VISIBLE != 0
            && exposed.rects().iter().any(|r| !r.intersect(&state.window).is_empty())
        {
            invalidate(&current);
        }
        child = window::get(state.next);
    }
    if !parent.is_desktop_window() {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("erasing what a child window uncovers in its parent", &REPORTED);
        return;
    }
    // What of the desktop shows there now: not under a visible window.
    let uncovered = exposed.intersect(&visible_region(&parent, true, true, false));
    let background = system_color(color::BACKGROUND);
    crate::display::draw(|screen| {
        for &rect in uncovered.rects() {
            screen.fill_rect(rect, background);
        }
    });
}
