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
//!   (co_VIS_WindowLayoutChanged) ;
//! - WM_PAINT : une fenêtre visible qui a une région à mettre à jour compte
//!   pour son thread ([`count_paint`], `QS_PAINT`) ; PeekMessage et
//!   GetMessage lui donnent WM_PAINT ([`paint_message`]) tant qu'elle n'est
//!   pas validée, par BeginPaint ([`begin_paint`] : cadre, DC coupé à la
//!   région, WM_ERASEBKGND) et EndPaint ([`end_paint`]), que fait
//!   DefWindowProc ([`def_paint`]).
//!
//! La région à mettre à jour d'une fenêtre est un rectangle (celui qui
//! tient tout ce qui a été invalidé), non une région.
//!
//! Le cadre est peint actif ou inactif selon `WNDS_ACTIVEFRAME`
//! ([`set_frame_active`], WM_NCACTIVATE).
//!
//! Pas encore, journalisé une fois : les fenêtres d'un autre thread (WM_NCPAINT et WM_ERASEBKGND ne
//! leur sont pas envoyés aussitôt ; WM_PAINT leur vient de leur file), les
//! régions de fenêtre (SetWindowRgn), et sans journal : `WS_EX_TRANSPARENT`
//! (ignoré, sauf pour l'ordre de WM_PAINT), InvalidateRect, ValidateRect,
//! RedrawWindow, UpdateWindow et GetUpdateRect du client, le curseur caché
//! pendant BeginPaint. Le bureau n'a pas de thread : il se repeint dans le
//! thread qui le découvre.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::NULLREGION;
use abi::user::{
    color, Msg32, PaintStruct32, Rect32, CS_PARENTDC, DCX_CACHE, DCX_INTERSECTRGN, DCX_KEEPCLIPRGN, DCX_USESTYLE,
    HRGN_WINDOW, RDW_ALLCHILDREN, RDW_ERASE, RDW_ERASENOW, RDW_FRAME, RDW_INTERNALPAINT, RDW_INVALIDATE,
    RDW_NOCHILDREN, RDW_NOERASE, RDW_NOFRAME, RDW_NOINTERNALPAINT, RDW_NOUPDATEDIRTY, RDW_UPDATENOW, RDW_VALIDATE,
    WM_ERASEBKGND, WM_NCPAINT, WM_PAINT, WNDS2_ENDPAINTINVALIDATE, WNDS2_STARTPAINT, WNDS2_WMPAINTSENT,
    WNDS_ACTIVEFRAME, WNDS_ERASEBACKGROUND, WNDS_INTERNALPAINT, WNDS_NONCPAINT, WNDS_PAINTNOTPROCESSED,
    WNDS_SENDERASEBACKGROUND, WNDS_SENDNCPAINT, WNDS_UPDATEDIRTY, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_EX_TRANSPARENT,
    WS_MINIMIZE, WS_VISIBLE,
};

use crate::gdi::dib::{ColorRef, Rect};
use crate::gdi::region::Region;
use crate::gui::ThreadInfo;
use crate::queue::Filter;
use crate::window::{self, LParam, Window, WindowState};

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
    let whole = Region::from_rect(window.state().window);
    invalidate_windows(window, Some(&whole), RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
}

/// La partie de `region` (à l'écran) dans la zone cliente de `state`, depuis
/// son coin.
fn client_part(state: &WindowState, region: &Region) -> Region {
    let mut part = region.clone();
    part.intersect_rect(state.client);
    part.offset(-state.client.left, -state.client.top);
    part
}

/// IntInvalidateWindows : `region` (à l'écran ; `None` : aucune, pour les
/// seuls drapeaux) est à repeindre (`RDW_INVALIDATE`, avec `RDW_FRAME` le
/// cadre, `RDW_ERASE` le fond ; `RDW_INTERNALPAINT` : WM_PAINT sans rien à
/// peindre) ou ne l'est plus (`RDW_VALIDATE`, `RDW_NOFRAME`, `RDW_NOERASE`,
/// `RDW_NOINTERNALPAINT`), coupée à la fenêtre (et à sa zone cliente sans
/// `RDW_FRAME`). Ses enfants visibles suivent, sauf `RDW_NOCHILDREN`, et
/// sauf ceux d'une fenêtre à `WS_CLIPCHILDREN` sans `RDW_ALLCHILDREN`. Une
/// fenêtre invalidée par un autre thread que le sien l'est
/// « salement » (`WNDS_UPDATEDIRTY`) : sans `RDW_NOUPDATEDIRTY`, une
/// validation ne la touche pas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn invalidate_windows(window: &Window, region: Option<&Region>, flags: u32) {
    let mut flags = flags;
    let state = window.state();
    let region = region.map(|region| {
        let mut region = region.clone();
        if flags & RDW_INVALIDATE != 0 && flags & RDW_FRAME == 0 {
            region.intersect_rect(state.client);
        }
        region.intersect_rect(state.window);
        region
    });
    if flags & RDW_INVALIDATE != 0 && region.as_ref().is_none_or(Region::is_empty) {
        return;
    }
    if flags & (RDW_INVALIDATE | RDW_INTERNALPAINT | RDW_ERASE | RDW_FRAME) != 0 {
        let other_thread = !same_thread(window);
        window::change(window, |state| {
            if flags & RDW_INTERNALPAINT != 0 {
                state.state |= WNDS_INTERNALPAINT;
            }
            if flags & RDW_INVALIDATE != 0 {
                state.state &= !WNDS_NONCPAINT;
                if other_thread {
                    state.state |= WNDS_UPDATEDIRTY;
                    if state.state2 & WNDS2_WMPAINTSENT != 0 {
                        state.state2 |= WNDS2_ENDPAINTINVALIDATE;
                    }
                }
                if flags & RDW_FRAME != 0 {
                    state.state |= WNDS_SENDNCPAINT;
                }
                if flags & RDW_ERASE != 0 {
                    state.state |= WNDS_SENDERASEBACKGROUND;
                }
                if let Some(region) = &region {
                    for &rect in client_part(state, region).rects() {
                        state.update.union_rect(rect);
                    }
                }
            }
        });
        // For the children.
        flags |= RDW_ERASE | RDW_FRAME;
    } else if flags & (RDW_VALIDATE | RDW_NOINTERNALPAINT | RDW_NOERASE | RDW_NOFRAME) != 0 {
        if state.state & WNDS_UPDATEDIRTY != 0 && flags & RDW_NOUPDATEDIRTY == 0 {
            return;
        }
        window::change(window, |state| {
            if flags & RDW_NOINTERNALPAINT != 0 {
                state.state &= !WNDS_INTERNALPAINT;
            }
            if flags & RDW_VALIDATE != 0 {
                if flags & RDW_NOFRAME != 0 {
                    state.state &= !WNDS_SENDNCPAINT;
                }
                if flags & RDW_NOERASE != 0 {
                    state.state &= !(WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
                }
                if let Some(region) = &region {
                    let validated = client_part(state, region);
                    state.update.subtract(&validated);
                }
                if state.update.is_empty() {
                    state.state &= !(WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
                }
            }
        });
    }
    let state = window.state();
    if flags & RDW_NOCHILDREN != 0
        || state.style & WS_MINIMIZE != 0
        || (flags & RDW_ALLCHILDREN == 0 && state.style & WS_CLIPCHILDREN != 0)
    {
        return;
    }
    let mut child = window::get(state.child);
    while let Some(current) = child {
        let child_state = current.state();
        if child_state.style & WS_VISIBLE != 0 {
            invalidate_windows(&current, region.as_ref(), flags);
        }
        child = window::get(child_state.next);
    }
}

/// IntIsWindowDrawable : `window` et ses parents sont visibles, et aucun
/// parent n'est réduit.
fn is_drawable(window: &Window) -> bool {
    let state = window.state();
    if state.style & WS_VISIBLE == 0 {
        return false;
    }
    let mut parent = window::get(state.parent);
    while let Some(current) = parent {
        let state = current.state();
        if state.style & WS_VISIBLE == 0 || state.style & WS_MINIMIZE != 0 {
            return false;
        }
        parent = window::get(state.parent);
    }
    true
}

/// co_UserRedrawWindow : `region`, sinon `rect` (dans la zone cliente ;
/// aucun : la zone cliente, ou la fenêtre avec `RDW_INVALIDATE | RDW_FRAME`
/// ou `RDW_VALIDATE | RDW_NOFRAME`) de `window` est invalidé ou validé selon
/// `flags` ([`invalidate_windows`]), puis la fenêtre se peint aussitôt
/// (`RDW_UPDATENOW` : WM_PAINT envoyé, [`update_windows`]) ou seulement son
/// cadre et son fond (`RDW_ERASENOW`). Rien pour une fenêtre qu'on ne voit
/// pas.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn redraw_window(window: &Arc<Window>, rect: Option<Rect>, region: Option<&Region>, flags: u32) {
    if !is_drawable(window) {
        return;
    }
    let state = window.state();
    let (dx, dy) = if window.is_desktop_window() { (0, 0) } else { (state.client.left, state.client.top) };
    let region = if flags & (RDW_INVALIDATE | RDW_VALIDATE) == 0 {
        None
    } else if let Some(region) = region {
        Some(region.offset_by(dx, dy))
    } else if let Some(rect) = rect {
        Some(Region::from_rect(Rect::new(
            rect.left.saturating_add(dx),
            rect.top.saturating_add(dy),
            rect.right.saturating_add(dx),
            rect.bottom.saturating_add(dy),
        )))
    } else if flags & (RDW_INVALIDATE | RDW_FRAME) == RDW_INVALIDATE | RDW_FRAME
        || flags & (RDW_VALIDATE | RDW_NOFRAME) == RDW_VALIDATE | RDW_NOFRAME
    {
        Some(Region::from_rect(state.window))
    } else {
        Some(Region::from_rect(state.client))
    };
    if flags & (RDW_INVALIDATE | RDW_VALIDATE | RDW_INTERNALPAINT | RDW_NOINTERNALPAINT) != 0 {
        invalidate_windows(window, region.as_ref(), flags);
    }
    if flags & RDW_UPDATENOW != 0 {
        update_windows(window, flags);
    } else if flags & RDW_ERASENOW != 0 {
        sync_and_paint(window);
    }
}

/// UserUpdateWindows : `window` se peint (WM_PAINT envoyé, [`update_window`]),
/// sauf une fenêtre `WS_EX_TRANSPARENT` dont une sœur suivante du même thread
/// a à se peindre.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn update_windows(window: &Arc<Window>, flags: u32) {
    let state = window.state();
    if state.ex_style & WS_EX_TRANSPARENT != 0 {
        let mut next = window::get(state.next);
        while let Some(current) = next {
            let next_state = current.state();
            if current.pti == window.pti
                && (!next_state.update.is_empty() || next_state.state & WNDS_INTERNALPAINT != 0)
            {
                return;
            }
            next = window::get(next_state.next);
        }
    }
    update_window(window, flags);
}

/// co_IntUpdateWindows (UpdateWindow : `RDW_ALLCHILDREN`) : une fenêtre qui
/// a quelque chose à peindre reçoit WM_PAINT aussitôt (sa partie dans la
/// région à mettre à jour de ses parents qui ne coupent pas leurs enfants y
/// est validée, IntValidateParents) ; une procédure qui n'appelle pas
/// BeginPaint voit son cadre et son fond repeints. Puis ses enfants
/// visibles, sauf `RDW_NOCHILDREN`.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn update_window(window: &Arc<Window>, flags: u32) {
    let state = window.state();
    if !state.update.is_empty() || state.state & WNDS_INTERNALPAINT != 0 {
        if !state.update.is_empty() {
            validate_parents(window);
        }
        window::change(window, |state| {
            state.state &= !(WNDS_INTERNALPAINT | WNDS_UPDATEDIRTY);
            state.state |= WNDS_PAINTNOTPROCESSED;
            state.state2 |= WNDS2_WMPAINTSENT;
        });
        let _ = window::send_message(window, WM_PAINT, 0, LParam::Value(0));
        if window.state().state & WNDS_PAINTNOTPROCESSED != 0 {
            paint_windows(window);
        }
    }
    if flags & RDW_NOCHILDREN != 0 || window.is_desktop_window() {
        return;
    }
    let mut child = window::get(window.state().child);
    while let Some(current) = child {
        let child_state = current.state();
        let dirty = |state: &WindowState| !state.update.is_empty() || state.state & WNDS_INTERNALPAINT != 0;
        // A transparent child waits for an opaque sibling after it to paint.
        let skip = child_state.ex_style & WS_EX_TRANSPARENT != 0 && dirty(&child_state) && {
            let mut next = window::get(child_state.next);
            let mut found = false;
            while let Some(other) = next {
                let other_state = other.state();
                if dirty(&other_state) {
                    found = true;
                    break;
                }
                next = window::get(other_state.next);
            }
            found
        };
        if !skip && child_state.style & WS_VISIBLE != 0 {
            update_window(&current, RDW_ALLCHILDREN);
        }
        child = window::get(child_state.next);
    }
}

/// IntIntersectWithParents : `rect` (à l'écran) coupé aux zones clientes
/// des parents de `window` ; `None` si un parent est caché ou réduit, ou
/// si rien n'en reste.
fn intersect_with_parents(window: &Window, rect: Rect) -> Option<Rect> {
    let mut rect = rect;
    let mut parent = window::get(window.state().parent);
    while let Some(current) = parent {
        let state = current.state();
        rect = rect.intersect(&state.client);
        if state.style & WS_VISIBLE == 0 || state.style & WS_MINIMIZE != 0 || rect.is_empty() {
            return None;
        }
        parent = window::get(state.parent);
    }
    Some(rect)
}

/// IntValidateParents : la partie de `window` qu'on voit dans ses parents
/// est validée dans la région à mettre à jour de ceux qui ne coupent pas
/// leurs enfants (jusqu'au premier à `WS_CLIPCHILDREN`). Sans
/// `WNDS_SYNCPAINTPENDING` (pas encore), toujours.
fn validate_parents(window: &Window) {
    let Some(rect) = intersect_with_parents(window, window.state().window) else { return };
    let region = Region::from_rect(rect);
    let mut parent = window::get(window.state().parent);
    while let Some(current) = parent {
        let state = current.state();
        if state.style & WS_CLIPCHILDREN != 0 {
            break;
        }
        if !state.update.is_empty() {
            invalidate_windows(&current, Some(&region), RDW_VALIDATE | RDW_NOCHILDREN | RDW_NOUPDATEDIRTY);
        }
        parent = window::get(state.parent);
    }
}

/// co_UserGetUpdateRect : le rectangle qui tient la région à mettre à jour
/// de `window` (dans sa zone cliente, coupé à elle et à ses parents ; vide
/// si un parent la cache), ou `None` sans région. `erase` : son cadre et
/// son fond se repeignent d'abord s'il le faut.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn get_update_rect(window: &Arc<Window>, erase: bool) -> Option<Rect> {
    if erase {
        paint_windows(window);
    }
    let state = window::change(window, |state| state.state &= !WNDS_UPDATEDIRTY);
    if state.update.is_empty() {
        return None;
    }
    let bounds = state.update.bounds();
    let (dx, dy) = (state.client.left, state.client.top);
    let on_screen = Rect::new(bounds.left + dx, bounds.top + dy, bounds.right + dx, bounds.bottom + dy);
    let Some(rect) = intersect_with_parents(window, on_screen.intersect(&state.client)) else {
        return Some(Rect::default());
    };
    if window.is_desktop_window() {
        return Some(rect);
    }
    Some(Rect::new(rect.left - dx, rect.top - dy, rect.right - dx, rect.bottom - dy))
}

/// co_UserGetUpdateRgn : la région à mettre à jour de `window` (dans sa
/// zone cliente, coupée à elle et à ses parents ; vide si un parent la
/// cache), ou `None` sans région. `erase` : son cadre et son fond se
/// repeignent d'abord s'il le faut.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn get_update_region(window: &Arc<Window>, erase: bool) -> Option<Region> {
    if erase {
        paint_windows(window);
    }
    let state = window::change(window, |state| state.state &= !WNDS_UPDATEDIRTY);
    if state.update.is_empty() {
        return None;
    }
    let (dx, dy) = (state.client.left, state.client.top);
    let Some(visible) = intersect_with_parents(window, state.client) else { return Some(Region::default()) };
    let mut region = state.update.offset_by(dx, dy);
    region.intersect_rect(visible);
    if !window.is_desktop_window() {
        region.offset(-dx, -dy);
    }
    Some(region)
}

/// IntIsWindowDirty : la fenêtre a quelque chose à peindre (visible, avec
/// une région à mettre à jour ou WM_PAINT demandé, `WNDS_INTERNALPAINT`).
pub fn is_dirty(state: &WindowState) -> bool {
    state.style & WS_VISIBLE != 0 && (!state.update.is_empty() || state.state & WNDS_INTERNALPAINT != 0)
}

/// MsqIncPaintCountQueue (`dirty`) ou MsqDecPaintCountQueue : `window` a
/// désormais quelque chose à peindre, ou ne l'a plus, pour le compte de son
/// thread. [`window::change`] l'appelle à chaque changement : le compte
/// reste celui des fenêtres à peindre (ReactOS le tient aux mêmes endroits
/// qu'ici, sauf quand une fenêtre se cache, et le remet à zéro quand il ne
/// trouve plus de fenêtre). Rien pour la fenêtre du bureau, sans thread.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn count_paint(window: &Window, dirty: bool) {
    let Some(thread) = crate::gui::thread_info_of(window.pti) else { return };
    if dirty {
        crate::queue::inc_paint(&thread);
    } else {
        crate::queue::dec_paint(&thread);
    }
}

/// IntSendNCPaint (`HRGN_WINDOW`) : le cadre entier de `window` se repeint
/// (WM_NCPAINT).
fn send_nc_paint(window: &Arc<Window>) {
    window::change(window, |state| state.state &= !WNDS_SENDNCPAINT);
    let _ = window::send_message(window, WM_NCPAINT, HRGN_WINDOW, LParam::Value(0));
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
    if window.is_desktop_window() {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the desktop window's background on request (RedrawWindow, InvalidateRect of NULL)", &REPORTED);
        return;
    }
    let Ok(thread) = crate::convert_current_thread() else { return };
    if thread.server != window.pti {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("painting a window of another thread", &REPORTED);
        return;
    }
    if state.state & WNDS_SENDNCPAINT != 0 {
        send_nc_paint(window);
    }
    if window.state().state & WNDS_SENDERASEBACKGROUND != 0 {
        erase_background(window);
    }
}

/// IntPaintWindow : WM_PAINT n'a pas appelé BeginPaint
/// (`WNDS_PAINTNOTPROCESSED` après IntDispatchMessage) : le cadre et le
/// fond se repeignent s'il le faut ; rien n'est validé.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn paint_window(window: &Arc<Window>) {
    paint_windows(window);
}

/// La région à mettre à jour de `state`, à l'écran ; `None` s'il n'y en a pas.
fn update_on_screen(state: &WindowState) -> Option<Region> {
    let mut update = state.update.clone();
    update.offset(state.client.left, state.client.top);
    (!update.is_empty()).then_some(update)
}

/// IntBeginPaint : `window` se peint. Son cadre se repeint s'il le faut
/// (WM_NCPAINT) ; un DC du cache coupé à sa région à mettre à jour est
/// pris, et cette région validée (rien à peindre : un DC qui ne peint
/// rien) ; le fond s'efface s'il le faut (WM_ERASEBKGND : `fErase` dit
/// qu'il reste à effacer), puis le cadre de ses enfants qui n'ont rien
/// d'autre à repeindre. Rend le `PAINTSTRUCT` (`hdc` nul sans DC).
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn begin_paint(window: &Arc<Window>) -> PaintStruct32 {
    let state = window::change(window, |state| {
        state.state2 |= WNDS2_STARTPAINT;
        state.state &= !(WNDS_PAINTNOTPROCESSED | WNDS_UPDATEDIRTY);
    });
    if state.state & WNDS_SENDNCPAINT != 0 {
        send_nc_paint(window);
    }
    let state = window.state();
    let mut ps = PaintStruct32::default();
    let Ok(hdc) = crate::dce::get_dc_ex(window, update_on_screen(&state).as_ref(), DCX_INTERSECTRGN | DCX_USESTYLE)
    else {
        return ps;
    };
    ps.hdc = hdc;
    let mut erase = false;
    window::change(window, |state| {
        if state.state & WNDS_SENDERASEBACKGROUND != 0 {
            state.state &= !(WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
            erase = true;
        }
        // Validated: the region is the DC's now.
        state.update = Region::default();
        state.state &= !WNDS_INTERNALPAINT;
    });
    let (complexity, paint) =
        crate::gdi::dc::lock(hdc).map_or((NULLREGION, Rect::default()), |dc| crate::gdi::dc::clip_box(&dc.state()));
    ps.paint = Rect32 { left: paint.left, top: paint.top, right: paint.right, bottom: paint.bottom };
    let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
    let client = state.client;
    let client = Rect::new(0, 0, client.right - client.left, client.bottom - client.top);
    if erase && complexity != NULLREGION && (class_style & CS_PARENTDC == 0 || !client.intersect(&paint).is_empty()) {
        let erased = window::send_message(window, WM_ERASEBKGND, hdc, LParam::Value(0));
        if !matches!(erased, Ok(result) if result != 0) {
            ps.erase = 1;
            window::change(window, |state| state.state |= WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
        }
    }
    send_child_nc_paint(window);
    ps
}

/// IntSendChildNCPaint : les enfants de `window` dont seul le cadre est à
/// repeindre le repeignent (ceux de son thread).
fn send_child_nc_paint(window: &Window) {
    let mut child = window::get(window.state().child);
    while let Some(current) = child {
        let state = current.state();
        if state.update.is_empty() && state.state & WNDS_SENDNCPAINT != 0 && same_thread(&current) {
            send_nc_paint(&current);
        }
        child = window::get(state.next);
    }
}

/// `window` est du thread courant.
fn same_thread(window: &Window) -> bool {
    crate::convert_current_thread().is_ok_and(|thread| thread.server == window.pti)
}

/// IntEndPaint : le DC de BeginPaint `hdc` est rendu ; `window` a fini de se
/// peindre.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn end_paint(window: &Window, hdc: u32) {
    crate::dce::release_dc(hdc);
    window::change(window, |state| state.state2 &= !(WNDS2_WMPAINTSENT | WNDS2_STARTPAINT));
}

/// DefWindowProc de WM_PAINT : BeginPaint puis EndPaint, ce qui valide la
/// fenêtre (son fond effacé s'il le faut) ; rien entre BeginPaint et
/// EndPaint d'une fenêtre qui a une zone cliente.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir. Rappelle le mode utilisateur.
pub fn def_paint(window: &Arc<Window>) {
    let state = window.state();
    if state.state2 & WNDS2_STARTPAINT != 0 && !state.client.is_empty() {
        return;
    }
    let ps = begin_paint(window);
    if ps.hdc != 0 {
        end_paint(window, ps.hdc);
    }
}

/// IntFindWindowToRepaint : la première fenêtre du thread `pti` qui a
/// quelque chose à peindre, de `first` et des sœurs qui la suivent dans
/// l'ordre Z, puis de leurs enfants ; une fenêtre `WS_EX_TRANSPARENT` passe
/// après ses sœurs opaques à peindre.
pub fn find_window_to_repaint(first: Option<Arc<Window>>, pti: u32) -> Option<Arc<Window>> {
    let mut current = first;
    while let Some(window) = current {
        let state = window.state();
        if window.pti == pti && is_dirty(&state) {
            if state.ex_style & WS_EX_TRANSPARENT != 0 {
                let mut sibling = window::get(state.next);
                while let Some(other) = sibling {
                    let other_state = other.state();
                    if other_state.ex_style & WS_EX_TRANSPARENT == 0 && other.pti == pti && is_dirty(&other_state) {
                        return Some(other);
                    }
                    sibling = window::get(other_state.next);
                }
            }
            return Some(window);
        }
        if let Some(found) = find_window_to_repaint(window::get(state.child), pti) {
            return Some(found);
        }
        current = window::get(state.next);
    }
    None
}

/// `ancestor` est `window` ou l'un de ses parents.
fn is_or_has_parent(window: &Window, ancestor: u32) -> bool {
    if window.handle == ancestor {
        return true;
    }
    let mut parent = window::get(window.state().parent);
    while let Some(current) = parent {
        if current.handle == ancestor {
            return true;
        }
        parent = window::get(current.state().parent);
    }
    false
}

/// `filter` demande WM_PAINT : tous les messages, ou un intervalle qui le
/// tient ; pas les messages du seul thread (`hWnd` à -1).
pub fn wants_paint(filter: &Filter) -> bool {
    filter.hwnd != u32::MAX && ((filter.min == 0 && filter.max == 0) || (filter.min..=filter.max).contains(&WM_PAINT))
}

/// IntGetPaintMessage : WM_PAINT pour la première fenêtre du thread
/// `thread` qui a quelque chose à peindre, si `filter` le demande (sa
/// fenêtre ou l'un de ses parents ; pas les messages du seul thread). Il ne
/// sort pas de la file : la fenêtre en reçoit un tant qu'elle n'est pas
/// validée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn paint_message(thread: &ThreadInfo, filter: &Filter) -> Option<Msg32> {
    if !wants_paint(filter) {
        return None;
    }
    let desktop = thread.desktop()?.desktop.window.clone();
    let found = find_window_to_repaint(Some(desktop), thread.server)?;
    if filter.hwnd != 0 && !is_or_has_parent(&found, filter.hwnd) {
        return None;
    }
    window::change(&found, |state| {
        state.state &= !(WNDS_INTERNALPAINT | WNDS_UPDATEDIRTY);
        state.state2 &= !WNDS2_STARTPAINT;
    });
    // WNDS2_WMPAINTSENT unless every parent clips its children.
    let mut parent = window::get(found.state().parent);
    while let Some(current) = parent {
        if current.is_desktop_window() {
            break;
        }
        let state = current.state();
        if state.style & WS_CLIPCHILDREN == 0 {
            window::change(&found, |state| state.state2 |= WNDS2_WMPAINTSENT);
        }
        parent = window::get(state.parent);
    }
    Some(Msg32 { hwnd: found.handle, message: WM_PAINT, ..Msg32::default() })
}

/// co_IntPaintWindows : le fond de la région à mettre à jour de `window`
/// s'efface (WM_ERASEBKGND, avec un DC du cache coupé à elle,
/// `DCX_INTERSECTRGN`) ; une fenêtre qui ne l'efface pas (elle rend 0)
/// garde son fond à effacer. Les appels de GDI qu'elle met en lot sont
/// exécutés au retour du rappel, avant que le DC soit rendu.
fn erase_background(window: &Arc<Window>) {
    let Some(update) = update_on_screen(&window.state()) else { return };
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

/// NC_HandleNCActivate : le cadre de `window` devient actif ou inactif
/// (`WNDS_ACTIVEFRAME`) et, s'il a changé et que `repaint`, il est peint de
/// nouveau. Rend s'il a changé.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_frame_active(window: &Window, active: bool, repaint: bool) -> bool {
    let before = window.state().state;
    let after = if active { before | WNDS_ACTIVEFRAME } else { before & !WNDS_ACTIVEFRAME };
    if before == after {
        return false;
    }
    window::change(window, |state| state.state = after);
    if repaint {
        nc_paint(window, HRGN_WINDOW);
    }
    true
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
    let text = window::text(window).unwrap_or_default();
    let menu_items = window::menu_items(window);
    let (ops, unpainted) = crate::nonclient::frame_ops(
        state.style,
        state.ex_style,
        size,
        &text,
        &menu_items,
        state.state & WNDS_ACTIVEFRAME != 0,
        true,
        &crate::metrics::get,
        &system_color,
        &crate::font::text_run_named,
        crate::cursor::caption_icon(window),
    );
    if unpainted.text {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the caption's text and button symbols without their fonts", &REPORTED);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_visible_window_with_something_to_paint_is_dirty() {
        let mut state = WindowState { style: WS_VISIBLE, ..WindowState::default() };
        assert!(!is_dirty(&state), "nothing to paint");
        state.invalidate(Rect::new(0, 0, 10, 10), false);
        assert!(!is_dirty(&state), "no client area: nothing invalidated");
        state.client = Rect::new(100, 100, 200, 150);
        state.invalidate(Rect::new(0, 0, 10, 10), false);
        assert!(is_dirty(&state), "an update region");
        state.style = 0;
        assert!(!is_dirty(&state), "hidden");
        state = WindowState { style: WS_VISIBLE, state: WNDS_INTERNALPAINT, ..WindowState::default() };
        assert!(is_dirty(&state), "WM_PAINT asked (RDW_INTERNALPAINT)");
    }

    #[test]
    fn a_screen_region_becomes_client_coordinates() {
        let state = WindowState {
            window: Rect::new(96, 77, 304, 254),
            client: Rect::new(100, 100, 300, 250),
            ..WindowState::default()
        };
        let mut region = Region::from_rect(Rect::new(90, 90, 120, 110));
        region.union_rect(Rect::new(290, 240, 400, 400));
        let part = client_part(&state, &region);
        assert_eq!(part.bounds(), Rect::new(0, 0, 200, 150), "the client area's corner at 0, 0");
        assert_eq!(part.area(), 20 * 10 + 10 * 10, "only what lies in the client area");
        assert!(client_part(&state, &Region::from_rect(Rect::new(96, 77, 304, 99))).is_empty(), "the caption");
    }

    #[test]
    fn wm_paint_comes_to_filters_that_hold_it() {
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        assert!(wants_paint(&all));
        assert!(wants_paint(&Filter { hwnd: 0x0002_0020, ..all }), "a window: it or a child of it");
        assert!(!wants_paint(&Filter { hwnd: u32::MAX, ..all }), "the thread's messages only");
        assert!(wants_paint(&Filter { min: WM_PAINT, max: WM_PAINT, ..all }));
        assert!(wants_paint(&Filter { min: 0, max: WM_PAINT, ..all }));
        assert!(!wants_paint(&Filter { min: WM_PAINT + 1, max: 0x400, ..all }), "above");
        assert!(!wants_paint(&Filter { min: 1, max: WM_PAINT - 1, ..all }), "below");
    }
}
