//! Le défilement d'une fenêtre ou d'un DC : ScrollWindowEx et ScrollDC
//! (`scrollex.c` de win32k, ReactOS épinglé, comme spécification).
//!
//! ScrollDC ([`scroll_dc`], UserScrollDC) copie, dans la surface du DC, la
//! partie de `prcScroll` qui tombe dans sa boîte de découpage (et
//! `prcClip`), décalée de (dx, dy) ; ce qu'il faut repeindre ([`plan`]) est
//! ce que le décalage découvre, plus ce qui n'a pas pu être copié parce que
//! la source n'était pas visible.
//!
//! ScrollWindowEx ([`scroll_window`], IntScrollWindowEx) fait de même sur la
//! zone cliente d'une fenêtre, par un DC du cache : sans ses filles (sauf
//! SW_SCROLLCHILDREN, qui les copie et les déplace, avec WM_MOVE) ; la
//! région déjà à repeindre de la fenêtre est décalée aussi, puis, avec
//! SW_INVALIDATE ou SW_ERASE, ce qui est découvert est invalidé (et à
//! effacer avec les deux). Il rend la complexité de cette région.
//!
//! Un écart voulu avec ReactOS : WM_MOVE d'une fille déplacée par
//! SW_SCROLLCHILDREN porte le coin de sa zone cliente dans celle de son
//! parent, comme la documentation de l'API (ReactOS donne celui de son
//! rectangle, ou de sa zone cliente à l'écran sous une fenêtre de premier
//! niveau).
//!
//! Pas encore : le caret (co_IntFixCaret : il se cacherait, puis suivrait le
//! défilement), SW_SMOOTHSCROLL (ignoré, comme ReactOS).

use alloc::sync::Arc;

use abi::gdi::rop::SRCCOPY;
use abi::user::{
    sw_scroll, CS_CLASSDC, CS_OWNDC, DCX_CACHE, DCX_NOCLIPCHILDREN, DCX_USESTYLE, RDW_ALLCHILDREN, RDW_ERASE,
    RDW_INVALIDATE, RDW_NOCHILDREN, WM_MOVE, WS_CLIPCHILDREN,
};

use crate::gdi::dib::Rect;
use crate::gdi::region::Region;
use crate::window::{self, LParam, Window};

/// Ce que fait ScrollDC ([`plan`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Où la copie écrit (vide : rien à copier) ; elle lit ce rectangle
    /// moins le décalage.
    pub dest: Rect,
    /// Ce qu'il faut repeindre.
    pub update: Region,
}

fn moved(rect: Rect, (dx, dy): (i32, i32)) -> Rect {
    Rect::new(rect.left + dx, rect.top + dy, rect.right + dx, rect.bottom + dy)
}

/// UserScrollDC, sans la copie, en coordonnées logiques : le décalage
/// `delta` de `scroll` (la boîte de découpage du DC, `clip_box`, sans lui),
/// coupé à `clip_box` et à `clip`. La source est `scroll` dans le découpage ;
/// la destination, la source décalée et coupée de même. À repeindre : la
/// destination de tout `scroll` et la source, moins ce qui a été copié
/// d'une source visible (`visible`, la région visible du DC).
pub fn plan(delta: (i32, i32), scroll: Option<Rect>, clip_box: Rect, clip: Option<Rect>, visible: &Region) -> Plan {
    let clip = clip.map_or(clip_box, |clip| clip_box.intersect(&clip));
    let (scroll, source) = match scroll {
        Some(scroll) => (scroll, clip.intersect(&scroll)),
        None => (clip_box, clip),
    };
    let dest = moved(source, delta).intersect(&clip);
    let mut update = Region::from_rect(moved(scroll, delta).intersect(&clip));
    update.union_rect(source);
    let mut copied = Region::from_rect(source).intersect(visible);
    copied.offset(delta.0, delta.1);
    update.subtract(&copied);
    Plan { dest, update }
}

/// UserScrollDC : le contenu du DC `hdc` (du processus courant) défile de
/// `delta` dans `scroll` coupé à `clip` ([`plan`]) ; rend la région à
/// repeindre, en coordonnées logiques. `None` pour un DC qui n'est pas au
/// processus.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn scroll_dc(hdc: u32, delta: (i32, i32), scroll: Option<Rect>, clip: Option<Rect>) -> Option<Region> {
    let dc = crate::gdi::dc::lock(hdc)?;
    let state = dc.state();
    let (_, clip_box) = crate::gdi::dc::clip_box(&state);
    let (dx, dy) = crate::gdi::dc::logical_origin(&state, None);
    let plan = plan(delta, scroll, clip_box, clip, &state.vis.offset_by(-dx, -dy));
    drop(dc);
    let dest = plan.dest;
    if !dest.is_empty() {
        let extent = (dest.left, dest.top, dest.right - dest.left, dest.bottom - dest.top);
        let from = (dest.left - delta.0, dest.top - delta.1);
        // The DC is the process's: the copy cannot be refused.
        let _ = crate::gdi::bitblt::bit_blt(hdc, extent, hdc, from, SRCCOPY);
    }
    Some(plan.update)
}

/// Ce que ScrollWindowEx a fait ([`scroll_window`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scrolled {
    /// Ce que le défilement découvre, dans la zone cliente (la région de
    /// `hrgnUpdate` et le rectangle de `prcUpdate`).
    pub update: Region,
    /// La région déjà à repeindre de la fenêtre avant et après son
    /// décalage, que `hrgnUpdate` reçoit en plus.
    pub window_update: Region,
}

/// Les drapeaux du DC de ScrollWindowEx : un DC du cache, coupé selon les
/// styles ; ScrollWindow (`SW_SCROLLWNDDCE`) prendrait celui de la fenêtre
/// ou de sa classe (pas encore : le cache aussi), sans couper les filles
/// qu'il déplace ; ScrollWindowEx, sans couper celles qu'il déplace.
pub fn dc_flags(flags: u32, class_style: u32, style: u32) -> u32 {
    let children = flags & sw_scroll::SCROLLCHILDREN != 0;
    if flags & sw_scroll::SCROLLWNDDCE != 0 {
        let mut dcx = DCX_USESTYLE;
        if class_style & (CS_OWNDC | CS_CLASSDC) == 0 {
            dcx |= DCX_CACHE;
        }
        if children && style & WS_CLIPCHILDREN != 0 {
            dcx |= DCX_CACHE | DCX_NOCLIPCHILDREN;
        }
        dcx
    } else {
        DCX_CACHE | DCX_USESTYLE | if children { DCX_NOCLIPCHILDREN } else { 0 }
    }
}

/// Le rectangle de `rect` dans la zone cliente de taille `client`, et la
/// zone cliente coupée à `clip` (IntScrollWindowEx).
pub fn areas(client: Rect, scroll: Option<Rect>, clip: Option<Rect>) -> (Rect, Rect) {
    let scroll = scroll.map_or(client, |scroll| client.intersect(&scroll));
    let clip = clip.map_or(client, |clip| client.intersect(&clip));
    (scroll, clip)
}

/// IntScrollWindowEx : la zone cliente de `window` défile de `delta`, dans
/// `scroll` coupé à `clip` (dans la zone cliente), selon `flags` (`SW_*`) ;
/// `want_window_update` : `hrgnUpdate` a été donné, qui recevra aussi la
/// région déjà à repeindre. `None` pour une fenêtre qu'on ne voit pas ou
/// si le DC n'a pas pu se prendre (ERROR) ; une région vide sans rien à
/// faire (NULLREGION).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn scroll_window(
    window: &Arc<Window>,
    delta: (i32, i32),
    scroll: Option<Rect>,
    clip: Option<Rect>,
    flags: u32,
    want_window_update: bool,
) -> Option<Scrolled> {
    if !crate::paint::is_drawable(window) {
        return None;
    }
    let state = window.state();
    let (scroll, clip) = areas(state.client_area(), scroll, clip);
    if clip.is_empty() || delta == (0, 0) {
        return Some(Scrolled::default());
    }
    let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
    let hdc = crate::dce::get_dc_ex(window, None, dc_flags(flags, class_style, state.style)).ok()?;
    let rdw = if flags & (sw_scroll::ERASE | sw_scroll::INVALIDATE) == sw_scroll::ERASE | sw_scroll::INVALIDATE {
        RDW_INVALIDATE | RDW_ERASE
    } else {
        RDW_INVALIDATE
    };
    let update = scroll_dc(hdc, delta, Some(scroll), Some(clip));
    crate::dce::release_dc(hdc);
    let update = update?;

    // What was already to repaint moves with the content.
    let mut window_update = Region::default();
    if let Some(pending) = crate::paint::get_update_region(window, false).filter(|region| !region.is_empty()) {
        let mut shifted = pending.offset_by(delta.0, delta.1);
        shifted.intersect_rect(clip);
        if want_window_update {
            window_update = pending;
            window_update.union(&shifted);
        }
        crate::paint::redraw_window(window, None, Some(&shifted), rdw);
    }

    if flags & sw_scroll::SCROLLCHILDREN != 0 {
        move_children(window, delta, scroll);
    }
    if flags & (sw_scroll::INVALIDATE | sw_scroll::ERASE) != 0 {
        let children = if flags & sw_scroll::SCROLLCHILDREN != 0 { RDW_ALLCHILDREN } else { RDW_NOCHILDREN };
        crate::paint::redraw_window(window, None, Some(&update), rdw | children);
    }
    Some(Scrolled { update, window_update })
}

/// SW_SCROLLCHILDREN : les filles de `window` se déplacent de `delta` ;
/// celles qui touchaient `scroll` (dans la zone cliente) reçoivent WM_MOVE,
/// le coin de leur zone cliente dans celle de `window`.
fn move_children(window: &Arc<Window>, delta: (i32, i32), scroll: Rect) {
    for handle in window::children(window, false) {
        let Some(child) = window::get(handle) else { continue };
        let origin = window.state().client;
        let before = child.state().window;
        let touched = !moved(before, (-origin.left, -origin.top)).intersect(&scroll).is_empty();
        window::move_tree(&child, delta.0, delta.1);
        if touched {
            let client = child.state().client;
            let at = window::make_long(client.left - origin.left, client.top - origin.top);
            let _ = window::send_message(&child, WM_MOVE, 0, LParam::Value(at));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrolling_up_uncovers_the_bottom() {
        let client = Rect::new(0, 0, 100, 50);
        let visible = Region::from_rect(client);
        let up = plan((0, -20), None, client, None, &visible);
        assert_eq!(up.dest, Rect::new(0, 0, 100, 30), "rows 20 to 50 copied to 0 to 30");
        assert_eq!(up.update.rects(), &[Rect::new(0, 30, 100, 50)]);
        let right = plan((15, 0), None, client, None, &visible);
        assert_eq!(right.update.rects(), &[Rect::new(0, 0, 15, 50)], "scrolled right: the left");
    }

    #[test]
    fn what_could_not_be_copied_is_repainted_too() {
        let client = Rect::new(0, 0, 100, 50);
        // A child covers (40, 10) to (60, 20): its pixels are not the
        // parent's, so what they move to must be repainted.
        let mut visible = Region::from_rect(client);
        visible.subtract_rect(Rect::new(40, 10, 60, 20));
        let up = plan((0, -10), None, client, None, &visible);
        assert_eq!(up.update.rects(), &[Rect::new(40, 0, 60, 10), Rect::new(0, 40, 100, 50)]);
        assert_eq!(up.update.complexity(), abi::gdi::COMPLEXREGION);
    }

    #[test]
    fn a_scroll_rectangle_and_a_clip_rectangle() {
        let client = Rect::new(0, 0, 100, 50);
        let visible = Region::from_rect(client);
        // Only rows 10 to 40 scroll, down 5: rows 10 to 15 are uncovered;
        // the copy writes rows 15 to 45, past the scroll rectangle (only
        // the clip rectangle stops it).
        let up = plan((0, 5), Some(Rect::new(0, 10, 100, 40)), client, None, &visible);
        assert_eq!(up.dest, Rect::new(0, 15, 100, 45));
        assert_eq!(up.update.rects(), &[Rect::new(0, 10, 100, 15)]);
        // A clip rectangle: nothing is written outside it.
        let clipped = plan((0, 5), None, client, Some(Rect::new(0, 0, 100, 30)), &visible);
        assert_eq!(clipped.dest, Rect::new(0, 5, 100, 30));
        assert_eq!(clipped.update.rects(), &[Rect::new(0, 0, 100, 5)]);
        // Nothing visible: all to repaint, nothing copied from.
        let hidden = plan((0, -10), None, client, None, &Region::default());
        assert_eq!(hidden.update.rects(), &[client]);
    }

    #[test]
    fn the_areas_are_cut_to_the_client_area() {
        let client = Rect::new(0, 0, 100, 50);
        assert_eq!(areas(client, None, None), (client, client));
        let (scroll, clip) = areas(client, Some(Rect::new(-10, 10, 50, 90)), Some(Rect::new(20, 0, 200, 40)));
        assert_eq!((scroll, clip), (Rect::new(0, 10, 50, 50), Rect::new(20, 0, 100, 40)));
    }

    #[test]
    fn the_dc_of_each_scroll() {
        assert_eq!(dc_flags(0, 0, 0), DCX_CACHE | DCX_USESTYLE);
        assert_eq!(dc_flags(sw_scroll::SCROLLCHILDREN, 0, 0), DCX_CACHE | DCX_USESTYLE | DCX_NOCLIPCHILDREN);
        let window_dce = sw_scroll::SCROLLWNDDCE | sw_scroll::SCROLLCHILDREN;
        assert_eq!(dc_flags(window_dce, CS_OWNDC, 0), DCX_USESTYLE, "its own DC");
        assert_eq!(
            dc_flags(window_dce, CS_OWNDC, WS_CLIPCHILDREN),
            DCX_USESTYLE | DCX_CACHE | DCX_NOCLIPCHILDREN,
            "its children moved"
        );
    }
}
