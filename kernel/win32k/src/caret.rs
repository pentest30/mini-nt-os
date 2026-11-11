//! Le caret, le curseur du texte (`caret.c` de win32k, ReactOS épinglé,
//! comme spécification) : un par thread, dans sa file (`CaretInfo`), dans
//! une de ses fenêtres.
//!
//! CreateCaret ([`create`]) lui donne sa fenêtre et sa forme : un rectangle
//! plein (`nWidth` × `nHeight`, la largeur ou la hauteur d'une bordure pour
//! 0), gris (`(HBITMAP)1` : un pixel sur deux) ou un bitmap ; il naît caché.
//! Il se dessine en inversant l'écran, dans la zone cliente de sa fenêtre
//! là où elle se voit ([`draw`] : DSTINVERT, PATINVERT du damier gris, ou
//! SRCINVERT du bitmap) : dessiné deux fois, il s'efface.
//!
//! HideCaret et ShowCaret s'additionnent, comme la documentation de l'API
//! (et Wine) le disent : il naît caché une fois, chaque HideCaret le cache
//! une fois de plus, et il ne se voit qu'avec autant de ShowCaret
//! (ReactOS n'a qu'un booléen). Visible, il se dessine aussitôt et clignote :
//! une minuterie du système (IDCARETTIMER, [`blink`], toutes les
//! `dtCaretBlink` millisecondes) l'inverse ; un temps de clignotement négatif
//! (INFINITE) le laisse fixe. SetCaretPos ([`set_pos`]) l'efface où il était
//! et le dessine où il va.
//!
//! BeginPaint le cache et EndPaint le remontre ([`hide_in`], [`show_in`]),
//! s'il est dans la fenêtre peinte ; ScrollWindowEx le cache pendant la
//! copie, puis le fait suivre le contenu ([`before_scroll`],
//! [`after_scroll`], co_IntFixCaret) ; la destruction de sa fenêtre le
//! détruit ([`destroy_in`]).
//!
//! Écarts voulus avec ReactOS : le niveau de masquage, le dessin aussitôt
//! visible (ReactOS attend la première échéance de la minuterie), et un
//! caret caché ne clignote pas (ReactOS l'inverse à chaque échéance dès sa
//! création).
//!
//! Pas encore : les événements d'accessibilité (EVENT_OBJECT_*), le caret
//! dans GetGUIThreadInfo.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::user::{sm, IDCARETTIMER, WS_CLIPCHILDREN, WS_CLIPSIBLINGS};
use abi::winerror::{ERROR_ACCESS_DENIED, ERROR_INVALID_WINDOW_HANDLE};

use crate::gdi::brush::GRAY_PATTERN;
use crate::gdi::dib::{ColorRef, MonoFill, Rect};
use crate::gui::ThreadInfo;
use crate::timer::TimerKey;
use crate::window::{self, Window};

/// `(HBITMAP)1` : un caret gris.
pub const GRAY: u32 = 1;

/// Les ROP3 du dessin : NOT D, P XOR D, S XOR D.
const DSTINVERT: u8 = 0x55;
const PATINVERT: u8 = 0x5A;
const SRCINVERT: u8 = 0x66;

/// `gpsi->dtCaretBlink` : le temps de clignotement, en millisecondes
/// (CursorBlinkRate par défaut) ; négatif (INFINITE) : fixe.
static BLINK_TIME: AtomicU32 = AtomicU32::new(530);

/// Le caret d'un thread (`THRDCARETINFO`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caret {
    /// Sa fenêtre ; 0 sans caret.
    pub hwnd: u32,
    /// 0 : plein ; [`GRAY`] : gris ; sinon le handle de son bitmap.
    pub bitmap: u32,
    /// Son coin, dans la zone cliente de sa fenêtre.
    pub pos: (i32, i32),
    pub size: (i32, i32),
    /// Combien de fois il est caché : 1 à sa création.
    pub hidden: u32,
    /// Il est dessiné à l'écran (`Showing`).
    pub showing: bool,
}

impl Caret {
    /// Il se voit : il existe et n'est pas caché.
    pub fn visible(&self) -> bool {
        self.hwnd != 0 && self.hidden == 0
    }

    /// HideCaret : caché une fois de plus ; rend s'il faut l'effacer (il
    /// était dessiné) et s'il était visible (son clignotement s'arrête).
    pub fn hide(&mut self) -> (bool, bool) {
        let was_visible = self.visible();
        self.hidden = self.hidden.saturating_add(1);
        (core::mem::take(&mut self.showing), was_visible)
    }

    /// ShowCaret : caché une fois de moins ; rend s'il devient visible (il
    /// se dessine et se met à clignoter).
    pub fn show(&mut self) -> bool {
        if self.hwnd == 0 || self.hidden == 0 {
            return false;
        }
        self.hidden -= 1;
        if self.hidden != 0 {
            return false;
        }
        self.showing = true;
        true
    }

    /// Une échéance de son clignotement : il s'inverse s'il est visible ;
    /// rend s'il faut le dessiner.
    pub fn blink(&mut self) -> bool {
        if !self.visible() {
            return false;
        }
        self.showing = !self.showing;
        true
    }

    /// SetCaretPos : il va en `pos` ; rend s'il faut l'effacer où il était et
    /// le dessiner où il va (rien s'il ne bouge pas).
    pub fn move_to(&mut self, pos: (i32, i32)) -> (bool, bool) {
        if pos == self.pos {
            return (false, false);
        }
        let erase = core::mem::take(&mut self.showing);
        self.pos = pos;
        self.showing = self.visible();
        (erase, self.showing)
    }
}

/// GetCaretBlinkTime : le temps de clignotement, en millisecondes.
pub fn blink_time() -> u32 {
    BLINK_TIME.load(Ordering::Relaxed)
}

/// SetCaretBlinkTime (IntSetCaretBlinkTime : pas dans le registre) ; un
/// caret qui clignote déjà garde son rythme jusqu'à sa prochaine minuterie.
pub fn set_blink_time(milliseconds: u32) {
    BLINK_TIME.store(milliseconds, Ordering::Relaxed);
}

/// Le thread GUI courant.
fn current() -> Option<Arc<ThreadInfo>> {
    crate::gui::convert_current_thread().ok()
}

/// Les rectangles de l'écran où `caret` se dessine : le sien, dans la zone
/// cliente de sa fenêtre, là où elle se voit (DCX_USESTYLE : sans ses filles
/// ni ses sœurs si son style le dit) ; son coin à l'écran.
fn place(caret: &Caret) -> Option<(Vec<Rect>, (i32, i32))> {
    let window = window::get(caret.hwnd)?;
    if !crate::paint::is_drawable(&window) {
        return None;
    }
    let state = window.state();
    let corner = (state.client.left + caret.pos.0, state.client.top + caret.pos.1);
    let rect = Rect::new(corner.0, corner.1, corner.0 + caret.size.0, corner.1 + caret.size.1);
    let clip = crate::paint::visible_region(
        &window,
        true,
        state.style & WS_CLIPCHILDREN != 0,
        state.style & WS_CLIPSIBLINGS != 0,
    );
    let parts: Vec<Rect> =
        clip.rects().iter().map(|visible| visible.intersect(&rect)).filter(|r| !r.is_empty()).collect();
    (!parts.is_empty()).then_some((parts, corner))
}

/// co_IntDrawCaret : `caret` s'inverse à l'écran (un rectangle plein, le
/// damier gris, ou son bitmap en XOR) ; un bitmap qui n'en est pas un ne
/// dessine rien, comme ReactOS.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du caret (son bitmap).
pub fn draw(caret: &Caret) {
    let Some((parts, corner)) = place(caret) else { return };
    match caret.bitmap {
        0 => {
            crate::display::draw(|screen| {
                for &part in &parts {
                    screen.pat_blt(part, ColorRef(0), DSTINVERT);
                }
            });
        }
        GRAY => {
            let fill = MonoFill { rows: GRAY_PATTERN, zero: ColorRef(0), one: ColorRef(0x00FF_FFFF), origin: corner };
            crate::display::draw(|screen| {
                for &part in &parts {
                    screen.pat_blt_mono(part, &fill, PATINVERT);
                }
            });
        }
        bitmap => {
            let pid = crate::gdi::dc::current_pid();
            let Some(surface) = crate::gdi::surface::lock(bitmap, pid) else { return };
            surface.draw(|source| {
                crate::display::draw(|screen| {
                    for &part in &parts {
                        let from = (part.left - corner.0, part.top - corner.1);
                        screen.blt_from(part, source, from, SRCINVERT, ColorRef(0));
                    }
                });
            });
        }
    }
}

/// La minuterie du clignotement de `caret` part (s'il clignote : un temps
/// positif), ou repart.
fn start_blinking(caret: &Caret) {
    let time = blink_time();
    if (time as i32) <= 0 {
        return;
    }
    if let Some(window) = window::get(caret.hwnd) {
        let _ = crate::timer::set_kernel_timer(&window, IDCARETTIMER, time, blink);
    }
}

/// La minuterie du clignotement de `caret` s'arrête.
fn stop_blinking(thread: &ThreadInfo, caret: &Caret) {
    crate::timer::kill_timer(thread, TimerKey { hwnd: caret.hwnd, id: IDCARETTIMER, system: true });
}

/// Change le caret de `thread` par `change`, qui rend ce qu'il faut
/// dessiner ; rend le caret avant le changement, et après.
fn update<R>(thread: &ThreadInfo, change: impl FnOnce(&mut Caret) -> R) -> (Caret, Caret, R) {
    thread
        .queue
        .with(|queue| {
            let before = queue.caret;
            let result = change(&mut queue.caret);
            (before, queue.caret, result)
        })
        .0
}

/// CaretSystemTimerProc : une échéance du clignotement du caret de la
/// fenêtre `hwnd`, au thread courant ; il s'inverse s'il est visible.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread du caret (DispatchMessage).
pub fn blink(hwnd: u32, _id: u32) {
    let Some(thread) = current() else { return };
    let (_, after, draw_it) = update(&thread, |caret| caret.hwnd == hwnd && caret.blink());
    if draw_it {
        draw(&after);
    }
}

/// La fenêtre `hwnd` du thread courant, pour les services du caret.
fn own_window(thread: &ThreadInfo, hwnd: u32) -> Result<Arc<Window>, u32> {
    let window = window::get(hwnd).ok_or(ERROR_INVALID_WINDOW_HANDLE)?;
    if window.pti != thread.server {
        return Err(ERROR_ACCESS_DENIED);
    }
    Ok(window)
}

/// NtUserCreateCaret : le caret du thread courant passe à la fenêtre `hwnd`
/// (du thread), de forme `bitmap` (0 : plein, [`GRAY`], ou un bitmap, dont
/// il prend la taille) et de taille `width` × `height` (0 : celles d'une
/// bordure) ; celui d'avant s'efface. Il naît caché, en (0, 0).
///
/// # Errors
/// `ERROR_INVALID_WINDOW_HANDLE` ; `ERROR_ACCESS_DENIED` pour la fenêtre
/// d'un autre thread.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn create(hwnd: u32, bitmap: u32, width: i32, height: i32) -> Result<(), u32> {
    let thread = current().ok_or(ERROR_ACCESS_DENIED)?;
    own_window(&thread, hwnd)?;
    let size = match bitmap {
        0 | GRAY => (
            if width == 0 { crate::metrics::get(sm::CXBORDER) } else { width },
            if height == 0 { crate::metrics::get(sm::CYBORDER) } else { height },
        ),
        handle => crate::gdi::surface::lock(handle, crate::gdi::dc::current_pid())
            .map_or((0, 0), |surface| (surface.size().0 as i32, surface.size().1 as i32)),
    };
    let new = Caret { hwnd, bitmap, pos: (0, 0), size, hidden: 1, showing: false };
    let (before, _, ()) = update(&thread, |caret| *caret = new);
    if before.visible() {
        stop_blinking(&thread, &before);
    }
    if before.showing {
        draw(&before);
    }
    Ok(())
}

/// co_IntDestroyCaret : le caret de `thread` s'efface et disparaît.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy(thread: &ThreadInfo) {
    let (before, _, ()) = update(thread, |caret| *caret = Caret::default());
    if before.hwnd != 0 {
        stop_blinking(thread, &before);
    }
    if before.showing {
        draw(&before);
    }
}

/// NtUserCallNoParam(DESTROY_CARET) : DestroyCaret du thread courant ;
/// toujours vrai, comme ReactOS.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn destroy_current() -> bool {
    if let Some(thread) = current() {
        destroy(&thread);
    }
    true
}

/// La destruction de la fenêtre `hwnd`, de `thread`, détruit son caret.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy_in(thread: &ThreadInfo, hwnd: u32) {
    if thread.queue.with(|queue| queue.caret.hwnd).0 == hwnd {
        destroy(thread);
    }
}

/// co_IntSetCaretPos : le caret du thread courant va en (`x`, `y`) de sa
/// fenêtre ; faux sans caret.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn set_pos(x: i32, y: i32) -> bool {
    let Some(thread) = current() else { return false };
    let (before, after, moved) = update(&thread, |caret| (caret.hwnd != 0).then(|| caret.move_to((x, y))));
    let Some((erase, show)) = moved else { return false };
    if erase {
        draw(&before);
    }
    if show {
        draw(&after);
    }
    if after.visible() && before.pos != after.pos {
        // The blink starts again from here.
        start_blinking(&after);
    }
    true
}

/// NtUserGetCaretPos : le coin du caret du thread courant.
pub fn pos() -> (i32, i32) {
    current().map_or((0, 0), |thread| thread.queue.with(|queue| queue.caret.pos).0)
}

/// Le caret de `thread` est-il dans la fenêtre `hwnd` (0 : n'importe
/// laquelle) ? `ERROR_ACCESS_DENIED` sinon (co_UserHideCaret,
/// co_UserShowCaret).
fn check_window(thread: &ThreadInfo, hwnd: u32) -> Result<(), u32> {
    if hwnd == 0 {
        return Ok(());
    }
    own_window(thread, hwnd)?;
    if thread.queue.with(|queue| queue.caret.hwnd).0 != hwnd {
        return Err(ERROR_ACCESS_DENIED);
    }
    Ok(())
}

/// co_UserHideCaret sur `thread`, sans vérification.
fn hide_on(thread: &ThreadInfo) {
    let (before, _, (erase, was_visible)) = update(thread, Caret::hide);
    if was_visible {
        stop_blinking(thread, &before);
    }
    if erase {
        draw(&before);
    }
}

/// co_UserShowCaret sur `thread`, sans vérification.
fn show_on(thread: &ThreadInfo) {
    let (_, after, shown) = update(thread, Caret::show);
    if shown {
        draw(&after);
        start_blinking(&after);
    }
}

/// NtUserHideCaret : le caret du thread courant, dans la fenêtre `hwnd`
/// (0 : n'importe laquelle), est caché une fois de plus.
///
/// # Errors
/// `ERROR_INVALID_WINDOW_HANDLE` ; `ERROR_ACCESS_DENIED` pour une fenêtre
/// d'un autre thread ou sans le caret.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn hide(hwnd: u32) -> Result<(), u32> {
    let thread = current().ok_or(ERROR_ACCESS_DENIED)?;
    check_window(&thread, hwnd)?;
    hide_on(&thread);
    Ok(())
}

/// NtUserShowCaret : le caret du thread courant, dans la fenêtre `hwnd`
/// (0 : n'importe laquelle), est caché une fois de moins ; il se dessine et
/// clignote s'il devient visible.
///
/// # Errors
/// Comme [`hide`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn show(hwnd: u32) -> Result<(), u32> {
    let thread = current().ok_or(ERROR_ACCESS_DENIED)?;
    check_window(&thread, hwnd)?;
    show_on(&thread);
    Ok(())
}

/// BeginPaint : le caret du thread courant se cache s'il est dans `window`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn hide_in(window: &Window) {
    if let Some(thread) = current().filter(|thread| thread.queue.with(|queue| queue.caret.hwnd).0 == window.handle) {
        hide_on(&thread);
    }
}

/// EndPaint : le caret du thread courant se remontre s'il est dans `window`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn show_in(window: &Window) {
    if let Some(thread) = current().filter(|thread| thread.queue.with(|queue| queue.caret.hwnd).0 == window.handle) {
        show_on(&thread);
    }
}

/// co_IntFixCaret, avant ScrollWindowEx de `window` sur `scroll` (dans sa
/// zone cliente) : le caret du thread courant se cache s'il est dans
/// `window` et touche `scroll`, ou dans une de ses filles quand elles
/// défilent aussi (`children`) ; rend sa fenêtre s'il s'est caché.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn before_scroll(window: &Window, scroll: Rect, children: bool) -> Option<u32> {
    let thread = current()?;
    let caret = thread.queue.with(|queue| queue.caret).0;
    if caret.hwnd == 0 {
        return None;
    }
    let touched = if caret.hwnd == window.handle {
        let rect = Rect::new(caret.pos.0, caret.pos.1, caret.pos.0 + caret.size.0, caret.pos.1 + caret.size.1);
        !rect.intersect(&scroll).is_empty()
    } else {
        children && window::children(window, true).contains(&caret.hwnd)
    };
    if !touched {
        return None;
    }
    hide_on(&thread);
    Some(caret.hwnd)
}

/// Après le défilement de `window` de `delta` : le caret caché par
/// [`before_scroll`] dans `hwnd` suit le contenu (s'il est dans `window`),
/// puis se remontre.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn after_scroll(window: &Window, hwnd: u32, delta: (i32, i32)) {
    let Some(thread) = current() else { return };
    if hwnd == window.handle {
        // Hidden: moving draws nothing.
        update(&thread, |caret| {
            let pos = (caret.pos.0 + delta.0, caret.pos.1 + delta.1);
            caret.move_to(pos)
        });
    }
    show_on(&thread);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caret() -> Caret {
        Caret { hwnd: 0x20, size: (2, 16), hidden: 1, ..Caret::default() }
    }

    #[test]
    fn a_new_caret_is_hidden_once() {
        let mut c = caret();
        assert!(!c.visible());
        assert!(!c.blink(), "a hidden caret does not blink");
        assert!(c.show(), "shown once: visible, drawn");
        assert!(c.visible() && c.showing);
        assert!(!c.show(), "shown again: nothing more");
        assert_eq!(c.hidden, 0);
    }

    #[test]
    fn hiding_counts() {
        let mut c = caret();
        c.show();
        assert_eq!(c.hide(), (true, true), "erased, its blink stopped");
        assert_eq!(c.hide(), (false, false), "already");
        assert!(!c.show(), "hidden twice, shown once: still hidden");
        assert!(c.show(), "and now visible");
        assert!(c.showing);
    }

    #[test]
    fn blinking_inverts_and_moving_redraws() {
        let mut c = caret();
        c.show();
        assert!(c.blink() && !c.showing, "off");
        assert!(c.blink() && c.showing, "on");
        assert_eq!(c.move_to((10, 20)), (true, true), "erased where it was, drawn where it goes");
        assert_eq!(c.move_to((10, 20)), (false, false), "not moved");
        c.blink();
        assert_eq!(c.move_to((30, 20)), (false, true), "off: nothing to erase, drawn at once");
        assert_eq!(c.hide(), (true, true), "hidden while drawn: erased");
        assert_eq!(c.move_to((40, 20)), (false, false), "hidden: nothing drawn");
        assert_eq!(c.pos, (40, 20));
    }

    #[test]
    fn without_a_window_there_is_nothing_to_show() {
        let mut c = Caret::default();
        assert!(!c.show() && !c.visible());
        c.hide();
        assert!(!c.show(), "still no caret");
    }
}
