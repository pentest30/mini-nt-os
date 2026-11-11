//! La destruction des fenêtres et le ménage de win32k à la fin d'un thread
//! ou d'un processus GUI (`window.c`, `main.c` de ReactOS comme
//! spécification : co_UserDestroyWindow, IntSendDestroyMsg,
//! co_UserFreeWindow, ExitThreadCallback, ExitProcessCallback).
//!
//! DestroyWindow ([`destroy_window`]), au thread de la fenêtre :
//! - une fenêtre fille prévient son parent (WM_PARENTNOTIFY de WM_DESTROY) ;
//! - visible, elle est cachée (ShowWindow(SW_HIDE) pour une fille,
//!   SetWindowPos(SWP_HIDEWINDOW) sinon) : ce qu'elle découvre se repeint ;
//! - ses fenêtres possédées du même thread sont détruites d'abord, celles
//!   d'un autre thread perdent leur propriétaire ;
//! - active, une autre fenêtre devient active
//!   (`crate::input::activate_other`) ; si elle a le clavier, son parent le
//!   prend (une fille), sinon personne (WM_KILLFOCUS) ;
//! - WM_DESTROY à elle, puis à ses enfants, de haut en bas ;
//! - puis co_UserFreeWindow : ses enfants d'abord, chacun recevant
//!   WM_NCDESTROY après les siens ; ses minuteries, ses messages dans la file
//!   (leurs envoyeurs réveillés), sa région à mettre à jour et le compte des
//!   fenêtres à peindre de son thread, la capture, le menu de sa barre, les
//!   DC du cache pris pour elle, ses propriétés, sa place dans l'ordre Z, et
//!   enfin son handle ([`crate::window::release`]).
//!
//! Une procédure qui détruit sa fenêtre pendant WM_DESTROY ne la détruit pas
//! deux fois : la seconde demande réussit sans rien faire.
//!
//! À la fin d'un thread GUI ([`thread_exit`], rappel de Ps), ses fenêtres
//! sont détruites sans message, comme ReactOS (`TIF_INCLEANUP` : le thread
//! ne reçoit plus rien) ; ce qu'elles découvrent se repeint, et une fenêtre
//! d'un autre thread devient active si l'une d'elles l'était. Ses
//! minuteries partent, sa file est vidée, les messages qu'on lui avait
//! envoyés reviennent à leurs envoyeurs (`crate::sent::abandon_all`), il
//! quitte le premier plan et son bureau.
//!
//! À la fin d'un processus GUI ([`process_exit`], rappel de Ps), ce qui
//! reste de ses objets USER (ses menus ; une fenêtre, s'il en restait) est
//! détruit, les DC du cache qu'il avait pris y reviennent, ses objets GDI
//! quittent la table, et son `PROCESSINFO` rend ses classes, ses bureaux et
//! sa station. Ce qui en resterait encore est journalisé.
//!
//! Pas encore : WM_ASYNC_DESTROYWINDOW aux enfants d'un autre thread
//! (détruits sans message, journalisé une fois), les crochets
//! (HCBT_DESTROYWND, HSHELL_WINDOWDESTROYED), le curseur réévalué (le
//! WM_MOUSEMOVE qu'insère ReactOS), le menu système, la dernière fenêtre
//! active d'un propriétaire (`spwndLastActive`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::user::{
    FNID_FREED, SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE, TYPE_ACCELTABLE,
    TYPE_CURSOR, TYPE_MENU, TYPE_WINDOW, WM_DESTROY, WM_NCDESTROY, WM_PARENTNOTIFY, WNDS2_INDESTROY, WNDS_DESTROYED,
    WNDS_ERASEBACKGROUND, WNDS_INTERNALPAINT, WNDS_SENDERASEBACKGROUND, WNDS_SENDNCPAINT, WS_CHILD,
    WS_EX_NOPARENTNOTIFY, WS_POPUP, WS_VISIBLE,
};
use abi::winerror::ERROR_ACCESS_DENIED;
use ob::Object;
use ps::{EProcess, EThread};

use crate::gdi::region::Region;
use crate::gui::ThreadInfo;
use crate::window::{self, LParam, Window};

/// Ce qu'une destruction envoie : DestroyWindow, ses messages ; la fin d'un
/// thread, aucun.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Messages,
    Silent,
}

/// co_UserDestroyWindow (NtUserDestroyWindow) : `window`, une fenêtre du
/// thread courant, est détruite avec ses enfants et ses fenêtres
/// possédées. Réussit aussi pour une fenêtre dont la destruction a déjà
/// commencé (sa procédure, pendant WM_DESTROY).
///
/// # Errors
/// L'erreur Win32 : `ERROR_ACCESS_DENIED` pour la fenêtre d'un autre thread
/// ou d'un bureau.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn destroy_window(window: &Arc<Window>) -> Result<(), u32> {
    let current = crate::convert_current_thread().map_err(|_| ERROR_ACCESS_DENIED)?;
    if window.is_desktop_window() || window.pti != current.server {
        return Err(ERROR_ACCESS_DENIED);
    }
    destroy(window, &current, Mode::Messages);
    Ok(())
}

/// Le `THREADINFO` du thread de `window` : `current` s'il est le sien.
fn thread_of(window: &Window, current: &Arc<ThreadInfo>) -> Option<Arc<ThreadInfo>> {
    if window.pti == current.server {
        Some(current.clone())
    } else {
        crate::gui::thread_info_of(window.pti)
    }
}

/// co_UserDestroyWindow, depuis le thread courant `current` : avec ses
/// messages (`Mode::Messages`, `window` est à `current`), ou sans
/// (`Mode::Silent`, `current` se termine).
fn destroy(window: &Arc<Window>, current: &Arc<ThreadInfo>, mode: Mode) {
    if !window.is_alive() || !window.begin_destroy() {
        return;
    }
    let messages = mode == Mode::Messages;
    let state = window.state();
    let hwnd = window.handle;
    let child = state.style & (WS_CHILD | WS_POPUP) == WS_CHILD;

    // IntSendParentNotify.
    if messages && child && state.ex_style & WS_EX_NOPARENTNOTIFY == 0 {
        if let Some(parent) = window::get(state.parent).filter(|parent| !parent.is_desktop_window()) {
            let wparam = (state.id_menu << 16) | WM_DESTROY;
            let _ = window::send_message(&parent, WM_PARENTNOTIFY, wparam, LParam::Value(hwnd));
        }
    }

    // Hidden: what it uncovers is painted again.
    if state.style & WS_VISIBLE != 0 && window.is_alive() {
        if !messages {
            hide_silently(window);
        } else if state.style & WS_CHILD != 0 {
            crate::winpos::show_window(window, SW_HIDE);
        } else {
            let flags = SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER;
            crate::winpos::set_window_pos(window, 0, 0, 0, 0, 0, flags);
        }
    }

    // The windows it owns: destroyed with it in its thread, freed of their
    // owner in another.
    if state.style & WS_CHILD == 0 && window.is_alive() {
        for owned in window::owned_by(hwnd) {
            if owned.pti == window.pti {
                destroy(&owned, current, mode);
            } else {
                window::change(&owned, |state| state.owner = 0);
            }
        }
    }

    if !window.is_alive() {
        return;
    }
    if messages {
        send_destroy(window, current);
    } else if thread_of(window, current).is_some_and(|thread| thread.queue.with(|queue| queue.active).0 == hwnd) {
        crate::input::activate_other(window, Some(window.pti), false);
    }
    if window.is_alive() {
        free_window(window, current, mode);
    }
}

/// Une fenêtre visible cachée sans message (la fin de son thread) : ce
/// qu'elle découvre se repeint.
fn hide_silently(window: &Arc<Window>) {
    let visible = window::is_visible(window);
    let state = window::change(window, |state| state.style &= !WS_VISIBLE);
    if visible {
        crate::paint::expose(window, &Region::from_rect(state.window));
    }
}

/// IntSendDestroyMsg : une fenêtre active du thread courant `current` en
/// rend une autre active, celle qui a son clavier le rend (à son parent pour
/// une fille) ; puis WM_DESTROY à `window`, puis à ses enfants, à toute
/// profondeur, tant qu'ils vivent.
fn send_destroy(window: &Arc<Window>, current: &Arc<ThreadInfo>) {
    if window.pti == current.server {
        let (active, focus) = current.queue.with(|queue| (queue.active, queue.focus)).0;
        if active == window.handle {
            crate::input::activate_other(window, None, true);
        }
        if focus == window.handle && current.queue.with(|queue| queue.focus).0 == window.handle {
            let state = window.state();
            let parent = if state.style & (WS_CHILD | WS_POPUP) == WS_CHILD { window::get(state.parent) } else { None };
            crate::input::set_focus(current, parent.filter(|parent| !parent.is_desktop_window()).as_ref());
        }
    }
    let _ = window::send_message(window, WM_DESTROY, 0, LParam::Value(0));
    if !window.is_alive() {
        return;
    }
    for child in window::children(window, false).into_iter().filter_map(window::get) {
        if child.is_alive() {
            send_destroy(&child, current);
        }
    }
}

/// co_UserFreeWindow, depuis le thread courant `current` : ses enfants
/// d'abord, WM_NCDESTROY ensuite (avec ses messages, au thread de la
/// fenêtre), puis ce qu'elle tient ([`finish`]).
fn free_window(window: &Arc<Window>, current: &Arc<ThreadInfo>, mode: Mode) {
    let mut first = false;
    window::change(window, |state| {
        first = state.state2 & WNDS2_INDESTROY == 0;
        state.state2 |= WNDS2_INDESTROY;
        state.style &= !WS_VISIBLE;
    });
    if !first {
        return;
    }
    let thread = thread_of(window, current);
    if let Some(thread) = &thread {
        thread.windows.lock().retain(|other| !Arc::ptr_eq(other, window));
    }
    for child in window::children(window, false).into_iter().filter_map(window::get) {
        let child_mode = if child.pti == current.server { mode } else { Mode::Silent };
        if child.pti != window.pti {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("win32k: DestroyWindow: a child of another thread destroyed without its messages: not yet");
            }
        }
        free_window(&child, current, child_mode);
    }
    if mode == Mode::Messages && window.pti == current.server {
        // Validated: no WM_PAINT while it handles WM_NCDESTROY.
        window::change(window, |state| {
            state.update = Region::default();
            state.state &= !WNDS_INTERNALPAINT;
        });
        let _ = window::send_message(window, WM_NCDESTROY, 0, LParam::Value(0));
    }
    finish(window, thread.as_ref());
}

/// La fin de co_UserFreeWindow : ce que tient `window` (de `thread`) est
/// rendu, puis son handle. Chaque étape peut se refaire sans effet : la fin
/// d'un thread la fait aussi pour une fenêtre dont la destruction a été
/// interrompue.
fn finish(window: &Arc<Window>, thread: Option<&Arc<ThreadInfo>>) {
    let hwnd = window.handle;
    crate::timer::destroy_window_timers(hwnd);
    if let Some(thread) = thread {
        crate::caret::destroy_in(thread, hwnd);
        let (gone, wake, change) = thread.queue.with(|queue| queue.remove_window_messages(hwnd));
        thread.mirror_queue_bits(wake, change);
        crate::sent::abandon_all(gone);
    }
    crate::mouse::forget_capture(hwnd);
    let state = window::change(window, |state| {
        state.style &= !WS_VISIBLE;
        state.update = Region::default();
        state.state &= !(WNDS_INTERNALPAINT | WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND | WNDS_SENDNCPAINT);
        state.state |= WNDS_DESTROYED;
        state.fnid |= FNID_FREED;
    });
    if state.style & (WS_CHILD | WS_POPUP) != WS_CHILD && state.menu != 0 {
        crate::menu::destroy(state.menu);
        window::change(window, |state| state.menu = 0);
    }
    crate::dce::free_window_dcs(hwnd);
    window::unlink(window);
    window::remove_properties(hwnd);
    for owned in window::owned_by(hwnd) {
        window::change(&owned, |state| state.owner = 0);
    }
    window::change(window, |state| (state.parent, state.owner, state.child) = (0, 0, 0));
    window::release(window);
}

/// ExitThreadCallback : `thread`, un thread GUI, se termine. Ses fenêtres
/// sont détruites sans message (celles de premier niveau d'abord), puis
/// celles dont la destruction aurait été interrompue ; ses minuteries
/// partent ; sa file est vidée, les messages qu'on lui avait envoyés
/// reviennent à leurs envoyeurs ; il n'est plus au premier plan et quitte
/// son bureau.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread qui se termine (rappel de Ps : ses APC
/// faits, rattaché à l'espace du système). Aucun rappel du mode
/// utilisateur.
pub fn thread_exit(thread: &Arc<Object<EThread>>) {
    let Some(slot) = thread.win32_thread() else { return };
    let info = crate::gui::thread_info(slot);
    // Nothing reaches it any more: activating another window must not
    // announce it to this thread (WM_ACTIVATEAPP).
    crate::input::forget_foreground(&info);
    let windows = info.windows.lock().clone();
    let count = windows.len();
    let is_top_level =
        |window: &Arc<Window>| window::get(window.state().parent).is_none_or(|parent| parent.is_desktop_window());
    let (top, rest): (Vec<_>, Vec<_>) = windows.into_iter().partition(is_top_level);
    for window in top.iter().chain(rest.iter()) {
        destroy(window, &info, Mode::Silent);
    }
    // A destruction it left halfway (it ended in WM_DESTROY, say).
    for window in window::windows_of(info.server) {
        info.windows.lock().retain(|other| !Arc::ptr_eq(other, &window));
        finish(&window, Some(&info));
    }
    drop((top, rest));
    crate::timer::destroy_thread_timers(&info);
    let (sent, _, _) = info.queue.with(crate::queue::QueueState::clear);
    let abandoned = sent.len();
    crate::sent::abandon_all(sent);
    crate::gui::leave_desktop(&info, thread.process());
    info.drop_keyboard_layout();
    let left = core::mem::take(&mut *info.windows.lock());
    if count != 0 || abandoned != 0 || !left.is_empty() {
        log::info!(
            "win32k: thread {} of {} ended with {} windows (destroyed), {} sent messages (given back)",
            thread.tid(),
            thread.process().image_file_name(),
            count,
            abandoned
        );
    }
    drop(left);
}

/// ExitProcessCallback : `process`, un processus GUI, se termine (son
/// dernier thread a fini) : ses objets USER qui restent sont détruits (ses
/// menus, ses tables d'accélérateurs ; une fenêtre qui resterait, sans
/// message), les DC du cache qu'il avait pris y reviennent, ses objets GDI
/// quittent la table, son `PROCESSINFO` rend ses classes, ses bureaux et sa
/// station. Ce qui reste ensuite est journalisé.
///
/// # IRQL
/// PASSIVE_LEVEL, dans son dernier thread (rappel de Ps ; pour un processus
/// sans thread, dans celui qui le termine), avant que ses handles soient
/// fermés et son espace d'adresses rendu. Aucun rappel du mode utilisateur,
/// rien n'y est lu ni écrit dans sa mémoire.
pub fn process_exit(process: &Arc<Object<EProcess>>) {
    let Some(info) = crate::existing_process_info(process) else { return };
    let pid = process.pid();
    let (mut windows, mut menus, mut cursors, mut accelerators) = (0, 0, 0, 0);
    for (handle, kind) in crate::handles::taken_by_process(pid) {
        match kind {
            TYPE_WINDOW => {
                if let Some(window) = window::get(handle) {
                    let thread = crate::gui::thread_info_of(window.pti);
                    if let Some(thread) = &thread {
                        thread.windows.lock().retain(|other| !Arc::ptr_eq(other, &window));
                    }
                    finish(&window, thread.as_ref());
                    windows += 1;
                }
            }
            TYPE_MENU if crate::menu::destroy(handle) => menus += 1,
            TYPE_CURSOR if crate::cursor::destroy(handle, true) => cursors += 1,
            TYPE_ACCELTABLE if crate::accel::destroy(handle) => accelerators += 1,
            _ => {}
        }
    }
    let dcs = crate::dce::free_process_dcs(pid);
    let gdi = crate::gdi::cleanup_process(pid);
    info.release();
    if windows != 0 || menus != 0 || cursors != 0 || accelerators != 0 || dcs != 0 || gdi != 0 {
        log::info!(
            "win32k: process {pid} ({}) ended: {windows} windows, {menus} menus, {cursors} cursors, {accelerators} accelerator tables, {dcs} cache DCs, {gdi} GDI objects given back",
            process.image_file_name()
        );
    }
    let (user_left, gdi_left) = (crate::handles::count_for_process(pid), crate::gdi::handles::count_of(pid));
    if user_left != 0 || gdi_left != 0 {
        log::warn!(
            "win32k: process {pid} ({}) leaves {user_left} USER and {gdi_left} GDI objects",
            process.image_file_name()
        );
    }
}
