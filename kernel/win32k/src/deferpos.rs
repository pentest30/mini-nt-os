//! DeferWindowPos : BeginDeferWindowPos, DeferWindowPos et EndDeferWindowPos,
//! comme `simplecall.c` (ONEPARAM_ROUTINE_BEGINDEFERWNDPOS) et `winpos.c`
//! (IntDeferWindowPos, IntEndDeferWindowPosEx) de win32k (ReactOS, comme
//! spécification).
//!
//! Un lot (`SMWP`, un HDWP) est un objet USER (`TYPE_SETWINDOWPOS`) qui
//! garde les déplacements demandés, un par fenêtre : un second déplacement
//! de la même fenêtre se fond dans le premier ([`Batch::defer`]). Le nombre
//! de fenêtres annoncé par BeginDeferWindowPos n'est qu'une indication, le
//! lot grandit à la demande. EndDeferWindowPos fait les déplacements l'un
//! après l'autre par SetWindowPos (co_WinPosSetWindowPos), dans l'ordre où
//! ils ont été demandés, saute une fenêtre détruite entre-temps et s'arrête
//! au premier qui échoue ; le lot est rendu dans tous les cas. Il est au
//! processus qui l'a commencé, dont la fin rend ceux qui restent
//! (`crate::destroy`).
//!
//! Pas encore : NtUserEndDeferWindowPosEx avec `bAsync` (chaque déplacement
//! envoyé à sa fenêtre, WM_ASYNC_SETWINDOWPOS), qu'EndDeferWindowPos de
//! `user32` ne demande pas ; refusé, journalisé une fois.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::user::{
    SWP_FRAMECHANGED, SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_NOCOPYBITS, SWP_NOMOVE, SWP_NOOWNERZORDER, SWP_NOREDRAW,
    SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, TYPE_SETWINDOWPOS,
};
use abi::winerror::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_DWP_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_SUCCESS,
};
use hal::sync::KSpinLock;

/// Un déplacement demandé : la fenêtre, la fenêtre après laquelle elle va
/// dans l'ordre Z (ou un `HWND_*`), sa place, sa taille et les `SWP_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Move {
    pub hwnd: u32,
    pub after: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub flags: u32,
}

/// Les `SWP_*` qu'un déplacement différé peut porter (IntDeferWindowPos).
pub const DEFERRED_FLAGS: u32 = SWP_NOSIZE
    | SWP_NOMOVE
    | SWP_NOZORDER
    | SWP_NOREDRAW
    | SWP_NOACTIVATE
    | SWP_NOCOPYBITS
    | SWP_NOOWNERZORDER
    | SWP_SHOWWINDOW
    | SWP_HIDEWINDOW
    | SWP_FRAMECHANGED;

/// Les `SWP_NO*` qu'un déplacement fondu garde seulement si les deux les
/// portaient : ce que l'un des deux change, il le change.
const KEPT_IF_BOTH: u32 =
    SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOREDRAW | SWP_NOACTIVATE | SWP_NOCOPYBITS | SWP_NOOWNERZORDER;

/// Les `SWP_*` que le second déplacement ajoute au premier.
const ADDED: u32 = SWP_SHOWWINDOW | SWP_HIDEWINDOW | SWP_FRAMECHANGED;

/// Les déplacements d'un lot, dans l'ordre de leur première demande.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    moves: Vec<Move>,
}

impl Batch {
    /// IntDeferWindowPos : le déplacement `next` entre dans le lot ; celui
    /// d'une fenêtre déjà là s'y fond : la place, la taille et le rang que
    /// `next` change remplacent les anciens, ses `SWP_NO*` ne restent que si
    /// les deux les portaient, SWP_SHOWWINDOW, SWP_HIDEWINDOW et
    /// SWP_FRAMECHANGED s'ajoutent.
    pub fn defer(&mut self, next: Move) {
        let Some(old) = self.moves.iter_mut().find(|old| old.hwnd == next.hwnd) else {
            self.moves.push(next);
            return;
        };
        if next.flags & SWP_NOZORDER == 0 {
            old.after = next.after;
        }
        if next.flags & SWP_NOMOVE == 0 {
            (old.x, old.y) = (next.x, next.y);
        }
        if next.flags & SWP_NOSIZE == 0 {
            (old.cx, old.cy) = (next.cx, next.cy);
        }
        old.flags &= next.flags | !KEPT_IF_BOTH;
        old.flags |= next.flags & ADDED;
    }

    /// Les déplacements, dans l'ordre où EndDeferWindowPos les fait.
    pub fn moves(&self) -> &[Move] {
        &self.moves
    }
}

/// Les lots ouverts, par handle.
static BATCHES: KSpinLock<Vec<(u32, Batch)>> = KSpinLock::new(Vec::new());

/// BeginDeferWindowPos (ONEPARAM_ROUTINE_BEGINDEFERWNDPOS) : un lot vide,
/// au processus courant, pour `count` fenêtres (une indication) ; rend son
/// handle.
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` pour un nombre négatif ;
/// `ERROR_NOT_ENOUGH_MEMORY` si la table des handles est pleine.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn begin(count: i32) -> Result<u32, u32> {
    if count < 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let owner = ps::ethread::current_thread()
        .and_then(|thread| crate::existing_process_info(thread.process()))
        .map_or(0, |info| info.server);
    // `user32` ne lit pas l'objet d'un lot : l'entrée porte une valeur non
    // nulle, sans plus.
    let handle = crate::handles::alloc(1, owner, TYPE_SETWINDOWPOS).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    BATCHES.lock().push((handle, Batch::default()));
    Ok(handle)
}

/// DeferWindowPos (IntDeferWindowPos) : le déplacement `next` entre dans le
/// lot `handle` ([`Batch::defer`]) ; rend le handle du lot.
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` pour un `SWP_*` hors de [`DEFERRED_FLAGS`] ;
/// `ERROR_INVALID_DWP_HANDLE` pour un lot qui n'existe pas.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn defer(handle: u32, next: Move) -> Result<u32, u32> {
    if next.flags & !DEFERRED_FLAGS != 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut batches = BATCHES.lock();
    let (_, batch) = batches.iter_mut().find(|(other, _)| *other == handle).ok_or(ERROR_INVALID_DWP_HANDLE)?;
    batch.defer(next);
    Ok(handle)
}

/// Retire le lot `handle` de la table et rend son handle.
fn take(handle: u32) -> Option<Batch> {
    let batch = {
        let mut batches = BATCHES.lock();
        let at = batches.iter().position(|(other, _)| *other == handle)?;
        batches.swap_remove(at).1
    };
    let _ = crate::handles::free(handle);
    Some(batch)
}

/// EndDeferWindowPos (IntEndDeferWindowPosEx) : les déplacements du lot
/// `handle`, l'un après l'autre par SetWindowPos ; une fenêtre détruite
/// entre-temps est sautée, le premier déplacement qui échoue arrête les
/// autres. Le lot est rendu. Rend si tous ont réussi ; après un déplacement
/// réussi qui ne change que la place ou la taille, la dernière erreur est
/// effacée (comme ReactOS).
///
/// # Errors
/// `ERROR_INVALID_DWP_HANDLE` pour un lot qui n'existe pas ;
/// `ERROR_CALL_NOT_IMPLEMENTED` avec `asynchronous` (le lot reste).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn end(handle: u32, asynchronous: bool) -> Result<bool, u32> {
    if asynchronous {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: EndDeferWindowPos with bAsync (WM_ASYNC_SETWINDOWPOS): not yet");
        }
        return Err(ERROR_CALL_NOT_IMPLEMENTED);
    }
    let batch = take(handle).ok_or(ERROR_INVALID_DWP_HANDLE)?;
    let mut done = true;
    for next in batch.moves() {
        let Some(window) = crate::window::get(next.hwnd) else { continue };
        done = crate::winpos::set_window_pos(&window, next.after, next.x, next.y, next.cx, next.cy, next.flags);
        if !done {
            break;
        }
        if next.flags & (SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER) == SWP_NOZORDER {
            let _ = crate::set_last_error(ERROR_SUCCESS);
        }
    }
    Ok(done)
}

/// Le lot `handle` est rendu sans rien déplacer (à la fin de son
/// processus) ; rend s'il existait.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn destroy(handle: u32) -> bool {
    take(handle).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moved(hwnd: u32, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> Move {
        Move { hwnd, after: 0, x, y, cx, cy, flags }
    }

    #[test]
    fn each_window_keeps_its_place_in_the_batch() {
        let mut batch = Batch::default();
        batch.defer(moved(0x10, 1, 2, 3, 4, SWP_NOZORDER));
        batch.defer(moved(0x20, 5, 6, 7, 8, SWP_NOZORDER));
        batch.defer(moved(0x10, 9, 9, 9, 9, SWP_NOZORDER | SWP_NOSIZE));
        let hwnds: Vec<u32> = batch.moves().iter().map(|next| next.hwnd).collect();
        assert_eq!(hwnds, [0x10, 0x20], "the second move of 0x10 merges with the first");
    }

    #[test]
    fn a_merged_move_takes_what_the_second_changes() {
        let mut batch = Batch::default();
        batch.defer(moved(0x10, 10, 20, 30, 40, SWP_NOZORDER | SWP_NOACTIVATE));
        batch.defer(Move { after: 1, ..moved(0x10, 0, 0, 300, 400, SWP_NOMOVE | SWP_NOACTIVATE | SWP_SHOWWINDOW) });
        let merged = batch.moves()[0];
        assert_eq!((merged.x, merged.y), (10, 20), "SWP_NOMOVE keeps the first place");
        assert_eq!((merged.cx, merged.cy), (300, 400), "the second size");
        assert_eq!(merged.after, 1, "the second asks a rank");
        assert_eq!(
            merged.flags,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
            "SWP_NOZORDER and SWP_NOMOVE go (one of the two changes them), SWP_NOACTIVATE stays, SWP_SHOWWINDOW is added"
        );
    }

    #[test]
    fn a_merged_move_keeps_the_first_rank_without_a_new_one() {
        let mut batch = Batch::default();
        batch.defer(Move { after: 1, ..moved(0x10, 1, 1, 1, 1, SWP_FRAMECHANGED) });
        batch.defer(moved(0x10, 2, 2, 2, 2, SWP_NOZORDER));
        let merged = batch.moves()[0];
        assert_eq!((merged.after, merged.x, merged.cx), (1, 2, 2));
        assert_eq!(merged.flags, SWP_FRAMECHANGED, "the first's SWP_FRAMECHANGED stays");
    }
}
