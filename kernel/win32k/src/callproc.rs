//! Les procédures d'appel (CALLPROCDATA, 02 §7.2) : la procédure d'une
//! classe ou d'une fenêtre demandée dans l'autre jeu de caractères
//! (GetClassInfoA d'une classe Unicode, GetWindowLongW d'une fenêtre ANSI)
//! ne se donne pas telle quelle : le client recevrait une procédure qu'il
//! appellerait avec des messages de l'autre jeu. Comme ReactOS
//! (`callproc.c`, comme spécification), win32k lui donne un handle de USER
//! de type `TYPE_CALLPROC` au mot haut `0xFFFF` (GetCallProcHandle) ; sa
//! `CALLPROCDATA` (`abi::user::CallProcData32`), dans le tas du bureau du
//! thread qui l'a demandé, dit la procédure et sa conversion (`wType` :
//! `CPD_A2U`, un appelant ANSI d'une procédure Unicode ; `CPD_U2A`, l'inverse).
//! CallWindowProcA et CallWindowProcW de `user32` la reconnaissent
//! (IsCallProcHandle, ValidateCallProc : l'entrée de la table des handles
//! doit être au `PROCESSINFO` de l'appelant) et convertissent les messages.
//!
//! Une classe garde les siennes (`spcpdFirst`) : une même procédure demandée
//! de la même façon rend le même handle (UserSearchForCallProc), et elles
//! partent avec la classe ([`destroy_class`]) ou avec le processus
//! ([`destroy`], `crate::destroy`).
//!
//! Écart : `spcpdNext` reste nul dans le tas (`user32` ne le lit pas ; win32k
//! garde la liste chez lui).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use abi::menu::ProcDeskHead32;
use abi::user::{CallProcData32, TYPE_CALLPROC};
use hal::sync::KSpinLock;

use crate::desktop::DesktopHeap;

/// GetCallProcHandle : la valeur que voit le client, le handle au mot haut
/// `0xFFFF`.
pub const fn handle_value(handle: u32) -> u32 {
    handle | 0xFFFF_0000
}

/// IsCallProcHandle : la valeur `procedure` est celle d'une procédure
/// d'appel.
pub const fn is_call_proc(procedure: u32) -> bool {
    procedure & 0xFFFF_0000 == 0xFFFF_0000
}

/// Une procédure d'appel : son handle, la classe qui la garde (son adresse),
/// sa procédure (`pfnClientPrevious`), son `wType`, et sa place dans le tas.
struct CallProc {
    handle: u32,
    class: usize,
    procedure: u32,
    kind: u32,
    heap: Arc<DesktopHeap>,
    at: u32,
}

/// Ce que le client voit d'une procédure de classe ou de fenêtre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// Cette procédure.
    Procedure(u32),
    /// Cette procédure, de l'autre jeu de caractères : le client en reçoit
    /// une procédure d'appel ([`Seen::for_client`]).
    Crossed(u32),
}

impl Seen {
    /// La valeur que reçoit le client : la procédure ; pour une procédure de
    /// l'autre jeu de caractères, la procédure d'appel de la classe `class`
    /// de `wType` `kind` ([`get`]), ou la procédure même sans elle, comme
    /// ReactOS.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans un service système.
    pub fn for_client(self, class: usize, kind: u32) -> u32 {
        match self {
            Self::Procedure(procedure) => procedure,
            Self::Crossed(procedure) => get(class, kind, procedure).unwrap_or(procedure),
        }
    }
}

/// Toutes les procédures d'appel.
static CALL_PROCS: KSpinLock<Vec<CallProc>> = KSpinLock::new(Vec::new());

/// UserGetCPD : la procédure d'appel de la classe `class` (son adresse,
/// celle de son `Class`) pour `procedure` et `kind` (`wType` : `CPD_A2U` ou
/// `CPD_U2A`, et `CPD_CLASS`, `CPD_WINDOW`… selon la demande), celle qu'elle
/// a déjà ou une neuve dans le tas du bureau du thread courant, au processus
/// courant ; rend la valeur à donner au client ([`handle_value`]).
/// `None` hors d'un thread GUI sur un bureau, ou si le tas ou la table des
/// handles sont pleins : l'appelant rend alors la procédure elle-même, comme
/// ReactOS.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn get(class: usize, kind: u32, procedure: u32) -> Option<u32> {
    let found = CALL_PROCS
        .lock()
        .iter()
        .find(|cpd| cpd.class == class && cpd.procedure == procedure && cpd.kind == kind)
        .map(|cpd| cpd.handle);
    if let Some(handle) = found {
        return Some(handle_value(handle));
    }
    let thread = ps::ethread::current_thread()?;
    let info = thread.win32_thread().map(crate::gui::thread_info)?;
    let owner = crate::existing_process_info(thread.process())?.server;
    let heap = info.desktop()?.desktop.heap.clone();
    let size = size_of::<CallProcData32>() as u32;
    let at = heap.alloc(size).ok()?;
    let Ok(handle) = crate::handles::alloc(heap.server_address(at), owner, TYPE_CALLPROC) else {
        heap.free(at, size);
        return None;
    };
    let record = CallProcData32 {
        head: ProcDeskHead32 {
            h: handle,
            c_lock_obj: 0,
            h_task_wow: owner,
            rpdesk: heap.server_address(0),
            p_self: heap.server_address(at),
        },
        spcpd_next: 0,
        pfn_client_previous: procedure,
        w_type: kind,
    };
    if heap.section.write_kernel(u64::from(at), record.as_bytes()).is_err() {
        let _ = crate::handles::free(handle);
        heap.free(at, size);
        return None;
    }
    CALL_PROCS.lock().push(CallProc { handle, class, procedure, kind, heap, at });
    Some(handle_value(handle))
}

/// UserGetCallProcInfo, pour une valeur que le client donne (une procédure
/// d'appel, [`is_call_proc`]) : sa procédure et son `wType`. Comme
/// UserGetObject, le mot haut ne compte pas.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn info(value: u32) -> Option<(u32, u32)> {
    if !is_call_proc(value) {
        return None;
    }
    let index = crate::handles::index(value)?;
    CALL_PROCS
        .lock()
        .iter()
        .find(|cpd| crate::handles::index(cpd.handle) == Some(index))
        .map(|cpd| (cpd.procedure, cpd.kind))
}

/// Rend une procédure d'appel : son handle, sa place dans le tas.
fn release(cpd: CallProc) {
    let _ = crate::handles::free(cpd.handle);
    cpd.heap.free(cpd.at, size_of::<CallProcData32>() as u32);
}

/// IntDestroyClass : les procédures d'appel de la classe `class` (son
/// adresse) partent avec elle.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn destroy_class(class: usize) {
    let gone: Vec<CallProc> = {
        let mut all = CALL_PROCS.lock();
        let (gone, kept) = core::mem::take(&mut *all).into_iter().partition(|cpd| cpd.class == class);
        *all = kept;
        gone
    };
    gone.into_iter().for_each(release);
}

/// La procédure d'appel de handle `handle` part (la fin de son processus) ;
/// faux sans elle.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn destroy(handle: u32) -> bool {
    let gone = {
        let mut all = CALL_PROCS.lock();
        all.iter().position(|cpd| cpd.handle == handle).map(|at| all.swap_remove(at))
    };
    gone.map(release).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_procedure_is_its_handle_with_the_high_word_set() {
        assert_eq!(handle_value(0x0002_0024), 0xFFFF_0024, "GetCallProcHandle: the generation goes");
        assert!(is_call_proc(0xFFFF_0024));
        assert!(!is_call_proc(0x7BDF_40E8), "a procedure");
        assert!(!is_call_proc(0x0002_0024), "a handle");
        assert_eq!(crate::handles::index(0xFFFF_0024), crate::handles::index(0x0002_0024), "the same entry");
        assert_eq!(info(0x0040_1000), None, "not a call procedure");
        assert_eq!(info(0xFFFF_7FFE), None, "none made");
    }
}
