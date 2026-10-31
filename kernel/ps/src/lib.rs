//! Ps — processus et threads (02 §5.5).
//!
//! - [`eprocess`] : EPROCESS, création d'un processus à partir d'une section
//!   d'image (espace d'adresses, image, PEB), le processus System.
//! - [`ethread`] : ETHREAD, création d'un thread utilisateur (TEB, pile
//!   noyau, thread Ke) et de sa pile utilisateur.
//! - [`exit`] : fin des threads et des processus (APC de fin, rundown,
//!   reaper).
//! - [`nls`] : les tables NLS (pages de code ANSI et OEM, casse Unicode),
//!   projetées dans chaque processus.
//! - [`process_parameters`] : les paramètres d'un processus
//!   (RTL_USER_PROCESS_PARAMETERS), que le noyau écrit dans ceux qu'il crée.
//! - [`cid`] : la table des PID et des TID.
//!
//! EPROCESS et ETHREAD sont des structures Rust sans contrainte de layout ;
//! seuls le PEB32 et le TEB32 suivent XP (`abi`). Les appels système
//! viendront au M3.
//!
//! [`loader`] est l'ancien chargeur (audit §5), qui projette encore son image
//! dans l'espace du système.
//!
//! WI7e Ch.5 §Processes and Threads

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod cid;
pub mod eprocess;
pub mod ethread;
pub mod exit;
#[expect(unsafe_op_in_unsafe_fn, reason = "ancien chargeur, à supprimer (audit §5)")]
pub mod loader;
pub mod nls;
pub mod process_parameters;
pub mod rundown;
pub mod system_dll;

pub use eprocess::{create_process, lookup_process, system_process, EProcess, PROCESS_TYPE};
pub use ethread::{
    create_thread, create_thread_with_parameter, create_user_stack, lookup_thread, EThread, InitialTeb, THREAD_TYPE,
};
pub use exit::{
    exit_thread, terminate_current_process, terminate_other_threads, terminate_process, terminate_thread,
    wait_for_reaper,
};
pub use process_parameters::ProcessParameters;

use alloc::boxed::Box;
use alloc::sync::Weak;

use hal::sync::KSpinLock;
use ke::dispatcher::{
    ke_initialize_event, ke_reset_event, ke_set_event, ke_wait_for_single_object, DispatcherHeader, KEvent,
    ObjectType as KObjectType, ProcessorMode, EVENT_INCREMENT,
};
use ke::sched::KePlatform;
use ob::Object;

use cid::CidTable;

/// Ce que désigne un PID ou un TID.
pub(crate) enum CidEntry {
    Process(Weak<Object<EProcess>>),
    Thread(Weak<Object<EThread>>),
}

/// PspCidTable.
pub(crate) static CID_TABLE: KSpinLock<CidTable<CidEntry>> = KSpinLock::new(CidTable::new());

/// Un événement du dispatcher dans un objet partagé : à adresse fixe (il est
/// chaîné aux blocs d'attente), libéré avec son propriétaire.
pub(crate) struct DispatcherEvent(*mut KEvent);

// SAFETY: Ke ne touche à l'événement que sous le verrou dispatcher.
unsafe impl Send for DispatcherEvent {}
// SAFETY: voir `Send`.
unsafe impl Sync for DispatcherEvent {}

impl DispatcherEvent {
    /// Un événement non signalé, de notification ou de synchronisation.
    pub(crate) fn new(kind: KObjectType) -> Self {
        let event = Box::into_raw(Box::<KEvent>::new_uninit()).cast::<KEvent>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_event(event, kind, false) };
        Self(event)
    }

    /// Son en-tête, à attendre.
    pub(crate) fn header(&self) -> *mut DispatcherHeader {
        // SAFETY: l'événement vit autant que `self`.
        unsafe { core::ptr::addr_of_mut!((*self.0).header) }
    }

    /// KeSetEvent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub(crate) fn set(&self) {
        // SAFETY: initialisé par `new`.
        unsafe { ke_set_event::<KePlatform>(self.0, EVENT_INCREMENT) };
    }

    /// KeResetEvent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub(crate) fn reset(&self) {
        // SAFETY: initialisé par `new`.
        unsafe { ke_reset_event::<KePlatform>(self.0) };
    }

    /// Attend qu'il soit signalé, en mode noyau, sans délai.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub(crate) fn wait(&self) {
        // SAFETY: initialisé par `new`, vivant pendant l'attente (`&self`).
        unsafe { ke_wait_for_single_object::<KePlatform>(self.header(), ProcessorMode::Kernel, false, None) };
    }
}

impl Drop for DispatcherEvent {
    fn drop(&mut self) {
        // SAFETY: alloué par `new` ; son propriétaire meurt, et personne ne
        // l'attend sans le tenir.
        drop(unsafe { Box::from_raw(self.0) });
    }
}

/// Crée le processus System (PID 4) et lance le reaper.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois, après `ke::init` et `ob::init`.
pub fn init() {
    eprocess::init_system_process();
    exit::start_reaper();
    log::info!("Ps: System process created (PID {}), reaper started", system_process().pid());
}
