//! L'écrivain paresseux (02 §5.6) : un thread système qui, chaque seconde,
//! réécrit les ruches dues (`cm::lazy_flush` : 5 s sans changement, ou 30 s
//! d'attente), puis vide les volumes montés dont quelque chose attend
//! (`io_manager::lazy_writer::MOUNTED` : les secteurs de la FAT gardés en
//! mémoire, le cache du disque). Les ruches d'abord : leur réécriture écrit
//! sur un volume, que le même passage vide ensuite. C'est ce que font
//! l'écrivain paresseux du gestionnaire de cache et l'écriture différée des
//! ruches de NT (CcLazyWriteScan, CmpLazyFlush de ReactOS, comme
//! spécification).
//!
//! L'arrêt ([`flush_everything`], NtShutdownSystem) réécrit toutes les
//! ruches qui ont changé, puis vide tous les volumes (CmShutdownSystem, puis
//! IoShutdownSystem).
//!
//! Une coupure de courant perd ce qui a changé depuis le dernier passage :
//! une ruche, ses 5 dernières secondes au plus (30 si elle ne cesse pas de
//! changer) ; un volume, sa dernière seconde. Après un passage qui ne laisse
//! rien en attente, le disque est cohérent.
//!
//! Une erreur est journalisée quand elle apparaît, puis quand elle cesse ;
//! jamais à chaque passage. Avec la feature `trace-lazy-writer`, chaque
//! passage qui écrit le dit, et dit « everything written » s'il ne laisse
//! rien en attente : le marqueur qu'attend le scénario `power-cut` avant de
//! couper le courant.

use core::ffi::c_void;
use core::ptr;

use abi::ntstatus::NtStatus;
use ke::dispatcher::{ke_delay_execution_thread, ProcessorMode};
use ke::sched::KePlatform;

/// La priorité du thread : celle des threads de travail différé de NT
/// (DelayedWorkQueue), au-dessus des threads ordinaires.
const PRIORITY: u8 = 12;
/// Un passage par seconde (une échéance relative, en 100 ns).
const PERIOD: i64 = -10_000_000;

/// Démarre le thread.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, l'ordonnanceur prêt.
pub fn start() {
    crate::spawn_kernel_thread(PRIORITY, lazy_writer_thread, ptr::null_mut());
    log::info!("[boot] lazy writer: the hives and the mounted volumes written back every second");
}

/// Ce que le dernier passage a rencontré : une erreur des ruches, des
/// volumes (pour ne journaliser que ses changements).
#[derive(Default)]
struct Errors {
    hives: Option<NtStatus>,
    volumes: Option<NtStatus>,
}

/// Le thread de l'écrivain paresseux.
fn lazy_writer_thread(_context: *mut c_void) {
    let mut errors = Errors::default();
    loop {
        // SAFETY: a kernel thread of Ke, at PASSIVE_LEVEL; it waits for
        // nothing but the interval.
        let _ = unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, PERIOD) };
        pass(&mut errors);
    }
}

/// Un passage : les ruches dues, puis les volumes.
fn pass(errors: &mut Errors) {
    #[cfg(feature = "trace-lazy-writer")]
    let start = hal::timer::interrupt_time();
    let hives = cm::registry().map(|registry| cm::lazy_flush(&registry, hal::timer::interrupt_time()));
    let hives = hives.unwrap_or_default();
    let volumes = io_manager::lazy_writer::MOUNTED.write_behind();
    report("the hives", &mut errors.hives, hives.error);
    report("the mounted volumes", &mut errors.volumes, volumes.error);
    #[cfg(feature = "trace-lazy-writer")]
    if hives.hives != 0 || volumes.volumes != 0 {
        let waiting = cm::registry().is_some_and(|registry| cm::hives_waiting(&registry))
            || io_manager::lazy_writer::MOUNTED.is_dirty();
        log::info!(
            "[lazy writer] wrote {} hive(s), {} volume(s) in {} ms; {}",
            hives.hives,
            volumes.volumes,
            hal::timer::interrupt_time().saturating_sub(start) / 10_000,
            if waiting { "more waits" } else { "everything written" }
        );
    }
}

/// Journalise une erreur de `what` quand elle apparaît ou change, et sa fin.
fn report(what: &str, last: &mut Option<NtStatus>, now: Option<NtStatus>) {
    if *last == now {
        return;
    }
    match now {
        Some(status) => log::warn!("[lazy writer] {what} not written back: {status}"),
        None => log::info!("[lazy writer] {what} written back again"),
    }
    *last = now;
}

/// L'arrêt : chaque ruche qui a changé est réécrite (CmShutdownSystem),
/// puis chaque volume monté vidé, son disque compris (IoShutdownSystem).
/// Rend la première erreur ; le reste est écrit quand même.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn flush_everything() -> Result<(), NtStatus> {
    let hives = cm::registry().map_or(Ok(()), |registry| cm::flush_all(&registry));
    let volumes = io_manager::lazy_writer::MOUNTED.flush();
    hives.and(volumes)
}
