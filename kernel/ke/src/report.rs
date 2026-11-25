//! Le relevé des threads : ce que fait chaque thread du noyau, sur le port
//! série, quand un NMI le demande (`hal::idt::take_nmi_request`, que le
//! balance set manager regarde à chacun de ses passages, chaque seconde).
//! Pour un système figé : le moniteur de QEMU envoie le NMI (`nmi`), et le
//! relevé dit qui attend quoi.
//!
//! Une ligne par thread, `[threads]` en tête : son TID de Ke, son état, sa
//! priorité courante et de base, son propriétaire (le processus et le
//! thread de l'exécutif, que décrit la routine de [`set_owner_describer`]),
//! ce qu'il attend (le type, l'adresse et l'état de chaque objet, le
//! propriétaire d'un mutant) ; pour un thread utilisateur, la trame de sa
//! dernière entrée dans le noyau (EIP, ESP, et le service système en cours
//! d'après EAX) ; puis sa pile noyau symbolisée, depuis le contexte de sa
//! dernière commutation.
//!
//! Chaque thread est copié dans un [`Record`] sous le verrou dispatcher, sans
//! allocation, ses piles lues par les tables de pages
//! (`hal::bugcheck::read_mapped_word`) : un pointeur faux ne fait pas de
//! faute. Il s'imprime une fois le verrou rendu.

use core::ffi::c_void;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::dispatcher::{ObjectType, ProcessorMode, ThreadState};

/// Les objets d'une attente que le relevé montre.
pub const MAX_WAITS: usize = 4;
/// Les adresses de retour de la pile noyau que le relevé montre.
pub const MAX_FRAMES: usize = 24;
/// La place de la description du propriétaire.
pub const OWNER_LEN: usize = 48;

/// Décrit le propriétaire d'un thread (le pointeur `owner` de Ke : l'ETHREAD
/// de Ps) dans `out`.
///
/// # Safety
/// Appelée sous le verrou dispatcher, avec le propriétaire d'un thread
/// enregistré, qui reste valide tant que son thread l'est.
pub type OwnerDescriber = unsafe fn(owner: *const c_void, out: &mut dyn Write);

/// La routine de [`set_owner_describer`], ou 0.
static OWNER_DESCRIBER: AtomicUsize = AtomicUsize::new(0);

/// L'exécutif décrit les propriétaires des threads avec `describe` (le
/// processus et le thread de Ps).
///
/// # IRQL
/// Tout niveau.
pub fn set_owner_describer(describe: OwnerDescriber) {
    OWNER_DESCRIBER.store(describe as usize, Ordering::Release);
}

/// La routine de [`set_owner_describer`].
pub(crate) fn owner_describer() -> Option<OwnerDescriber> {
    let raw = OWNER_DESCRIBER.load(Ordering::Acquire);
    // SAFETY: seule `set_owner_describer` y écrit, une `OwnerDescriber`.
    (raw != 0).then(|| unsafe { core::mem::transmute::<usize, OwnerDescriber>(raw) })
}

/// Un objet qu'un thread attend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    pub kind: ObjectType,
    pub object: u64,
    pub signal_state: i32,
    /// Le TID de Ke du propriétaire d'un mutant.
    pub mutant_owner: Option<usize>,
}

/// La trame de la dernière entrée d'un thread utilisateur dans le noyau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trap {
    pub eip: u32,
    pub esp: u32,
    /// Le numéro du service système en cours, pour une entrée par `int 2Eh`
    /// ou SYSENTER (EAX tant que le service n'a pas rendu).
    pub service: Option<u32>,
}

/// Ce que le relevé sait d'un thread.
pub struct Record {
    pub tid: usize,
    pub state: ThreadState,
    pub priority: u8,
    pub base_priority: u8,
    pub user_mode: bool,
    /// Le thread qui fait le relevé.
    pub current: bool,
    pub wait_mode: ProcessorMode,
    pub alertable: bool,
    /// Les objets attendus (les [`MAX_WAITS`] premiers) et leur nombre.
    pub waits: [Option<Wait>; MAX_WAITS],
    pub wait_count: usize,
    pub trap: Option<Trap>,
    /// La pile noyau : l'adresse où il a quitté le processeur, puis les
    /// adresses de retour.
    pub frames: [u64; MAX_FRAMES],
    pub frame_count: usize,
    pub owner: [u8; OWNER_LEN],
    pub owner_len: usize,
}

impl Record {
    /// Un relevé vide du thread `tid`.
    pub const fn new(tid: usize, state: ThreadState) -> Self {
        Self {
            tid,
            state,
            priority: 0,
            base_priority: 0,
            user_mode: false,
            current: false,
            wait_mode: ProcessorMode::Kernel,
            alertable: false,
            waits: [None; MAX_WAITS],
            wait_count: 0,
            trap: None,
            frames: [0; MAX_FRAMES],
            frame_count: 0,
            owner: [0; OWNER_LEN],
            owner_len: 0,
        }
    }

    /// La description du propriétaire.
    pub fn owner(&self) -> &str {
        core::str::from_utf8(&self.owner[..self.owner_len]).unwrap_or("?")
    }

    /// Écrit la description du propriétaire (tronquée à [`OWNER_LEN`]).
    pub fn describe_owner(&mut self, describe: impl FnOnce(&mut dyn Write)) {
        let mut text = hal::symbols::FixedBuf::new(&mut self.owner);
        describe(&mut text);
        self.owner_len = text.as_str().len();
    }

    /// Ajoute une adresse de la pile ; `false` quand il n'y a plus de place.
    pub fn push_frame(&mut self, address: u64) -> bool {
        let Some(slot) = self.frames.get_mut(self.frame_count) else { return false };
        *slot = address;
        self.frame_count += 1;
        true
    }

    /// La ligne du thread, sans sa pile : son état, son propriétaire, son
    /// attente, sa trame (`service_name` nomme un service système).
    pub fn write_line(&self, out: &mut dyn Write, service_name: impl Fn(u32) -> Option<&'static str>) -> fmt::Result {
        write!(out, "ke {} {:?}", self.tid, self.state)?;
        if self.current {
            out.write_str(" (this report)")?;
        }
        write!(out, " prio {}/{}", self.priority, self.base_priority)?;
        out.write_str(if self.user_mode { " user" } else { " kernel" })?;
        if self.owner_len > 0 {
            write!(out, " ({})", self.owner())?;
        }
        if self.state == ThreadState::Waiting {
            let mode = match self.wait_mode {
                ProcessorMode::Kernel => "kernel",
                ProcessorMode::User => "user",
            };
            write!(out, "; waits {mode}")?;
            if self.alertable {
                out.write_str(" alertable")?;
            }
            write!(out, " on {}:", self.wait_count)?;
            for wait in self.waits.iter().flatten() {
                write!(out, " {:?}@{:#x}={}", wait.kind, wait.object, wait.signal_state)?;
                if let Some(owner) = wait.mutant_owner {
                    write!(out, " (owner ke {owner})")?;
                }
            }
        }
        if let Some(trap) = self.trap {
            match trap.service {
                Some(number) => {
                    write!(out, "; in {} ({number:#06x})", service_name(number).unwrap_or("an unknown service"))?;
                }
                None => out.write_str("; from user mode")?,
            }
            write!(out, " at eip {:08x} esp {:08x}", trap.eip, trap.esp)?;
        }
        Ok(())
    }
}

/// Le relevé de tous les threads, sur le port série : une ligne par thread,
/// puis sa pile noyau symbolisée.
///
/// # IRQL
/// PASSIVE_LEVEL (le balance set manager).
pub fn report_threads() {
    log::info!("[threads] report (NMI): {} context switches", crate::sched::context_switches());
    let mut count = 0;
    for tid in 0..crate::sched::tid_bound() {
        let Some(record) = crate::sched::record(tid) else { continue };
        count += 1;
        let mut line = [0u8; 320];
        let mut text = hal::symbols::FixedBuf::new(&mut line);
        let _ = record.write_line(&mut text, |number| abi::service::lookup(number).map(|(_, s)| s.name));
        log::info!("[threads] {}", text.as_str());
        for (index, &address) in record.frames[..record.frame_count].iter().enumerate() {
            // A return address: the call is the byte before it (the first
            // address is where the thread switched, not a return).
            let inside = if index == 0 { address } else { address - 1 };
            let mut name = [0u8; 160];
            let mut symbol = hal::symbols::FixedBuf::new(&mut name);
            match hal::symbols::lookup(inside) {
                Some((function, offset)) => {
                    let _ = hal::symbols::write_demangled(function, &mut symbol);
                    let _ = write!(symbol, "+{:#x}", offset + (address - inside));
                }
                None => {
                    let _ = write!(symbol, "{address:#x}");
                }
            }
            log::info!("[threads]     {}", symbol.as_str());
        }
    }
    log::info!("[threads] {count} threads");
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;

    fn line(record: &Record) -> String {
        let mut out = String::new();
        record.write_line(&mut out, |number| (number == 0x0001).then_some("NtWaitForSingleObject")).unwrap();
        out
    }

    #[test]
    fn a_waiting_user_thread_shows_its_owner_its_objects_and_its_service() {
        let mut record = Record::new(23, ThreadState::Waiting);
        record.priority = 10;
        record.base_priority = 8;
        record.user_mode = true;
        record.wait_mode = ProcessorMode::User;
        record.alertable = true;
        record.wait_count = 2;
        record.waits[0] = Some(Wait {
            kind: ObjectType::SynchronizationEvent,
            object: 0xFFFF_8000_0012_3450,
            signal_state: 0,
            mutant_owner: None,
        });
        record.waits[1] = Some(Wait {
            kind: ObjectType::Mutant,
            object: 0xFFFF_8000_0000_1000,
            signal_state: 0,
            mutant_owner: Some(7),
        });
        record.trap = Some(Trap { eip: 0x7C92_EB94, esp: 0x0180_FD00, service: Some(0x0001) });
        record.describe_owner(|out| {
            let _ = out.write_str("PID 132 TID 168 explorer.exe");
        });
        assert_eq!(
            line(&record),
            "ke 23 Waiting prio 10/8 user (PID 132 TID 168 explorer.exe); waits user alertable on 2: \
             SynchronizationEvent@0xffff800000123450=0 Mutant@0xffff800000001000=0 (owner ke 7); \
             in NtWaitForSingleObject (0x0001) at eip 7c92eb94 esp 0180fd00"
        );
    }

    #[test]
    fn a_ready_kernel_thread_is_one_short_line() {
        let mut record = Record::new(3, ThreadState::Ready);
        record.priority = 16;
        record.base_priority = 16;
        assert_eq!(line(&record), "ke 3 Ready prio 16/16 kernel");
        record.current = true;
        record.state = ThreadState::Running;
        assert_eq!(line(&record), "ke 3 Running (this report) prio 16/16 kernel");
    }

    #[test]
    fn a_user_thread_out_of_a_service_and_an_unknown_service_are_said_so() {
        let mut record = Record::new(5, ThreadState::Ready);
        record.user_mode = true;
        record.trap = Some(Trap { eip: 0x0040_1000, esp: 0x0012_FF00, service: None });
        assert!(line(&record).ends_with("; from user mode at eip 00401000 esp 0012ff00"), "{}", line(&record));
        record.trap = Some(Trap { eip: 0x0040_1000, esp: 0x0012_FF00, service: Some(0x7FF) });
        assert!(line(&record).contains("; in an unknown service (0x07ff)"), "{}", line(&record));
    }

    #[test]
    fn the_owner_and_the_frames_keep_to_their_room() {
        let mut record = Record::new(1, ThreadState::Ready);
        record.describe_owner(|out| {
            let _ = out.write_str(&"x".repeat(OWNER_LEN + 10));
        });
        assert_eq!(record.owner().len(), OWNER_LEN);
        for address in 0..MAX_FRAMES as u64 {
            assert!(record.push_frame(address));
        }
        assert!(!record.push_frame(99), "no room after MAX_FRAMES");
        assert_eq!(record.frame_count, MAX_FRAMES);
    }
}
