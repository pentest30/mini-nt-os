//! Le thread d'entrée brute (RIT, 02 §7.2 ; RawInputThreadMain d'`input.c`
//! de ReactOS, comme spécification) : il lit le clavier (`i8042`) et remet
//! chaque touche à win32k (`win32k::input::process_keyboard_input`).
//!
//! L'interruption du clavier (`hal::ps2`) appelle [`notify`], qui met un
//! DPC dans la file ; le DPC signale l'événement qu'attend le thread, à la
//! priorité de ReactOS (LOW_REALTIME_PRIORITY + 3). Le thread ne vide le
//! clavier qu'une fois que win32k a pris l'écran : avant, ce qui le lisait
//! (l'ancien lanceur, `syscall.rs`) le garde.
//!
//! Pas encore : la souris, les IRP (kbdclass), les bureaux d'entrée qui
//! changent, l'arrêt du thread.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use ke::dispatcher::{ke_initialize_event, ke_set_event, ke_wait_for_single_object, KEvent, ObjectType, ProcessorMode};
use ke::dpc::{ke_insert_queue_dpc, KDpc};
use ke::sched::KePlatform;

/// Ce que le DPC signale : une touche est dans l'anneau.
static EVENT: AtomicPtr<KEvent> = AtomicPtr::new(ptr::null_mut());
/// Le DPC de l'interruption du clavier.
static DPC: KDpc = KDpc::new(signal, ptr::null_mut());
/// Quand la dernière touche a été remise à win32k (`hal::timer::interrupt_time`,
/// en 100 ns) ; 0 avant la première.
static LAST_KEY: AtomicU64 = AtomicU64::new(0);

/// Quand la dernière touche a été remise à win32k, en unités de 100 ns de
/// `hal::timer::interrupt_time` ; `None` avant la première. La sonde de
/// `smss` attend un programme interactif tant qu'on le tape.
///
/// # IRQL
/// Tout niveau (une lecture atomique).
pub fn last_key_time() -> Option<u64> {
    Some(LAST_KEY.load(Ordering::Relaxed)).filter(|&time| time != 0)
}

/// Appelé par l'interruption du clavier : le DPC dans la file.
fn notify() {
    // SAFETY: a static DPC, which keeps its address; inserting it twice
    // leaves it once in the queue.
    unsafe { ke_insert_queue_dpc(&DPC, ptr::null_mut(), ptr::null_mut()) };
}

/// Le DPC : signale l'événement du thread.
fn signal(_dpc: *const KDpc, _context: *mut c_void, _arg1: *mut c_void, _arg2: *mut c_void) {
    let event = EVENT.load(Ordering::Acquire);
    if !event.is_null() {
        // SAFETY: an event initialised by `start`, never freed.
        unsafe { ke_set_event::<KePlatform>(event, 0) };
    }
}

/// Le thread d'entrée brute.
fn raw_input_thread(_context: *mut c_void) {
    let event = EVENT.load(Ordering::Acquire);
    let mut keyboard = i8042::Keyboard::new();
    loop {
        // SAFETY: an event initialised by `start`, never freed; this kernel
        // thread waits at PASSIVE_LEVEL.
        let header = unsafe { ptr::addr_of_mut!((*event).header) };
        // SAFETY: as above.
        let _ = unsafe { ke_wait_for_single_object::<KePlatform>(header, ProcessorMode::Kernel, false, None) };
        if !win32k::display::acquired() {
            continue;
        }
        while let Some(data) = keyboard.read() {
            win32k::input::process_keyboard_input(&data);
            LAST_KEY.store(hal::timer::interrupt_time().max(1), Ordering::Relaxed);
        }
    }
}

/// Démarre le thread d'entrée brute et branche l'interruption du clavier.
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, l'ordonnanceur prêt.
pub fn start() {
    assert!(EVENT.load(Ordering::Acquire).is_null(), "the raw input thread started twice");
    let event = alloc::boxed::Box::into_raw(alloc::boxed::Box::<KEvent>::new_uninit()).cast::<KEvent>();
    // SAFETY: fresh memory at a fixed address, never freed.
    unsafe { ke_initialize_event(event, ObjectType::SynchronizationEvent, false) };
    EVENT.store(event, Ordering::Release);
    hal::ps2::set_notify(Some(notify));
    crate::spawn_kernel_thread(ke::sched::LOW_REALTIME_PRIORITY + 3, raw_input_thread, ptr::null_mut());
    log::info!("[boot] raw input thread: the PS/2 keyboard (i8042) to win32k");
}
