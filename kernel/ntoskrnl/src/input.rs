//! Le thread d'entrée brute (RIT, 02 §7.2 ; RawInputThreadMain d'`input.c`
//! de ReactOS, comme spécification) : il lit le clavier et la souris
//! (`i8042`) et remet chaque touche et chaque mouvement à win32k
//! (`win32k::input::process_keyboard_input`,
//! `win32k::mouse::process_mouse_input`).
//!
//! L'interruption du clavier (`hal::ps2`) appelle [`notify`], qui met un
//! DPC dans la file ; le DPC signale l'événement qu'attend le thread, à la
//! priorité de ReactOS (LOW_REALTIME_PRIORITY + 3). Le thread ne vide le
//! clavier qu'une fois que win32k a pris l'écran : avant, ce qui le lisait
//! (l'ancien lanceur, `syscall.rs`) le garde.
//!
//! Les deux interruptions (IRQ1, IRQ12) appellent le même [`notify`].
//!
//! Le thread fait aussi expirer les minuteries de USER, comme le RIT de
//! ReactOS (son `MasterTimer`) : il attend au plus jusqu'à l'échéance la
//! plus proche (`win32k::timer::next_due`), puis appelle
//! `win32k::timer::expire`. Poser une minuterie signale son événement
//! (`win32k::timer::set_wake`), et il recalcule son attente.
//!
//! Sous VirtualBox, la souris est absolue (`vboxmouse`) : chaque paquet de la
//! souris PS/2 prend la position du pointeur de l'hôte que donne VMMDev,
//! tant que l'intégration de la souris de l'hôte est active.
//!
//! Pas encore : les IRP (kbdclass, mouclass), les bureaux d'entrée qui
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

/// La souris absolue de VirtualBox, si la machine en est une : sa page de
/// requêtes vient de Mm et reste au pilote ; rendue sinon.
fn absolute_mouse() -> Option<vboxmouse::VBoxMouse> {
    let pfn = mm::pfn::allocate_page(mm::pfn::PageUsage::NonPagedPool)?;
    let physical = pfn.to_phys();
    let virt = (hal::HHDM_OFFSET.load(Ordering::Acquire) + physical) as *mut u8;
    // SAFETY: a page just allocated, reached through the HHDM (which maps
    // the first 4 GiB; the driver refuses a page above), given to the driver
    // for good.
    match unsafe { vboxmouse::VBoxMouse::new(vboxmouse::RequestPage { physical, virt }) } {
        Ok(mouse) => {
            log::info!("[boot] raw input thread: VirtualBox's absolute mouse (VMMDev)");
            Some(mouse)
        }
        Err(reason) => {
            mm::pfn::free_page(pfn);
            if reason != vboxmouse::Unavailable::NoDevice {
                log::warn!("[boot] raw input thread: no absolute mouse from VMMDev: {reason:?}");
            }
            None
        }
    }
}

/// Réveille le thread : une minuterie de USER vient d'être posée.
fn wake_for_timers() {
    signal(ptr::null(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
}

/// Le délai relatif (négatif, en 100 ns) jusqu'à l'échéance `due` de la
/// minuterie la plus proche ; `None` sans minuterie. Une échéance passée
/// donne le délai le plus court.
fn timer_timeout(due: Option<u64>, now: u64) -> Option<i64> {
    due.map(|due| -(due.saturating_sub(now).clamp(1, i64::MAX as u64) as i64))
}

/// Le thread d'entrée brute.
fn raw_input_thread(_context: *mut c_void) {
    let event = EVENT.load(Ordering::Acquire);
    let mut keyboard = i8042::Keyboard::new();
    let mut mouse = i8042::Mouse::new();
    let mut absolute = mouse.as_ref().and_then(|_| absolute_mouse());
    let mut first_packet = true;
    let mut first_absolute = true;
    loop {
        // SAFETY: an event initialised by `start`, never freed; this kernel
        // thread waits at PASSIVE_LEVEL.
        let header = unsafe { ptr::addr_of_mut!((*event).header) };
        let timeout = timer_timeout(win32k::timer::next_due(), hal::timer::interrupt_time());
        // SAFETY: as above.
        let _ = unsafe { ke_wait_for_single_object::<KePlatform>(header, ProcessorMode::Kernel, false, timeout) };
        win32k::timer::expire();
        if !win32k::display::acquired() {
            continue;
        }
        while let Some(data) = keyboard.read() {
            win32k::input::process_keyboard_input(&data);
            LAST_KEY.store(hal::timer::interrupt_time().max(1), Ordering::Relaxed);
        }
        while let Some(mut data) = mouse.as_mut().and_then(i8042::Mouse::read) {
            if absolute.as_mut().is_some_and(|vbox| vbox.apply(&mut data)) {
                if first_absolute {
                    first_absolute = false;
                    log::info!("[input] VirtualBox mouse: first absolute position: {}, {}", data.last_x, data.last_y);
                }
            } else if first_packet && (data.last_x, data.last_y, data.button_flags) != (0, 0, 0) {
                // The first packet that does something, once (a boot
                // scenario's marker); never one per packet.
                first_packet = false;
                log::info!(
                    "[input] PS/2 mouse: first packet: dx={}, dy={}, buttons={:#06x}",
                    data.last_x,
                    data.last_y,
                    data.button_flags
                );
            }
            win32k::mouse::process_mouse_input(&data);
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
    win32k::timer::set_wake(wake_for_timers);
    hal::ps2::set_notify(Some(notify));
    crate::spawn_kernel_thread(ke::sched::LOW_REALTIME_PRIORITY + 3, raw_input_thread, ptr::null_mut());
    match hal::ps2::mouse_packet_size() {
        Some(size) => {
            log::info!("[boot] raw input thread: the PS/2 keyboard and mouse ({size}-byte packets, i8042) to win32k")
        }
        None => log::info!("[boot] raw input thread: the PS/2 keyboard (i8042) to win32k; no mouse"),
    }
}
