//! Les portes du mode utilisateur (02 §6.1), sur la trame de trap
//! (`hal::trap`) :
//!
//! | Porte | Service |
//! |---|---|
//! | `int 2Ah` | KiGetTickCount : EAX reçoit les millisecondes depuis le démarrage |
//! | `int 2Bh` | KiCallbackReturn : `STATUS_NO_CALLBACK_ACTIVE`, en attendant `KeUserModeCallback` (M6) |
//! | `int 2Ch` | KiRaiseAssertion : l'exception `STATUS_ASSERTION_FAILURE`, à l'adresse de l'`int 2Ch` ([`super::exceptions`]) |
//! | `int 2Dh` | KiDebugService : `DbgPrint` vers le port série |
//! | `int 2Eh` | KiSystemService ([`super::dispatch`]) |

use abi::ntstatus::{STATUS_ASSERTION_FAILURE, STATUS_NO_CALLBACK_ACTIVE, STATUS_SUCCESS};
use hal::trap::{set_trap_hook, KTrapFrame};

/// Le service de débogage qui affiche une chaîne (BREAKPOINT_PRINT).
const BREAKPOINT_PRINT: u32 = 1;

/// Au plus autant d'octets par `DbgPrint`, comme le tampon d'XP.
const MAX_PRINT: u32 = 512;

/// Branche les portes `int 2Ah` à `int 2Eh`.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn install() {
    set_trap_hook(0x2A, Some(get_tick_count));
    set_trap_hook(0x2B, Some(callback_return));
    set_trap_hook(0x2C, Some(raise_assertion));
    set_trap_hook(0x2D, Some(debug_service));
    set_trap_hook(0x2E, Some(system_service));
}

/// `int 2Ah` : GetTickCount, en millisecondes (sur 32 bits, qui bouclent).
fn get_tick_count(frame: &mut KTrapFrame) {
    frame.rax = u64::from(hal::timer::get_tick_count() as u32);
}

/// `int 2Bh` : pas de rappel en mode utilisateur en cours.
fn callback_return(frame: &mut KTrapFrame) {
    frame.rax = u64::from(STATUS_NO_CALLBACK_ACTIVE.0);
}

/// `int 2Ch` : une assertion a échoué en mode utilisateur ; l'exception est
/// à l'instruction, deux octets avant EIP.
fn raise_assertion(frame: &mut KTrapFrame) {
    frame.rip -= 2;
    super::exceptions::raise(frame, STATUS_ASSERTION_FAILURE, &[]);
}

/// `int 2Dh` : EAX donne le service, ECX et EDX ses arguments ; `ntdll` fait
/// suivre l'instruction d'un `int 3`, que le noyau saute. `BREAKPOINT_PRINT`
/// écrit les EDX octets en ECX (512 au plus) sur le port série, précédés du
/// PID et du TID ; sans débogueur, les autres services ne font rien.
fn debug_service(frame: &mut KTrapFrame) {
    frame.rip += 1;
    if frame.rax as u32 == BREAKPOINT_PRINT {
        x86_64::instructions::interrupts::enable();
        print(frame.rcx as u32, (frame.rdx as u32).min(MAX_PRINT));
        x86_64::instructions::interrupts::disable();
    }
    frame.rax = u64::from(STATUS_SUCCESS.0);
}

/// Écrit la chaîne de `length` octets en `buffer`, adresse utilisateur.
fn print(buffer: u32, length: u32) {
    let mut bytes = [0u8; MAX_PRINT as usize];
    let bytes = &mut bytes[..length as usize];
    if ke::usermem::copy_from_user(bytes, u64::from(buffer)).is_err() {
        return;
    }
    let text: alloc::string::String = bytes
        .iter()
        .map(|&b| if b == b'\n' || b == b'\t' || (0x20..0x7F).contains(&b) { char::from(b) } else { '?' })
        .collect();
    let (pid, tid) = ps::ethread::current_thread().map_or((0, 0), |thread| (thread.pid(), thread.tid()));
    log::info!("DbgPrint {pid}.{tid}: {}", text.trim_end_matches('\n'));
}

/// `int 2Eh` : un thread de Ps va à KiSystemService, interruptions actives ;
/// un thread de l'ancien chargeur à son dispatcher (`syscall`), qui a ses
/// propres numéros.
fn system_service(frame: &mut KTrapFrame) {
    let (number, arguments) = (frame.rax as u32, frame.rdx as u32);
    if ke::sched::current_thread_owner().is_null() {
        frame.rax = u64::from(crate::syscall::dispatch(number, arguments));
        return;
    }
    x86_64::instructions::interrupts::enable();
    if let super::Completion::Status(status) = super::dispatch(number, arguments, Some(&mut *frame)) {
        frame.rax = u64::from(status.0);
    }
    x86_64::instructions::interrupts::disable();
}
