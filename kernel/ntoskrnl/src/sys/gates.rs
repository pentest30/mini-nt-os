//! Les portes du mode utilisateur (02 §6.1), sur la trame de trap
//! (`hal::trap`) :
//!
//! | Porte | Service |
//! |---|---|
//! | `int 2Ah` | KiGetTickCount : EAX reçoit les millisecondes depuis le démarrage |
//! | `int 2Bh` | KiCallbackReturn : `STATUS_NO_CALLBACK_ACTIVE`, en attendant `KeUserModeCallback` (M6) |
//! | `int 2Ch` | KiRaiseAssertion : l'exception `STATUS_ASSERTION_FAILURE`, à l'adresse de l'`int 2Ch` ([`super::exceptions`]) |
//! | `int 2Dh` | KiDebugService : `DbgPrint` vers le port série ; `DbgPrompt`, faute de débogueur, reçoit `i` |
//! | `int 2Eh` | KiSystemService ([`super::dispatch`]) |
//! | SYSENTER | KiFastCallEntry, vers le même KiSystemService |

use abi::ntstatus::{STATUS_ASSERTION_FAILURE, STATUS_NO_CALLBACK_ACTIVE, STATUS_SUCCESS};
use hal::trap::{set_trap_hook, KTrapFrame, SYSENTER};

/// Le service de débogage qui affiche une chaîne (BREAKPOINT_PRINT).
const BREAKPOINT_PRINT: u32 = 1;
/// Le service de débogage qui pose une question au débogueur
/// (BREAKPOINT_PROMPT).
const BREAKPOINT_PROMPT: u32 = 2;
/// La réponse que donne le noyau, faute de débogueur : « Ignore », ce que
/// demande `RtlAssert` après une assertion qui échoue. Sans réponse, il
/// reposerait la question sans fin.
const PROMPT_ANSWER: &[u8] = b"i";

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
    set_trap_hook(SYSENTER, Some(fast_system_service));
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

/// `int 2Dh` : EAX donne le service, ECX, EDX, EBX et EDI ses arguments ;
/// `ntdll` fait suivre l'instruction d'un `int 3`, que le noyau saute.
/// `BREAKPOINT_PRINT` écrit les EDX octets en ECX (512 au plus) sur le port
/// série, précédés du PID et du TID. `BREAKPOINT_PROMPT` écrit de même la
/// question, puis, faute de débogueur, met [`PROMPT_ANSWER`] dans le tampon de
/// EDI octets en EBX et rend sa longueur, ce que le journal dit aussi. Sans
/// débogueur, les autres services ne font rien.
fn debug_service(frame: &mut KTrapFrame) {
    frame.rip += 1;
    let service = frame.rax as u32;
    frame.rax = u64::from(STATUS_SUCCESS.0);
    if service != BREAKPOINT_PRINT && service != BREAKPOINT_PROMPT {
        return;
    }
    x86_64::instructions::interrupts::enable();
    print(frame.rcx as u32, (frame.rdx as u32).min(MAX_PRINT));
    if service == BREAKPOINT_PROMPT {
        let answered = PROMPT_ANSWER.len() <= frame.rdi as u32 as usize
            && ke::usermem::copy_to_user(u64::from(frame.rbx as u32), PROMPT_ANSWER).is_ok();
        let length = if answered { PROMPT_ANSWER.len() } else { 0 };
        log::info!(
            "DbgPrompt: no debugger, answered {:?}",
            core::str::from_utf8(&PROMPT_ANSWER[..length]).unwrap_or("")
        );
        frame.rax = length as u64;
    }
    x86_64::instructions::interrupts::disable();
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

/// `int 2Eh` : EAX donne le service, EDX l'adresse de ses arguments. Un
/// thread de Ps va à KiSystemService ; un thread de l'ancien chargeur à son
/// dispatcher (`syscall`), qui a ses propres numéros.
fn system_service(frame: &mut KTrapFrame) {
    let (number, arguments) = (frame.rax as u32, frame.rdx as u32);
    if ke::sched::current_thread_owner().is_null() {
        frame.rax = u64::from(crate::syscall::dispatch(number, arguments));
        return;
    }
    service(frame, number, arguments);
}

/// L'adresse où un thread de l'ancien chargeur revient de SYSENTER : le
/// `ret` de son KUSER_SHARED_DATA, dans l'espace du système.
const LEGACY_SYSTEM_CALL_RETURN: u32 = ps::loader::SHARED_USER_DATA32_VA + 0x300;

/// SYSENTER : EAX donne le service, EDX la pile utilisateur au `sysenter`, et
/// la trame attend son EIP de retour.
///
/// - Un thread de Ps suit l'ABI d'XP : sur sa pile, le retour dans le stub de
///   ntdll, celui de l'appelant du stub, puis les arguments (EDX + 8). Il
///   revient par `ntdll!KiFastSystemCallRet`
///   (`SharedUserData->SystemCallReturn`), avec ESP en EDX : son `ret` rend
///   la main au stub.
/// - Un thread de l'ancien chargeur a ses arguments en EDX + 4 et revient par
///   [`LEGACY_SYSTEM_CALL_RETURN`].
fn fast_system_service(frame: &mut KTrapFrame) {
    let (number, stack) = (frame.rax as u32, frame.rdx as u32);
    if ke::sched::current_thread_owner().is_null() {
        frame.rip = u64::from(LEGACY_SYSTEM_CALL_RETURN);
        frame.rax = u64::from(crate::syscall::dispatch(number, stack.wrapping_add(4)));
        return;
    }
    frame.rip = u64::from(system_call_return());
    service(frame, number, stack.wrapping_add(8));
}

/// `SharedUserData->SystemCallReturn` : `ntdll!KiFastSystemCallRet`, ou 0
/// sans DLL système (le thread faute alors en 0, et son exception le suit).
fn system_call_return() -> u32 {
    mm::shared_data::kernel_alias().map_or(0, |shared| {
        // SAFETY: the kernel alias of the shared page, mapped for good; the
        // kernel writes this word whole.
        unsafe { core::ptr::addr_of!((*shared).system_call_return).read_volatile() }
    })
}

/// KiSystemService pour un thread de Ps, interruptions actives : le statut
/// dans EAX, sauf pour un service qui a mis dans la trame le nouveau
/// contexte du thread.
fn service(frame: &mut KTrapFrame, number: u32, arguments: u32) {
    x86_64::instructions::interrupts::enable();
    if let super::Completion::Status(status) = super::dispatch(number, arguments, frame) {
        frame.rax = u64::from(status.0);
    }
    x86_64::instructions::interrupts::disable();
}
