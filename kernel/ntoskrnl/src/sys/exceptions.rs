//! Les exceptions du mode utilisateur (02 §6.5) : les fautes du processeur
//! (par `hal::trap`) et NtRaiseException vont à KiDispatchException
//! (`ke::exception`), qui les livre au répartiteur de ntdll ; NtContinue
//! reprend le contexte qu'il rend.
//!
//! | Vecteur | Exception | Paramètres |
//! |---|---|---|
//! | #DE | `STATUS_INTEGER_DIVIDE_BY_ZERO` | |
//! | #BP | `STATUS_BREAKPOINT`, à l'adresse de l'`int 3` | `BREAKPOINT_BREAK` |
//! | #UD | `STATUS_ILLEGAL_INSTRUCTION` | |
//! | #GP | `STATUS_PRIVILEGED_INSTRUCTION` pour une instruction privilégiée, sinon `STATUS_ACCESS_VIOLATION` | lecture, `0xFFFFFFFF` |
//! | #PF | ce que rend Mm (`mm::fault`) : `STATUS_ACCESS_VIOLATION`, `STATUS_GUARD_PAGE_VIOLATION`, `STATUS_STACK_OVERFLOW` | accès (0 lecture, 1 écriture, 8 exécution), adresse |
//!
//! Sans répartiteur, en seconde chance, ou si la pile ne reçoit pas le
//! contexte, le processus se termine avec le code de l'exception : il n'y a
//! ni débogueur ni port d'exception. Un thread de l'ancien chargeur, sans
//! ntdll, se termine.
//!
//! Pas encore : `STATUS_INTEGER_OVERFLOW` pour un quotient trop grand (#DE),
//! les exceptions flottantes (`hal::idt` termine encore le processus).

use core::mem::offset_of;

use abi::context::Context32;
use abi::exception::{
    ExceptionRecord32, BREAKPOINT_BREAK, EXCEPTION_EXECUTE_FAULT, EXCEPTION_MAXIMUM_PARAMETERS, EXCEPTION_READ_FAULT,
    EXCEPTION_WRITE_FAULT,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_VIOLATION, STATUS_BREAKPOINT, STATUS_ILLEGAL_INSTRUCTION, STATUS_INTEGER_DIVIDE_BY_ZERO,
    STATUS_INVALID_PARAMETER, STATUS_PRIVILEGED_INSTRUCTION, STATUS_SUCCESS,
};
use hal::trap::{set_trap_hook, KTrapFrame};
use ke::context::{apply_user_context, UserSelectors};
use ke::usermem::{copy_from_user, probe_for_read, UserPtr};
use x86_64::structures::idt::PageFaultErrorCode;

/// Branche les exceptions du mode utilisateur.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn install() {
    set_trap_hook(0x00, Some(divide_error));
    set_trap_hook(0x03, Some(breakpoint));
    set_trap_hook(0x06, Some(invalid_opcode));
    set_trap_hook(0x0D, Some(general_protection));
    set_trap_hook(0x0E, Some(page_fault));
}

/// L'exception `code` à l'EIP de la trame, en première chance ; le processus
/// qui ne peut pas la recevoir se termine avec son code. Entrée et sortie
/// interruptions masquées, comme la porte.
pub(super) fn raise(frame: &mut KTrapFrame, code: NtStatus, parameters: &[u32]) {
    // As in a system service: the stack writes may fault, Ps runs the
    // process down.
    x86_64::instructions::interrupts::enable();
    let record = ExceptionRecord32::new(code.0, frame.rip as u32, parameters);
    let dispatched = if ke::sched::current_thread_owner().is_null() {
        Err(code)
    } else {
        ke::exception::dispatch_user_exception(&record, frame, true)
    };
    if let Err(status) = dispatched {
        ps::terminate_current_process(status);
    }
    x86_64::instructions::interrupts::disable();
}

/// #DE.
fn divide_error(frame: &mut KTrapFrame) {
    raise(frame, STATUS_INTEGER_DIVIDE_BY_ZERO, &[]);
}

/// #BP : la trappe laisse EIP après l'`int 3`, l'exception est à son octet.
fn breakpoint(frame: &mut KTrapFrame) {
    frame.rip -= 1;
    raise(frame, STATUS_BREAKPOINT, &[BREAKPOINT_BREAK]);
}

/// #UD.
fn invalid_opcode(frame: &mut KTrapFrame) {
    raise(frame, STATUS_ILLEGAL_INSTRUCTION, &[]);
}

/// #GP.
fn general_protection(frame: &mut KTrapFrame) {
    if is_privileged_instruction(frame.rip as u32) {
        raise(frame, STATUS_PRIVILEGED_INSTRUCTION, &[]);
    } else {
        raise(frame, STATUS_ACCESS_VIOLATION, &[EXCEPTION_READ_FAULT, u32::MAX]);
    }
}

/// Les préfixes d'une instruction i386.
const PREFIXES: [u8; 11] = [0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3];

/// L'instruction en `eip` demande l'anneau 0 : HLT, CLI, STI, IN, OUT, INS,
/// OUTS, CLTS, INVD, WBINVD, MOV vers ou depuis un registre de contrôle ou de
/// débogage, RDMSR, WRMSR. Faux si elle ne se lit pas.
fn is_privileged_instruction(eip: u32) -> bool {
    let byte = |offset: u32| UserPtr::<u8>::new(eip.wrapping_add(offset)).read().ok();
    // Past the prefixes; an instruction takes at most 15 bytes.
    let mut offset = 0;
    while offset < 14 && byte(offset).is_some_and(|b| PREFIXES.contains(&b)) {
        offset += 1;
    }
    match byte(offset) {
        Some(0xF4 | 0xFA | 0xFB | 0x6C..=0x6F | 0xE4..=0xE7 | 0xEC..=0xEF) => true,
        Some(0x0F) => matches!(byte(offset + 1), Some(0x06 | 0x08 | 0x09 | 0x20..=0x23 | 0x30 | 0x32)),
        _ => false,
    }
}

/// #PF : Mm résout la faute (page à zéro, copie sur écriture, garde de la
/// pile), ou rend l'exception.
fn page_fault(frame: &mut KTrapFrame) {
    // CR2 before interrupts are enabled: another fault would replace it.
    let address = x86_64::registers::control::Cr2::read_raw();
    let error = PageFaultErrorCode::from_bits_truncate(frame.error_code);
    let status = mm::fault::page_fault_hook(address, error).unwrap_or(STATUS_ACCESS_VIOLATION);
    if status == STATUS_SUCCESS {
        return;
    }
    let access = if error.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
        EXCEPTION_EXECUTE_FAULT
    } else if error.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
        EXCEPTION_WRITE_FAULT
    } else {
        EXCEPTION_READ_FAULT
    };
    raise(frame, status, &[access, address as u32]);
}

/// NtContinue(Context, TestAlert) : le thread reprend avec le contexte ;
/// avec TestAlert (`ntdll!KiUserApcDispatcher`), il recevra au retour ses APC
/// utilisateur encore en file.
pub(super) fn nt_continue(arguments: &[u32], frame: &mut KTrapFrame) -> Result<(), NtStatus> {
    let context = UserPtr::<Context32>::new(arguments[0]).read()?;
    apply_user_context(&context, context.context_flags, frame, UserSelectors::current());
    // A BOOLEAN, in the low byte of its argument.
    if arguments[1] as u8 != 0 {
        ke::apc::ke_test_alert_thread::<ke::sched::KePlatform>();
    }
    Ok(())
}

/// NtRaiseException(ExceptionRecord, Context, FirstChance) : l'exception
/// part du contexte, en première ou en seconde chance ; une seconde chance
/// termine le processus. `STATUS_INVALID_PARAMETER` pour plus de 15
/// paramètres.
pub(super) fn nt_raise_exception(arguments: &[u32], frame: &mut KTrapFrame) -> Result<(), NtStatus> {
    let record = capture_record(arguments[0])?;
    let context = UserPtr::<Context32>::new(arguments[1]).read()?;
    // A BOOLEAN, in the low byte of its argument.
    let first_chance = arguments[2] as u8 != 0;
    apply_user_context(&context, context.context_flags, frame, UserSelectors::current());
    if let Err(code) = ke::exception::dispatch_user_exception(&record, frame, first_chance) {
        ps::terminate_current_process(code);
    }
    Ok(())
}

/// Un `EXCEPTION_RECORD` utilisateur : son en-tête, puis ses paramètres.
fn capture_record(address: u32) -> Result<ExceptionRecord32, NtStatus> {
    let header = offset_of!(ExceptionRecord32, exception_information);
    probe_for_read(u64::from(address), header, 4)?;
    let count = UserPtr::<u32>::new(address + offset_of!(ExceptionRecord32, number_parameters) as u32).read()?;
    if count as usize > EXCEPTION_MAXIMUM_PARAMETERS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut record = ExceptionRecord32::new(0, 0, &[]);
    copy_from_user(&mut record.as_bytes_mut()[..header + 4 * count as usize], u64::from(address))?;
    // The parameters read are the ones counted.
    record.number_parameters = count;
    Ok(record)
}
