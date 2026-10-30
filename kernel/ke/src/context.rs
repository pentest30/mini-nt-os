//! Le `CONTEXT` x86 d'un thread (`abi::context`) et sa trame de trap
//! (`hal::trap::KTrapFrame`) : KeContextFromKframes et KeContextToKframes,
//! pour les exceptions, `NtGetContextThread`, `NtSetContextThread` et
//! `NtContinue`.
//!
//! Un contexte qui vient du mode utilisateur est assaini avant d'aller dans
//! la trame : EFLAGS ne garde que les drapeaux du mode utilisateur, avec IF,
//! et les sélecteurs sont ceux d'un processus i386, imposés et non recopiés
//! (un sélecteur invalide ferait fauter le retour en mode utilisateur, dans
//! le noyau).
//!
//! Une livraison vers le mode utilisateur (exception, APC) met le contexte
//! complet sur la pile du thread ([`push_user_context`]) et fait reprendre la
//! trame dans un répartiteur de ntdll ([`enter_user_dispatcher`]).
//!
//! Pas encore : l'état x87/SSE (`CONTEXT_FLOATING_POINT`,
//! `CONTEXT_EXTENDED_REGISTERS`, depuis l'état FPU du thread) et les
//! registres de débogage.

use core::mem::size_of;

use abi::context::{Context32, CONTEXT_CONTROL, CONTEXT_FULL, CONTEXT_INTEGER, CONTEXT_SEGMENTS};
use abi::ntstatus::{NtStatus, STATUS_ACCESS_VIOLATION};
use hal::trap::KTrapFrame;

use crate::usermem::UserPtr;

/// Les drapeaux d'EFLAGS que le mode utilisateur fixe : CF, PF, AF, ZF, SF,
/// TF, DF, OF, AC et ID. IOPL, NT, RF, VM, VIF et VIP restent au noyau.
pub const EFLAGS_USER_MASK: u32 = 0x0024_0DD5;
/// Les drapeaux toujours mis : le bit 1, réservé, et IF.
pub const EFLAGS_USER_SET: u32 = 0x0000_0202;
/// TF : le pas à pas.
const EFLAGS_TF: u64 = 0x100;

/// Les sélecteurs d'un thread i386 en mode utilisateur, RPL 3 compris.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserSelectors {
    /// CS : le code 32 bits.
    pub code: u16,
    /// SS, DS et ES : les données.
    pub data: u16,
    /// FS : le TEB.
    pub teb: u16,
}

impl UserSelectors {
    /// Ceux de la GDT du noyau (`hal::gdt`).
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn current() -> Self {
        Self {
            code: hal::gdt::user_code32_selector() | 3,
            data: hal::gdt::user_data32_selector() | 3,
            teb: hal::gdt::user_teb_fs_selector() | 3,
        }
    }
}

/// Le contexte contient les parties `part` (bit d'architecture compris).
fn has(flags: u32, part: u32) -> bool {
    flags & part == part
}

/// EFLAGS d'un contexte venu du mode utilisateur, assaini.
pub fn sanitize_eflags(eflags: u32) -> u32 {
    (eflags & EFLAGS_USER_MASK) | EFLAGS_USER_SET
}

/// KeContextFromKframes : remplit les parties `flags` de `context` depuis
/// la trame (les autres ne changent pas).
pub fn context_from_trap_frame(frame: &KTrapFrame, flags: u32, context: &mut Context32) {
    if has(flags, CONTEXT_CONTROL) {
        context.ebp = frame.rbp as u32;
        context.eip = frame.rip as u32;
        context.seg_cs = frame.cs as u32 & 0xFFFF;
        context.eflags = frame.rflags as u32;
        context.esp = frame.rsp as u32;
        context.seg_ss = frame.ss as u32 & 0xFFFF;
    }
    if has(flags, CONTEXT_INTEGER) {
        context.edi = frame.rdi as u32;
        context.esi = frame.rsi as u32;
        context.ebx = frame.rbx as u32;
        context.edx = frame.rdx as u32;
        context.ecx = frame.rcx as u32;
        context.eax = frame.rax as u32;
    }
    if has(flags, CONTEXT_SEGMENTS) {
        context.seg_gs = frame.gs as u32 & 0xFFFF;
        context.seg_fs = frame.fs as u32 & 0xFFFF;
        context.seg_es = frame.es as u32 & 0xFFFF;
        context.seg_ds = frame.ds as u32 & 0xFFFF;
    }
}

/// KeContextToKframes : applique à la trame les parties `flags` d'un
/// contexte venu du mode utilisateur, assaini (EFLAGS, sélecteurs
/// `selectors`).
pub fn apply_user_context(context: &Context32, flags: u32, frame: &mut KTrapFrame, selectors: UserSelectors) {
    if has(flags, CONTEXT_CONTROL) {
        frame.rbp = u64::from(context.ebp);
        frame.rip = u64::from(context.eip);
        frame.cs = u64::from(selectors.code);
        frame.rflags = u64::from(sanitize_eflags(context.eflags));
        frame.rsp = u64::from(context.esp);
        frame.ss = u64::from(selectors.data);
    }
    if has(flags, CONTEXT_INTEGER) {
        frame.rdi = u64::from(context.edi);
        frame.rsi = u64::from(context.esi);
        frame.rbx = u64::from(context.ebx);
        frame.rdx = u64::from(context.edx);
        frame.rcx = u64::from(context.ecx);
        frame.rax = u64::from(context.eax);
    }
    if has(flags, CONTEXT_SEGMENTS) {
        // GS is not reloaded on the way out (hal::trap): it stays null.
        frame.gs = 0;
        frame.fs = u64::from(selectors.teb);
        frame.es = u64::from(selectors.data);
        frame.ds = u64::from(selectors.data);
    }
}

/// Écrit le `CONTEXT` complet de la trame sur la pile utilisateur, sous ESP
/// aligné sur 4 ; rend son adresse.
///
/// # IRQL
/// < DISPATCH_LEVEL. Peut faire des fautes de page.
pub fn push_user_context(frame: &KTrapFrame) -> Result<u32, NtStatus> {
    let mut context = Context32::zeroed();
    context.context_flags = CONTEXT_FULL;
    context_from_trap_frame(frame, CONTEXT_FULL, &mut context);
    let at = (frame.rsp as u32 & !3).checked_sub(size_of::<Context32>() as u32).ok_or(STATUS_ACCESS_VIOLATION)?;
    UserPtr::<Context32>::new(at).write(&context)?;
    Ok(at)
}

/// La trame reprend en mode utilisateur à `eip`, pile en `esp`, avec les
/// sélecteurs imposés et sans pas à pas, qui ne suit pas le thread dans le
/// répartiteur.
///
/// # IRQL
/// Tout niveau.
pub fn enter_user_dispatcher(frame: &mut KTrapFrame, eip: u32, esp: u32) {
    let selectors = UserSelectors::current();
    frame.rsp = u64::from(esp);
    frame.rip = u64::from(eip);
    frame.rflags &= !EFLAGS_TF;
    frame.cs = u64::from(selectors.code);
    frame.ss = u64::from(selectors.data);
    frame.ds = u64::from(selectors.data);
    frame.es = u64::from(selectors.data);
    frame.fs = u64::from(selectors.teb);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::context::{CONTEXT_FULL, CONTEXT_I386};

    const SELECTORS: UserSelectors = UserSelectors { code: 0x1B, data: 0x23, teb: 0x3B };

    fn frame() -> KTrapFrame {
        KTrapFrame {
            rax: 0x1111_1111,
            rbx: 0x2222_2222,
            rcx: 0x3333_3333,
            rdx: 0x4444_4444,
            rsi: 0x5555_5555,
            rdi: 0x6666_6666,
            rbp: 0x0012_FF80,
            rip: 0x0040_1000,
            cs: 0x1B,
            rflags: 0x246,
            rsp: 0x0012_FF00,
            ss: 0x23,
            ds: 0x23,
            es: 0x23,
            fs: 0x3B,
            gs: 0,
            vector: 0x2E,
            ..KTrapFrame::default()
        }
    }

    #[test]
    fn a_full_context_round_trips() {
        let mut context = Context32::zeroed();
        context_from_trap_frame(&frame(), CONTEXT_FULL, &mut context);
        assert_eq!((context.eax, context.ebx, context.edi), (0x1111_1111, 0x2222_2222, 0x6666_6666));
        assert_eq!((context.eip, context.esp, context.ebp), (0x0040_1000, 0x0012_FF00, 0x0012_FF80));
        assert_eq!((context.seg_cs, context.seg_ss, context.seg_fs), (0x1B, 0x23, 0x3B));
        let mut back = KTrapFrame { vector: 0x2E, ..KTrapFrame::default() };
        apply_user_context(&context, CONTEXT_FULL, &mut back, SELECTORS);
        assert_eq!(back, frame());
    }

    #[test]
    fn only_the_parts_asked_for_move() {
        let mut context = Context32::zeroed();
        context_from_trap_frame(&frame(), CONTEXT_INTEGER, &mut context);
        assert_eq!(context.eax, 0x1111_1111);
        assert_eq!((context.eip, context.seg_cs), (0, 0), "no control part");
        let mut target = frame();
        let other = Context32 { eip: 0xDEAD, eax: 7, ..Context32::zeroed() };
        apply_user_context(&other, CONTEXT_INTEGER, &mut target, SELECTORS);
        assert_eq!((target.rax, target.rip), (7, 0x0040_1000));
        apply_user_context(&other, CONTEXT_I386 | 0x40, &mut target, SELECTORS);
        assert_eq!(target.rax, 7, "no part known: nothing moves");
    }

    #[test]
    fn a_user_context_is_sanitized() {
        let hostile = Context32 {
            eflags: 0xFFFF_FFFF,
            seg_cs: 0x08,
            seg_ss: 0x10,
            seg_ds: 0x10,
            seg_es: 0x30,
            seg_fs: 0x08,
            seg_gs: 0x2B,
            ..Context32::zeroed()
        };
        let mut target = KTrapFrame::default();
        apply_user_context(&hostile, CONTEXT_FULL, &mut target, SELECTORS);
        assert_eq!(target.rflags, 0x0024_0FD7, "IOPL, NT, RF, VM, VIF, VIP dropped; IF and bit 1 set");
        assert_eq!((target.cs, target.ss, target.ds, target.es), (0x1B, 0x23, 0x23, 0x23));
        assert_eq!((target.fs, target.gs), (0x3B, 0));
        assert_eq!(sanitize_eflags(0), 0x202, "interrupts stay enabled in user mode");
    }
}
