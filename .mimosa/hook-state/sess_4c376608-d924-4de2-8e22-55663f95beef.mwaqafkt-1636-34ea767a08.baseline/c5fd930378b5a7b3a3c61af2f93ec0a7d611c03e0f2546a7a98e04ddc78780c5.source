//! Contexte de commutation d'un thread et primitive de commutation (audit §3 :
//! `KContext` et `context_switch_raw` sont gardés ; la zone FPU viendra avec
//! l'ADR-009). Le thread lui-même est `ke::sched::Thread`.

use core::arch::global_asm;

/// Registres non volatils sauvegardés à la commutation (communs aux ABI SysV et
/// MS x64), et l'adresse de reprise.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KContext {
    pub rsp: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

impl KContext {
    /// Contexte d'un thread qui n'a jamais tourné : la commutation « retourne » à
    /// `entry`, en haut de la pile `stack_top`, avec l'alignement d'une fonction
    /// tout juste appelée (RSP ≡ 8 mod 16 à son entrée).
    pub const fn initial(stack_top: u64, entry: u64) -> Self {
        Self { rsp: (stack_top - 8) & !0xF, rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0, rip: entry }
    }
}

unsafe extern "C" {
    fn ke_context_switch(old_ctx: *mut KContext, new_ctx: *const KContext);
}

/// Sauve le contexte courant dans `old_ctx` et reprend `new_ctx`. Revient quand
/// un autre thread commute vers `old_ctx`.
///
/// # Safety
/// - `old_ctx` et `new_ctx` sont valides, distincts, et vivent pendant la
///   commutation ; `new_ctx` vient d'une commutation ou de [`KContext::initial`]
///   sur une pile valide.
/// - Interruptions masquées, à DISPATCH_LEVEL.
#[inline(always)]
pub unsafe fn context_switch_raw(old_ctx: *mut KContext, new_ctx: *const KContext) {
    // SAFETY: garanti par l'appelant.
    unsafe { ke_context_switch(old_ctx, new_ctx) };
}

global_asm!(
    r#"
    .global ke_context_switch
ke_context_switch:
    # rdi = old_ctx, rsi = new_ctx
    mov [rdi + 0x00], rsp
    mov [rdi + 0x08], rbx
    mov [rdi + 0x10], rbp
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], r13
    mov [rdi + 0x28], r14
    mov [rdi + 0x30], r15
    mov rax, [rsp]
    mov [rdi + 0x38], rax

    mov rsp, [rsi + 0x00]
    mov rbx, [rsi + 0x08]
    mov rbp, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov r13, [rsi + 0x20]
    mov r14, [rsi + 0x28]
    mov r15, [rsi + 0x30]
    mov rax, [rsi + 0x38]
    mov [rsp], rax
    ret
    "#
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    /// `ke_context_switch` lit et écrit ces décalages en dur.
    #[test]
    fn kcontext_offsets_match_the_switch_stub() {
        assert_eq!(offset_of!(KContext, rsp), 0x00);
        assert_eq!(offset_of!(KContext, rbx), 0x08);
        assert_eq!(offset_of!(KContext, rbp), 0x10);
        assert_eq!(offset_of!(KContext, r12), 0x18);
        assert_eq!(offset_of!(KContext, r13), 0x20);
        assert_eq!(offset_of!(KContext, r14), 0x28);
        assert_eq!(offset_of!(KContext, r15), 0x30);
        assert_eq!(offset_of!(KContext, rip), 0x38);
        assert_eq!(core::mem::size_of::<KContext>(), 64);
    }

    /// Après le `ret` de la commutation, RSP = `rsp + 8` : l'entrée voit RSP ≡ 8
    /// (mod 16), comme une fonction appelée.
    #[test]
    fn an_initial_context_enters_like_a_called_function() {
        for top in [0x1000u64, 0x1008, 0x7ff0] {
            let ctx = KContext::initial(top, 0xdead);
            assert_eq!((ctx.rsp + 8) % 16, 8, "top {top:#x}");
            assert!(ctx.rsp + 8 <= top, "the return slot is inside the stack");
            assert_eq!(ctx.rip, 0xdead);
        }
    }
}
