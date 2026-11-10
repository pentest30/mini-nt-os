//! Ce que USER garde pour les consoles de `consrv` (NtUserConsoleControl ;
//! `win32ss/user/ntuser/console.c` de ReactOS comme spécification) : l'atome
//! de la classe des fenêtres console (gaGuiConsoleWndClass), et, sur chaque
//! bureau, son thread d'entrée des consoles
//! (`crate::desktop::Desktop::exchange_console_thread`).

use core::sync::atomic::{AtomicU16, Ordering};

/// gaGuiConsoleWndClass : l'atome de la classe des fenêtres console, que
/// `consrv` enregistre ; 0 avant.
static CONSOLE_WINDOW_CLASS: AtomicU16 = AtomicU16::new(0);

/// GuiConsoleWndClassAtom : la classe des fenêtres console est `atom`.
///
/// # IRQL
/// Quelconque.
pub fn set_console_window_class(atom: u16) {
    CONSOLE_WINDOW_CLASS.store(atom, Ordering::Release);
}

/// L'atome de la classe des fenêtres console ; 0 tant que `consrv` ne l'a
/// pas dit.
///
/// # IRQL
/// Quelconque.
pub fn console_window_class() -> u16 {
    CONSOLE_WINDOW_CLASS.load(Ordering::Acquire)
}
