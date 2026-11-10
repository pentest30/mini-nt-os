//! La fin d'un rappel en mode utilisateur (`ps::callback`) : NtCallbackReturn,
//! et l'`int 2Bh` (KiCallbackReturn, [`super::gates`]), qui en prend les
//! arguments dans ECX, EDX et EAX.

use abi::ntstatus::NtStatus;

/// NtCallbackReturn(Result, ResultLength, Status) : rend au service qui a
/// fait le rappel en cours l'adresse et la longueur de son résultat, et son
/// statut. Ne revient (avec `STATUS_NO_CALLBACK_ACTIVE`) que sans rappel en
/// cours.
pub(super) fn nt_callback_return(arguments: &[u32]) -> NtStatus {
    // The dispatcher's frames hold nothing to give back: they are dropped.
    ps::callback::callback_return(arguments[0], arguments[1], NtStatus(arguments[2]))
}
