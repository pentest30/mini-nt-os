//! Lpc — les ports d'XP (02 §5.9).
//!
//! - [`port`] : le type `Port`, un port de connexion d'un serveur, nommé
//!   dans l'espace de noms, et sa file de messages.
//!
//! Pas encore : la connexion (NtConnectPort, NtSecureConnectPort,
//! NtAcceptConnectPort, NtCompleteConnectPort), les ports de communication,
//! les requêtes avec réponse (NtRequestWaitReplyPort, NtReplyPort), les
//! messages volumineux par sections partagées (M5).
//!
//! WI7e Ch.3 §Advanced Local Procedure Call (l'ancêtre)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod port;

pub use port::{Message, Port, PORT_ALL_ACCESS, PORT_CONNECT, PORT_TYPE};
