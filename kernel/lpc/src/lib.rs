//! Lpc — les ports d'XP (02 §5.9).
//!
//! - [`port`] : le type `Port`, de trois sortes (port de connexion nommé
//!   d'un serveur, port client, port de communication du serveur), et sa
//!   file de messages.
//! - [`conversation`] : la connexion (demande, acceptation ou refus,
//!   réveil du client), les requêtes avec réponse, les datagrammes.
//!
//! Pas encore : la section d'un serveur, les rappels, les messages de
//! fermeture (M5).
//!
//! WI7e Ch.3 §Advanced Local Procedure Call (l'ancêtre)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod conversation;
pub mod port;

pub use conversation::{
    accept, check_message, complete, connect, reply, request_port, request_wait_reply, send, Accepted, ClientView,
    Connected,
};
pub use port::{Message, Port, PortKind, HEADER_LENGTH, PORT_ALL_ACCESS, PORT_CONNECT, PORT_TYPE};
