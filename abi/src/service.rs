//! System services (02 §6.2): a service number selects a table and an entry
//! in it. The tables, generated from the pinned ReactOS version, are in
//! [`services`](crate::services), which also names every number.
//!
//! Bits 0–11 of a number are the index in its table, bits 12–13 the table:
//! 0 for ntoskrnl (`KiServiceTable`), 1 for win32k (`W32pServiceTable`); the
//! other two tables are empty. Higher bits are ignored.

use crate::services::{NTOSKRNL, WIN32K};

/// A system service: its NT name, and the size of the arguments the
/// dispatcher copies from the user stack (32-bit each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Service {
    pub name: &'static str,
    pub argument_bytes: u32,
}

impl Service {
    /// A service taking `argument_count` 32-bit arguments.
    pub const fn new(name: &'static str, argument_count: u32) -> Self {
        Self { name, argument_bytes: argument_count * 4 }
    }
}

/// A service table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    Ntoskrnl,
    Win32k,
}

/// The index bits of a service number.
pub const INDEX_MASK: u32 = 0xFFF;
/// Where the table bits of a service number start.
pub const TABLE_SHIFT: u32 = 12;

/// The service of `number`, with its table; `None` outside the tables
/// (`STATUS_INVALID_SYSTEM_SERVICE`).
pub fn lookup(number: u32) -> Option<(Table, &'static Service)> {
    let index = (number & INDEX_MASK) as usize;
    match (number >> TABLE_SHIFT) & 3 {
        0 => NTOSKRNL.get(index).map(|service| (Table::Ntoskrnl, service)),
        1 => WIN32K.get(index).map(|service| (Table::Win32k, service)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{NtClose, NtGdiAbortDoc, NtUserGetDC};

    #[test]
    fn a_number_finds_its_service() {
        assert_eq!(lookup(NtClose), Some((Table::Ntoskrnl, &Service { name: "NtClose", argument_bytes: 4 })));
        assert_eq!(lookup(NtGdiAbortDoc).map(|(table, s)| (table, s.name)), Some((Table::Win32k, "NtGdiAbortDoc")));
        assert_eq!(lookup(NtUserGetDC).map(|(_, s)| s.name), Some("NtUserGetDC"));
    }

    #[test]
    fn every_name_is_its_own_number() {
        for (base, table) in [(0, &NTOSKRNL[..]), (0x1000, &WIN32K[..])] {
            for (i, service) in table.iter().enumerate() {
                assert_eq!(
                    lookup(base + i as u32),
                    Some((if base == 0 { Table::Ntoskrnl } else { Table::Win32k }, service))
                );
            }
        }
    }

    #[test]
    fn numbers_outside_the_tables_find_nothing() {
        assert_eq!(lookup(NTOSKRNL.len() as u32), None);
        assert_eq!(lookup(0x1000 + WIN32K.len() as u32), None);
        assert_eq!(lookup(0x2000), None, "table 2 is empty");
        assert_eq!(lookup(0x3000 | NtClose), None, "table 3 is empty");
        assert_eq!(lookup(0x4000 | NtClose).map(|(_, s)| s.name), Some("NtClose"), "high bits ignored");
    }
}
