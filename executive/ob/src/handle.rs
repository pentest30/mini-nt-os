//! Handle table — per-process mapping of HANDLE → ObjectRef.
//!
//! NT handles are indices (multiples of 4) into a handle table.
//! We use a simple Vec<Option<Entry>> for Phase 1/2.
//! Phase 3: implement the full NT 3-level handle table structure.

use alloc::vec::Vec;
use spin::Mutex;
use super::object::ObjectRef;

/// A Win32/NT kernel handle value.
/// INVALID_HANDLE_VALUE = 0xFFFF_FFFF_FFFF_FFFF (as isize = -1).
pub type Handle = u64;
pub const INVALID_HANDLE: Handle = u64::MAX;

/// Pseudo-handles recognised by Ob without a table lookup.
pub const CURRENT_PROCESS_HANDLE: Handle = u64::MAX - 1; // (HANDLE)-1
pub const CURRENT_THREAD_HANDLE:  Handle = u64::MAX - 2; // (HANDLE)-2

struct Entry {
    object:     ObjectRef,
    access:     u32,   // granted access mask
    inherit:    bool,
}

/// Per-process handle table.
pub struct HandleTable {
    entries: Vec<Option<Entry>>,
}

impl HandleTable {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Insert an object and return its handle (multiple of 4, NT-compatible).
    pub fn insert(&mut self, object: ObjectRef, access: u32, inherit: bool) -> Handle {
        // Find a free slot.
        let index = self.entries.iter().position(|e| e.is_none())
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        self.entries[index] = Some(Entry { object, access, inherit });
        // NT handle = (index + 1) * 4 (slot 0 → handle 4).
        ((index + 1) as u64) * 4
    }

    /// Look up an object by handle. Returns None for invalid handles.
    pub fn lookup(&self, handle: Handle) -> Option<ObjectRef> {
        if handle == INVALID_HANDLE { return None; }
        let index = (handle / 4) as usize;
        let slot  = index.checked_sub(1)?;
        self.entries.get(slot)?.as_ref().map(|e| e.object.clone())
    }

    /// Close a handle (NtClose). Returns false if the handle was invalid.
    pub fn close(&mut self, handle: Handle) -> bool {
        if handle == INVALID_HANDLE { return false; }
        let index = (handle / 4) as usize;
        let slot  = match index.checked_sub(1) {
            Some(s) => s,
            None    => return false,
        };
        if let Some(entry) = self.entries.get_mut(slot) {
            if entry.is_some() {
                *entry = None;
                return true;
            }
        }
        false
    }
}
