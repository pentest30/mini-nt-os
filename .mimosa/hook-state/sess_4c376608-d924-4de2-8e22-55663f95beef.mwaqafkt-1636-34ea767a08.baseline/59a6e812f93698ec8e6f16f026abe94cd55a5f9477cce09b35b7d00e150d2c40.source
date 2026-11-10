//! A writer of whole hives from a tree of keys (feature `builder`): for the
//! tests, and for `tools/mkhive`.
//!
//! The hive is version 1.3, as XP writes its hives, in a single bin. Every
//! key refers to one shared security cell (`sk`) with an empty self-relative
//! descriptor; subkey lists are hash leaves (`lh`) sorted by upcased name;
//! names are stored in Latin-1 when they can be. Data above 4 bytes goes to
//! a data cell of its own; above [`super::BIG_DATA_SEGMENT`] bytes, the hive
//! stays readable by this crate (version 1.3 has no big data cells).

use alloc::string::String;
use alloc::vec::Vec;

use super::{
    checksum, upcase, BASE_BLOCK_SIZE, HBIN_HEADER_SIZE, KEY_COMP_NAME, KEY_HIVE_ENTRY, KEY_NO_DELETE, NO_CELL,
    VALUE_COMP_NAME,
};

/// A key to write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyNode {
    pub name: String,
    /// Its class; empty for none.
    pub class: String,
    /// When it was last written, as a FILETIME; 0 if unknown.
    pub last_written: u64,
    pub values: Vec<ValueNode>,
    pub subkeys: Vec<KeyNode>,
}

/// A value to write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValueNode {
    /// Empty for the default value.
    pub name: String,
    pub data_type: u32,
    pub data: Vec<u8>,
}

impl KeyNode {
    /// A key named `name`, without values or subkeys.
    pub fn new(name: &str) -> Self {
        Self { name: name.into(), ..Self::default() }
    }

    /// The key at `path` below this one (`\`-separated, without case),
    /// created with the keys on the way if needed.
    pub fn key_mut(&mut self, path: &str) -> &mut KeyNode {
        let mut key = self;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            let units: Vec<u16> = part.encode_utf16().map(upcase).collect();
            let found = key.subkeys.iter().position(|k| k.name.encode_utf16().map(upcase).eq(units.iter().copied()));
            let index = found.unwrap_or_else(|| {
                key.subkeys.push(KeyNode::new(part));
                key.subkeys.len() - 1
            });
            key = &mut key.subkeys[index];
        }
        key
    }

    /// Sets its value `name` (replacing one of the same name, without case).
    pub fn set_value(&mut self, name: &str, data_type: u32, data: Vec<u8>) {
        let units: Vec<u16> = name.encode_utf16().map(upcase).collect();
        self.values.retain(|v| !v.name.encode_utf16().map(upcase).eq(units.iter().copied()));
        self.values.push(ValueNode { name: name.into(), data_type, data });
    }
}

/// A name as stored: Latin-1 if every character fits, else UTF-16.
fn stored_name(name: &str) -> (Vec<u8>, bool) {
    if name.chars().all(|c| (c as u32) <= 0xFF) {
        (name.chars().map(|c| c as u32 as u8).collect(), true)
    } else {
        (name.encode_utf16().flat_map(u16::to_le_bytes).collect(), false)
    }
}

/// The hash of a name in an `lh` list.
fn name_hash(name: &str) -> u32 {
    name.encode_utf16().fold(0u32, |hash, unit| hash.wrapping_mul(37).wrapping_add(u32::from(upcase(unit))))
}

/// The cells of the bin under construction.
struct Bin {
    data: Vec<u8>,
    keys: u32,
}

impl Bin {
    /// A new allocated cell of `length` payload bytes; its offset.
    fn alloc(&mut self, length: usize) -> u32 {
        let offset = self.data.len();
        let size = (length + 4).next_multiple_of(8);
        self.data.resize(offset + size, 0);
        self.data[offset..offset + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
        offset as u32
    }

    /// Writes `bytes` at `at` in the payload of the cell at `cell`.
    fn field(&mut self, cell: u32, at: usize, bytes: &[u8]) {
        let start = cell as usize + 4 + at;
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
    }

    /// Writes the key `node` and everything below it; its offset.
    fn key(&mut self, node: &KeyNode, parent: u32, security: u32, root: bool) -> u32 {
        let (name, compressed) = stored_name(&node.name);
        let nk = self.alloc(76 + name.len());
        self.keys += 1;

        // Values.
        let mut largest_name = 0usize;
        let mut largest_data = 0usize;
        let mut value_offsets = Vec::with_capacity(node.values.len());
        for value in &node.values {
            let (value_name, value_compressed) = stored_name(&value.name);
            largest_name = largest_name.max(value.name.encode_utf16().count() * 2);
            largest_data = largest_data.max(value.data.len());
            let vk = self.alloc(20 + value_name.len());
            self.field(vk, 0, b"vk");
            self.field(vk, 2, &(value_name.len() as u16).to_le_bytes());
            if value.data.len() <= 4 {
                self.field(vk, 4, &(value.data.len() as u32 | 0x8000_0000).to_le_bytes());
                let mut inline = [0u8; 4];
                inline[..value.data.len()].copy_from_slice(&value.data);
                self.field(vk, 8, &inline);
            } else {
                let data = self.alloc(value.data.len());
                self.field(data, 0, &value.data);
                self.field(vk, 4, &(value.data.len() as u32).to_le_bytes());
                self.field(vk, 8, &data.to_le_bytes());
            }
            self.field(vk, 12, &value.data_type.to_le_bytes());
            let flags = if value_compressed { VALUE_COMP_NAME } else { 0 };
            self.field(vk, 16, &flags.to_le_bytes());
            self.field(vk, 20, &value_name);
            value_offsets.push(vk);
        }
        let values = if value_offsets.is_empty() {
            NO_CELL
        } else {
            let list = self.alloc(4 * value_offsets.len());
            for (i, vk) in value_offsets.iter().enumerate() {
                self.field(list, 4 * i, &vk.to_le_bytes());
            }
            list
        };

        // Subkeys, sorted by upcased name.
        let mut children: Vec<&KeyNode> = node.subkeys.iter().collect();
        children.sort_by_key(|k| k.name.encode_utf16().map(upcase).collect::<Vec<u16>>());
        let largest_subkey = children.iter().map(|k| k.name.encode_utf16().count() * 2).max().unwrap_or(0);
        let largest_class = children.iter().map(|k| k.class.encode_utf16().count() * 2).max().unwrap_or(0);
        let child_offsets: Vec<(u32, u32)> =
            children.iter().map(|child| (self.key(child, nk, security, false), name_hash(&child.name))).collect();
        let subkeys = if child_offsets.is_empty() {
            NO_CELL
        } else {
            let list = self.alloc(4 + 8 * child_offsets.len());
            self.field(list, 0, b"lh");
            self.field(list, 2, &(child_offsets.len() as u16).to_le_bytes());
            for (i, (offset, hash)) in child_offsets.iter().enumerate() {
                self.field(list, 4 + 8 * i, &offset.to_le_bytes());
                self.field(list, 8 + 8 * i, &hash.to_le_bytes());
            }
            list
        };

        // Its class, in UTF-16.
        let class: Vec<u8> = node.class.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let class_cell = if class.is_empty() {
            NO_CELL
        } else {
            let cell = self.alloc(class.len());
            self.field(cell, 0, &class);
            cell
        };

        let mut flags = if compressed { KEY_COMP_NAME } else { 0 };
        if root {
            flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
        }
        self.field(nk, 0, b"nk");
        self.field(nk, 2, &flags.to_le_bytes());
        self.field(nk, 4, &node.last_written.to_le_bytes());
        self.field(nk, 16, &parent.to_le_bytes());
        self.field(nk, 20, &(child_offsets.len() as u32).to_le_bytes());
        self.field(nk, 28, &subkeys.to_le_bytes());
        self.field(nk, 32, &NO_CELL.to_le_bytes());
        self.field(nk, 36, &(value_offsets.len() as u32).to_le_bytes());
        self.field(nk, 40, &values.to_le_bytes());
        self.field(nk, 44, &security.to_le_bytes());
        self.field(nk, 48, &class_cell.to_le_bytes());
        self.field(nk, 52, &(largest_subkey as u32).to_le_bytes());
        self.field(nk, 56, &(largest_class as u32).to_le_bytes());
        self.field(nk, 60, &(largest_name as u32).to_le_bytes());
        self.field(nk, 64, &(largest_data as u32).to_le_bytes());
        self.field(nk, 72, &(name.len() as u16).to_le_bytes());
        self.field(nk, 74, &(class.len() as u16).to_le_bytes());
        self.field(nk, 76, &name);
        nk
    }
}

/// The security descriptor every key refers to: self-relative
/// (`SE_SELF_RELATIVE`), without owner, group or lists.
const SECURITY_DESCRIPTOR: [u8; 20] = [1, 0, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// The hive file for the tree below `root`, its base block naming it
/// `file_name` (the last 31 characters are kept).
pub fn build(root: &KeyNode, file_name: &str) -> Vec<u8> {
    let mut bin = Bin { data: alloc::vec![0u8; HBIN_HEADER_SIZE], keys: 0 };
    // The shared security cell first, a ring of one.
    let security = bin.alloc(20 + SECURITY_DESCRIPTOR.len());
    bin.field(security, 0, b"sk");
    bin.field(security, 4, &security.to_le_bytes());
    bin.field(security, 8, &security.to_le_bytes());
    bin.field(security, 16, &(SECURITY_DESCRIPTOR.len() as u32).to_le_bytes());
    bin.field(security, 20, &SECURITY_DESCRIPTOR);
    let root_offset = bin.key(root, NO_CELL, security, true);
    let references = bin.keys;
    bin.field(security, 12, &references.to_le_bytes());

    // The rest of the last page is one free cell; cells are 8-byte multiples,
    // so the rest is 0 or at least 8 bytes.
    let used = bin.data.len();
    let size = used.next_multiple_of(0x1000);
    bin.data.resize(size, 0);
    if size > used {
        bin.data[used..used + 4].copy_from_slice(&((size - used) as u32).to_le_bytes());
    }
    bin.data[..4].copy_from_slice(b"hbin");
    bin.data[8..12].copy_from_slice(&(size as u32).to_le_bytes());

    let mut file = alloc::vec![0u8; BASE_BLOCK_SIZE];
    file[..4].copy_from_slice(b"regf");
    file[4..8].copy_from_slice(&1u32.to_le_bytes()); // primary sequence
    file[8..12].copy_from_slice(&1u32.to_le_bytes()); // secondary sequence
    file[20..24].copy_from_slice(&1u32.to_le_bytes()); // major version
    file[24..28].copy_from_slice(&3u32.to_le_bytes()); // minor version
    file[32..36].copy_from_slice(&1u32.to_le_bytes()); // file format: direct memory load
    file[36..40].copy_from_slice(&root_offset.to_le_bytes());
    file[40..44].copy_from_slice(&(size as u32).to_le_bytes());
    file[44..48].copy_from_slice(&1u32.to_le_bytes()); // clustering factor
    let units: Vec<u16> = file_name.encode_utf16().collect();
    let kept = &units[units.len().saturating_sub(31)..];
    for (i, unit) in kept.iter().enumerate() {
        file[48 + 2 * i..50 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    let sum = checksum(&file);
    file[508..512].copy_from_slice(&sum.to_le_bytes());
    file.extend_from_slice(&bin.data);
    file
}
