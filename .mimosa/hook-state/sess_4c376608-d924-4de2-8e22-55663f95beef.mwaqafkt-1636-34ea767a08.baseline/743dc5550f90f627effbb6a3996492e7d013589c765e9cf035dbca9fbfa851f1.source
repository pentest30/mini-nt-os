//! Les classes d'information des services du registre : ce que rendent
//! NtQueryKey, NtEnumerateKey, NtQueryValueKey et NtEnumerateValueKey, en
//! octets, avec leur taille minimale (la partie fixe, layouts dans
//! `abi::registry`). Le service rend ensuite ce qui tient dans le tampon de
//! l'appelant.

use alloc::vec::Vec;

use abi::registry::{
    KeyBasicInformation32, KeyFullInformation32, KeyNodeInformation32, KeyValueBasicInformation32,
    KeyValueFullInformation32, KeyValuePartialInformation32, KEY_BASIC_INFORMATION, KEY_FULL_INFORMATION,
    KEY_NODE_INFORMATION, KEY_VALUE_BASIC_INFORMATION, KEY_VALUE_FULL_INFORMATION, KEY_VALUE_PARTIAL_INFORMATION,
};

/// Ce que les classes d'information disent d'une clé.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyFacts {
    /// Son nom, en UTF-16.
    pub name: Vec<u16>,
    /// Sa classe, en UTF-16 ; vide sans elle.
    pub class: Vec<u16>,
    /// FILETIME.
    pub last_written: u64,
    pub subkeys: u32,
    /// La plus longue sous-clé, en octets.
    pub max_name: u32,
    pub max_class: u32,
    pub values: u32,
    pub max_value_name: u32,
    pub max_value_data: u32,
}

/// Une valeur.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValueFacts {
    /// Son nom, en UTF-16 ; vide pour la valeur par défaut.
    pub name: Vec<u16>,
    pub data_type: u32,
    pub data: Vec<u8>,
}

/// Une classe d'information encodée : ses octets, et la taille de sa
/// partie fixe, sous laquelle l'appelant ne reçoit rien.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub minimum: usize,
}

fn units_bytes(units: &[u16]) -> impl Iterator<Item = u8> + '_ {
    units.iter().flat_map(|u| u.to_le_bytes())
}

/// La classe `class` (`KEY_*_INFORMATION`) de la clé `facts` ; `None` pour
/// une classe que Cm ne connaît pas.
pub fn key_information(facts: &KeyFacts, class: u32) -> Option<Encoded> {
    let name_length = (facts.name.len() * 2) as u32;
    let class_length = (facts.class.len() * 2) as u32;
    let mut bytes = Vec::new();
    let minimum = match class {
        KEY_BASIC_INFORMATION => {
            let header = KeyBasicInformation32 { last_write_time: facts.last_written, title_index: 0, name_length };
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend(units_bytes(&facts.name));
            core::mem::size_of::<KeyBasicInformation32>()
        }
        KEY_NODE_INFORMATION => {
            let fixed = core::mem::size_of::<KeyNodeInformation32>() as u32;
            let header = KeyNodeInformation32 {
                last_write_time: facts.last_written,
                title_index: 0,
                class_offset: if facts.class.is_empty() { u32::MAX } else { fixed + name_length },
                class_length,
                name_length,
            };
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend(units_bytes(&facts.name));
            bytes.extend(units_bytes(&facts.class));
            fixed as usize
        }
        KEY_FULL_INFORMATION => {
            let fixed = core::mem::size_of::<KeyFullInformation32>() as u32;
            let header = KeyFullInformation32 {
                last_write_time: facts.last_written,
                title_index: 0,
                class_offset: if facts.class.is_empty() { u32::MAX } else { fixed },
                class_length,
                sub_keys: facts.subkeys,
                max_name_len: facts.max_name,
                max_class_len: facts.max_class,
                values: facts.values,
                max_value_name_len: facts.max_value_name,
                max_value_data_len: facts.max_value_data,
            };
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend(units_bytes(&facts.class));
            fixed as usize
        }
        _ => return None,
    };
    Some(Encoded { bytes, minimum })
}

/// La classe `class` (`KEY_VALUE_*_INFORMATION`) de la valeur `facts` ;
/// `None` pour une classe que Cm ne connaît pas. Dans
/// KEY_VALUE_FULL_INFORMATION, les données suivent le nom, alignées sur
/// 4 octets.
pub fn value_information(facts: &ValueFacts, class: u32) -> Option<Encoded> {
    let name_length = (facts.name.len() * 2) as u32;
    let data_length = facts.data.len() as u32;
    let mut bytes = Vec::new();
    let minimum = match class {
        KEY_VALUE_BASIC_INFORMATION => {
            let header = KeyValueBasicInformation32 { title_index: 0, data_type: facts.data_type, name_length };
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend(units_bytes(&facts.name));
            core::mem::size_of::<KeyValueBasicInformation32>()
        }
        KEY_VALUE_FULL_INFORMATION => {
            let fixed = core::mem::size_of::<KeyValueFullInformation32>();
            let data_offset = (fixed + name_length as usize).next_multiple_of(4);
            let header = KeyValueFullInformation32 {
                title_index: 0,
                data_type: facts.data_type,
                data_offset: data_offset as u32,
                data_length,
                name_length,
            };
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend(units_bytes(&facts.name));
            bytes.resize(data_offset, 0);
            bytes.extend_from_slice(&facts.data);
            fixed
        }
        KEY_VALUE_PARTIAL_INFORMATION => {
            let header = KeyValuePartialInformation32 { title_index: 0, data_type: facts.data_type, data_length };
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(&facts.data);
            core::mem::size_of::<KeyValuePartialInformation32>()
        }
        _ => return None,
    };
    Some(Encoded { bytes, minimum })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn key_classes_put_the_name_and_class_after_the_fixed_part() {
        let facts = KeyFacts {
            name: "Session".encode_utf16().collect(),
            class: "C".encode_utf16().collect(),
            last_written: 0x1122_3344_5566_7788,
            subkeys: 3,
            max_name: 18,
            values: 2,
            max_value_name: 34,
            max_value_data: 64,
            ..KeyFacts::default()
        };
        let basic = key_information(&facts, KEY_BASIC_INFORMATION).unwrap();
        assert_eq!((basic.minimum, basic.bytes.len()), (16, 16 + 14));
        assert_eq!((word(&basic.bytes, 0), word(&basic.bytes, 12)), (0x5566_7788, 14));
        assert_eq!(&basic.bytes[16..18], &[b'S', 0]);
        let node = key_information(&facts, KEY_NODE_INFORMATION).unwrap();
        assert_eq!(
            (node.minimum, word(&node.bytes, 12), word(&node.bytes, 16)),
            (24, 24 + 14, 2),
            "class after the name"
        );
        assert_eq!(&node.bytes[38..40], &[b'C', 0]);
        let full = key_information(&facts, KEY_FULL_INFORMATION).unwrap();
        assert_eq!(full.minimum, 44);
        let fields: Vec<u32> = (12..44).step_by(4).map(|at| word(&full.bytes, at)).collect();
        assert_eq!(fields, [44, 2, 3, 18, 0, 2, 34, 64], "class offset and length, counts and maxima");
        let classless = KeyFacts { class: Vec::new(), ..facts };
        assert_eq!(word(&key_information(&classless, KEY_FULL_INFORMATION).unwrap().bytes, 12), u32::MAX);
        assert!(key_information(&classless, 3).is_none(), "KeyNameInformation is not known");
    }

    #[test]
    fn value_classes_align_full_data_on_four_bytes() {
        let facts = ValueFacts { name: "Abc".encode_utf16().collect(), data_type: 4, data: vec![1, 2, 3, 4] };
        let basic = value_information(&facts, KEY_VALUE_BASIC_INFORMATION).unwrap();
        assert_eq!((basic.minimum, basic.bytes.len(), word(&basic.bytes, 4), word(&basic.bytes, 8)), (12, 18, 4, 6));
        let full = value_information(&facts, KEY_VALUE_FULL_INFORMATION).unwrap();
        // 20 + 6 bytes of name, the data at 28.
        assert_eq!((full.minimum, word(&full.bytes, 8), word(&full.bytes, 12), word(&full.bytes, 16)), (20, 28, 4, 6));
        assert_eq!(&full.bytes[28..], &[1, 2, 3, 4]);
        let partial = value_information(&facts, KEY_VALUE_PARTIAL_INFORMATION).unwrap();
        assert_eq!((partial.minimum, word(&partial.bytes, 8), &partial.bytes[12..]), (12, 4, &[1u8, 2, 3, 4][..]));
        assert!(value_information(&facts, 3).is_none());
    }
}
