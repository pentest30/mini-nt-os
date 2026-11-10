//! Identifiants clients (`CLIENT_ID`) : la table des PID et des TID
//! (PspCidTable).
//!
//! Processus et threads tirent leur identifiant d'un même espace : des
//! multiples de 4, 0 restant au processus Idle. Comme pour une table de
//! handles, l'entrée libérée en dernier est reprise la première ; le
//! processus System, créé le premier, reçoit 4. La table ne garde pas les
//! objets en vie : un processus ou un thread rend son identifiant quand il
//! est détruit.

use alloc::vec::Vec;

/// Ce que désigne un identifiant.
pub struct CidTable<T> {
    /// Entrée `i` : l'identifiant `4 * i` ; l'entrée 0 n'est jamais donnée.
    entries: Vec<Option<T>>,
    /// Entrées libérées, la dernière reprise la première.
    free: Vec<usize>,
    /// Nombre maximal d'entrées.
    limit: usize,
}

/// Au plus 2^24 identifiants, comme les handles.
const MAX_ENTRIES: usize = 1 << 24;

impl<T> Default for CidTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> CidTable<T> {
    /// Une table vide.
    pub const fn new() -> Self {
        Self::with_limit(MAX_ENTRIES)
    }

    /// Une table vide d'au plus `limit` identifiants (tests).
    pub const fn with_limit(limit: usize) -> Self {
        Self { entries: Vec::new(), free: Vec::new(), limit }
    }

    /// Donne un identifiant à `object` ; `None` si la table est pleine.
    pub fn insert(&mut self, object: T) -> Option<u32> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let index = self.entries.len().max(1);
                if index > self.limit {
                    return None;
                }
                self.entries.resize_with(index + 1, || None);
                index
            }
        };
        self.entries[index] = Some(object);
        Some((index * 4) as u32)
    }

    /// L'entrée de `id` : un multiple de 4, non nul ; ses deux bits du bas
    /// sont ignorés, comme pour un handle.
    fn index(id: u32) -> Option<usize> {
        let index = (id / 4) as usize;
        (index != 0).then_some(index)
    }

    /// Ce que désigne `id`.
    pub fn get(&self, id: u32) -> Option<&T> {
        self.entries.get(Self::index(id)?)?.as_ref()
    }

    /// Remplace ce que désigne `id`, déjà donné.
    ///
    /// # Panics
    /// Si `id` n'est pas donné.
    pub fn set(&mut self, id: u32, object: T) {
        let entry = Self::index(id).and_then(|index| self.entries.get_mut(index)).and_then(Option::as_mut);
        *entry.expect("an id not given") = object;
    }

    /// Rend `id` et ce qu'il désignait.
    pub fn remove(&mut self, id: u32) -> Option<T> {
        let index = Self::index(id)?;
        let object = self.entries.get_mut(index)?.take()?;
        self.free.push(index);
        Some(object)
    }

    /// Les identifiants donnés et ce qu'ils désignent, dans l'ordre.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &T)> + '_ {
        self.entries.iter().enumerate().filter_map(|(index, entry)| Some(((index * 4) as u32, entry.as_ref()?)))
    }

    /// Nombre d'identifiants donnés.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    /// Aucun identifiant n'est donné.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_multiples_of_four_from_four() {
        let mut table = CidTable::new();
        assert_eq!([table.insert('a'), table.insert('b'), table.insert('c')], [Some(4), Some(8), Some(12)]);
        assert_eq!(table.get(8), Some(&'b'));
        assert_eq!(table.get(9), Some(&'b'), "low bits ignored");
        assert_eq!(table.get(0), None, "0 is the Idle process's");
        assert_eq!(table.get(16), None);
        assert_eq!(table.len(), 3);
        table.set(8, 'B');
        assert_eq!(table.get(8), Some(&'B'));
    }

    #[test]
    #[should_panic(expected = "not given")]
    fn set_needs_a_given_id() {
        CidTable::new().set(4, 'a');
    }

    #[test]
    fn the_last_id_freed_is_the_first_given_again() {
        let mut table = CidTable::new();
        for c in ['a', 'b', 'c'] {
            table.insert(c);
        }
        assert_eq!(table.remove(4), Some('a'));
        assert_eq!(table.remove(12), Some('c'));
        assert_eq!(table.remove(12), None, "already free");
        assert_eq!(table.get(4), None);
        assert_eq!([table.insert('d'), table.insert('e'), table.insert('f')], [Some(12), Some(4), Some(16)]);
    }

    #[test]
    fn a_full_table_gives_no_id() {
        let mut table = CidTable::with_limit(2);
        assert_eq!([table.insert(1), table.insert(2), table.insert(3)], [Some(4), Some(8), None]);
        table.remove(4);
        assert_eq!(table.insert(4), Some(4));
        assert!(!table.is_empty());
    }

    #[test]
    fn the_ids_given_come_in_order() {
        let mut table = CidTable::new();
        let ids: Vec<u32> = ["a", "b", "c"].into_iter().map(|o| table.insert(o).unwrap()).collect();
        table.remove(ids[1]);
        let listed: Vec<(u32, &str)> = table.iter().map(|(id, o)| (id, *o)).collect();
        assert_eq!(listed, [(ids[0], "a"), (ids[2], "c")]);
    }
}
