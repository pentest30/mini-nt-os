//! La file de données d'un sens d'une instance (NP_DATA_QUEUE) : soit des
//! lectures en attente, soit des données écrites qui attendent d'être lues,
//! jamais les deux.
//!
//! Chaque écriture est une entrée : un message pour un tube de type message,
//! un morceau du flux pour un tube d'octets. Une lecture en mode message
//! prend au plus une entrée (le reste d'un message trop long pour le tampon
//! reste en tête, `STATUS_BUFFER_OVERFLOW`) ; une lecture en mode octet en
//! prend autant que son tampon en tient. Le quota du sens limite ce qui est
//! écrit sans être lu : une écriture qui le dépasse reste en attente (elle
//! est « bloquée ») jusqu'à ce que des lectures le libèrent, mais ses
//! données sont déjà dans la file.
//!
//! La spécification suivie est celle de ReactOS : `drivers/filesystems/npfs`
//! (`datasup.c`, `readsup.c`, `writesup.c`).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};
use abi::pipe::{FILE_PIPE_MESSAGE_MODE, FILE_PIPE_MESSAGE_TYPE};

use crate::request::{Completed, Deferred, Request};

/// Une entrée de la file.
enum Entry {
    /// Une lecture en attente, de `size` octets au plus.
    Read { request: Arc<Request>, size: usize },
    /// Des données écrites. `quota` : la part du quota du sens qu'elles
    /// tiennent (QuotaInEntry) ; `request` : l'écriture qui attend que tout
    /// le reste de ses données tienne dans le quota.
    Write { data: Vec<u8>, quota: usize, request: Option<Arc<Request>> },
}

/// Ce que tient la file (QueueState).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueState {
    Empty,
    ReadEntries,
    WriteEntries,
}

/// La file de données d'un sens.
pub(crate) struct DataQueue {
    quota: usize,
    quota_used: usize,
    /// Ce qui est déjà lu de la première entrée (ByteOffset).
    offset: usize,
    entries: VecDeque<Entry>,
}

impl DataQueue {
    /// Une file vide, de quota `quota`.
    pub(crate) fn new(quota: usize) -> Self {
        Self { quota, quota_used: 0, offset: 0, entries: VecDeque::new() }
    }

    pub(crate) fn state(&self) -> QueueState {
        match self.entries.front() {
            None => QueueState::Empty,
            Some(Entry::Read { .. }) => QueueState::ReadEntries,
            Some(Entry::Write { .. }) => QueueState::WriteEntries,
        }
    }

    pub(crate) fn quota(&self) -> usize {
        self.quota
    }

    /// Le quota libre.
    pub(crate) fn quota_left(&self) -> usize {
        self.quota - self.quota_used
    }

    /// BytesInQueue : la taille des entrées (des lectures demandées, ou des
    /// données écrites, ce qui est déjà lu de la première compris).
    pub(crate) fn bytes_in_queue(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| match entry {
                Entry::Read { size, .. } => *size,
                Entry::Write { data, .. } => data.len(),
            })
            .sum()
    }

    /// Les octets qu'une lecture trouverait (ReadDataAvailable).
    pub(crate) fn readable(&self) -> usize {
        match self.state() {
            QueueState::WriteEntries => self.bytes_in_queue() - self.offset,
            _ => 0,
        }
    }

    /// Le nombre de messages écrits, et la longueur de ce qui reste du
    /// premier (FSCTL_PIPE_PEEK).
    pub(crate) fn messages(&self) -> (usize, usize) {
        match self.entries.front() {
            Some(Entry::Write { data, .. }) => (self.entries.len(), data.len() - self.offset),
            _ => (0, 0),
        }
    }

    /// Le plus de ce qu'une écriture de `size` octets trouverait sans
    /// dépasser le quota : les lectures en attente, puis le quota libre
    /// (la condition de NpCommonWrite).
    pub(crate) fn has_room_for(&self, size: usize) -> bool {
        match self.state() {
            QueueState::ReadEntries => {
                let waiting = self.bytes_in_queue();
                waiting >= size || self.quota >= size - waiting
            }
            _ => self.quota_left() >= size,
        }
    }

    /// NpWriteDataQueue : donne `data` aux lectures en attente, la première
    /// d'abord ; une lecture finit avec ce que son tampon tient, en
    /// `STATUS_BUFFER_OVERFLOW` si son mode `read_mode` est le mode message
    /// et qu'il reste des données. Un message vide d'un tube de type message
    /// (`pipe_type`) finit la première lecture, sans données. Rend ce qui
    /// reste à écrire : `Some(n)` si une entrée doit garder `n` octets (ou un
    /// message vide), `None` si tout est lu.
    pub(crate) fn write_to_readers(
        &mut self,
        data: &[u8],
        read_mode: u32,
        pipe_type: u32,
        deferred: &mut Deferred,
    ) -> Option<usize> {
        let mut left = data.len();
        // An empty message still goes to a reader.
        let mut empty_message = pipe_type == FILE_PIPE_MESSAGE_TYPE && data.is_empty();
        while self.state() == QueueState::ReadEntries && (left > 0 || empty_message) {
            let Some(Entry::Read { request, size }) = self.entries.pop_front() else { unreachable!("a read entry") };
            if request.abandoned() {
                deferred.drop_later(request);
                continue;
            }
            let take = left.min(size);
            let start = data.len() - left;
            left -= take;
            let status = if left == 0 {
                empty_message = false;
                STATUS_SUCCESS
            } else if read_mode == FILE_PIPE_MESSAGE_MODE {
                STATUS_BUFFER_OVERFLOW
            } else {
                STATUS_SUCCESS
            };
            let completed = Completed { status, information: take as u32, data: data[start..start + take].to_vec() };
            deferred.finish(request, completed);
        }
        (left > 0 || empty_message).then_some(left)
    }

    /// NpAddDataQueueEntry, pour une écriture : garde `data`, dont
    /// `written` octets sont déjà lus, dans la part du quota qui reste ;
    /// `request`, s'il y en a une, attend si tout ne tient pas. Rend vrai si
    /// elle attend.
    pub(crate) fn add_write(&mut self, data: Vec<u8>, written: usize, request: Option<Arc<Request>>) -> bool {
        debug_assert!(written == 0 || self.entries.is_empty(), "a partly written entry comes first");
        let left = data.len() - written;
        let quota = left.min(self.quota_left());
        let stalled = quota < left && request.is_some();
        self.quota_used += quota;
        if written > 0 {
            self.offset = written;
        }
        self.entries.push_back(Entry::Write { data, quota, request: if stalled { request } else { None } });
        stalled
    }

    /// NpAddDataQueueEntry, pour une lecture de `size` octets au plus, qui
    /// attend.
    pub(crate) fn add_read(&mut self, request: Arc<Request>, size: usize) {
        debug_assert!(self.state() != QueueState::WriteEntries, "a read waits only on an empty queue");
        self.entries.push_back(Entry::Read { request, size });
    }

    /// NpReadDataQueue : lit (ou, avec `peek`, regarde sans prendre) au plus
    /// `size` octets des données écrites. En mode message (`read_mode`), au
    /// plus un message, en `STATUS_BUFFER_OVERFLOW` s'il n'est pas lu en
    /// entier (le reste reste en tête) ; en mode octet, d'une entrée à
    /// l'autre. Chaque écriture lue en entier finit ; le quota libéré
    /// débloque les écritures qui attendent.
    pub(crate) fn read(
        &mut self,
        size: usize,
        read_mode: u32,
        peek: bool,
        deferred: &mut Deferred,
    ) -> (Vec<u8>, NtStatus) {
        let mut out = Vec::new();
        let mut status = STATUS_SUCCESS;
        let mut index = 0;
        let mut freed = false;
        while out.len() < size {
            let first = index == 0;
            let offset = if first { self.offset } else { 0 };
            let Some(Entry::Write { data, quota, .. }) = self.entries.get_mut(index) else { break };
            let left = data.len() - offset;
            let take = left.min(size - out.len());
            out.extend_from_slice(&data[offset..offset + take]);
            if !peek {
                let charged = take.min(*quota);
                *quota -= charged;
                self.quota_used -= charged;
                self.offset += take;
                freed = true;
            }
            if take < left {
                if read_mode == FILE_PIPE_MESSAGE_MODE {
                    status = STATUS_BUFFER_OVERFLOW;
                    break;
                }
            } else {
                if peek {
                    index += 1;
                } else {
                    self.finish_first(deferred);
                }
                if read_mode == FILE_PIPE_MESSAGE_MODE {
                    status = STATUS_SUCCESS;
                    break;
                }
            }
        }
        if freed {
            self.complete_stalled_writes(deferred);
        }
        (out, status)
    }

    /// La première entrée, lue en entier, quitte la file ; son écriture,
    /// si elle attendait encore, finit.
    fn finish_first(&mut self, deferred: &mut Deferred) {
        if let Some(Entry::Write { data, quota, request }) = self.entries.pop_front() {
            self.quota_used -= quota;
            if let Some(request) = request {
                deferred.finish_status(request, STATUS_SUCCESS, data.len() as u32);
            }
        }
        self.offset = 0;
    }

    /// NpCompleteStalledWrites : le quota libre va aux écritures qui
    /// attendent, dans l'ordre ; celle dont tout le reste tient finit.
    fn complete_stalled_writes(&mut self, deferred: &mut Deferred) {
        let mut left = self.quota_left();
        let mut offset = self.offset;
        for entry in self.entries.iter_mut() {
            if left == 0 {
                break;
            }
            if let Entry::Write { data, quota, request } = entry {
                if request.is_some() {
                    let rest = data.len() - offset;
                    let added = (rest - *quota).min(left);
                    left -= added;
                    *quota += added;
                    if *quota == rest {
                        let request = request.take().expect("a stalled write");
                        deferred.finish_status(request, STATUS_SUCCESS, data.len() as u32);
                    }
                }
            }
            offset = 0;
        }
        self.quota_used = self.quota - left;
    }

    /// Vide la file : chaque demande qui y attend (lecture, écriture
    /// bloquée) finit avec `status` ; les données sont perdues.
    pub(crate) fn flush(&mut self, status: NtStatus, deferred: &mut Deferred) {
        for entry in self.entries.drain(..) {
            match entry {
                Entry::Read { request, .. } | Entry::Write { request: Some(request), .. } => {
                    deferred.finish_status(request, status, 0)
                }
                Entry::Write { request: None, .. } => {}
            }
        }
        self.quota_used = 0;
        self.offset = 0;
    }

    /// Les lectures en attente finissent avec `status` (une fin qui casse
    /// le tube) ; les données restent.
    pub(crate) fn flush_reads(&mut self, status: NtStatus, deferred: &mut Deferred) {
        while let Some(Entry::Read { .. }) = self.entries.front() {
            if let Some(Entry::Read { request, .. }) = self.entries.pop_front() {
                deferred.finish_status(request, status, 0);
            }
        }
    }

    /// Retire les demandes pour lesquelles `matches` est vrai et les finit
    /// avec `status` ; une écriture retirée emporte ses données. Rend leur
    /// nombre.
    pub(crate) fn cancel(
        &mut self,
        matches: &dyn Fn(&Request) -> bool,
        status: NtStatus,
        deferred: &mut Deferred,
    ) -> usize {
        let mut cancelled = 0;
        let mut index = 0;
        while index < self.entries.len() {
            let hit = match &self.entries[index] {
                Entry::Read { request, .. } | Entry::Write { request: Some(request), .. } => matches(request),
                Entry::Write { request: None, .. } => false,
            };
            if !hit {
                index += 1;
                continue;
            }
            match self.entries.remove(index) {
                Some(Entry::Read { request, .. }) => deferred.finish_status(request, status, 0),
                Some(Entry::Write { quota, request: Some(request), .. }) => {
                    self.quota_used -= quota;
                    if index == 0 {
                        self.offset = 0;
                    }
                    deferred.finish_status(request, status, 0);
                }
                _ => unreachable!("a request's entry"),
            }
            cancelled += 1;
        }
        if cancelled > 0 {
            self.complete_stalled_writes(deferred);
        }
        cancelled
    }
}
