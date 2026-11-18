//! Le presse-papiers de USER (02 §7.2 ; `clipboard.c` du win32k et du
//! `user32` de ReactOS comme spécification ; là où ReactOS s'écarte d'XP, le
//! test `clipboard.c` de Wine, vérifié sous Windows, dit ce que fait XP).
//!
//! Chaque station de fenêtres a son presse-papiers ([`Clipboard`], dans
//! `crate::winsta::WindowStation`), qu'on atteint par la station du
//! processus courant si son handle porte WINSTA_ACCESSCLIPBOARD
//! (IntGetWinStaForCbAccess).
//!
//! Ses formats, dans l'ordre où ils sont posés (EnumClipboardFormats),
//! portent chacun ses données ([`Data`]) : un objet `TYPE_CLIPDATA` de la
//! table des handles USER (les octets que `user32` confie au noyau par
//! NtUserConvertMemHandle et relit par NtUserCreateLocalMemHandle :
//! [`create_data`], [`data`]), une valeur (un objet de GDI, un nombre), rien
//! encore (le rendu différé : SetClipboardData sans données), ou rien du tout
//! pour un format de texte que `user32` synthétise.
//!
//! - OpenClipboard ([`open`]) : avec une fenêtre ou sans ; refusé
//!   (`ERROR_ACCESS_DENIED`) quand une autre fenêtre (ou aucune) l'a ouvert ;
//!   ouvert par la même, il passe au thread qui l'ouvre (comme XP).
//! - EmptyClipboard ([`empty`]) : WM_DESTROYCLIPBOARD au propriétaire, qui
//!   voit encore ses formats, puis les formats partent et la fenêtre qui a
//!   ouvert le presse-papiers devient le propriétaire (aucun sans fenêtre).
//! - SetClipboardData ([`set_data`]) : par le thread qui l'a ouvert ; par un
//!   autre quand la fenêtre qui l'a ouvert en est le propriétaire, ou
//!   pendant un rendu différé (comme XP).
//! - GetClipboardData ([`get_data`]), par le thread qui l'a ouvert : un format
//!   de texte synthétisé rend les données de sa source (CF_UNICODETEXT, puis
//!   CF_TEXT, puis CF_OEMTEXT), que `user32` convertit et repose ; un format
//!   différé est d'abord demandé au propriétaire (WM_RENDERFORMAT).
//! - CloseClipboard ([`close`]) : si le contenu a changé, les formats
//!   synthétisés s'ajoutent (CF_LOCALE, des données du noyau : les
//!   paramètres régionaux du thread ; CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT,
//!   que `user32` synthétisera) et la première visionneuse reçoit
//!   WM_DRAWCLIPBOARD.
//! - Le numéro de séquence (GetClipboardSequenceNumber) croît à chaque
//!   EmptyClipboard, à chaque SetClipboardData, à chaque format synthétisé
//!   ajouté et quand des formats différés partent avec leur propriétaire ;
//!   ni pour un rendu (différé ou synthétisé), ni à la fermeture seule.
//! - La chaîne des visionneuses : SetClipboardViewer ([`set_viewer`]),
//!   ChangeClipboardChain ([`change_chain`], WM_CHANGECBCHAIN à la
//!   première), GetClipboardViewer.
//!
//! Les messages partent hors de tout verrou : WM_DESTROYCLIPBOARD,
//! WM_RENDERFORMAT, WM_RENDERALLFORMATS et WM_CHANGECBCHAIN sont envoyés
//! (l'appelant attend la réponse), WM_DRAWCLIPBOARD est une notification,
//! mise dans la file du thread de la visionneuse, le sien compris (comme
//! XP).
//!
//! La destruction (`crate::destroy`) : le propriétaire détruit par
//! DestroyWindow reçoit d'abord WM_RENDERALLFORMATS s'il a des formats
//! différés ([`release_owner`]) ; une fenêtre détruite cesse d'être le
//! propriétaire (ses formats encore différés partent), la fenêtre qui a
//! ouvert le presse-papiers (il se ferme) ou la visionneuse
//! ([`forget_window`]) ; un thread qui finit le presse-papiers ouvert le
//! ferme ([`thread_exit`]) ; un processus qui finit rend les données qu'il a
//! confiées au noyau et qu'aucun presse-papiers ne tient ([`destroy_data`]).
//! Les données posées restent : on colle ce qu'a copié un processus fini.
//!
//! Écarts voulus avec ReactOS, pour faire comme XP : WM_DESTROYCLIPBOARD
//! avant que les formats partent ; le numéro de séquence (ReactOS ne le fait
//! croître qu'à EmptyClipboard : son `user32` ne demande jamais
//! `fIncSerialNumber`, que Mino ignore) ; SetClipboardData refusé à un autre
//! thread que celui qui a ouvert le presse-papiers, hors des deux cas
//! d'XP ; WM_RENDERALLFORMATS au seul propriétaire, et seulement s'il a des
//! formats différés ; un thread qui finit ferme le presse-papiers qu'il a
//! ouvert ; les formats synthétisés sans source partent avec les formats
//! différés ; SetClipboardViewer ne perd pas un changement en attente.
//!
//! Pas encore : CF_BITMAP, CF_PALETTE et les métafichiers (des objets de GDI
//! rendus publics, CF_DIB et CF_BITMAP, CF_ENHMETAFILE et CF_METAFILEPICT
//! synthétisés l'un de l'autre), les auditeurs de Vista
//! (AddClipboardFormatListener, WM_CLIPBOARDUPDATE), les données dans le pool
//! paginé.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use abi::teb32::Teb32;
use abi::user::cf::{CF_BITMAP, CF_LOCALE, CF_OEMTEXT, CF_PALETTE, CF_TEXT, CF_UNICODETEXT};
use abi::user::{
    GetClipbData32, TYPE_CLIPDATA, WM_CHANGECBCHAIN, WM_DESTROYCLIPBOARD, WM_DRAWCLIPBOARD, WM_RENDERALLFORMATS,
    WM_RENDERFORMAT,
};
use abi::winerror::{
    ERROR_ACCESS_DENIED, ERROR_CLIPBOARD_NOT_OPEN, ERROR_INVALID_HANDLE, ERROR_INVALID_WINDOW_HANDLE,
    ERROR_NOT_ENOUGH_MEMORY,
};
use hal::sync::KSpinLock;
use ob::Object;

use crate::gui::ThreadInfo;
use crate::window::LParam;
use crate::winsta::{WindowStation, WINSTA_ACCESSCLIPBOARD};

/// Les données d'un format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data {
    /// Rendu différé (DATA_DELAYED) : le propriétaire les donnera à
    /// WM_RENDERFORMAT.
    Delayed,
    /// Synthétisé par `user32` d'un autre format de texte (DATA_SYNTH_USER).
    Synthesized,
    /// Un handle : un objet `TYPE_CLIPDATA` (`global`), ou une valeur que le
    /// noyau ne lit pas.
    Handle { handle: u32, global: bool },
}

/// Un format et ses données (CLIP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub format: u32,
    pub data: Data,
}

/// Ce que GetClipboardData trouve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Le format manque, ou ses données (rendu différé sans propriétaire,
    /// ou que le propriétaire n'a pas données).
    Missing,
    /// Ses données : le handle, et ce qu'en dit GETCLIPBDATA.
    Found { handle: u32, info: GetClipbData32 },
    /// Le format source `format` est différé : à demander à `owner`
    /// (WM_RENDERFORMAT).
    Render { format: u32, owner: u32 },
}

/// Les formats de texte que synthétise `user32`, dans l'ordre où ils
/// s'ajoutent ; un format synthétisé prend sa source dans l'ordre inverse.
const TEXT_FORMATS: [u32; 3] = [CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT];

/// Le presse-papiers d'une station (les champs `*Clip*` du
/// WINSTATION_OBJECT). Les fenêtres sont des handles, les threads les
/// adresses du serveur de leurs `THREADINFO`.
#[derive(Debug, Default)]
pub struct Clipboard {
    formats: Vec<Format>,
    /// ptiClipLock : le thread qui l'a ouvert ; 0, fermé.
    open_thread: u32,
    /// spwndClipOpen : la fenêtre qui l'a ouvert (0 : aucune).
    open_window: u32,
    /// spwndClipOwner : son propriétaire.
    owner: u32,
    /// spwndClipViewer : la première visionneuse.
    viewer: u32,
    /// iClipSequenceNumber.
    sequence: u32,
    /// fClipboardChanged : à annoncer à la fermeture.
    changed: bool,
    /// fInDelayedRendering : un WM_RENDERFORMAT est en cours.
    rendering: bool,
}

impl Clipboard {
    /// Un presse-papiers vide et fermé.
    pub const fn new() -> Self {
        Self {
            formats: Vec::new(),
            open_thread: 0,
            open_window: 0,
            owner: 0,
            viewer: 0,
            sequence: 0,
            changed: false,
            rendering: false,
        }
    }

    /// Les données de `format`, s'il y est.
    pub fn data_of(&self, format: u32) -> Option<Data> {
        self.formats.iter().find(|clip| clip.format == format).map(|clip| clip.data)
    }

    /// IsClipboardFormatAvailable.
    pub fn is_available(&self, format: u32) -> bool {
        self.data_of(format).is_some()
    }

    /// CountClipboardFormats.
    pub fn count(&self) -> u32 {
        self.formats.len() as u32
    }

    /// Ses formats, dans l'ordre.
    pub fn formats(&self) -> impl Iterator<Item = u32> + '_ {
        self.formats.iter().map(|clip| clip.format)
    }

    /// GetClipboardOwner.
    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// GetOpenClipboardWindow : la fenêtre qui l'a ouvert, s'il l'est.
    pub fn open_window(&self) -> u32 {
        if self.open_thread == 0 {
            0
        } else {
            self.open_window
        }
    }

    /// GetClipboardViewer.
    pub fn viewer(&self) -> u32 {
        self.viewer
    }

    /// GetClipboardSequenceNumber.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// IntIsClipboardOpenByMe : `thread` l'a ouvert.
    pub fn is_open_by(&self, thread: u32) -> bool {
        self.open_thread != 0 && self.open_thread == thread
    }

    /// Ouvert par `thread`, sinon `ERROR_CLIPBOARD_NOT_OPEN`.
    pub fn check_open(&self, thread: u32) -> Result<(), u32> {
        if self.is_open_by(thread) {
            Ok(())
        } else {
            Err(ERROR_CLIPBOARD_NOT_OPEN)
        }
    }

    /// UserOpenClipboard : `thread` l'ouvre avec la fenêtre `window` (0 :
    /// aucune).
    ///
    /// # Errors
    /// `ERROR_ACCESS_DENIED` s'il est ouvert avec une autre fenêtre.
    pub fn open(&mut self, thread: u32, window: u32) -> Result<(), u32> {
        if self.open_thread != 0 && self.open_window != window {
            return Err(ERROR_ACCESS_DENIED);
        }
        self.open_thread = thread;
        self.open_window = window;
        Ok(())
    }

    /// UserCloseClipboard : `thread` le ferme ; s'il a changé, les formats
    /// synthétisés s'ajoutent ([`Self::publish`]). Rend la visionneuse à
    /// prévenir (WM_DRAWCLIPBOARD).
    ///
    /// # Errors
    /// `ERROR_CLIPBOARD_NOT_OPEN` s'il ne l'a pas ouvert.
    pub fn close(&mut self, thread: u32, make_locale: impl FnOnce() -> Option<u32>) -> Result<Option<u32>, u32> {
        self.check_open(thread)?;
        self.open_thread = 0;
        self.open_window = 0;
        Ok(self.publish(make_locale))
    }

    /// UserEmptyClipboard, une fois WM_DESTROYCLIPBOARD envoyé : ses formats
    /// partent, la fenêtre qui l'a ouvert devient son propriétaire. Rend les
    /// objets `TYPE_CLIPDATA` qu'il ne tient plus.
    ///
    /// # Errors
    /// `ERROR_CLIPBOARD_NOT_OPEN` si `thread` ne l'a pas ouvert.
    pub fn empty(&mut self, thread: u32) -> Result<Vec<u32>, u32> {
        self.check_open(thread)?;
        let freed = core::mem::take(&mut self.formats).into_iter().filter_map(|clip| global_handle(clip.data));
        let mut freed: Vec<u32> = freed.collect();
        freed.sort_unstable();
        freed.dedup();
        self.owner = self.open_window;
        self.sequence = self.sequence.wrapping_add(1);
        self.changed = true;
        self.rendering = false;
        Ok(freed)
    }

    /// SetClipboardData est permis à `thread` : il l'a ouvert, ou la fenêtre
    /// qui l'a ouvert en est le propriétaire, ou un rendu différé est en
    /// cours.
    pub fn may_set(&self, thread: u32) -> bool {
        self.open_thread != 0 && (self.open_thread == thread || self.open_window == self.owner || self.rendering)
    }

    /// UserSetClipboardData : `format` reçoit `data` (en fin de liste s'il
    /// n'y était pas). Rendre un format synthétisé (ce que `user32` repose
    /// après l'avoir converti) ou un rendu différé ne change pas le numéro de
    /// séquence, et le premier n'est pas un changement. Rend l'objet
    /// `TYPE_CLIPDATA` que plus rien ne tient.
    ///
    /// # Errors
    /// `ERROR_CLIPBOARD_NOT_OPEN` sans format ou si `thread` ne le peut pas
    /// ([`Self::may_set`]) ; `ERROR_NOT_ENOUGH_MEMORY`.
    pub fn set_data(&mut self, thread: u32, format: u32, data: Data) -> Result<Option<u32>, u32> {
        if format == 0 || !self.may_set(thread) {
            return Err(ERROR_CLIPBOARD_NOT_OPEN);
        }
        let synthesized = self.data_of(format) == Some(Data::Synthesized);
        let old = match self.formats.iter_mut().find(|clip| clip.format == format) {
            Some(clip) => Some(core::mem::replace(&mut clip.data, data)),
            None => {
                self.formats.try_reserve(1).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
                self.formats.push(Format { format, data });
                None
            }
        };
        if !synthesized {
            self.changed = true;
            if !self.rendering {
                self.sequence = self.sequence.wrapping_add(1);
            }
        }
        Ok(old.and_then(|old| self.unreferenced(old)))
    }

    /// Un rendu différé (WM_RENDERFORMAT) commence ou finit.
    pub fn set_rendering(&mut self, rendering: bool) {
        self.rendering = rendering;
    }

    /// Le format de texte que donne le format synthétisé `format` : le
    /// premier de CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT qui a ses données ou un
    /// rendu différé.
    fn text_source(&self, format: u32) -> Option<(u32, Data)> {
        if !TEXT_FORMATS.contains(&format) {
            return None;
        }
        TEXT_FORMATS.iter().rev().find_map(|&source| match self.data_of(source) {
            Some(Data::Synthesized) | None => None,
            Some(data) => Some((source, data)),
        })
    }

    /// Le handle des données de `format`, si elles sont là.
    fn handle_of(&self, format: u32) -> u32 {
        match self.data_of(format) {
            Some(Data::Handle { handle, .. }) => handle,
            _ => 0,
        }
    }

    /// NtUserGetClipboardData, sans le rendu : ce que `thread` trouve pour
    /// `format`. GETCLIPBDATA dit le format des données (la source d'un
    /// format synthétisé), si c'est un `TYPE_CLIPDATA`, et donne pour CF_TEXT
    /// les données de CF_LOCALE, pour CF_BITMAP celles de CF_PALETTE.
    ///
    /// # Errors
    /// `ERROR_CLIPBOARD_NOT_OPEN` si `thread` ne l'a pas ouvert.
    pub fn lookup(&self, thread: u32, format: u32) -> Result<Lookup, u32> {
        self.check_open(thread)?;
        let Some(data) = self.data_of(format) else { return Ok(Lookup::Missing) };
        let (source, data) = match data {
            Data::Synthesized => match self.text_source(format) {
                Some(source) => source,
                None => return Ok(Lookup::Missing),
            },
            data => (format, data),
        };
        Ok(match data {
            Data::Delayed if self.owner != 0 => Lookup::Render { format: source, owner: self.owner },
            Data::Delayed | Data::Synthesized => Lookup::Missing,
            Data::Handle { handle, global } => {
                let locale_or_palette = match format {
                    CF_TEXT => self.handle_of(CF_LOCALE),
                    CF_BITMAP => self.handle_of(CF_PALETTE),
                    _ => 0,
                };
                let info = GetClipbData32 { fmt_ret: source, global_handle: u32::from(global), locale_or_palette };
                Lookup::Found { handle, info }
            }
        })
    }

    /// UserEnumClipboardFormats : le format qui suit `after` (le premier pour
    /// 0) ; 0 après le dernier ou pour un format absent.
    ///
    /// # Errors
    /// `ERROR_CLIPBOARD_NOT_OPEN` si `thread` ne l'a pas ouvert.
    pub fn enum_next(&self, thread: u32, after: u32) -> Result<u32, u32> {
        self.check_open(thread)?;
        let next = if after == 0 {
            self.formats.first()
        } else {
            let at = self.formats.iter().position(|clip| clip.format == after);
            at.and_then(|at| self.formats.get(at + 1))
        };
        Ok(next.map_or(0, |clip| clip.format))
    }

    /// NtUserGetPriorityClipboardFormat : le premier de `list` qui y est ;
    /// -1 si aucun, 0 s'il est vide.
    pub fn priority(&self, list: &[u32]) -> i32 {
        if self.formats.is_empty() {
            return 0;
        }
        list.iter().find(|&&format| self.is_available(format)).map_or(-1, |&format| format as i32)
    }

    /// NtUserSetClipboardViewer : `hwnd` devient la première visionneuse ;
    /// rend la précédente, qu'elle doit prévenir à son tour.
    pub fn set_viewer(&mut self, hwnd: u32) -> u32 {
        core::mem::replace(&mut self.viewer, hwnd)
    }

    /// NtUserChangeClipboardChain : `remove` quitte la chaîne, `next` le
    /// suit ; s'il en était la tête, `next` le devient. Rend la visionneuse
    /// à qui envoyer WM_CHANGECBCHAIN, la tête de la chaîne.
    pub fn change_chain(&mut self, remove: u32, next: u32) -> Option<u32> {
        if self.viewer == 0 {
            return None;
        }
        if self.viewer == remove {
            self.viewer = next;
        }
        (self.viewer != 0).then_some(self.viewer)
    }

    /// `hwnd` est son propriétaire et a des formats différés : il recevra
    /// WM_RENDERALLFORMATS avant sa destruction.
    pub fn owns_delayed(&self, hwnd: u32) -> bool {
        hwnd != 0 && self.owner == hwnd && self.formats.iter().any(|clip| clip.data == Data::Delayed)
    }

    /// UserClipboardRelease : `hwnd`, détruit après WM_RENDERALLFORMATS,
    /// n'est plus le propriétaire ; ses formats encore différés partent, et
    /// le changement est annoncé tout de suite ([`Self::publish`], comme
    /// XP : avant WM_DESTROY). Rend la visionneuse à prévenir.
    pub fn release_owner(&mut self, hwnd: u32, make_locale: impl FnOnce() -> Option<u32>) -> Option<u32> {
        if hwnd == 0 || self.owner != hwnd {
            return None;
        }
        self.owner = 0;
        self.drop_delayed();
        self.publish(make_locale)
    }

    /// UserClipboardFreeWindow : `hwnd` est détruit. Propriétaire, il ne
    /// l'est plus et ses formats différés partent ; s'il a ouvert le
    /// presse-papiers, celui-ci se ferme ; visionneuse, la chaîne s'arrête
    /// (ReactOS). Fermé, un changement est annoncé. Rend la visionneuse à
    /// prévenir.
    pub fn forget_window(&mut self, hwnd: u32, make_locale: impl FnOnce() -> Option<u32>) -> Option<u32> {
        if hwnd == 0 {
            return None;
        }
        if self.owner == hwnd {
            self.owner = 0;
            self.drop_delayed();
        }
        if self.open_thread != 0 && self.open_window == hwnd {
            self.open_thread = 0;
            self.open_window = 0;
        }
        if self.viewer == hwnd {
            self.viewer = 0;
        }
        if self.open_thread != 0 {
            return None;
        }
        self.publish(make_locale)
    }

    /// `thread` finit : le presse-papiers qu'il a ouvert se ferme, comme par
    /// CloseClipboard. Rend la visionneuse à prévenir.
    pub fn thread_exit(&mut self, thread: u32, make_locale: impl FnOnce() -> Option<u32>) -> Option<u32> {
        self.close(thread, make_locale).ok().flatten()
    }

    /// Les formats différés partent, et les formats synthétisés qui n'ont
    /// plus de source ; un changement.
    fn drop_delayed(&mut self) {
        let before = self.formats.len();
        self.formats.retain(|clip| clip.data != Data::Delayed);
        let orphans: Vec<u32> = self
            .formats
            .iter()
            .filter(|clip| clip.data == Data::Synthesized && self.text_source(clip.format).is_none())
            .map(|clip| clip.format)
            .collect();
        self.formats.retain(|clip| !orphans.contains(&clip.format));
        if self.formats.len() != before {
            self.sequence = self.sequence.wrapping_add(1);
            self.changed = true;
        }
    }

    /// S'il a changé : les formats synthétisés s'ajoutent
    /// (IntAddSynthesizedFormats) et la première visionneuse est à prévenir
    /// (rendue).
    fn publish(&mut self, make_locale: impl FnOnce() -> Option<u32>) -> Option<u32> {
        if !core::mem::take(&mut self.changed) {
            return None;
        }
        self.synthesize(make_locale);
        (self.viewer != 0).then_some(self.viewer)
    }

    /// IntAddSynthesizedFormats, pour le texte : CF_LOCALE (ses données,
    /// faites par `make_locale`), puis CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT
    /// qui manquent, en fin de liste ; chacun fait croître le numéro de
    /// séquence.
    fn synthesize(&mut self, make_locale: impl FnOnce() -> Option<u32>) {
        if !TEXT_FORMATS.iter().any(|&format| self.is_available(format)) {
            return;
        }
        let mut added = Vec::new();
        if !self.is_available(CF_LOCALE) {
            if let Some(handle) = make_locale() {
                added.push(Format { format: CF_LOCALE, data: Data::Handle { handle, global: true } });
            }
        }
        for format in TEXT_FORMATS {
            if !self.is_available(format) {
                added.push(Format { format, data: Data::Synthesized });
            }
        }
        if self.formats.try_reserve(added.len()).is_err() {
            if let Some(handle) = added.iter().find_map(|clip| global_handle(clip.data)) {
                destroy_data(handle);
            }
            return;
        }
        self.sequence = self.sequence.wrapping_add(added.len() as u32);
        self.formats.extend(added);
    }

    /// L'objet `TYPE_CLIPDATA` de `old`, données remplacées, si plus aucun
    /// format ne le tient.
    fn unreferenced(&self, old: Data) -> Option<u32> {
        let handle = global_handle(old)?;
        (!self.formats.iter().any(|clip| global_handle(clip.data) == Some(handle))).then_some(handle)
    }
}

impl Drop for Clipboard {
    /// La station part : ses données aussi.
    fn drop(&mut self) {
        let mut handles: Vec<u32> = self.formats.iter().filter_map(|clip| global_handle(clip.data)).collect();
        handles.sort_unstable();
        handles.dedup();
        for handle in handles {
            destroy_data(handle);
        }
    }
}

/// L'objet `TYPE_CLIPDATA` de `data`, s'il en est un.
fn global_handle(data: Data) -> Option<u32> {
    match data {
        Data::Handle { handle, global: true } => Some(handle),
        _ => None,
    }
}

/// Les données des objets `TYPE_CLIPDATA` (CLIPBOARDDATA), par handle.
static DATA: KSpinLock<BTreeMap<u32, Arc<Vec<u8>>>> = KSpinLock::new(BTreeMap::new());

/// La taille au plus des données d'un format.
pub const MAX_DATA: usize = 64 << 20;

/// NtUserConvertMemHandle : un objet `TYPE_CLIPDATA` de `bytes`, au
/// propriétaire `owner` (un `PROCESSINFO`, son adresse du serveur ; 0 :
/// aucun) jusqu'à ce qu'un presse-papiers le prenne ; rend son handle.
///
/// # Errors
/// `ERROR_NOT_ENOUGH_MEMORY` si la table des handles est pleine.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn create_data(bytes: Vec<u8>, owner: u32) -> Result<u32, u32> {
    let handle = crate::handles::alloc(1, owner, TYPE_CLIPDATA).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    DATA.lock().insert(handle, Arc::new(bytes));
    Ok(handle)
}

/// Les données de l'objet `TYPE_CLIPDATA` `handle`, s'il existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn data(handle: u32) -> Option<Arc<Vec<u8>>> {
    DATA.lock().get(&handle).cloned()
}

/// L'objet `TYPE_CLIPDATA` `handle` et son handle sont rendus ; rend s'il
/// existait.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn destroy_data(handle: u32) -> bool {
    let removed = DATA.lock().remove(&handle);
    if removed.is_none() {
        return false;
    }
    let _ = crate::handles::free(handle);
    drop(removed);
    true
}

/// CF_LOCALE, des données du noyau : l'objet des paramètres régionaux
/// `locale`, au presse-papiers.
fn locale_data(locale: u32) -> Option<u32> {
    let bytes = locale.to_le_bytes().to_vec();
    create_data(bytes, 0).ok()
}

/// La station du processus courant, si son handle porte
/// WINSTA_ACCESSCLIPBOARD (IntGetWinStaForCbAccess).
fn current_station() -> Result<Arc<Object<WindowStation>>, u32> {
    let thread = ps::ethread::current_thread().ok_or(ERROR_INVALID_HANDLE)?;
    let info = crate::existing_process_info(thread.process()).ok_or(ERROR_INVALID_HANDLE)?;
    let station = info.window_station().ok_or(ERROR_INVALID_HANDLE)?;
    if station.access.0 & WINSTA_ACCESSCLIPBOARD == 0 {
        return Err(ERROR_ACCESS_DENIED);
    }
    Ok(station.station)
}

/// Le `THREADINFO` du thread courant.
fn current_thread() -> Result<Arc<ThreadInfo>, u32> {
    crate::convert_current_thread().map_err(|_| ERROR_ACCESS_DENIED)
}

/// Les paramètres régionaux du thread courant (`TEB.CurrentLocale`), sinon
/// ceux des threads (`ex::locale::user_locale`).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
fn thread_locale() -> u32 {
    let teb = ps::ethread::current_thread().map(|thread| thread.teb());
    let at = teb.map(|teb| teb + offset_of!(Teb32, current_locale) as u32);
    let locale = at.and_then(|at| ke::usermem::UserPtr::<u32>::new(at).read().ok());
    locale.filter(|&locale| locale != 0).unwrap_or_else(ex::locale::user_locale)
}

/// Envoie `message` à la fenêtre `hwnd` et attend sa réponse (0 si elle n'est
/// plus).
fn send(hwnd: u32, message: u32, wparam: u32, lparam: u32) -> u32 {
    let Some(window) = crate::window::get(hwnd) else { return 0 };
    crate::window::send_message(&window, message, wparam, LParam::Value(lparam)).unwrap_or(0)
}

/// WM_DRAWCLIPBOARD, une notification, dans la file du thread de la
/// visionneuse `viewer`.
fn notify_viewer(viewer: u32) {
    let Some(window) = crate::window::get(viewer) else { return };
    let Some(thread) = crate::gui::thread_info_of(window.pti) else { return };
    let _ = crate::sent::notify(&thread, viewer, WM_DRAWCLIPBOARD, 0, 0);
}

/// NtUserOpenClipboard : le thread courant ouvre le presse-papiers de sa
/// station avec la fenêtre `hwnd` (0 : aucune).
///
/// # Errors
/// L'erreur Win32 : `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre
/// inconnue ; `ERROR_ACCESS_DENIED` s'il est ouvert avec une autre fenêtre ;
/// celles de la station (`ERROR_INVALID_HANDLE` sans elle,
/// `ERROR_ACCESS_DENIED` sans WINSTA_ACCESSCLIPBOARD).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn open(hwnd: u32) -> Result<(), u32> {
    if hwnd != 0 && crate::window::get(hwnd).is_none() {
        return Err(ERROR_INVALID_WINDOW_HANDLE);
    }
    let station = current_station()?;
    let thread = current_thread()?;
    station.with_clipboard(|clipboard| clipboard.open(thread.server, hwnd))
}

/// NtUserCloseClipboard : le thread courant le ferme ; s'il a changé, les
/// formats synthétisés s'ajoutent et la visionneuse reçoit WM_DRAWCLIPBOARD.
///
/// # Errors
/// L'erreur Win32 : `ERROR_CLIPBOARD_NOT_OPEN` ; celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn close() -> Result<(), u32> {
    let station = current_station()?;
    let thread = current_thread()?;
    let locale = thread_locale();
    let viewer = station.with_clipboard(|clipboard| clipboard.close(thread.server, || locale_data(locale)))?;
    if let Some(viewer) = viewer {
        notify_viewer(viewer);
    }
    Ok(())
}

/// NtUserEmptyClipboard : WM_DESTROYCLIPBOARD au propriétaire, puis le
/// presse-papiers se vide et la fenêtre qui l'a ouvert devient son
/// propriétaire.
///
/// # Errors
/// L'erreur Win32 : `ERROR_CLIPBOARD_NOT_OPEN` ; celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn empty() -> Result<(), u32> {
    let station = current_station()?;
    let thread = current_thread()?;
    let owner = station.with_clipboard(|clipboard| clipboard.check_open(thread.server).map(|()| clipboard.owner()))?;
    if owner != 0 {
        send(owner, WM_DESTROYCLIPBOARD, 0, 0);
    }
    let freed = station.with_clipboard(|clipboard| clipboard.empty(thread.server))?;
    for handle in freed {
        destroy_data(handle);
    }
    Ok(())
}

/// NtUserSetClipboardData : `format` reçoit `handle` (0 : un rendu différé),
/// un objet `TYPE_CLIPDATA` si `global`, que le presse-papiers prend
/// (il n'est plus au processus) ; rend `handle`.
///
/// # Errors
/// L'erreur Win32 : `ERROR_INVALID_HANDLE` pour un objet `TYPE_CLIPDATA`
/// qui n'existe pas ; celles de [`Clipboard::set_data`] et de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn set_data(format: u32, handle: u32, global: bool) -> Result<u32, u32> {
    let station = current_station()?;
    let thread = current_thread()?;
    let content = match handle {
        0 => Data::Delayed,
        handle if global && data(handle).is_none() => return Err(ERROR_INVALID_HANDLE),
        handle => Data::Handle { handle, global },
    };
    let freed = station.with_clipboard(|clipboard| clipboard.set_data(thread.server, format, content))?;
    if handle != 0 && global {
        crate::handles::set_process(handle, 0);
    }
    if let Some(freed) = freed {
        destroy_data(freed);
    }
    Ok(handle)
}

/// NtUserGetClipboardData : les données de `format` et leur GETCLIPBDATA ;
/// `None` s'il manque. Un format différé est d'abord demandé au
/// propriétaire (WM_RENDERFORMAT, que le propriétaire traite pendant que le
/// thread courant attend).
///
/// # Errors
/// L'erreur Win32 : `ERROR_CLIPBOARD_NOT_OPEN` ; celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn get_data(format: u32) -> Result<Option<(u32, GetClipbData32)>, u32> {
    let station = current_station()?;
    let thread = current_thread()?;
    let mut lookup = station.with_clipboard(|clipboard| clipboard.lookup(thread.server, format))?;
    if let Lookup::Render { format: source, owner } = lookup {
        station.with_clipboard(|clipboard| clipboard.set_rendering(true));
        send(owner, WM_RENDERFORMAT, source, 0);
        lookup = station.with_clipboard(|clipboard| {
            clipboard.set_rendering(false);
            clipboard.lookup(thread.server, format)
        })?;
    }
    Ok(match lookup {
        Lookup::Found { handle, info } => Some((handle, info)),
        Lookup::Missing | Lookup::Render { .. } => None,
    })
}

/// Ce que `read` lit du presse-papiers de la station du processus courant.
///
/// # Errors
/// Celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn query<R>(read: impl FnOnce(&Clipboard) -> R) -> Result<R, u32> {
    let station = current_station()?;
    Ok(station.with_clipboard(|clipboard| read(clipboard)))
}

/// EnumClipboardFormats (ONEPARAM_ROUTINE_ENUMCLIPBOARDFORMATS) : le format
/// qui suit `after`.
///
/// # Errors
/// L'erreur Win32 : `ERROR_CLIPBOARD_NOT_OPEN` ; celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn enum_formats(after: u32) -> Result<u32, u32> {
    let station = current_station()?;
    let thread = current_thread()?;
    station.with_clipboard(|clipboard| clipboard.enum_next(thread.server, after))
}

/// NtUserSetClipboardViewer : `hwnd` devient la première visionneuse et
/// reçoit WM_DRAWCLIPBOARD ; rend la précédente.
///
/// # Errors
/// L'erreur Win32 : `ERROR_INVALID_WINDOW_HANDLE` ; celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn set_viewer(hwnd: u32) -> Result<u32, u32> {
    let station = current_station()?;
    if crate::window::get(hwnd).is_none() {
        return Err(ERROR_INVALID_WINDOW_HANDLE);
    }
    let previous = station.with_clipboard(|clipboard| clipboard.set_viewer(hwnd));
    notify_viewer(hwnd);
    Ok(previous)
}

/// NtUserChangeClipboardChain : `remove` quitte la chaîne, `next` le suit ;
/// rend ce que la tête de la chaîne répond à WM_CHANGECBCHAIN (FALSE sans
/// visionneuse).
///
/// # Errors
/// L'erreur Win32 : `ERROR_INVALID_WINDOW_HANDLE` si `remove`, ou `next`
/// non nul, n'est pas une fenêtre ; celles de la station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn change_chain(remove: u32, next: u32) -> Result<u32, u32> {
    let station = current_station()?;
    let exists = |hwnd: u32| crate::window::get(hwnd).is_some();
    if !exists(remove) || (next != 0 && !exists(next)) {
        return Err(ERROR_INVALID_WINDOW_HANDLE);
    }
    let head = station.with_clipboard(|clipboard| clipboard.change_chain(remove, next));
    Ok(head.map_or(0, |head| send(head, WM_CHANGECBCHAIN, remove, next)))
}

/// IntSendDestroyMsg (UserClipboardRelease) : `hwnd`, que DestroyWindow
/// détruit dans son thread, reçoit WM_RENDERALLFORMATS s'il est un
/// propriétaire qui a des formats différés, puis ne l'est plus.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread de la fenêtre, sans rien tenir. Rappelle le
/// mode utilisateur.
pub fn release_owner(hwnd: u32) {
    for station in crate::winsta::stations() {
        if station.with_clipboard(|clipboard| clipboard.owns_delayed(hwnd)) {
            send(hwnd, WM_RENDERALLFORMATS, 0, 0);
        }
        let locale = thread_locale();
        if let Some(viewer) = station.with_clipboard(|clipboard| clipboard.release_owner(hwnd, || locale_data(locale)))
        {
            notify_viewer(viewer);
        }
    }
}

/// UserClipboardFreeWindow : `hwnd` est détruit (avec ses messages ou sans,
/// à la fin de son thread) : voir [`Clipboard::forget_window`].
///
/// # IRQL
/// PASSIVE_LEVEL. Aucun rappel du mode utilisateur.
pub fn forget_window(hwnd: u32) {
    for station in crate::winsta::stations() {
        let locale = ex::locale::user_locale();
        if let Some(viewer) = station.with_clipboard(|clipboard| clipboard.forget_window(hwnd, || locale_data(locale)))
        {
            notify_viewer(viewer);
        }
    }
}

/// Le thread GUI `pti` finit : le presse-papiers qu'il a ouvert se ferme
/// ([`Clipboard::thread_exit`]).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread qui finit (rappel de Ps). Aucun rappel du
/// mode utilisateur.
pub fn thread_exit(pti: u32) {
    for station in crate::winsta::stations() {
        let locale = ex::locale::user_locale();
        if let Some(viewer) = station.with_clipboard(|clipboard| clipboard.thread_exit(pti, || locale_data(locale))) {
            notify_viewer(viewer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use abi::user::cf::{CF_DIB, CF_ENHMETAFILE};

    const ME: u32 = 0x100;
    const OTHER: u32 = 0x200;
    const WIN: u32 = 0x1_0020;
    const WIN2: u32 = 0x1_0022;
    /// Les poignées de données des tests (jamais dans la table : leur
    /// destruction ne trouve rien).
    const H1: u32 = 0xF_0040;
    const H2: u32 = 0xF_0042;
    const LOCALE: u32 = 0xF_0044;
    /// CF_WAVE, un format sans synthèse.
    const CF_WAVE: u32 = 12;

    fn global(handle: u32) -> Data {
        Data::Handle { handle, global: true }
    }

    fn no_locale() -> Option<u32> {
        None
    }

    fn opened(thread: u32, window: u32) -> Clipboard {
        let mut clipboard = Clipboard::new();
        clipboard.open(thread, window).unwrap();
        clipboard
    }

    #[test]
    fn it_opens_by_window_and_passes_to_the_thread_that_opens_it() {
        let mut clipboard = opened(ME, 0);
        assert_eq!(clipboard.open(ME, WIN), Err(ERROR_ACCESS_DENIED), "already open without a window");
        assert_eq!(clipboard.open(ME, 0), Ok(()), "again, the same window");
        assert_eq!(clipboard.open(OTHER, WIN), Err(ERROR_ACCESS_DENIED));
        assert_eq!(clipboard.open_window(), 0);
        assert_eq!(clipboard.close(OTHER, no_locale), Err(ERROR_CLIPBOARD_NOT_OPEN));
        assert_eq!(clipboard.close(ME, no_locale), Ok(None));
        assert_eq!(clipboard.close(ME, no_locale), Err(ERROR_CLIPBOARD_NOT_OPEN), "not twice");

        assert_eq!(clipboard.open(ME, WIN), Ok(()));
        assert_eq!(clipboard.open_window(), WIN);
        assert_eq!(clipboard.open(OTHER, WIN), Ok(()), "the same window, from another thread (XP)");
        assert!(clipboard.is_open_by(OTHER) && !clipboard.is_open_by(ME));
        assert_eq!(clipboard.close(ME, no_locale), Err(ERROR_CLIPBOARD_NOT_OPEN));
    }

    #[test]
    fn empty_makes_the_open_window_the_owner_and_frees_the_data() {
        let mut clipboard = opened(ME, WIN);
        assert_eq!(clipboard.empty(OTHER), Err(ERROR_CLIPBOARD_NOT_OPEN));
        assert_eq!(clipboard.empty(ME), Ok(Vec::new()));
        assert_eq!((clipboard.owner(), clipboard.sequence()), (WIN, 1));
        assert_eq!(clipboard.empty(ME), Ok(Vec::new()), "again");
        assert_eq!(clipboard.sequence(), 2, "the sequence grows even when it was empty");
        clipboard.set_data(ME, CF_UNICODETEXT, global(H1)).unwrap();
        clipboard.set_data(ME, 0xC100, global(H1)).unwrap();
        clipboard.set_data(ME, CF_DIB, Data::Handle { handle: 0x99, global: false }).unwrap();
        assert_eq!(clipboard.empty(ME), Ok(alloc::vec![H1]), "one object, once; values are not ours");
        assert_eq!(clipboard.count(), 0);
        clipboard.close(ME, no_locale).unwrap();
        clipboard.open(ME, 0).unwrap();
        clipboard.empty(ME).unwrap();
        assert_eq!(clipboard.owner(), 0, "opened without a window: no owner");
    }

    #[test]
    fn set_data_needs_the_opener_or_an_open_owner_or_a_rendering() {
        let mut clipboard = Clipboard::new();
        assert_eq!(clipboard.set_data(ME, CF_TEXT, global(H1)), Err(ERROR_CLIPBOARD_NOT_OPEN), "closed");
        clipboard.open(ME, WIN).unwrap();
        assert_eq!(clipboard.set_data(ME, 0, global(H1)), Err(ERROR_CLIPBOARD_NOT_OPEN), "no format");
        assert_eq!(clipboard.set_data(OTHER, CF_TEXT, global(H1)), Err(ERROR_CLIPBOARD_NOT_OPEN), "no owner yet");
        assert_eq!(clipboard.set_data(ME, CF_TEXT, global(H1)), Ok(None), "the opener, not the owner");
        clipboard.empty(ME).unwrap();
        assert_eq!(clipboard.set_data(OTHER, CF_WAVE, Data::Delayed), Ok(None), "opened by its owner");
        clipboard.close(ME, no_locale).unwrap();
        clipboard.open(ME, WIN2).unwrap();
        assert_eq!(clipboard.set_data(OTHER, CF_WAVE, global(H2)), Err(ERROR_CLIPBOARD_NOT_OPEN), "not by its owner");
        clipboard.set_rendering(true);
        assert_eq!(clipboard.set_data(OTHER, CF_WAVE, global(H2)), Ok(None), "a rendering");
    }

    #[test]
    fn the_sequence_grows_at_each_change_but_not_for_a_rendering() {
        let mut clipboard = opened(ME, WIN);
        clipboard.empty(ME).unwrap();
        assert_eq!(clipboard.sequence(), 1);
        clipboard.set_data(ME, CF_TEXT, global(H1)).unwrap();
        clipboard.set_data(ME, CF_UNICODETEXT, Data::Delayed).unwrap();
        clipboard.set_data(ME, CF_UNICODETEXT, Data::Delayed).unwrap();
        assert_eq!(clipboard.sequence(), 4, "each SetClipboardData, delayed or not");
        assert!(!clipboard.is_available(CF_OEMTEXT), "synthesized at the close");
        assert_eq!(clipboard.close(ME, || Some(LOCALE)), Ok(None), "no viewer");
        assert_eq!(clipboard.sequence(), 6, "CF_LOCALE and CF_OEMTEXT added");
        let order: Vec<u32> = clipboard.formats().collect();
        assert_eq!(order, [CF_TEXT, CF_UNICODETEXT, CF_LOCALE, CF_OEMTEXT]);

        clipboard.open(ME, WIN).unwrap();
        clipboard.set_rendering(true);
        assert_eq!(clipboard.set_data(OTHER, CF_UNICODETEXT, global(H2)), Ok(None));
        clipboard.set_rendering(false);
        assert_eq!(clipboard.sequence(), 6, "a rendering");
        assert_eq!(clipboard.set_data(ME, CF_OEMTEXT, global(0xF_0050)), Ok(None));
        assert_eq!(clipboard.sequence(), 6, "user32 puts back what it synthesized");
        assert_eq!(clipboard.close(ME, no_locale), Ok(None));
        assert_eq!(clipboard.sequence(), 6, "nothing new to synthesize");
        clipboard.open(ME, WIN).unwrap();
        assert_eq!(clipboard.close(ME, no_locale), Ok(None));
        assert_eq!(clipboard.sequence(), 6, "nothing changed");
    }

    #[test]
    fn the_close_synthesizes_the_text_formats_in_the_order_of_xp() {
        for (set, expected) in [
            (CF_TEXT, [CF_TEXT, CF_LOCALE, CF_OEMTEXT, CF_UNICODETEXT]),
            (CF_OEMTEXT, [CF_OEMTEXT, CF_LOCALE, CF_TEXT, CF_UNICODETEXT]),
            (CF_UNICODETEXT, [CF_UNICODETEXT, CF_LOCALE, CF_TEXT, CF_OEMTEXT]),
        ] {
            let mut clipboard = opened(ME, 0);
            clipboard.empty(ME).unwrap();
            clipboard.set_data(ME, set, global(H1)).unwrap();
            assert_eq!(clipboard.count(), 1, "nothing synthesized while it is open");
            clipboard.close(ME, || Some(LOCALE)).unwrap();
            let order: Vec<u32> = clipboard.formats().collect();
            assert_eq!(order, expected, "from {set}");
            assert_eq!(clipboard.data_of(CF_LOCALE), Some(global(LOCALE)));
        }
        let mut clipboard = opened(ME, 0);
        clipboard.set_data(ME, CF_ENHMETAFILE, Data::Handle { handle: 0x77, global: false }).unwrap();
        let mut asked = false;
        clipboard
            .close(ME, || {
                asked = true;
                None
            })
            .unwrap();
        assert!(!asked && clipboard.count() == 1, "no text, no locale (no metafile synthesis yet)");
    }

    #[test]
    fn a_synthesized_text_format_gives_its_source() {
        let mut clipboard = opened(ME, WIN);
        clipboard.empty(ME).unwrap();
        clipboard.set_data(ME, CF_TEXT, global(H1)).unwrap();
        clipboard.close(ME, || Some(LOCALE)).unwrap();
        assert_eq!(clipboard.lookup(ME, CF_TEXT), Err(ERROR_CLIPBOARD_NOT_OPEN), "closed");
        clipboard.open(ME, WIN).unwrap();
        let found = |handle, fmt_ret, extra| Lookup::Found {
            handle,
            info: GetClipbData32 { fmt_ret, global_handle: 1, locale_or_palette: extra },
        };
        assert_eq!(clipboard.lookup(ME, CF_TEXT), Ok(found(H1, CF_TEXT, LOCALE)), "CF_TEXT gives CF_LOCALE");
        assert_eq!(clipboard.lookup(ME, CF_UNICODETEXT), Ok(found(H1, CF_TEXT, 0)), "from CF_TEXT");
        assert_eq!(clipboard.lookup(ME, CF_OEMTEXT), Ok(found(H1, CF_TEXT, 0)));
        assert_eq!(clipboard.lookup(ME, CF_LOCALE), Ok(found(LOCALE, CF_LOCALE, 0)));
        assert_eq!(clipboard.lookup(ME, CF_DIB), Ok(Lookup::Missing));
        assert_eq!(clipboard.lookup(OTHER, CF_TEXT), Err(ERROR_CLIPBOARD_NOT_OPEN), "not its opener");

        // CF_UNICODETEXT, delayed, comes first: its owner renders it.
        clipboard.set_data(ME, CF_UNICODETEXT, Data::Delayed).unwrap();
        assert_eq!(clipboard.lookup(ME, CF_OEMTEXT), Ok(Lookup::Render { format: CF_UNICODETEXT, owner: WIN }));
        clipboard.set_rendering(true);
        clipboard.set_data(OTHER, CF_UNICODETEXT, global(H2)).unwrap();
        clipboard.set_rendering(false);
        assert_eq!(clipboard.lookup(ME, CF_OEMTEXT), Ok(found(H2, CF_UNICODETEXT, 0)));
    }

    #[test]
    fn a_delayed_format_without_an_owner_is_missing() {
        let mut clipboard = opened(ME, 0);
        clipboard.set_data(ME, CF_WAVE, Data::Delayed).unwrap();
        assert_eq!(clipboard.owner(), 0);
        assert_eq!(clipboard.lookup(ME, CF_WAVE), Ok(Lookup::Missing));
    }

    #[test]
    fn replaced_data_is_freed_once_nothing_holds_it() {
        let mut clipboard = opened(ME, WIN);
        clipboard.set_data(ME, CF_TEXT, global(H1)).unwrap();
        clipboard.set_data(ME, 0xC100, global(H1)).unwrap();
        assert_eq!(clipboard.set_data(ME, CF_TEXT, global(H2)), Ok(None), "the other format holds it");
        assert_eq!(clipboard.set_data(ME, 0xC100, Data::Delayed), Ok(Some(H1)));
        assert_eq!(clipboard.set_data(ME, CF_TEXT, global(H2)), Ok(None), "the same object again");
    }

    #[test]
    fn formats_enumerate_in_order() {
        let mut clipboard = opened(ME, 0);
        assert_eq!(clipboard.enum_next(ME, 0), Ok(0), "empty");
        for format in [CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT] {
            clipboard.set_data(ME, format, Data::Delayed).unwrap();
        }
        assert_eq!(clipboard.enum_next(OTHER, 0), Err(ERROR_CLIPBOARD_NOT_OPEN));
        assert_eq!(clipboard.enum_next(ME, 0), Ok(CF_UNICODETEXT));
        assert_eq!(clipboard.enum_next(ME, CF_UNICODETEXT), Ok(CF_TEXT));
        assert_eq!(clipboard.enum_next(ME, CF_TEXT), Ok(CF_OEMTEXT));
        assert_eq!(clipboard.enum_next(ME, CF_OEMTEXT), Ok(0));
        assert_eq!(clipboard.enum_next(ME, 0xDEAD), Ok(0), "unknown");
        assert_eq!(clipboard.priority(&[CF_DIB, CF_TEXT, CF_UNICODETEXT]), CF_TEXT as i32);
        assert_eq!(clipboard.priority(&[CF_DIB]), -1);
        assert_eq!(Clipboard::new().priority(&[CF_TEXT]), 0, "empty");
    }

    #[test]
    fn the_close_tells_the_viewer_when_it_changed() {
        let mut clipboard = Clipboard::new();
        assert_eq!(clipboard.set_viewer(WIN2), 0);
        clipboard.open(ME, WIN).unwrap();
        assert_eq!(clipboard.close(ME, no_locale), Ok(None), "nothing changed");
        clipboard.open(ME, WIN).unwrap();
        clipboard.set_data(ME, CF_WAVE, Data::Delayed).unwrap();
        assert_eq!(clipboard.close(ME, no_locale), Ok(Some(WIN2)));
        assert_eq!(clipboard.set_viewer(WIN), WIN2, "the next in the chain");
    }

    #[test]
    fn the_chain_changes_at_its_head() {
        let mut clipboard = Clipboard::new();
        assert_eq!(clipboard.change_chain(WIN, WIN2), None, "no viewer");
        clipboard.set_viewer(WIN);
        assert_eq!(clipboard.change_chain(WIN2, 0), Some(WIN), "not the head: the head is told");
        assert_eq!(clipboard.viewer(), WIN);
        assert_eq!(clipboard.change_chain(WIN, WIN2), Some(WIN2), "the head leaves, its next is told");
        assert_eq!(clipboard.change_chain(WIN2, 0), None, "the last leaves");
        assert_eq!(clipboard.viewer(), 0);
    }

    #[test]
    fn a_destroyed_owner_takes_its_delayed_formats_and_tells_the_viewer() {
        let mut clipboard = opened(ME, WIN);
        clipboard.empty(ME).unwrap();
        clipboard.set_data(ME, CF_UNICODETEXT, Data::Delayed).unwrap();
        clipboard.set_data(ME, CF_WAVE, global(H1)).unwrap();
        clipboard.close(ME, || Some(LOCALE)).unwrap();
        clipboard.set_viewer(WIN2);
        assert!(clipboard.owns_delayed(WIN) && !clipboard.owns_delayed(WIN2));
        let sequence = clipboard.sequence();
        assert_eq!(clipboard.release_owner(WIN2, no_locale), None, "not the owner");
        assert_eq!(clipboard.release_owner(WIN, no_locale), Some(WIN2));
        assert_eq!(clipboard.owner(), 0);
        assert_eq!(clipboard.sequence(), sequence + 1);
        let order: Vec<u32> = clipboard.formats().collect();
        assert_eq!(order, [CF_WAVE, CF_LOCALE], "the delayed text and what was synthesized of it are gone");
        assert!(!clipboard.owns_delayed(WIN));
    }

    #[test]
    fn a_destroyed_window_closes_the_clipboard_it_opened_and_leaves_the_chain() {
        let mut clipboard = opened(ME, WIN);
        clipboard.empty(ME).unwrap();
        clipboard.set_data(ME, CF_WAVE, Data::Delayed).unwrap();
        clipboard.set_viewer(WIN);
        assert_eq!(clipboard.forget_window(WIN, no_locale), None, "the viewer was the window itself");
        assert_eq!((clipboard.owner(), clipboard.viewer(), clipboard.open_window()), (0, 0, 0));
        assert!(!clipboard.is_open_by(ME) && !clipboard.is_available(CF_WAVE));

        let mut clipboard = opened(ME, WIN);
        clipboard.set_viewer(WIN2);
        clipboard.set_data(ME, CF_WAVE, global(H1)).unwrap();
        assert_eq!(clipboard.forget_window(WIN, no_locale), Some(WIN2), "closed with a change");

        let mut clipboard = opened(OTHER, WIN2);
        clipboard.owner = WIN;
        clipboard.set_data(OTHER, CF_WAVE, Data::Delayed).unwrap();
        assert_eq!(clipboard.forget_window(WIN, no_locale), None, "still open by another: told at its close");
        assert!(clipboard.is_open_by(OTHER) && !clipboard.is_available(CF_WAVE));
    }

    #[test]
    fn a_thread_that_ends_closes_what_it_opened() {
        let mut clipboard = opened(ME, 0);
        clipboard.set_viewer(WIN2);
        clipboard.empty(ME).unwrap();
        assert_eq!(clipboard.thread_exit(OTHER, no_locale), None, "not its opener");
        assert_eq!(clipboard.thread_exit(ME, no_locale), Some(WIN2));
        assert_eq!(clipboard.open_window(), 0);
        assert!(!clipboard.is_open_by(ME));
        assert_eq!(clipboard.thread_exit(ME, no_locale), None, "once");
    }
}
