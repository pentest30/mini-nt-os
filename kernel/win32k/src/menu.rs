//! Les menus (`menu.c` de win32k, ReactOS épinglé, comme spécification). Un
//! menu est un objet du bureau, au processus qui l'a créé : son `MENU`, le
//! tableau de ses `ITEM` et leurs textes vivent dans le tas du bureau du
//! thread créateur, où `user32` les lit lui-même (GetMenuItemCount,
//! GetSubMenu, GetMenuItemID, GetMenuState, GetMenuString, GetMenuItemInfo,
//! IsMenu ; GetMenu par `WND.IDMenu`) ; l'entrée de la table des handles
//! porte l'adresse du serveur du `MENU`.
//!
//! Le noyau garde sa copie de chaque menu ([`MenuState`], ses [`Item`]) dans
//! une table sous un seul verrou, comme le verrou de USER de ReactOS (la
//! recherche par identifiant descend dans les sous-menus), et la republie
//! après chaque changement ([`Menus::publish_dirty`]) : l'en-tête, le tableau
//! des items (`cAlloced` par 8), le texte de chaque item (NUL final, `Xlpstr`
//! et `lpstr`).
//!
//! Les items (IntSetMenuItemInfo, [`Menus::set_item`]) : type, état,
//! identifiant, sous-menu (marqué MNF_POPUP ; une boucle ou une profondeur
//! au-delà de MAXMENUDEPTH refusée), coches, données, bitmap, texte ; un
//! item sans texte, sans données de texte et sans bitmap devient un
//! séparateur. Par identifiant, la recherche descend dans les sous-menus
//! (MENU_FindItem, [`Menus::find`]). InsertMenuItem, SetMenuItemInfo,
//! RemoveMenu, DeleteMenu (qui détruit le sous-menu), EnableMenuItem,
//! CheckMenuItem, SetMenuDefaultItem, SetMenuInfo, SetMenuContextHelpId,
//! SetMenu ([`attach`]).
//!
//! DestroyMenu détruit le menu et ses sous-menus ([`destroy`]), comme la
//! destruction de la fenêtre dont il est la barre et la fin du processus
//! (`crate::destroy`).
//!
//! Écarts voulus avec ReactOS : un sous-menu détruit quitte les items qui
//! l'ouvraient (ReactOS le garde en vie tant qu'ils le tiennent, et leurs
//! `spSubMenu` resteraient sinon des adresses libérées que `user32` suivrait) ;
//! un menu qui s'ouvrirait lui-même est refusé (ReactOS en crée un vide à sa
//! place) ; InsertMenuItem garde les coches de MIIM_CHECKMARKS (ReactOS les
//! efface après les avoir posées).
//!
//! Pas encore : la place et la taille des items (le dessin de la barre, les
//! menus déroulants), les menus système (GetSystemMenu).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use abi::menu::{
    hbmmenu, item_kind, mf, mfs, mft, miim, mim, mnf, mns, Item32, Menu32, MenuInfo32, MenuItemInfoW32, ProcDeskHead32,
    UnicodeString32, MENUITEMINFO_TYPE_MASK, NO_SELECTED_ITEM,
};
use abi::ntstatus::NtStatus;
use abi::user::TYPE_MENU;
use abi::winerror::{
    dos_error, ERROR_INVALID_MENU_HANDLE, ERROR_INVALID_PARAMETER, ERROR_MENU_ITEM_NOT_FOUND, ERROR_NOT_ENOUGH_MEMORY,
};
use hal::sync::KSpinLock;

use crate::desktop::DesktopHeap;

/// MAXMENUDEPTH : la profondeur la plus grande d'une branche de menus.
const MAX_DEPTH: u32 = 30;
/// MAX_MENU_ITEMS : les items d'un menu au plus.
const MAX_ITEMS: usize = 0x4000;
/// SC_TASKLIST : SetMenuItemInfo le prend pour un item qui existe (Word 95).
const SC_TASKLIST: u32 = 0xF130;
/// La taille d'un `ITEM` dans le tas.
const ITEM_SIZE: u32 = size_of::<Item32>() as u32;
/// La taille d'un `MENU` dans le tas.
const MENU_SIZE: u32 = size_of::<Menu32>() as u32;

/// Où vont les enregistrements d'un menu : le tas d'un bureau (un tas en
/// mémoire dans les tests).
pub trait MenuHeap: Send + Sync {
    /// `size` octets à zéro ; leur position.
    fn alloc(&self, size: u32) -> Result<u32, NtStatus>;
    /// Rend le bloc de `size` octets en `at`.
    fn free(&self, at: u32, size: u32);
    /// Écrit `bytes` en `at`.
    fn write(&self, at: u32, bytes: &[u8]) -> Result<(), NtStatus>;
    /// L'adresse du serveur de la position `at`.
    fn server_address(&self, at: u32) -> u32;
}

impl MenuHeap for DesktopHeap {
    fn alloc(&self, size: u32) -> Result<u32, NtStatus> {
        DesktopHeap::alloc(self, size)
    }

    fn free(&self, at: u32, size: u32) {
        DesktopHeap::free(self, at, size);
    }

    fn write(&self, at: u32, bytes: &[u8]) -> Result<(), NtStatus> {
        self.section.write_kernel(u64::from(at), bytes)
    }

    fn server_address(&self, at: u32) -> u32 {
        DesktopHeap::server_address(self, at)
    }
}

/// Un item d'un menu (`ITEM`), la copie du noyau.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Item {
    /// MFT_* (`fType`).
    pub f_type: u32,
    /// MFS_* (`fState`).
    pub f_state: u32,
    /// Son identifiant (`wID`).
    pub id: u32,
    /// Le handle du menu qu'il ouvre ; 0 sans sous-menu.
    pub submenu: u32,
    /// Ses bitmaps de coche (`hbmpChecked`, `hbmpUnchecked`).
    pub checked: u32,
    pub unchecked: u32,
    /// Son texte, UTF-16 sans le NUL ; vide sans texte.
    pub text: Vec<u16>,
    /// `dwItemData`.
    pub data: u32,
    /// Son bitmap (`hbmp`), un handle ou un HBMMENU_*.
    pub bitmap: u32,
    /// Sa place et sa taille dans le menu (`xItem`, `yItem`, `cxItem`,
    /// `cyItem`).
    pub x: u32,
    pub y: u32,
    pub cx: u32,
    pub cy: u32,
    /// Son texte dans le tas : sa position et sa taille en octets ; (0, 0)
    /// tant qu'il n'est pas publié.
    text_at: (u32, u32),
}

/// Un menu (`MENU`), la copie du noyau.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MenuState {
    /// MNS_* | MNF_* (`fFlags`).
    pub flags: u32,
    /// La position de l'item sélectionné (`iItem`), NO_SELECTED_ITEM sans.
    pub focused: u32,
    /// Sa taille (`cxMenu`, `cyMenu`) ; 0 de haut : à recalculer.
    pub width: u32,
    pub height: u32,
    pub help_id: u32,
    pub max_height: u32,
    pub data: u32,
    pub brush: u32,
    /// La fenêtre dont il est la barre (`hWnd`) ; 0 sans.
    pub hwnd: u32,
    pub items: Vec<Item>,
}

/// UpdateMenuItemState : les bits d'état que `change` donne (grisé,
/// désactivé, coché, surligné, par défaut, choisi à la souris) ; les autres
/// restent.
fn update_state(state: u32, change: u32) -> u32 {
    const BITS: u32 = mf::GRAYED | mf::DISABLED | mfs::CHECKED | mfs::HILITE | mfs::DEFAULT | mf::MOUSESELECT;
    (state & !BITS) | (change & BITS)
}

/// Le texte de `item` quitte le tas (à la prochaine publication) et l'item.
fn drop_text(item: &mut Item, freed: &mut Vec<(u32, u32)>) {
    if item.text_at.1 != 0 {
        freed.push(item.text_at);
    }
    item.text_at = (0, 0);
    item.text.clear();
}

/// Un menu de la table : sa copie, son tas, où il y est.
struct Entry {
    state: MenuState,
    heap: Arc<dyn MenuHeap>,
    /// La position de son `MENU`.
    at: u32,
    /// Le `PROCESSINFO` de son processus (`hTaskWow`).
    owner: u32,
    /// La position de son tableau d'items et le nombre d'items qu'il tient
    /// (`cAlloced`) ; (0, 0) sans tableau.
    items_at: u32,
    capacity: u32,
    /// Les blocs à rendre au tas après la prochaine publication.
    freed: Vec<(u32, u32)>,
    /// Changé depuis sa dernière publication.
    dirty: bool,
}

/// La table des menus, par handle.
pub struct Menus {
    map: BTreeMap<u32, Entry>,
}

impl Default for Menus {
    fn default() -> Self {
        Self::new()
    }
}

impl Menus {
    /// Une table vide.
    pub const fn new() -> Self {
        Self { map: BTreeMap::new() }
    }

    /// IntCreateMenu : le menu `handle`, vide, dont le `MENU` est en `at`
    /// dans `heap`, au processus `owner` ; un menu déroulant (MNF_POPUP)
    /// pour CreatePopupMenu.
    pub fn add(&mut self, handle: u32, heap: Arc<dyn MenuHeap>, at: u32, owner: u32, popup: bool) {
        let state =
            MenuState { flags: if popup { mnf::POPUP } else { 0 }, focused: NO_SELECTED_ITEM, ..MenuState::default() };
        let entry = Entry { state, heap, at, owner, items_at: 0, capacity: 0, freed: Vec::new(), dirty: true };
        self.map.insert(handle, entry);
    }

    /// Le menu `handle` existe.
    pub fn contains(&self, handle: u32) -> bool {
        self.map.contains_key(&handle)
    }

    /// La copie du menu `handle`.
    pub fn state(&self, handle: u32) -> Option<&MenuState> {
        self.map.get(&handle).map(|entry| &entry.state)
    }

    /// Le menu `handle`, à changer : il sera republié.
    fn state_mut(&mut self, handle: u32) -> Option<&mut MenuState> {
        let entry = self.map.get_mut(&handle)?;
        entry.dirty = true;
        Some(&mut entry.state)
    }

    /// L'adresse du serveur du `MENU` de `handle` ; 0 sans lui.
    fn server_address(&self, handle: u32) -> u32 {
        self.map.get(&handle).map_or(0, |entry| entry.heap.server_address(entry.at))
    }

    /// MENU_FindItem : l'item `at` du menu `handle`, par position, ou par
    /// identifiant — dans ses sous-menus d'abord, sinon le dernier item à
    /// sous-menu qui le porte ; rend le menu où il est et sa position.
    pub fn find(&self, handle: u32, at: u32, by_position: bool) -> Option<(u32, usize)> {
        let items = &self.map.get(&handle)?.state.items;
        if by_position {
            return ((at as usize) < items.len()).then_some((handle, at as usize));
        }
        let mut fallback = None;
        for (index, item) in items.iter().enumerate() {
            if item.submenu != 0 {
                if let Some(found) = self.find(item.submenu, at, false) {
                    return Some(found);
                }
                if item.id == at {
                    fallback = Some((handle, index));
                }
            } else if item.id == at {
                return Some((handle, index));
            }
        }
        fallback
    }

    /// MENU_depth : la profondeur de la branche la plus longue sous
    /// `handle`, `depth` au-dessus ; s'arrête passé [`MAX_DEPTH`] (une
    /// boucle n'en finit pas autrement).
    fn depth(&self, handle: u32, depth: u32) -> u32 {
        let Some(entry) = self.map.get(&handle) else { return depth };
        let depth = depth + 1;
        if depth > MAX_DEPTH {
            return depth;
        }
        let mut deepest = depth;
        for item in &entry.state.items {
            if deepest > MAX_DEPTH {
                break;
            }
            if item.submenu != 0 {
                deepest = deepest.max(self.depth(item.submenu, depth));
            }
        }
        deepest
    }

    /// IntInsertMenuItem et MENU_InsertItem : un item neuf, rempli par
    /// `info` et `text` ([`Self::set_item`]), au bout du menu (par position
    /// au-delà du dernier : AppendMenu), à sa position, ou avant l'item qui
    /// porte l'identifiant `at` (dans le sous-menu où il est) ; les boutons
    /// MDI d'une barre restent à droite.
    ///
    /// # Errors
    /// `ERROR_INVALID_MENU_HANDLE` ; `ERROR_NOT_ENOUGH_MEMORY` passé
    /// MAX_MENU_ITEMS ; celles de l'item.
    pub fn insert(
        &mut self,
        handle: u32,
        at: u32,
        by_position: bool,
        info: &MenuItemInfoW32,
        text: Option<&[u16]>,
    ) -> Result<(), u32> {
        let count = self.state(handle).ok_or(ERROR_INVALID_MENU_HANDLE)?.items.len();
        if count >= MAX_ITEMS {
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
        let (menu, mut position) = if by_position {
            (handle, (at as usize).min(count))
        } else {
            self.find(handle, at, false).unwrap_or((handle, count))
        };
        let state = self.state_mut(menu).ok_or(ERROR_INVALID_MENU_HANDLE)?;
        while position > 0 && (hbmmenu::SYSTEM..=hbmmenu::MBAR_CLOSE_D).contains(&state.items[position - 1].bitmap) {
            position -= 1;
        }
        state.items.insert(position, Item::default());
        state.height = 0;
        if let Err(error) = self.set_item_info(menu, position, info, text) {
            if let Some(state) = self.state_mut(menu) {
                state.items.remove(position);
            }
            return Err(error);
        }
        Ok(())
    }

    /// UserMenuItemInfo (l'écriture) : l'item `at` du menu `handle` reçoit
    /// `info` et `text` ([`Self::set_item_info`]).
    ///
    /// # Errors
    /// `ERROR_INVALID_MENU_HANDLE` ; `ERROR_MENU_ITEM_NOT_FOUND` sans l'item
    /// (SC_TASKLIST par identifiant passe pour lui) ; celles de l'item.
    pub fn set_item(
        &mut self,
        handle: u32,
        at: u32,
        by_position: bool,
        info: &MenuItemInfoW32,
        text: Option<&[u16]>,
    ) -> Result<(), u32> {
        if !self.contains(handle) {
            return Err(ERROR_INVALID_MENU_HANDLE);
        }
        let Some((menu, index)) = self.find(handle, at, by_position) else {
            if !by_position && at == SC_TASKLIST {
                return Ok(());
            }
            return Err(ERROR_MENU_ITEM_NOT_FOUND);
        };
        self.set_item_info(menu, index, info, text)
    }

    /// IntSetMenuItemInfo : les champs de l'item `index` du menu `menu` que
    /// `info.fMask` donne ; le texte vient de `text` (la légende capturée,
    /// `cch` caractères au plus).
    ///
    /// # Errors
    /// `ERROR_INVALID_PARAMETER` pour un sous-menu qui n'existe pas, qui est
    /// le menu lui-même ou qui ferait une branche trop profonde (une
    /// boucle).
    fn set_item_info(
        &mut self,
        menu: u32,
        index: usize,
        info: &MenuItemInfoW32,
        text: Option<&[u16]>,
    ) -> Result<(), u32> {
        let mask = info.f_mask;
        let submenu = if mask & miim::SUBMENU != 0 && info.h_sub_menu != 0 {
            let sub = info.h_sub_menu;
            if !self.contains(sub) || sub == menu || self.depth(sub, 0) > MAX_DEPTH || self.find_menu(sub, menu) {
                return Err(ERROR_INVALID_PARAMETER);
            }
            if let Some(state) = self.state_mut(sub) {
                state.flags |= mnf::POPUP;
            }
            Some(sub)
        } else {
            (mask & miim::SUBMENU != 0).then_some(0)
        };
        let entry = self.map.get_mut(&menu).ok_or(ERROR_INVALID_MENU_HANDLE)?;
        entry.dirty = true;
        let system = entry.state.flags & mnf::SYSMENU != 0;
        if mask & miim::STATE != 0 && info.f_state & mfs::DEFAULT != 0 {
            for item in &mut entry.state.items {
                item.f_state &= !mfs::DEFAULT;
            }
        }
        let item = entry.state.items.get_mut(index).ok_or(ERROR_MENU_ITEM_NOT_FOUND)?;
        if mask & miim::FTYPE != 0 {
            item.f_type = (item.f_type & !MENUITEMINFO_TYPE_MASK) | (info.f_type & MENUITEMINFO_TYPE_MASK);
        }
        if mask & miim::TYPE != 0 {
            if item.f_type != info.f_type && item_kind(item.f_type) == mft::STRING {
                drop_text(item, &mut entry.freed);
            }
            if info.f_type & mft::BITMAP != 0 {
                item.bitmap = if info.hbmp_item != 0 { info.hbmp_item } else { info.dw_type_data & 0xFFFF };
            }
        }
        if mask & miim::BITMAP != 0 {
            item.bitmap = info.hbmp_item;
            if abi::menu::is_magic_bitmap(item.bitmap) {
                item.f_state |= mfs::HBMMENUBMP;
            } else {
                item.f_state &= !mfs::HBMMENUBMP;
            }
        }
        if mask & miim::CHECKMARKS != 0 {
            item.checked = info.hbmp_checked;
            item.unchecked = info.hbmp_unchecked;
        }
        if mask & miim::DATA != 0 {
            item.data = info.dw_item_data;
        }
        if mask & miim::ID != 0 {
            item.id = info.w_id;
        }
        if mask & miim::STATE != 0 {
            item.f_state = update_state(item.f_state, info.f_state);
        }
        if let Some(submenu) = submenu {
            item.submenu = submenu;
        }
        if mask & miim::STRING != 0 || (mask & miim::TYPE != 0 && item_kind(info.f_type) == mft::STRING) {
            drop_text(item, &mut entry.freed);
            if let Some(text) = text.filter(|_| info.dw_type_data != 0 && info.cch != 0) {
                let length = (info.cch as usize).min(text.len());
                item.text.extend_from_slice(&text[..length]);
            }
        }
        if !system
            && item.text.is_empty()
            && info.dw_type_data == 0
            && item.f_type & mft::OWNERDRAW == 0
            && item.bitmap == 0
        {
            item.f_type |= mft::SEPARATOR;
        }
        Ok(())
    }

    /// `menu` est-il sous `handle`, ou `handle` lui-même ?
    fn find_menu(&self, handle: u32, menu: u32) -> bool {
        handle == menu
            || self.map.get(&handle).is_some_and(|entry| {
                entry.state.items.iter().any(|item| item.submenu != 0 && self.find_menu(item.submenu, menu))
            })
    }

    /// IntRemoveMenuItem : l'item `at` (par position si `flags` porte
    /// MF_BYPOSITION, sinon par identifiant) quitte son menu ; son sous-menu
    /// est détruit avec lui si `recurse` (DeleteMenu), il vit sinon
    /// (RemoveMenu). Rend les handles des menus détruits ; `None` sans
    /// l'item.
    pub fn remove(&mut self, handle: u32, at: u32, flags: u32, recurse: bool) -> Option<Vec<u32>> {
        let (menu, index) = self.find(handle, at, flags & mf::BYPOSITION != 0)?;
        let entry = self.map.get_mut(&menu)?;
        entry.dirty = true;
        let mut item = entry.state.items.remove(index);
        drop_text(&mut item, &mut entry.freed);
        entry.state.height = 0;
        Some(if recurse && item.submenu != 0 { self.destroy(item.submenu) } else { Vec::new() })
    }

    /// IntEnableMenuItem : l'item `id` (selon `flags`, MF_BYPOSITION) prend
    /// l'état grisé et désactivé de `flags` ; rend celui d'avant (MF_GRAYED,
    /// MF_DISABLED), `None` sans l'item.
    pub fn enable(&mut self, handle: u32, id: u32, flags: u32) -> Option<u32> {
        let (menu, index) = self.find(handle, id, flags & mf::BYPOSITION != 0)?;
        let item = self.state_mut(menu)?.items.get_mut(index)?;
        let before = item.f_state & (mf::GRAYED | mf::DISABLED);
        item.f_state ^= (before ^ flags) & (mf::GRAYED | mf::DISABLED);
        Some(before)
    }

    /// IntCheckMenuItem : l'item `id` (selon `flags`) est coché si `flags`
    /// porte MF_CHECKED ; rend son état d'avant (MF_CHECKED ou 0), `None`
    /// sans l'item.
    pub fn check(&mut self, handle: u32, id: u32, flags: u32) -> Option<u32> {
        let (menu, index) = self.find(handle, id, flags & mf::BYPOSITION != 0)?;
        let item = self.state_mut(menu)?.items.get_mut(index)?;
        let before = item.f_state & mf::CHECKED;
        item.f_state ^= (before ^ flags) & mf::CHECKED;
        Some(before)
    }

    /// UserSetMenuDefaultItem : plus aucun item par défaut, puis l'item
    /// `item` (sa position, ou son identifiant dans ce menu seul) le
    /// devient ; -1 n'en laisse aucun. Faux sans items ou sans lui.
    pub fn set_default(&mut self, handle: u32, item: u32, by_position: bool) -> bool {
        let Some(state) = self.state_mut(handle) else { return false };
        if state.items.is_empty() {
            return false;
        }
        for each in &mut state.items {
            each.f_state &= !mfs::DEFAULT;
        }
        if item == u32::MAX {
            return true;
        }
        let found = if by_position {
            state.items.get_mut(item as usize)
        } else {
            state.items.iter_mut().find(|each| each.id == item)
        };
        found.map(|each| each.f_state |= mfs::DEFAULT).is_some()
    }

    /// IntSetMenuInfo : le fond, l'aide, la hauteur, les données et le
    /// style que `info.fMask` donne, aussi aux sous-menus avec
    /// MIM_APPLYTOSUBMENUS. Faux sans le menu.
    pub fn set_info(&mut self, handle: u32, info: &MenuInfo32) -> bool {
        let Some(state) = self.state_mut(handle) else { return false };
        let mask = info.f_mask;
        if mask & mim::BACKGROUND != 0 {
            state.brush = info.hbr_back;
        }
        if mask & mim::HELPID != 0 {
            state.help_id = info.dw_context_help_id;
        }
        if mask & mim::MAXHEIGHT != 0 {
            state.max_height = info.cy_max;
        }
        if mask & mim::MENUDATA != 0 {
            state.data = info.dw_menu_data;
        }
        if mask & mim::STYLE != 0 {
            state.flags ^= (state.flags ^ info.dw_style) & mns::STYLE_MASK;
        }
        if mask & mim::APPLYTOSUBMENUS != 0 {
            let submenus: Vec<u32> = state.items.iter().map(|item| item.submenu).filter(|&sub| sub != 0).collect();
            for submenu in submenus {
                self.set_info(submenu, info);
            }
        }
        true
    }

    /// IntSetMenuContextHelpId. Faux sans le menu.
    pub fn set_help_id(&mut self, handle: u32, help_id: u32) -> bool {
        self.state_mut(handle).map(|state| state.help_id = help_id).is_some()
    }

    /// IntSetMenuFlagRtoL : le menu se lit de droite à gauche. Faux sans lui.
    pub fn set_rtol(&mut self, handle: u32) -> bool {
        self.state_mut(handle).map(|state| state.flags |= mnf::RTOL).is_some()
    }

    /// IntSetMenu, pour les menus : `menu` (s'il n'est pas 0) devient la
    /// barre de `hwnd`, `old` (s'il n'est pas 0) ne l'est plus.
    ///
    /// # Errors
    /// `ERROR_INVALID_MENU_HANDLE` pour un menu qui n'existe pas ou qui est
    /// déjà la barre d'une autre fenêtre.
    pub fn attach(&mut self, menu: u32, old: u32, hwnd: u32) -> Result<(), u32> {
        if menu != 0 {
            let state = self.state(menu).ok_or(ERROR_INVALID_MENU_HANDLE)?;
            if state.hwnd != 0 && state.hwnd != hwnd {
                return Err(ERROR_INVALID_MENU_HANDLE);
            }
        }
        if old != 0 && old != menu {
            if let Some(state) = self.state_mut(old) {
                state.hwnd = 0;
            }
        }
        if let Some(state) = self.state_mut(menu) {
            state.hwnd = hwnd;
        }
        Ok(())
    }

    /// IntDestroyMenuObject(…, TRUE) : le menu `handle` et ses sous-menus
    /// quittent la table et leur tas ; les items d'autres menus qui les
    /// ouvraient n'ont plus de sous-menu. Rend leurs handles (vide sans le
    /// menu).
    pub fn destroy(&mut self, handle: u32) -> Vec<u32> {
        let Some(mut entry) = self.map.remove(&handle) else { return Vec::new() };
        let mut gone = alloc::vec![handle];
        let heap = entry.heap.clone();
        for item in &mut entry.state.items {
            drop_text(item, &mut entry.freed);
        }
        if entry.capacity != 0 {
            heap.free(entry.items_at, entry.capacity * ITEM_SIZE);
        }
        heap.free(entry.at, MENU_SIZE);
        for (at, size) in entry.freed.drain(..) {
            heap.free(at, size);
        }
        for item in &entry.state.items {
            if item.submenu != 0 {
                gone.extend(self.destroy(item.submenu));
            }
        }
        for other in self.map.values_mut() {
            for item in other.state.items.iter_mut().filter(|item| gone.contains(&item.submenu)) {
                item.submenu = 0;
                other.dirty = true;
            }
        }
        gone
    }

    /// Republie les menus changés ([`Self::publish`]).
    ///
    /// # Errors
    /// La première erreur d'un tas (plein) ; les autres menus sont publiés.
    pub fn publish_dirty(&mut self) -> Result<(), NtStatus> {
        let dirty: Vec<u32> = self.map.iter().filter(|(_, entry)| entry.dirty).map(|(&handle, _)| handle).collect();
        let mut result = Ok(());
        for handle in dirty {
            if let Err(status) = self.publish(handle) {
                result = result.and(Err(status));
            }
        }
        result
    }

    /// Écrit le menu `handle` dans son tas : le texte des items qui n'y est
    /// pas encore, le tableau des items (agrandi par 8 au besoin, rendu
    /// vide), puis le `MENU` ; enfin les blocs qui ne servent plus sont
    /// rendus.
    fn publish(&mut self, handle: u32) -> Result<(), NtStatus> {
        let submenus: Vec<u32> = match self.map.get(&handle) {
            Some(entry) => entry.state.items.iter().map(|item| self.server_address(item.submenu)).collect(),
            None => return Ok(()),
        };
        let Some(entry) = self.map.get_mut(&handle) else { return Ok(()) };
        let heap = entry.heap.clone();
        for item in &mut entry.state.items {
            if !item.text.is_empty() && item.text_at.1 == 0 {
                let units = item.text.len() as u32 + 1;
                let at = heap.alloc(units * 2)?;
                let bytes: Vec<u8> =
                    item.text.iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect();
                if let Err(status) = heap.write(at, &bytes) {
                    heap.free(at, units * 2);
                    return Err(status);
                }
                item.text_at = (at, units * 2);
            }
        }
        let count = entry.state.items.len() as u32;
        let mut old = None;
        if count == 0 && entry.capacity != 0 {
            old = Some((entry.items_at, entry.capacity));
            (entry.items_at, entry.capacity) = (0, 0);
        } else if count > entry.capacity {
            let capacity = count.next_multiple_of(8);
            let at = heap.alloc(capacity * ITEM_SIZE)?;
            if entry.capacity != 0 {
                old = Some((entry.items_at, entry.capacity));
            }
            (entry.items_at, entry.capacity) = (at, capacity);
        }
        if count != 0 {
            let mut bytes = Vec::with_capacity((count * ITEM_SIZE) as usize);
            for (item, &submenu) in entry.state.items.iter().zip(&submenus) {
                bytes.extend_from_slice(item_record(item, submenu, &*heap).as_bytes());
            }
            heap.write(entry.items_at, &bytes)?;
        }
        heap.write(entry.at, menu_record(handle, entry).as_bytes())?;
        if let Some((at, capacity)) = old {
            heap.free(at, capacity * ITEM_SIZE);
        }
        for (at, size) in entry.freed.drain(..) {
            heap.free(at, size);
        }
        entry.dirty = false;
        Ok(())
    }
}

/// L'`ITEM` de `item`, dont le sous-menu est à l'adresse du serveur
/// `submenu` (0 sans).
fn item_record(item: &Item, submenu: u32, heap: &dyn MenuHeap) -> Item32 {
    let text = if item.text_at.1 == 0 { 0 } else { heap.server_address(item.text_at.0) };
    let length = item.text.len() as u32;
    Item32 {
        f_type: item.f_type,
        f_state: item.f_state,
        w_id: item.id,
        sp_sub_menu: submenu,
        hbmp_checked: item.checked,
        hbmp_unchecked: item.unchecked,
        xlpstr: text,
        cch: if text == 0 { 0 } else { length },
        dw_item_data: item.data,
        x_item: item.x,
        y_item: item.y,
        cx_item: item.cx,
        cy_item: item.cy,
        hbmp: item.bitmap,
        lpstr: if text == 0 {
            UnicodeString32::default()
        } else {
            UnicodeString32 { length: (length * 2) as u16, maximum_length: (length * 2 + 2) as u16, buffer: text }
        },
        ..Item32::default()
    }
}

/// Le `MENU` du menu `handle`.
fn menu_record(handle: u32, entry: &Entry) -> Menu32 {
    let heap = &entry.heap;
    let state = &entry.state;
    Menu32 {
        head: ProcDeskHead32 {
            h: handle,
            c_lock_obj: 0,
            h_task_wow: entry.owner,
            rpdesk: heap.server_address(0),
            p_self: heap.server_address(entry.at),
        },
        f_flags: state.flags,
        i_item: state.focused,
        c_alloced: entry.capacity,
        c_items: state.items.len() as u32,
        cx_menu: state.width,
        cy_menu: state.height,
        rg_items: if entry.capacity == 0 { 0 } else { heap.server_address(entry.items_at) },
        dw_context_help_id: state.help_id,
        cy_max: state.max_height,
        dw_menu_data: state.data,
        hbr_back: state.brush,
        hwnd: state.hwnd,
        ..Menu32::default()
    }
}

/// La table des menus du système.
static MENUS: KSpinLock<Menus> = KSpinLock::new(Menus::new());

/// Change la table par `change`, puis republie les menus changés.
///
/// # Errors
/// Celles de `change` ; `ERROR_NOT_ENOUGH_MEMORY` si un tas est plein.
fn with<R>(change: impl FnOnce(&mut Menus) -> Result<R, u32>) -> Result<R, u32> {
    let mut menus = MENUS.lock();
    let result = change(&mut menus);
    let published = menus.publish_dirty();
    drop(menus);
    let value = result?;
    published.map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    Ok(value)
}

/// UserCreateMenu : un menu neuf (une barre, ou un menu déroulant avec
/// `popup`) dans le tas du bureau du thread courant, au processus courant ;
/// rend son handle.
///
/// # Errors
/// `ERROR_NOT_ENOUGH_MEMORY` pour un thread sans bureau, un tas ou une
/// table des handles pleins.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn create(popup: bool) -> Result<u32, u32> {
    let thread = crate::gui::convert_current_thread().map_err(dos_error)?;
    let desktop = thread.desktop().ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
    let heap = desktop.desktop.heap.clone();
    let owner = ps::ethread::current_thread()
        .and_then(|thread| crate::existing_process_info(thread.process()))
        .map_or(0, |info| info.server);
    let at = heap.alloc(MENU_SIZE).map_err(dos_error)?;
    let handle = match crate::handles::alloc(heap.server_address(at), owner, TYPE_MENU) {
        Ok(handle) => handle,
        Err(status) => {
            heap.free(at, MENU_SIZE);
            return Err(dos_error(status));
        }
    };
    let result = with(|menus| {
        menus.add(handle, heap.clone(), at, owner, popup);
        Ok(handle)
    });
    if result.is_err() {
        destroy(handle);
    }
    result
}

/// Le menu `handle` existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn exists(handle: u32) -> bool {
    MENUS.lock().contains(handle)
}

/// Les items du menu `handle`, une copie (pour dessiner la barre) ; vide
/// sans lui.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn items(handle: u32) -> Vec<Item> {
    MENUS.lock().state(handle).map_or_else(Vec::new, |state| state.items.clone())
}

/// NtUserThunkedMenuItemInfo avec `bInsert` : [`Menus::insert`].
///
/// # Errors
/// Celles de [`Menus::insert`] et de la publication.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn insert_item(
    handle: u32,
    at: u32,
    by_position: bool,
    info: &MenuItemInfoW32,
    text: Option<&[u16]>,
) -> Result<(), u32> {
    with(|menus| menus.insert(handle, at, by_position, info, text))
}

/// NtUserThunkedMenuItemInfo sans `bInsert` : [`Menus::set_item`].
///
/// # Errors
/// Celles de [`Menus::set_item`] et de la publication.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_item_info(
    handle: u32,
    at: u32,
    by_position: bool,
    info: &MenuItemInfoW32,
    text: Option<&[u16]>,
) -> Result<(), u32> {
    with(|menus| menus.set_item(handle, at, by_position, info, text))
}

/// RemoveMenu (`recurse` faux) et DeleteMenu (vrai) : [`Menus::remove`] ;
/// faux sans le menu ou l'item. Les handles des sous-menus détruits sont
/// rendus.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn remove(handle: u32, at: u32, flags: u32, recurse: bool) -> bool {
    let gone = with(|menus| menus.remove(handle, at, flags, recurse).ok_or(ERROR_MENU_ITEM_NOT_FOUND));
    gone.map(|gone| free_handles(&gone)).is_ok()
}

/// EnableMenuItem : [`Menus::enable`] ; -1 sans le menu ou l'item.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn enable(handle: u32, id: u32, flags: u32) -> u32 {
    with(|menus| menus.enable(handle, id, flags).ok_or(ERROR_MENU_ITEM_NOT_FOUND)).unwrap_or(u32::MAX)
}

/// CheckMenuItem : [`Menus::check`] ; -1 sans le menu ou l'item.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn check(handle: u32, id: u32, flags: u32) -> u32 {
    with(|menus| menus.check(handle, id, flags).ok_or(ERROR_MENU_ITEM_NOT_FOUND)).unwrap_or(u32::MAX)
}

/// SetMenuDefaultItem : [`Menus::set_default`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_default(handle: u32, item: u32, by_position: bool) -> bool {
    with(|menus| Ok(menus.set_default(handle, item, by_position))).unwrap_or(false)
}

/// SetMenuInfo : [`Menus::set_info`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_info(handle: u32, info: &MenuInfo32) -> bool {
    with(|menus| Ok(menus.set_info(handle, info))).unwrap_or(false)
}

/// SetMenuContextHelpId : [`Menus::set_help_id`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_help_id(handle: u32, help_id: u32) -> bool {
    with(|menus| Ok(menus.set_help_id(handle, help_id))).unwrap_or(false)
}

/// SetMenuFlagRtoL : [`Menus::set_rtol`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_rtol(handle: u32) -> bool {
    with(|menus| Ok(menus.set_rtol(handle))).unwrap_or(false)
}

/// IntSetMenu : `menu` devient la barre de la fenêtre `hwnd`, à la place de
/// `old` ([`Menus::attach`]).
///
/// # Errors
/// Celles de [`Menus::attach`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn attach(menu: u32, old: u32, hwnd: u32) -> Result<(), u32> {
    with(|menus| menus.attach(menu, old, hwnd))
}

/// Rend les handles des menus `gone`.
fn free_handles(gone: &[u32]) {
    for &handle in gone {
        let _ = crate::handles::free(handle);
    }
}

/// IntDestroyMenuObject(…, TRUE) : le menu et ses sous-menus détruits
/// ([`Menus::destroy`]), leurs handles rendus ; faux sans lui. La barre
/// d'une fenêtre qui le désignait n'a plus d'items (comme XP, la fenêtre
/// garde le handle).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy(handle: u32) -> bool {
    let gone = with(|menus| Ok(menus.destroy(handle))).unwrap_or_default();
    free_handles(&gone);
    !gone.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un tas en mémoire : des blocs les uns après les autres, à partir de
    /// 8 ; ce qui est rendu est noté.
    struct Heap {
        bytes: KSpinLock<Vec<u8>>,
        next: KSpinLock<u32>,
        freed: KSpinLock<Vec<(u32, u32)>>,
    }

    const BASE: u32 = 0xBC40_0000;

    impl Heap {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                bytes: KSpinLock::new(alloc::vec![0; 0x10000]),
                next: KSpinLock::new(8),
                freed: KSpinLock::new(Vec::new()),
            })
        }

        fn word(&self, server: u32) -> u32 {
            let at = (server - BASE) as usize;
            let bytes = self.bytes.lock();
            u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
        }

        /// Le texte NUL final à l'adresse du serveur `server`.
        fn text(&self, server: u32) -> Vec<u16> {
            let bytes = self.bytes.lock();
            let mut at = (server - BASE) as usize;
            let mut units = Vec::new();
            loop {
                let unit = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
                if unit == 0 {
                    return units;
                }
                units.push(unit);
                at += 2;
            }
        }
    }

    impl MenuHeap for Heap {
        fn alloc(&self, size: u32) -> Result<u32, NtStatus> {
            let mut next = self.next.lock();
            let at = *next;
            *next += size.next_multiple_of(8);
            Ok(at)
        }

        fn free(&self, at: u32, size: u32) {
            self.freed.lock().push((at, size));
        }

        fn write(&self, at: u32, bytes: &[u8]) -> Result<(), NtStatus> {
            self.bytes.lock()[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }

        fn server_address(&self, at: u32) -> u32 {
            BASE + at
        }
    }

    fn table() -> (Menus, Arc<Heap>) {
        (Menus::new(), Heap::new())
    }

    /// Le menu `handle` dans `heap`, son `MENU` en `at`.
    fn add(menus: &mut Menus, heap: &Arc<Heap>, handle: u32, popup: bool) -> u32 {
        let at = heap.alloc(MENU_SIZE).unwrap();
        menus.add(handle, heap.clone(), at, 0x7000, popup);
        at
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Ce que MENU_mnu2mnuii et AppendMenuW donnent pour MF_STRING.
    fn string_item(id: u32, text: &[u16]) -> MenuItemInfoW32 {
        MenuItemInfoW32 {
            cb_size: 48,
            f_mask: miim::STATE | miim::ID | miim::FTYPE | miim::STRING | miim::BITMAP,
            w_id: id,
            dw_type_data: 0x0040_1000,
            cch: text.len() as u32,
            ..MenuItemInfoW32::default()
        }
    }

    /// AppendMenuW(menu, MF_POPUP, submenu, text).
    fn popup_item(submenu: u32, text: &[u16]) -> MenuItemInfoW32 {
        MenuItemInfoW32 {
            f_mask: string_item(0, text).f_mask | miim::SUBMENU,
            h_sub_menu: submenu,
            w_id: submenu,
            ..string_item(0, text)
        }
    }

    fn append(menus: &mut Menus, menu: u32, info: &MenuItemInfoW32, text: &[u16]) {
        menus.insert(menu, u32::MAX, true, info, Some(text)).unwrap();
    }

    #[test]
    fn user32_reads_a_menu_its_items_and_their_text_in_the_heap() {
        let (mut menus, heap) = table();
        let bar = add(&mut menus, &heap, 0x10, false);
        let popup = add(&mut menus, &heap, 0x20, true);
        let (file, item) = (wide("&File"), wide("Open"));
        append(&mut menus, 0x20, &string_item(100, &item), &item);
        append(&mut menus, 0x10, &popup_item(0x20, &file), &file);
        menus.publish_dirty().unwrap();

        let menu = BASE + bar;
        assert_eq!(heap.word(menu), 0x10, "head.h");
        assert_eq!(heap.word(menu + 16), menu, "pSelf");
        assert_eq!(heap.word(menu + 20), 0, "a bar: no MNF_POPUP");
        assert_eq!(heap.word(menu + 28), 8, "cAlloced");
        assert_eq!(heap.word(menu + 32), 1, "cItems");
        let items = heap.word(menu + 52);
        assert_ne!(items, 0, "rgItems");
        assert_eq!(heap.word(items + 8), 0x20, "wID of a popup item: its handle");
        assert_eq!(heap.word(items + 12), BASE + popup, "spSubMenu: the submenu's MENU");
        assert_eq!(heap.text(heap.word(items + 24)), file, "Xlpstr");
        assert_eq!(heap.word(items + 28), 5, "cch");
        assert_eq!(heap.word(items + 76), (12 << 16) | 10, "lpstr: Length 10, MaximumLength 12");
        assert_eq!(heap.word(BASE + popup + 20), mnf::POPUP);
        let sub_items = heap.word(BASE + popup + 52);
        assert_eq!(heap.word(sub_items + 8), 100);
        assert_eq!(heap.text(heap.word(sub_items + 24)), item);
    }

    #[test]
    fn an_item_is_found_by_position_or_by_identifier_in_submenus_first() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, false);
        add(&mut menus, &heap, 0x20, true);
        let text = wide("x");
        append(&mut menus, 0x20, &string_item(7, &text), &text);
        append(&mut menus, 0x10, &string_item(5, &text), &text);
        append(&mut menus, 0x10, &popup_item(0x20, &text), &text);
        assert_eq!(menus.find(0x10, 1, true), Some((0x10, 1)));
        assert_eq!(menus.find(0x10, 2, true), None);
        assert_eq!(menus.find(0x10, 7, false), Some((0x20, 0)), "in the submenu");
        assert_eq!(menus.find(0x10, 5, false), Some((0x10, 0)));
        assert_eq!(menus.find(0x10, 0x20, false), Some((0x10, 1)), "the popup item, by its identifier");
        assert_eq!(menus.find(0x10, 9, false), None);
    }

    #[test]
    fn insertion_by_position_identifier_or_at_the_end() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, true);
        let text = wide("x");
        append(&mut menus, 0x10, &string_item(1, &text), &text);
        append(&mut menus, 0x10, &string_item(3, &text), &text);
        menus.insert(0x10, 1, true, &string_item(2, &text), Some(&text)).unwrap();
        menus.insert(0x10, 3, false, &string_item(4, &text), Some(&text)).unwrap();
        menus.insert(0x10, 99, false, &string_item(5, &text), Some(&text)).unwrap();
        let ids: Vec<u32> = menus.state(0x10).unwrap().items.iter().map(|item| item.id).collect();
        assert_eq!(ids, [1, 2, 4, 3, 5], "before the identifier, or at the end without it");
        assert_eq!(menus.insert(0x99, 0, true, &string_item(6, &text), None), Err(ERROR_INVALID_MENU_HANDLE));
    }

    #[test]
    fn an_item_without_text_or_bitmap_is_a_separator() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, true);
        // AppendMenuW(MF_SEPARATOR): MF_GRAYED | MF_DISABLED, no text.
        let separator = MenuItemInfoW32 {
            f_mask: miim::STATE | miim::ID | miim::FTYPE,
            f_type: mft::SEPARATOR,
            f_state: mf::GRAYED | mf::DISABLED,
            ..MenuItemInfoW32::default()
        };
        menus.insert(0x10, u32::MAX, true, &separator, None).unwrap();
        let empty = MenuItemInfoW32 { f_mask: miim::ID | miim::FTYPE, w_id: 4, ..MenuItemInfoW32::default() };
        menus.insert(0x10, u32::MAX, true, &empty, None).unwrap();
        let text = wide("x");
        append(&mut menus, 0x10, &string_item(5, &text), &text);
        let items = &menus.state(0x10).unwrap().items;
        assert_eq!(items[0].f_type, mft::SEPARATOR);
        assert_eq!(items[0].f_state, mf::GRAYED | mf::DISABLED);
        assert_eq!(items[1].f_type, mft::SEPARATOR, "no text, no type data: a separator");
        assert_eq!(items[2].f_type, mft::STRING);
    }

    #[test]
    fn a_new_text_replaces_the_old_in_the_heap() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, true);
        let (old, new) = (wide("Old"), wide("Newer"));
        append(&mut menus, 0x10, &string_item(1, &old), &old);
        menus.publish_dirty().unwrap();
        let items = heap.word(BASE + 8 + 52);
        let old_at = heap.word(items + 24);
        let modify = MenuItemInfoW32 { f_mask: miim::STRING, dw_type_data: 1, cch: 5, ..MenuItemInfoW32::default() };
        menus.set_item(0x10, 1, false, &modify, Some(&new)).unwrap();
        menus.publish_dirty().unwrap();
        assert_eq!(heap.text(heap.word(items + 24)), new);
        assert!(heap.freed.lock().contains(&(old_at - BASE, 8)), "the old text goes back to the heap");
        // ModifyMenu with a longer cch than its string: the string's length.
        let short = MenuItemInfoW32 { cch: 50, ..modify };
        menus.set_item(0x10, 0, true, &short, Some(&old)).unwrap();
        assert_eq!(menus.state(0x10).unwrap().items[0].text, old);
        assert_eq!(menus.set_item(0x10, 7, false, &modify, Some(&new)), Err(ERROR_MENU_ITEM_NOT_FOUND), "no such item");
        assert_eq!(menus.set_item(0x10, SC_TASKLIST, false, &modify, None), Ok(()), "Word 95's SC_TASKLIST");
    }

    #[test]
    fn enable_check_and_default_return_what_was_before() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, true);
        let text = wide("x");
        append(&mut menus, 0x10, &string_item(1, &text), &text);
        append(&mut menus, 0x10, &string_item(2, &text), &text);
        assert_eq!(menus.enable(0x10, 1, mf::GRAYED), Some(0));
        assert_eq!(menus.enable(0x10, 1, 0), Some(mf::GRAYED));
        assert_eq!(menus.enable(0x10, 1, mf::BYPOSITION | mf::DISABLED), Some(0), "position 1: the second item");
        assert_eq!(menus.state(0x10).unwrap().items[1].f_state, mf::DISABLED);
        assert_eq!(menus.enable(0x10, 9, 0), None);
        assert_eq!(menus.check(0x10, 2, mf::CHECKED), Some(0));
        assert_eq!(menus.check(0x10, 2, 0), Some(mf::CHECKED));
        assert!(menus.set_default(0x10, 2, false));
        assert!(menus.set_default(0x10, 0, true));
        let states: Vec<u32> =
            menus.state(0x10).unwrap().items.iter().map(|item| item.f_state & mfs::DEFAULT).collect();
        assert_eq!(states, [mfs::DEFAULT, 0], "one default item");
        assert!(!menus.set_default(0x10, 5, true));
        assert!(menus.set_default(0x10, u32::MAX, false), "-1: none");
        assert!(menus.state(0x10).unwrap().items.iter().all(|item| item.f_state & mfs::DEFAULT == 0));
    }

    #[test]
    fn a_menu_may_not_open_itself_nor_an_ancestor() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, false);
        add(&mut menus, &heap, 0x20, true);
        let text = wide("x");
        append(&mut menus, 0x10, &popup_item(0x20, &text), &text);
        let itself = menus.insert(0x20, u32::MAX, true, &popup_item(0x20, &text), Some(&text));
        assert_eq!(itself, Err(ERROR_INVALID_PARAMETER));
        let loop_ = menus.insert(0x20, u32::MAX, true, &popup_item(0x10, &text), Some(&text));
        assert_eq!(loop_, Err(ERROR_INVALID_PARAMETER));
        assert!(menus.state(0x20).unwrap().items.is_empty(), "the failed item is gone");
        let missing = menus.insert(0x10, u32::MAX, true, &popup_item(0x99, &text), Some(&text));
        assert_eq!(missing, Err(ERROR_INVALID_PARAMETER));
    }

    #[test]
    fn delete_destroys_the_submenu_remove_keeps_it() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, false);
        add(&mut menus, &heap, 0x20, true);
        add(&mut menus, &heap, 0x30, true);
        let text = wide("x");
        append(&mut menus, 0x10, &popup_item(0x20, &text), &text);
        append(&mut menus, 0x10, &popup_item(0x30, &text), &text);
        assert_eq!(menus.remove(0x10, 0, mf::BYPOSITION, false), Some(Vec::new()), "RemoveMenu");
        assert!(menus.contains(0x20));
        assert_eq!(menus.remove(0x10, 0x30, 0, true), Some(alloc::vec![0x30]), "DeleteMenu");
        assert!(!menus.contains(0x30));
        assert_eq!(menus.remove(0x10, 0, mf::BYPOSITION, true), None, "empty");
        menus.publish_dirty().unwrap();
        assert_eq!(heap.word(BASE + 8 + 52), 0, "no items: no rgItems");
    }

    #[test]
    fn a_destroyed_menu_takes_its_submenus_and_leaves_its_parents() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, false);
        add(&mut menus, &heap, 0x20, true);
        add(&mut menus, &heap, 0x30, true);
        let text = wide("x");
        append(&mut menus, 0x10, &popup_item(0x20, &text), &text);
        append(&mut menus, 0x20, &popup_item(0x30, &text), &text);
        menus.publish_dirty().unwrap();
        assert_eq!(menus.destroy(0x20), alloc::vec![0x20, 0x30]);
        assert!(menus.contains(0x10) && !menus.contains(0x20) && !menus.contains(0x30));
        assert_eq!(menus.state(0x10).unwrap().items[0].submenu, 0, "the parent's item opens nothing now");
        menus.publish_dirty().unwrap();
        let items = heap.word(BASE + 8 + 52);
        assert_eq!(heap.word(items + 12), 0, "nor does user32 see a submenu");
        assert!(menus.destroy(0x20).is_empty(), "once");
    }

    #[test]
    fn a_bar_belongs_to_one_window() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, false);
        add(&mut menus, &heap, 0x20, false);
        assert_eq!(menus.attach(0x10, 0, 0x100), Ok(()));
        assert_eq!(menus.attach(0x10, 0, 0x200), Err(ERROR_INVALID_MENU_HANDLE), "another window's bar");
        assert_eq!(menus.attach(0x20, 0x10, 0x100), Ok(()), "the window changes its bar");
        assert_eq!((menus.state(0x10).unwrap().hwnd, menus.state(0x20).unwrap().hwnd), (0, 0x100));
        assert_eq!(menus.attach(0x99, 0, 0x100), Err(ERROR_INVALID_MENU_HANDLE));
    }

    #[test]
    fn menu_info_and_its_submenus() {
        let (mut menus, heap) = table();
        add(&mut menus, &heap, 0x10, false);
        add(&mut menus, &heap, 0x20, true);
        let text = wide("x");
        append(&mut menus, 0x10, &popup_item(0x20, &text), &text);
        let info = MenuInfo32 {
            f_mask: mim::HELPID | mim::STYLE | mim::APPLYTOSUBMENUS,
            dw_style: mns::NOTIFYBYPOS | 0x7,
            dw_context_help_id: 42,
            ..MenuInfo32::default()
        };
        assert!(menus.set_info(0x10, &info));
        let sub = menus.state(0x20).unwrap();
        assert_eq!((sub.help_id, sub.flags), (42, mnf::POPUP | mns::NOTIFYBYPOS), "the style bits only");
        assert!(!menus.set_info(0x99, &info));
    }

    #[test]
    fn the_items_array_grows_by_eight() {
        let (mut menus, heap) = table();
        let at = add(&mut menus, &heap, 0x10, true);
        let text = wide("x");
        for id in 0..9 {
            append(&mut menus, 0x10, &string_item(id, &text), &text);
            menus.publish_dirty().unwrap();
        }
        assert_eq!(heap.word(BASE + at + 28), 16, "cAlloced");
        assert_eq!(heap.word(BASE + at + 32), 9, "cItems");
        assert!(heap.freed.lock().iter().any(|&(_, size)| size == 8 * ITEM_SIZE), "the old array of 8 goes back");
    }

    #[test]
    fn the_state_bits_a_change_gives() {
        assert_eq!(update_state(mf::CHECKED | mfs::HBMMENUBMP, mf::GRAYED), mf::GRAYED | mfs::HBMMENUBMP);
        assert_eq!(update_state(mf::GRAYED, mfs::DEFAULT | mfs::HILITE), mfs::DEFAULT | mfs::HILITE);
    }
}
