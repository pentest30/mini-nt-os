//! Les menus (`menu.c` de ReactOS, comme spécification) : la barre de
//! menus d'une fenêtre et ses menus déroulants. Un menu est un objet de la
//! table des handles USER (`TYPE_MENU`), une liste d'items — un
//! identifiant, un titre, des drapeaux (désactivé, coché, séparateur), un
//! sous-menu pour les items qui en ouvrent un — dans l'ordre où ils
//! se lisent.
//!
//! La barre se dessine dans la zone non-cliente de sa fenêtre
//! ([`crate::nonclient`]) ; les menus déroulants attendent (TrackPopupMenu,
//! la souris dessus).
//!
//! Un menu est au processus qui l'a créé (son `PROCESSINFO` dans la table
//! des handles) ; DestroyMenu le détruit avec ses sous-menus ([`destroy`]),
//! comme la destruction de la fenêtre dont il est la barre, et la fin du
//! processus (`crate::destroy`).
//!
//! Pas encore : les accélérateurs soulignés (&x), les bitmaps d'items,
//! GetMenuBarInfo, la barre redessinée à la sélection (le surlignage).

use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::sync::KSpinLock;

use abi::ntstatus::NtStatus;
use abi::user::TYPE_MENU;

/// MF_* : les drapeaux d'un item (ceux que EnableMenuItem pose et que
/// MENUITEMINFOW rend comme état).
pub mod mf {
    /// L'item est coché.
    pub const CHECKED: u32 = 0x0008;
    /// L'item est grisé.
    pub const GRAYED: u32 = 0x0001;
    /// L'item est désactivé (posé avec GRAYED en général).
    pub const DISABLED: u32 = 0x0002;
    /// Le séparateur.
    pub const SEPARATOR: u32 = 0x0800;
    /// L'item ouvre le sous-menu `popup`.
    pub const POPUP: u32 = 0x0010;
}

/// Un item d'un menu.
#[derive(Clone, Debug, Default)]
pub struct Item {
    /// Son identifiant (l'application le reçoit de WM_COMMAND), ou sa
    /// position pour un sous-menu.
    pub id: u32,
    /// Son titre, UTF-16 sans le nul ; vide pour un séparateur.
    pub caption: Vec<u16>,
    /// `mf::*`.
    pub flags: u32,
    /// Le handle du menu qu'il ouvre ; 0 sans sous-menu.
    pub popup: u32,
}

/// Un menu : ses items, dans l'ordre.
pub struct Menu {
    items: KSpinLock<Vec<Item>>,
}

impl Default for Menu {
    fn default() -> Self {
        Self::new()
    }
}

impl Menu {
    /// Un menu vide.
    pub fn new() -> Self {
        Self { items: KSpinLock::new(Vec::new()) }
    }

    /// Ses items, une copie (pour dessiner la barre).
    pub fn items(&self) -> Vec<Item> {
        self.items.lock().clone()
    }

    /// L'item à `at` : par position (`by_position`), ou par identifiant —
    /// le premier qui le porte.
    pub fn find(&self, at: u32, by_position: bool) -> Option<Item> {
        let items = self.items.lock();
        if by_position {
            return items.get(at as usize).cloned();
        }
        items.iter().find(|item| item.id == at).cloned()
    }

    /// UserInsertMenuItem : l'item au bout (la fin de la barre), ou à sa
    /// position ; rend l'item inséré. Rien n'est mis à jour : un item qui
    /// existe n'est pas remplacé ici.
    pub fn insert(&self, at: Option<u32>, item: Item) -> Item {
        let mut items = self.items.lock();
        let index = at.map_or(items.len(), |at| (at as usize).min(items.len()));
        items.insert(index, item.clone());
        item
    }

    /// UserMenuItemInfo (l'écriture) : les champs de l'item `at` (par
    /// position ou identifiant) remplacés ; `None` sans lui.
    pub fn set(&self, at: u32, by_position: bool, change: impl FnOnce(&mut Item)) -> Option<()> {
        let mut items = self.items.lock();
        let item =
            if by_position { items.get_mut(at as usize)? } else { items.iter_mut().find(|item| item.id == at)? };
        change(item);
        Some(())
    }

    /// NtUserRemoveMenu : l'item `at` (par position ou identifiant) retiré
    /// — son sous-menu n'est pas détruit ; `None` sans lui.
    pub fn remove(&self, at: u32, by_position: bool) -> Option<Item> {
        let mut items = self.items.lock();
        let index = if by_position { at as usize } else { items.iter().position(|item| item.id == at)? };
        (index < items.len()).then(|| items.remove(index))
    }
}

/// Les menus par handle (la table USER pointe à l'objet du serveur ; les
/// menus n'y sont pas alloués du tas d'un bureau, ils sont à eux).
static MENUS: KSpinLock<Vec<(u32, Arc<Menu>)>> = KSpinLock::new(Vec::new());

/// UserCreateMenu : un menu neuf dans la table des handles USER, au
/// processus courant ; rend son handle.
///
/// # Errors
/// `STATUS_INSUFFICIENT_RESOURCES` sans place.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn create() -> Result<u32, NtStatus> {
    let menu = Arc::new(Menu::new());
    let server = Arc::as_ptr(&menu) as u32;
    let owner = ps::ethread::current_thread()
        .and_then(|thread| crate::existing_process_info(thread.process()))
        .map_or(0, |info| info.server);
    let handle = crate::handles::alloc(server, owner, TYPE_MENU)?;
    MENUS.lock().push((handle, menu));
    Ok(handle)
}

/// Le menu `handle`, s'il existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(handle: u32) -> Option<Arc<Menu>> {
    MENUS.lock().iter().find(|(at, _)| *at == handle).map(|(_, menu)| menu.clone())
}

/// IntDestroyMenuObject(…, TRUE) : le menu et ses sous-menus rendus (leurs
/// handles libres) ; `false` sans lui. La barre d'une fenêtre qui le
/// désignait n'a plus d'items (comme XP, la fenêtre garde le handle).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy(handle: u32) -> bool {
    let Some(menu) = get(handle) else { return false };
    let popups: Vec<u32> = menu.items().iter().filter(|item| item.popup != 0).map(|item| item.popup).collect();
    MENUS.lock().retain(|(at, _)| *at != handle);
    let _ = crate::handles::free(handle);
    for popup in popups {
        destroy(popup);
    }
    true
}
