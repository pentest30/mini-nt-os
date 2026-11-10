//! Les classes de fenêtres (02 §7.2) : ce que RegisterClassEx enregistre
//! (NtUserRegisterClassExWOW), et que nomme CreateWindowEx.
//!
//! Comme dans ReactOS (`class.c`, comme spécification) :
//! - un processus GUI a ses classes privées et publiques (`CS_GLOBALCLASS`),
//!   les plus récentes d'abord ([`ClassLists`]) ; à son premier
//!   enregistrement, il reçoit les classes du système dont la procédure est
//!   dans win32k (UserRegisterSystemClasses : le bureau, les menus, le
//!   sélecteur de tâches, les barres de défilement, les titres d'icônes, les
//!   fenêtres de messages) ;
//! - une classe a deux atomes dans la table de USER ([`crate::atom`]) : celui
//!   de son nom et celui de sa version (le même nom, sans manifeste) ;
//! - une classe dont la procédure est celle d'une classe du système qui a
//!   une procédure du serveur prend cette procédure (`CSF_SERVERSIDEPROC`) ;
//! - CreateWindowEx cherche la classe parmi les privées de l'instance, les
//!   publiques, puis celles de `user32` ([`ClassLists::find`]).
//!
//! `user32` lit une classe par le `CLS` qu'une fenêtre désigne : il est dans
//! le tas du bureau de la fenêtre ([`Class::image_on`], comme le clone que
//! fait IntGetClassForDesktop), écrit à la première fenêtre de la classe sur
//! ce bureau, ses octets de plus à la suite ; il vit autant que la classe et
//! le tas.
//!
//! Écarts : pas d'objets curseur ni icône (les handles sont gardés, `spicn`
//! et `spcur` restent nuls), ni de pinceaux (un pinceau du système vaut sa
//! couleur plus un) ; le nom de menu reste dans le client (les pointeurs de
//! `CLSMENUNAME`), le noyau en garde une copie pour charger le menu d'une
//! fenêtre (`lpszMenuName`) ; le compte des fenêtres d'une classe
//! (`cWndReferenceCount`) n'est pas tenu dans le `CLS` ; pas de
//! `atomSysClass` dans le `SERVERINFO` ; ni désenregistrement, ni
//! procédures d'appel (une classe Unicode demandée en ANSI rend sa
//! procédure, journalisé).

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    Cls32, CLS_GLOBAL, CLS_MENU_NAME_IS_STRING, CLS_UNICODE, CSF_ANSIPROC, CSF_SERVERSIDEPROC, CSF_WOWDEFERDESTROY,
    CS_DBLCLKS, CS_GLOBALCLASS, CS_HREDRAW, CS_VREDRAW, FNID_DESKTOP, FNID_ICONTITLE, FNID_MENU, FNID_MESSAGEWND,
    FNID_SCROLLBAR, FNID_SWITCH, WC_DESKTOP, WC_ICONTITLE, WC_MENU, WC_SWITCH,
};
use abi::winerror::{dos_error, ERROR_CLASS_ALREADY_EXISTS};
use hal::sync::KSpinLock;

use crate::atom::{self, AtomName};
use crate::desktop::DesktopHeap;

/// CS_* que les classes du système emploient.
const CS_PARENTDC: u32 = 0x0080;
const CS_SAVEBITS: u32 = 0x0800;
const CS_DROPSHADOW: u32 = 0x0002_0000;
/// COLOR_* (pinceaux des classes du système), COLOR_MENUBAR le dernier.
const COLOR_BACKGROUND: u32 = 1;
const COLOR_MENU: u32 = 4;
const COLOR_MENUBAR: u32 = 30;

/// Le nom d'une classe donné aux services : un atome entier (MAKEINTATOM)
/// ou une chaîne.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassName {
    Atom(u16),
    String(Vec<u16>),
}

impl ClassName {
    fn atom_name(&self) -> AtomName<'_> {
        match self {
            ClassName::Atom(atom) => AtomName::Integer(*atom),
            ClassName::String(name) => AtomName::String(name),
        }
    }

    /// IntGetAtomFromStringOrAtom : l'atome du nom, s'il existe (une chaîne
    /// qui n'en a pas : `None`).
    pub fn atom(&self) -> Option<u16> {
        match self {
            ClassName::Atom(0) => None,
            ClassName::Atom(atom) => Some(*atom),
            ClassName::String(_) => atom::find(self.atom_name()),
        }
    }
}

/// Ce que WNDCLASSEXW donne d'une classe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClassInfo {
    pub style: u32,
    pub wnd_proc: u32,
    pub cls_extra: i32,
    pub wnd_extra: i32,
    pub instance: u32,
    pub icon: u32,
    pub cursor: u32,
    /// Un pinceau, ou une couleur du système plus un.
    pub background: u32,
    pub icon_sm: u32,
}

/// Le nom de menu d'une classe, tel que le client le garde (CLSMENUNAME) :
/// ses chaînes Unicode et ANSI, ou un identifiant de ressource (dans
/// `unicode` et `ansi`) ; et la copie du noyau de la chaîne (`name`, vide
/// pour un identifiant), que `user32` charge pour une fenêtre de la classe
/// (`crate::callback::load_menu`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MenuName {
    pub unicode: u32,
    pub ansi: u32,
    pub is_string: bool,
    pub name: Vec<u16>,
}

impl MenuName {
    /// La ressource du menu : son nom, ou son identifiant ; aucune sans nom
    /// de menu.
    pub fn resource(&self) -> Option<crate::callback::MenuResource<'_>> {
        if self.is_string {
            (!self.name.is_empty()).then_some(crate::callback::MenuResource::Name(&self.name))
        } else {
            (self.unicode != 0).then_some(crate::callback::MenuResource::Id(self.unicode as u16))
        }
    }
}

/// Une classe de fenêtres.
pub struct Class {
    /// atomClassName : l'atome de sa version.
    pub atom: u16,
    /// atomNVClassName : l'atome de son nom.
    pub nv_atom: u16,
    pub fnid: u32,
    /// CSF_*.
    pub flags: u32,
    pub info: ClassInfo,
    pub menu: MenuName,
    /// Trouvée quelle que soit l'instance (`CS_GLOBALCLASS`).
    pub global: bool,
    /// Son `CLS` dans le tas de chaque bureau où elle a eu une fenêtre.
    images: KSpinLock<Vec<(Weak<DesktopHeap>, u32)>>,
}

impl Class {
    /// Sa procédure prend des messages Unicode.
    pub fn unicode(&self) -> bool {
        self.flags & CSF_ANSIPROC == 0
    }

    /// Son `CLS`, en `at` du tas `heap`.
    fn cls(&self, heap: &DesktopHeap, at: u32) -> Cls32 {
        let mut bits = 0;
        if self.unicode() {
            bits |= CLS_UNICODE;
        }
        if self.global {
            bits |= CLS_GLOBAL;
        }
        if self.menu.is_string {
            bits |= CLS_MENU_NAME_IS_STRING;
        }
        Cls32 {
            atom_class_name: self.atom,
            atom_nv_class_name: self.nv_atom,
            fnid: self.fnid,
            rpdesk_parent: heap.server_base,
            csf_flags: self.flags,
            client_ansi_menu_name: self.menu.ansi,
            client_unicode_menu_name: self.menu.unicode,
            base: heap.server_address(at),
            style: self.info.style,
            wnd_proc: self.info.wnd_proc,
            cb_cls_extra: self.info.cls_extra,
            cb_wnd_extra: self.info.wnd_extra,
            module: self.info.instance,
            background: self.info.background,
            menu_name: self.menu.unicode,
            bits,
            ..Cls32::default()
        }
    }

    /// IntGetClassForDesktop : la position de son `CLS` dans le tas `heap`
    /// d'un bureau, écrit (suivi de ses octets de plus, à zéro) la première
    /// fois.
    ///
    /// # Errors
    /// Celles du tas du bureau.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn image_on(&self, heap: &Arc<DesktopHeap>) -> Result<u32, NtStatus> {
        let mut images = self.images.lock();
        images.retain(|(other, _)| other.strong_count() > 0);
        if let Some((_, at)) = images.iter().find(|(other, _)| core::ptr::eq(other.as_ptr(), Arc::as_ptr(heap))) {
            return Ok(*at);
        }
        let size = self.image_size();
        let at = heap.alloc(size)?;
        if let Err(status) = heap.section.write_kernel(u64::from(at), self.cls(heap, at).as_bytes()) {
            heap.free(at, size);
            return Err(status);
        }
        images.push((Arc::downgrade(heap), at));
        Ok(at)
    }

    /// La taille de son `CLS` et de ses octets de plus.
    fn image_size(&self) -> u32 {
        size_of::<Cls32>() as u32 + self.info.cls_extra.max(0) as u32
    }

    /// IntGetClassWndProc : la procédure que le client voit, ANSI ou non
    /// (`ansi`) : pour une procédure du serveur, celle du client du même
    /// FNID.
    pub fn procedure(&self, ansi: bool) -> u32 {
        if self.flags & CSF_SERVERSIDEPROC != 0 {
            let fnid = (abi::user::FNID_FIRST..=FNID_SWITCH)
                .find(|&fnid| crate::client::server_procedure(fnid) == Some(self.info.wnd_proc));
            if let Some(procedure) = fnid.and_then(|fnid| crate::client::client_procedure(fnid, ansi)) {
                return procedure;
            }
            return self.info.wnd_proc;
        }
        if ansi == self.unicode() {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "win32k: the procedure of class {:#x} asked in the other character set: no call procedure yet",
                    self.nv_atom
                );
            }
        }
        self.info.wnd_proc
    }
}

impl Drop for Class {
    fn drop(&mut self) {
        let images = core::mem::take(&mut *self.images.lock());
        for (heap, at) in images {
            if let Some(heap) = heap.upgrade() {
                heap.free(at, self.image_size());
            }
        }
        let _ = atom::delete(self.atom);
        let _ = atom::delete(self.nv_atom);
    }
}

/// Les classes d'un processus GUI, les plus récentes d'abord.
#[derive(Default)]
pub struct ClassLists {
    private: Vec<Arc<Class>>,
    public: Vec<Arc<Class>>,
    /// Les classes du système sont enregistrées (`W32PF_CLASSESREGISTERED`).
    system: bool,
}

/// IntFindClass : la classe d'atome `atom` de `list` (la plus récente), de
/// l'instance `instance` s'il y en a une.
fn find_in(list: &[Arc<Class>], atom: u16, instance: Option<u32>) -> Option<Arc<Class>> {
    list.iter()
        .rev()
        .find(|class| {
            class.atom == atom
                && instance.is_none_or(|instance| class.info.instance == instance)
                && class.flags & CSF_WOWDEFERDESTROY == 0
        })
        .cloned()
}

/// Une classe du système dont la procédure est dans win32k
/// (DefaultServerClasses de ReactOS).
struct SystemClass {
    name: ClassName,
    style: u32,
    wnd_extra: i32,
    /// Un pinceau du système (une couleur, sans le plus un), ou 0.
    brush: u32,
    fnid: u32,
}

fn system_classes() -> [SystemClass; 6] {
    let scroll_bar: Vec<u16> = "ScrollBar".encode_utf16().collect();
    let message: Vec<u16> = "Message".encode_utf16().collect();
    [
        SystemClass {
            name: ClassName::Atom(WC_DESKTOP),
            style: CS_GLOBALCLASS | CS_DBLCLKS,
            wnd_extra: 8,
            brush: COLOR_BACKGROUND,
            fnid: FNID_DESKTOP,
        },
        SystemClass {
            name: ClassName::Atom(WC_SWITCH),
            style: CS_VREDRAW | CS_HREDRAW | CS_SAVEBITS,
            wnd_extra: 4,
            brush: 0,
            fnid: FNID_SWITCH,
        },
        SystemClass {
            name: ClassName::Atom(WC_MENU),
            style: CS_DBLCLKS | CS_SAVEBITS | CS_DROPSHADOW,
            wnd_extra: 16,
            brush: COLOR_MENU + 1,
            fnid: FNID_MENU,
        },
        SystemClass {
            name: ClassName::String(scroll_bar),
            style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC,
            // sizeof(SBWND) - sizeof(WND): fVert, wDisableFlags, SBCALC.
            wnd_extra: 4 + 4 + 16 * 4,
            brush: 0,
            fnid: FNID_SCROLLBAR,
        },
        SystemClass { name: ClassName::Atom(WC_ICONTITLE), style: 0, wnd_extra: 0, brush: 0, fnid: FNID_ICONTITLE },
        SystemClass {
            name: ClassName::String(message),
            style: CS_GLOBALCLASS,
            wnd_extra: 0,
            brush: 0,
            fnid: FNID_MESSAGEWND,
        },
    ]
}

/// Un pinceau de classe : une couleur du système (jusqu'à `COLOR_MENUBAR`)
/// devient son pinceau, la couleur plus un (IntGetSysColorBrush) ; un vrai
/// pinceau reste lui-même.
fn class_brush(brush: u32) -> u32 {
    if brush != 0 && brush <= COLOR_MENUBAR {
        brush + 1
    } else {
        brush
    }
}

impl ClassLists {
    /// IntGetClassAtom : la classe que CreateWindowEx nomme par `name` pour
    /// l'instance `instance` : privée de l'instance, publique, privée puis
    /// publique de `user32` (`client_module`).
    pub fn find(&self, name: &ClassName, instance: u32, client_module: u32) -> Option<Arc<Class>> {
        let atom = name.atom()?;
        find_in(&self.private, atom, Some(instance))
            .or_else(|| find_in(&self.public, atom, None))
            .or_else(|| find_in(&self.private, atom, Some(client_module)))
            .or_else(|| find_in(&self.public, atom, Some(client_module)))
    }

    /// UserRegisterClass : enregistre la classe `name` (sa version :
    /// `version`) ; rend l'atome de son nom.
    ///
    /// # Errors
    /// L'erreur Win32 : `ERROR_CLASS_ALREADY_EXISTS` pour une classe privée
    /// de la même instance, ou publique, du même nom ; celle de la table des
    /// atomes.
    pub fn register(
        &mut self,
        name: &ClassName,
        version: &ClassName,
        info: ClassInfo,
        menu: MenuName,
        fnid: u32,
        flags: u32,
    ) -> Result<u16, u32> {
        if flags & CSF_SERVERSIDEPROC == 0 {
            if let Some(atom) = version.atom() {
                if find_in(&self.private, atom, Some(info.instance)).is_some_and(|class| !class.global) {
                    return Err(ERROR_CLASS_ALREADY_EXISTS);
                }
                if info.style & CS_GLOBALCLASS != 0
                    && find_in(&self.public, atom, None).is_some_and(|class| class.global)
                {
                    return Err(ERROR_CLASS_ALREADY_EXISTS);
                }
            }
        }
        let class = Arc::new(create(name, version, info, menu, fnid, flags)?);
        let nv_atom = class.nv_atom;
        if class.global {
            self.public.push(class);
        } else {
            self.private.push(class);
        }
        Ok(nv_atom)
    }

    /// UserRegisterSystemClasses : une fois par processus, les classes du
    /// système dont la procédure est dans win32k, publiques, de l'instance
    /// de `user32` (`client_module`), une fois ses procédures enregistrées.
    pub fn register_system_classes(&mut self, client_module: u32) {
        if self.system || client_module == 0 {
            return;
        }
        let mut all = true;
        for system in system_classes() {
            let Some(wnd_proc) = crate::client::server_procedure(system.fnid) else {
                all = false;
                continue;
            };
            let info = ClassInfo {
                style: system.style,
                wnd_proc,
                wnd_extra: system.wnd_extra,
                instance: client_module,
                background: class_brush(system.brush),
                ..ClassInfo::default()
            };
            match create(&system.name, &system.name, info, MenuName::default(), system.fnid, CSF_SERVERSIDEPROC) {
                Ok(class) => self.public.push(Arc::new(class)),
                Err(error) => {
                    log::warn!("win32k: system class {:#x} not registered (error {error})", system.fnid);
                    all = false;
                }
            }
        }
        self.system = all;
    }

    /// Les classes du système sont enregistrées.
    pub fn system_registered(&self) -> bool {
        self.system
    }
}

/// IntCreateClass : une classe, ses deux atomes ajoutés à la table de USER.
fn create(
    name: &ClassName,
    version: &ClassName,
    info: ClassInfo,
    menu: MenuName,
    fnid: u32,
    flags: u32,
) -> Result<Class, u32> {
    let nv_atom = atom::add(name.atom_name()).map_err(dos_error)?;
    let atom = match atom::add(version.atom_name()) {
        Ok(atom) => atom,
        Err(status) => {
            let _ = atom::delete(nv_atom);
            return Err(dos_error(status));
        }
    };
    let mut class = Class {
        atom,
        nv_atom,
        fnid,
        flags,
        info,
        menu,
        global: info.style & CS_GLOBALCLASS != 0,
        images: KSpinLock::new(Vec::new()),
    };
    if class.flags & CSF_SERVERSIDEPROC == 0 {
        if let Some(server) =
            crate::client::server_procedure_of(info.wnd_proc).and_then(crate::client::server_procedure)
        {
            class.flags = (class.flags | CSF_SERVERSIDEPROC) & !CSF_ANSIPROC;
            class.info.wnd_proc = server;
        }
    }
    Ok(class)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> ClassName {
        ClassName::String(text.encode_utf16().collect())
    }

    fn info(style: u32, instance: u32) -> ClassInfo {
        ClassInfo { style, wnd_proc: 0x0040_1000, instance, ..ClassInfo::default() }
    }

    #[test]
    fn a_class_is_found_by_its_name_or_atom() {
        let mut lists = ClassLists::default();
        let atom =
            lists.register(&name("TestFound"), &name("TestFound"), info(0, 0x40_0000), MenuName::default(), 0, 0);
        let atom = atom.expect("registered");
        let by_name = lists.find(&name("testfound"), 0x40_0000, 0x77A0_0000).expect("found, without case");
        assert_eq!(by_name.nv_atom, atom);
        let by_atom = lists.find(&ClassName::Atom(atom), 0x40_0000, 0x77A0_0000).expect("found by its atom");
        assert!(Arc::ptr_eq(&by_name, &by_atom));
        assert!(lists.find(&name("TestFound"), 0x50_0000, 0x77A0_0000).is_none(), "private to its instance");
        assert!(lists.find(&name("TestMissing"), 0x40_0000, 0x77A0_0000).is_none());
    }

    #[test]
    fn a_class_cannot_be_registered_twice() {
        let mut lists = ClassLists::default();
        let first =
            lists.register(&name("TestTwice"), &name("TestTwice"), info(0, 0x40_0000), MenuName::default(), 0, 0);
        assert!(first.is_ok());
        let again =
            lists.register(&name("TESTTWICE"), &name("TESTTWICE"), info(0, 0x40_0000), MenuName::default(), 0, 0);
        assert_eq!(again, Err(ERROR_CLASS_ALREADY_EXISTS), "same instance");
        let other =
            lists.register(&name("TestTwice"), &name("TestTwice"), info(0, 0x50_0000), MenuName::default(), 0, 0);
        assert!(other.is_ok(), "another instance may");
        let global = info(CS_GLOBALCLASS, 0x40_0000);
        assert!(lists.register(&name("TestGlobal"), &name("TestGlobal"), global, MenuName::default(), 0, 0).is_ok());
        let again = lists.register(&name("TestGlobal"), &name("TestGlobal"), global, MenuName::default(), 0, 0);
        assert_eq!(again, Err(ERROR_CLASS_ALREADY_EXISTS), "one global class of a name");
    }

    #[test]
    fn global_classes_are_found_whatever_the_instance_and_private_ones_first() {
        let mut lists = ClassLists::default();
        let global = info(CS_GLOBALCLASS, 0x40_0000);
        lists.register(&name("TestBoth"), &name("TestBoth"), global, MenuName::default(), 0, 0).unwrap();
        let found = lists.find(&name("TestBoth"), 0x60_0000, 0).expect("global");
        assert!(found.global);
        lists.register(&name("TestBoth"), &name("TestBoth"), info(0, 0x60_0000), MenuName::default(), 0, 0).unwrap();
        assert!(!lists.find(&name("TestBoth"), 0x60_0000, 0).unwrap().global, "the private one of the instance first");
    }

    #[test]
    fn user32s_own_classes_come_last() {
        let mut lists = ClassLists::default();
        let user32 = 0x77A0_0000;
        lists.register(&name("TestOwn"), &name("TestOwn"), info(0, user32), MenuName::default(), 0, 0).unwrap();
        assert!(lists.find(&name("TestOwn"), 0x40_0000, user32).is_some(), "user32's private class");
        assert!(lists.find(&name("TestOwn"), 0x40_0000, 0x1234).is_none());
    }

    #[test]
    fn a_class_gives_back_its_atoms() {
        let mut lists = ClassLists::default();
        let atom = lists.register(&name("TestGone"), &name("TestGone"), info(0, 1), MenuName::default(), 0, 0).unwrap();
        assert_eq!(atom::find(AtomName::String(&"TestGone".encode_utf16().collect::<Vec<_>>())), Some(atom));
        drop(lists);
        assert_eq!(atom::find(AtomName::String(&"TestGone".encode_utf16().collect::<Vec<_>>())), None);
    }

    /// The client procedures of these tests: ANSI `0x7000_0000 + i`,
    /// Unicode `0x7100_0000 + i`, for FNID_FIRST + i.
    fn client_procedures() {
        crate::client::set_procedures_for_test(
            core::array::from_fn(|i| 0x7000_0000 + i as u32),
            core::array::from_fn(|i| 0x7100_0000 + i as u32),
        );
    }

    #[test]
    fn a_process_gets_the_server_side_system_classes_once() {
        client_procedures();
        let user32 = 0x77A0_0000;
        let mut lists = ClassLists::default();
        lists.register_system_classes(0);
        assert!(!lists.system_registered(), "not before user32 registered its procedures");
        lists.register_system_classes(user32);
        assert!(lists.system_registered());
        assert_eq!(lists.public.len(), 6);
        let desktop = lists.find(&ClassName::Atom(WC_DESKTOP), 0x40_0000, user32).expect("the desktop class");
        assert_eq!((desktop.fnid, desktop.flags, desktop.info.instance), (FNID_DESKTOP, CSF_SERVERSIDEPROC, user32));
        assert_eq!(desktop.info.wnd_proc, 0x7100_0003, "the server procedure: the client's Unicode one");
        assert_eq!(desktop.info.background, COLOR_BACKGROUND + 1);
        assert_eq!(desktop.procedure(true), 0x7000_0003, "seen by the client: its ANSI procedure");
        assert_eq!(desktop.procedure(false), 0x7100_0003);
        let message = ClassName::String("message".encode_utf16().collect());
        assert_eq!(lists.find(&message, 0x40_0000, user32).map(|class| class.fnid), Some(FNID_MESSAGEWND));
        lists.register_system_classes(user32);
        assert_eq!(lists.public.len(), 6, "once");
    }

    #[test]
    fn a_class_with_a_server_procedure_takes_it() {
        client_procedures();
        let mut lists = ClassLists::default();
        let scroll = ClassInfo { wnd_proc: 0x7000_0000, instance: 0x40_0000, ..ClassInfo::default() };
        let name = name("TestServerSide");
        lists.register(&name, &name, scroll, MenuName::default(), 0, CSF_ANSIPROC).unwrap();
        let class = lists.find(&name, 0x40_0000, 0).unwrap();
        assert_eq!(class.flags, CSF_SERVERSIDEPROC, "server side, and no more ANSI");
        assert_eq!(class.info.wnd_proc, 0x7100_0000, "the scroll bar's server procedure");
        let button = ClassInfo { wnd_proc: 0x7100_0007, instance: 0x40_0000, ..ClassInfo::default() };
        let name = self::name("TestButton");
        lists.register(&name, &name, button, MenuName::default(), 0, 0).unwrap();
        assert_eq!(lists.find(&name, 0x40_0000, 0).unwrap().flags, 0, "the button has no server procedure");
    }

    #[test]
    fn system_brushes_are_their_colour_plus_one() {
        assert_eq!(class_brush(COLOR_BACKGROUND), 2);
        assert_eq!(class_brush(0), 0);
        assert_eq!(class_brush(0x0010_0040), 0x0010_0040, "a brush");
    }

    #[test]
    fn an_integer_name_is_its_own_atom() {
        assert_eq!(ClassName::Atom(WC_DESKTOP).atom(), Some(WC_DESKTOP));
        assert_eq!(ClassName::Atom(0).atom(), None);
    }
}
