//! Les crochets (SetWindowsHookEx ; `hook.c` et `callback.c` de win32k,
//! ReactOS comme spécification).
//!
//! Un crochet (`HOOK`) est un objet USER (`TYPE_HOOK`) dans le tas du bureau
//! de son thread, où `user32` le lit : CallNextHookEx regarde le `phkNext`,
//! le `HookId` et le `Ansi` du crochet que désigne son `CLIENTINFO`
//! (`phkCurrent`). Un crochet de thread accroche un thread du bureau de
//! celui qui le pose (un autre processus demande un module) ; un crochet
//! global accroche le bureau. Chaque thread, et chaque bureau, a une chaîne
//! par type de crochet : le dernier posé est appelé le premier. Le
//! `fsHooks` du `CLIENTINFO` d'un thread et celui du `DESKTOPINFO` disent
//! quels types y ont des crochets ; `user32` les teste (CallMsgFilter).
//!
//! Les appels ([`call_hooks`], co_HOOK_CallHooks) : le premier crochet de
//! la chaîne du thread courant est appelé par `user32`
//! (USER32_CALLBACK_HOOKPROC) ; pendant l'appel, il est le crochet courant
//! du thread (`sphkCurrent`, et `phkCurrent` dans son `CLIENTINFO`) et son
//! `phkNext` désigne le suivant, que CallNextHookEx ([`call_next`]) appelle
//! à son tour. Puis chaque crochet global du bureau, hors chaîne, s'il est
//! du thread courant ou de son processus : ReactOS n'appelle pas les autres
//! (pas encore les crochets de bas niveau, qu'il poste au thread qui les a
//! posés).
//!
//! Sont appelés : WH_GETMESSAGE (le message que PeekMessage ou GetMessage va
//! rendre, que le crochet peut changer : `crate::queue::peek`) ;
//! WH_SYSMSGFILTER puis WH_MSGFILTER ([`call_msg_filter`] : CallMsgFilter,
//! la boucle d'un menu avec MSGF_MENU) ; WH_CBT pour HCBT_CREATEWND
//! ([`create_window`] : la fenêtre que CreateWindowEx crée, avant tout
//! message ; MFC y attache son `CWnd` et la sous-classe), pas encore pour
//! les autres codes de HCBT. Les autres types se posent, mais ne sont pas
//! encore appelés (journalisé une fois par type) : WH_CALLWNDPROC,
//! WH_CALLWNDPROCRET, WH_KEYBOARD, WH_MOUSE, WH_KEYBOARD_LL, WH_MOUSE_LL,
//! WH_SHELL, WH_FOREGROUNDIDLE, WH_JOURNALRECORD, WH_JOURNALPLAYBACK,
//! WH_DEBUG, WH_HARDWARE.
//!
//! Un crochet est rendu par UnhookWindowsHookEx, à la fin du thread qu'il
//! accroche, à celle du thread qui l'a posé, ou à celle de son processus.
//! ReactOS ne le rend qu'à la fin du thread accroché ; Mino le rend aussi à
//! celle du thread qui l'a posé, dont la procédure ne serait plus servie.
//! Un crochet retiré pendant son appel reste dans le tas jusqu'à la fin de
//! l'appel (il est encore le crochet courant) ; son handle est rendu tout de
//! suite.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use abi::teb32::Teb32;
use abi::user::{
    hcbt, hook_flag, wh, CbtCreateWndExtra32, ClientInfo32, CreateStructW32, DeskInfoHead32, Hook32,
    HookProcArguments32, Msg32, TIF_CSRSSTHREAD, TIF_SYSTEMTHREAD, TYPE_HOOK, USER32_CALLBACK_HOOKPROC,
};
use abi::winerror::{
    ERROR_ACCESS_DENIED, ERROR_GLOBAL_ONLY_HOOK, ERROR_HOOK_NEEDS_HMOD, ERROR_HOOK_TYPE_NOT_ALLOWED,
    ERROR_INVALID_FILTER_PROC, ERROR_INVALID_HOOK_FILTER, ERROR_INVALID_HOOK_HANDLE, ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY,
};
use hal::sync::KSpinLock;

use crate::desktop::DesktopHeap;
use crate::gui::ThreadInfo;

/// Ce qui place un crochet dans les chaînes : son handle, son type, le
/// thread qu'il accroche (`None` : global), le tas de son bureau (son
/// adresse, la clé du bureau).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub handle: u32,
    pub id: i32,
    pub hooked: Option<u32>,
    pub desktop: usize,
}

/// Une chaîne : celle d'un thread (son `THREADINFO`), ou celle d'un bureau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Thread(u32),
    Desktop(usize),
}

impl Place {
    /// Le crochet est de la chaîne `chain` du type `id`.
    pub fn is_in(&self, id: i32, chain: Chain) -> bool {
        self.id == id
            && match chain {
                Chain::Thread(pti) => self.hooked == Some(pti),
                Chain::Desktop(desktop) => self.hooked.is_none() && self.desktop == desktop,
            }
    }

    /// Sa chaîne.
    pub const fn chain(&self) -> Chain {
        match self.hooked {
            Some(pti) => Chain::Thread(pti),
            None => Chain::Desktop(self.desktop),
        }
    }
}

/// Les crochets de la chaîne `chain` du type `id` dans `places` (le
/// dernier posé en tête de `places`), dans l'ordre de leurs appels.
pub fn chain_of(places: &[Place], id: i32, chain: Chain) -> Vec<u32> {
    places.iter().filter(|place| place.is_in(id, chain)).map(|place| place.handle).collect()
}

/// IntGetNextHook : le crochet qui suit `handle` dans sa chaîne.
pub fn next_of(places: &[Place], handle: u32) -> Option<u32> {
    let place = places.iter().find(|place| place.handle == handle)?;
    let chain = chain_of(places, place.id, place.chain());
    let at = chain.iter().position(|&other| other == handle)?;
    chain.get(at + 1).copied()
}

/// Le `fsHooks` de la chaîne `chain` : un bit par type qui y a un crochet.
pub fn flags_of(places: &[Place], chain: Chain) -> u32 {
    places.iter().filter(|place| place.is_in(place.id, chain)).fold(0, |flags, place| flags | hook_flag(place.id))
}

/// Un crochet.
pub struct Hook {
    pub place: Place,
    proc_: u32,
    /// ihmod : le module de la procédure (0 sans).
    module: u32,
    /// offPfn : la place de la procédure dans son module.
    off_pfn: u32,
    ansi: bool,
    /// Le chemin du module, sans nul (vide sans module).
    module_name: Vec<u16>,
    /// head.pti : le thread accroché, ou celui qui a posé un crochet global.
    owner: u32,
    /// Le thread qui l'a posé, et son processus.
    installer: u32,
    installer_pid: u32,
    /// Le tas où est son `HOOK`, et sa place dans le tas.
    heap: Arc<DesktopHeap>,
    at: u32,
    /// La place du `DESKTOPINFO` de son bureau dans le tas.
    desk_info: u32,
}

impl Hook {
    /// L'adresse du serveur de son `HOOK`.
    pub fn address(&self) -> u32 {
        self.heap.server_address(self.at)
    }

    /// Son `phkNext` devient `next` (une adresse du serveur, 0 : aucun).
    fn set_next(&self, next: u32) {
        let at = u64::from(self.at) + offset_of!(Hook32, phk_next) as u64;
        let _ = self.heap.section.write_kernel(at, &next.to_le_bytes());
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.heap.free(self.at, size_of::<Hook32>() as u32);
    }
}

/// Les crochets posés (le dernier en tête), et le crochet courant de chaque
/// thread qui en appelle un (`sphkCurrent`).
struct Table {
    hooks: Vec<Arc<Hook>>,
    current: Vec<(u32, Arc<Hook>)>,
}

impl Table {
    fn places(&self) -> Vec<Place> {
        self.hooks.iter().map(|hook| hook.place).collect()
    }

    fn get(&self, handle: u32) -> Option<Arc<Hook>> {
        self.hooks.iter().find(|hook| hook.place.handle == handle).cloned()
    }

    fn current_of(&self, pti: u32) -> Option<Arc<Hook>> {
        self.current.iter().find(|(thread, _)| *thread == pti).map(|(_, hook)| hook.clone())
    }

    /// Le crochet courant de `pti` devient `hook` ; rend l'ancien.
    fn set_current(&mut self, pti: u32, hook: Option<Arc<Hook>>) -> Option<Arc<Hook>> {
        let at = self.current.iter().position(|(thread, _)| *thread == pti);
        let previous = at.map(|at| self.current.swap_remove(at).1);
        if let Some(hook) = hook {
            self.current.push((pti, hook));
        }
        previous
    }

    /// Le `phkNext` du crochet `hook` désigne le suivant de sa chaîne ;
    /// rend son adresse (0 : aucun).
    fn link_next(&self, hook: &Hook) -> u32 {
        let next = next_of(&self.places(), hook.place.handle).and_then(|next| self.get(next));
        let address = next.map_or(0, |next| next.address());
        hook.set_next(address);
        address
    }
}

static TABLE: KSpinLock<Table> = KSpinLock::new(Table { hooks: Vec::new(), current: Vec::new() });
/// Le nombre de crochets posés : sans eux, PeekMessage ne prend aucun verrou.
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// Les types posés sans être encore appelés, déjà journalisés (un bit par
/// type).
static REPORTED: AtomicU32 = AtomicU32::new(0);

/// Le type est appelé par Mino.
const fn is_called(id: i32) -> bool {
    matches!(id, wh::GETMESSAGE | wh::MSGFILTER | wh::SYSMSGFILTER | wh::CBT)
}

/// Ce que `lParam` désigne pour la procédure d'un crochet, copié après ses
/// arguments dans le rappel (co_IntCallHookProc), et ce qu'elle peut y
/// changer.
pub enum HookParam<'a> {
    /// Un MSG (WH_GETMESSAGE, WH_MSGFILTER, WH_SYSMSGFILTER) ; WH_GETMESSAGE
    /// reprend ce que la procédure y laisse.
    Message(&'a mut Msg32),
    /// WH_CBT, HCBT_CREATEWND : le CREATESTRUCTW de la fenêtre créée et la
    /// fenêtre après laquelle elle vient ; la procédure peut changer sa
    /// place, sa taille et cette fenêtre.
    CreateWindow(&'a mut CbtCreateWndExtra32),
}

/// Le type ne se pose que global.
const fn is_global_only(id: i32) -> bool {
    matches!(id, wh::JOURNALRECORD | wh::JOURNALPLAYBACK | wh::KEYBOARD_LL | wh::MOUSE_LL | wh::SYSMSGFILTER)
}

/// Le type demande un module pour accrocher un autre processus.
const fn needs_module(id: i32) -> bool {
    matches!(
        id,
        wh::GETMESSAGE
            | wh::CALLWNDPROC
            | wh::CBT
            | wh::HARDWARE
            | wh::DEBUG
            | wh::SHELL
            | wh::FOREGROUNDIDLE
            | wh::CALLWNDPROCRET
    )
}

/// Ce que demande SetWindowsHookEx.
pub struct Request {
    /// hMod : le module de la procédure (0 sans).
    pub module: u32,
    /// Le chemin du module, sans nul.
    pub module_name: Vec<u16>,
    /// Le thread à accrocher (0 : global).
    pub thread_id: u32,
    pub id: i32,
    pub proc_: u32,
    pub ansi: bool,
}

/// Écrit le `fsHooks` du `CLIENTINFO` du thread `pti`, s'il vit encore.
fn write_thread_flags(pti: u32, flags: u32) {
    let Some(tid) = crate::gui::thread_of_server_address(pti) else { return };
    let Ok(thread) = ps::ethread::lookup_thread(tid) else { return };
    let at = u64::from(thread.teb())
        + offset_of!(Teb32, win32_client_info) as u64
        + offset_of!(ClientInfo32, fs_hooks) as u64;
    let _ = thread.process().write_memory(at, &flags.to_le_bytes());
}

/// Écrit le `fsHooks` du `DESKTOPINFO` du bureau dont `heap` est le tas.
fn write_desktop_flags(heap: &DesktopHeap, desk_info: u32, flags: u32) {
    let at = u64::from(desk_info) + offset_of!(DeskInfoHead32, fs_hooks) as u64;
    let _ = heap.section.write_kernel(at, &flags.to_le_bytes());
}

/// Le `fsHooks` de la chaîne `chain` est réécrit là où `user32` le lit.
fn publish_flags(chain: Chain, desktop: Option<(&DesktopHeap, u32)>) {
    let flags = flags_of(&TABLE.lock().places(), chain);
    match (chain, desktop) {
        (Chain::Thread(pti), _) => write_thread_flags(pti, flags),
        (Chain::Desktop(_), Some((heap, desk_info))) => write_desktop_flags(heap, desk_info, flags),
        (Chain::Desktop(_), None) => {}
    }
}

/// `phkCurrent` du `CLIENTINFO` du thread courant devient `address`.
fn set_client_current(address: u32) {
    let Some(thread) = ps::ethread::current_thread() else { return };
    let at = u64::from(thread.teb())
        + offset_of!(Teb32, win32_client_info) as u64
        + offset_of!(ClientInfo32, phk_current) as u64;
    let _ = ke::usermem::copy_to_user(at, &address.to_le_bytes());
}

/// NtUserSetWindowsHookEx : le crochet `request`, posé par le thread
/// courant `thread` ; rend son handle.
///
/// # Errors
/// Une erreur Win32 : `ERROR_INVALID_HOOK_FILTER` (type inconnu),
/// `ERROR_INVALID_FILTER_PROC` (sans procédure), `ERROR_GLOBAL_ONLY_HOOK`,
/// `ERROR_INVALID_PARAMETER` (pas un thread GUI), `ERROR_ACCESS_DENIED`
/// (sans bureau, ou un autre bureau), `ERROR_HOOK_NEEDS_HMOD`,
/// `ERROR_HOOK_TYPE_NOT_ALLOWED` (un thread de `csrss` ou du système),
/// `ERROR_NOT_ENOUGH_MEMORY`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_windows_hook(thread: &ThreadInfo, request: Request) -> Result<u32, u32> {
    let id = request.id;
    if !(wh::MIN..=wh::MAX).contains(&id) {
        return Err(ERROR_INVALID_HOOK_FILTER);
    }
    if request.proc_ == 0 {
        return Err(ERROR_INVALID_FILTER_PROC);
    }
    let pid = ps::ethread::current_thread().map_or(0, |current| current.process().pid());
    let desktop = thread.desktop().ok_or(ERROR_ACCESS_DENIED)?.desktop;
    let hooked = if request.thread_id != 0 {
        if is_global_only(id) {
            return Err(ERROR_GLOBAL_ONLY_HOOK);
        }
        let target = ps::ethread::lookup_thread(request.thread_id).map_err(|_| ERROR_INVALID_PARAMETER)?;
        let info = crate::gui::thread_info(target.win32_thread().ok_or(ERROR_INVALID_PARAMETER)?);
        let other = info.desktop().ok_or(ERROR_ACCESS_DENIED)?.desktop;
        if !Arc::ptr_eq(&other, &desktop) {
            return Err(ERROR_ACCESS_DENIED);
        }
        if target.process().pid() != pid {
            if request.module == 0 && needs_module(id) {
                return Err(ERROR_HOOK_NEEDS_HMOD);
            }
            if info.ti_flags & (TIF_CSRSSTHREAD | TIF_SYSTEMTHREAD) != 0 && needs_module(id) {
                return Err(ERROR_HOOK_TYPE_NOT_ALLOWED);
            }
        }
        Some(info.server)
    } else {
        if request.module == 0 && (needs_module(id) || id == wh::SYSMSGFILTER) {
            return Err(ERROR_HOOK_NEEDS_HMOD);
        }
        None
    };
    if !is_called(id) && REPORTED.fetch_or(hook_flag(id), Ordering::Relaxed) & hook_flag(id) == 0 {
        log::warn!("win32k: a hook of type {id} is set, but hooks of that type are not called yet");
    }
    let heap = desktop.heap.clone();
    let size = size_of::<Hook32>() as u32;
    let at = heap.alloc(size).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    let owner = hooked.unwrap_or(thread.server);
    let handle = match crate::handles::alloc(heap.server_address(at), owner, TYPE_HOOK) {
        Ok(handle) => handle,
        Err(_) => {
            heap.free(at, size);
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
    };
    let off_pfn = if request.module != 0 { request.proc_.wrapping_sub(request.module) } else { 0 };
    let object = Hook32 {
        handle,
        pti: owner,
        desktop: heap.server_address(0),
        self_: heap.server_address(at),
        hook_id: id,
        off_pfn,
        ihmod: request.module,
        pti_hooked: hooked.unwrap_or(0),
        rpdesk: heap.server_address(0),
        proc_: request.proc_,
        ansi: u32::from(request.ansi),
        ..Hook32::default()
    };
    let _ = heap.section.write_kernel(u64::from(at), object.as_bytes());
    let place = Place { handle, id, hooked, desktop: Arc::as_ptr(&heap) as usize };
    let hook = Arc::new(Hook {
        place,
        proc_: request.proc_,
        module: request.module,
        off_pfn,
        ansi: request.ansi,
        module_name: request.module_name,
        owner,
        installer: thread.server,
        installer_pid: pid,
        heap,
        at,
        desk_info: desktop.desk_info,
    });
    TABLE.lock().hooks.insert(0, hook);
    COUNT.fetch_add(1, Ordering::Relaxed);
    publish_flags(place.chain(), Some((&desktop.heap, desktop.desk_info)));
    Ok(handle)
}

/// IntRemoveHook : le crochet `handle` quitte sa chaîne et rend son handle ;
/// le `fsHooks` de sa chaîne est réécrit. Rend s'il existait.
fn remove(handle: u32) -> bool {
    let removed = {
        let mut table = TABLE.lock();
        let at = table.hooks.iter().position(|hook| hook.place.handle == handle);
        at.map(|at| table.hooks.remove(at))
    };
    let Some(hook) = removed else { return false };
    COUNT.fetch_sub(1, Ordering::Relaxed);
    let _ = crate::handles::free(handle);
    publish_flags(hook.place.chain(), Some((&*hook.heap, hook.desk_info)));
    true
}

/// NtUserUnhookWindowsHookEx : le crochet `handle` est retiré.
///
/// # Errors
/// `ERROR_INVALID_HOOK_HANDLE` pour un handle qui n'est pas un crochet.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn unhook(handle: u32) -> Result<(), u32> {
    if remove(handle) {
        Ok(())
    } else {
        Err(ERROR_INVALID_HOOK_HANDLE)
    }
}

/// Ce qu'un appel de procédure demande, pris du crochet avant l'appel.
struct ProcCall {
    id: i32,
    proc_: u32,
    module: u32,
    off_pfn: u32,
    ansi: bool,
    module_name: Vec<u16>,
}

impl ProcCall {
    fn of(hook: &Hook) -> Self {
        Self {
            id: hook.place.id,
            proc_: hook.proc_,
            module: hook.module,
            off_pfn: hook.off_pfn,
            ansi: hook.ansi,
            module_name: hook.module_name.clone(),
        }
    }
}

/// Les arguments du rappel d'une procédure de crochet
/// (HOOKPROC_CALLBACK_ARGUMENTS, puis ce que désigne `lParam` : le MSG, ou
/// HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS).
fn arguments(call: &ProcCall, code: i32, w_param: u32, param: &HookParam<'_>) -> Vec<u8> {
    let mut arguments = HookProcArguments32 {
        hook_id: call.id,
        code,
        w_param,
        l_param: size_of::<HookProcArguments32>() as u32,
        proc_: call.proc_,
        module: call.module,
        off_pfn: call.off_pfn,
        ansi: u32::from(call.ansi),
        ..HookProcArguments32::default()
    };
    let length = call.module_name.len().min(arguments.module_name.len() - 1);
    arguments.module_name[..length].copy_from_slice(&call.module_name[..length]);
    let mut bytes = arguments.as_bytes().to_vec();
    match param {
        HookParam::Message(message) => bytes.extend_from_slice(message.as_bytes()),
        HookParam::CreateWindow(create) => bytes.extend_from_slice(create.as_bytes()),
    }
    bytes
}

/// Le HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS que rend le rappel, après les
/// arguments.
fn returned_create(output: &[u8]) -> Option<CbtCreateWndExtra32> {
    let bytes = output.get(size_of::<HookProcArguments32>()..)?.get(..size_of::<CbtCreateWndExtra32>())?;
    let word = |i: usize| u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    Some(CbtCreateWndExtra32 {
        create_struct: CreateStructW32 {
            create_params: word(0),
            instance: word(1),
            menu: word(2),
            parent: word(3),
            cy: word(4) as i32,
            cx: word(5) as i32,
            y: word(6) as i32,
            x: word(7) as i32,
            style: word(8),
            name: word(9),
            class: word(10),
            ex_style: word(11),
        },
        insert_after: word(12),
    })
}

/// Le MSG que rend le rappel, après les arguments.
fn returned_message(output: &[u8]) -> Option<Msg32> {
    let bytes = output.get(size_of::<HookProcArguments32>()..)?.get(..size_of::<Msg32>())?;
    let word = |i: usize| u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    Some(Msg32 {
        hwnd: word(0),
        message: word(1),
        w_param: word(2),
        l_param: word(3),
        time: word(4),
        pt_x: word(5) as i32,
        pt_y: word(6) as i32,
    })
}

/// co_IntCallHookProc : `user32` appelle la procédure de `call` avec `code`,
/// `w_param` et `param` ; rend ce qu'elle rend (0 si le rappel échoue). Pour
/// WH_GETMESSAGE, le message reprend ce que la procédure y a laissé ; pour
/// HCBT_CREATEWND, la place, la taille et la fenêtre d'avant (ce que
/// `user32` réécrit).
fn call_proc(call: ProcCall, code: i32, w_param: u32, param: &mut HookParam<'_>) -> u32 {
    let bytes = arguments(&call, code, w_param, param);
    let id = call.id;
    drop(call);
    let Ok(output) = ps::callback::user_mode_callback(USER32_CALLBACK_HOOKPROC, &bytes, bytes.len()) else {
        return 0;
    };
    let at = offset_of!(HookProcArguments32, result);
    let Some(result) = output.get(at..at + 4) else { return 0 };
    match param {
        HookParam::Message(message) if id == wh::GETMESSAGE => {
            if let Some(changed) = returned_message(&output) {
                **message = changed;
            }
        }
        HookParam::CreateWindow(create) => {
            if let Some(changed) = returned_create(&output) {
                create.create_struct.x = changed.create_struct.x;
                create.create_struct.y = changed.create_struct.y;
                create.create_struct.cx = changed.create_struct.cx;
                create.create_struct.cy = changed.create_struct.cy;
                create.insert_after = changed.insert_after;
            }
        }
        HookParam::Message(_) => {}
    }
    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

/// co_HOOK_CallHooks : les crochets de type `id` du thread courant `thread`
/// sont appelés avec `code`, `w_param` et `param` (sa chaîne, puis les
/// crochets globaux de son bureau) ; rend ce qu'a rendu le dernier appelé, 0
/// sans crochet.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir : rappelle le
/// mode utilisateur.
pub fn call_hooks(thread: &ThreadInfo, id: i32, code: i32, w_param: u32, param: &mut HookParam<'_>) -> u32 {
    if COUNT.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let pti = thread.server;
    let Some(desktop) = thread.desktop() else { return 0 };
    let desktop_key = Arc::as_ptr(&desktop.desktop.heap) as usize;
    drop(desktop);
    let (first, globals) = {
        let table = TABLE.lock();
        let places = table.places();
        let first = chain_of(&places, id, Chain::Thread(pti)).first().and_then(|&handle| table.get(handle));
        (first, chain_of(&places, id, Chain::Desktop(desktop_key)))
    };
    let mut result = 0;
    if let Some(first) = first {
        let handle = first.place.handle;
        let (call, address, saved) = {
            let mut table = TABLE.lock();
            table.link_next(&first);
            let saved = table.set_current(pti, Some(first.clone()));
            (ProcCall::of(&first), first.address(), saved)
        };
        let saved_address = saved.as_ref().map_or(0, |saved| saved.address());
        drop(first);
        set_client_current(address);
        result = call_proc(call, code, w_param, param);
        set_client_current(saved_address);
        let (done, first) = {
            let mut table = TABLE.lock();
            (table.set_current(pti, saved), table.get(handle))
        };
        for hook in done.iter().chain(first.iter()) {
            hook.set_next(0);
        }
        drop((done, first));
    }
    let pid = ps::ethread::current_thread().map_or(0, |current| current.process().pid());
    for handle in globals {
        let call = {
            let table = TABLE.lock();
            table
                .get(handle)
                .filter(|hook| hook.owner == pti || hook.installer_pid == pid)
                .map(|hook| ProcCall::of(&hook))
        };
        if let Some(call) = call {
            result = call_proc(call, code, w_param, param);
        }
    }
    result
}

/// WH_CBT, HCBT_CREATEWND (co_UserCreateWindowEx) : la fenêtre `hwnd` que
/// le thread courant `thread` crée, avant WM_GETMINMAXINFO et WM_NCCREATE,
/// avec son CREATESTRUCTW et la fenêtre après laquelle elle vient
/// (`create`, que les crochets peuvent changer : place, taille, fenêtre
/// d'avant). Rend ce qu'ils rendent : non nul, la création est refusée.
///
/// # IRQL
/// Comme [`call_hooks`].
pub fn create_window(thread: &ThreadInfo, hwnd: u32, create: &mut CbtCreateWndExtra32) -> u32 {
    call_hooks(thread, wh::CBT, hcbt::CREATEWND, hwnd, &mut HookParam::CreateWindow(create))
}

/// WH_GETMESSAGE : le message `message` que PeekMessage ou GetMessage va
/// rendre au thread courant `thread`, sorti de la file si `removed` ; les
/// crochets peuvent le changer.
///
/// # IRQL
/// Comme [`call_hooks`].
pub fn get_message(thread: &ThreadInfo, message: &mut Msg32, removed: bool) {
    let _ =
        call_hooks(thread, wh::GETMESSAGE, abi::user::HC_ACTION, u32::from(removed), &mut HookParam::Message(message));
}

/// IntCallMsgFilter : WH_SYSMSGFILTER, puis WH_MSGFILTER si le premier rend
/// 0, pour le message `message` du thread courant `thread` dans une boucle
/// de type `code` (`MSGF_*`) ; rend ce qu'ils rendent (non nul : le message
/// est traité).
///
/// # IRQL
/// Comme [`call_hooks`].
pub fn call_msg_filter(thread: &ThreadInfo, message: &mut Msg32, code: i32) -> u32 {
    match call_hooks(thread, wh::SYSMSGFILTER, code, 0, &mut HookParam::Message(message)) {
        0 => call_hooks(thread, wh::MSGFILTER, code, 0, &mut HookParam::Message(message)),
        handled => handled,
    }
}

/// NtUserCallNextHookEx : le crochet qui suit le crochet courant du thread
/// courant `thread` est appelé avec `code`, `w_param` et `param` (lu en
/// `lParam` par l'appelant, réécrit pour WH_GETMESSAGE et HCBT_CREATEWND) ;
/// il devient le crochet courant. Rend ce qu'il rend ; 0 sans crochet
/// courant ou sans suivant. Le suivant est celui de la chaîne au moment de
/// l'appel (ReactOS garde celui de l'appel du crochet courant).
///
/// # IRQL
/// Comme [`call_hooks`].
pub fn call_next(thread: &ThreadInfo, code: i32, w_param: u32, param: &mut HookParam<'_>) -> u32 {
    let pti = thread.server;
    let next = {
        let mut table = TABLE.lock();
        let Some(current) = table.current_of(pti) else { return 0 };
        let next = next_of(&table.places(), current.place.handle).and_then(|next| table.get(next));
        if let Some(next) = &next {
            table.link_next(next);
        }
        drop(table.set_current(pti, next.clone()));
        next
    };
    set_client_current(next.as_ref().map_or(0, |next| next.address()));
    let Some(next) = next else { return 0 };
    let call = ProcCall::of(&next);
    drop(next);
    if is_called(call.id) {
        call_proc(call, code, w_param, param)
    } else {
        0
    }
}

/// Le type du crochet courant du thread courant `thread`, s'il en a un
/// (son `lParam` : un MSG pour WH_GETMESSAGE, WH_MSGFILTER et
/// WH_SYSMSGFILTER, un CBT_CREATEWNDW pour HCBT_CREATEWND de WH_CBT).
pub fn current_id(thread: &ThreadInfo) -> Option<i32> {
    TABLE.lock().current_of(thread.server).map(|hook| hook.place.id)
}

/// HOOK_DestroyThreadHooks : le thread `pti` se termine ; les crochets qui
/// l'accrochent et ceux qu'il a posés sont retirés, son crochet courant
/// oublié. Rend combien.
///
/// # IRQL
/// PASSIVE_LEVEL, à la fin du thread (aucun rappel).
pub fn thread_exit(pti: u32) -> usize {
    let handles: Vec<u32> = {
        let mut table = TABLE.lock();
        drop(table.set_current(pti, None));
        table
            .hooks
            .iter()
            .filter(|hook| hook.place.hooked == Some(pti) || hook.installer == pti || hook.owner == pti)
            .map(|hook| hook.place.handle)
            .collect()
    };
    handles.iter().filter(|&&handle| remove(handle)).count()
}

/// La fin d'un processus : un crochet qui reste à son nom (`handle`) est
/// retiré ; rend s'il existait.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy(handle: u32) -> bool {
    remove(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u32 = 0x9000_0010;
    const B: u32 = 0x9000_0020;

    fn local(handle: u32, id: i32, pti: u32) -> Place {
        Place { handle, id, hooked: Some(pti), desktop: 1 }
    }

    fn global(handle: u32, id: i32, desktop: usize) -> Place {
        Place { handle, id, hooked: None, desktop }
    }

    #[test]
    fn the_last_hook_set_is_called_first_in_its_own_chain() {
        // Newest first, as SetWindowsHookEx inserts them.
        let places = [
            local(0x30, wh::GETMESSAGE, A),
            local(0x2E, wh::MSGFILTER, A),
            local(0x2C, wh::GETMESSAGE, B),
            local(0x2A, wh::GETMESSAGE, A),
            global(0x28, wh::GETMESSAGE, 1),
        ];
        assert_eq!(chain_of(&places, wh::GETMESSAGE, Chain::Thread(A)), [0x30, 0x2A]);
        assert_eq!(chain_of(&places, wh::GETMESSAGE, Chain::Thread(B)), [0x2C]);
        assert_eq!(chain_of(&places, wh::MSGFILTER, Chain::Thread(A)), [0x2E]);
        assert_eq!(chain_of(&places, wh::GETMESSAGE, Chain::Desktop(1)), [0x28], "the global one alone");
        assert_eq!(chain_of(&places, wh::GETMESSAGE, Chain::Desktop(2)), [], "another desktop");
        assert_eq!(next_of(&places, 0x30), Some(0x2A), "the next of its type and thread");
        assert_eq!(next_of(&places, 0x2A), None, "the end of the chain");
        assert_eq!(next_of(&places, 0x2C), None, "B's chain");
        assert_eq!(next_of(&places, 0x28), None);
        assert_eq!(next_of(&places, 0x99), None, "no such hook");
    }

    #[test]
    fn a_chain_has_a_bit_per_hooked_type() {
        let places = [local(0x30, wh::GETMESSAGE, A), local(0x2E, wh::MSGFILTER, A), global(0x2C, wh::SHELL, 1)];
        assert_eq!(flags_of(&places, Chain::Thread(A)), (1 << 4) | 1, "HOOKID_TO_FLAG: 1 << (id + 1)");
        assert_eq!(flags_of(&places, Chain::Thread(B)), 0);
        assert_eq!(flags_of(&places, Chain::Desktop(1)), 1 << 11);
    }

    #[test]
    fn some_types_are_global_only_or_need_a_module() {
        assert!(is_global_only(wh::MOUSE_LL) && is_global_only(wh::SYSMSGFILTER));
        assert!(!is_global_only(wh::GETMESSAGE) && !is_global_only(wh::MSGFILTER));
        assert!(needs_module(wh::GETMESSAGE) && !needs_module(wh::MSGFILTER) && !needs_module(wh::KEYBOARD));
    }

    #[test]
    fn a_message_hook_gets_the_message_after_its_arguments() {
        let call = ProcCall {
            id: wh::GETMESSAGE,
            proc_: 0x7AF1_7F3C,
            module: 0,
            off_pfn: 0,
            ansi: false,
            module_name: Vec::new(),
        };
        let mut message =
            Msg32 { hwnd: 0x2_0086, message: 0x201, w_param: 1, l_param: 0x0010_0020, ..Msg32::default() };
        let sent = message;
        let bytes = arguments(&call, 0, 1, &HookParam::Message(&mut message));
        assert_eq!(bytes.len(), 0x428 + 28);
        assert_eq!(bytes[..4], wh::GETMESSAGE.to_le_bytes());
        assert_eq!(bytes[12..16], 0x428u32.to_le_bytes(), "lParam: the MSG's offset");
        assert_eq!(bytes[16..20], 0x7AF1_7F3Cu32.to_le_bytes(), "the procedure");
        assert_eq!(returned_message(&bytes), Some(sent), "the MSG read back");
        assert_eq!(returned_message(&bytes[..0x428 + 20]), None, "too short");
    }

    #[test]
    fn a_cbt_hook_gets_the_created_window_after_its_arguments() {
        assert!(is_called(wh::CBT), "MFC ties its CWnd to a window in HCBT_CREATEWND");
        let call =
            ProcCall { id: wh::CBT, proc_: 0x5F40_1234, module: 0, off_pfn: 0, ansi: true, module_name: Vec::new() };
        let mut create = CbtCreateWndExtra32 {
            create_struct: CreateStructW32 {
                create_params: 0x0012_F000,
                instance: 0x0040_0000,
                cx: 300,
                cy: 200,
                x: 10,
                y: 20,
                style: 0x94C8_00C4,
                name: 0x0012_FE00,
                class: 0x8002,
                ..CreateStructW32::default()
            },
            insert_after: 0,
        };
        let sent = create;
        let bytes = arguments(&call, hcbt::CREATEWND, 0x2_0090, &HookParam::CreateWindow(&mut create));
        assert_eq!(bytes.len(), 0x428 + 0x34, "HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS after the arguments");
        assert_eq!(bytes[..4], wh::CBT.to_le_bytes());
        assert_eq!(bytes[4..8], hcbt::CREATEWND.to_le_bytes());
        assert_eq!(bytes[8..12], 0x2_0090u32.to_le_bytes(), "wParam: the window");
        assert_eq!(bytes[12..16], 0x428u32.to_le_bytes(), "lParam: the record's offset");
        assert_eq!(bytes[28..32], 1u32.to_le_bytes(), "an ANSI procedure");
        assert_eq!(returned_create(&bytes), Some(sent), "the record read back");
        assert_eq!(returned_create(&bytes[..0x428 + 0x30]), None, "too short");
    }
}
