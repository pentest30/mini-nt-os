//! Les processus et threads GUI : ce que win32k garde d'eux
//! (`PROCESSINFO`, `THREADINFO`), créé quand un thread fait son premier
//! appel à win32k (PsConvertToGuiThread, puis les rappels de win32k pour le
//! processus et le thread : InitProcessCallback, InitThreadCallback).
//!
//! Un processus GUI reçoit sa vue de la section partagée de USER
//! ([`crate::shared`]), et son PEB la limite des lots de GDI
//! (`GdiDCAttributeList`). Un thread GUI reçoit, dans son TEB, son
//! `THREADINFO` (`Win32ThreadInfo`) et son `CLIENTINFO`
//! (`Win32ClientInfo`), que `user32` lit.
//!
//! Le `PROCESSINFO` et le `THREADINFO` ne sont vus des clients que par une
//! adresse du serveur, qu'ils comparent sans la suivre (ADR-021) :
//! [`process_server_address`], [`thread_server_address`].
//!
//! Un thread GUI peut être sur un bureau ([`set_thread_desktop`]) : son
//! processus voit alors le tas du bureau, et son `CLIENTINFO` y désigne le
//! `DESKTOPINFO` et son `CLIENTTHREADINFO`.
//!
//! Pas encore : la pile noyau agrandie d'un thread GUI (pour les rappels du
//! mode utilisateur), la file de messages, ce qui est rendu à la fin d'un
//! thread ou d'un processus GUI (son bureau, ses vues), la disposition du
//! clavier (`hKL` et `CodePage` restent nuls, comme sous ReactOS sans
//! disposition chargée), la table des handles de GDI
//! (`GdiSharedHandleTable` reste nul).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::peb32::Peb32;
use abi::teb32::Teb32;
use abi::user::{ClientInfo32, ClientThreadInfo32, TIF_CSRSSTHREAD, TIF_DONTATTACHQUEUE, TIF_SYSTEMTHREAD};
use hal::sync::KSpinLock;
use ob::{AccessMask, Object};
use ps::{EProcess, EThread};

use mm::address_space::ViewOptions;
use mm::vad::PageProtect;

use crate::desktop::Desktop;
use crate::keyboard::KeyboardLayout;
use crate::queue::MessageQueue;
use crate::winsta::WindowStation;

/// GDI_BATCH_LIMIT : les appels de GDI qu'un client met en lot au plus
/// (`PEB.GdiDCAttributeList`).
pub const GDI_BATCH_LIMIT: u32 = abi::gdi::GDI_BATCH_LIMIT;

/// Ce que win32k garde d'un processus GUI (`PROCESSINFO`).
pub struct ProcessInfo {
    /// Son adresse du serveur, que voient les clients (`CLIENTINFO.ppi`).
    pub server: u32,
    /// L'adresse de sa vue de la section partagée de USER.
    pub shared_view: u32,
    /// L'adresse de sa vue de la table des handles GDI
    /// (`PEB.GdiSharedHandleTable`).
    pub gdi_view: u32,
    /// Les places libres pour les attributs de ses DC (`pPoolDcAttr`).
    pub dc_attrs: KSpinLock<crate::gdi::dc::AttrPool>,
    /// Sa station de fenêtres (`hwinsta`, `prpwinsta`, `amwinsta`).
    window_station: KSpinLock<Option<ProcessWindowStation>>,
    /// Ses vues des tas de bureau (HeapMappings), une par bureau, avec le
    /// nombre de ses threads sur lui.
    desktop_views: KSpinLock<Vec<DesktopView>>,
    /// Son bureau de démarrage (`hdeskStartup`, `rpdeskStartup`).
    startup_desktop: KSpinLock<Option<(u32, Arc<Object<Desktop>>)>>,
    /// Ses classes de fenêtres (`pclsPrivateList`, `pclsPublicList`).
    pub classes: KSpinLock<crate::class::ClassLists>,
    /// Son `STARTUPINFO` (`usi`), lu de ses paramètres au premier besoin :
    /// la première fenêtre recouvrante montrée en prend la commande
    /// (`STARTF_USESHOWWINDOW`), une seule fois.
    pub startup: KSpinLock<Option<crate::window::StartupPlace>>,
}

/// La vue d'un tas de bureau dans un processus.
struct DesktopView {
    desktop: Arc<Object<Desktop>>,
    view: u32,
    threads: u32,
}

/// La station de fenêtres d'un processus : le handle qu'il a donné, la
/// station, et les droits de ce handle.
#[derive(Clone)]
pub struct ProcessWindowStation {
    pub handle: u32,
    pub station: Arc<Object<WindowStation>>,
    pub access: AccessMask,
}

impl ProcessInfo {
    /// Un processus GUI sans station.
    pub fn new(server: u32, shared_view: u32, gdi_view: u32) -> Self {
        Self {
            server,
            shared_view,
            gdi_view,
            dc_attrs: KSpinLock::new(crate::gdi::dc::AttrPool::default()),
            window_station: KSpinLock::new(None),
            desktop_views: KSpinLock::new(Vec::new()),
            startup_desktop: KSpinLock::new(None),
            classes: KSpinLock::new(crate::class::ClassLists::default()),
            startup: KSpinLock::new(None),
        }
    }

    /// Son bureau de démarrage : le handle, et le bureau.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn startup_desktop(&self) -> Option<(u32, Arc<Object<Desktop>>)> {
        self.startup_desktop.lock().clone()
    }

    /// L'adresse de sa vue du tas de `desktop`, s'il en a une.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn desktop_view(&self, desktop: &Arc<Object<Desktop>>) -> Option<u32> {
        let views = self.desktop_views.lock();
        views.iter().find(|view| Arc::ptr_eq(&view.desktop, desktop)).map(|view| view.view)
    }

    /// Sa vue du tas `heap` d'un bureau, s'il le voit.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn heap_view(&self, heap: &crate::desktop::DesktopHeap) -> Option<u32> {
        let views = self.desktop_views.lock();
        views.iter().find(|view| core::ptr::eq(&*view.desktop.heap, heap)).map(|view| view.view)
    }

    /// IntMapDesktopView : sa vue du tas de `desktop`, projetée au premier de
    /// ses threads sur ce bureau (lecture seule, `SEC_NO_CHANGE`).
    fn map_desktop(&self, process: &EProcess, desktop: &Arc<Object<Desktop>>) -> Result<u32, NtStatus> {
        if let Some(view) = self.count_view(desktop) {
            return Ok(view);
        }
        let heap = &desktop.heap;
        let options = ViewOptions { top_down: false, no_change: true };
        let size = u64::from(heap.size);
        let view = process
            .with_space(|space| space.map_view_with(&heap.section, 0, 0, size, PageProtect::READONLY, options))??
            .base as u32;
        let mut views = self.desktop_views.lock();
        if let Some(other) = views.iter_mut().find(|other| Arc::ptr_eq(&other.desktop, desktop)) {
            // Another thread of the process mapped it meanwhile.
            other.threads += 1;
            let kept = other.view;
            drop(views);
            let _ = process.with_space(|space| space.unmap_view(u64::from(view)));
            return Ok(kept);
        }
        views.push(DesktopView { desktop: desktop.clone(), view, threads: 1 });
        Ok(view)
    }

    /// Un thread de plus sur `desktop`, si sa vue existe : rend l'adresse.
    fn count_view(&self, desktop: &Arc<Object<Desktop>>) -> Option<u32> {
        let mut views = self.desktop_views.lock();
        let view = views.iter_mut().find(|view| Arc::ptr_eq(&view.desktop, desktop))?;
        view.threads += 1;
        Some(view.view)
    }

    /// IntUnmapDesktopView : un thread de moins sur `desktop` ; la vue part
    /// avec le dernier.
    fn unmap_desktop(&self, process: &EProcess, desktop: &Arc<Object<Desktop>>) {
        let mut views = self.desktop_views.lock();
        let Some(index) = views.iter().position(|view| Arc::ptr_eq(&view.desktop, desktop)) else { return };
        views[index].threads -= 1;
        if views[index].threads > 0 {
            return;
        }
        let gone = views.remove(index);
        drop(views);
        let _ = process.with_space(|space| space.unmap_view(u64::from(gone.view)));
    }

    /// Sa station de fenêtres, s'il en a une.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn window_station(&self) -> Option<ProcessWindowStation> {
        self.window_station.lock().clone()
    }

    /// UserSetProcessWindowStation : `station` devient sa station (ou plus
    /// aucune) ; la précédente part une fois le verrou rendu.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_window_station(&self, station: Option<ProcessWindowStation>) {
        let previous = core::mem::replace(&mut *self.window_station.lock(), station);
        drop(previous);
    }
}

/// Ce que win32k garde d'un thread GUI (`THREADINFO`).
pub struct ThreadInfo {
    /// Son adresse du serveur (`TEB.Win32ThreadInfo`).
    pub server: u32,
    /// Ses `TIF_*`.
    pub ti_flags: u32,
    /// Son bureau (`rpdesk`, `hdesk`, `pcti`), s'il en a un.
    desktop: KSpinLock<Option<ThreadDesktop>>,
    /// Sa disposition de clavier (`KeyboardLayout`), s'il en a une.
    keyboard_layout: KSpinLock<Option<Arc<KeyboardLayout>>>,
    /// Sa file de messages (`MessageQueue`).
    pub queue: MessageQueue,
    /// Ses fenêtres (`WindowListHead`) : elles vivent autant que lui, en
    /// attendant DestroyWindow.
    pub windows: KSpinLock<Vec<Arc<crate::window::Window>>>,
}

/// Le bureau d'un thread : le handle qu'il a donné, le bureau, et la
/// position de son `CLIENTTHREADINFO` dans le tas du bureau.
#[derive(Clone)]
pub struct ThreadDesktop {
    pub handle: u32,
    pub desktop: Arc<Object<Desktop>>,
    pub client_thread_info: u32,
}

impl ThreadInfo {
    /// Un thread GUI sans bureau.
    pub fn new(server: u32, ti_flags: u32) -> Self {
        Self {
            server,
            ti_flags,
            desktop: KSpinLock::new(None),
            keyboard_layout: KSpinLock::new(None),
            queue: MessageQueue::new(),
            windows: KSpinLock::new(Vec::new()),
        }
    }

    /// Reporte les bits de réveil et de changement de sa file dans son
    /// `CLIENTTHREADINFO` (`fsChangeBits`, `fsWakeBits`), s'il est sur un
    /// bureau : `user32` les y lit.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn mirror_queue_bits(&self, wake: u16, change: u16) {
        let Some(desktop) = self.desktop() else { return };
        let at = u64::from(desktop.client_thread_info) + offset_of!(ClientThreadInfo32, fs_change_bits) as u64;
        let [c0, c1] = change.to_le_bytes();
        let [w0, w1] = wake.to_le_bytes();
        let _ = desktop.desktop.heap.section.write_kernel(at, &[c0, c1, w0, w1]);
    }

    /// Sa disposition de clavier, s'il en a une.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn keyboard_layout(&self) -> Option<Arc<KeyboardLayout>> {
        self.keyboard_layout.lock().clone()
    }

    /// `layout` devient sa disposition de clavier ; l'ancienne part une fois
    /// le verrou rendu.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_keyboard_layout(&self, layout: Arc<KeyboardLayout>) {
        let previous = self.keyboard_layout.lock().replace(layout);
        drop(previous);
    }

    /// Son bureau, s'il en a un.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn desktop(&self) -> Option<ThreadDesktop> {
        self.desktop.lock().clone()
    }
}

/// IntSetThreadDesktop : le thread courant passe sur le bureau `desktop`
/// (de handle `handle` ; `None` : plus aucun, pour `csrss`). Son processus
/// voit le tas du bureau, un `CLIENTTHREADINFO` y est pris pour lui, son
/// `CLIENTINFO` les désigne (`pDeskInfo`, `ulClientDelta`,
/// `pClientThreadInfo`) ; l'ancien bureau est quitté (son
/// `CLIENTTHREADINFO` rendu, la vue retirée avec le dernier thread). Un
/// thread qui n'est ni de `csrss` ni du système donne à son processus son
/// bureau de démarrage, s'il n'en a pas.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` hors d'un thread de Ps ; celles de la
/// projection, du tas et de l'écriture du TEB.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn set_thread_desktop(handle: u32, desktop: Option<Arc<Object<Desktop>>>) -> Result<(), NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    let info = convert_current_thread()?;
    let process = thread.process().clone();
    let process_info = process_info(&process)?;
    let current = info.desktop();
    if let (Some(current), Some(desktop)) = (&current, &desktop) {
        if Arc::ptr_eq(&current.desktop, desktop) {
            return Ok(());
        }
    }
    let next = match desktop {
        None => None,
        Some(desktop) => {
            let view = process_info.map_desktop(&process, &desktop)?;
            let cti = match desktop.heap.alloc(size_of::<ClientThreadInfo32>() as u32) {
                Ok(cti) => cti,
                Err(status) => {
                    process_info.unmap_desktop(&process, &desktop);
                    return Err(status);
                }
            };
            Some((ThreadDesktop { handle, desktop, client_thread_info: cti }, view))
        }
    };
    let client = match &next {
        None => DesktopClient::default(),
        Some((thread_desktop, view)) => DesktopClient::new(thread_desktop, *view),
    };
    if let Err(status) = write_desktop_client(&thread, &process, &client) {
        if let Some((thread_desktop, _)) = next {
            let size = size_of::<ClientThreadInfo32>() as u32;
            thread_desktop.desktop.heap.free(thread_desktop.client_thread_info, size);
            process_info.unmap_desktop(&process, &thread_desktop.desktop);
        }
        return Err(status);
    }
    let next = next.map(|(thread_desktop, _)| thread_desktop);
    if is_client_thread(info.ti_flags) {
        if let Some(next) = &next {
            let mut startup = process_info.startup_desktop.lock();
            if startup.is_none() {
                *startup = Some((next.handle, next.desktop.clone()));
            }
        }
    }
    let previous = core::mem::replace(&mut *info.desktop.lock(), next);
    if let Some(previous) = previous {
        previous.desktop.heap.free(previous.client_thread_info, size_of::<ClientThreadInfo32>() as u32);
        process_info.unmap_desktop(&process, &previous.desktop);
    }
    // The new CLIENTTHREADINFO gets the queue's bits (ReactOS copies the old
    // one).
    let ((), wake, change) = info.queue.with(|_| ());
    info.mirror_queue_bits(wake, change);
    Ok(())
}

/// Un thread de `TIF_*` `ti_flags` est un thread client : ni du système ni
/// de `csrss`. Il donne son bureau à son processus comme bureau de
/// démarrage, et `user32` le prépare à sa conversion (ClientThreadSetup).
pub const fn is_client_thread(ti_flags: u32) -> bool {
    ti_flags & (TIF_SYSTEMTHREAD | TIF_CSRSSTHREAD) == 0
}

/// Ce que le `CLIENTINFO` d'un thread dit de son bureau.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DesktopClient {
    /// pDeskInfo, dans la vue du processus.
    pub desk_info: u32,
    /// ulClientDelta.
    pub client_delta: u32,
    /// pClientThreadInfo, dans la vue du processus.
    pub client_thread_info: u32,
}

impl DesktopClient {
    /// Pour un thread sur `thread_desktop`, dont le processus voit le tas en
    /// `view`.
    pub fn new(thread_desktop: &ThreadDesktop, view: u32) -> Self {
        let delta = thread_desktop.desktop.heap.server_base.wrapping_sub(view);
        Self {
            desk_info: view + thread_desktop.desktop.desk_info,
            client_delta: delta,
            client_thread_info: view + thread_desktop.client_thread_info,
        }
    }
}

/// Écrit dans le `CLIENTINFO` du TEB de `thread` ce que dit `client`.
fn write_desktop_client(thread: &EThread, process: &EProcess, client: &DesktopClient) -> Result<(), NtStatus> {
    let info = u64::from(thread.teb()) + offset_of!(Teb32, win32_client_info) as u64;
    let words = [client.desk_info, client.client_delta];
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    process.write_memory(info + offset_of!(ClientInfo32, desk_info) as u64, &bytes)?;
    let cti = info + offset_of!(ClientInfo32, client_thread_info) as u64;
    process.write_memory(cti, &client.client_thread_info.to_le_bytes())
}

/// L'adresse du serveur du `PROCESSINFO` du processus `pid` : une adresse
/// de 16 octets par PID dans `0x80000000`–`0x8FFFFFFF`, unique tant qu'il
/// vit, où un client ne peut rien lire. Les PID sont sous 2^26 (la table des
/// CID a 2^24 entrées).
pub const fn process_server_address(pid: u32) -> u32 {
    0x8000_0000 | ((pid >> 2) << 4)
}

/// L'adresse du serveur du `THREADINFO` du thread `tid`, de même dans
/// `0x90000000`–`0x9FFFFFFF`.
pub const fn thread_server_address(tid: u32) -> u32 {
    0x9000_0000 | ((tid >> 2) << 4)
}

/// Le TID du thread d'adresse du serveur `pti` ([`thread_server_address`]),
/// si elle en est une.
pub const fn thread_of_server_address(pti: u32) -> Option<u32> {
    if pti & 0xF000_0000 != 0x9000_0000 || pti & 0xF != 0 {
        return None;
    }
    Some((pti & 0x0FFF_FFFF) >> 2)
}

/// Le `THREADINFO` du thread GUI d'adresse du serveur `pti`, s'il vit.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn thread_info_of(pti: u32) -> Option<Arc<ThreadInfo>> {
    let thread = ps::ethread::lookup_thread(thread_of_server_address(pti)?).ok()?;
    let info: Arc<ThreadInfo> = downcast(thread.win32_thread()?);
    (info.server == pti).then_some(info)
}

/// RtlGetExpWinVer : la version du système qu'attend une image de
/// sous-système `major.minor`, `MAKEWORD(minor, major)` ; une version 1
/// compte pour 3.10 (Windows 3.1).
pub const fn exp_win_ver(major: u32, minor: u32) -> u32 {
    if major == 1 {
        0x030A
    } else {
        ((major & 0xFF) << 8) | (minor & 0xFF)
    }
}

/// Les `TIF_*` d'un nouveau thread GUI : ceux de `csrss`
/// (`TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE`) pour un thread de `csrss`, et
/// pour tous tant que `csrss` ne s'est pas déclaré (InitThreadCallback de
/// ReactOS) ; aucun sinon.
pub const fn thread_flags(csrss: u32, pid: u32) -> u32 {
    if csrss == 0 || csrss == pid {
        TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE
    } else {
        0
    }
}

/// Le `PROCESSINFO` de `process`, créé s'il n'en a pas (InitProcessCallback,
/// GdiProcessCreate) : ses vues de la section partagée de USER et de la
/// table des handles GDI ; son PEB reçoit l'adresse de la seconde
/// (`GdiSharedHandleTable`) et la limite des lots de GDI.
///
/// # Errors
/// Celles des projections et de l'écriture du PEB (le processus reste
/// alors GUI, sans table de GDI dans son PEB) ;
/// `STATUS_PROCESS_IS_TERMINATING` pour un processus sans espace
/// d'adresses.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn process_info(process: &Arc<Object<EProcess>>) -> Result<Arc<ProcessInfo>, NtStatus> {
    if let Some(info) = process.win32_process() {
        return Ok(downcast(info));
    }
    let view = process.with_space(crate::shared::map_into)??;
    let gdi_view = match process.with_space(crate::gdi::handles::map_into) {
        Ok(Ok(gdi_view)) => gdi_view,
        Ok(Err(status)) | Err(status) => {
            let _ = process.with_space(|space| space.unmap_view(u64::from(view)));
            return Err(status);
        }
    };
    let created = Arc::new(ProcessInfo::new(process_server_address(process.pid()), view, gdi_view));
    let kept: Arc<ProcessInfo> = downcast(process.set_win32_process(created.clone()));
    if !Arc::ptr_eq(&kept, &created) {
        // Another thread of the process converted it first: its views are
        // the process's, not these.
        let _ = process.with_space(|space| {
            let _ = space.unmap_view(u64::from(view));
            let _ = space.unmap_view(u64::from(gdi_view));
        });
        return Ok(kept);
    }
    let peb = u64::from(process.peb());
    process.write_memory(peb + offset_of!(Peb32, gdi_shared_handle_table) as u64, &gdi_view.to_le_bytes())?;
    process.write_memory(peb + offset_of!(Peb32, gdi_dc_attribute_list) as u64, &GDI_BATCH_LIMIT.to_le_bytes())?;
    Ok(kept)
}

/// PsConvertToGuiThread : le thread courant devient un thread GUI, s'il ne
/// l'est pas, et son processus un processus GUI ; rend son `THREADINFO`.
/// Son TEB reçoit son `THREADINFO` et son `CLIENTINFO`. Un thread client
/// (ni du système ni de `csrss`) est ensuite préparé par `user32`
/// (ClientThreadSetup, [`crate::callback`]), comme à la fin
/// d'InitThreadCallback.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` hors d'un thread de Ps ; celles de
/// [`process_info`], de l'écriture du TEB et du rappel. Un rappel qui échoue
/// laisse le thread converti, contrairement à ReactOS, qui défait la
/// conversion : l'appel suivant ne le refait pas.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, à son appel système. Rappelle le mode
/// utilisateur à la conversion d'un thread client.
pub fn convert_current_thread() -> Result<Arc<ThreadInfo>, NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    if let Some(info) = thread.win32_thread() {
        return Ok(downcast(info));
    }
    let process = thread.process().clone();
    let process_info = process_info(&process)?;
    let info = Arc::new(ThreadInfo::new(
        thread_server_address(thread.tid()),
        thread_flags(crate::csrss::csrss(), process.pid()),
    ));
    write_teb(&thread, &process, &process_info, &info)?;
    let info: Arc<ThreadInfo> = downcast(thread.set_win32_thread(info));
    if !is_client_thread(info.ti_flags) {
        return Ok(info);
    }
    log::info!("win32k: ClientThreadSetup for thread {} of {}", thread.tid(), process.image_file_name());
    // Nothing held across the callback: a thread that ends in it drops
    // this frame.
    drop((thread, process, process_info, info));
    crate::callback::client_thread_setup()?;
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    Ok(downcast(thread.win32_thread().expect("a GUI thread stays one")))
}

/// Écrit dans le TEB de `thread` son `THREADINFO` et son `CLIENTINFO`.
fn write_teb(
    thread: &EThread,
    process: &EProcess,
    process_info: &ProcessInfo,
    info: &ThreadInfo,
) -> Result<(), NtStatus> {
    let mut version = [0u8; 8];
    let at = u64::from(process.peb()) + offset_of!(Peb32, image_subsystem_major_version) as u64;
    process.read_memory(at, &mut version)?;
    let major = u32::from_le_bytes([version[0], version[1], version[2], version[3]]);
    let minor = u32::from_le_bytes([version[4], version[5], version[6], version[7]]);
    let client = ClientInfo32 {
        exp_win_ver: exp_win_ver(major, minor),
        ti_flags: info.ti_flags,
        ppi: process_info.server,
        ..ClientInfo32::default()
    };
    let teb = u64::from(thread.teb());
    process.write_memory(teb + offset_of!(Teb32, win32_thread_info) as u64, &info.server.to_le_bytes())?;
    process.write_memory(teb + offset_of!(Teb32, win32_client_info) as u64, client.as_bytes())
}

/// Le `THREADINFO` que Ps garde pour un thread GUI (`EThread::win32_thread`).
pub fn thread_info(any: Arc<dyn core::any::Any + Send + Sync>) -> Arc<ThreadInfo> {
    downcast(any)
}

/// Ce que Ps garde pour win32k est toujours de ses types.
fn downcast<T: Send + Sync + 'static>(any: Arc<dyn core::any::Any + Send + Sync>) -> Arc<T> {
    any.downcast::<T>().unwrap_or_else(|_| panic!("a Win32 slot of Ps holds another type"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_are_unique_per_id_and_out_of_reach() {
        assert_eq!(process_server_address(4), 0x8000_0010);
        assert_eq!(process_server_address(0x03FF_FFFC), 0x8FFF_FFF0, "the last PID");
        assert_eq!(thread_server_address(8), 0x9000_0020);
        assert_eq!(thread_of_server_address(thread_server_address(8)), Some(8));
        assert_eq!(thread_of_server_address(thread_server_address(0x03FF_FFFC)), Some(0x03FF_FFFC), "the last TID");
        assert_eq!(thread_of_server_address(process_server_address(8)), None, "a process");
        assert_eq!(thread_of_server_address(0x9000_0024), None, "not a THREADINFO");
        assert_eq!(thread_of_server_address(0), None, "the desktop window's");
        assert_ne!(process_server_address(8), process_server_address(12));
    }

    #[test]
    fn the_expected_version_comes_from_the_subsystem_version() {
        assert_eq!(exp_win_ver(4, 0), 0x0400);
        assert_eq!(exp_win_ver(5, 1), 0x0501);
        assert_eq!(exp_win_ver(1, 0), 0x030A, "1.x is Windows 3.1");
    }

    #[test]
    fn only_client_threads_are_client_threads() {
        assert!(is_client_thread(0), "winlogon's thread");
        assert!(is_client_thread(TIF_DONTATTACHQUEUE));
        assert!(!is_client_thread(TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE), "a csrss thread");
        assert!(!is_client_thread(TIF_SYSTEMTHREAD), "a system thread");
    }

    #[test]
    fn threads_are_csrss_threads_until_csrss_is_known() {
        assert_eq!(thread_flags(0, 20), TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE);
        assert_eq!(thread_flags(20, 20), TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE);
        assert_eq!(thread_flags(20, 24), 0);
    }
}
