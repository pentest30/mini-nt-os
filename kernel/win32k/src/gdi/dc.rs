//! Les contextes de périphérique de l'écran (`dclife.c`, `dcattr.c`,
//! `dcobjs.c`, `bitblt.c`, `cliprgn.c` de ReactOS, comme spécification).
//!
//! Un DC peint dans sa région visible (à l'écran, déjà coupée à ce que
//! demande USER : [`crate::dce`]), à partir de son origine (le coin de la
//! zone cliente d'une fenêtre). Ses attributs (`DC_ATTR`) sont dans la
//! mémoire de son propriétaire, où `gdi32` les lit et les écrit sans appel
//! au noyau (GdiSelectBrush change `hbrush` et le marque `DC_BRUSH_DIRTY`) ;
//! le noyau les reprend quand il dessine (DC_vUpdateFillBrush). Un DC au
//! repos n'est à personne et n'a pas d'attributs ; celui qui le prend
//! ([`take`]) en reçoit de neufs, ceux d'un DC créé (DC_vSetOwner puis
//! IntGdiCleanDC : rien ne reste d'une prise à l'autre).
//!
//! Les attributs d'un processus sont pris dans des blocs de sa mémoire de
//! 64 Kio ([`AttrPool`], GdiPoolAllocate), rendus à sa fin avec elle.
//!
//! Pas encore : les DC en mémoire et leurs bitmaps, les régions de
//! découpage d'un client (SelectClipRgn), les transformations (le DC est en
//! MM_TEXT, ses matrices à zéro), les stylos (`hpen` reste nul), les DC
//! d'un autre propriétaire que le processus courant.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::dirty::{DC_BRUSH_DIRTY, DIRTY_FILL};
use abi::gdi::{objt, stock, DcAttr32, COMPLEXREGION, LO_DC_TYPE, NULLREGION, SIMPLEREGION};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use hal::sync::KSpinLock;
use ke::usermem::{copy_from_user, copy_to_user};
use mm::vad::PageProtect;
use mm::virtual_alloc::AllocType;

use super::brush::{Brush, STOCK_BRUSHES};
use super::dib::Rect;
use super::handles::{self, Object, OWNER_NONE};
use super::region::Region;

/// L'état d'un DC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DcState {
    /// Son propriétaire : son PID, et l'adresse de ses attributs chez lui.
    pub owner: Option<(u32, u32)>,
    /// L'origine de ses coordonnées, à l'écran (`ptlDCOrig`).
    pub origin: (i32, i32),
    /// Ce qu'il peut peindre, à l'écran (`prgnVis`, `prgnRao`).
    pub vis: Region,
    /// Son pinceau de remplissage (`dclevel.pbrFill`) : son handle, et lui.
    pub fill: Option<(u32, Brush)>,
}

/// Un DC.
pub struct Dc {
    state: KSpinLock<DcState>,
}

impl Default for Dc {
    /// Un DC à personne, qui ne peint rien.
    fn default() -> Self {
        Self { state: KSpinLock::new(DcState::default()) }
    }
}

impl Dc {
    /// Une copie de son état.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn state(&self) -> DcState {
        self.state.lock().clone()
    }

    /// Change son état.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn change<R>(&self, change: impl FnOnce(&mut DcState) -> R) -> R {
        change(&mut self.state.lock())
    }
}

/// Les octets d'un bloc d'attributs.
pub const ATTR_BLOCK: u32 = 0x1_0000;
/// La place des attributs d'un DC dans un bloc.
const ATTR_SIZE: u32 = size_of::<DcAttr32>() as u32;

/// Les attributs libres d'un processus, dans ses blocs.
#[derive(Debug, Default)]
pub struct AttrPool {
    free: Vec<u32>,
}

impl AttrPool {
    /// Une place libre ; `None` s'il n'y en a plus.
    pub fn take(&mut self) -> Option<u32> {
        self.free.pop()
    }

    /// Les places d'un bloc neuf, en `base` : la plus basse sera prise la
    /// première.
    pub fn add_block(&mut self, base: u32) {
        self.free.extend((0..ATTR_BLOCK / ATTR_SIZE).rev().map(|i| base + i * ATTR_SIZE));
    }

    /// Rend une place.
    pub fn give_back(&mut self, attr: u32) {
        self.free.push(attr);
    }
}

/// GdiPoolAllocate : une place pour les attributs d'un DC dans la mémoire du
/// processus courant, dans un bloc neuf s'il le faut.
fn allocate_attr() -> Result<(u32, u32), NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    let process = thread.process().clone();
    let info = crate::gui::process_info(&process)?;
    if let Some(attr) = info.dc_attrs.lock().take() {
        return Ok((process.pid(), attr));
    }
    let alloc_type = AllocType::MEM_RESERVE | AllocType::MEM_COMMIT;
    let base =
        process.with_space(|space| space.allocate(0, u64::from(ATTR_BLOCK), alloc_type, PageProtect::READWRITE))??;
    let mut pool = info.dc_attrs.lock();
    pool.add_block(base as u32);
    let attr = pool.take().expect("a new block has room");
    Ok((process.pid(), attr))
}

/// GdiPoolFree : rend la place `attr` au processus courant.
fn free_attr(attr: u32) {
    let Some(thread) = ps::ethread::current_thread() else { return };
    if let Ok(info) = crate::gui::process_info(thread.process()) {
        info.dc_attrs.lock().give_back(attr);
    }
}

/// Le PID du processus courant (0 hors d'un thread de Ps).
fn current_pid() -> u32 {
    ps::ethread::current_thread().map_or(0, |thread| thread.pid())
}

/// IntGdiCreateDC pour l'écran : un DC neuf, à personne ; rend son handle.
///
/// # Errors
/// Ceux de la table des handles.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn create_display_dc() -> Result<(u32, Arc<Dc>), NtStatus> {
    let dc = Arc::new(Dc::default());
    let handle = handles::insert(Object::Dc(dc.clone()), LO_DC_TYPE, objt::DC, OWNER_NONE)?;
    Ok((handle, dc))
}

/// DC_vSetOwner(GDI_OBJ_HMGR_POWNED) : le DC `handle` devient au processus
/// courant, avec les attributs d'un DC neuf chez lui (WHITE_BRUSH), sa
/// région visible `vis` et son origine `origin`.
///
/// # Errors
/// Ceux de l'allocation et de l'écriture des attributs, de la table.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn take(handle: u32, dc: &Dc, vis: Region, origin: (i32, i32)) -> Result<(), NtStatus> {
    let (pid, attr) = allocate_attr()?;
    let white = super::brush::stock_object(stock::WHITE_BRUSH);
    let (width, height) = crate::display::mode().map_or((0, 0), |mode| (mode.width as i32, mode.height as i32));
    let written = copy_to_user(u64::from(attr), DcAttr32::initial(white, 0, width, height).as_bytes())
        .and_then(|()| handles::set_owner(handle, pid, attr));
    if let Err(status) = written {
        free_attr(attr);
        return Err(status);
    }
    dc.change(|state| {
        *state =
            DcState { owner: Some((pid, attr)), origin, vis, fill: Some((white, STOCK_BRUSHES[stock::WHITE_BRUSH])) }
    });
    Ok(())
}

/// DC_vSetOwner(GDI_OBJ_HMGR_NONE) : le DC `handle` n'est plus à personne ;
/// ses attributs retournent au processus courant, son propriétaire.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn give_back(handle: u32, dc: &Dc) {
    let old = dc.change(core::mem::take);
    let _ = handles::set_owner(handle, OWNER_NONE, 0);
    if let Some((_, attr)) = old.owner {
        free_attr(attr);
    }
}

/// DC_LockDc : le DC de `hdc`, s'il est au processus courant.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn lock(hdc: u32) -> Option<Arc<Dc>> {
    match handles::get(hdc, current_pid())? {
        Object::Dc(dc) => Some(dc),
        Object::Brush(_) => None,
    }
}

/// Les octets du début des attributs : `pvLDC`, `ulDirty_`, `hbrush`.
const ATTR_HEAD: usize = offset_of!(DcAttr32, hbrush) + 4;

/// `ulDirty_` et `hbrush` des attributs en `attr`, chez le processus
/// courant.
fn read_attr(attr: u32) -> Result<(u32, u32), NtStatus> {
    let mut head = [0u8; ATTR_HEAD];
    copy_from_user(&mut head, u64::from(attr))?;
    let word = |at: usize| u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
    Ok((word(offset_of!(DcAttr32, dirty)), word(offset_of!(DcAttr32, hbrush))))
}

/// Écrit `ulDirty_` et `hbrush` dans les attributs en `attr`.
fn write_attr(attr: u32, dirty: u32, hbrush: u32) -> Result<(), NtStatus> {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dirty.to_le_bytes());
    bytes[4..].copy_from_slice(&hbrush.to_le_bytes());
    copy_to_user(u64::from(attr) + offset_of!(DcAttr32, dirty) as u64, &bytes)
}

/// DC_vUpdateFillBrush : le pinceau `hbrush` des attributs devient celui du
/// DC (`resolve` le trouve) ; un handle sans pinceau laisse l'ancien, que
/// les attributs reprennent. Rend le pinceau du DC, le `hbrush` des
/// attributs, et `dirty` sans `DIRTY_FILL | DC_BRUSH_DIRTY`.
pub fn updated_fill(
    fill: Option<(u32, Brush)>,
    hbrush: u32,
    dirty: u32,
    resolve: impl Fn(u32) -> Option<Brush>,
) -> (Option<(u32, Brush)>, u32, u32) {
    let clean = dirty & !(DIRTY_FILL | DC_BRUSH_DIRTY);
    if fill.is_some_and(|(handle, _)| handle == hbrush) {
        return (fill, hbrush, clean);
    }
    match (resolve(hbrush), fill) {
        (Some(brush), _) => (Some((hbrush, brush)), hbrush, clean),
        (None, Some((handle, _))) => (fill, handle, clean),
        (None, None) => (None, hbrush, clean),
    }
}

/// Le pinceau `handle`, s'il est au processus courant ou public.
fn resolve_brush(handle: u32) -> Option<Brush> {
    handles::brush(handle, current_pid()).map(|brush| *brush)
}

/// Le pinceau du DC après DC_vUpdateFillBrush, si ses attributs le
/// demandent (`DIRTY_FILL | DC_BRUSH_DIRTY`) : ceux-ci sont alors réécrits
/// sans ces bits. `hbrush` remplace celui des attributs (un appel en lot
/// apporte le sien) ; `restore` : les attributs restent ce qu'ils étaient
/// (GdiFlushUserBatch les rétablit après l'appel).
fn fill_brush(dc: &Dc, attr: u32, hbrush: Option<u32>, restore: bool) -> Result<Option<Brush>, NtStatus> {
    let (dirty, current) = read_attr(attr)?;
    if dirty & (DIRTY_FILL | DC_BRUSH_DIRTY) != 0 {
        let fill = dc.state().fill;
        let (fill, kept, clean) = updated_fill(fill, hbrush.unwrap_or(current), dirty, resolve_brush);
        dc.change(|state| state.fill = fill);
        if !restore {
            write_attr(attr, clean, kept)?;
        }
    }
    Ok(dc.state().fill.map(|(_, brush)| brush))
}

/// ROP3 qui se sert d'une source (WIN32_ROP4_USES_SOURCE) : PatBlt n'en a
/// pas.
pub const fn uses_source(rop: u32) -> bool {
    let rop3 = (rop >> 16) & 0xFF;
    (rop3 & 0xCC) >> 2 != rop3 & 0x33
}

/// Le rectangle de IntPatBlt : (`x`, `y`) et des étendues signées (une
/// négative va vers la gauche ou le haut), à l'écran depuis `origin`.
pub fn pat_rect(x: i32, y: i32, width: i32, height: i32, origin: (i32, i32)) -> Rect {
    let (left, right) = if width >= 0 { (x, x.saturating_add(width)) } else { (x.saturating_add(width), x) };
    let (top, bottom) = if height >= 0 { (y, y.saturating_add(height)) } else { (y.saturating_add(height), y) };
    Rect::new(
        left.saturating_add(origin.0),
        top.saturating_add(origin.1),
        right.saturating_add(origin.0),
        bottom.saturating_add(origin.1),
    )
}

/// IntPatBlt : `rect` (à l'écran), dans la région visible `vis`, prend
/// `brush` par le ROP3 `rop`. Un pinceau nul ne peint rien.
pub fn paint(vis: &Region, rect: Rect, rop: u32, brush: &Brush) {
    if brush.null {
        return;
    }
    let rop3 = (rop >> 16) as u8;
    crate::display::draw(|screen| {
        for part in vis.rects() {
            screen.pat_blt(part.intersect(&rect), brush.color, rop3);
        }
    });
}

/// NtGdiPatBlt : sur le DC `hdc`, le rectangle (`x`, `y`, `width`,
/// `height`) prend son pinceau par `rop`. `Err` : l'erreur de Win32.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn pat_blt(hdc: u32, x: i32, y: i32, width: i32, height: i32, rop: u32) -> Result<bool, u32> {
    if uses_source(rop) {
        return Ok(false);
    }
    let dc = lock(hdc).ok_or(abi::winerror::ERROR_INVALID_HANDLE)?;
    let Some((_, attr)) = dc.state().owner else { return Ok(false) };
    let Ok(Some(brush)) = fill_brush(&dc, attr, None, false) else { return Ok(false) };
    let state = dc.state();
    paint(&state.vis, pat_rect(x, y, width, height, state.origin), rop, &brush);
    Ok(true)
}

/// Un PatBlt mis en lot (GdiBCPatBlt) sur `dc`, avec le pinceau qu'il
/// apporte (`hbrush`).
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn batched_pat_blt(dc: &Dc, x: i32, y: i32, width: i32, height: i32, rop: u32, hbrush: u32) {
    if uses_source(rop) {
        return;
    }
    let Some((_, attr)) = dc.state().owner else { return };
    let Ok(Some(brush)) = fill_brush(dc, attr, Some(hbrush), true) else {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: a batched PatBlt without a brush or attributes dropped");
        }
        return;
    };
    let state = dc.state();
    paint(&state.vis, pat_rect(x, y, width, height, state.origin), rop, &brush);
}

/// GdiGetClipBox : le rectangle qui tient la région visible, depuis
/// l'origine, et sa complexité (NULLREGION, SIMPLEREGION : un seul
/// rectangle, COMPLEXREGION).
pub fn clip_box(state: &DcState) -> (i32, Rect) {
    let rects = state.vis.rects();
    let Some(first) = rects.first() else { return (NULLREGION, Rect::default()) };
    let bounds = rects.iter().fold(*first, |bounds, rect| bounds.union(rect));
    let area = i64::from(bounds.right - bounds.left) * i64::from(bounds.bottom - bounds.top);
    // Disjoint rectangles: one rectangle exactly when they fill their bounds.
    let complexity = if area == state.vis.area() { SIMPLEREGION } else { COMPLEXREGION };
    let (dx, dy) = state.origin;
    (complexity, Rect::new(bounds.left - dx, bounds.top - dy, bounds.right - dx, bounds.bottom - dy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::ColorRef;
    use abi::gdi::rop;

    const RED: Brush = Brush::solid(ColorRef(0xFF));

    #[test]
    fn pat_blt_has_no_source() {
        assert!(!uses_source(rop::PATCOPY));
        assert!(!uses_source(rop::PATINVERT));
        assert!(!uses_source(rop::DSTINVERT));
        assert!(!uses_source(rop::BLACKNESS));
        assert!(!uses_source(rop::WHITENESS));
        assert!(uses_source(0x00CC_0020), "SRCCOPY");
        assert!(uses_source(0x0088_0C6A), "SRCAND");
    }

    #[test]
    fn negative_extents_go_left_and_up_from_the_origin() {
        assert_eq!(pat_rect(10, 20, 30, 40, (100, 200)), Rect::new(110, 220, 140, 260));
        assert_eq!(pat_rect(10, 20, -5, -8, (100, 200)), Rect::new(105, 212, 110, 220));
        assert_eq!(pat_rect(i32::MAX, 0, 10, 1, (0, 0)).right, i32::MAX, "no overflow");
    }

    #[test]
    fn a_selected_brush_becomes_the_dc_s_brush() {
        let white = Some((0x0090_000A, STOCK_BRUSHES[0]));
        let resolve = |handle| (handle == 0x0090_0020).then_some(RED);
        let (fill, kept, dirty) = updated_fill(white, 0x0090_0020, DC_BRUSH_DIRTY | 0x80, resolve);
        assert_eq!((fill, kept, dirty), (Some((0x0090_0020, RED)), 0x0090_0020, 0x80));
    }

    #[test]
    fn a_brush_handle_without_a_brush_keeps_the_old_one() {
        let white = Some((0x0090_000A, STOCK_BRUSHES[0]));
        let (fill, kept, dirty) = updated_fill(white, 0x1234, DC_BRUSH_DIRTY | DIRTY_FILL, |_| None);
        assert_eq!((fill, kept, dirty), (white, 0x0090_000A, 0), "the attributes take the old handle back");
        let (fill, kept, _) = updated_fill(None, 0x1234, DIRTY_FILL, |_| None);
        assert_eq!((fill, kept), (None, 0x1234));
    }

    #[test]
    fn the_same_brush_is_not_looked_up_again() {
        let white = Some((0x0090_000A, STOCK_BRUSHES[0]));
        let (fill, kept, dirty) = updated_fill(white, 0x0090_000A, DIRTY_FILL, |_| panic!("not looked up"));
        assert_eq!((fill, kept, dirty), (white, 0x0090_000A, 0));
    }

    #[test]
    fn the_clip_box_bounds_the_visible_region_from_the_origin() {
        let mut state = DcState { origin: (100, 50), ..DcState::default() };
        assert_eq!(clip_box(&state), (NULLREGION, Rect::default()));
        state.vis = Region::from_rect(Rect::new(110, 60, 210, 160));
        assert_eq!(clip_box(&state), (SIMPLEREGION, Rect::new(10, 10, 110, 110)));
        state.vis.subtract_rect(Rect::new(150, 0, 300, 100));
        assert_eq!(clip_box(&state), (COMPLEXREGION, Rect::new(10, 10, 110, 110)), "an L");
        // Three pieces left of a hole: one rectangle, as ReactOS's banded
        // region would have it.
        let mut pieces = Region::from_rect(Rect::new(100, 50, 110, 60));
        pieces.subtract_rect(Rect::new(103, 53, 106, 56));
        pieces.intersect_rect(Rect::new(100, 50, 103, 60));
        assert_eq!(pieces.rects().len(), 3);
        state.vis = pieces;
        assert_eq!(clip_box(&state), (SIMPLEREGION, Rect::new(0, 0, 3, 10)), "pieces that fill their bounds");
    }

    #[test]
    fn a_pool_hands_out_a_block_from_its_start() {
        let mut pool = AttrPool::default();
        assert_eq!(pool.take(), None);
        pool.add_block(0x0040_0000);
        assert_eq!(pool.take(), Some(0x0040_0000));
        assert_eq!(pool.take(), Some(0x0040_01D0));
        pool.give_back(0x0040_0000);
        assert_eq!(pool.take(), Some(0x0040_0000));
        let mut count = 2;
        while pool.take().is_some() {
            count += 1;
        }
        assert_eq!(count, 0x1_0000 / 0x1D0, "141 places in a block");
    }
}
