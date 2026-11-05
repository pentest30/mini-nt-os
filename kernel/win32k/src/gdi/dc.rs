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
//! Un client coupe encore où le DC peint par une région de découpage
//! (SelectClipRgn, ExtSelectClipRgn : `dclevel.prgnClip`, depuis l'origine
//! du DC ; [`select_clip`]) : le DC peint dans sa région visible coupée par
//! elle (`prgnRao`, [`DcState::rao`]). Les attributs disent la région
//! visible (`VisRectRegion` : sa complexité, le rectangle qui la tient,
//! depuis l'origine), dont `gdi32` tire ce que rend un SelectClipRgn qu'il
//! met en lot.
//!
//! Pas encore : les DC en mémoire et leurs bitmaps, les régions de méta
//! (SetMetaRgn), ExcludeClipRect, IntersectClipRect, OffsetClipRgn,
//! GetClipRgn, les transformations (le DC est en MM_TEXT, ses matrices à
//! zéro), les stylos (`hpen` reste nul), les DC d'un autre propriétaire
//! que le processus courant.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::dirty::{DC_BRUSH_DIRTY, DIRTY_FILL};
use abi::gdi::{objt, rgn, stock, DcAttr32, RgnAttr32, ATTR_RGN_VALID, ERROR, LO_DC_TYPE, SIMPLEREGION};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::user::Rect32;
use hal::sync::KSpinLock;
use ke::usermem::{copy_from_user, copy_to_user};
use mm::vad::PageProtect;
use mm::virtual_alloc::AllocType;

use super::brush::{Brush, STOCK_BRUSHES};
use super::dib::Rect;
use super::handles::{self, Object, OWNER_NONE};
use super::region::{combine, Region};

/// L'état d'un DC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DcState {
    /// Son propriétaire : son PID, et l'adresse de ses attributs chez lui.
    pub owner: Option<(u32, u32)>,
    /// L'origine de ses coordonnées, à l'écran (`ptlDCOrig`).
    pub origin: (i32, i32),
    /// Ce qu'il peut peindre, à l'écran (`prgnVis`).
    pub vis: Region,
    /// Sa région de découpage, depuis son origine (`dclevel.prgnClip`).
    pub clip: Option<Region>,
    /// Son pinceau de remplissage (`dclevel.pbrFill`) : son handle, et lui.
    pub fill: Option<(u32, Brush)>,
}

impl DcState {
    /// Où il peint, à l'écran (`prgnRao`) : sa région visible, coupée par sa
    /// région de découpage.
    pub fn rao(&self) -> Region {
        match &self.clip {
            Some(clip) => self.vis.intersect(&clip.offset_by(self.origin.0, self.origin.1)),
            None => self.vis.clone(),
        }
    }

    /// Le rectangle qui tient sa région visible, depuis son origine.
    fn vis_bounds(&self) -> Rect {
        let bounds = self.vis.bounds();
        let (dx, dy) = self.origin;
        if bounds.is_empty() {
            return bounds;
        }
        Rect::new(bounds.left - dx, bounds.top - dy, bounds.right - dx, bounds.bottom - dy)
    }

    /// `VisRectRegion` (UpdateVisRgn) : la complexité de sa région visible
    /// et le rectangle qui la tient, depuis son origine.
    pub fn vis_rect_region(&self) -> RgnAttr32 {
        let bounds = self.vis_bounds();
        RgnAttr32 {
            attr_flags: ATTR_RGN_VALID,
            complexity: self.vis.complexity() as u32,
            rect: Rect32 { left: bounds.left, top: bounds.top, right: bounds.right, bottom: bounds.bottom },
        }
    }
}

/// IntGdiExtSelectClipRgn : la région de découpage de `state` devient
/// `region` (`RGN_COPY` ; aucune : plus de région), ou sa combinaison avec
/// elle selon `mode` (sans région de découpage, avec le rectangle qui tient
/// la région visible ; `RGN_AND` la prend telle quelle). Rend la complexité
/// de là où le DC peint désormais (de sa région visible sans région de
/// découpage), ou ERROR (un autre mode sans région, un mode inconnu).
pub fn select_clip(state: &mut DcState, region: Option<&Region>, mode: i32) -> i32 {
    let Some(region) = region else {
        if mode != rgn::COPY {
            return ERROR;
        }
        state.clip = None;
        return state.vis.complexity();
    };
    if mode != rgn::COPY && (mode != rgn::AND || state.clip.is_some()) {
        let base = state.clip.clone().unwrap_or_else(|| Region::from_rect(state.vis_bounds()));
        let Some(combined) = combine(&base, Some(region), mode) else { return ERROR };
        state.clip = Some(combined);
    } else {
        state.clip = Some(region.clone());
    }
    state.rao().complexity()
}

/// IntGdiExtSelectClipRect, un SelectClipRgn mis en lot : la région de
/// découpage devient le rectangle `rect` (aucun : plus de région) ; rien ne
/// change si elle est déjà ce rectangle.
pub fn select_clip_rect(state: &mut DcState, rect: Option<Rect>, mode: i32) -> i32 {
    let Some(rect) = rect else { return select_clip(state, None, mode) };
    let region = Region::from_corners(rect.left, rect.top, rect.right, rect.bottom);
    if state.clip.as_ref().is_some_and(|clip| clip.complexity() == SIMPLEREGION && clip.bounds() == region.bounds()) {
        return state.rao().complexity();
    }
    select_clip(state, Some(&region), mode)
}

/// NtGdiExtSelectClipRgn, une fois la région lue : sur le DC `hdc`, voir
/// [`select_clip`]. `Err` : l'erreur de Win32 (`ERROR_INVALID_PARAMETER`
/// pour un mode inconnu, `ERROR_INVALID_HANDLE` pour un DC qui n'est pas au
/// processus).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn ext_select_clip_rgn(hdc: u32, region: Option<&Region>, mode: i32) -> Result<i32, u32> {
    if !(rgn::AND..=rgn::COPY).contains(&mode) {
        return Err(abi::winerror::ERROR_INVALID_PARAMETER);
    }
    let dc = lock(hdc).ok_or(abi::winerror::ERROR_INVALID_HANDLE)?;
    if region.is_none() && mode != rgn::COPY {
        return Ok(ERROR);
    }
    Ok(dc.change(|state| select_clip(state, region, mode)))
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

    /// Les places de `size` octets d'un bloc neuf, en `base` : la plus basse
    /// sera prise la première.
    pub fn add_block(&mut self, base: u32, size: u32) {
        self.free.extend((0..ATTR_BLOCK / size).rev().map(|i| base + i * size));
    }

    /// Rend une place.
    pub fn give_back(&mut self, attr: u32) {
        self.free.push(attr);
    }
}

/// Ce dont les attributs sont chez le propriétaire : un DC (`DC_ATTR`,
/// `pPoolDcAttr`) ou une région (`RGN_ATTR`, `pPoolRgnAttr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrKind {
    Dc,
    Region,
}

impl AttrKind {
    /// La place de ses attributs dans un bloc.
    pub const fn size(self) -> u32 {
        match self {
            Self::Dc => size_of::<DcAttr32>() as u32,
            Self::Region => size_of::<RgnAttr32>() as u32,
        }
    }

    fn pool(self, info: &crate::gui::ProcessInfo) -> &KSpinLock<AttrPool> {
        match self {
            Self::Dc => &info.dc_attrs,
            Self::Region => &info.rgn_attrs,
        }
    }
}

/// GdiPoolAllocate : une place pour des attributs `kind` dans la mémoire du
/// processus courant, dans un bloc neuf s'il le faut. Rend le PID et
/// l'adresse.
///
/// # Errors
/// Hors d'un thread de Ps ou d'un processus GUI ; celles de l'allocation.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn allocate_attr(kind: AttrKind) -> Result<(u32, u32), NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    let process = thread.process().clone();
    let info = crate::gui::process_info(&process)?;
    if let Some(attr) = kind.pool(&info).lock().take() {
        return Ok((process.pid(), attr));
    }
    let alloc_type = AllocType::MEM_RESERVE | AllocType::MEM_COMMIT;
    let base =
        process.with_space(|space| space.allocate(0, u64::from(ATTR_BLOCK), alloc_type, PageProtect::READWRITE))??;
    let mut pool = kind.pool(&info).lock();
    pool.add_block(base as u32, kind.size());
    let attr = pool.take().expect("a new block has room");
    Ok((process.pid(), attr))
}

/// GdiPoolFree : rend la place `attr` des attributs `kind` au processus
/// courant.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn free_attr(kind: AttrKind, attr: u32) {
    let Some(thread) = ps::ethread::current_thread() else { return };
    if let Ok(info) = crate::gui::process_info(thread.process()) {
        kind.pool(&info).lock().give_back(attr);
    }
}

/// Le PID du processus courant (0 hors d'un thread de Ps).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn current_pid() -> u32 {
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
    let (pid, attr) = allocate_attr(AttrKind::Dc)?;
    let white = super::brush::stock_object(stock::WHITE_BRUSH);
    let (width, height) = crate::display::mode().map_or((0, 0), |mode| (mode.width as i32, mode.height as i32));
    let state = DcState {
        owner: Some((pid, attr)),
        origin,
        vis,
        clip: None,
        fill: Some((white, STOCK_BRUSHES[stock::WHITE_BRUSH])),
    };
    let attrs = DcAttr32 { vis_rect_region: state.vis_rect_region(), ..DcAttr32::initial(white, 0, width, height) };
    let written = copy_to_user(u64::from(attr), attrs.as_bytes()).and_then(|()| handles::set_owner(handle, pid, attr));
    if let Err(status) = written {
        free_attr(AttrKind::Dc, attr);
        return Err(status);
    }
    dc.change(|current| *current = state);
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
        free_attr(AttrKind::Dc, attr);
    }
}

/// DC_LockDc : le DC de `hdc`, s'il est au processus courant.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn lock(hdc: u32) -> Option<Arc<Dc>> {
    match handles::get(hdc, current_pid())? {
        Object::Dc(dc) => Some(dc),
        _ => None,
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
    paint(&state.rao(), pat_rect(x, y, width, height, state.origin), rop, &brush);
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
    paint(&state.rao(), pat_rect(x, y, width, height, state.origin), rop, &brush);
}

/// GdiGetClipBox : le rectangle qui tient là où le DC peint (`prgnRao`),
/// depuis l'origine, et sa complexité (NULLREGION, SIMPLEREGION : un seul
/// rectangle, COMPLEXREGION).
pub fn clip_box(state: &DcState) -> (i32, Rect) {
    let rao = state.rao();
    if rao.is_empty() {
        return (rao.complexity(), Rect::default());
    }
    let bounds = rao.bounds();
    let (dx, dy) = state.origin;
    (rao.complexity(), Rect::new(bounds.left - dx, bounds.top - dy, bounds.right - dx, bounds.bottom - dy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::ColorRef;
    use abi::gdi::{rop, COMPLEXREGION, NULLREGION};

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

    /// A DC at (100, 50) that sees (110, 60)-(210, 160).
    fn seeing() -> DcState {
        DcState { origin: (100, 50), vis: Region::from_rect(Rect::new(110, 60, 210, 160)), ..DcState::default() }
    }

    #[test]
    fn a_clip_region_cuts_where_the_dc_paints_from_its_origin() {
        let mut state = seeing();
        assert_eq!(state.rao(), state.vis, "no clip region");
        let clip = Region::from_rect(Rect::new(0, 0, 50, 200));
        assert_eq!(select_clip(&mut state, Some(&clip), rgn::COPY), SIMPLEREGION);
        assert_eq!(state.rao().rects(), [Rect::new(110, 60, 150, 160)]);
        assert_eq!(clip_box(&state), (SIMPLEREGION, Rect::new(10, 10, 50, 110)));
        assert_eq!(state.clip.as_ref(), Some(&clip), "kept from the origin");
        let outside = Region::from_rect(Rect::new(500, 500, 600, 600));
        assert_eq!(select_clip(&mut state, Some(&outside), rgn::COPY), NULLREGION);
        assert_eq!(clip_box(&state), (NULLREGION, Rect::default()));
        assert_eq!(select_clip(&mut state, None, rgn::COPY), SIMPLEREGION, "the visible region's");
        assert_eq!(state.clip, None);
    }

    #[test]
    fn modes_combine_with_the_clip_region_or_the_visible_bounds() {
        let mut state = seeing();
        let left = Region::from_rect(Rect::new(0, 0, 50, 200));
        assert_eq!(select_clip(&mut state, Some(&left), rgn::AND), SIMPLEREGION, "AND without a clip: a copy");
        assert_eq!(state.clip.as_ref(), Some(&left));
        let top = Region::from_rect(Rect::new(0, 0, 200, 30));
        assert_eq!(select_clip(&mut state, Some(&top), rgn::AND), SIMPLEREGION);
        assert_eq!(state.clip.as_ref().map(Region::rects), Some(&[Rect::new(0, 0, 50, 30)][..]));
        let strip = Region::from_rect(Rect::new(0, 0, 200, 20));
        assert_eq!(select_clip(&mut state, Some(&strip), rgn::OR), COMPLEXREGION, "an L");
        state.clip = None;
        assert_eq!(select_clip(&mut state, Some(&top), rgn::DIFF), SIMPLEREGION);
        assert_eq!(
            state.clip.as_ref().map(Region::bounds),
            Some(Rect::new(10, 30, 110, 110)),
            "from the visible bounds"
        );
        assert_eq!(select_clip(&mut state, None, rgn::AND), ERROR, "no region to combine");
        assert_eq!(select_clip(&mut state, Some(&top), 9), ERROR);
    }

    #[test]
    fn a_batched_clip_rectangle_already_there_changes_nothing() {
        let mut state = seeing();
        assert_eq!(select_clip_rect(&mut state, Some(Rect::new(50, 200, 0, 0)), rgn::COPY), SIMPLEREGION);
        assert_eq!(state.clip.as_ref().map(Region::rects), Some(&[Rect::new(0, 0, 50, 200)][..]), "corners in order");
        state.vis.subtract_rect(Rect::new(110, 60, 120, 70));
        assert_eq!(select_clip_rect(&mut state, Some(Rect::new(0, 0, 50, 200)), rgn::COPY), COMPLEXREGION);
        assert_eq!(select_clip_rect(&mut state, None, rgn::COPY), COMPLEXREGION);
        assert_eq!(state.clip, None);
        assert_eq!(select_clip_rect(&mut state, None, rgn::OR), ERROR);
    }

    #[test]
    fn the_attributes_say_the_visible_region_from_the_origin() {
        let attr = seeing().vis_rect_region();
        assert_eq!((attr.attr_flags, attr.complexity), (ATTR_RGN_VALID, SIMPLEREGION as u32));
        assert_eq!(attr.rect, Rect32 { left: 10, top: 10, right: 110, bottom: 110 });
        let nothing = DcState { origin: (100, 50), ..DcState::default() }.vis_rect_region();
        assert_eq!((nothing.complexity, nothing.rect), (NULLREGION as u32, Rect32::default()));
    }

    #[test]
    fn an_unknown_mode_is_refused_before_the_dc() {
        assert_eq!(ext_select_clip_rgn(0x1234, None, 0), Err(abi::winerror::ERROR_INVALID_PARAMETER));
        assert_eq!(ext_select_clip_rgn(0x1234, None, 6), Err(abi::winerror::ERROR_INVALID_PARAMETER));
    }

    #[test]
    fn a_pool_hands_out_a_block_from_its_start() {
        let mut pool = AttrPool::default();
        assert_eq!(pool.take(), None);
        pool.add_block(0x0040_0000, AttrKind::Dc.size());
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

    #[test]
    fn region_attributes_take_less_room() {
        let mut pool = AttrPool::default();
        pool.add_block(0x0050_0000, AttrKind::Region.size());
        assert_eq!((pool.take(), pool.take()), (Some(0x0050_0000), Some(0x0050_0018)));
        let mut count = 2;
        while pool.take().is_some() {
            count += 1;
        }
        assert_eq!(count, 0x1_0000 / 0x18, "2730 places in a block");
    }
}
