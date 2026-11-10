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
//! Un DC en mémoire (CreateCompatibleDC, [`create_memory_dc`]) peint dans
//! le bitmap qu'on y choisit (SelectObject, [`select_bitmap`] ; d'abord le
//! bitmap par défaut, 1 × 1, où rien ne se dessine), son origine en (0, 0),
//! sa région visible tout le bitmap ([`DcState::draw`]). Ses attributs
//! disent `DC_DIBSECTION` quand une DIB section y est choisie : `gdi32` y
//! dessine alors sans mettre en lot.
//!
//! Pas encore : les régions de méta
//! (SetMetaRgn), ExcludeClipRect, IntersectClipRect, OffsetClipRgn,
//! GetClipRgn, les transformations (le DC est en MM_TEXT, ses matrices à
//! zéro), les stylos (`hpen` reste nul), les DC d'un autre propriétaire
//! que le processus courant.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::dirty::{DC_BRUSH_DIRTY, DC_DIBSECTION, DIRTY_FILL, DIRTY_LINE};
use abi::gdi::{
    objt, rgn, stock, BrushAttr32, DcAttr32, RgnAttr32, ATTR_RGN_VALID, ERROR, LO_BITMAP_TYPE, LO_DC_TYPE, SIMPLEREGION,
};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL};
use abi::user::Rect32;
use hal::sync::KSpinLock;
use ke::usermem::{copy_from_user, copy_to_user};
use mm::vad::PageProtect;
use mm::virtual_alloc::AllocType;

use super::brush::{Brush, STOCK_BRUSHES};
use super::dib::{Bitmap, ColorRef, MonoFill, Rect};
use super::handles::{self, Object, OWNER_NONE};
use super::region::{combine, Region};
use super::surface::{self, Surface};

/// Le bitmap choisi dans un DC en mémoire : son handle, et lui.
#[derive(Clone)]
pub struct Selected {
    pub handle: u32,
    pub surface: Arc<Surface>,
}

impl PartialEq for Selected {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle && Arc::ptr_eq(&self.surface, &other.surface)
    }
}

impl Eq for Selected {}

impl core::fmt::Debug for Selected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Selected({:#x}, {:?})", self.handle, self.surface)
    }
}

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
    /// Son stylo (`dclevel.pbrLine`) : son handle, et lui ; le stylo
    /// implicite (noir, un pixel) sans handle.
    pub pen: Option<(u32, super::pen::Pen)>,
    /// Sa position courante (`dclevel.ptlCurrent`), d'où LineTo part.
    pub position: (i32, i32),
    /// Le bitmap où il peint (`dclevel.pSurface`) : aucun pour un DC de
    /// l'écran, qui peint sur l'écran.
    pub bitmap: Option<Selected>,
}

impl DcState {
    /// Appelle `draw` avec la surface où il peint : l'écran ou son bitmap ;
    /// faux sans pilote d'affichage, ou avec le bitmap par défaut.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (`draw` y tourne).
    pub fn draw(&self, draw: impl FnMut(&mut Bitmap<'_>)) -> bool {
        match &self.bitmap {
            None => crate::display::draw(draw),
            Some(selected) => selected.surface.draw(draw),
        }
    }

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
    /// Un DC en mémoire (DCTYPE_MEMORY).
    memory: bool,
}

impl Default for Dc {
    /// Un DC de l'écran à personne, qui ne peint rien.
    fn default() -> Self {
        Self { state: KSpinLock::new(DcState::default()), memory: false }
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
/// `pPoolDcAttr`), une région (`RGN_ATTR`, `pPoolRgnAttr`) ou un pinceau
/// (`BRUSH_ATTR`, `pPoolBrushAttr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrKind {
    Dc,
    Region,
    Brush,
}

impl AttrKind {
    /// La place de ses attributs dans un bloc.
    pub const fn size(self) -> u32 {
        match self {
            Self::Dc => size_of::<DcAttr32>() as u32,
            Self::Region => size_of::<RgnAttr32>() as u32,
            Self::Brush => size_of::<BrushAttr32>() as u32,
        }
    }

    fn pool(self, info: &crate::gui::ProcessInfo) -> &KSpinLock<AttrPool> {
        match self {
            Self::Dc => &info.dc_attrs,
            Self::Region => &info.rgn_attrs,
            Self::Brush => &info.brush_attrs,
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
        pen: None,
        position: (0, 0),
        bitmap: None,
    };
    let attrs = DcAttr32 {
        vis_rect_region: state.vis_rect_region(),
        lfnt_new: super::brush::stock_object(stock::SYSTEM_FONT),
        ..DcAttr32::initial(white, 0, width, height)
    };
    let written = copy_to_user(u64::from(attr), attrs.as_bytes()).and_then(|()| handles::set_owner(handle, pid, attr));
    if let Err(status) = written {
        free_attr(AttrKind::Dc, attr);
        return Err(status);
    }
    dc.change(|current| *current = state);
    Ok(())
}

/// GreOpenDCW d'un client (CreateDC("DISPLAY")) : un DC de l'écran entier
/// au processus courant, avec ses attributs chez lui, à lui jusqu'à
/// DeleteDC ; rend son handle. `user32` en fait l'écran dont il tire les
/// bitmaps d'un curseur (CreateCompatibleDC, CreateCompatibleBitmap).
///
/// # Errors
/// Celles de [`create_display_dc`] et de [`take`] (rien ne reste alors).
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn open_display_dc() -> Result<u32, NtStatus> {
    let (handle, dc) = create_display_dc()?;
    let (width, height) = crate::display::mode().map_or((0, 0), |mode| (mode.width as i32, mode.height as i32));
    if let Err(status) = take(handle, &dc, Region::from_rect(Rect::new(0, 0, width, height)), (0, 0)) {
        let _ = handles::delete(handle, OWNER_NONE, |_| true);
        return Err(status);
    }
    Ok(handle)
}

/// DC_vSetOwner(GDI_OBJ_HMGR_NONE) : le DC `handle` n'est plus à personne ;
/// ses attributs retournent au processus courant, son propriétaire.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn give_back(handle: u32, dc: &Dc) {
    if let Some((_, attr)) = disown(handle, dc) {
        free_attr(AttrKind::Dc, attr);
    }
}

/// Le DC `handle` n'est plus à personne, sans rendre ses attributs à son
/// processus (un autre que le processus courant, ou qui se termine) ; rend
/// son ancien propriétaire et l'adresse de ses attributs chez lui.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn disown(handle: u32, dc: &Dc) -> Option<(u32, u32)> {
    let old = dc.change(core::mem::take);
    let _ = handles::set_owner(handle, OWNER_NONE, 0);
    old.owner
}

/// GreCreateCompatibleDC : un DC en mémoire, au processus courant, avec ses
/// attributs chez lui (ceux d'un DC neuf : WHITE_BRUSH, SYSTEM_FONT) et le
/// bitmap par défaut ; rend son handle.
///
/// # Errors
/// `STATUS_UNSUCCESSFUL` avant les objets de stock ; celles de
/// l'allocation et de l'écriture des attributs, de la table.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn create_memory_dc() -> Result<u32, NtStatus> {
    let default = super::brush::stock_object(stock::DEFAULT_BITMAP);
    let surface = surface::lock(default, handles::OWNER_PUBLIC).ok_or(STATUS_UNSUCCESSFUL)?;
    let (pid, attr) = allocate_attr(AttrKind::Dc)?;
    let white = super::brush::stock_object(stock::WHITE_BRUSH);
    let state = DcState {
        owner: Some((pid, attr)),
        origin: (0, 0),
        vis: Region::from_rect(Rect::new(0, 0, 1, 1)),
        clip: None,
        fill: Some((white, STOCK_BRUSHES[stock::WHITE_BRUSH])),
        pen: None,
        position: (0, 0),
        bitmap: Some(Selected { handle: default, surface }),
    };
    let (width, height) = crate::display::mode().map_or((0, 0), |mode| (mode.width as i32, mode.height as i32));
    let attrs = DcAttr32 {
        vis_rect_region: state.vis_rect_region(),
        lfnt_new: super::brush::stock_object(stock::SYSTEM_FONT),
        ..DcAttr32::initial(white, 0, width, height)
    };
    let dc = Arc::new(Dc { state: KSpinLock::new(state), memory: true });
    let inserted = copy_to_user(u64::from(attr), attrs.as_bytes())
        .and_then(|()| handles::insert_with_user_data(Object::Dc(dc), LO_DC_TYPE, objt::DC, pid, attr));
    if inserted.is_err() {
        free_attr(AttrKind::Dc, attr);
    }
    inserted
}

/// IntGdiDeleteDC : le DC `hdc` du processus courant (en mémoire, ou de
/// l'écran que CreateDC lui a donné) quitte la table, rend ses attributs,
/// et son bitmap le quitte. Faux pour un DC d'un autre processus. Un DC du
/// cache se rend au cache avant (`crate::dce::release_dc`).
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn delete_dc(hdc: u32) -> bool {
    let is_dc = |object: &Object| matches!(object, Object::Dc(_));
    let Some((Object::Dc(dc), attr)) = handles::delete(hdc, current_pid(), is_dc) else { return false };
    let old = dc.change(core::mem::take);
    if let Some(selected) = &old.bitmap {
        selected.surface.deselect(hdc);
    }
    if attr != 0 {
        free_attr(AttrKind::Dc, attr);
    }
    true
}

/// NtGdiSelectBitmap : le bitmap `hbmp` (du processus courant, ou le bitmap
/// par défaut) devient celui du DC en mémoire `hdc`, dont la région visible
/// devient tout le bitmap ; ses attributs disent qu'il faut reprendre son
/// pinceau et son stylo, et s'il peint dans une DIB section. Rend l'ancien
/// bitmap ; `None` pour un handle nul, un DC de l'écran, un bitmap déjà
/// choisi dans un autre DC.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn select_bitmap(hdc: u32, hbmp: u32) -> Option<u32> {
    if hdc == 0 || hbmp & abi::gdi::GDI_HANDLE_TYPE_MASK != LO_BITMAP_TYPE {
        return None;
    }
    let dc = lock(hdc).filter(|dc| dc.memory)?;
    let surface = surface::lock(hbmp, current_pid())?;
    let (width, height) = surface.size();
    let dib = surface.is_dib_section();
    let new = Selected { handle: hbmp, surface };
    let old = dc.change(|state| {
        let old = state.bitmap.clone()?;
        if old.handle == hbmp {
            return Some((old, false));
        }
        if !new.surface.select(hdc) {
            return None;
        }
        state.vis = Region::from_rect(Rect::new(0, 0, width as i32, height as i32));
        state.bitmap = Some(new.clone());
        Some((old, true))
    });
    let (old, changed) = old?;
    if !changed {
        return Some(old.handle);
    }
    old.surface.deselect(hdc);
    let state = dc.state();
    if let Some((_, attr)) = state.owner {
        let (set, clear) = if dib { (DC_DIBSECTION, 0) } else { (0, DC_DIBSECTION) };
        let _ = change_dirty(attr, DIRTY_FILL | DIRTY_LINE | set, clear).and_then(|()| {
            let at = u64::from(attr) + offset_of!(DcAttr32, vis_rect_region) as u64;
            copy_to_user(at, state.vis_rect_region().as_bytes())
        });
    }
    Some(old.handle)
}

/// Met les bits `set` et retire les bits `clear` de `ulDirty_` des
/// attributs en `attr`, chez le processus courant.
fn change_dirty(attr: u32, set: u32, clear: u32) -> Result<(), NtStatus> {
    let at = u64::from(attr) + offset_of!(DcAttr32, dirty) as u64;
    let mut dirty = [0u8; 4];
    copy_from_user(&mut dirty, at)?;
    let dirty = (u32::from_le_bytes(dirty) | set) & !clear;
    copy_to_user(at, &dirty.to_le_bytes())
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
///
/// # Errors
/// Celles de la lecture et de l'écriture des attributs.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn fill_brush(dc: &Dc, attr: u32, hbrush: Option<u32>, restore: bool) -> Result<Option<Brush>, NtStatus> {
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

/// Les attributs de texte du DC (`crForegroundClr`, `crBackgroundClr`,
/// `lBkMode`, `flTextAlign`, `hlfntNew`), lus dans ses attributs chez son
/// propriétaire ; `None` pour un DC sans propriétaire ou des attributs
/// illisibles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_attrs(dc: &Dc) -> Option<super::text::TextAttrs> {
    let (_, attr) = dc.state().owner?;
    let mut bytes = [0u8; offset_of!(DcAttr32, lfnt_new) + 4];
    copy_from_user(&mut bytes, u64::from(attr)).ok()?;
    let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    Some(super::text::TextAttrs {
        font: word(offset_of!(DcAttr32, lfnt_new)),
        color: ColorRef(word(offset_of!(DcAttr32, cr_foreground_clr))),
        background: ColorRef(word(offset_of!(DcAttr32, cr_background_clr))),
        bk_mode: word(offset_of!(DcAttr32, bk_mode)) as i32,
        align: word(offset_of!(DcAttr32, fl_text_align)),
    })
}

/// IntGdiSetTextColor et IntGdiSetBkColor : `text` et `background`
/// (COLORREF) deviennent les couleurs du texte et du fond du DC, dans ses
/// attributs chez son propriétaire (les deux formes, et leurs bits de
/// changement, comme `gdi32` les écrit) ; `None` pour un DC sans
/// propriétaire ou des attributs qu'on ne peut écrire.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn set_text_colors(dc: &Dc, text: u32, background: u32) -> Option<()> {
    let (_, attr) = dc.state().owner?;
    let at = |field: usize| u64::from(attr) + field as u64;
    for (field, value) in [
        (offset_of!(DcAttr32, cr_foreground_clr), text),
        (offset_of!(DcAttr32, ul_foreground_clr), text),
        (offset_of!(DcAttr32, cr_background_clr), background),
        (offset_of!(DcAttr32, ul_background_clr), background),
    ] {
        copy_to_user(at(field), &value.to_le_bytes()).ok()?;
    }
    let mut dirty = [0u8; 4];
    copy_from_user(&mut dirty, at(offset_of!(DcAttr32, dirty))).ok()?;
    let dirty = u32::from_le_bytes(dirty) | abi::gdi::dirty::DIRTY_TEXT | abi::gdi::dirty::DIRTY_BACKGROUND;
    copy_to_user(at(offset_of!(DcAttr32, dirty)), &dirty.to_le_bytes()).ok()
}

/// DC_hSelectFont (NtGdiSelectFont) : la police `hfont` devient celle du DC
/// (`hlfntNew` de ses attributs) ; rend l'ancienne, ou `None` si `hfont`
/// n'est pas une police du processus ou publique, ou sans attributs.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn select_font(dc: &Dc, hfont: u32) -> Option<u32> {
    let (pid, attr) = dc.state().owner?;
    super::fontobj::get(hfont, pid)?;
    let at = u64::from(attr) + offset_of!(DcAttr32, lfnt_new) as u64;
    let mut old = [0u8; 4];
    copy_from_user(&mut old, at).ok()?;
    copy_to_user(at, &hfont.to_le_bytes()).ok()?;
    Some(u32::from_le_bytes(old))
}

/// SelectObject(hpen) : le stylo du DC devient `hpen` (son type GDI doit
/// être un stylo, au processus du DC) ; rend l'ancien handle, 0 sans.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn select_pen(dc: &Dc, hpen: u32) -> Option<u32> {
    if hpen & abi::gdi::GDI_HANDLE_TYPE_MASK != abi::gdi::LO_PEN_TYPE {
        return None;
    }
    let (pid, _) = dc.state().owner?;
    let object = super::handles::get(hpen, pid)?;
    let pen = match object {
        super::handles::Object::Pen(pen) => pen,
        _ => return None,
    };
    Some(dc.change(|state| state.pen.replace((hpen, *pen)).map_or(0, |(old, _)| old)))
}

/// MoveToEx : la position courante du DC devient `(x, y)` (coordonnées
/// logiques) ; rend l'ancienne en `out` s'il n'est pas nul, et en valeur.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn move_to(dc: &Dc, x: i32, y: i32, out: u32) -> Option<(i32, i32)> {
    let old = dc.change(|state| core::mem::replace(&mut state.position, (x, y)));
    if out != 0 {
        copy_to_user(u64::from(out), &[old.0.to_le_bytes(), old.1.to_le_bytes()].concat()).ok()?;
    }
    Some(old)
}

/// LineTo : le trait de la position courante à `(x, y)` (coordonnées
/// logiques), du stylo du DC — le noir d'un pixel sans stylo choisi —, où
/// il peut peindre (`prgnRao`, comme [`paint`]) ; la position devient
/// `(x, y)`. `false` sans DC ou sans où dessiner.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn line_to(dc: &Dc, x: i32, y: i32) -> bool {
    let state = dc.state();
    let (dx, dy) = logical_origin(&state, None);
    let from = (state.position.0 + dx, state.position.1 + dy);
    let to = (x + dx, y + dy);
    let pen = state.pen.as_ref().map_or(super::pen::Pen::BLACK, |(_, pen)| *pen);
    let rao = state.rao();
    if rao.is_empty() {
        return false;
    }
    let parts: alloc::vec::Vec<Rect> = rao.rects().to_vec();
    let drew = state.draw(|surface| surface.draw_line(from, to, &pen, &parts));
    drop(state);
    dc.change(|state| state.position = (x, y));
    drew
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

/// Ce qu'un pinceau peint sur un DC ([`fill_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fill {
    /// Rien : un pinceau nul (BS_NULL).
    Nothing,
    /// Une couleur.
    Solid(ColorRef),
    /// Un motif monochrome, posé sur la surface du DC.
    Mono(MonoFill),
}

/// Ce que `brush` peint sur le DC d'état `state`. Un motif monochrome
/// prend les couleurs du texte et du fond `colors` (un lot apporte celles
/// qu'avait le DC) ou, sans elles, celles des attributs du DC (noir sur
/// blanc, celles d'un nouveau DC, sans attributs) ; son coin tombe à
/// l'origine du DC plus celle du pinceau (`ptlBrushOrigin`, SetBrushOrgEx :
/// ptlFillOrigin de ReactOS).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn fill_of(state: &DcState, brush: &Brush, colors: Option<(u32, u32)>) -> Fill {
    if brush.null {
        return Fill::Nothing;
    }
    let Some(rows) = brush.mono else { return Fill::Solid(brush.color) };
    let word = |field: usize| {
        let (_, attr) = state.owner?;
        let mut bytes = [0u8; 4];
        copy_from_user(&mut bytes, u64::from(attr) + field as u64).ok()?;
        Some(u32::from_le_bytes(bytes))
    };
    let (text, background) = colors
        .or_else(|| {
            Some((word(offset_of!(DcAttr32, cr_foreground_clr))?, word(offset_of!(DcAttr32, cr_background_clr))?))
        })
        .unwrap_or((0, 0x00FF_FFFF));
    let brush_origin = offset_of!(DcAttr32, brush_origin);
    let (bx, by) = (word(brush_origin).unwrap_or(0) as i32, word(brush_origin + 4).unwrap_or(0) as i32);
    Fill::Mono(MonoFill {
        rows,
        zero: ColorRef(text & 0x00FF_FFFF),
        one: ColorRef(background & 0x00FF_FFFF),
        origin: (state.origin.0.wrapping_add(bx), state.origin.1.wrapping_add(by)),
    })
}

/// IntPatBlt : `rect` (sur la surface du DC d'état `state`), là où il peint,
/// prend `fill` ([`fill_of`]) par le ROP3 `rop`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn paint(state: &DcState, rect: Rect, rop: u32, fill: &Fill) {
    let rop3 = (rop >> 16) as u8;
    let rao = state.rao();
    match fill {
        Fill::Nothing => {}
        Fill::Solid(color) => {
            state.draw(|surface| {
                for part in rao.rects() {
                    surface.pat_blt(part.intersect(&rect), *color, rop3);
                }
            });
        }
        Fill::Mono(pattern) => {
            state.draw(|surface| {
                for part in rao.rects() {
                    surface.pat_blt_mono(part.intersect(&rect), pattern, rop3);
                }
            });
        }
    }
}

/// Les parties d'un Rectangle de (`left`, `top`) à (`right`, `bottom`)
/// (bords en tout ordre, la droite et le bas exclus) : son intérieur, s'il
/// en a un, et ses quatre bords d'un pixel (haut, bas, gauche, droite) ;
/// aucun pour un rectangle vide.
pub fn rectangle_parts(left: i32, top: i32, right: i32, bottom: i32) -> (Option<Rect>, alloc::vec::Vec<Rect>) {
    let (left, right) = (left.min(right), left.max(right));
    let (top, bottom) = (top.min(bottom), top.max(bottom));
    if right == left || bottom == top {
        return (None, alloc::vec::Vec::new());
    }
    let inside = Rect::new(left + 1, top + 1, right - 1, bottom - 1);
    let edges = alloc::vec![
        Rect::new(left, top, right, top + 1),
        Rect::new(left, bottom - 1, right, bottom),
        Rect::new(left, top, left + 1, bottom),
        Rect::new(right - 1, top, right, bottom),
    ];
    (Some(inside).filter(|rect| !rect.is_empty()), edges)
}

/// NtGdiRectangle : sur le DC `hdc`, le rectangle de (`left`, `top`) à
/// (`right`, `bottom`) ([`rectangle_parts`]) : son intérieur prend le
/// pinceau du DC, son contour le stylo. Pas encore de stylos : le contour
/// est d'un pixel, noir (BLACK_PEN, le stylo d'un nouveau DC, et celui de
/// COLOR_WINDOWFRAME que les boutons de `user32` choisissent). `Err` :
/// l'erreur de Win32.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn rectangle(hdc: u32, left: i32, top: i32, right: i32, bottom: i32) -> Result<bool, u32> {
    let dc = lock(hdc).ok_or(abi::winerror::ERROR_INVALID_HANDLE)?;
    let Some((_, attr)) = dc.state().owner else { return Ok(false) };
    let brush = fill_brush(&dc, attr, None, false).ok().flatten();
    let state = dc.state();
    let (dx, dy) = logical_origin(&state, None);
    let moved = |rect: Rect| Rect::new(rect.left + dx, rect.top + dy, rect.right + dx, rect.bottom + dy);
    let (inside, edges) = rectangle_parts(left, top, right, bottom);
    if let (Some(inside), Some(brush)) = (inside, brush) {
        paint(&state, moved(inside), abi::gdi::rop::PATCOPY, &fill_of(&state, &brush, None));
    }
    let pen = Fill::Solid(ColorRef(0));
    for edge in edges {
        paint(&state, moved(edge), abi::gdi::rop::PATCOPY, &pen);
    }
    Ok(true)
}

/// Ce que NtGdiGetDCObject rend d'un DC dont les attributs ont pour pinceau
/// `hbrush`, pour stylo `hpen` et pour police `font`, et qui peint dans le
/// bitmap `bitmap` : l'objet du type `kind` (GDI_OBJECT_TYPE_*), la police
/// du système pour une police pas encore choisie, le bitmap par défaut pour
/// un DC de l'écran ; `None` pour un autre type (pas encore de palettes).
pub fn current_object(kind: u32, hbrush: u32, hpen: u32, font: u32, bitmap: Option<u32>) -> Option<u32> {
    use abi::gdi::object_type::{BITMAP, BRUSH, EXTPEN, FONT, PEN};
    match kind {
        BRUSH => Some(hbrush),
        PEN | EXTPEN => Some(hpen),
        FONT if font == 0 => Some(super::brush::stock_object(abi::gdi::stock::SYSTEM_FONT)),
        FONT => Some(font),
        BITMAP => Some(bitmap.unwrap_or_else(|| super::brush::stock_object(abi::gdi::stock::DEFAULT_BITMAP))),
        _ => None,
    }
}

/// NtGdiGetDCObject (GetCurrentObject) : l'objet du type `kind` choisi dans
/// le DC `hdc` ([`current_object`]), lu dans ses attributs chez son
/// propriétaire. `Err` : l'erreur de Win32.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn get_dc_object(hdc: u32, kind: u32) -> Result<u32, u32> {
    use abi::winerror::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};
    let dc = lock(hdc).ok_or(ERROR_INVALID_HANDLE)?;
    let state = dc.state();
    let (_, attr) = state.owner.ok_or(ERROR_INVALID_HANDLE)?;
    let mut bytes = [0u8; offset_of!(DcAttr32, lfnt_new) + 4];
    copy_from_user(&mut bytes, u64::from(attr)).map_err(|_| ERROR_INVALID_HANDLE)?;
    let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let bitmap = state.bitmap.as_ref().map(|selected| selected.handle);
    current_object(
        kind,
        word(offset_of!(DcAttr32, hbrush)),
        word(offset_of!(DcAttr32, hpen)),
        word(offset_of!(DcAttr32, lfnt_new)),
        bitmap,
    )
    .ok_or(ERROR_INVALID_PARAMETER)
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
    paint(&state, pat_rect(x, y, width, height, logical_origin(&state, None)), rop, &fill_of(&state, &brush, None));
    Ok(true)
}

/// Un PatBlt mis en lot (GdiBCPatBlt, `call`) sur `dc`, avec le pinceau et
/// les couleurs du texte et du fond qu'il apporte (celles d'un motif
/// monochrome). Son origine est celle des attributs du DC quand le lot
/// part, pas le `ptlViewportOrg` du lot : le PatBlt de `gdi32` ne le
/// remplit pas (il reste ce qu'avait le TEB), mais il marque le DC
/// (DC_MODE_DIRTY) pour que SetViewportOrgEx et ses voisins vident le lot
/// avant de changer l'origine.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn batched_pat_blt(dc: &Dc, call: &abi::gdi::GdiBsPatBlt32) {
    let (x, y, width, height, rop) = (call.x, call.y, call.width, call.height, call.rop);
    if uses_source(rop) {
        return;
    }
    let Some((_, attr)) = dc.state().owner else { return };
    let Ok(Some(brush)) = fill_brush(dc, attr, Some(call.hbrush), true) else {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: a batched PatBlt without a brush or attributes dropped");
        }
        return;
    };
    let state = dc.state();
    let fill = fill_of(&state, &brush, Some((call.cr_foreground_clr, call.cr_background_clr)));
    paint(&state, pat_rect(x, y, width, height, logical_origin(&state, None)), rop, &fill);
}

/// GdiGetClipBox : le rectangle qui tient là où le DC peint (`prgnRao`),
/// en coordonnées logiques ([`logical_origin`]), et sa complexité
/// (NULLREGION, SIMPLEREGION : un seul rectangle, COMPLEXREGION).
pub fn clip_box(state: &DcState) -> (i32, Rect) {
    let rao = state.rao();
    if rao.is_empty() {
        return (rao.complexity(), Rect::default());
    }
    let bounds = rao.bounds();
    let (dx, dy) = logical_origin(state, None);
    (rao.complexity(), Rect::new(bounds.left - dx, bounds.top - dy, bounds.right - dx, bounds.bottom - dy))
}

/// La translation MM_TEXT des coordonnées logiques d'un DC vers ses
/// coordonnées de périphérique : l'origine de sa vue (`viewport`) moins
/// celle de sa fenêtre (`window`), comme les pose SetViewportOrgEx,
/// OffsetViewportOrgEx, SetWindowOrgEx (DrawState décale la vue pour
/// dessiner le libellé d'un bouton).
pub const fn translation(window: (i32, i32), viewport: (i32, i32)) -> (i32, i32) {
    (viewport.0.wrapping_sub(window.0), viewport.1.wrapping_sub(window.1))
}

/// Les origines de la fenêtre et de la vue du DC, lues dans ses attributs
/// chez son propriétaire ; `None` sans attributs ou s'ils sont illisibles.
fn attr_origins(state: &DcState) -> Option<((i32, i32), (i32, i32))> {
    let (_, attr) = state.owner?;
    let point = |field: usize| {
        let mut bytes = [0u8; 8];
        copy_from_user(&mut bytes, u64::from(attr) + field as u64).ok()?;
        let word = |at: usize| i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        Some((word(0), word(4)))
    };
    Some((point(offset_of!(DcAttr32, window_org))?, point(offset_of!(DcAttr32, viewport_org))?))
}

/// Où tombe, à l'écran, le point logique (0, 0) du DC : son origine plus la
/// translation ([`translation`]) de ses attributs ; un appel en lot apporte
/// l'origine de la vue qu'il avait (`viewport`). Pas encore les étendues
/// (seul MM_TEXT, sans mise à l'échelle).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn logical_origin(state: &DcState, viewport: Option<(i32, i32)>) -> (i32, i32) {
    let (window, attr_viewport) = attr_origins(state).unwrap_or_default();
    let (dx, dy) = translation(window, viewport.unwrap_or(attr_viewport));
    (state.origin.0.wrapping_add(dx), state.origin.1.wrapping_add(dy))
}

/// La translation des coordonnées logiques du DC vers ses coordonnées de
/// périphérique ([`translation`] de ses attributs).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn logical_offset(state: &DcState) -> (i32, i32) {
    let (window, viewport) = attr_origins(state).unwrap_or_default();
    translation(window, viewport)
}

/// NtGdiRectVisible : une partie de `rect` (coordonnées logiques,
/// [`logical_origin`] ; ses bords dans n'importe quel ordre) tombe là où le
/// DC peint (`prgnRao`).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn rect_visible(state: &DcState, rect: Rect) -> bool {
    let (dx, dy) = logical_origin(state, None);
    let (left, right) = (rect.left.min(rect.right), rect.left.max(rect.right));
    let (top, bottom) = (rect.top.min(rect.bottom), rect.top.max(rect.bottom));
    let mut rao = state.rao();
    rao.intersect_rect(Rect::new(left + dx, top + dy, right + dx, bottom + dy));
    !rao.is_empty()
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

    #[test]
    fn logical_coordinates_move_with_the_viewport_and_against_the_window() {
        assert_eq!(translation((0, 0), (0, 0)), (0, 0), "a new DC");
        assert_eq!(translation((0, 0), (12, 4)), (12, 4), "DrawState: OffsetViewportOrgEx");
        assert_eq!(translation((10, 20), (0, 0)), (-10, -20), "SetWindowOrgEx");
        assert_eq!(translation((10, 20), (12, 4)), (2, -16));
    }

    #[test]
    fn a_rectangle_has_an_inside_and_four_one_pixel_edges() {
        let (inside, edges) = rectangle_parts(10, 20, 40, 30);
        assert_eq!(inside, Some(Rect::new(11, 21, 39, 29)));
        assert_eq!(edges[0], Rect::new(10, 20, 40, 21), "the top");
        assert_eq!(edges[1], Rect::new(10, 29, 40, 30), "the bottom: the bottom edge excluded");
        assert_eq!(edges[2], Rect::new(10, 20, 11, 30), "the left");
        assert_eq!(edges[3], Rect::new(39, 20, 40, 30), "the right");
        assert_eq!(rectangle_parts(40, 30, 10, 20).0, inside, "edges in any order");
        assert_eq!(rectangle_parts(10, 20, 12, 30).0, None, "two pixels wide: no inside");
        assert!(rectangle_parts(10, 20, 10, 30).1.is_empty(), "empty");
    }

    #[test]
    fn the_current_objects_of_a_dc() {
        use abi::gdi::object_type::{BITMAP, BRUSH, FONT, PALETTE, PEN};
        assert_eq!(current_object(BRUSH, 0x10, 0x20, 0x30, None), Some(0x10));
        assert_eq!(current_object(PEN, 0x10, 0x20, 0x30, None), Some(0x20));
        assert_eq!(current_object(FONT, 0x10, 0x20, 0x30, None), Some(0x30));
        assert_eq!(current_object(BITMAP, 0x10, 0x20, 0x30, Some(0x40)), Some(0x40));
        assert_eq!(current_object(PALETTE, 0x10, 0x20, 0x30, None), None, "no palettes yet");
    }

    #[test]
    fn a_rect_is_visible_where_it_meets_the_visible_region() {
        let state =
            DcState { origin: (100, 50), vis: Region::from_rect(Rect::new(110, 60, 210, 160)), ..DcState::default() };
        assert!(rect_visible(&state, Rect::new(0, 0, 20, 20)), "(10, 10)-(20, 20) of it");
        assert!(!rect_visible(&state, Rect::new(0, 0, 10, 10)), "left of and above it");
        assert!(!rect_visible(&state, Rect::new(110, 0, 200, 300)), "right of it");
        assert!(rect_visible(&state, Rect::new(50, 50, 20, 20)), "edges in any order");
        assert!(!rect_visible(&DcState::default(), Rect::new(0, 0, 100, 100)), "nothing visible");
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
