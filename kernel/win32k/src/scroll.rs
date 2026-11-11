//! Les barres de défilement des fenêtres (WS_HSCROLL, WS_VSCROLL) :
//! `scrollbar.c` et `nonclient.c` de win32k, `controls/scrollbar.c` de
//! `user32` (ReactOS épinglé), comme spécification.
//!
//! Chaque fenêtre a ses deux barres dès qu'on lui en parle
//! (co_IntCreateScrollBars : SetScrollInfo, GetScrollBarInfo,
//! EnableScrollBar, ou son cadre peint avec une barre) : leur état dans le
//! noyau ([`ScrollBars`] : intervalle, page, position, position suivie,
//! état de chaque partie, `SBINFOEX` de ReactOS), et leur `SBINFO` dans le
//! tas de son bureau (`WND.pSBInfo`), où `user32` lit lui-même GetScrollPos
//! et GetScrollRange ; l'intervalle est d'abord de 0 à 100.
//!
//! - SetScrollInfo ([`set_info`], co_IntSetScrollInfo) : la page ramenée à
//!   l'intervalle, la position dans l'intervalle moins la page ; une barre
//!   qui n'a plus de quoi défiler se cache (ou, `SIF_DISABLENOSCROLL`, ses
//!   flèches se désactivent), une qui en a de nouveau se montre ; la barre
//!   se repeint (ses flèches, si elles changent, par le cadre ; sinon son
//!   intérieur, aussitôt) ;
//! - ShowScrollBar ([`show_scroll_bar`]) : le style de la barre, le cadre
//!   recalculé (SetWindowPos, `SWP_FRAMECHANGED`) s'il change ;
//! - EnableScrollBar ([`enable_scroll_bar`]) : l'état des flèches ; `user32`
//!   repeint la barre ;
//! - GetScrollBarInfo ([`bar_info`], co_IntGetScrollBarInfo) : le rectangle
//!   de la barre dans la fenêtre ([`bar_rect`]), ses flèches et son curseur
//!   ([`thumb`], IntCalculateThumb), l'état de ses parties ; `user32` le
//!   demande pour suivre la souris (DefWndTrackScrollBar : un clic sur une
//!   barre, HTVSCROLL ou HTHSCROLL, devient WM_SYSCOMMAND SC_VSCROLL ou
//!   SC_HSCROLL), et rend l'état de ses parties par NtUserSetScrollBarInfo ;
//! - le dessin ([`bar_ops`], IntDrawScrollBar) : deux flèches
//!   (DrawFrameControl `DFC_SCROLL` : un bouton en relief, enfoncé et plat
//!   pendant un clic, le symbole de Marlett, grisé si la flèche est
//!   désactivée), le fond (le pinceau gris en damier, COLOR_3DFACE sur
//!   COLOR_3DHILIGHT, quand COLOR_3DHILIGHT est COLOR_WINDOW, comme sous les
//!   couleurs d'XP ; COLOR_SCROLLBAR sinon), noir là où l'on clique, et le
//!   curseur (DrawEdge `EDGE_RAISED`) ; entre deux barres, le coin en
//!   COLOR_BTNFACE, et la poignée de taille d'une fenêtre à cadre épais
//!   ([`corner_ops`]).
//!
//! Comme la documentation de l'API (et Wine), ESB_DISABLE_LTUP désactive la
//! flèche du haut d'une barre verticale ; IntEnableScrollBar de ReactOS les
//! échange. L'état de la barre elle-même (`rgstate[0]` : invisible,
//! indisponible, hors de l'écran) se calcule à chaque GetScrollBarInfo, ce
//! que ReactOS écrit puis écrase.
//!
//! Pas encore : les barres de défilement des contrôles (SB_CTL, la classe
//! ScrollBar), les barres d'une fenêtre de droite à gauche
//! (WS_EX_LAYOUTRTL), les thèmes.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    color, esb, sb, sif, sm, state_system, Rect32, SbData32, SbInfo32, ScrollBarInfo32, ScrollInfo32,
    SetScrollBarInfo32, CCHILDREN_SCROLLBAR, OBJID_HSCROLL, RDW_FRAME, RDW_INVALIDATE, SWP_FRAMECHANGED,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, WS_BORDER, WS_CHILD, WS_EX_LEFTSCROLLBAR, WS_HSCROLL,
    WS_MAXIMIZE, WS_THICKFRAME, WS_VSCROLL,
};
use abi::winerror::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER, ERROR_NO_SCROLLBARS};

use crate::gdi::brush::GRAY_PATTERN;
use crate::gdi::dib::{ColorRef, MonoFill, Rect};
use crate::gdi::draw::{draw_edge, Op, BF_FLAT, BF_MIDDLE, BF_RECT, EDGE_RAISED, EDGE_SUNKEN};
use crate::nonclient::{button_symbol, marlett, square_in, Layout};
use crate::window::{self, Window, WindowState};

/// SB_HORZ et SB_VERT, en indices de [`ScrollBars::bars`].
pub const HORZ: usize = 0;
pub const VERT: usize = 1;

/// Les parties d'une barre dans `rgstate` (SCROLL_*) : la flèche du haut ou
/// de gauche, la page avant le curseur, le curseur, la page après, la flèche
/// du bas ou de droite.
pub const TOP_ARROW: usize = 1;
pub const TOP_RECT: usize = 2;
pub const THUMB: usize = 3;
pub const BOTTOM_RECT: usize = 4;
pub const BOTTOM_ARROW: usize = 5;

/// MINTRACKTHUMB : la longueur minimale du curseur d'une barre à page.
const MIN_TRACK_THUMB: i32 = 8;

/// L'état d'une barre dans le noyau (SBINFOEX : son SCROLLINFO et son
/// SCROLLBARINFO).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    pub min: i32,
    pub max: i32,
    pub page: u32,
    pub pos: i32,
    /// nTrackPos : la position que `user32` suit pendant qu'on tire le
    /// curseur (NtUserSetScrollBarInfo).
    pub track_pos: i32,
    /// SIF_THEMED, une fois donné.
    pub themed: bool,
    /// `rgstate` : la barre, puis ses parties ([`TOP_ARROW`]…).
    pub states: [u32; CCHILDREN_SCROLLBAR + 1],
    pub reserved: i32,
}

impl Bar {
    /// Une barre neuve : de 0 à 100, sans page, en 0.
    pub const fn new() -> Self {
        Self { min: 0, max: 100, page: 0, pos: 0, track_pos: 0, themed: false, states: [0; 6], reserved: 0 }
    }

    /// Son SBDATA.
    pub fn data(&self) -> SbData32 {
        SbData32 { pos_min: self.min, pos_max: self.max, page: self.page as i32, pos: self.pos }
    }

    /// Elle n'a rien à faire défiler : posMin >= posMax - max(page - 1, 0).
    pub fn nothing_to_scroll(&self) -> bool {
        let page = i64::from(self.page as i32);
        i64::from(self.min) >= i64::from(self.max) - (page - 1).max(0)
    }
}

impl Default for Bar {
    fn default() -> Self {
        Self::new()
    }
}

/// Les barres d'une fenêtre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrollBars {
    /// La place de leur `SBINFO` dans le tas du bureau.
    pub at: u32,
    /// WSBflags : les flèches désactivées (ESB_*), le même champ pour les
    /// deux barres (comme ReactOS).
    pub flags: u32,
    pub bars: [Bar; 2],
}

impl ScrollBars {
    /// Des barres neuves, leur `SBINFO` en `at`.
    pub const fn new(at: u32) -> Self {
        Self { at, flags: 0, bars: [Bar::new(); 2] }
    }

    /// Leur `SBINFO`.
    pub fn sb_info(&self) -> SbInfo32 {
        SbInfo32 { wsb_flags: self.flags as i32, horz: self.bars[HORZ].data(), vert: self.bars[VERT].data() }
    }
}

/// La barre de SB_HORZ ou SB_VERT. `ERROR_INVALID_PARAMETER` pour une autre
/// valeur ; `ERROR_CALL_NOT_IMPLEMENTED` pour SB_CTL (journalisé une fois).
pub fn index(which: u32) -> Result<usize, u32> {
    match which {
        sb::HORZ => Ok(HORZ),
        sb::VERT => Ok(VERT),
        sb::CTL => {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("win32k: scroll bar controls (SB_CTL): not yet");
            }
            Err(ERROR_CALL_NOT_IMPLEMENTED)
        }
        _ => Err(ERROR_INVALID_PARAMETER),
    }
}

/// Le style d'une fenêtre qui montre la barre `bar`.
const fn style_of(bar: usize) -> u32 {
    if bar == HORZ {
        WS_HSCROLL
    } else {
        WS_VSCROLL
    }
}

/// EngMulDiv : `a × b / c`, arrondi au plus proche (la moitié loin de zéro).
fn mul_div(a: i32, b: i32, c: i32) -> i32 {
    if c == 0 {
        return if (a < 0) == (b < 0) { i32::MAX } else { i32::MIN };
    }
    let product = i64::from(a) * i64::from(b);
    let c = i64::from(c);
    let half = c.abs() / 2;
    let rounded = if (product < 0) == (c < 0) { product + half * c.signum() } else { product - half * c.signum() };
    (rounded / c).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// IntEnableScrollBar : les flèches de `states` selon `arrows` (ESB_*),
/// indisponibles ou non ; rend si elles ont changé.
pub fn enable_arrows(states: &mut [u32; CCHILDREN_SCROLLBAR + 1], arrows: u32) -> bool {
    let mut changed = false;
    let mut put = |index: usize, value: u32| {
        if states[index] != value {
            states[index] = value;
            changed = true;
        }
    };
    match arrows {
        esb::DISABLE_BOTH => {
            put(TOP_ARROW, state_system::UNAVAILABLE);
            put(BOTTOM_ARROW, state_system::UNAVAILABLE);
        }
        esb::DISABLE_LTUP => put(TOP_ARROW, state_system::UNAVAILABLE),
        esb::DISABLE_RTDN => put(BOTTOM_ARROW, state_system::UNAVAILABLE),
        esb::ENABLE_BOTH => {
            put(TOP_ARROW, 0);
            put(BOTTOM_ARROW, 0);
        }
        _ => {}
    }
    changed
}

/// Ce que SetScrollInfo laisse à faire ([`set_info`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Set {
    /// Ce qu'il rend : la position, ou celle d'avant (SIF_PREVIOUSPOS).
    pub returned: i32,
    /// Ni intervalle, ni page, ni position demandés : rien d'autre à faire.
    pub nothing: bool,
    /// L'intervalle ou la page ont changé (bChangeParams).
    pub changed: bool,
    /// La position a changé.
    pub moved: bool,
    /// La barre n'a plus de quoi défiler : elle se cache (SA_SSI_HIDE).
    pub hide: bool,
    /// Elle en a de nouveau : elle se montre (SA_SSI_SHOW).
    pub show: bool,
    /// Ses flèches ont changé (SA_SSI_REPAINT_ARROWS).
    pub repaint_arrows: bool,
}

/// co_IntSetScrollInfo, sans la peinture : la barre `bar` de `bars` prend
/// ce que `info` donne.
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` pour un `cbSize` qui n'est pas celui d'un
/// SCROLLINFO (avec ou sans `nTrackPos`) ou un `fMask` inconnu.
pub fn set_info(bars: &mut ScrollBars, bar: usize, info: &ScrollInfo32) -> Result<Set, u32> {
    let full = size_of::<ScrollInfo32>() as u32;
    if info.cb_size != full && info.cb_size != full - 4 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mask = info.f_mask;
    if mask & !sif::THEMED & !(sif::ALL | sif::DISABLENOSCROLL | sif::PREVIOUSPOS) != 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut set = Set::default();
    let current = &mut bars.bars[bar];
    if mask & sif::THEMED != 0 {
        current.themed = true;
    }
    if mask & sif::PAGE != 0 && current.page != info.n_page {
        current.page = info.n_page;
        set.changed = true;
    }
    let mut old_pos = 0;
    if mask & sif::POS != 0 {
        old_pos = current.pos;
        current.pos = info.n_pos;
    }
    if mask & sif::RANGE != 0 {
        if info.n_min > info.n_max {
            (current.min, current.max) = (info.n_min, info.n_min);
            set.changed = true;
        } else if current.min != info.n_min || current.max != info.n_max {
            (current.min, current.max) = (info.n_min, info.n_max);
            set.changed = true;
        }
    }
    // The page no longer than the range, the position in the range less the
    // page.
    let max_page = current.max.abs_diff(current.min).saturating_add(1);
    current.page = current.page.min(max_page);
    let page = i64::from(current.page.max(1));
    let max_pos = i64::from(current.max) + 1 - page;
    if current.pos < current.min {
        current.pos = current.min;
    } else if i64::from(current.pos) > max_pos {
        current.pos = max_pos as i32;
    }
    set.moved = mask & sif::POS != 0 && current.pos != old_pos;
    set.returned = if mask & sif::PREVIOUSPOS != 0 { old_pos } else { current.pos };
    if mask & sif::ALL == 0 {
        set.nothing = true;
        return Ok(set);
    }
    if mask & (sif::RANGE | sif::PAGE | sif::DISABLENOSCROLL) != 0 {
        let mut flags = bars.flags;
        let current = &bars.bars[bar];
        if i64::from(current.min) + page > i64::from(current.max) {
            if mask & sif::DISABLENOSCROLL != 0 {
                flags = esb::DISABLE_BOTH;
                set.changed = true;
            } else if set.changed {
                set.hide = true;
            }
        } else if mask & !sif::THEMED != sif::PAGE && set.changed {
            // Shown and enabled again, unless only the page changed.
            flags = esb::ENABLE_BOTH;
            set.show = true;
        }
        if bars.flags != flags {
            bars.flags = flags;
            set.repaint_arrows = true;
        }
    }
    if set.changed && mask & sif::DISABLENOSCROLL != 0 {
        let flags = bars.flags;
        enable_arrows(&mut bars.bars[bar].states, flags);
    }
    Ok(set)
}

/// co_IntGetScrollInfo : ce que `info` demande (`fMask`, SIF_ALL pour tout)
/// de la barre `bar`.
pub fn get_info(bar: &Bar, mut info: ScrollInfo32) -> ScrollInfo32 {
    let mask = info.f_mask & !sif::THEMED;
    info.f_mask = mask;
    if mask & sif::PAGE != 0 {
        info.n_page = bar.page;
    }
    if mask & sif::POS != 0 {
        info.n_pos = bar.pos;
    }
    if mask & sif::RANGE != 0 {
        (info.n_min, info.n_max) = (bar.min, bar.max);
    }
    if mask & sif::TRACKPOS != 0 {
        info.n_track_pos = bar.track_pos;
    }
    info
}

/// IntGetScrollBarRect : le rectangle de la barre `bar` d'une fenêtre de
/// style `style` et `ex_style`, de rectangles `window` et `client` (à
/// l'écran), dans les coordonnées de la fenêtre : contre la zone cliente,
/// d'un pixel plus longue de chaque côté si la fenêtre a une bordure
/// (WS_BORDER), du côté de l'autre barre sinon.
pub fn bar_rect(bar: usize, style: u32, ex_style: u32, window: Rect, client: Rect, m: &impl Fn(usize) -> i32) -> Rect {
    let mut rect = Rect::new(
        client.left - window.left,
        client.top - window.top,
        client.right - window.left,
        client.bottom - window.top,
    );
    if bar == HORZ {
        rect.top = rect.bottom;
        rect.bottom += m(sm::CYHSCROLL);
        if style & WS_BORDER != 0 {
            rect.left -= 1;
            rect.right += 1;
        } else if style & WS_VSCROLL != 0 {
            rect.right += 1;
        }
    } else {
        if ex_style & WS_EX_LEFTSCROLLBAR != 0 {
            rect.right = rect.left;
            rect.left -= m(sm::CXVSCROLL);
        } else {
            rect.left = rect.right;
            rect.right += m(sm::CXVSCROLL);
        }
        if style & WS_BORDER != 0 {
            rect.top -= 1;
            rect.bottom += 1;
        } else if style & WS_HSCROLL != 0 {
            rect.bottom += 1;
        }
    }
    rect
}

/// IntCalculateThumb : la longueur des flèches de la barre `bar` (de
/// rectangle `rect`, verticale ou non), et le haut et le bas de son curseur
/// depuis le haut (ou la gauche) de la barre ; (0, 0) sans curseur : une
/// barre trop courte, sans rien à faire défiler et ses deux flèches
/// désactivées, ou sans la place du curseur. Le curseur d'une barre à page
/// est aussi long que la page dans l'intervalle (8 pixels au moins), celui
/// d'une barre sans page de SM_CXHTHUMB.
pub fn thumb(rect: Rect, vertical: bool, bar: &Bar, m: &impl Fn(usize) -> i32) -> (i32, i32, i32) {
    let (arrow, length) =
        if vertical { (m(sm::CYVSCROLL), rect.bottom - rect.top) } else { (m(sm::CXHSCROLL), rect.right - rect.left) };
    if length <= 2 * arrow {
        return (length / 2, 0, 0);
    }
    if bar.states[TOP_ARROW] == state_system::UNAVAILABLE
        && bar.states[BOTTOM_ARROW] == state_system::UNAVAILABLE
        && bar.nothing_to_scroll()
    {
        return (arrow, 0, 0);
    }
    let page = bar.page as i32;
    let mut size = if page != 0 { MIN_TRACK_THUMB } else { m(sm::CXHTHUMB) };
    let room = length - 2 * arrow;
    if room < size {
        return (arrow, 0, 0);
    }
    if page != 0 {
        size = size.max(mul_div(room, page, bar.max.wrapping_sub(bar.min).wrapping_add(1)));
    }
    let mut top = arrow;
    if room > size {
        let last = bar.max.wrapping_sub((page - 1).max(0));
        top = if bar.min < last {
            arrow + mul_div(room - size, bar.pos.wrapping_sub(bar.min), last.wrapping_sub(bar.min))
        } else {
            arrow + size
        };
    }
    (arrow, top, top + size)
}

fn rect32(rect: Rect) -> Rect32 {
    Rect32 { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }
}

/// co_IntGetScrollBarInfo de la barre `bar` (d'état `state` dans le noyau)
/// d'une fenêtre de style `style` et `ex_style`, de rectangles `window` et
/// `client` (à l'écran) : son rectangle dans la fenêtre ([`bar_rect`]),
/// ses flèches et son curseur ([`thumb`]) ; l'état de la barre (invisible
/// sans son style ; sans rien à faire défiler, indisponible, ou hors de
/// l'écran si elle est invisible), puis celui de ses parties.
pub fn bar_info(
    bar: usize,
    state: &Bar,
    style: u32,
    ex_style: u32,
    (window, client): (Rect, Rect),
    m: &impl Fn(usize) -> i32,
) -> ScrollBarInfo32 {
    let rect = bar_rect(bar, style, ex_style, window, client, m);
    let (line, top, bottom) = thumb(rect, bar == VERT, state, m);
    let mut states = state.states;
    states[0] = 0;
    let shown = style & style_of(bar) != 0;
    if !shown {
        states[0] |= state_system::INVISIBLE;
    }
    if state.nothing_to_scroll() {
        states[0] |= if shown { state_system::UNAVAILABLE } else { state_system::OFFSCREEN };
    }
    ScrollBarInfo32 {
        cb_size: size_of::<ScrollBarInfo32>() as u32,
        rc_scroll_bar: rect32(rect),
        dxy_line_button: line,
        xy_thumb_top: top,
        xy_thumb_bottom: bottom,
        reserved: state.reserved,
        rgstate: states,
    }
}

/// Ce que peint le fond d'une barre (DefWndControlColor, CTLCOLOR_SCROLLBAR) :
/// le pinceau gris, COLOR_3DFACE sur COLOR_3DHILIGHT en damier depuis le
/// coin de la fenêtre, quand COLOR_3DHILIGHT est COLOR_WINDOW ; sinon
/// COLOR_SCROLLBAR.
fn background(rect: Rect, c: &impl Fn(usize) -> ColorRef) -> Op {
    if c(color::BTNHIGHLIGHT) == c(color::WINDOW) {
        let fill =
            MonoFill { rows: GRAY_PATTERN, zero: c(color::BTNFACE), one: c(color::BTNHIGHLIGHT), origin: (0, 0) };
        Op::Mono(rect, fill)
    } else {
        Op::Fill(rect, c(color::SCROLLBAR))
    }
}

/// UITOOLS95_DrawFrameScroll d'une flèche : un bouton en relief (enfoncé et
/// plat, `DFCS_PUSHED | DFCS_FLAT`, pendant un clic), le symbole de Marlett
/// (5, 6, 3, 4 : haut, bas, gauche, droite) grisé si elle est désactivée.
fn arrow_ops(
    rect: Rect,
    symbol: char,
    pressed: bool,
    inactive: bool,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let (edge, flat) = if pressed { (EDGE_SUNKEN, BF_FLAT) } else { (EDGE_RAISED, 0) };
    draw_edge(&mut rect.clone(), edge, flat | BF_MIDDLE | BF_RECT, c, ops);
    button_symbol(rect, symbol, inactive, pressed, c, layout, ops)
}

/// IntDrawScrollBar d'une barre (`info`, dans les coordonnées de la
/// fenêtre ; verticale ou non) : ses flèches (IntDrawScrollArrows), son fond
/// et son curseur (IntDrawScrollInterior) ; rien pour un rectangle vide.
/// Faux si les symboles des flèches n'ont pas pu se dessiner.
pub fn bar_ops(
    info: &ScrollBarInfo32,
    vertical: bool,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let r = info.rc_scroll_bar;
    let rect = Rect::new(r.left, r.top, r.right, r.bottom);
    if rect.is_empty() {
        return true;
    }
    let line = info.dxy_line_button;
    let mut drawn = true;
    if line != 0 {
        let (first, last, symbols) = if vertical {
            (
                Rect::new(rect.left, rect.top, rect.right, rect.top + line),
                Rect::new(rect.left, rect.bottom - line, rect.right, rect.bottom),
                ('5', '6'),
            )
        } else {
            (
                Rect::new(rect.left, rect.top, rect.left + line, rect.bottom),
                Rect::new(rect.right - line, rect.top, rect.right, rect.bottom),
                ('3', '4'),
            )
        };
        for (part, at, symbol) in [(TOP_ARROW, first, symbols.0), (BOTTOM_ARROW, last, symbols.1)] {
            let state = info.rgstate[part];
            let pressed = state & state_system::PRESSED != 0;
            let inactive = state & state_system::UNAVAILABLE != 0;
            drawn &= arrow_ops(at, symbol, pressed, inactive, c, layout, ops);
        }
    }
    interior_ops(info, vertical, c, ops);
    drawn
}

/// IntDrawScrollInterior : le fond de la barre entre ses flèches ([`background`],
/// noir sur la page où l'on clique), puis son curseur en relief.
pub fn interior_ops(info: &ScrollBarInfo32, vertical: bool, c: &impl Fn(usize) -> ColorRef, ops: &mut Vec<Op>) {
    let r = info.rc_scroll_bar;
    let line = info.dxy_line_button;
    let mut rect = if vertical {
        Rect::new(r.left, r.top + line, r.right, r.bottom - line)
    } else {
        Rect::new(r.left + line, r.top, r.right - line, r.bottom)
    };
    if info.xy_thumb_bottom == 0 {
        ops.push(background(rect, c));
        return;
    }
    let size = info.xy_thumb_bottom - info.xy_thumb_top;
    let before = info.xy_thumb_top - line;
    let black = ColorRef::rgb(0, 0, 0);
    let part = |at: Rect, pressed: bool| {
        if pressed {
            Op::Fill(at, black)
        } else {
            background(at, c)
        }
    };
    let top_pressed = info.rgstate[TOP_RECT] & state_system::PRESSED != 0;
    let bottom_pressed = info.rgstate[BOTTOM_RECT] & state_system::PRESSED != 0;
    if line != 0 && size != 0 {
        if vertical {
            ops.push(part(Rect::new(rect.left, rect.top, rect.right, rect.top + before), top_pressed));
            rect.top += before;
            ops.push(part(Rect::new(rect.left, rect.top + size, rect.right, rect.bottom), bottom_pressed));
            rect.bottom = rect.top + size;
        } else {
            ops.push(part(Rect::new(rect.left, rect.top, rect.left + before, rect.bottom), top_pressed));
            rect.left += before;
            ops.push(part(Rect::new(rect.left + size, rect.top, rect.right, rect.bottom), bottom_pressed));
            rect.right = rect.left + size;
        }
    }
    if size != 0 {
        draw_edge(&mut rect, EDGE_RAISED, BF_RECT | BF_MIDDLE, c, ops);
    }
}

/// NC_DoNCPaint, entre deux barres : le coin (dans `inside`, le rectangle
/// de la fenêtre sans son cadre, son titre, sa barre de menus et son bord
/// client) en COLOR_BTNFACE ; avec une poignée de taille (`size_grip`), les
/// symboles o (COLOR_BTNHIGHLIGHT) et p (COLOR_BTNSHADOW) de Marlett
/// (DFCS_SCROLLSIZEGRIP).
pub fn corner_ops(
    inside: Rect,
    ex_style: u32,
    size_grip: bool,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let mut corner = inside;
    if ex_style & WS_EX_LEFTSCROLLBAR != 0 {
        corner.right = corner.left + m(sm::CXVSCROLL);
    } else {
        corner.left = corner.right - m(sm::CXVSCROLL);
    }
    corner.top = corner.bottom - m(sm::CYHSCROLL);
    ops.push(Op::Fill(corner, c(color::BTNFACE)));
    if !size_grip {
        return true;
    }
    let cell = square_in(corner);
    marlett(cell, 'o', c(color::BTNHIGHLIGHT), 0, corner, layout, ops)
        && marlett(cell, 'p', c(color::BTNSHADOW), 0, corner, layout, ops)
}

/// HASSIZEGRIP : une fenêtre de premier niveau à cadre épais, non agrandie ;
/// ou une fille aussi grande que la zone cliente d'un tel parent.
pub fn has_size_grip(state: &WindowState, parent: Option<&WindowState>) -> bool {
    let grip = |style: u32| style & WS_THICKFRAME != 0 && style & WS_MAXIMIZE == 0;
    if state.style & WS_CHILD == 0 {
        return grip(state.style);
    }
    let Some(parent) = parent else { return false };
    let size = |r: Rect| (r.right - r.left, r.bottom - r.top);
    grip(parent.style) && size(state.window) == size(parent.client)
}

/// Ce que le cadre de `window` (d'état `state`) peint de ses barres : les
/// informations des barres qu'elle montre, et si elle a une poignée de
/// taille. Ses barres naissent ici si elle n'en avait pas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn frame_bars(window: &Window, state: &WindowState) -> (Vec<(ScrollBarInfo32, bool)>, bool) {
    if state.style & (WS_HSCROLL | WS_VSCROLL) == 0 {
        return (Vec::new(), false);
    }
    let Ok(bars) = ensure(window) else { return (Vec::new(), false) };
    let mut shown = Vec::new();
    for bar in [VERT, HORZ] {
        if state.style & style_of(bar) != 0 {
            let info = bar_info(
                bar,
                &bars.bars[bar],
                state.style,
                state.ex_style,
                (state.window, state.client),
                &crate::metrics::get,
            );
            shown.push((info, bar == VERT));
        }
    }
    let parent = window::get(state.parent).map(|parent| parent.state());
    (shown, has_size_grip(state, parent.as_ref()))
}

/// co_IntCreateScrollBars : les barres de `window`, créées (leur `SBINFO`
/// dans le tas de son bureau) si elle n'en a pas.
///
/// # Errors
/// `STATUS_NO_MEMORY` si le tas est plein ; celles de l'écriture du tas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn ensure(window: &Window) -> Result<ScrollBars, NtStatus> {
    if let Some(bars) = window.state().scroll {
        return Ok(bars);
    }
    let size = size_of::<SbInfo32>() as u32;
    let at = window.heap.alloc(size)?;
    let mut kept = ScrollBars::new(at);
    window::change(window, |state| kept = *state.scroll.get_or_insert(kept));
    if kept.at != at {
        // Another thread made them first.
        window.heap.free(at, size);
        return Ok(kept);
    }
    publish(window, &kept)?;
    Ok(kept)
}

/// Écrit le `SBINFO` de `bars` dans le tas du bureau de `window`.
fn publish(window: &Window, bars: &ScrollBars) -> Result<(), NtStatus> {
    window.heap.section.write_kernel(u64::from(bars.at), bars.sb_info().as_bytes())
}

/// Change les barres de `window` (créées s'il le faut) par `change`, puis
/// réécrit leur `SBINFO`.
fn update<R>(window: &Window, change: impl FnOnce(&mut ScrollBars) -> R) -> Result<R, u32> {
    ensure(window).map_err(abi::winerror::dos_error)?;
    let mut result = None;
    let state = window::change(window, |state| {
        if let Some(bars) = state.scroll.as_mut() {
            result = Some(change(bars));
        }
    });
    let bars = state.scroll.ok_or(ERROR_NO_SCROLLBARS)?;
    publish(window, &bars).map_err(abi::winerror::dos_error)?;
    result.ok_or(ERROR_NO_SCROLLBARS)
}

/// NtUserSetScrollInfo de la barre `which` (SB_HORZ, SB_VERT) de `window` :
/// [`set_info`], puis la barre cachée ou montrée ([`show_scroll_bar`]), ou
/// repeinte si `redraw` et qu'elle se voit : par le cadre si ses flèches
/// changent (ou avec un thème), sinon son intérieur aussitôt
/// (IntRefeshScrollInterior). Rend la position (ou celle d'avant).
///
/// # Errors
/// L'erreur de Win32 : celles de [`index`] et de [`set_info`] ;
/// `ERROR_NOT_ENOUGH_MEMORY` si le tas du bureau est plein.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système. Rappelle le mode utilisateur.
pub fn set_scroll_info(window: &Arc<Window>, which: u32, info: &ScrollInfo32, redraw: bool) -> Result<i32, u32> {
    let bar = index(which)?;
    let set = update(window, |bars| set_info(bars, bar, info))??;
    if set.nothing {
        return Ok(set.returned);
    }
    if set.hide {
        show_scroll_bar(window, which, false, false)?;
        return Ok(set.returned);
    }
    if set.show && show_scroll_bar(window, which, true, true)? {
        // SetWindowPos has painted the frame.
        return Ok(set.returned);
    }
    let state = window.state();
    let Some(bars) = state.scroll else { return Ok(set.returned) };
    if !redraw || state.style & style_of(bar) == 0 || !window::is_visible(window) {
        return Ok(set.returned);
    }
    let themed = bars.bars[bar].themed;
    if set.repaint_arrows || (themed && (set.changed || set.moved)) {
        // The bar's rectangle, from the client area's corner.
        let rect = bar_rect(bar, state.style, state.ex_style, state.window, state.client, &crate::metrics::get);
        let (dx, dy) = (state.client.left - state.window.left, state.client.top - state.window.top);
        let rect = Rect::new(rect.left - dx, rect.top - dy, rect.right - dx, rect.bottom - dy);
        crate::paint::redraw_window(window, Some(rect), None, RDW_INVALIDATE | RDW_FRAME);
    } else if !themed {
        let info = bar_info(
            bar,
            &bars.bars[bar],
            state.style,
            state.ex_style,
            (state.window, state.client),
            &crate::metrics::get,
        );
        let mut ops = Vec::new();
        interior_ops(&info, bar == VERT, &crate::paint::system_color, &mut ops);
        crate::paint::draw_frame_ops(window, &state, &ops);
    }
    Ok(set.returned)
}

/// NtUserSBGetParms (co_IntGetScrollInfo) de la barre `which` de `window` :
/// [`get_info`].
///
/// # Errors
/// Celles de [`index`] ; `ERROR_NO_SCROLLBARS` si elle n'a pas encore de
/// barres.
pub fn scroll_info(window: &Window, which: u32, info: ScrollInfo32) -> Result<ScrollInfo32, u32> {
    let bar = index(which)?;
    let bars = window.state().scroll.ok_or(ERROR_NO_SCROLLBARS)?;
    Ok(get_info(&bars.bars[bar], info))
}

/// La barre d'un OBJID_* (SBOBJ_TO_SBID).
fn bar_of_object(object: i32) -> Result<usize, u32> {
    let which = object.wrapping_sub(OBJID_HSCROLL);
    index(u32::try_from(which).map_err(|_| ERROR_INVALID_PARAMETER)?)
}

/// NtUserGetScrollBarInfo de l'objet `object` (OBJID_HSCROLL, OBJID_VSCROLL)
/// de `window`, ses barres créées s'il le faut : [`bar_info`].
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` pour un autre objet ;
/// `ERROR_CALL_NOT_IMPLEMENTED` pour OBJID_CLIENT (SB_CTL) ;
/// `ERROR_NOT_ENOUGH_MEMORY` si le tas du bureau est plein.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn scroll_bar_info(window: &Window, object: i32) -> Result<ScrollBarInfo32, u32> {
    let bar = bar_of_object(object)?;
    let bars = ensure(window).map_err(abi::winerror::dos_error)?;
    let state = window.state();
    Ok(bar_info(bar, &bars.bars[bar], state.style, state.ex_style, (state.window, state.client), &crate::metrics::get))
}

/// NtUserSetScrollBarInfo de l'objet `object` de `window` : la position
/// suivie et l'état des parties que `user32` tient pendant un clic.
///
/// # Errors
/// Comme [`scroll_bar_info`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_scroll_bar_info(window: &Window, object: i32, info: &SetScrollBarInfo32) -> Result<(), u32> {
    let bar = bar_of_object(object)?;
    update(window, |bars| {
        let current = &mut bars.bars[bar];
        current.track_pos = info.n_track_pos;
        current.reserved = info.reserved;
        current.states = info.rgstate;
    })
}

/// NtUserEnableScrollBar : les flèches de la barre `which` (SB_HORZ,
/// SB_VERT, SB_BOTH) de `window` selon `arrows` (ESB_*), qui devient aussi
/// `WSBflags` ; rend si elles ont changé (`user32` repeint alors la barre).
/// Faux pour la fenêtre d'un bureau.
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` pour une autre barre ; celles de [`index`]
/// pour SB_CTL ; `ERROR_NOT_ENOUGH_MEMORY` si le tas du bureau est plein.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn enable_scroll_bar(window: &Window, which: u32, arrows: u32) -> Result<bool, u32> {
    if window.is_desktop_window() {
        return Ok(false);
    }
    let bars: &[usize] = match which {
        sb::BOTH => &[VERT, HORZ],
        sb::HORZ => &[HORZ],
        sb::VERT => &[VERT],
        other => {
            index(other)?;
            return Err(ERROR_INVALID_PARAMETER);
        }
    };
    update(window, |scroll| {
        scroll.flags = arrows;
        let mut changed = false;
        for &bar in bars {
            changed |= enable_arrows(&mut scroll.bars[bar].states, arrows);
        }
        changed
    })
}

/// co_UserShowScrollBar : la barre `which` de `window` montrée ou cachée
/// (`show_h` pour SB_HORZ, `show_v` pour SB_VERT, les deux pour SB_BOTH) ;
/// si son style change, le cadre est recalculé et repeint (SetWindowPos,
/// `SWP_FRAMECHANGED`). Rend si le cadre a changé.
///
/// # Errors
/// `ERROR_INVALID_PARAMETER` pour une autre barre ; celles de [`index`]
/// pour SB_CTL.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système. Rappelle le mode utilisateur.
pub fn show_scroll_bar(window: &Arc<Window>, which: u32, show_h: bool, show_v: bool) -> Result<bool, u32> {
    let (mut set, mut clear) = (0, 0);
    let mut put = |show: bool, style: u32| {
        if show {
            set |= style;
        } else {
            clear |= style;
        }
    };
    match which {
        sb::HORZ => put(show_h, WS_HSCROLL),
        sb::VERT => put(show_v, WS_VSCROLL),
        sb::BOTH => {
            put(show_h, WS_HSCROLL);
            put(show_v, WS_VSCROLL);
        }
        // The control itself (co_WinPosShowWindow): not yet, `index` says so.
        sb::CTL => {
            index(which)?;
            return Ok(false);
        }
        _ => return Err(ERROR_INVALID_PARAMETER),
    }
    let mut old = 0;
    window::change(window, |state| {
        old = state.style;
        state.style = (state.style | set) & !clear;
    });
    if old & clear == 0 && old & set == set {
        return Ok(false);
    }
    let flags = SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER | SWP_FRAMECHANGED;
    crate::winpos::set_window_pos(window, 0, 0, 0, 0, 0, flags);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::{WS_CAPTION, WS_OVERLAPPEDWINDOW, WS_POPUP};

    fn metric(index: usize) -> i32 {
        crate::metrics::system_metrics(1280, 800, &crate::metrics::Parameters::DEFAULT)[index]
    }

    fn info(mask: u32, min: i32, max: i32, page: u32, pos: i32) -> ScrollInfo32 {
        ScrollInfo32 { cb_size: 28, f_mask: mask, n_min: min, n_max: max, n_page: page, n_pos: pos, n_track_pos: 0 }
    }

    #[test]
    fn set_scroll_info_keeps_the_page_and_the_position_in_the_range() {
        let mut bars = ScrollBars::new(0);
        let set = set_info(&mut bars, VERT, &info(sif::ALL, 0, 99, 10, 30)).unwrap();
        assert_eq!((set.returned, set.changed, set.show, set.hide), (30, true, true, false));
        assert_eq!(bars.bars[VERT].data(), SbData32 { pos_min: 0, pos_max: 99, page: 10, pos: 30 });
        // The last position is the range less the page.
        let set = set_info(&mut bars, VERT, &info(sif::POS, 0, 0, 0, 200)).unwrap();
        assert_eq!((set.returned, set.changed, set.nothing), (90, false, false));
        // SetScrollPos: the position before.
        let set = set_info(&mut bars, VERT, &info(sif::POS | sif::PREVIOUSPOS, 0, 0, 0, -5)).unwrap();
        assert_eq!((set.returned, bars.bars[VERT].pos), (90, 0));
        // A page longer than the range is cut to it.
        set_info(&mut bars, VERT, &info(sif::PAGE, 0, 0, 500, 0)).unwrap();
        assert_eq!(bars.bars[VERT].page, 100);
        // A range given upside down is a single point.
        set_info(&mut bars, HORZ, &info(sif::RANGE, 50, 10, 0, 0)).unwrap();
        assert_eq!((bars.bars[HORZ].min, bars.bars[HORZ].max, bars.bars[HORZ].pos), (50, 50, 50));
        assert_eq!(bars.bars[VERT].min, 0, "each bar its own");
    }

    #[test]
    fn a_bar_with_nothing_to_scroll_hides_or_is_disabled() {
        let mut bars = ScrollBars::new(0);
        let set = set_info(&mut bars, VERT, &info(sif::RANGE | sif::PAGE, 0, 9, 10, 0)).unwrap();
        assert!(set.hide && !set.show, "the page holds the whole range");
        let set = set_info(&mut bars, VERT, &info(sif::RANGE | sif::PAGE, 0, 9, 10, 0)).unwrap();
        assert!(!set.hide, "nothing changed");
        let set = set_info(&mut bars, VERT, &info(sif::RANGE | sif::PAGE | sif::DISABLENOSCROLL, 0, 9, 10, 0)).unwrap();
        assert!(!set.hide && set.repaint_arrows);
        assert_eq!(bars.flags, esb::DISABLE_BOTH);
        assert_eq!(
            (bars.bars[VERT].states[TOP_ARROW], bars.bars[VERT].states[BOTTOM_ARROW]),
            (state_system::UNAVAILABLE, state_system::UNAVAILABLE)
        );
        let set = set_info(&mut bars, VERT, &info(sif::RANGE, 0, 99, 0, 0)).unwrap();
        assert!(set.show && set.repaint_arrows, "something to scroll again");
        assert_eq!(bars.flags, esb::ENABLE_BOTH);
        let set = set_info(&mut bars, VERT, &info(sif::PAGE, 0, 0, 20, 0)).unwrap();
        assert!(!set.show && !set.hide, "a page alone shows nothing");
    }

    #[test]
    fn set_scroll_info_checks_its_record() {
        let mut bars = ScrollBars::new(0);
        let mut bad = info(sif::ALL, 0, 9, 0, 0);
        bad.cb_size = 20;
        assert_eq!(set_info(&mut bars, VERT, &bad), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(set_info(&mut bars, VERT, &info(0x100, 0, 9, 0, 0)), Err(ERROR_INVALID_PARAMETER));
        let mut short = info(sif::RANGE, 0, 9, 0, 0);
        short.cb_size = 24;
        assert!(set_info(&mut bars, VERT, &short).is_ok(), "without nTrackPos");
        let set = set_info(&mut bars, VERT, &info(sif::DISABLENOSCROLL, 0, 0, 0, 0)).unwrap();
        assert!(set.nothing, "no SIF_ALL");
    }

    #[test]
    fn get_scroll_info_gives_what_is_asked() {
        let bar = Bar { min: 1, max: 50, page: 5, pos: 7, track_pos: 9, ..Bar::new() };
        let got =
            get_info(&bar, ScrollInfo32 { cb_size: 28, f_mask: sif::ALL | sif::THEMED, ..ScrollInfo32::default() });
        assert_eq!((got.n_min, got.n_max, got.n_page, got.n_pos, got.n_track_pos), (1, 50, 5, 7, 9));
        let got = get_info(&bar, ScrollInfo32 { cb_size: 28, f_mask: sif::POS, n_min: -1, ..ScrollInfo32::default() });
        assert_eq!((got.n_pos, got.n_min, got.f_mask), (7, -1, sif::POS));
    }

    #[test]
    fn the_arrows_follow_the_documented_sides() {
        let mut states = [0; 6];
        assert!(enable_arrows(&mut states, esb::DISABLE_LTUP));
        assert_eq!((states[TOP_ARROW], states[BOTTOM_ARROW]), (state_system::UNAVAILABLE, 0), "the top arrow");
        assert!(enable_arrows(&mut states, esb::DISABLE_RTDN));
        assert_eq!(states[BOTTOM_ARROW], state_system::UNAVAILABLE);
        assert!(!enable_arrows(&mut states, esb::DISABLE_BOTH), "already");
        assert!(enable_arrows(&mut states, esb::ENABLE_BOTH));
        assert_eq!(states, [0; 6]);
    }

    #[test]
    fn the_bars_lie_against_the_client_area() {
        let window = Rect::new(100, 100, 400, 300);
        let client = Rect::new(104, 123, 380, 280);
        let style = WS_OVERLAPPEDWINDOW | WS_VSCROLL | WS_HSCROLL;
        // WS_BORDER (in WS_CAPTION): a pixel longer at each end.
        assert_eq!(bar_rect(VERT, style, 0, window, client, &metric), Rect::new(280, 22, 296, 181));
        assert_eq!(bar_rect(HORZ, style, 0, window, client, &metric), Rect::new(3, 180, 281, 196));
        let popup = WS_POPUP | WS_VSCROLL | WS_HSCROLL;
        assert_eq!(bar_rect(VERT, popup, 0, window, client, &metric), Rect::new(280, 23, 296, 181), "to the corner");
        assert_eq!(bar_rect(HORZ, popup, 0, window, client, &metric), Rect::new(4, 180, 281, 196));
        assert_eq!(
            bar_rect(VERT, WS_POPUP | WS_VSCROLL, WS_EX_LEFTSCROLLBAR, window, client, &metric),
            Rect::new(-12, 23, 4, 180),
            "on the left"
        );
        assert!(style & WS_CAPTION == WS_CAPTION);
    }

    #[test]
    fn the_thumb_is_as_long_as_the_page_and_where_the_position_is() {
        let arrow = metric(sm::CYVSCROLL);
        let rect = Rect::new(0, 0, 16, 2 * arrow + 100);
        let mut bar = Bar { min: 0, max: 99, page: 10, pos: 0, ..Bar::new() };
        assert_eq!(thumb(rect, true, &bar, &metric), (arrow, arrow, arrow + 10), "a tenth of the room, at the top");
        bar.pos = 90;
        assert_eq!(thumb(rect, true, &bar, &metric), (arrow, arrow + 90, arrow + 100), "at the bottom");
        bar.pos = 45;
        assert_eq!(thumb(rect, true, &bar, &metric), (arrow, arrow + 45, arrow + 55));
        bar.page = 0;
        bar.pos = 0;
        let size = metric(sm::CXHTHUMB);
        assert_eq!(thumb(rect, true, &bar, &metric), (arrow, arrow, arrow + size), "without a page");
        let short = Rect::new(0, 0, 16, 2 * arrow);
        assert_eq!(thumb(short, true, &bar, &metric), (arrow, 0, 0), "no room: half the bar each arrow");
        let mut disabled = Bar { min: 0, max: 9, page: 10, ..Bar::new() };
        enable_arrows(&mut disabled.states, esb::DISABLE_BOTH);
        assert_eq!(thumb(rect, true, &disabled, &metric), (arrow, 0, 0), "nothing to scroll");
        let wide = Rect::new(0, 0, 2 * metric(sm::CXHSCROLL) + 200, 16);
        let bar = Bar { min: 0, max: 199, page: 50, pos: 150, ..Bar::new() };
        let arrow = metric(sm::CXHSCROLL);
        assert_eq!(thumb(wide, false, &bar, &metric), (arrow, arrow + 150, arrow + 200), "horizontal");
    }

    #[test]
    fn the_bar_s_own_state_comes_from_its_style_and_range() {
        let window = Rect::new(0, 0, 200, 200);
        let client = Rect::new(0, 0, 184, 200);
        let mut bar = Bar::new();
        let shown = bar_info(VERT, &bar, WS_POPUP | WS_VSCROLL, 0, (window, client), &metric);
        assert_eq!(shown.rgstate[0], 0);
        assert_eq!(shown.rc_scroll_bar, Rect32 { left: 184, top: 0, right: 200, bottom: 200 });
        let hidden = bar_info(HORZ, &bar, WS_POPUP | WS_VSCROLL, 0, (window, client), &metric);
        assert_eq!(hidden.rgstate[0], state_system::INVISIBLE);
        bar.max = 0;
        let empty = bar_info(VERT, &bar, WS_POPUP | WS_VSCROLL, 0, (window, client), &metric);
        assert_eq!(empty.rgstate[0], state_system::UNAVAILABLE);
        let offscreen = bar_info(HORZ, &bar, WS_POPUP | WS_VSCROLL, 0, (window, client), &metric);
        assert_eq!(offscreen.rgstate[0], state_system::INVISIBLE | state_system::OFFSCREEN);
    }

    fn system(index: usize) -> ColorRef {
        ColorRef(crate::metrics::SYSTEM_COLORS[index])
    }

    fn no_fonts(
        _: crate::font::Named,
        _: i32,
        _: &[u16],
        _: Option<i32>,
        _: crate::font::Quality,
    ) -> Option<crate::font::TextRun> {
        None
    }

    /// The colour of each pixel of `ops` drawn on a 20 × 80 surface.
    fn render(ops: &[Op]) -> impl Fn(i32, i32) -> u32 {
        use crate::gdi::dib::{Bitmap, PixelLayout};
        let mut pixels = alloc::vec![0u32; 20 * 80];
        let mut surface = Bitmap::new(&mut pixels, 20, 80, 20, PixelLayout::Rgbx).unwrap();
        crate::gdi::draw::paint(
            &mut surface,
            ops,
            (0, 0),
            &crate::gdi::region::Region::from_rect(Rect::new(0, 0, 20, 80)),
        );
        move |x, y| pixels[(y * 20 + x) as usize]
    }

    #[test]
    fn a_bar_is_drawn_arrows_background_and_thumb() {
        let info = ScrollBarInfo32 {
            cb_size: 60,
            rc_scroll_bar: Rect32 { left: 0, top: 0, right: 16, bottom: 80 },
            dxy_line_button: 16,
            xy_thumb_top: 30,
            xy_thumb_bottom: 40,
            ..ScrollBarInfo32::default()
        };
        let mut ops = Vec::new();
        assert!(!bar_ops(&info, true, &system, &no_fonts, &mut ops), "no Marlett here");
        let at = render(&ops);
        assert_eq!((at(0, 0), at(5, 5)), (system(color::LIGHT_3D).0, system(color::BTNFACE).0), "the top arrow");
        assert_eq!(at(15, 79), system(color::DKSHADOW_3D).0, "the bottom arrow");
        // The gray brush, from the window's corner: 3DFACE where x + y is
        // even, 3DHILIGHT where it is odd.
        assert_eq!((at(4, 20), at(5, 20)), (system(color::BTNFACE).0, system(color::BTNHIGHLIGHT).0));
        assert_eq!(at(5, 45), system(color::BTNFACE).0, "below the thumb");
        assert_eq!(
            (at(0, 30), at(1, 31), at(8, 35)),
            (system(color::LIGHT_3D).0, system(color::BTNHIGHLIGHT).0, system(color::BTNFACE).0),
            "the thumb"
        );
        let mut pressed = info;
        pressed.rgstate[BOTTOM_RECT] = state_system::PRESSED;
        pressed.rgstate[TOP_ARROW] = state_system::PRESSED;
        let mut ops = Vec::new();
        bar_ops(&pressed, true, &system, &no_fonts, &mut ops);
        let at = render(&ops);
        assert_eq!(at(4, 50), 0, "black where the click is");
        assert_eq!(
            (at(0, 0), at(1, 1)),
            (system(color::BTNSHADOW).0, system(color::BTNFACE).0),
            "a pushed, flat arrow"
        );
        let no_thumb = ScrollBarInfo32 { xy_thumb_top: 0, xy_thumb_bottom: 0, ..info };
        let mut ops = Vec::new();
        bar_ops(&no_thumb, true, &system, &no_fonts, &mut ops);
        assert_eq!(render(&ops)(5, 35), system(color::BTNFACE).0, "all background");
    }

    #[test]
    fn a_size_grip_only_on_a_sizable_window() {
        let state =
            |style: u32, window: Rect, client: Rect| WindowState { style, window, client, ..WindowState::default() };
        let top = state(WS_OVERLAPPEDWINDOW, Rect::new(0, 0, 100, 100), Rect::new(4, 23, 96, 96));
        assert!(has_size_grip(&top, None));
        assert!(!has_size_grip(&state(WS_OVERLAPPEDWINDOW | WS_MAXIMIZE, top.window, top.client), None));
        assert!(!has_size_grip(&state(WS_POPUP | WS_CAPTION, top.window, top.client), None));
        let child = state(WS_CHILD, Rect::new(4, 23, 96, 96), Rect::new(4, 23, 96, 96));
        assert!(has_size_grip(&child, Some(&top)), "as big as its parent's client area");
        let smaller = state(WS_CHILD, Rect::new(4, 23, 50, 96), Rect::new(4, 23, 50, 96));
        assert!(!has_size_grip(&smaller, Some(&top)));
    }

    #[test]
    fn mul_div_rounds_to_the_nearest() {
        assert_eq!(mul_div(10, 1, 4), 3, "2.5 goes up");
        assert_eq!(mul_div(10, 1, 3), 3);
        assert_eq!(mul_div(-10, 1, 4), -3, "and away from zero");
        assert_eq!(mul_div(100, 10, 100), 10);
    }
}
