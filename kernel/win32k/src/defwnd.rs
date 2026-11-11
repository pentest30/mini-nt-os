//! DefWindowProc côté noyau (IntDefWindowProc), que `user32` appelle par
//! NtUserMessageCall (`FNID_DEFWINDOWPROC`) pour les messages qu'il ne
//! traite pas lui-même, et les mesures du cadre d'une fenêtre que
//! CreateWindowEx et SetWindowPos emploient (co_WinPosGetMinMaxInfo).
//!
//! Comme ReactOS (`defwnd.c`, `nonclient.c`, `winpos.c`, comme
//! spécification), d'après les styles de la fenêtre et les métriques du
//! système ([`crate::metrics`]) :
//! - WM_NCCALCSIZE ([`nc_calc_size`]) : la zone cliente est le rectangle de
//!   la fenêtre sans ses bordures (`UserGetWindowBorders`), sa barre de
//!   titre, son bord client et ses barres de défilement ; avec des
//!   rectangles valides (`wParam`), les `WVR_*` de sa classe ;
//! - WM_GETMINMAXINFO, ses valeurs par défaut ([`min_max_info`]), adaptées
//!   à la zone de travail du moniteur ([`adapt_to_monitor`]) ;
//! - WM_WINDOWPOSCHANGING : la taille demandée, ramenée dans les limites de
//!   WM_GETMINMAXINFO ([`limit_size`]) ; WM_WINDOWPOSCHANGED : WM_MOVE et
//!   WM_SIZE si la zone cliente a bougé ou changé ;
//! - WM_NCHITTEST : l'endroit d'un point dans la fenêtre ([`nc_hit_test`],
//!   GetNCHitEx) ;
//! - WM_MOUSEACTIVATE : la question remonte aux parents d'une fenêtre fille ;
//!   un clic sur la barre de titre n'active pas (WM_NCLBUTTONDOWN le fera),
//!   un autre active ;
//! - WM_NCLBUTTONDOWN (NC_HandleNCLButtonDown) : sur la barre de titre, la
//!   fenêtre de premier niveau activée et passée devant, puis SC_MOVE ; sur
//!   un bord ou un coin, SC_SIZE ; sur un bouton du titre, son suivi
//!   ([`crate::sizemove`]) ;
//! - WM_NCACTIVATE : le cadre peint actif ou inactif
//!   (`crate::paint::set_frame_active`, NC_HandleNCActivate ; pas de
//!   peinture pour un `lParam` de -1) ; rend TRUE ;
//! - WM_SYSCOMMAND ([`crate::sizemove::sys_command`]) : SC_MOVE, SC_SIZE,
//!   SC_CLOSE (WM_CLOSE), SC_MINIMIZE, SC_MAXIMIZE, SC_RESTORE ;
//! - WM_SETCURSOR ([`crate::cursor::def_set_cursor`]) : le curseur de la
//!   classe dans la zone cliente, une flèche double sur un bord, la flèche
//!   ailleurs ;
//! - WM_SETICON, WM_GETICON ([`crate::cursor::set_window_icon`],
//!   [`crate::cursor::window_icon`]) : les icônes de la fenêtre, dans ses
//!   propriétés ; le cadre se repeint ;
//! - WM_DEVICECHANGE rend TRUE ; un message de l'application (au-delà de
//!   WM_USER) rend 0.
//!
//! Les autres messages que ReactOS traite ici (WM_PAINT, WM_ERASEBKGND,
//! WM_NCPAINT, WM_ACTIVATE, WM_SHOWWINDOW,
//! WM_CLOSE (DestroyWindow), les touches, le double-clic sur le titre…)
//! attendent la peinture, les contextes de périphérique, l'activation et
//! l'entrée : ils rendent 0, journalisés une fois chacun. Pas encore de
//! menus (`WNDS_HASMENU`).

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::mem::size_of;

use abi::ntstatus::NtStatus;
use abi::user::vk::{VK_ESCAPE, VK_F10, VK_LMENU, VK_MENU, VK_RMENU, VK_TAB};
use abi::user::{
    sm, MinMaxInfo32, WindowPos32, SIZE_MAXIMIZED, SIZE_MINIMIZED, SIZE_RESTORED, SWP_NOCLIENTMOVE, SWP_NOCLIENTSIZE,
    SWP_NOSIZE, SWP_STATECHANGED, WM_DEVICECHANGE, WM_MOVE, WM_NCCALCSIZE, WM_NCPAINT, WM_PAINT, WM_PAINTICON, WM_SIZE,
    WM_USER, WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING, WNDS_HASCAPTION, WNDS_HASHORIZONTALSCROLLBAR, WNDS_HASMENU,
    WNDS_HASVERTICALSCROOLLBAR, WS_BORDER, WS_CAPTION, WS_CHILD, WS_DLGFRAME, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME,
    WS_EX_LAYOUTRTL, WS_EX_LEFTSCROLLBAR, WS_EX_STATICEDGE, WS_EX_TOOLWINDOW, WS_EX_WINDOWEDGE, WS_HSCROLL,
    WS_MAXIMIZE, WS_MAXIMIZEBOX, WS_MINIMIZE, WS_POPUP, WS_THICKFRAME, WS_VSCROLL, WVR_HREDRAW, WVR_VALIDRECTS,
    WVR_VREDRAW,
};
use abi::user::{
    CS_HREDRAW, CS_VREDRAW, HTBORDER, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCAPTION, HTCLIENT, HTCLOSE, HTHSCROLL,
    HTLEFT, HTMAXBUTTON, HTMENU, HTMINBUTTON, HTNOWHERE, HTRIGHT, HTSIZE, HTTOP, HTTOPLEFT, HTTOPRIGHT, HTVSCROLL,
    MA_ACTIVATE, MA_NOACTIVATE, WM_LBUTTONDOWN, WM_MOUSEACTIVATE, WM_NCACTIVATE, WM_NCHITTEST, WM_NC_MOUSE_OFFSET,
    WM_SYSCOMMAND, WS_MINIMIZEBOX, WS_SYSMENU,
};
use abi::user::{KF_ALTDOWN, KF_REPEAT, SC_KEYMENU, WM_KEYUP, WM_SYSCHAR, WM_SYSKEYDOWN, WM_SYSKEYUP};
use hal::sync::KSpinLock;
use ke::usermem::{copy_from_user, copy_to_user};

use crate::gdi::dib::Rect;
use crate::metrics;
use crate::window::{LParam, Window};

/// UserHasWindowEdge : la fenêtre a un bord extérieur en relief.
pub fn has_window_edge(style: u32, ex_style: u32) -> bool {
    if style & WS_MINIMIZE != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
        return true;
    }
    if ex_style & WS_EX_STATICEDGE != 0 {
        return false;
    }
    if style & WS_THICKFRAME != 0 {
        return true;
    }
    matches!(style & WS_CAPTION, WS_DLGFRAME | WS_CAPTION)
}

/// UserGetWindowBorders (sans la zone cliente) : l'épaisseur horizontale et
/// verticale des bordures, d'après les métriques `m`.
pub fn window_borders(style: u32, ex_style: u32, m: &impl Fn(usize) -> i32) -> (i32, i32) {
    let mut border = 0;
    if has_window_edge(style, ex_style) {
        border += 2;
    } else if ex_style & (WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME) == WS_EX_STATICEDGE {
        border += 1;
    }
    if style & WS_CAPTION != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
        border += 1;
    }
    let (mut cx, mut cy) = (border, border);
    if style & WS_THICKFRAME != 0 && style & WS_MINIMIZE == 0 {
        cx += m(sm::CXFRAME) - m(sm::CXDLGFRAME);
        cy += m(sm::CYFRAME) - m(sm::CYDLGFRAME);
    }
    (cx * m(sm::CXBORDER), cy * m(sm::CYBORDER))
}

/// Ce que WM_NCCALCSIZE donne : la zone cliente, ce que rend le message,
/// et les `WNDS_HAS*` de la fenêtre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NcCalcSize {
    pub client: Rect,
    pub result: u32,
    pub state: u32,
}

/// NC_HandleNCCalcSize : la zone cliente d'une fenêtre de rectangle `rect` ;
/// `valid_rects` est le `wParam` de WM_NCCALCSIZE. Sous le titre, la barre
/// de menus prend la hauteur que `menu_bar` lui donne, mise en page dans ce
/// qui reste (dans les coordonnées de la fenêtre) ; `None` : pas de barre.
pub fn nc_calc_size(
    style: u32,
    ex_style: u32,
    class_style: u32,
    valid_rects: bool,
    menu_bar: &dyn Fn(Rect) -> Option<i32>,
    rect: Rect,
    m: &impl Fn(usize) -> i32,
) -> NcCalcSize {
    let mut result = 0;
    if valid_rects {
        if class_style & CS_VREDRAW != 0 {
            result |= WVR_VREDRAW;
        }
        if class_style & CS_HREDRAW != 0 {
            result |= WVR_HREDRAW;
        }
        result |= WVR_VALIDRECTS;
    }
    let mut client = rect;
    let mut state = 0;
    if style & WS_MINIMIZE != 0 {
        client.right = client.left;
        client.bottom = client.top;
        return NcCalcSize { client, result, state };
    }
    let inflate = |r: &mut Rect, dx: i32, dy: i32| {
        r.left -= dx;
        r.top -= dy;
        r.right += dx;
        r.bottom += dy;
    };
    if has_window_edge(style, ex_style) {
        let (cx, cy) = window_borders(style, ex_style, m);
        inflate(&mut client, -cx, -cy);
    } else if ex_style & WS_EX_STATICEDGE != 0 || style & WS_BORDER != 0 {
        inflate(&mut client, -1, -1);
    }
    if style & WS_CAPTION == WS_CAPTION {
        state |= WNDS_HASCAPTION;
        client.top += if ex_style & WS_EX_TOOLWINDOW != 0 { m(sm::CYSMCAPTION) } else { m(sm::CYCAPTION) };
    }
    let inside =
        Rect::new(client.left - rect.left, client.top - rect.top, client.right - rect.left, client.bottom - rect.top);
    if let Some(height) = menu_bar(inside) {
        state |= WNDS_HASMENU;
        client.top += height;
    }
    if ex_style & WS_EX_CLIENTEDGE != 0 {
        inflate(&mut client, -2 * m(sm::CXBORDER), -2 * m(sm::CYBORDER));
    }
    if style & WS_VSCROLL != 0 && client.right - client.left >= m(sm::CXVSCROLL) {
        state |= WNDS_HASVERTICALSCROOLLBAR;
        let mut left = ex_style & WS_EX_LEFTSCROLLBAR != 0;
        if !valid_rects && ex_style & WS_EX_LAYOUTRTL != 0 {
            left = !left;
        }
        if left {
            client.left += m(sm::CXVSCROLL);
        } else {
            client.right -= m(sm::CXVSCROLL);
        }
    }
    if style & WS_HSCROLL != 0 && client.bottom - client.top > m(sm::CYHSCROLL) {
        state |= WNDS_HASHORIZONTALSCROLLBAR;
        client.bottom -= m(sm::CYHSCROLL);
    }
    client.bottom = client.bottom.max(client.top);
    client.right = client.right.max(client.left);
    NcCalcSize { client, result, state }
}

/// IntGetWindowBorders (simplifiée) : les bords que compte
/// co_WinPosGetMinMaxInfo.
fn border_count(style: u32, ex_style: u32) -> i32 {
    let mut adjust = if ex_style & WS_EX_WINDOWEDGE != 0 {
        2
    } else if ex_style & WS_EX_STATICEDGE != 0 {
        1
    } else {
        0
    };
    if ex_style & WS_EX_CLIENTEDGE != 0 {
        adjust += 2;
    }
    if style & WS_CAPTION != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
        adjust += 1;
    }
    adjust
}

/// co_WinPosGetMinMaxInfo, avant WM_GETMINMAXINFO : les valeurs par défaut
/// d'une fenêtre en `origin` (`ptReserved`), dont le parent a la zone
/// cliente `parent` (à l'origine).
pub fn min_max_info(
    style: u32,
    ex_style: u32,
    origin: (i32, i32),
    parent: Rect,
    m: &impl Fn(usize) -> i32,
) -> MinMaxInfo32 {
    // ReactOS takes WS_BORDER off a full caption first: nothing below
    // looks at it.
    let mut adjust = border_count(style, ex_style);
    if style & WS_THICKFRAME != 0 && style & WS_CHILD == 0 && style & WS_MINIMIZE == 0 {
        adjust += 1;
    }
    let (mut xinc, mut yinc) = (adjust, adjust);
    if style & WS_THICKFRAME != 0 && style & WS_CHILD != 0 && style & WS_MINIMIZE == 0 {
        xinc += m(sm::CXFRAME) - m(sm::CXDLGFRAME);
        yinc += m(sm::CYFRAME) - m(sm::CYDLGFRAME);
    }
    let (dx, dy) = (xinc * m(sm::CXBORDER), yinc * m(sm::CYBORDER));
    let rect =
        Rect { left: parent.left - dx, top: parent.top - dy, right: parent.right + dx, bottom: parent.bottom + dy };
    let (xinc, yinc) = (-rect.left, -rect.top);
    let min_track_size = if style & (WS_DLGFRAME | WS_BORDER) != 0 {
        [m(sm::CXMINTRACK), m(sm::CYMINTRACK)]
    } else {
        [2 * xinc, 2 * yinc]
    };
    MinMaxInfo32 {
        reserved: [origin.0, origin.1],
        max_size: [rect.right - rect.left, rect.bottom - rect.top],
        max_position: [-xinc, -yinc],
        min_track_size,
        max_track_size: [m(sm::CXMAXTRACK), m(sm::CYMAXTRACK)],
    }
}

/// co_WinPosGetMinMaxInfo, après WM_GETMINMAXINFO : ce que la procédure a
/// laissé à sa valeur par défaut (`defaults`) s'adapte à la zone de travail
/// `work` du moniteur de rectangle `monitor` (à son rectangle pour une
/// fenêtre sans bouton d'agrandissement, ou contextuelle sans titre). Rend
/// si la fenêtre agrandie couvre le moniteur (`WNDS_MAXIMIZESTOMONITOR`).
pub fn adapt_to_monitor(
    info: &mut MinMaxInfo32,
    defaults: &MinMaxInfo32,
    style: u32,
    monitor: Rect,
    work: Rect,
) -> bool {
    let area =
        if style & WS_MAXIMIZEBOX != 0 && (style & WS_CAPTION == WS_CAPTION || style & (WS_CHILD | WS_POPUP) == 0) {
            work
        } else {
            monitor
        };
    // The borders around the parent's client area: -ptMaxPosition by default.
    let (xinc, yinc) = (-defaults.max_position[0], -defaults.max_position[1]);
    let screen = (monitor.right - monitor.left, monitor.bottom - monitor.top);
    if info.max_size == [screen.0 + 2 * xinc, screen.1 + 2 * yinc] {
        info.max_size = [area.right - area.left + 2 * xinc, area.bottom - area.top + 2 * yinc];
    }
    if info.max_position == [-xinc, -yinc] {
        info.max_position = [area.left - xinc, area.top - yinc];
    }
    info.max_size[0] >= screen.0 && info.max_size[1] >= screen.1
}

/// DefWndHandleWindowPosChanging : la taille demandée `size`, d'une fenêtre
/// de style `style`, ramenée sous le suivi maximal puis (sauf réduite) au
/// moins au suivi minimal de `limits` (une fenêtre à cadre épais ou
/// recouvrante) ; sans limites, positive.
pub fn limit_size(size: (i32, i32), style: u32, limits: Option<([i32; 2], [i32; 2])>) -> (i32, i32) {
    let Some((min, max)) = limits else { return (size.0.max(0), size.1.max(0)) };
    let (mut cx, mut cy) = (size.0.min(max[0]), size.1.min(max[1]));
    if style & WS_MINIMIZE == 0 {
        (cx, cy) = (cx.max(min[0]), cy.max(min[1]));
    }
    (cx, cy)
}

/// DefWndHandleWindowPosChanged : WM_MOVE (la zone cliente, dans celle du
/// parent d'une fenêtre fille, sinon à l'écran) si elle a bougé, WM_SIZE
/// (sa taille) si elle a changé (`SWP_NOCLIENTMOVE`, `SWP_NOCLIENTSIZE` de
/// `flags`).
fn window_pos_changed(window: &Arc<Window>, flags: u32) {
    let state = window.state();
    let origin = match crate::window::get(state.parent) {
        Some(parent) if state.style & WS_CHILD != 0 => (parent.state().client.left, parent.state().client.top),
        _ => (0, 0),
    };
    let client = state.client;
    if flags & SWP_NOCLIENTMOVE == 0 {
        let at = crate::window::make_long(client.left - origin.0, client.top - origin.1);
        let _ = crate::window::send_message(window, WM_MOVE, 0, LParam::Value(at));
    }
    if flags & SWP_NOCLIENTSIZE == 0 || flags & SWP_STATECHANGED != 0 {
        let (kind, size) = if state.style & WS_MINIMIZE != 0 {
            (SIZE_MINIMIZED, 0)
        } else {
            let kind = if state.style & WS_MAXIMIZE != 0 { SIZE_MAXIMIZED } else { SIZE_RESTORED };
            (kind, crate::window::make_long(client.right - client.left, client.bottom - client.top))
        };
        let _ = crate::window::send_message(window, WM_SIZE, kind, LParam::Value(size));
    }
}

/// HAS_THICKFRAME de ReactOS : un cadre épais, sauf sous un cadre de
/// dialogue sans bordure.
fn has_thick_frame(style: u32) -> bool {
    style & WS_THICKFRAME != 0 && style & (WS_DLGFRAME | WS_BORDER) != WS_DLGFRAME
}

/// HAS_DLGFRAME de ReactOS.
fn has_dialog_frame(style: u32, ex_style: u32) -> bool {
    ex_style & WS_EX_DLGMODALFRAME != 0 || (style & WS_DLGFRAME != 0 && style & WS_THICKFRAME == 0)
}

/// HAS_THINFRAME de ReactOS : une bordure, ou une fenêtre recouvrante.
fn has_thin_frame(style: u32) -> bool {
    style & WS_BORDER != 0 || style & (WS_CHILD | WS_POPUP) == 0
}

/// Le code d'un point sur le cadre épais (hors du rectangle `inner`) :
/// `low`, `middle` ou `high` selon sa place `along` entre `from` et `to`,
/// les coins sur la longueur `size`.
fn sizing_border(along: i32, from: i32, to: i32, size: i32, (low, middle, high): (u32, u32, u32)) -> u32 {
    if along < from + size {
        low
    } else if along >= to - size {
        high
    } else {
        middle
    }
}

/// GetNCHitEx : où tombe le point (`x`, `y`) de l'écran dans une fenêtre de
/// style `style` et `ex_style`, de rectangles `window` et `client` (à
/// l'écran) : HTCLIENT dans la zone cliente ; les bords d'un cadre épais
/// (HTLEFT…, les coins sur la longueur d'un bouton du titre) ; HTBORDER sur
/// un autre cadre ; dans la barre de titre, ses boutons (fermer, agrandir,
/// réduire, de droite à gauche) ou HTCAPTION ; au-dessus de la zone cliente,
/// entre ses côtés, sa barre de menus si elle en a une (`has_menu` :
/// HAS_MENU, une fenêtre qui n'est pas fille et a un menu) ; contre la zone
/// cliente, ses barres de défilement (HTVSCROLL, HTHSCROLL, et HTSIZE dans le
/// coin entre les deux) ; HTNOWHERE ailleurs (pas encore de menu système :
/// pas de HTSYSMENU). Une fenêtre réduite est toute en titre.
pub fn nc_hit_test(
    style: u32,
    ex_style: u32,
    has_menu: bool,
    window: Rect,
    client: Rect,
    (x, y): (i32, i32),
    m: &impl Fn(usize) -> i32,
) -> u32 {
    let inside = |r: &Rect| x >= r.left && x < r.right && y >= r.top && y < r.bottom;
    if !inside(&window) {
        return HTNOWHERE;
    }
    if style & WS_MINIMIZE != 0 {
        return HTCAPTION;
    }
    if inside(&client) {
        return HTCLIENT;
    }
    let deflate = |r: Rect, dx: i32, dy: i32| Rect::new(r.left + dx, r.top + dy, r.right - dx, r.bottom - dy);
    let mut rect = window;
    if has_thick_frame(style) {
        rect = deflate(rect, m(sm::CXFRAME), m(sm::CYFRAME));
        if !inside(&rect) {
            let (cx, cy) = (m(sm::CXSIZE), m(sm::CYSIZE));
            return if y < rect.top {
                sizing_border(x, rect.left, rect.right, cx, (HTTOPLEFT, HTTOP, HTTOPRIGHT))
            } else if y >= rect.bottom {
                sizing_border(x, rect.left, rect.right, cx, (HTBOTTOMLEFT, HTBOTTOM, HTBOTTOMRIGHT))
            } else if x < rect.left {
                sizing_border(y, rect.top, rect.bottom, cy, (HTTOPLEFT, HTLEFT, HTBOTTOMLEFT))
            } else {
                sizing_border(y, rect.top, rect.bottom, cy, (HTTOPRIGHT, HTRIGHT, HTBOTTOMRIGHT))
            };
        }
    } else {
        if has_dialog_frame(style, ex_style) {
            rect = deflate(rect, m(sm::CXDLGFRAME), m(sm::CYDLGFRAME));
        } else if has_thin_frame(style) {
            rect = deflate(rect, m(sm::CXBORDER), m(sm::CYBORDER));
        }
        if !inside(&rect) {
            return HTBORDER;
        }
    }
    if style & WS_CAPTION == WS_CAPTION {
        let tool = ex_style & WS_EX_TOOLWINDOW != 0;
        rect.top += if tool { m(sm::CYSMCAPTION) } else { m(sm::CYCAPTION) } - 1;
        if !inside(&rect) {
            if style & WS_SYSMENU != 0 {
                rect.right -= m(sm::CYCAPTION);
                if x >= rect.right {
                    return HTCLOSE;
                }
                if style & (WS_MINIMIZEBOX | WS_MAXIMIZEBOX) != 0 && !tool {
                    rect.right -= m(sm::CXSIZE);
                    if x >= rect.right {
                        return HTMAXBUTTON;
                    }
                    rect.right -= m(sm::CXSIZE);
                    if x >= rect.right {
                        return HTMINBUTTON;
                    }
                }
            }
            return HTCAPTION;
        }
    }
    if has_menu && y < client.top && x >= client.left && x < client.right {
        return HTMENU;
    }
    // The scroll bars, beside the client area (the vertical one on the left
    // for WS_EX_LEFTSCROLLBAR, which right-to-left windows swap).
    let left =
        (ex_style ^ if ex_style & WS_EX_LAYOUTRTL != 0 { WS_EX_LEFTSCROLLBAR } else { 0 }) & WS_EX_LEFTSCROLLBAR != 0;
    let mut rect = client;
    if style & WS_VSCROLL != 0 {
        if left {
            rect.left -= m(sm::CXVSCROLL);
        } else {
            rect.right += m(sm::CXVSCROLL);
        }
        if inside(&rect) {
            return HTVSCROLL;
        }
    }
    if style & WS_HSCROLL != 0 {
        rect.bottom += m(sm::CYHSCROLL);
        if inside(&rect) {
            let corner = if left { x <= rect.left + m(sm::CXVSCROLL) } else { x >= rect.right - m(sm::CXVSCROLL) };
            return if style & WS_VSCROLL != 0 && corner { HTSIZE } else { HTHSCROLL };
        }
    }
    HTNOWHERE
}

/// [`nc_hit_test`] pour `window`, d'après son état : son style, ses
/// rectangles, et sa barre de menus (HAS_MENU).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn window_hit_test(window: &Window, point: (i32, i32)) -> u32 {
    let state = window.state();
    let has_menu = state.style & WS_CHILD == 0 && state.menu != 0;
    nc_hit_test(state.style, state.ex_style, has_menu, state.window, state.client, point, &metrics::get)
}

/// DefWindowProc de WM_MOUSEACTIVATE : une fenêtre fille pose la question à
/// son parent, dont une réponse non nulle vaut ; sinon un clic gauche sur la
/// barre de titre n'active pas (WM_NCLBUTTONDOWN activera), un autre active.
fn mouse_activate(window: &Arc<Window>, wparam: u32, lparam: u32) -> u32 {
    let state = window.state();
    if state.style & WS_CHILD != 0 {
        if let Some(parent) = crate::window::get(state.parent) {
            match crate::window::send_message(&parent, WM_MOUSEACTIVATE, wparam, LParam::Value(lparam)) {
                Ok(0) | Err(_) => {}
                Ok(answer) => return answer,
            }
        }
    }
    if lparam >> 16 == WM_LBUTTONDOWN && lparam & 0xFFFF == HTCAPTION {
        MA_NOACTIVATE
    } else {
        MA_ACTIVATE
    }
}

/// WM_NCLBUTTONDOWN.
const NC_LBUTTONDOWN: u32 = WM_LBUTTONDOWN - WM_NC_MOUSE_OFFSET;

/// Ce que DefWindowProc retient des touches du menu, dans la file du
/// thread : Alt enfoncé seul (QF_FMENUSTATUS), F10 enfoncé (QF_FF10STATUS).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MenuKeys {
    pub alt: bool,
    pub f10: bool,
}

/// Où va SC_KEYMENU ([`key_menu`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMenu {
    /// À la fenêtre elle-même, `lParam` le caractère (Alt et une lettre).
    Window(u32),
    /// À sa fenêtre de premier niveau, `lParam` 0 (Alt ou F10 relâché).
    Root,
}

/// Une touche Alt (VK_MENU, ou celle de gauche ou de droite).
fn is_alt(wparam: u32) -> bool {
    [VK_MENU, VK_LMENU, VK_RMENU].iter().any(|&vk| u32::from(vk) == wparam)
}

/// IntDefWindowProc de WM_SYSKEYDOWN, WM_KEYUP, WM_SYSKEYUP et WM_SYSCHAR,
/// pour les menus : Alt enfoncé seul (sans répétition) puis relâché, ou F10
/// enfoncé puis relâché, demandent la barre (SC_KEYMENU, 0, à la fenêtre de
/// premier niveau) ; Alt et une lettre (WM_SYSCHAR) demandent l'item qu'elle
/// souligne (SC_KEYMENU, la lettre) ; une autre touche entre-temps oublie Alt.
/// Pas encore : Alt+F4, Alt+Tab, Alt+Échap, Maj+F10 (WM_CONTEXTMENU), Maj+Échap
/// et Alt+Espace (le menu de la fenêtre), Entrée sur une fenêtre réduite.
pub fn key_menu(keys: &mut MenuKeys, message: u32, wparam: u32, lparam: u32) -> Option<KeyMenu> {
    let flags = lparam >> 16;
    match message {
        WM_SYSKEYDOWN => {
            if flags & KF_ALTDOWN != 0 {
                if flags & KF_REPEAT == 0 {
                    keys.alt = is_alt(wparam) && !keys.alt;
                }
                keys.f10 = false;
            } else if wparam == u32::from(VK_F10) {
                keys.f10 = true;
            }
            None
        }
        WM_KEYUP | WM_SYSKEYUP => {
            let fire = (is_alt(wparam) && keys.alt) || (wparam == u32::from(VK_F10) && keys.f10);
            *keys = MenuKeys::default();
            fire.then_some(KeyMenu::Root)
        }
        WM_SYSCHAR => {
            keys.alt = false;
            let control = [u32::from(VK_TAB), u32::from(VK_ESCAPE)].contains(&wparam);
            (flags & KF_ALTDOWN != 0 && wparam != 0 && !control).then_some(KeyMenu::Window(wparam))
        }
        _ => None,
    }
}

/// Les messages que ReactOS traite ici et que DefWindowProc ne traite pas
/// encore, déjà journalisés.
static REPORTED: KSpinLock<BTreeSet<u32>> = KSpinLock::new(BTreeSet::new());

/// Les couleurs par défaut d'un contrôle de type `ctl_type` (CTLCOLOR_*) :
/// celles de son texte et de son fond, et celle de son pinceau (indices des
/// couleurs du système).
///
/// DefWndControlColor : le texte en COLOR_WINDOWTEXT, sur COLOR_WINDOW pour
/// une zone d'édition ou une liste, sur COLOR_3DFACE sinon ; une barre de
/// défilement, son texte en COLOR_3DFACE sur COLOR_3DHILIGHT et le pinceau
/// COLOR_SCROLLBAR (ou le pinceau gris : [`control_brush`]).
pub const fn default_control_colors(ctl_type: u32) -> (usize, usize, usize) {
    use abi::user::color::{BTNFACE, BTNHIGHLIGHT, SCROLLBAR, WINDOW, WINDOWTEXT};
    match ctl_type {
        abi::user::CTLCOLOR_SCROLLBAR => (BTNFACE, BTNHIGHLIGHT, SCROLLBAR),
        abi::user::CTLCOLOR_EDIT | abi::user::CTLCOLOR_LISTBOX => (WINDOWTEXT, WINDOW, WINDOW),
        _ => (WINDOWTEXT, BTNFACE, BTNFACE),
    }
}

/// Le pinceau public du fond d'un contrôle ([`control_brush`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlBrush {
    /// Celui de la couleur du système de cet indice (`ahbrSystem`).
    System(usize),
    /// Le pinceau gris (`hbrGray`).
    Gray,
}

/// DefWndControlColor : le pinceau du fond d'un contrôle de type
/// `ctl_type` sous les couleurs du système `colors` : celui de sa couleur
/// ([`default_control_colors`]) ; pour une barre de défilement dont le fond
/// (COLOR_3DHILIGHT) a la couleur des fenêtres (COLOR_WINDOW), comme sous
/// les couleurs d'XP, le pinceau gris, dont le damier (COLOR_3DFACE sur
/// COLOR_3DHILIGHT) la distingue d'elles.
pub fn control_brush(ctl_type: u32, colors: &[u32]) -> ControlBrush {
    use abi::user::color::{BTNHIGHLIGHT, WINDOW};
    let (_, background, brush) = default_control_colors(ctl_type);
    if ctl_type == abi::user::CTLCOLOR_SCROLLBAR && colors.get(background) == colors.get(WINDOW) {
        debug_assert_eq!(background, BTNHIGHLIGHT);
        return ControlBrush::Gray;
    }
    ControlBrush::System(brush)
}

/// DefWndControlColor : le DC `hdc` prend les couleurs par défaut d'un
/// contrôle de type `ctl_type` ([`default_control_colors`]) ; rend le
/// pinceau public de son fond ([`control_brush`]).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le processus du DC.
pub fn control_color(hdc: u32, ctl_type: u32) -> u32 {
    let colors = &crate::metrics::SYSTEM_COLORS;
    let (text, background, _) = default_control_colors(ctl_type);
    if let Some(dc) = crate::gdi::dc::lock(hdc) {
        let color = |index: usize| colors.get(index).copied().unwrap_or(0);
        let _ = crate::gdi::dc::set_text_colors(&dc, color(text), color(background));
    }
    match control_brush(ctl_type, colors) {
        ControlBrush::System(index) => crate::gdi::brush::sys_color_brush(index),
        ControlBrush::Gray => crate::gdi::brush::gray_brush(),
    }
}

/// GetControlColor (co_ de ReactOS) : le pinceau du fond du contrôle
/// `window`, que donne son parent `parent` (lui-même sans parent) en
/// réponse à `message` (WM_CTLCOLOR*) ; s'il n'en donne pas un valide, ou
/// s'il est d'un autre processus, celui de [`control_color`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Envoie un
/// message (rappel, ou un autre thread).
pub fn get_control_color(parent: Option<&Arc<Window>>, window: &Arc<Window>, hdc: u32, message: u32) -> u32 {
    let parent = parent.unwrap_or(window);
    let ctl_type = message - abi::user::WM_CTLCOLORMSGBOX;
    let pid = crate::gdi::dc::current_pid();
    if crate::gui::process_id_of(parent.pti) != Some(pid) {
        return control_color(hdc, ctl_type);
    }
    let brush =
        crate::window::send_message(parent, message, hdc, crate::window::LParam::Value(window.handle)).unwrap_or(0);
    if brush != 0 && crate::gdi::handles::brush(brush, pid).is_some() {
        return brush;
    }
    control_color(hdc, ctl_type)
}

/// GetControlBrush : [`get_control_color`] du parent de `window` : son
/// parent pour une fenêtre fille, son propriétaire pour une fenêtre
/// surgissante (IntGetParent).
///
/// # IRQL
/// Comme [`get_control_color`].
pub fn get_control_brush(window: &Arc<Window>, hdc: u32, message: u32) -> u32 {
    let state = window.state();
    let parent = if state.style & WS_CHILD != 0 {
        crate::window::get(state.parent)
    } else if state.style & abi::user::WS_POPUP != 0 {
        crate::window::get(state.owner)
    } else {
        None
    };
    get_control_color(parent.as_ref(), window, hdc, message)
}

/// IntDefWindowProc : le traitement par défaut de `message` pour `window`
/// (aucune : WM_DEVICECHANGE seul a un sens). `lparam` est une adresse du
/// client pour un message qui désigne une structure (WM_NCCALCSIZE).
///
/// # Errors
/// Celles d'une lecture ou d'une écriture du client.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn def_window_proc(window: Option<&Arc<Window>>, message: u32, wparam: u32, lparam: u32) -> Result<u32, NtStatus> {
    if message > WM_USER {
        return Ok(0);
    }
    match (message, window) {
        (WM_DEVICECHANGE, _) => Ok(1),
        (abi::user::WM_CTLCOLORMSGBOX..=abi::user::WM_CTLCOLORSTATIC, _) => {
            Ok(control_color(wparam, message - abi::user::WM_CTLCOLORMSGBOX))
        }
        (WM_NCHITTEST, Some(window)) => {
            let point = (i32::from(lparam as u16 as i16), i32::from((lparam >> 16) as u16 as i16));
            Ok(window_hit_test(window, point))
        }
        (WM_MOUSEACTIVATE, Some(window)) => Ok(mouse_activate(window, wparam, lparam)),
        (abi::user::WM_SETCURSOR, Some(window)) => Ok(crate::cursor::def_set_cursor(window, wparam, lparam)),
        (abi::user::WM_SETICON, Some(window)) => match crate::cursor::set_window_icon(window, wparam, lparam) {
            Some(old) => Ok(old),
            None => {
                let _ = crate::set_last_error(abi::winerror::ERROR_INVALID_PARAMETER);
                Ok(0)
            }
        },
        (abi::user::WM_GETICON, Some(window)) => match crate::cursor::window_icon(window, wparam) {
            Some(icon) => Ok(icon),
            None => {
                let _ = crate::set_last_error(abi::winerror::ERROR_INVALID_PARAMETER);
                Ok(0)
            }
        },
        (WM_NCACTIVATE, Some(window)) => {
            crate::paint::set_frame_active(window, wparam != 0, lparam != u32::MAX);
            Ok(1)
        }
        (NC_LBUTTONDOWN, Some(window)) => {
            crate::sizemove::nc_lbutton_down(window, wparam, lparam);
            Ok(0)
        }
        (WM_SYSCOMMAND, Some(window)) => {
            crate::sizemove::sys_command(window, wparam, lparam);
            Ok(0)
        }
        (WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP | WM_SYSCHAR, Some(window)) => {
            let thread = crate::convert_current_thread()?;
            let command = thread.queue.with(|queue| key_menu(&mut queue.menu_keys, message, wparam, lparam)).0;
            drop(thread);
            let (target, character) = match command {
                Some(KeyMenu::Window(character)) => (window.clone(), character),
                Some(KeyMenu::Root) => (crate::mouse::top_level(window), 0),
                None => return Ok(0),
            };
            let _ = crate::window::send_message(&target, WM_SYSCOMMAND, SC_KEYMENU, LParam::Value(character));
            Ok(0)
        }
        (abi::menu::wm::CANCELMODE, Some(window)) => {
            // Alt forgotten (QF_FMENUSTATUS; F10 down stays, as ReactOS
            // keeps QF_FF10STATUS), a menu this window tracks ended
            // (MENU_EndMenu), its capture released.
            let thread = crate::convert_current_thread()?;
            let capture = thread.queue.with(|queue| {
                queue.menu_keys.alt = false;
                queue.capture
            });
            crate::menutrack::end_menu_of(window);
            if capture.0 == window.handle {
                crate::mouse::set_capture(&thread, None);
            }
            Ok(0)
        }
        (WM_NCCALCSIZE, Some(window)) if lparam != 0 => {
            // The RECT, or the first of NCCALCSIZE_PARAMS.
            let mut bytes = [0u8; 16];
            copy_from_user(&mut bytes, u64::from(lparam))?;
            let word =
                |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
            let rect = Rect { left: word(0), top: word(1), right: word(2), bottom: word(3) };
            let state = window.state();
            let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
            let calc = nc_calc_size(
                state.style,
                state.ex_style,
                class_style,
                wparam != 0,
                &|inside| crate::menubar::calc(window, inside),
                rect,
                &metrics::get,
            );
            let client = calc.client;
            let words = [client.left, client.top, client.right, client.bottom];
            let bytes: alloc::vec::Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            copy_to_user(u64::from(lparam), &bytes)?;
            const NON_CLIENT: u32 =
                WNDS_HASMENU | WNDS_HASCAPTION | WNDS_HASVERTICALSCROOLLBAR | WNDS_HASHORIZONTALSCROLLBAR;
            crate::window::change(window, |s| s.state = (s.state & !NON_CLIENT) | calc.state);
            Ok(calc.result)
        }
        (WM_NCCALCSIZE, _) => Ok(0),
        (WM_NCPAINT, Some(window)) => {
            crate::paint::nc_paint(window, wparam);
            Ok(0)
        }
        (WM_PAINT | WM_PAINTICON, Some(window)) => {
            crate::paint::def_paint(window);
            Ok(0)
        }
        (WM_WINDOWPOSCHANGING, Some(window)) if lparam != 0 => {
            let mut bytes = [0u8; size_of::<WindowPos32>()];
            copy_from_user(&mut bytes, u64::from(lparam))?;
            let mut pos = crate::winpos::window_pos_of(&bytes);
            if pos.flags & SWP_NOSIZE != 0 {
                return Ok(0);
            }
            let style = window.state().style;
            let limits = if style & WS_THICKFRAME != 0 || style & (WS_POPUP | WS_CHILD) == 0 {
                let info = crate::window::min_max_info(window);
                Some((info.min_track_size, info.max_track_size))
            } else {
                None
            };
            (pos.cx, pos.cy) = limit_size((pos.cx, pos.cy), style, limits);
            copy_to_user(u64::from(lparam), pos.as_bytes())?;
            Ok(0)
        }
        (WM_WINDOWPOSCHANGED, Some(window)) if lparam != 0 => {
            let mut bytes = [0u8; size_of::<WindowPos32>()];
            copy_from_user(&mut bytes, u64::from(lparam))?;
            let pos = crate::winpos::window_pos_of(&bytes);
            window_pos_changed(window, pos.flags);
            Ok(0)
        }
        _ => {
            if REPORTED.lock().insert(message) {
                log::warn!("win32k: DefWindowProc: message {message:#06x} not yet (0)");
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No menu bar.
    fn no_bar(_: Rect) -> Option<i32> {
        None
    }

    #[test]
    fn controls_default_to_xp_s_colours() {
        use abi::user::color::{BTNFACE, BTNHIGHLIGHT, SCROLLBAR, WINDOW, WINDOWTEXT};
        assert_eq!(default_control_colors(4), (WINDOWTEXT, BTNFACE, BTNFACE), "a dialog: COLOR_3DFACE");
        assert_eq!(default_control_colors(6), (WINDOWTEXT, BTNFACE, BTNFACE), "a static");
        assert_eq!(default_control_colors(3), (WINDOWTEXT, BTNFACE, BTNFACE), "a button");
        assert_eq!(default_control_colors(1), (WINDOWTEXT, WINDOW, WINDOW), "an edit: COLOR_WINDOW");
        assert_eq!(default_control_colors(2), (WINDOWTEXT, WINDOW, WINDOW), "a list box");
        assert_eq!(default_control_colors(5), (BTNFACE, BTNHIGHLIGHT, SCROLLBAR), "a scroll bar");
    }

    #[test]
    fn a_scroll_bar_on_white_windows_takes_the_gray_brush() {
        use abi::user::color::{BTNFACE, BTNHIGHLIGHT, SCROLLBAR, WINDOW};
        let mut colors = metrics::SYSTEM_COLORS;
        assert_eq!(colors[BTNHIGHLIGHT], colors[WINDOW], "XP's colours: both white");
        assert_eq!(control_brush(abi::user::CTLCOLOR_SCROLLBAR, &colors), ControlBrush::Gray);
        assert_eq!(control_brush(3, &colors), ControlBrush::System(BTNFACE), "a button");
        colors[WINDOW] = 0x00C0_C0C0;
        assert_eq!(control_brush(abi::user::CTLCOLOR_SCROLLBAR, &colors), ControlBrush::System(SCROLLBAR));
    }
    use abi::user::{WS_EX_WINDOWEDGE, WS_OVERLAPPEDWINDOW};

    fn metric(index: usize) -> i32 {
        metrics::system_metrics(1280, 800, &metrics::Parameters::DEFAULT)[index]
    }

    #[test]
    fn edges_follow_the_frame() {
        assert!(has_window_edge(WS_OVERLAPPEDWINDOW, 0));
        assert!(has_window_edge(WS_POPUP | WS_DLGFRAME, 0));
        assert!(!has_window_edge(WS_POPUP | WS_BORDER, 0), "a thin border only");
        assert!(!has_window_edge(WS_THICKFRAME, WS_EX_STATICEDGE), "a static edge wins");
        assert!(has_window_edge(WS_POPUP, WS_EX_DLGMODALFRAME));
        assert_eq!(window_borders(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, &metric), (4, 4), "edge, other, frame");
        assert_eq!(window_borders(WS_POPUP | WS_CAPTION, 0, &metric), (3, 3));
        assert_eq!(window_borders(WS_POPUP, WS_EX_STATICEDGE, &metric), (1, 1));
    }

    #[test]
    fn the_client_area_of_an_overlapped_window() {
        let rect = Rect::new(0, 0, 800, 600);
        let calc = nc_calc_size(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, CS_VREDRAW, false, &no_bar, rect, &metric);
        assert_eq!(calc.client, Rect::new(4, 24, 796, 596), "4 of border, 20 of caption");
        assert_eq!((calc.result, calc.state), (0, WNDS_HASCAPTION));
        let valid =
            nc_calc_size(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, CS_VREDRAW | CS_HREDRAW, true, &no_bar, rect, &metric);
        assert_eq!(valid.result, WVR_VREDRAW | WVR_HREDRAW | WVR_VALIDRECTS);
    }

    #[test]
    fn borders_scroll_bars_and_edges_come_off_the_client_area() {
        let rect = Rect::new(10, 10, 210, 110);
        assert_eq!(nc_calc_size(WS_POPUP, 0, 0, false, &no_bar, rect, &metric).client, rect, "no frame");
        assert_eq!(
            nc_calc_size(WS_POPUP | WS_BORDER, 0, 0, false, &no_bar, rect, &metric).client,
            Rect::new(11, 11, 209, 109)
        );
        let scrolled =
            nc_calc_size(WS_POPUP | WS_VSCROLL | WS_HSCROLL, WS_EX_CLIENTEDGE, 0, false, &no_bar, rect, &metric);
        assert_eq!(scrolled.client, Rect::new(12, 12, 192, 92), "2 of client edge, then 16 of each scroll bar");
        assert_eq!(scrolled.state, WNDS_HASVERTICALSCROOLLBAR | WNDS_HASHORIZONTALSCROLLBAR);
        let left = nc_calc_size(WS_POPUP | WS_VSCROLL, WS_EX_LEFTSCROLLBAR, 0, false, &no_bar, rect, &metric);
        assert_eq!(left.client, Rect::new(26, 10, 210, 110), "a scroll bar on the left");
        let tool = nc_calc_size(WS_POPUP | WS_CAPTION, WS_EX_TOOLWINDOW, 0, false, &no_bar, rect, &metric);
        assert_eq!(tool.client, Rect::new(13, 29, 207, 107), "a small caption");
        let tiny = nc_calc_size(WS_OVERLAPPEDWINDOW, 0, 0, false, &no_bar, Rect::new(0, 0, 4, 4), &metric);
        assert!(tiny.client.right >= tiny.client.left && tiny.client.bottom >= tiny.client.top, "never inverted");
        let minimized = nc_calc_size(WS_OVERLAPPEDWINDOW | WS_MINIMIZE, 0, 0, false, &no_bar, rect, &metric);
        assert_eq!(minimized.client, Rect::new(10, 10, 10, 10));
    }

    #[test]
    fn the_default_min_max_info_of_an_overlapped_window() {
        let info = min_max_info(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (0, 0), Rect::new(0, 0, 1280, 800), &metric);
        assert_eq!(info.max_size, [1288, 808], "the screen and 4 of border each side");
        assert_eq!(info.max_position, [-4, -4]);
        assert_eq!(info.min_track_size, [112, 28]);
        assert_eq!(info.max_track_size, [1292, 812]);
        let popup = min_max_info(WS_POPUP, 0, (5, 6), Rect::new(0, 0, 1280, 800), &metric);
        assert_eq!((popup.reserved, popup.max_size, popup.min_track_size), ([5, 6], [1280, 800], [0, 0]));
    }

    #[test]
    fn the_default_min_max_info_of_other_frames() {
        let screen = Rect::new(0, 0, 1280, 800);
        let sizing = min_max_info(WS_POPUP | WS_CAPTION | WS_THICKFRAME, WS_EX_WINDOWEDGE, (0, 0), screen, &metric);
        assert_eq!((sizing.max_size, sizing.min_track_size), ([1288, 808], [112, 28]), "like an overlapped window");
        let dialog = min_max_info(WS_POPUP | WS_DLGFRAME, WS_EX_WINDOWEDGE, (0, 0), screen, &metric);
        assert_eq!((dialog.max_position, dialog.min_track_size), ([-3, -3], [112, 28]), "a frame without a border");
        let edged = min_max_info(WS_POPUP, WS_EX_CLIENTEDGE, (0, 0), screen, &metric);
        assert_eq!((edged.max_size, edged.min_track_size), ([1284, 804], [4, 4]), "2 of client edge each side");
        let child =
            min_max_info(WS_CHILD | WS_THICKFRAME, WS_EX_WINDOWEDGE, (0, 0), Rect::new(0, 0, 400, 300), &metric);
        assert_eq!(child.max_position, [-3, -3], "2 of edge, and the frame beyond a dialog frame");
    }

    #[test]
    fn where_a_point_falls_in_an_overlapped_window() {
        // 800 x 600 at (100, 100): a 4-pixel frame, a 20-pixel caption.
        let (style, ex) = (WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE);
        let window = Rect::new(100, 100, 900, 700);
        let client = Rect::new(104, 124, 896, 696);
        let at = |x, y| nc_hit_test(style, ex, false, window, client, (x, y), &metric);
        assert_eq!(at(500, 400), HTCLIENT);
        assert_eq!(at(99, 400), HTNOWHERE, "outside");
        assert_eq!(at(500, 110), HTCAPTION);
        assert_eq!(at(890, 110), HTCLOSE, "the last caption-height of the caption");
        assert_eq!(at(862, 110), HTMAXBUTTON);
        assert_eq!(at(845, 110), HTMINBUTTON);
        assert_eq!(at(820, 110), HTCAPTION, "left of the buttons");
        assert_eq!(at(101, 400), HTLEFT);
        assert_eq!(at(898, 400), HTRIGHT);
        assert_eq!(at(500, 101), HTTOP);
        assert_eq!(at(500, 698), HTBOTTOM);
        assert_eq!(at(101, 101), HTTOPLEFT);
        assert_eq!(at(110, 101), HTTOPLEFT, "a corner runs a button's width along the edge");
        assert_eq!(at(898, 698), HTBOTTOMRIGHT);
        assert_eq!(at(101, 690), HTBOTTOMLEFT);
    }

    use abi::user::KF_UP;

    /// The `lParam` of a key: KF_* in its high word.
    fn key(flags: u32) -> u32 {
        1 | flags << 16
    }

    #[test]
    fn alt_or_f10_pressed_and_released_alone_ask_for_the_bar() {
        let (alt, f10, letter) = (u32::from(VK_MENU), u32::from(VK_F10), u32::from(b'F'));
        let mut keys = MenuKeys::default();
        // Alt down, its repeats, then up: the bar, from the root window.
        assert_eq!(key_menu(&mut keys, WM_SYSKEYDOWN, alt, key(KF_ALTDOWN)), None);
        assert_eq!(key_menu(&mut keys, WM_SYSKEYDOWN, alt, key(KF_ALTDOWN | KF_REPEAT)), None);
        assert!(keys.alt, "a repeat leaves it");
        assert_eq!(key_menu(&mut keys, WM_SYSKEYUP, alt, key(KF_UP | KF_REPEAT)), Some(KeyMenu::Root));
        assert_eq!(keys, MenuKeys::default());
        // Alt and a letter: the letter's item, from the window; Alt's
        // release then asks for nothing.
        key_menu(&mut keys, WM_SYSKEYDOWN, u32::from(VK_LMENU), key(KF_ALTDOWN));
        assert_eq!(key_menu(&mut keys, WM_SYSKEYDOWN, letter, key(KF_ALTDOWN)), None);
        assert_eq!(key_menu(&mut keys, WM_SYSCHAR, u32::from(b'f'), key(KF_ALTDOWN)), Some(KeyMenu::Window(0x66)));
        assert_eq!(key_menu(&mut keys, WM_KEYUP, alt, key(KF_UP | KF_REPEAT)), None);
        // Alt+Tab and Alt+Escape are not the menus'.
        let tab = key_menu(&mut keys, WM_SYSCHAR, u32::from(VK_TAB), key(KF_ALTDOWN));
        assert_eq!(tab, None);
        // F10 down then up: the bar.
        assert_eq!(key_menu(&mut keys, WM_SYSKEYDOWN, f10, key(0)), None);
        assert_eq!(key_menu(&mut keys, WM_SYSKEYUP, f10, key(KF_UP | KF_REPEAT)), Some(KeyMenu::Root));
        // A WM_SYSCHAR without Alt (no menu), and a key up never pressed.
        assert_eq!(key_menu(&mut keys, WM_SYSCHAR, u32::from(b'f'), key(0)), None);
        assert_eq!(key_menu(&mut keys, WM_KEYUP, f10, key(KF_UP)), None);
    }

    #[test]
    fn the_menu_bar_lies_over_the_client_area() {
        // As above with a 19-pixel bar under the caption (y 124 to 143).
        let (style, ex) = (WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE);
        let window = Rect::new(100, 100, 900, 700);
        let client = Rect::new(104, 143, 896, 696);
        let at = |has_menu, x, y| nc_hit_test(style, ex, has_menu, window, client, (x, y), &metric);
        assert_eq!(at(true, 500, 130), HTMENU);
        assert_eq!(at(true, 104, 142), HTMENU, "from the client area's left");
        assert_eq!(at(true, 500, 143), HTCLIENT);
        assert_eq!(at(true, 500, 110), HTCAPTION);
        assert_eq!(at(true, 101, 130), HTLEFT, "the frame first");
        assert_eq!(at(false, 500, 130), HTNOWHERE, "no bar: nothing there");
    }

    #[test]
    fn where_a_point_falls_in_other_frames() {
        let window = Rect::new(0, 0, 200, 100);
        // A dialog: a dialog frame, a caption with only the close button.
        let dialog = WS_POPUP | WS_CAPTION | WS_SYSMENU;
        let client = Rect::new(3, 22, 197, 97);
        assert_eq!(nc_hit_test(dialog, WS_EX_DLGMODALFRAME, false, window, client, (1, 50), &metric), HTBORDER);
        assert_eq!(nc_hit_test(dialog, 0, false, window, client, (190, 10), &metric), HTCLOSE);
        assert_eq!(nc_hit_test(dialog, 0, false, window, client, (165, 10), &metric), HTCAPTION, "no other buttons");
        // A popup without a frame: its client area is the whole window.
        assert_eq!(nc_hit_test(WS_POPUP, 0, false, window, window, (5, 5), &metric), HTCLIENT);
        // A bordered popup: its border.
        let inner = Rect::new(1, 1, 199, 99);
        assert_eq!(nc_hit_test(WS_POPUP | WS_BORDER, 0, false, window, inner, (0, 50), &metric), HTBORDER);
        // Minimized: all caption.
        let min = WS_OVERLAPPEDWINDOW | WS_MINIMIZE;
        assert_eq!(nc_hit_test(min, 0, false, window, Rect::new(0, 0, 0, 0), (50, 50), &metric), HTCAPTION);
    }

    #[test]
    fn the_scroll_bars_lie_beside_the_client_area() {
        // A popup with a border and both bars: its client area 16 pixels
        // less wide and less tall.
        let style = WS_POPUP | WS_BORDER | WS_VSCROLL | WS_HSCROLL;
        let window = Rect::new(0, 0, 200, 100);
        let client = Rect::new(1, 1, 183, 83);
        let at = |ex: u32, x, y| nc_hit_test(style, ex, false, window, client, (x, y), &metric);
        assert_eq!(at(0, 190, 40), HTVSCROLL);
        assert_eq!(at(0, 100, 90), HTHSCROLL);
        assert_eq!(at(0, 190, 90), HTSIZE, "the corner between them");
        assert_eq!(at(0, 182, 82), HTCLIENT);
        assert_eq!(at(0, 0, 40), HTBORDER);
        // On the left: the client area moves right.
        let left = Rect::new(17, 1, 199, 83);
        let at = |x, y| nc_hit_test(style, WS_EX_LEFTSCROLLBAR, false, window, left, (x, y), &metric);
        assert_eq!((at(5, 40), at(5, 90), at(100, 90)), (HTVSCROLL, HTSIZE, HTHSCROLL));
        let hidden = nc_hit_test(WS_POPUP | WS_BORDER, 0, false, window, client, (190, 40), &metric);
        assert_eq!(hidden, HTNOWHERE, "no bar without its style");
    }

    #[test]
    fn a_requested_size_stays_within_the_limits() {
        let limits = Some(([112, 28], [1292, 812]));
        assert_eq!(limit_size((10, 10), WS_OVERLAPPEDWINDOW, limits), (112, 28), "the minimum");
        assert_eq!(limit_size((5000, 900), WS_OVERLAPPEDWINDOW, limits), (1292, 812), "the maximum");
        assert_eq!(limit_size((400, 300), WS_OVERLAPPEDWINDOW, limits), (400, 300));
        assert_eq!(limit_size((10, 10), WS_OVERLAPPEDWINDOW | WS_MINIMIZE, limits), (10, 10), "minimized");
        assert_eq!(limit_size((10, 10), 0, Some(([300, 200], [100, 100]))), (300, 200), "the minimum wins");
        assert_eq!(limit_size((-3, 7), WS_POPUP, None), (0, 7), "no limits, not negative");
    }

    #[test]
    fn default_limits_adapt_to_the_work_area() {
        let screen = Rect::new(0, 0, 1280, 800);
        let work = Rect::new(0, 30, 1280, 770);
        let defaults = min_max_info(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (0, 0), screen, &metric);
        let mut whole = defaults;
        assert!(adapt_to_monitor(&mut whole, &defaults, WS_OVERLAPPEDWINDOW, screen, screen), "it covers the monitor");
        assert_eq!(whole, defaults, "the work area is the monitor");
        let mut info = defaults;
        assert!(!adapt_to_monitor(&mut info, &defaults, WS_OVERLAPPEDWINDOW, screen, work), "not the whole height");
        assert_eq!((info.max_size, info.max_position), ([1288, 748], [-4, 26]), "the work area and its borders");
        let dialog_style = WS_POPUP | WS_CAPTION | WS_THICKFRAME;
        let mut dialog = defaults;
        adapt_to_monitor(&mut dialog, &defaults, dialog_style, screen, work);
        assert_eq!(dialog.max_size, [1288, 808], "no maximize box: the whole monitor");
        let mut popup = defaults;
        adapt_to_monitor(&mut popup, &defaults, WS_POPUP | WS_MAXIMIZEBOX, screen, work);
        assert_eq!((popup.max_size, popup.max_position), ([1288, 808], [-4, -4]), "a popup without a caption");
        let mut chosen = MinMaxInfo32 { max_size: [500, 400], max_position: [10, 20], ..defaults };
        assert!(!adapt_to_monitor(&mut chosen, &defaults, WS_OVERLAPPEDWINDOW, screen, work), "smaller");
        assert_eq!((chosen.max_size, chosen.max_position), ([500, 400], [10, 20]), "what the procedure chose");
    }
}
