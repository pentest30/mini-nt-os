//! DefWindowProc côté noyau (IntDefWindowProc), que `user32` appelle par
//! NtUserMessageCall (`FNID_DEFWINDOWPROC`) pour les messages qu'il ne
//! traite pas lui-même, et les mesures du cadre d'une fenêtre que
//! CreateWindowEx emploie (co_WinPosGetMinMaxInfo).
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
//! - WM_DEVICECHANGE rend TRUE ; un message de l'application (au-delà de
//!   WM_USER) rend 0.
//!
//! Les autres messages que ReactOS traite ici (WM_PAINT, WM_ERASEBKGND,
//! WM_NCPAINT, WM_NCACTIVATE, WM_NCHITTEST, WM_SETCURSOR, WM_ACTIVATE,
//! WM_SHOWWINDOW, WM_WINDOWPOSCHANGING et CHANGED, WM_SYSCOMMAND, WM_CLOSE,
//! les touches et les boutons…) attendent la peinture, les contextes de
//! périphérique, le positionnement et l'entrée : ils rendent 0, journalisés une fois chacun. Pas encore de
//! menus (`WNDS_HASMENU`).

use alloc::collections::BTreeSet;
use alloc::sync::Arc;

use abi::ntstatus::NtStatus;
use abi::user::{
    sm, MinMaxInfo32, WM_DEVICECHANGE, WM_NCCALCSIZE, WM_USER, WNDS_HASCAPTION, WNDS_HASHORIZONTALSCROLLBAR,
    WNDS_HASVERTICALSCROOLLBAR, WS_BORDER, WS_CAPTION, WS_CHILD, WS_DLGFRAME, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME,
    WS_EX_LAYOUTRTL, WS_EX_LEFTSCROLLBAR, WS_EX_STATICEDGE, WS_EX_TOOLWINDOW, WS_EX_WINDOWEDGE, WS_HSCROLL,
    WS_MAXIMIZEBOX, WS_MINIMIZE, WS_POPUP, WS_THICKFRAME, WS_VSCROLL, WVR_HREDRAW, WVR_VALIDRECTS, WVR_VREDRAW,
};
use abi::user::{CS_HREDRAW, CS_VREDRAW};
use hal::sync::KSpinLock;
use ke::usermem::{copy_from_user, copy_to_user};

use crate::gdi::dib::Rect;
use crate::metrics;
use crate::window::Window;

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

/// NC_HandleNCCalcSize : la zone cliente d'une fenêtre de rectangle `rect`
/// (sans menu) ; `valid_rects` est le `wParam` de WM_NCCALCSIZE.
pub fn nc_calc_size(
    style: u32,
    ex_style: u32,
    class_style: u32,
    valid_rects: bool,
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

/// Les messages que ReactOS traite ici et que DefWindowProc ne traite pas
/// encore, déjà journalisés.
static REPORTED: KSpinLock<BTreeSet<u32>> = KSpinLock::new(BTreeSet::new());

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
        (WM_NCCALCSIZE, Some(window)) if lparam != 0 => {
            // The RECT, or the first of NCCALCSIZE_PARAMS.
            let mut bytes = [0u8; 16];
            copy_from_user(&mut bytes, u64::from(lparam))?;
            let word =
                |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
            let rect = Rect { left: word(0), top: word(1), right: word(2), bottom: word(3) };
            let state = window.state();
            let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
            let calc = nc_calc_size(state.style, state.ex_style, class_style, wparam != 0, rect, &metrics::get);
            let client = calc.client;
            let words = [client.left, client.top, client.right, client.bottom];
            let bytes: alloc::vec::Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            copy_to_user(u64::from(lparam), &bytes)?;
            const NON_CLIENT: u32 = WNDS_HASCAPTION | WNDS_HASVERTICALSCROOLLBAR | WNDS_HASHORIZONTALSCROLLBAR;
            crate::window::change(window, |s| s.state = (s.state & !NON_CLIENT) | calc.state);
            Ok(calc.result)
        }
        (WM_NCCALCSIZE, _) => Ok(0),
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
        let calc = nc_calc_size(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, CS_VREDRAW, false, rect, &metric);
        assert_eq!(calc.client, Rect::new(4, 24, 796, 596), "4 of border, 20 of caption");
        assert_eq!((calc.result, calc.state), (0, WNDS_HASCAPTION));
        let valid = nc_calc_size(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, CS_VREDRAW | CS_HREDRAW, true, rect, &metric);
        assert_eq!(valid.result, WVR_VREDRAW | WVR_HREDRAW | WVR_VALIDRECTS);
    }

    #[test]
    fn borders_scroll_bars_and_edges_come_off_the_client_area() {
        let rect = Rect::new(10, 10, 210, 110);
        assert_eq!(nc_calc_size(WS_POPUP, 0, 0, false, rect, &metric).client, rect, "no frame");
        assert_eq!(nc_calc_size(WS_POPUP | WS_BORDER, 0, 0, false, rect, &metric).client, Rect::new(11, 11, 209, 109));
        let scrolled = nc_calc_size(WS_POPUP | WS_VSCROLL | WS_HSCROLL, WS_EX_CLIENTEDGE, 0, false, rect, &metric);
        assert_eq!(scrolled.client, Rect::new(12, 12, 192, 92), "2 of client edge, then 16 of each scroll bar");
        assert_eq!(scrolled.state, WNDS_HASVERTICALSCROOLLBAR | WNDS_HASHORIZONTALSCROLLBAR);
        let left = nc_calc_size(WS_POPUP | WS_VSCROLL, WS_EX_LEFTSCROLLBAR, 0, false, rect, &metric);
        assert_eq!(left.client, Rect::new(26, 10, 210, 110), "a scroll bar on the left");
        let tool = nc_calc_size(WS_POPUP | WS_CAPTION, WS_EX_TOOLWINDOW, 0, false, rect, &metric);
        assert_eq!(tool.client, Rect::new(13, 29, 207, 107), "a small caption");
        let tiny = nc_calc_size(WS_OVERLAPPEDWINDOW, 0, 0, false, Rect::new(0, 0, 4, 4), &metric);
        assert!(tiny.client.right >= tiny.client.left && tiny.client.bottom >= tiny.client.top, "never inverted");
        let minimized = nc_calc_size(WS_OVERLAPPEDWINDOW | WS_MINIMIZE, 0, 0, false, rect, &metric);
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
