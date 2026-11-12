//! Le positionnement des fenêtres : SetWindowPos ([`set_window_pos`]),
//! ShowWindow ([`show_window`]) avec réduire, agrandir et rétablir
//! ([`min_maximize`]), GetWindowPlacement et SetWindowPlacement
//! ([`placement`], [`set_placement`]).
//!
//! Comme co_WinPosSetWindowPos de ReactOS (`winpos.c`, comme
//! spécification) : WM_WINDOWPOSCHANGING (la procédure peut changer la
//! demande ; DefWindowProc la ramène dans les limites de WM_GETMINMAXINFO),
//! les nouveaux rectangles ([`new_rects`]), les drapeaux corrigés
//! ([`fixup_flags`] : ce qui ne change pas, la fenêtre amenée en haut de
//! l'ordre Z quand elle s'active), WM_NCCALCSIZE avec des rectangles
//! valides (la zone cliente), sa place dans l'ordre Z
//! (`window::link`), ses enfants déplacés avec sa zone cliente, montrée ou
//! cachée (`WS_VISIBLE`), WM_CHILDACTIVATE à une fenêtre fille qui
//! s'active, puis WM_WINDOWPOSCHANGED (DefWindowProc en tire WM_MOVE et
//! WM_SIZE, `SIZE_MINIMIZED`, `SIZE_MAXIMIZED` ou `SIZE_RESTORED` quand son
//! état change, `SWP_STATECHANGED`).
//!
//! Le `WINDOWPOS` de WM_WINDOWPOSCHANGED donne la place de la fenêtre dans
//! la zone cliente de son parent, comme le dit l'API ; ReactOS y met ses
//! coordonnées d'écran (les mêmes pour une fenêtre de premier niveau).
//!
//! ShowWindow, comme co_WinPosShowWindow : la commande du `STARTUPINFO` du
//! processus pour sa première fenêtre recouvrante (`STARTF_USESHOWWINDOW`,
//! une fois), les drapeaux de SetWindowPos de la commande
//! ([`show_command`]) ; réduire, agrandir ou rétablir passe par
//! co_WinPosMinMaximize ([`min_maximize`]), qui change le style
//! (`WS_MINIMIZE`, `WS_MAXIMIZE`) et donne la nouvelle place ; WM_SHOWWINDOW
//! (pas quand l'état change), SetWindowPos (si ses parents sont visibles,
//! ou si son état change ; sinon `WS_VISIBLE` seul), puis WM_SIZE et
//! WM_MOVE qui attendaient qu'elle soit montrée (`WNDS_SENDSIZEMOVEMSGS`).
//!
//! La place gardée de chaque fenêtre ([`InternalPos`], `InternalPos` de
//! ReactOS) : son rectangle normal, celui qu'elle reprend quand on la
//! rétablit, et ses places réduite et agrandie. Agrandie, une fenêtre
//! prend la place et la taille de WM_GETMINMAXINFO : la zone de travail de
//! son moniteur et ses bords au-delà, si bien que son cadre épais sort de
//! l'écran. Réduite, elle devient une barre de titre de SM_CXMINIMIZED ×
//! SM_CYMINIMIZED : sans shell qui montre les fenêtres réduites, à la
//! première case libre en bas à gauche de la zone cliente de son parent
//! ([`icon_slot`] : MINIMIZEDMETRICS, `ARW_BOTTOMLEFT | ARW_RIGHT` par
//! défaut, `crate::metrics`) ; avec `ARW_HIDE` (ce que demande un shell),
//! hors de l'écran, comme ReactOS.
//!
//! Une fenêtre de premier niveau activée passe au premier plan
//! ([`crate::input::activate`]) : sa file reçoit le clavier.
//!
//! Après le déplacement ([`crate::paint`]) : une fenêtre visible est
//! invalidée entière, ce qu'elle découvre est exposé (le bureau s'y
//! repeint), et une fenêtre montrée, déplacée ou redimensionnée repeint
//! aussitôt son cadre (WM_NCPAINT), avant WM_WINDOWPOSCHANGED.
//!
//! GetWindowPlacement et SetWindowPlacement, comme IntGetWindowPlacement et
//! IntSetWindowPlacement : le rectangle « normal » est celui que la fenêtre
//! garde, dans la zone cliente de son parent, en coordonnées de la zone de
//! travail pour une fenêtre de premier niveau ; SetWindowPlacement ramène
//! les places sur la zone de travail (make_rect_onscreen), les garde, met
//! la fenêtre à celle de son état, puis la montre par ShowWindow.
//!
//! Pas encore, journalisé une fois : cacher les fenêtres possédées d'une
//! fenêtre réduite (IntShowOwnedPopups) ; la copie des bits valides (tout
//! est repeint), garder les fenêtres possédées au-dessus de leur
//! propriétaire (WinPosDoOwnedPopups), `SWP_ASYNCWINDOWPOS` (fait tout de
//! suite), les messages à la fenêtre d'un autre thread ; le crochet CBT
//! (HCBT_MINMAX).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::user::{
    sm, NcCalcSizeParams32, WindowPos32, HWND_BOTTOM, HWND_NOTOPMOST, HWND_TOP, HWND_TOPMOST, SWP_ASYNCWINDOWPOS,
    SWP_DEFERERASE, SWP_FRAMECHANGED, SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_NOCLIENTMOVE, SWP_NOCLIENTSIZE, SWP_NOMOVE,
    SWP_NOOWNERZORDER, SWP_NOREDRAW, SWP_NOSENDCHANGING, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SWP_STATECHANGED,
    WM_CHILDACTIVATE, WM_NCCALCSIZE, WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING, WNDS2_WIN31COMPAT, WNDS_SENDNCPAINT,
    WS_CHILD, WS_EX_TOPMOST, WS_MINIMIZE, WS_POPUP, WS_VISIBLE,
};
use abi::user::{
    WindowPlacement32, ARW_BOTTOMRIGHT, ARW_HIDE, ARW_STARTMASK, ARW_TOPLEFT, ARW_TOPRIGHT, ARW_UP, RDW_NOERASE,
    RDW_NOINTERNALPAINT, RDW_VALIDATE, SWP_NOCOPYBITS, WA_ACTIVE, WM_ACTIVATE, WM_QUERYOPEN, WNDS_MAXIMIZESTOMONITOR,
    WPF_ASYNCWINDOWPLACEMENT, WPF_MAXINIT, WPF_MININIT, WPF_RESTORETOMAXIMIZED, WPF_SETMINPOSITION, WS_EX_TOOLWINDOW,
};
use abi::user::{
    STARTF_USEPOSITION, STARTF_USESHOWWINDOW, STARTF_USESIZE, SW_FORCEMINIMIZE, SW_HIDE, SW_MAXIMIZE, SW_MINIMIZE,
    SW_RESTORE, SW_SHOW, SW_SHOWDEFAULT, SW_SHOWMAXIMIZED, SW_SHOWMINIMIZED, SW_SHOWMINNOACTIVE, SW_SHOWNA,
    SW_SHOWNOACTIVATE, SW_SHOWNORMAL, WM_SHOWWINDOW, WNDS_SENDSIZEMOVEMSGS, WS_CAPTION, WS_EX_MDICHILD, WS_MAXIMIZE,
};

use crate::gdi::dib::Rect;
use crate::gdi::region::Region;
use crate::paint;
use crate::window::{self, LParam, StartupPlace, Window};

/// SWP_AGG_*, des drapeaux ensemble : rien ne bouge, ce qui dit ce qui a
/// changé, la zone cliente ne change pas ; la géométrie ne change pas
/// (comme ReactOS : ni la taille, ni celle de la zone cliente, ni l'ordre Z).
pub const SWP_AGG_NOPOSCHANGE: u32 = SWP_NOSIZE | SWP_NOMOVE | SWP_NOCLIENTSIZE | SWP_NOCLIENTMOVE | SWP_NOZORDER;
pub const SWP_AGG_STATUSFLAGS: u32 = SWP_AGG_NOPOSCHANGE | SWP_FRAMECHANGED | SWP_HIDEWINDOW | SWP_SHOWWINDOW;
pub const SWP_AGG_NOCLIENTCHANGE: u32 = SWP_NOCLIENTSIZE | SWP_NOCLIENTMOVE;
pub const SWP_AGG_NOGEOMETRYCHANGE: u32 = SWP_NOSIZE | SWP_NOCLIENTSIZE | SWP_NOZORDER;

/// Ce que WinPosFixupFlags sait de la fenêtre avant de la placer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Situation {
    pub style: u32,
    pub ex_style: u32,
    /// Son rectangle, à l'écran.
    pub window: Rect,
    /// Son parent est visible.
    pub parent_visible: bool,
    /// L'origine de la zone cliente du parent, à l'écran.
    pub parent_origin: (i32, i32),
    /// Elle est la première, la dernière de ses sœurs dans l'ordre Z.
    pub first: bool,
    pub last: bool,
    /// Elle est au premier plan (la fenêtre active de l'utilisateur).
    pub foreground: bool,
}

/// La fenêtre `hwndInsertAfter` d'un SetWindowPos : inconnue, d'un autre
/// parent, ou sœur (que la fenêtre suit déjà, ou non).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertAfter {
    Missing,
    Stranger,
    Sibling { followed_by_window: bool },
}

/// WinPosFixupFlags : `pos` corrigé. Les coordonnées sur 16 bits, les
/// tailles positives ; `SWP_NOREDRAW` sous un parent caché quand rien ne
/// bouge, ou pour une fenêtre cachée qui le reste ; `SWP_SHOWWINDOW` d'une
/// fenêtre visible et `SWP_HIDEWINDOW` d'une cachée ôtés ; `SWP_NOSIZE` et
/// `SWP_NOMOVE` quand la taille et la place ne changent pas ; une fenêtre de
/// premier niveau qui s'active monte en haut de l'ordre Z ; `SWP_NOZORDER`
/// quand sa place dans l'ordre Z ne change pas. `after` dit ce qu'est une
/// sœur donnée. Rend `false` pour une sœur d'un autre parent (rien ne se
/// fait, SetWindowPos rend TRUE).
pub fn fixup_flags(pos: &mut WindowPos32, at: &Situation, after: impl FnOnce(u32) -> InsertAfter) -> bool {
    pos.x = pos.x.clamp(-32768, 32767);
    pos.y = pos.y.clamp(-32768, 32767);
    pos.cx = pos.cx.max(0);
    pos.cy = pos.cy.max(0);
    if !at.parent_visible && pos.flags & SWP_AGG_STATUSFLAGS == SWP_AGG_NOPOSCHANGE {
        pos.flags |= SWP_NOREDRAW;
    }
    if at.style & WS_VISIBLE != 0 {
        pos.flags &= !SWP_SHOWWINDOW;
    } else {
        pos.flags &= !SWP_HIDEWINDOW;
        if pos.flags & SWP_SHOWWINDOW == 0 {
            pos.flags |= SWP_NOREDRAW;
        }
    }
    if at.window.right - at.window.left == pos.cx && at.window.bottom - at.window.top == pos.cy {
        pos.flags |= SWP_NOSIZE;
    }
    if at.window.left == pos.x + at.parent_origin.0 && at.window.top == pos.y + at.parent_origin.1 {
        pos.flags |= SWP_NOMOVE;
    }
    let topmost = at.ex_style & WS_EX_TOPMOST != 0;
    if !at.foreground
        && at.style & (WS_POPUP | WS_CHILD) != WS_CHILD
        && pos.flags & (SWP_NOACTIVATE | SWP_HIDEWINDOW) == 0
        && (pos.flags & SWP_NOZORDER != 0 || (pos.insert_after != HWND_TOPMOST && pos.insert_after != HWND_NOTOPMOST))
    {
        // Brought to the top when activating.
        pos.flags &= !SWP_NOZORDER;
        pos.insert_after = if topmost { HWND_TOPMOST } else { HWND_TOP };
    }
    if pos.flags & SWP_NOZORDER != 0 {
        return true;
    }
    // 16-bit HWND_TOPMOST and HWND_NOTOPMOST.
    match pos.insert_after {
        0xFFFF => pos.insert_after = HWND_TOPMOST,
        0xFFFE => pos.insert_after = HWND_NOTOPMOST,
        _ => {}
    }
    let unchanged = match pos.insert_after {
        HWND_TOP => {
            if topmost {
                pos.insert_after = HWND_TOPMOST;
            }
            at.first
        }
        HWND_BOTTOM => !topmost && at.last,
        HWND_TOPMOST => topmost && at.first,
        HWND_NOTOPMOST => !topmost,
        sibling => match after(sibling) {
            InsertAfter::Missing => return true,
            InsertAfter::Stranger => return false,
            InsertAfter::Sibling { followed_by_window } => sibling == pos.hwnd || followed_by_window,
        },
    };
    if unchanged {
        pos.flags |= SWP_NOZORDER;
    }
    true
}

fn offset(rect: Rect, dx: i32, dy: i32) -> Rect {
    Rect::new(rect.left + dx, rect.top + dy, rect.right + dx, rect.bottom + dy)
}

/// co_WinPosDoWinPosChanging, sans le message : les rectangles de la
/// fenêtre et de sa zone cliente (à l'écran) après `pos`, depuis `window`
/// et `client` ; `origin` est celle de la zone cliente du parent (0, 0 pour
/// le bureau). Une fenêtre réduite prend la taille d'une icône réduite
/// (métriques `m`), sa zone cliente est sa fenêtre.
pub fn new_rects(
    window: Rect,
    client: Rect,
    minimized: bool,
    pos: &WindowPos32,
    origin: (i32, i32),
    m: &impl Fn(usize) -> i32,
) -> (Rect, Rect) {
    let mut new_window = window;
    let mut new_client = if minimized { window } else { client };
    if pos.flags & SWP_NOSIZE == 0 {
        let (cx, cy) = if minimized { (m(sm::CXMINIMIZED), m(sm::CYMINIMIZED)) } else { (pos.cx, pos.cy) };
        new_window.right = new_window.left + cx;
        new_window.bottom = new_window.top + cy;
    }
    if pos.flags & SWP_NOMOVE == 0 {
        let (x, y) = (pos.x + origin.0, pos.y + origin.1);
        new_window = offset(new_window, x - window.left, y - window.top);
        new_client = offset(new_client, x - window.left, y - window.top);
    }
    (new_window, new_client)
}

/// Une fois, journalise ce qui manque encore à SetWindowPos.
fn report_missing(what: &str, reported: &AtomicBool) {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: SetWindowPos: {what}: not yet");
    }
}

/// Un `WINDOWPOS` lu dans les octets d'un message.
pub fn window_pos_of(bytes: &[u8]) -> WindowPos32 {
    let word = |i: usize| u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    WindowPos32 {
        hwnd: word(0),
        insert_after: word(1),
        x: word(2) as i32,
        y: word(3) as i32,
        cx: word(4) as i32,
        cy: word(5) as i32,
        flags: word(6),
    }
}

/// L'origine de la zone cliente du parent de `window` à l'écran (0, 0 pour
/// le bureau ou sans parent).
fn parent_origin(parent: Option<&Arc<Window>>) -> (i32, i32) {
    match parent {
        Some(parent) if !parent.is_desktop_window() => {
            let client = parent.state().client;
            (client.left, client.top)
        }
        _ => (0, 0),
    }
}

/// co_WinPosDoNCCALCSize : WM_NCCALCSIZE avec des rectangles valides (la
/// nouvelle place de la fenêtre, l'ancienne, l'ancienne zone cliente, dans
/// la zone cliente du parent d'une fenêtre fille) quand la taille ou le
/// cadre changent ; rend la nouvelle zone cliente et ôte de `pos`
/// `SWP_NOCLIENTMOVE` et `SWP_NOCLIENTSIZE` si elle bouge ou change.
fn nc_calc_size(window: &Arc<Window>, pos: &mut WindowPos32, new_window: Rect, new_client: Rect) -> Rect {
    let state = window.state();
    let mut client = new_client;
    if pos.flags & (SWP_FRAMECHANGED | SWP_NOSIZE) != SWP_NOSIZE {
        let origin = if state.style & WS_CHILD != 0 {
            window::get(state.parent).map_or((0, 0), |parent| (parent.state().client.left, parent.state().client.top))
        } else {
            (0, 0)
        };
        let relative = |rect: Rect| {
            let rect = offset(rect, -origin.0, -origin.1);
            [rect.left, rect.top, rect.right, rect.bottom]
        };
        let params = NcCalcSizeParams32 {
            rects: [relative(new_window), relative(state.window), relative(state.client)],
            pos: 0,
        };
        let mut bytes: Vec<u8> = params.as_bytes().to_vec();
        bytes.extend_from_slice(pos.as_bytes());
        let _ = window::send_message(window, WM_NCCALCSIZE, 1, LParam::Buffer { bytes: &mut bytes, write_back: true });
        let word = |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
        let given = Rect::new(word(0), word(1), word(2), word(3));
        // Garbage from the procedure is ignored.
        if given.left <= given.right && given.top <= given.bottom {
            client = window::fix_client_rect(offset(given, origin.0, origin.1), new_window);
        }
        if client.left != state.client.left || client.top != state.client.top {
            pos.flags &= !SWP_NOCLIENTMOVE;
        }
        if client.right - client.left != state.client.right - state.client.left
            || client.bottom - client.top != state.client.bottom - state.client.top
        {
            pos.flags &= !SWP_NOCLIENTSIZE;
        }
    } else if pos.flags & SWP_NOMOVE == 0 && (client.left != state.client.left || client.top != state.client.top) {
        pos.flags &= !SWP_NOCLIENTMOVE;
    }
    client
}

/// co_WinPosSetWindowPos : place `window` en `x`, `y` (dans la zone cliente
/// de son parent), de `cx` × `cy`, sous `insert_after` dans l'ordre Z
/// (`HWND_*` ou une sœur), selon `flags` (`SWP_*`). Rend TRUE, même quand
/// rien ne se fait (une sœur d'un autre parent).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn set_window_pos(window: &Arc<Window>, insert_after: u32, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> bool {
    let mut pos = WindowPos32 { hwnd: window.handle, insert_after, x, y, cx, cy, flags };
    if pos.flags & SWP_ASYNCWINDOWPOS != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("SWP_ASYNCWINDOWPOS (done at once)", &REPORTED);
        pos.flags &= !SWP_ASYNCWINDOWPOS;
    }

    // WM_WINDOWPOSCHANGING: the procedure may change the request.
    if pos.flags & SWP_NOSENDCHANGING == 0
        && !(pos.flags & SWP_AGG_NOCLIENTCHANGE != 0 && pos.flags & SWP_SHOWWINDOW != 0)
    {
        let mut bytes = pos.as_bytes().to_vec();
        let changing = LParam::Buffer { bytes: &mut bytes, write_back: true };
        if window::send_message(window, WM_WINDOWPOSCHANGING, 0, changing).is_ok() {
            pos = WindowPos32 { hwnd: window.handle, ..window_pos_of(&bytes) };
        }
    }
    let state = window.state();
    let parent = window::get(state.parent);
    let origin = parent_origin(parent.as_ref());
    let minimized = state.style & WS_MINIMIZE != 0;
    let (new_window, new_client) = new_rects(state.window, state.client, minimized, &pos, origin, &crate::metrics::get);
    pos.flags |= SWP_NOCLIENTMOVE | SWP_NOCLIENTSIZE;

    let situation = Situation {
        style: state.style,
        ex_style: state.ex_style,
        window: state.window,
        parent_visible: parent.as_ref().is_none_or(|parent| window::is_visible(parent)),
        parent_origin: origin,
        first: parent.as_ref().is_some_and(|parent| parent.state().child == window.handle),
        last: state.next == 0,
        foreground: false,
    };
    let sibling = |after: u32| match window::get(after) {
        None => InsertAfter::Missing,
        Some(after) if after.state().parent != state.parent => InsertAfter::Stranger,
        Some(after) => InsertAfter::Sibling { followed_by_window: after.state().next == window.handle },
    };
    if !fixup_flags(&mut pos, &situation, sibling) {
        return true;
    }
    if pos.flags & (SWP_NOZORDER | SWP_HIDEWINDOW | SWP_SHOWWINDOW) != SWP_NOZORDER
        && parent.as_ref().is_some_and(|parent| parent.is_desktop_window())
        && (state.owner != 0 || crate::window::owns_windows(window))
    {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("owned windows kept above their owner (WinPosDoOwnedPopups)", &REPORTED);
    }

    // Visible before: its region would not be empty (no regions yet).
    let visible_before = pos.flags & (SWP_NOREDRAW | SWP_SHOWWINDOW) == 0
        && pos.flags & (SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_HIDEWINDOW | SWP_FRAMECHANGED)
            != (SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER)
        && window::is_visible(window)
        && !state.window.is_empty();

    let new_client = nc_calc_size(window, &mut pos, new_window, new_client);
    if pos.flags & SWP_NOZORDER == 0 {
        window::link(window, pos.insert_after);
    }
    let old = window.state();
    if new_client.left != old.client.left || new_client.top != old.client.top {
        // The children keep their place in the client area.
        window::move_tree(window, new_client.left - old.client.left, new_client.top - old.client.top);
    }
    let state = window::change(window, |state| {
        (state.window, state.client) = (new_window, new_client);
        if pos.flags & SWP_HIDEWINDOW != 0 {
            state.style &= !WS_VISIBLE;
        } else if pos.flags & SWP_SHOWWINDOW != 0 {
            state.style |= WS_VISIBLE;
        }
        if state.style & WS_VISIBLE != 0
            && (pos.flags & SWP_STATECHANGED != 0
                || (state.state2 & WNDS2_WIN31COMPAT == 0 && pos.flags & SWP_NOREDRAW != 0))
        {
            state.state |= WNDS_SENDNCPAINT;
        }
    });
    let redraw = pos.flags & SWP_NOREDRAW == 0 && pos.flags & SWP_AGG_STATUSFLAGS != SWP_AGG_NOPOSCHANGE;
    if redraw || (pos.flags & SWP_NOZORDER != 0 && pos.flags & SWP_NOOWNERZORDER != 0) {
        let visible_after = window::is_visible(window) && !new_window.is_empty();
        if visible_after {
            // No bits are copied: all of it is to be painted again.
            paint::invalidate(window);
        }
        if visible_before {
            let mut exposed = Region::from_rect(old.window);
            if visible_after {
                exposed.subtract_rect(new_window);
            }
            paint::expose(window, &exposed);
        }
    }

    if pos.flags & (SWP_NOACTIVATE | SWP_HIDEWINDOW) == 0 {
        if state.style & (WS_CHILD | WS_POPUP) == WS_CHILD {
            let _ = window::send_message(window, WM_CHILDACTIVATE, 0, LParam::Value(0));
        } else {
            crate::input::activate(window);
        }
    }

    // Invisible, only its place in the Z order: no WM_WINDOWPOSCHANGED.
    if !visible_before
        && state.ex_style & WS_EX_TOPMOST == 0
        && pos.flags & SWP_AGG_STATUSFLAGS == SWP_AGG_NOPOSCHANGE & !SWP_NOZORDER
    {
        pos.flags |= SWP_NOZORDER | SWP_NOREDRAW;
    }

    if flags & SWP_DEFERERASE == 0 {
        // Erase the parent when hiding or resizing a child; a top-level
        // window repaints itself.
        if flags & SWP_HIDEWINDOW != 0
            || (flags & SWP_SHOWWINDOW == 0 && pos.flags & SWP_AGG_STATUSFLAGS != SWP_AGG_NOGEOMETRYCHANGE)
        {
            match window::get(state.parent).filter(|parent| !parent.is_desktop_window()) {
                Some(parent) => paint::sync_and_paint(&parent),
                None => paint::sync_and_paint(window),
            }
        }
        // Newly shown windows get their chance to paint.
        if pos.flags & SWP_AGG_STATUSFLAGS != SWP_AGG_NOPOSCHANGE
            && flags & SWP_AGG_NOCLIENTCHANGE == 0
            && flags & SWP_SHOWWINDOW != 0
        {
            paint::sync_and_paint(window);
        }
    }

    if pos.flags & SWP_AGG_STATUSFLAGS != SWP_AGG_NOPOSCHANGE
        && !(flags & SWP_AGG_NOCLIENTCHANGE != 0 && flags & SWP_SHOWWINDOW != 0)
    {
        // The final place, in the parent's client area.
        let origin = parent_origin(window::get(state.parent).as_ref());
        pos.x = new_window.left - origin.0;
        pos.y = new_window.top - origin.1;
        pos.cx = new_window.right - new_window.left;
        pos.cy = new_window.bottom - new_window.top;
        let mut bytes = pos.as_bytes().to_vec();
        let _ = window::send_message(
            window,
            WM_WINDOWPOSCHANGED,
            0,
            LParam::Buffer { bytes: &mut bytes, write_back: false },
        );
    }
    true
}

/// Ce que fait une commande de ShowWindow ([`show_command`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShowCommand {
    /// Rien à faire : rend cette valeur.
    Done(bool),
    /// Les drapeaux de SetWindowPos.
    Place(u32),
    /// Réduire, agrandir ou rétablir (co_WinPosMinMaximize) par la commande
    /// `cmd`, puis SetWindowPos avec ces drapeaux et ceux qu'il donne.
    MinMax { cmd: u32, swp: u32 },
}

/// La commande de réduction `cmd` (SW_MINIMIZE, SW_SHOWMINIMIZED,
/// SW_SHOWMINNOACTIVE, SW_FORCEMINIMIZE).
pub fn is_minimize_command(cmd: u32) -> bool {
    matches!(cmd, SW_MINIMIZE | SW_SHOWMINIMIZED | SW_SHOWMINNOACTIVE | SW_FORCEMINIMIZE)
}

/// co_WinPosShowWindow, son `switch` : ce que fait la commande `cmd` à une
/// fenêtre de style `style` et de style étendu `ex_style`, visible ou non
/// (`was_visible`). Réduire (une fenêtre qui ne l'est pas) n'active pas ;
/// SW_SHOWMINNOACTIVE ne change pas non plus son rang. Agrandir une
/// fenêtre qui ne l'est pas passe par co_WinPosMinMaximize (SW_MAXIMIZE),
/// rétablir une fenêtre réduite ou agrandie aussi. Une fenêtre fille (hors
/// MDI) ne prend ni l'activation ni le haut de l'ordre Z, sauf par
/// SW_SHOWNA ; pour une commande de co_WinPosMinMaximize, l'appelant
/// l'ajoute ([`child_flags`]), d'après les drapeaux qu'il rend. Aucune
/// fenêtre n'est active, une fenêtre cachée garde donc son rang
/// (`SWP_NOACTIVATE | SWP_NOZORDER`). ReactOS le vérifie de nouveau après
/// WM_SHOWWINDOW, pour un style que la procédure aurait changé : pas
/// encore.
///
/// SW_FORCEMINIMIZE réduit comme SW_MINIMIZE, ce que dit l'API (même si le
/// thread de la fenêtre ne répond pas) ; ReactOS cache la fenêtre
/// (IntForceMinimizeWindow), pour ses fenêtres fantômes.
pub fn show_command(cmd: u32, style: u32, ex_style: u32, was_visible: bool) -> ShowCommand {
    let mut swp = 0;
    match cmd {
        SW_HIDE => {
            if !was_visible {
                return ShowCommand::Done(false);
            }
            swp |= SWP_HIDEWINDOW | SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER;
        }
        SW_SHOWMINNOACTIVE | SW_SHOWMINIMIZED | SW_MINIMIZE | SW_FORCEMINIMIZE => {
            if cmd == SW_SHOWMINNOACTIVE {
                swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            }
            // CORE-15669: SW_MINIMIZE shows too.
            swp |= SWP_SHOWWINDOW | SWP_NOACTIVATE;
            if style & WS_MINIMIZE == 0 {
                let cmd = if cmd == SW_FORCEMINIMIZE { SW_MINIMIZE } else { cmd };
                return ShowCommand::MinMax { cmd, swp };
            }
            if was_visible {
                return ShowCommand::Done(true);
            }
            swp |= SWP_NOSIZE | SWP_NOMOVE;
        }
        SW_SHOWMAXIMIZED => {
            swp |= SWP_SHOWWINDOW;
            if style & WS_MAXIMIZE == 0 {
                return ShowCommand::MinMax { cmd: SW_MAXIMIZE, swp };
            }
            if was_visible {
                return ShowCommand::Done(true);
            }
            swp |= SWP_NOSIZE | SWP_NOMOVE;
        }
        SW_SHOWNA => {
            swp |= SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
            if style & WS_CHILD != 0 && ex_style & WS_EX_MDICHILD == 0 {
                swp |= SWP_NOZORDER;
            }
            return ShowCommand::Place(swp);
        }
        SW_SHOW => {
            if was_visible {
                return ShowCommand::Done(true);
            }
            swp |= SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
        }
        SW_SHOWNOACTIVATE | SW_SHOWNORMAL | SW_SHOWDEFAULT | SW_RESTORE => {
            if cmd == SW_SHOWNOACTIVATE {
                swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            }
            if !was_visible {
                swp |= SWP_SHOWWINDOW;
            }
            if style & (WS_MINIMIZE | WS_MAXIMIZE) != 0 {
                return ShowCommand::MinMax { cmd, swp };
            }
            if was_visible {
                return ShowCommand::Done(true);
            }
            swp |= SWP_NOSIZE | SWP_NOMOVE;
        }
        _ => return ShowCommand::Done(false),
    }
    ShowCommand::Place(swp | child_flags(cmd, style, ex_style))
}

/// Ce qu'une fenêtre fille (hors MDI) ajoute aux drapeaux `swp` de la
/// commande `cmd` : ni activée ni montée dans l'ordre Z, sauf par SW_SHOWNA
/// (« We can't activate a child window »).
pub fn child_flags(cmd: u32, style: u32, ex_style: u32) -> u32 {
    if style & WS_CHILD != 0 && ex_style & WS_EX_MDICHILD == 0 && cmd != SW_SHOWNA {
        SWP_NOACTIVATE | SWP_NOZORDER
    } else {
        0
    }
}

/// La commande de ShowWindow que prend une fenêtre de style `style` (avec
/// un propriétaire : `owned`) d'après le `STARTUPINFO` du processus
/// (`startup`) : sa première fenêtre recouvrante à titre et sans
/// propriétaire y prend sa commande (`SW_SHOWNORMAL` et `SW_SHOW` y
/// deviennent `SW_SHOWDEFAULT`), comme `SW_SHOWDEFAULT` ; le `STARTUPINFO`
/// sert alors une seule fois.
pub fn startup_command(cmd: u32, style: u32, owned: bool, startup: &mut StartupPlace) -> u32 {
    let mut cmd = cmd;
    let mut first_time = false;
    if startup.flags & STARTF_USESHOWWINDOW != 0
        && style & (WS_POPUP | WS_CHILD) != WS_CHILD
        && style & WS_CAPTION == WS_CAPTION
        && !owned
    {
        if cmd == SW_SHOWNORMAL || cmd == SW_SHOW {
            cmd = SW_SHOWDEFAULT;
        }
        first_time = true;
    }
    if cmd == SW_SHOWDEFAULT && startup.flags & STARTF_USESHOWWINDOW != 0 {
        cmd = startup.show;
        first_time = true;
    }
    if first_time {
        startup.flags &= !(STARTF_USEPOSITION | STARTF_USESIZE | STARTF_USESHOWWINDOW);
    }
    cmd
}

/// [`startup_command`] avec le `STARTUPINFO` du processus courant, lu de
/// ses paramètres la première fois.
fn process_startup_command(window: &Window, cmd: u32) -> u32 {
    let Some(process) = ps::ethread::current_thread().map(|thread| thread.process().clone()) else { return cmd };
    let Ok(info) = crate::process_info(&process) else { return cmd };
    if info.startup.lock().is_none() {
        let startup = window::startup_place();
        info.startup.lock().get_or_insert(startup);
    }
    let state = window.state();
    let mut startup = info.startup.lock();
    match startup.as_mut() {
        Some(startup) => startup_command(cmd, state.style, state.owner != 0, startup),
        None => cmd,
    }
}

/// IsChildVisible : les parents d'une fenêtre fille, jusqu'au premier qui ne
/// l'est pas, sont visibles.
fn is_child_visible(window: &Window) -> bool {
    let mut state = window.state();
    loop {
        if state.style & (WS_POPUP | WS_CHILD) != WS_CHILD {
            return true;
        }
        let Some(parent) = window::get(state.parent) else { return true };
        state = parent.state();
        if state.style & WS_VISIBLE == 0 {
            return false;
        }
    }
}

/// IntShowOwnedPopups : pas encore (journalisé une fois) ; les fenêtres
/// que possède une fenêtre réduite restent montrées.
fn show_owned_popups(window: &Window, show: bool) {
    if !window::owns_windows(window) {
        return;
    }
    static REPORTED: AtomicBool = AtomicBool::new(false);
    if !REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: ShowWindow: hiding or showing the owned windows of a minimized window ({show}): not yet");
    }
}

/// co_WinPosShowWindow : montre, cache, réduit, agrandit ou rétablit
/// `window` selon `cmd` (`SW_*`) ; rend si elle était visible.
///
/// Après le placement : réduite par SW_MINIMIZE, la fenêtre active du
/// premier plan cède l'activation (ActivateOtherWindowMin, sinon
/// co_WinPosActivateOtherWindow : [`crate::input::activate_other_min`],
/// [`crate::input::activate_other`]) et le clavier revient à son parent
/// (personne pour une fenêtre de premier niveau) ; rétablie d'une fenêtre
/// réduite, elle prend le clavier et, de premier niveau, WM_ACTIVATE.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn show_window(window: &Arc<Window>, cmd: u32) -> bool {
    let state = window.state();
    let style = state.style;
    let was_visible = style & WS_VISIBLE != 0;
    let cmd = process_startup_command(window, cmd);
    let child = style & WS_CHILD != 0;
    let (mut swp, new_pos) = match show_command(cmd, style, state.ex_style, was_visible) {
        ShowCommand::Done(result) => return result,
        ShowCommand::Place(swp) => (swp, Rect::default()),
        ShowCommand::MinMax { cmd: what, swp } => {
            if what == SW_SHOWMINIMIZED {
                // Fix wine Win test_SetFocus todo #1 & #2.
                if let Ok(thread) = crate::convert_current_thread() {
                    let parent = window::get(state.parent).filter(|_| style & (WS_CHILD | WS_POPUP) == WS_CHILD);
                    crate::input::set_focus(&thread, parent.as_ref());
                }
            }
            if is_minimize_command(what) {
                show_owned_popups(window, false);
            }
            let (more, rect) = min_maximize(window, what);
            let swp = swp | more;
            let state = window.state();
            (swp | child_flags(cmd, state.style, state.ex_style), rect)
        }
    };
    let show = cmd != SW_HIDE;
    if (show != was_visible || cmd == SW_SHOWNA) && cmd != SW_SHOWMAXIMIZED && swp & SWP_STATECHANGED == 0 {
        let _ = window::send_message(window, WM_SHOWWINDOW, u32::from(show), LParam::Value(0));
        if !window.is_alive() {
            return was_visible;
        }
    }
    let state = window.state();
    if is_child_visible(window) || swp & SWP_STATECHANGED != 0 {
        let after = if state.ex_style & WS_EX_TOPMOST != 0 { HWND_TOPMOST } else { HWND_TOP };
        let (cx, cy) = (new_pos.right - new_pos.left, new_pos.bottom - new_pos.top);
        swp &= 0xFFFF;
        set_window_pos(window, after, new_pos.left, new_pos.top, cx, cy, swp);
    } else {
        // Under a hidden parent: WS_VISIBLE alone.
        window::change(window, |state| {
            state.style = if show { state.style | WS_VISIBLE } else { state.style & !WS_VISIBLE };
        });
    }
    if cmd == SW_SHOWMAXIMIZED && swp & SWP_STATECHANGED != 0 {
        show_owned_popups(window, true);
    }
    if cmd == SW_HIDE {
        return was_visible;
    }
    if cmd == SW_MINIMIZE || cmd == SW_FORCEMINIMIZE {
        give_up_activation(window);
    }
    if window.state().state & WNDS_SENDSIZEMOVEMSGS != 0 {
        window::send_size_move(window);
    }
    // Restored from minimized: the window takes the keyboard.
    if style & WS_MINIMIZE != 0 && window.state().style & WS_MINIMIZE == 0 {
        if let Ok(thread) = crate::convert_current_thread() {
            crate::input::set_focus(&thread, Some(window));
        }
        if !child {
            let _ = window::send_message(window, WM_ACTIVATE, WA_ACTIVE, LParam::Value(0));
        }
    }
    was_visible
}

/// Après SW_MINIMIZE : la fenêtre active du premier plan cède l'activation
/// (à une autre fenêtre de premier niveau d'abord, ActivateOtherWindowMin),
/// et le clavier revient à son parent.
fn give_up_activation(window: &Arc<Window>) {
    let Ok(thread) = crate::convert_current_thread() else { return };
    if thread.server != window.pti {
        return;
    }
    let active = thread.queue.with(|queue| queue.active).0;
    let foreground = crate::input::foreground().is_some_and(|foreground| Arc::ptr_eq(&foreground, &thread));
    let parent = window::get(window.state().parent);
    let top_level = parent.as_ref().is_none_or(|parent| parent.is_desktop_window());
    if active == window.handle && foreground && !(top_level && crate::input::activate_other_min(window)) {
        crate::input::activate_other(window, None, true);
    }
    // The keyboard, once another window is active (it may have it now).
    if thread.queue.with(|queue| queue.focus).0 == window.handle {
        crate::input::set_focus(&thread, parent.filter(|_| !top_level).as_ref());
    }
}

/// co_WinPosMinMaximize : `window` réduite, agrandie ou rétablie selon `cmd`
/// (`SW_MINIMIZE`, `SW_SHOWMINIMIZED`, `SW_SHOWMINNOACTIVE`, `SW_MAXIMIZE`,
/// `SW_SHOWNORMAL`, `SW_SHOWNOACTIVATE`, `SW_RESTORE`, `SW_SHOWDEFAULT`) :
/// son style change (`WS_MINIMIZE`, `WS_MAXIMIZE`) et sa place gardée aussi
/// ([`InternalPos`]) ; rend les drapeaux de SetWindowPos à ajouter
/// (`SWP_STATECHANGED` si son état change ; `SWP_NOSIZE | SWP_NOMOVE`
/// pour rien) et le rectangle où la placer, dans la zone cliente de son
/// parent.
///
/// - Réduire : elle se rétablira agrandie si elle l'est
///   (`WPF_RESTORETOMAXIMIZED`), elle n'a plus rien à peindre, et va à la
///   place de son icône ([`find_icon_pos`]), de SM_CXMINIMIZED ×
///   SM_CYMINIMIZED.
/// - Agrandir : à la place et à la taille de WM_GETMINMAXINFO
///   ([`crate::window::min_max_info`]) ; rien si elle l'est déjà et
///   qu'elle est visible.
/// - Rétablir une fenêtre réduite : WM_QUERYOPEN d'abord (FALSE : elle le
///   reste) ; agrandie si elle l'était, sinon à son rectangle normal ;
///   rétablir une fenêtre agrandie : à son rectangle normal.
///
/// Écarts voulus avec ReactOS : le rectangle rendu est un rectangle, dont
/// l'appelant tire la taille (ReactOS y met tantôt la taille, tantôt le
/// coin opposé : rétablie agrandie depuis réduite, une fenêtre y gagnait sa
/// place en taille) ; le rectangle normal est celui que garde
/// `InternalPos`, dans la zone cliente du parent (ReactOS prend celui de
/// GetWindowPlacement, décalé dans la zone de travail).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn min_maximize(window: &Arc<Window>, cmd: u32) -> (u32, Rect) {
    const NOTHING: u32 = SWP_NOSIZE | SWP_NOMOVE;
    // IntGetWindowPlacement: the place kept up to date.
    let _ = placement(window);
    let state = window.state();
    let mut swp = 0;
    if state.style & WS_MINIMIZE != 0 {
        if is_minimize_command(cmd) {
            return (NOTHING, Rect::default());
        }
        let open = window::send_message(window, WM_QUERYOPEN, 0, LParam::Value(0));
        if open.is_ok_and(|open| open == 0) {
            return (NOTHING, Rect::default());
        }
        swp |= SWP_NOCOPYBITS;
    }
    let max_rect = |window: &Arc<Window>| {
        let info = window::min_max_info(window);
        let [x, y] = info.max_position;
        Rect::new(x, y, x + info.max_size[0], y + info.max_size[1])
    };
    match cmd {
        SW_MINIMIZE | SW_SHOWMINNOACTIVE | SW_SHOWMINIMIZED | SW_FORCEMINIMIZE => {
            window::change(window, |state| {
                let pos = &mut state.internal_pos;
                if state.style & WS_MAXIMIZE != 0 {
                    pos.flags |= WPF_RESTORETOMAXIMIZED;
                } else {
                    pos.flags &= !WPF_RESTORETOMAXIMIZED;
                }
                if pos.flags & WPF_SETMINPOSITION == 0 {
                    pos.flags &= !WPF_MININIT;
                }
                state.style = (state.style | WS_MINIMIZE) & !WS_MAXIMIZE;
            });
            paint::redraw_window(window, None, None, RDW_VALIDATE | RDW_NOERASE | RDW_NOINTERNALPAINT);
            let (x, y) = find_icon_pos(window);
            if state.style & WS_MINIMIZE == 0 {
                swp |= SWP_STATECHANGED;
            }
            let m = crate::metrics::get;
            swp |= SWP_NOCOPYBITS;
            (swp, Rect::new(x, y, x + m(sm::CXMINIMIZED), y + m(sm::CYMINIMIZED)))
        }
        SW_MAXIMIZE => {
            if state.style & (WS_MAXIMIZE | WS_VISIBLE) == WS_MAXIMIZE | WS_VISIBLE {
                return (NOTHING, Rect::default());
            }
            let rect = max_rect(window);
            window::change(window, |state| state.style = (state.style | WS_MAXIMIZE) & !WS_MINIMIZE);
            if state.style & WS_MAXIMIZE == 0 {
                swp |= SWP_STATECHANGED;
            }
            (swp, rect)
        }
        SW_SHOWNOACTIVATE | SW_SHOWNORMAL | SW_RESTORE | SW_SHOWDEFAULT => {
            // The state before the change (`window::change` gives the one after).
            let old = state;
            window::change(window, |state| {
                if cmd == SW_SHOWNOACTIVATE {
                    state.internal_pos.flags &= !WPF_RESTORETOMAXIMIZED;
                }
                state.style &= !(WS_MINIMIZE | WS_MAXIMIZE);
            });
            if old.style & WS_MINIMIZE != 0 {
                show_owned_popups(window, true);
                if old.internal_pos.flags & WPF_RESTORETOMAXIMIZED != 0 && cmd != SW_SHOWNOACTIVATE {
                    let rect = max_rect(window);
                    window::change(window, |state| state.style |= WS_MAXIMIZE);
                    return (swp | SWP_STATECHANGED, rect);
                }
                return (swp, old.internal_pos.normal);
            }
            if old.style & WS_MAXIMIZE == 0 {
                return (swp, Rect::default());
            }
            window::change(window, |state| state.internal_pos.flags &= !WPF_RESTORETOMAXIMIZED);
            (swp | SWP_STATECHANGED, old.internal_pos.normal)
        }
        _ => (swp, Rect::default()),
    }
}

/// Une place pas encore donnée (`InternalPos`, `WINDOWPLACEMENT`).
pub const NO_PLACE: (i32, i32) = (-1, -1);

/// La place gardée d'une fenêtre (`InternalPos` de ReactOS), dans la zone
/// cliente de son parent : son rectangle normal (celui qu'elle reprend
/// quand on la rétablit), ses places réduite (`icon`, le coin de son icône)
/// et agrandie (`max` ; depuis la zone de travail de son moniteur pour une
/// fenêtre de premier niveau), [`NO_PLACE`] tant qu'elles ne sont pas
/// données ; `flags` : `WPF_MININIT`, `WPF_MAXINIT` (ces places sont
/// prises), `WPF_SETMINPOSITION` (donnée par SetWindowPlacement),
/// `WPF_RESTORETOMAXIMIZED` (réduite depuis agrandie). Son rectangle normal
/// est pris la première fois qu'on la regarde (`initialized`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InternalPos {
    pub initialized: bool,
    pub flags: u32,
    pub normal: Rect,
    pub icon: (i32, i32),
    pub max: (i32, i32),
}

impl Default for InternalPos {
    fn default() -> Self {
        Self { initialized: false, flags: 0, normal: Rect::default(), icon: NO_PLACE, max: NO_PLACE }
    }
}

/// WinPosInitInternalPos : `pos` prend la place présente d'une fenêtre de
/// style `style`, de rectangle `rect` dans la zone cliente de son parent ;
/// la première fois, son rectangle normal et rien d'autre. Réduite : la
/// place de l'icône (`WPF_MININIT`). Agrandie (`WPF_MAXINIT`) : son coin,
/// depuis la zone de travail de son moniteur `monitor` pour une fenêtre de
/// premier niveau (`top_level` ; depuis le rectangle du moniteur pour une
/// fenêtre sans bouton d'agrandissement, ou contextuelle sans titre :
/// [`crate::defwnd::maximize_area`]), aucune si elle couvre son moniteur
/// (`to_monitor`, `WNDS_MAXIMIZESTOMONITOR`). Normale : son rectangle
/// normal.
pub fn init_internal_pos(
    pos: &mut InternalPos,
    style: u32,
    to_monitor: bool,
    rect: Rect,
    top_level: bool,
    monitor: Option<crate::monitor::Monitor>,
) {
    if !pos.initialized {
        *pos = InternalPos { initialized: true, normal: rect, ..InternalPos::default() };
    }
    let corner = (rect.left, rect.top);
    if style & WS_MINIMIZE != 0 {
        pos.icon = corner;
        pos.flags |= WPF_MININIT;
    } else if style & WS_MAXIMIZE != 0 {
        pos.flags |= WPF_MAXINIT;
        if !top_level {
            pos.max = corner;
        } else if to_monitor {
            pos.flags &= !WPF_MAXINIT;
            pos.max = NO_PLACE;
        } else {
            let area = monitor.map_or(Rect::default(), |m| crate::defwnd::maximize_area(style, m.rect, m.work));
            pos.max = (rect.left - area.left, rect.top - area.top);
        }
    } else {
        pos.normal = rect;
    }
}

/// La place de l'icône d'une fenêtre réduite (WinPosFindIconPos,
/// co_WinPosArrangeIconicWindows) : la première case libre (aucune autre
/// icône n'y est, `taken`) de la zone cliente `area` de son parent, en
/// cases de `size` (SM_CXMINIMIZED × SM_CYMINIMIZED), depuis le coin que
/// donne `arrange` (MINIMIZEDMETRICS.iArrange : `ARW_BOTTOMLEFT`…) et dans
/// sa direction (de côté, ou vers le haut ou le bas avec `ARW_UP`), à
/// `border` (SM_CXBORDER, SM_CYBORDER) du bord ; des cases pleines
/// seulement. Toutes prises : la première.
///
/// ReactOS part toujours d'en bas à gauche vers la droite (« FIXME:
/// Support Minimize Metrics ») et s'arrête à la première icône qui n'est
/// pas à la case qu'il essaie ; Mino prend la première case libre.
pub fn icon_slot(arrange: u32, area: Rect, taken: &[(i32, i32)], size: (i32, i32), border: (i32, i32)) -> (i32, i32) {
    let start = arrange & ARW_STARTMASK;
    let (right, top) =
        (start == ARW_BOTTOMRIGHT || start == ARW_TOPRIGHT, start == ARW_TOPLEFT || start == ARW_TOPRIGHT);
    let columns = ((area.right - area.left) / size.0.max(1)).max(1);
    let rows = ((area.bottom - area.top) / size.1.max(1)).max(1);
    let slot = |index: i32| {
        let (column, row) =
            if arrange & ARW_UP != 0 { (index / rows, index % rows) } else { (index % columns, index / columns) };
        let x =
            if right { area.right - (column + 1) * size.0 - border.0 } else { area.left + column * size.0 + border.0 };
        let y = if top { area.top + row * size.1 + border.1 } else { area.bottom - (row + 1) * size.1 - border.1 };
        (x, y)
    };
    (0..columns * rows).map(slot).find(|place| !taken.contains(place)).unwrap_or_else(|| slot(0))
}

/// WinPosFindIconPos : la place de l'icône de `window`, qu'elle garde
/// (`WPF_MININIT`). Celle que SetWindowPlacement a donnée
/// (`WPF_SETMINPOSITION`), sinon [`icon_slot`] parmi les icônes de ses
/// sœurs réduites et visibles, d'après MINIMIZEDMETRICS (SM_ARRANGE) ;
/// avec `ARW_HIDE` (un shell les montre lui-même), une fenêtre de premier
/// niveau va hors de l'écran, en (−32000, −32000), comme ReactOS.
fn find_icon_pos(window: &Arc<Window>) -> (i32, i32) {
    let state = window.state();
    let pos = state.internal_pos;
    let place = if pos.flags & (WPF_SETMINPOSITION | WPF_MININIT) == WPF_SETMINPOSITION | WPF_MININIT {
        pos.icon
    } else {
        let parent = window::get(state.parent);
        let arrange = crate::metrics::get(sm::ARRANGE) as u32;
        let desktop = parent.as_ref().is_none_or(|parent| parent.is_desktop_window());
        if desktop && arrange & ARW_HIDE != 0 {
            (-32000, -32000)
        } else {
            let mut taken = Vec::new();
            let mut sibling = parent.as_ref().and_then(|parent| window::get(parent.state().child));
            while let Some(other) = sibling {
                let other_state = other.state();
                if other.handle != window.handle
                    && other_state.style & (WS_VISIBLE | WS_MINIMIZE) == WS_VISIBLE | WS_MINIMIZE
                    && other_state.internal_pos.flags & WPF_MININIT != 0
                {
                    taken.push(other_state.internal_pos.icon);
                }
                sibling = window::get(other_state.next);
            }
            let area = parent.as_ref().map_or(Rect::default(), |parent| window::client_rect(parent));
            let m = crate::metrics::get;
            let size = (m(sm::CXMINIMIZED), m(sm::CYMINIMIZED));
            icon_slot(arrange, area, &taken, size, (m(sm::CXBORDER), m(sm::CYBORDER)))
        }
    };
    window::change(window, |state| {
        state.internal_pos.icon = place;
        state.internal_pos.flags |= WPF_MININIT;
    });
    place
}

/// IntGetWindowPlacement, d'une fenêtre de style `style` et de style
/// étendu `ex_style` dont la place gardée est `pos` (déjà à jour,
/// [`init_internal_pos`]) : la commande qui la montre telle qu'elle est
/// (réduite, agrandie ou normale), sa place réduite et sa place agrandie si
/// elles sont prises (pas la place agrandie d'une fenêtre qui couvre son
/// moniteur, `to_monitor`), sinon (−1, −1), et son rectangle normal ;
/// WPF_RESTORETOMAXIMIZED si elle se rétablira agrandie ou l'est,
/// WPF_SETMINPOSITION d'une fenêtre fille qui l'a reçu. Pour une fenêtre de
/// premier niveau (`top_level`) qui n'est pas une fenêtre d'outils, le
/// rectangle et la place réduite sont donnés dans la zone de travail de son
/// moniteur (`monitor`).
pub fn placement_of(
    style: u32,
    ex_style: u32,
    pos: &InternalPos,
    to_monitor: bool,
    top_level: bool,
    monitor: Option<crate::monitor::Monitor>,
) -> WindowPlacement32 {
    let show_cmd = if style & WS_MINIMIZE != 0 {
        SW_SHOWMINIMIZED
    } else if style & WS_MAXIMIZE != 0 {
        SW_SHOWMAXIMIZED
    } else {
        SW_SHOWNORMAL
    };
    let mut normal = pos.normal;
    let mut min = if pos.flags & WPF_MININIT != 0 { pos.icon } else { NO_PLACE };
    let max = if pos.flags & WPF_MAXINIT != 0 && !to_monitor { pos.max } else { NO_PLACE };
    if top_level && ex_style & WS_EX_TOOLWINDOW == 0 {
        if let Some(monitor) = monitor {
            if pos.flags & WPF_MININIT != 0 {
                min.0 -= monitor.work.left - monitor.rect.left;
                min.1 -= monitor.work.top - monitor.rect.top;
            }
            normal = offset(normal, monitor.rect.left - monitor.work.left, monitor.rect.top - monitor.work.top);
        }
    }
    let mut flags = 0;
    if pos.flags & WPF_RESTORETOMAXIMIZED != 0 || style & WS_MAXIMIZE != 0 {
        flags |= WPF_RESTORETOMAXIMIZED;
    }
    if style & (WS_CHILD | WS_POPUP) == WS_CHILD && pos.flags & WPF_SETMINPOSITION != 0 {
        flags |= WPF_SETMINPOSITION;
    }
    WindowPlacement32 {
        length: core::mem::size_of::<WindowPlacement32>() as u32,
        flags,
        show_cmd,
        min_position: [min.0, min.1],
        max_position: [max.0, max.1],
        normal_position: [normal.left, normal.top, normal.right, normal.bottom],
    }
}

/// Le rectangle de `window` dans la zone cliente de son parent (à l'écran
/// pour une fenêtre de premier niveau), et si elle est de premier niveau.
fn rect_in_parent(window: &Window) -> (Rect, bool) {
    let state = window.state();
    match window::get(state.parent).filter(|parent| !parent.is_desktop_window()) {
        Some(parent) => {
            let client = parent.state().client;
            (offset(state.window, -client.left, -client.top), false)
        }
        None => (state.window, true),
    }
}

/// WinPosInitInternalPos pour `window`, d'après sa place présente : rend
/// sa place gardée, et si elle est de premier niveau.
fn update_internal_pos(window: &Window) -> (InternalPos, bool) {
    let (rect, top_level) = rect_in_parent(window);
    let monitor = crate::monitor::from_rect(rect, abi::user::MONITOR_DEFAULTTOPRIMARY);
    let state = window::change(window, |state| {
        let to_monitor = state.state & WNDS_MAXIMIZESTOMONITOR != 0;
        init_internal_pos(&mut state.internal_pos, state.style, to_monitor, rect, top_level, monitor);
    });
    (state.internal_pos, top_level)
}

/// GetWindowPlacement : la place de `window` gardée à jour, puis
/// [`placement_of`], le moniteur pris de son rectangle normal (le principal
/// par défaut).
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn placement(window: &Window) -> WindowPlacement32 {
    let (pos, top_level) = update_internal_pos(window);
    let state = window.state();
    let to_monitor = state.state & WNDS_MAXIMIZESTOMONITOR != 0;
    let monitor = crate::monitor::from_rect(pos.normal, abi::user::MONITOR_DEFAULTTOPRIMARY);
    placement_of(state.style, state.ex_style, &pos, to_monitor, top_level, monitor)
}

/// make_rect_onscreen : `rect` ramené sur la zone de travail `work` quand
/// il en sort tout entier, par un côté ou par l'autre (sa taille gardée).
pub fn on_screen(rect: Rect, work: Rect) -> Rect {
    let mut rect = rect;
    if rect.right <= work.left {
        rect.right += work.left - rect.left;
        rect.left = work.left;
    } else if rect.left >= work.right {
        rect.left += work.right - rect.right;
        rect.right = work.right;
    }
    if rect.bottom <= work.top {
        rect.bottom += work.top - rect.top;
        rect.top = work.top;
    } else if rect.top >= work.bottom {
        rect.top += work.bottom - rect.bottom;
        rect.bottom = work.bottom;
    }
    rect
}

/// make_point_onscreen : le point `point` ramené sur la zone de travail
/// `work` ([`on_screen`] d'un pixel). Un point (−1, −1) reste « pas donné »
/// : ReactOS le ramène en (0, 0), et la fenêtre agrandie d'un programme qui
/// rend à SetWindowPlacement ce que GetWindowPlacement lui a donné (le
/// Bloc-notes) aurait alors son cadre sur l'écran, en haut à gauche.
pub fn point_on_screen(point: (i32, i32), work: Option<Rect>) -> (i32, i32) {
    match work {
        Some(work) if point != NO_PLACE => {
            let rect = on_screen(Rect::new(point.0, point.1, point.0 + 1, point.1 + 1), work);
            (rect.left, rect.top)
        }
        _ => point,
    }
}

/// IntSetWindowPlacement (PLACE_MAX | PLACE_RECT, et PLACE_MIN avec
/// `WPF_SETMINPOSITION`) : les places de `placement` ramenées sur la zone de
/// travail du moniteur le plus proche ([`on_screen`], [`point_on_screen`])
/// deviennent celles que `window` garde ; elle va à celle de son état
/// (réduite : sa place réduite si elle est donnée ; agrandie : sa place
/// agrandie si elle est donnée ; sinon son rectangle normal), sans changer
/// son rang ni l'activer, puis elle est montrée par la commande de
/// `placement` ([`show_window`]) ; réduite alors, elle garde
/// `WPF_SETMINPOSITION` et `WPF_RESTORETOMAXIMIZED` de `placement`. FALSE
/// pour la fenêtre du bureau. `WPF_ASYNCWINDOWPLACEMENT` : fait tout de
/// suite, journalisé une fois.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn set_placement(window: &Arc<Window>, placement: &WindowPlacement32) -> bool {
    if window.is_desktop_window() {
        return false;
    }
    let near =
        |rect: Rect| crate::monitor::from_rect(rect, abi::user::MONITOR_DEFAULTTONEAREST).map(|monitor| monitor.work);
    let place_min = placement.flags & WPF_SETMINPOSITION != 0;
    let point = |[x, y]: [i32; 2]| point_on_screen((x, y), near(Rect::new(x, y, x + 1, y + 1)));
    let min = point(placement.min_position);
    let max = point(placement.max_position);
    let [left, top, right, bottom] = placement.normal_position;
    let mut normal = Rect::new(left, top, right, bottom);
    if let Some(work) = near(normal) {
        normal = on_screen(normal, work);
    }
    // The place it has now first (WinPosInitInternalPos), then the given one;
    // a place given for its icon holds at once (ReactOS takes it once the
    // window is minimized, and WinPosFindIconPos ignores it).
    let (mut pos, _) = update_internal_pos(window);
    if place_min {
        pos.icon = min;
        pos.flags |= WPF_SETMINPOSITION | WPF_MININIT;
    }
    pos.max = max;
    pos.normal = normal;
    let state = window::change(window, |state| state.internal_pos = pos);

    let mut flags = SWP_NOZORDER | SWP_NOACTIVATE;
    if placement.flags & WPF_ASYNCWINDOWPLACEMENT != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: SetWindowPlacement: WPF_ASYNCWINDOWPLACEMENT (done at once): not yet");
        }
        flags |= SWP_ASYNCWINDOWPOS;
    }
    if state.style & WS_MINIMIZE != 0 {
        if (place_min || pos.flags & WPF_SETMINPOSITION != 0) && pos.icon != NO_PLACE {
            set_window_pos(window, HWND_TOP, pos.icon.0, pos.icon.1, 0, 0, SWP_NOSIZE | flags);
            window::change(window, |state| state.internal_pos.flags |= WPF_MININIT);
        }
    } else if state.style & WS_MAXIMIZE != 0 {
        if max != NO_PLACE {
            set_window_pos(window, HWND_TOP, max.0, max.1, 0, 0, SWP_NOSIZE | flags);
            window::change(window, |state| state.internal_pos.flags |= WPF_MAXINIT);
        }
    } else {
        let (cx, cy) = (normal.right - normal.left, normal.bottom - normal.top);
        set_window_pos(window, HWND_TOP, normal.left, normal.top, cx, cy, flags);
    }
    show_window(window, placement.show_cmd);
    if window.state().style & WS_MINIMIZE != 0 {
        let kept = placement.flags & (WPF_SETMINPOSITION | WPF_RESTORETOMAXIMIZED);
        window::change(window, |state| state.internal_pos.flags |= kept);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::{WS_MAXIMIZEBOX, WS_THICKFRAME};

    fn metric(index: usize) -> i32 {
        crate::metrics::system_metrics(1280, 800, &crate::metrics::Parameters::DEFAULT)[index]
    }

    fn situation() -> Situation {
        Situation {
            style: WS_POPUP | WS_VISIBLE,
            window: Rect::new(10, 20, 110, 70),
            parent_visible: true,
            ..Situation::default()
        }
    }

    fn pos(x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> WindowPos32 {
        WindowPos32 { hwnd: 0x10, insert_after: HWND_TOP, x, y, cx, cy, flags }
    }

    const NOTHING: fn(u32) -> InsertAfter = |_| InsertAfter::Missing;

    #[test]
    fn what_does_not_change_is_flagged() {
        let mut same = pos(10, 20, 100, 50, SWP_NOZORDER | SWP_NOACTIVATE);
        assert!(fixup_flags(&mut same, &situation(), NOTHING));
        assert_eq!(same.flags & (SWP_NOSIZE | SWP_NOMOVE), SWP_NOSIZE | SWP_NOMOVE, "same place, same size");
        let mut moved = pos(11, 20, 100, 51, SWP_NOZORDER | SWP_NOACTIVATE);
        fixup_flags(&mut moved, &situation(), NOTHING);
        assert_eq!(moved.flags & (SWP_NOSIZE | SWP_NOMOVE), 0);
        let child = Situation { parent_origin: (5, 5), ..situation() };
        let mut inside = pos(5, 15, 1, 1, SWP_NOZORDER | SWP_NOACTIVATE);
        fixup_flags(&mut inside, &child, NOTHING);
        assert_ne!(inside.flags & SWP_NOMOVE, 0, "in its parent's client area");
        let mut far = pos(100_000, -100_000, -5, 3, SWP_NOZORDER | SWP_NOACTIVATE);
        fixup_flags(&mut far, &situation(), NOTHING);
        assert_eq!((far.x, far.y, far.cx, far.cy), (32767, -32768, 0, 3), "16-bit places, sizes not negative");
    }

    #[test]
    fn showing_and_hiding_follow_the_visibility() {
        let mut show = pos(0, 0, 0, 0, SWP_SHOWWINDOW | SWP_NOZORDER | SWP_NOACTIVATE);
        fixup_flags(&mut show, &situation(), NOTHING);
        assert_eq!(show.flags & SWP_SHOWWINDOW, 0, "already visible");
        let hidden = Situation { style: WS_POPUP, ..situation() };
        let mut stay = pos(0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOZORDER | SWP_NOACTIVATE);
        fixup_flags(&mut stay, &hidden, NOTHING);
        assert_eq!(stay.flags & (SWP_HIDEWINDOW | SWP_NOREDRAW), SWP_NOREDRAW, "hidden: nothing to draw");
        let mut shown = pos(0, 0, 0, 0, SWP_SHOWWINDOW | SWP_NOZORDER | SWP_NOACTIVATE);
        fixup_flags(&mut shown, &hidden, NOTHING);
        assert_eq!(shown.flags & (SWP_SHOWWINDOW | SWP_NOREDRAW), SWP_SHOWWINDOW);
        let under_hidden = Situation { parent_visible: false, ..situation() };
        let mut still = pos(10, 20, 100, 50, SWP_NOZORDER | SWP_NOACTIVATE);
        still.flags |= SWP_NOSIZE | SWP_NOMOVE | SWP_AGG_NOCLIENTCHANGE;
        fixup_flags(&mut still, &under_hidden, NOTHING);
        assert_ne!(still.flags & SWP_NOREDRAW, 0, "a hidden parent, nothing moves");
    }

    #[test]
    fn activating_brings_a_top_level_window_to_the_top() {
        let mut activated = pos(0, 0, 0, 0, SWP_NOZORDER);
        fixup_flags(&mut activated, &situation(), NOTHING);
        assert_eq!((activated.flags & SWP_NOZORDER, activated.insert_after), (0, HWND_TOP));
        let topmost = Situation { ex_style: WS_EX_TOPMOST, ..situation() };
        let mut above = pos(0, 0, 0, 0, SWP_NOZORDER);
        fixup_flags(&mut above, &topmost, NOTHING);
        assert_eq!(above.insert_after, HWND_TOPMOST);
        let child = Situation { style: WS_CHILD, ..situation() };
        let mut not_a_child = pos(0, 0, 0, 0, SWP_NOZORDER);
        fixup_flags(&mut not_a_child, &child, NOTHING);
        assert_ne!(not_a_child.flags & SWP_NOZORDER, 0, "a child is not");
        let foreground = Situation { foreground: true, ..situation() };
        let mut already = pos(0, 0, 0, 0, SWP_NOZORDER);
        fixup_flags(&mut already, &foreground, NOTHING);
        assert_ne!(already.flags & SWP_NOZORDER, 0, "nor the foreground window");
    }

    #[test]
    fn a_place_already_held_is_no_z_order_change() {
        let first = Situation { first: true, ..situation() };
        let mut top = pos(0, 0, 0, 0, SWP_NOACTIVATE);
        fixup_flags(&mut top, &first, NOTHING);
        assert_ne!(top.flags & SWP_NOZORDER, 0, "already first");
        let last = Situation { last: true, ..situation() };
        let mut bottom = WindowPos32 { insert_after: HWND_BOTTOM, ..pos(0, 0, 0, 0, SWP_NOACTIVATE) };
        fixup_flags(&mut bottom, &last, NOTHING);
        assert_ne!(bottom.flags & SWP_NOZORDER, 0, "already last");
        let mut not_topmost = WindowPos32 { insert_after: 0xFFFE, ..pos(0, 0, 0, 0, SWP_NOACTIVATE) };
        fixup_flags(&mut not_topmost, &situation(), NOTHING);
        assert_eq!((not_topmost.insert_after, not_topmost.flags & SWP_NOZORDER), (HWND_NOTOPMOST, SWP_NOZORDER));
        let mut behind = WindowPos32 { insert_after: 0x20, ..pos(0, 0, 0, 0, SWP_NOACTIVATE) };
        fixup_flags(&mut behind, &situation(), |_| InsertAfter::Sibling { followed_by_window: true });
        assert_ne!(behind.flags & SWP_NOZORDER, 0, "already after it");
        let mut moving = WindowPos32 { insert_after: 0x20, ..pos(0, 0, 0, 0, SWP_NOACTIVATE) };
        fixup_flags(&mut moving, &situation(), |_| InsertAfter::Sibling { followed_by_window: false });
        assert_eq!(moving.flags & SWP_NOZORDER, 0);
        let mut stranger = WindowPos32 { insert_after: 0x20, ..pos(0, 0, 0, 0, SWP_NOACTIVATE) };
        assert!(!fixup_flags(&mut stranger, &situation(), |_| InsertAfter::Stranger), "nothing is done");
    }

    #[test]
    fn new_rectangles_move_and_size() {
        let (window, client) = (Rect::new(10, 20, 110, 70), Rect::new(14, 44, 106, 66));
        let both = pos(50, 60, 200, 100, 0);
        assert_eq!(
            new_rects(window, client, false, &both, (0, 0), &metric),
            (Rect::new(50, 60, 250, 160), Rect::new(54, 84, 146, 106)),
            "the client area follows the window, its size waits for WM_NCCALCSIZE"
        );
        let in_parent = pos(5, 5, 0, 0, SWP_NOSIZE);
        assert_eq!(new_rects(window, client, false, &in_parent, (100, 200), &metric).0, Rect::new(105, 205, 205, 255));
        let minimized = new_rects(window, client, true, &pos(0, 0, 500, 500, SWP_NOMOVE), (0, 0), &metric);
        assert_eq!(minimized, (Rect::new(10, 20, 176, 45), window), "an icon's size; its client area is the window");
    }

    #[test]
    fn show_commands_become_set_window_pos_flags() {
        use ShowCommand::{Done, Place};
        let shown = SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
        assert_eq!(show_command(SW_SHOWNORMAL, WS_POPUP, 0, false), Place(shown), "activated, brought up");
        assert_eq!(show_command(SW_SHOWNORMAL, WS_POPUP, 0, true), Done(true), "already visible");
        assert_eq!(show_command(SW_SHOW, WS_POPUP, 0, false), Place(shown));
        assert_eq!(show_command(SW_SHOW, WS_POPUP, 0, true), Done(true));
        let child = shown | SWP_NOACTIVATE | SWP_NOZORDER;
        assert_eq!(show_command(SW_SHOW, WS_CHILD, 0, false), Place(child), "a child is not activated");
        assert_eq!(show_command(SW_SHOW, WS_CHILD, WS_EX_MDICHILD, false), Place(shown), "an MDI child is");
        assert_eq!(show_command(SW_SHOWNOACTIVATE, WS_POPUP, 0, false), Place(child));
        assert_eq!(show_command(SW_RESTORE, WS_POPUP, 0, false), Place(shown));
        let na = SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
        assert_eq!(show_command(SW_SHOWNA, WS_POPUP, 0, true), Place(na), "even visible");
        assert_eq!(show_command(SW_SHOWNA, WS_CHILD, 0, true), Place(na | SWP_NOZORDER));
        let hide = SWP_HIDEWINDOW | SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER;
        assert_eq!(show_command(SW_HIDE, WS_POPUP, 0, true), Place(hide), "not active: it keeps its rank");
        assert_eq!(show_command(SW_HIDE, WS_POPUP, 0, false), Done(false), "already hidden");
        assert_eq!(show_command(12, WS_POPUP, 0, false), Done(false), "beyond SW_MAX");
    }

    #[test]
    fn minimizing_and_maximizing_go_through_min_maximize() {
        use ShowCommand::{Done, MinMax, Place};
        let quiet = SWP_SHOWWINDOW | SWP_NOACTIVATE;
        assert_eq!(show_command(SW_MINIMIZE, WS_POPUP, 0, true), MinMax { cmd: SW_MINIMIZE, swp: quiet });
        assert_eq!(show_command(SW_SHOWMINIMIZED, WS_POPUP, 0, false), MinMax { cmd: SW_SHOWMINIMIZED, swp: quiet });
        let no_rank = quiet | SWP_NOZORDER;
        assert_eq!(
            show_command(SW_SHOWMINNOACTIVE, WS_POPUP, 0, true),
            MinMax { cmd: SW_SHOWMINNOACTIVE, swp: no_rank },
            "nor its rank"
        );
        assert_eq!(
            show_command(SW_FORCEMINIMIZE, WS_POPUP, 0, true),
            MinMax { cmd: SW_MINIMIZE, swp: quiet },
            "as SW_MINIMIZE"
        );
        assert_eq!(show_command(SW_MINIMIZE, WS_POPUP | WS_MINIMIZE, 0, true), Done(true), "already minimized");
        assert_eq!(
            show_command(SW_SHOWMINIMIZED, WS_POPUP | WS_MINIMIZE, 0, false),
            Place(quiet | SWP_NOSIZE | SWP_NOMOVE),
            "minimized, hidden: shown where it is"
        );
        let shown = SWP_SHOWWINDOW;
        assert_eq!(show_command(SW_SHOWMAXIMIZED, WS_POPUP, 0, true), MinMax { cmd: SW_MAXIMIZE, swp: shown });
        assert_eq!(show_command(SW_SHOWMAXIMIZED, WS_POPUP | WS_MAXIMIZE, 0, true), Done(true));
        assert_eq!(
            show_command(SW_SHOWMAXIMIZED, WS_POPUP | WS_MINIMIZE, 0, true),
            MinMax { cmd: SW_MAXIMIZE, swp: shown },
            "from minimized"
        );
        assert_eq!(show_command(SW_RESTORE, WS_POPUP | WS_MAXIMIZE, 0, true), MinMax { cmd: SW_RESTORE, swp: 0 });
        assert_eq!(
            show_command(SW_SHOWNORMAL, WS_POPUP | WS_MINIMIZE, 0, false),
            MinMax { cmd: SW_SHOWNORMAL, swp: SWP_SHOWWINDOW },
            "restoring"
        );
        let no_activate = SWP_NOACTIVATE | SWP_NOZORDER;
        assert_eq!(
            show_command(SW_SHOWNOACTIVATE, WS_POPUP | WS_MINIMIZE, 0, true),
            MinMax { cmd: SW_SHOWNOACTIVATE, swp: no_activate }
        );
        assert!(is_minimize_command(SW_SHOWMINNOACTIVE) && !is_minimize_command(SW_RESTORE));
        assert_eq!(child_flags(SW_MINIMIZE, WS_CHILD, 0), SWP_NOACTIVATE | SWP_NOZORDER, "a child");
        assert_eq!(child_flags(SW_SHOWNA, WS_CHILD, 0), 0, "but by SW_SHOWNA");
        assert_eq!(child_flags(SW_MINIMIZE, WS_CHILD, WS_EX_MDICHILD), 0, "an MDI child");
        assert_eq!(child_flags(SW_MINIMIZE, WS_POPUP, 0), 0);
    }

    #[test]
    fn the_startup_info_shows_the_first_overlapped_window_once() {
        let given = |show: u32| StartupPlace {
            flags: STARTF_USESHOWWINDOW | STARTF_USEPOSITION,
            show,
            ..StartupPlace::default()
        };
        let mut startup = given(SW_SHOWMINNOACTIVE);
        let overlapped = WS_CAPTION | WS_THICKFRAME;
        assert_eq!(startup_command(SW_SHOWNORMAL, overlapped, false, &mut startup), SW_SHOWMINNOACTIVE);
        assert_eq!(startup.flags, 0, "once");
        assert_eq!(startup_command(SW_SHOWNORMAL, overlapped, false, &mut startup), SW_SHOWNORMAL, "then no more");
        let mut kept = given(SW_HIDE);
        assert_eq!(
            startup_command(SW_SHOWNA, overlapped, false, &mut kept),
            SW_SHOWNA,
            "only SW_SHOW and SW_SHOWNORMAL"
        );
        assert_eq!(kept.flags, 0, "but it is used up");
        for (style, owned) in [(WS_POPUP, false), (overlapped, true), (WS_CHILD | WS_CAPTION, false)] {
            let mut other = given(SW_HIDE);
            assert_eq!(startup_command(SW_SHOW, style, owned, &mut other), SW_SHOW, "{style:#x} {owned}");
            assert_ne!(other.flags, 0, "kept for the first overlapped window");
        }
        let mut default = given(SW_SHOWMAXIMIZED);
        assert_eq!(startup_command(SW_SHOWDEFAULT, WS_POPUP, false, &mut default), SW_SHOWMAXIMIZED, "SW_SHOWDEFAULT");
        let mut none = StartupPlace::default();
        assert_eq!(startup_command(SW_SHOWDEFAULT, overlapped, false, &mut none), SW_SHOWDEFAULT, "no STARTUPINFO");
    }

    fn monitor() -> crate::monitor::Monitor {
        crate::monitor::Monitor { handle: 1, rect: Rect::new(0, 0, 1024, 768), work: Rect::new(0, 30, 1024, 768) }
    }

    /// The place kept of a window of style `style` at `rect`, seen once.
    fn kept(style: u32, rect: Rect, top_level: bool) -> InternalPos {
        let mut pos = InternalPos::default();
        init_internal_pos(&mut pos, style, false, rect, top_level, Some(monitor()));
        pos
    }

    #[test]
    fn the_placement_says_how_the_window_is_shown_and_where() {
        let rect = Rect::new(100, 130, 500, 430);
        let pos = kept(WS_VISIBLE, rect, true);
        let normal = placement_of(WS_VISIBLE, 0, &pos, false, true, Some(monitor()));
        assert_eq!((normal.length, normal.flags, normal.show_cmd), (44, 0, SW_SHOWNORMAL));
        assert_eq!((normal.min_position, normal.max_position), ([-1, -1], [-1, -1]), "never placed");
        assert_eq!(normal.normal_position, [100, 100, 500, 400], "in the work area");
        let tool = placement_of(WS_VISIBLE, WS_EX_TOOLWINDOW, &pos, false, true, Some(monitor()));
        assert_eq!(tool.normal_position, [100, 130, 500, 430], "a tool window: on the screen");
        let child = placement_of(WS_CHILD, 0, &kept(WS_CHILD, rect, false), false, false, Some(monitor()));
        assert_eq!(child.normal_position, [100, 130, 500, 430], "a child: in its parent");
    }

    #[test]
    fn a_minimized_or_maximized_window_keeps_its_normal_rectangle() {
        let normal_rect = Rect::new(100, 130, 500, 430);
        let mut pos = kept(WS_VISIBLE, normal_rect, true);
        // Maximized: its place from the work area, its normal rectangle kept.
        let maximized = Rect::new(-4, 26, 1028, 772);
        let style = WS_MAXIMIZE | WS_CAPTION | WS_MAXIMIZEBOX;
        init_internal_pos(&mut pos, style, false, maximized, true, Some(monitor()));
        assert_eq!((pos.normal, pos.max, pos.flags), (normal_rect, (-4, -4), WPF_MAXINIT));
        let shown = placement_of(style, 0, &pos, false, true, Some(monitor()));
        assert_eq!((shown.show_cmd, shown.flags), (SW_SHOWMAXIMIZED, WPF_RESTORETOMAXIMIZED));
        assert_eq!((shown.max_position, shown.normal_position), ([-4, -4], [100, 100, 500, 400]));
        let covering = placement_of(style, 0, &pos, true, true, Some(monitor()));
        assert_eq!(covering.max_position, [-1, -1], "covering its monitor: no place");
        let mut popup = kept(WS_VISIBLE, normal_rect, true);
        init_internal_pos(&mut popup, WS_MAXIMIZE | WS_POPUP, false, maximized, true, Some(monitor()));
        assert_eq!(popup.max, (-4, 26), "a popup without a caption: from the monitor");
        let mut covers = kept(WS_VISIBLE, normal_rect, true);
        init_internal_pos(&mut covers, style, true, maximized, true, Some(monitor()));
        assert_eq!((covers.max, covers.flags & WPF_MAXINIT), (NO_PLACE, 0));
        let mut child = kept(WS_CHILD, normal_rect, false);
        init_internal_pos(&mut child, WS_CHILD | WS_MAXIMIZE, false, Rect::new(-2, -2, 50, 50), false, None);
        assert_eq!(child.max, (-2, -2), "a child: in its parent");

        // Minimized: the icon's place, from the work area for the caller.
        init_internal_pos(&mut pos, WS_MINIMIZE, false, Rect::new(1, 742, 167, 767), true, Some(monitor()));
        assert_eq!((pos.icon, pos.normal), ((1, 742), normal_rect));
        let pos = InternalPos { flags: pos.flags | WPF_RESTORETOMAXIMIZED, ..pos };
        let shown = placement_of(WS_MINIMIZE, 0, &pos, false, true, Some(monitor()));
        assert_eq!(shown.show_cmd, SW_SHOWMINIMIZED);
        assert_eq!((shown.min_position, shown.flags), ([1, 712], WPF_RESTORETOMAXIMIZED), "it comes back maximized");
        let both = placement_of(WS_MINIMIZE | WS_MAXIMIZE, 0, &pos, false, true, Some(monitor()));
        assert_eq!(both.show_cmd, SW_SHOWMINIMIZED, "minimized comes first");
        let set = InternalPos { flags: WPF_SETMINPOSITION, ..InternalPos::default() };
        assert_eq!(placement_of(WS_CHILD, 0, &set, false, false, None).flags, WPF_SETMINPOSITION, "a child's");
        assert_eq!(placement_of(WS_POPUP, 0, &set, false, true, None).flags, 0);
    }

    #[test]
    fn the_first_look_takes_the_normal_rectangle_once() {
        let rect = Rect::new(10, 20, 110, 70);
        let mut pos = InternalPos::default();
        assert_eq!((pos.icon, pos.max, pos.initialized), (NO_PLACE, NO_PLACE, false));
        init_internal_pos(&mut pos, WS_MAXIMIZE | WS_POPUP, false, rect, true, None);
        assert_eq!((pos.normal, pos.initialized), (rect, true), "the place it has, even maximized");
        init_internal_pos(&mut pos, WS_MAXIMIZE | WS_POPUP, false, Rect::new(0, 0, 5, 5), true, None);
        assert_eq!(pos.normal, rect, "then kept");
    }

    #[test]
    fn minimized_windows_take_the_first_free_place() {
        let area = Rect::new(0, 0, 1280, 800);
        let (size, border) = ((166, 25), (1, 1));
        assert_eq!(icon_slot(0, area, &[], size, border), (1, 774), "the bottom left corner");
        assert_eq!(icon_slot(0, area, &[(1, 774)], size, border), (167, 774), "then to its right");
        assert_eq!(icon_slot(0, area, &[(167, 774)], size, border), (1, 774), "a free place before");
        let row: Vec<(i32, i32)> = (0..7).map(|column| (1 + 166 * column, 774)).collect();
        assert_eq!(icon_slot(0, area, &row, size, border), (1, 749), "a row of whole icons, then above");
        assert_eq!(icon_slot(ARW_BOTTOMRIGHT, area, &[], size, border), (1113, 774));
        assert_eq!(icon_slot(ARW_TOPLEFT, area, &[(1, 1)], size, border), (167, 1));
        assert_eq!(icon_slot(ARW_TOPRIGHT | ARW_UP, area, &[(1113, 1)], size, border), (1113, 26), "down");
        assert_eq!(icon_slot(ARW_UP, area, &[(1, 774)], size, border), (1, 749), "up");
        let tiny = Rect::new(0, 0, 100, 10);
        assert_eq!(icon_slot(0, tiny, &[(1, -16)], size, border), (1, -16), "all taken: the first");
    }

    #[test]
    fn a_point_out_of_the_work_area_is_brought_back_but_not_none() {
        let work = Some(Rect::new(0, 0, 800, 600));
        assert_eq!(point_on_screen((-50, 20), work), (0, 20));
        assert_eq!(point_on_screen((900, 700), work), (799, 599));
        assert_eq!(point_on_screen((10, 20), work), (10, 20));
        assert_eq!(point_on_screen(NO_PLACE, work), NO_PLACE, "not given: kept");
        assert_eq!(point_on_screen((-50, 20), None), (-50, 20), "no monitor");
    }

    #[test]
    fn a_rect_out_of_the_work_area_is_brought_back() {
        let work = Rect::new(0, 0, 800, 600);
        assert_eq!(on_screen(Rect::new(10, 20, 110, 70), work), Rect::new(10, 20, 110, 70), "inside: kept");
        assert_eq!(on_screen(Rect::new(-300, 20, -200, 70), work), Rect::new(0, 20, 100, 70), "left");
        assert_eq!(on_screen(Rect::new(900, 20, 1000, 70), work), Rect::new(700, 20, 800, 70), "right");
        assert_eq!(on_screen(Rect::new(10, -90, 110, -40), work), Rect::new(10, 0, 110, 50), "above");
        assert_eq!(on_screen(Rect::new(10, 700, 110, 750), work), Rect::new(10, 550, 110, 600), "below");
        assert_eq!(on_screen(Rect::new(-50, 20, 50, 70), work), Rect::new(-50, 20, 50, 70), "partly in: kept");
    }

    #[test]
    fn a_placement_reads_back_from_its_bytes() {
        let placement = WindowPlacement32 {
            length: 44,
            flags: WPF_RESTORETOMAXIMIZED,
            show_cmd: SW_SHOWMAXIMIZED,
            min_position: [-1, -2],
            max_position: [3, 4],
            normal_position: [5, -6, 7, 8],
        };
        let bytes = placement.as_bytes();
        assert_eq!(&bytes[28..32], &5i32.to_le_bytes(), "rcNormalPosition at 28");
        assert_eq!(WindowPlacement32::from_bytes(&bytes), placement);
    }
}
