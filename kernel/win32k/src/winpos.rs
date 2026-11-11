//! Le positionnement des fenêtres : SetWindowPos ([`set_window_pos`]) et
//! ShowWindow ([`show_window`]).
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
//! WM_SIZE).
//!
//! Le `WINDOWPOS` de WM_WINDOWPOSCHANGED donne la place de la fenêtre dans
//! la zone cliente de son parent, comme le dit l'API ; ReactOS y met ses
//! coordonnées d'écran (les mêmes pour une fenêtre de premier niveau).
//!
//! ShowWindow, comme co_WinPosShowWindow : la commande du `STARTUPINFO` du
//! processus pour sa première fenêtre recouvrante (`STARTF_USESHOWWINDOW`,
//! une fois), les drapeaux de SetWindowPos de la commande
//! ([`show_command`]), WM_SHOWWINDOW, SetWindowPos (si ses parents sont
//! visibles, sinon `WS_VISIBLE` seul), puis WM_SIZE et WM_MOVE qui
//! attendaient qu'elle soit montrée (`WNDS_SENDSIZEMOVEMSGS`).
//!
//! Une fenêtre de premier niveau activée passe au premier plan
//! ([`crate::input::activate`]) : sa file reçoit le clavier.
//!
//! Après le déplacement ([`crate::paint`]) : une fenêtre visible est
//! invalidée entière, ce qu'elle découvre est exposé (le bureau s'y
//! repeint), et une fenêtre montrée, déplacée ou redimensionnée repeint
//! aussitôt son cadre (WM_NCPAINT), avant WM_WINDOWPOSCHANGED.
//!
//! GetWindowPlacement et SetWindowPlacement ([`placement`],
//! [`set_placement`]), comme IntGetWindowPlacement et IntSetWindowPlacement
//! : le rectangle « normal » est le rectangle de la fenêtre dans la zone
//! cliente de son parent, en coordonnées de la zone de travail pour une
//! fenêtre de premier niveau ; SetWindowPlacement ramène ce rectangle sur
//! la zone de travail (make_rect_onscreen), y place la fenêtre, puis la
//! montre par ShowWindow. Sans réduire ni agrandir, il n'y a pas de place
//! gardée à part (`InternalPos` de ReactOS : rectangle normal d'une
//! fenêtre réduite ou agrandie, places de l'icône et de la fenêtre
//! agrandie) : les points rendus valent (−1, −1), et une fenêtre réduite
//! ou agrandie n'est pas déplacée (journalisé une fois).
//!
//! Pas encore, journalisé une fois : réduire et agrandir (les commandes qui
//! le demandent, ou montrer une fenêtre réduite ou agrandie, ne font rien et
//! rendent FALSE) ; la copie des bits valides (tout est repeint), garder
//! les fenêtres possédées au-dessus
//! de leur propriétaire (WinPosDoOwnedPopups), `SWP_ASYNCWINDOWPOS` (fait
//! tout de suite), les messages à la fenêtre d'un autre thread.

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
use abi::user::{WindowPlacement32, WPF_ASYNCWINDOWPLACEMENT, WPF_RESTORETOMAXIMIZED, WS_EX_TOOLWINDOW};
use abi::user::{
    STARTF_USEPOSITION, STARTF_USESHOWWINDOW, STARTF_USESIZE, SW_FORCEMINIMIZE, SW_HIDE, SW_MINIMIZE, SW_RESTORE,
    SW_SHOW, SW_SHOWDEFAULT, SW_SHOWMAXIMIZED, SW_SHOWMINIMIZED, SW_SHOWMINNOACTIVE, SW_SHOWNA, SW_SHOWNOACTIVATE,
    SW_SHOWNORMAL, WM_SHOWWINDOW, WNDS_SENDSIZEMOVEMSGS, WS_CAPTION, WS_EX_MDICHILD, WS_MAXIMIZE,
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
    /// Réduire, agrandir ou rétablir (co_WinPosMinMaximize).
    MinMax,
}

/// co_WinPosShowWindow, son `switch` : ce que fait la commande `cmd` à une
/// fenêtre de style `style` et de style étendu `ex_style`, visible ou non
/// (`was_visible`). Une fenêtre fille (hors MDI) ne prend ni l'activation
/// ni le haut de l'ordre Z ; aucune fenêtre n'est active, une fenêtre
/// cachée garde donc son rang (`SWP_NOACTIVATE | SWP_NOZORDER`). ReactOS
/// le vérifie de nouveau après WM_SHOWWINDOW, pour un style que la
/// procédure aurait changé : pas encore.
pub fn show_command(cmd: u32, style: u32, ex_style: u32, was_visible: bool) -> ShowCommand {
    let child = style & WS_CHILD != 0 && ex_style & WS_EX_MDICHILD == 0;
    let mut swp = 0;
    match cmd {
        SW_HIDE => {
            if !was_visible {
                return ShowCommand::Done(false);
            }
            swp |= SWP_HIDEWINDOW | SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER;
        }
        SW_FORCEMINIMIZE | SW_SHOWMINNOACTIVE | SW_SHOWMINIMIZED | SW_MINIMIZE | SW_SHOWMAXIMIZED => {
            return ShowCommand::MinMax;
        }
        SW_SHOWNA => {
            swp |= SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
            if child {
                swp |= SWP_NOZORDER;
            }
        }
        SW_SHOW => {
            if was_visible {
                return ShowCommand::Done(true);
            }
            swp |= SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
            if child {
                swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            }
        }
        SW_SHOWNOACTIVATE | SW_SHOWNORMAL | SW_SHOWDEFAULT | SW_RESTORE => {
            if cmd == SW_SHOWNOACTIVATE {
                swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            }
            if !was_visible {
                swp |= SWP_SHOWWINDOW;
            }
            if style & (WS_MINIMIZE | WS_MAXIMIZE) != 0 {
                return ShowCommand::MinMax;
            }
            if was_visible {
                return ShowCommand::Done(true);
            }
            swp |= SWP_NOSIZE | SWP_NOMOVE;
            if child {
                swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            }
        }
        _ => return ShowCommand::Done(false),
    }
    ShowCommand::Place(swp)
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

/// co_WinPosShowWindow : montre ou cache `window` selon `cmd` (`SW_*`) ;
/// rend si elle était visible.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn show_window(window: &Arc<Window>, cmd: u32) -> bool {
    let state = window.state();
    let was_visible = state.style & WS_VISIBLE != 0;
    let cmd = process_startup_command(window, cmd);
    let swp = match show_command(cmd, state.style, state.ex_style, was_visible) {
        ShowCommand::Done(result) => return result,
        ShowCommand::MinMax => {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("win32k: ShowWindow: minimizing and maximizing (co_WinPosMinMaximize): not yet");
            }
            return false;
        }
        ShowCommand::Place(swp) => swp,
    };
    let show = cmd != SW_HIDE;
    if show != was_visible || cmd == SW_SHOWNA {
        let _ = window::send_message(window, WM_SHOWWINDOW, u32::from(show), LParam::Value(0));
    }
    let state = window.state();
    if is_child_visible(window) {
        let after = if state.ex_style & WS_EX_TOPMOST != 0 { HWND_TOPMOST } else { HWND_TOP };
        set_window_pos(window, after, 0, 0, 0, 0, swp & 0xFFFF);
    } else {
        // Under a hidden parent: WS_VISIBLE alone.
        window::change(window, |state| {
            state.style = if show { state.style | WS_VISIBLE } else { state.style & !WS_VISIBLE };
        });
    }
    if cmd == SW_HIDE {
        return was_visible;
    }
    if window.state().state & WNDS_SENDSIZEMOVEMSGS != 0 {
        window::send_size_move(window);
    }
    was_visible
}

/// IntGetWindowPlacement, d'une fenêtre de style `style` et de style
/// étendu `ex_style`, de rectangle `normal` dans la zone cliente de son
/// parent : la commande qui la montre telle qu'elle est (réduite, agrandie
/// ou normale), ses points de fenêtre réduite et agrandie (−1, −1 : jamais
/// placés) et son rectangle normal. Pour une fenêtre de premier niveau
/// (`top_level`) qui n'est pas une fenêtre d'outils, le rectangle est
/// donné dans la zone de travail de son moniteur (`monitor`).
pub fn placement_of(
    style: u32,
    ex_style: u32,
    normal: Rect,
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
    let mut normal = normal;
    if top_level && ex_style & WS_EX_TOOLWINDOW == 0 {
        if let Some(monitor) = monitor {
            normal = offset(normal, monitor.rect.left - monitor.work.left, monitor.rect.top - monitor.work.top);
        }
    }
    WindowPlacement32 {
        length: core::mem::size_of::<WindowPlacement32>() as u32,
        flags: if style & WS_MAXIMIZE != 0 { WPF_RESTORETOMAXIMIZED } else { 0 },
        show_cmd,
        min_position: [-1, -1],
        max_position: [-1, -1],
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

/// GetWindowPlacement : [`placement_of`] pour `window`, le moniteur pris de
/// son rectangle (le principal par défaut).
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn placement(window: &Window) -> WindowPlacement32 {
    let (normal, top_level) = rect_in_parent(window);
    let state = window.state();
    let monitor = crate::monitor::from_rect(normal, abi::user::MONITOR_DEFAULTTOPRIMARY);
    placement_of(state.style, state.ex_style, normal, top_level, monitor)
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

/// IntSetWindowPlacement : `window` placée sur le rectangle normal de
/// `placement` (ramené sur la zone de travail du moniteur le plus proche),
/// sans changer son rang ni l'activer, puis montrée par la commande de
/// `placement` ([`show_window`]). FALSE pour la fenêtre du bureau.
/// `WPF_ASYNCWINDOWPLACEMENT` : fait tout de suite, journalisé une fois.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn set_placement(window: &Arc<Window>, placement: &WindowPlacement32) -> bool {
    if window.is_desktop_window() {
        return false;
    }
    let [left, top, right, bottom] = placement.normal_position;
    let mut normal = Rect::new(left, top, right, bottom);
    if let Some(monitor) = crate::monitor::from_rect(normal, abi::user::MONITOR_DEFAULTTONEAREST) {
        normal = on_screen(normal, monitor.work);
    }
    let mut flags = SWP_NOZORDER | SWP_NOACTIVATE;
    if placement.flags & WPF_ASYNCWINDOWPLACEMENT != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: SetWindowPlacement: WPF_ASYNCWINDOWPLACEMENT (done at once): not yet");
        }
        flags |= SWP_ASYNCWINDOWPOS;
    }
    if window.state().style & (WS_MINIMIZE | WS_MAXIMIZE) != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: SetWindowPlacement of a minimized or maximized window (InternalPos): not yet");
        }
    } else {
        let (cx, cy) = (normal.right - normal.left, normal.bottom - normal.top);
        set_window_pos(window, HWND_TOP, normal.left, normal.top, cx, cy, flags);
    }
    show_window(window, placement.show_cmd);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::WS_THICKFRAME;

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
        use ShowCommand::{Done, MinMax, Place};
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
        assert_eq!(show_command(SW_MINIMIZE, WS_POPUP, 0, false), MinMax);
        assert_eq!(show_command(SW_SHOWMAXIMIZED, WS_POPUP, 0, true), MinMax);
        assert_eq!(show_command(SW_SHOWNORMAL, WS_POPUP | WS_MAXIMIZE, 0, true), MinMax, "restoring");
        assert_eq!(show_command(12, WS_POPUP, 0, false), Done(false), "beyond SW_MAX");
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

    #[test]
    fn the_placement_says_how_the_window_is_shown_and_where() {
        let monitor =
            crate::monitor::Monitor { handle: 1, rect: Rect::new(0, 0, 1024, 768), work: Rect::new(0, 30, 1024, 768) };
        let rect = Rect::new(100, 130, 500, 430);
        let normal = placement_of(WS_VISIBLE, 0, rect, true, Some(monitor));
        assert_eq!((normal.length, normal.flags, normal.show_cmd), (44, 0, SW_SHOWNORMAL));
        assert_eq!((normal.min_position, normal.max_position), ([-1, -1], [-1, -1]), "never placed");
        assert_eq!(normal.normal_position, [100, 100, 500, 400], "in the work area");
        let tool = placement_of(WS_VISIBLE, WS_EX_TOOLWINDOW, rect, true, Some(monitor));
        assert_eq!(tool.normal_position, [100, 130, 500, 430], "a tool window: on the screen");
        let child = placement_of(WS_CHILD, 0, rect, false, Some(monitor));
        assert_eq!(child.normal_position, [100, 130, 500, 430], "a child: in its parent");
        let maximized = placement_of(WS_MAXIMIZE, 0, rect, true, Some(monitor));
        assert_eq!((maximized.show_cmd, maximized.flags), (SW_SHOWMAXIMIZED, WPF_RESTORETOMAXIMIZED));
        let minimized = placement_of(WS_MINIMIZE | WS_MAXIMIZE, 0, rect, true, Some(monitor));
        assert_eq!(minimized.show_cmd, SW_SHOWMINIMIZED, "minimized comes first");
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
