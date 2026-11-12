//! Les menus déroulants (`menu.c` de win32k, ReactOS épinglé, comme
//! spécification) : leur mise en page ([`layout`] : MENU_PopupMenuCalcSize,
//! MENU_CalcItemSize), leur fenêtre (la classe #32768, à procédure du serveur :
//! [`window_proc`], PopupMenuWndProc) et leur dessin ([`popup_ops`] :
//! MENU_DrawPopupMenu, MENU_DrawMenuItem).
//!
//! Un item d'un menu déroulant : la place d'une coche (SM_CXMENUCHECK, sauf
//! MNS_NOCHECK), quatre pixels et un caractère, son texte, la place de la
//! flèche d'un sous-menu (OBM_MNARROW) ; le texte qui suit une tabulation (un
//! raccourci) s'aligne sur celui des autres items de sa colonne (`dxTab`).
//! Un item de MF_MENUBREAK commence une colonne. Les places sont dans la zone
//! cliente de la fenêtre du menu, que son cadre (WS_EX_DLGMODALFRAME) entoure
//! de SM_CXDLGFRAME.
//!
//! Le dessin : le fond COLOR_MENU ; l'item surligné en COLOR_HIGHLIGHT, son
//! texte en COLOR_HIGHLIGHTTEXT ; grisé, en relief ; coché, la coche (ou la
//! puce de MFT_RADIOCHECK) de Marlett ; un sous-menu, la flèche de Marlett ;
//! un séparateur, un sillon (EDGE_ETCHED).
//!
//! Pas encore : les items à bitmap et dessinés par l'application, les
//! menus trop hauts pour l'écran (les flèches de défilement), le fond
//! d'un MENUINFO (`hbrBack`), le rappel SETOBM (la taille de la flèche est
//! celle du bitmap OBM_MNARROW du `user32` de ReactOS épinglé).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::menu::{item_kind, mf, mfs, mft, mns, wm};
use abi::user::{
    color, sm, MA_NOACTIVATE, WM_CREATE, WM_ERASEBKGND, WM_MOUSEACTIVATE, WM_NCCALCSIZE, WM_NCCREATE, WM_NCDESTROY,
    WM_NCHITTEST, WM_NCPAINT, WM_PAINT,
};
use hal::sync::KSpinLock;

use crate::gdi::dib::{ColorRef, Rect};
use crate::gdi::draw::{draw_edge, Op, BF_LEFT, BF_TOP, EDGE_ETCHED};
use crate::menu::Item;
use crate::menubar::{strip_prefix, text_ops, Align, MenuFont};
use crate::nonclient::{marlett, square_in, Layout};
use crate::window::{LParam, Window};

/// La largeur de la flèche d'un sous-menu : OBM_MNARROW, 6 × 9 pixels dans
/// les ressources du `user32` de ReactOS épinglé (le rappel SETOBM la
/// donnerait à win32k).
pub const ARROW_WIDTH: i32 = 6;
/// MENU_COL_SPACE : les pixels entre deux colonnes.
const COL_SPACE: i32 = 4;

/// IS_STRING_ITEM : un item de texte (ni bitmap, ni dessiné par
/// l'application, ni séparateur).
fn is_string(item: &Item) -> bool {
    item_kind(item.f_type) == mft::STRING
}

/// MENU_CalcItemSize pour un menu déroulant : l'item `item` commence en
/// (`x`, `y`) ; sa droite et son bas, son `dxTab`.
fn calc_item(
    item: &mut Item,
    (x, y): (i32, i32),
    no_check: bool,
    font: &MenuFont,
    m: &impl Fn(usize) -> i32,
) -> (i32, i32) {
    item.x = x as u32;
    item.y = y as u32;
    let (mut right, mut bottom) = (x, y);
    if item.f_type & mft::SEPARATOR != 0 {
        bottom += m(sm::CYMENUSIZE) / 2;
        right += ARROW_WIDTH + font.char_width;
        item.dx_tab = 0;
        return (right, bottom);
    }
    if !no_check {
        right += m(sm::CXMENUCHECK);
    }
    right += 4 + font.char_width;
    let mut tab = right;
    right += ARROW_WIDTH;
    let mut height = 0;
    if !item.text.is_empty() && item.f_type & mf::SYSMENU == 0 {
        let bold = item.f_state & mfs::DEFAULT != 0;
        let measure = |text: &[u16]| (font.measure)(&strip_prefix(text).0, bold);
        let (text_width, text_height) = match item.text.iter().position(|&unit| unit == u16::from(b'\t')) {
            Some(at) => {
                let (before, before_height) = measure(&item.text[..at]);
                let (after, after_height) = measure(&item.text[at + 1..]);
                tab += before;
                (before + font.char_width + after, before_height.max(after_height))
            }
            None => {
                let (width, text_height) = measure(&item.text);
                tab += width;
                (width, text_height)
            }
        };
        right += 2 + text_width;
        height = (text_height + 2).max(font.char_height + 4);
    }
    item.dx_tab = tab as u32;
    bottom += height;
    (right, bottom)
}

/// MENU_PopupMenuCalcSize : les items d'un menu déroulant de haut en bas,
/// une colonne de plus à chaque MF_MENUBREAK ; chaque colonne prend la
/// largeur de son plus large item (les raccourcis alignés sur le plus long
/// texte). Rend la taille du menu (`cxMenu`, `cyMenu`) ; (0, 0) sans items.
pub fn layout(items: &mut [Item], no_check: bool, font: &MenuFont, m: &impl Fn(usize) -> i32) -> (i32, i32) {
    let (mut width, mut height) = (0, 0);
    let mut start = 0;
    while start < items.len() {
        let mut x = width;
        if items[start].f_type & (mft::MENUBREAK | mft::MENUBARBREAK) != 0 {
            x += COL_SPACE;
        }
        let mut y = 0;
        let (mut max_tab, mut max_tab_width) = (0, 0);
        let mut at = start;
        while at < items.len() {
            let item = &mut items[at];
            if at != start && item.f_type & (mft::MENUBREAK | mft::MENUBARBREAK) != 0 {
                break;
            }
            let (right, bottom) = calc_item(item, (x, y), no_check, font, m);
            (item.cx, item.cy) = (right as u32, bottom as u32);
            width = width.max(right);
            y = bottom;
            if is_string(item) && item.dx_tab != 0 {
                max_tab = max_tab.max(item.dx_tab as i32);
                max_tab_width = max_tab_width.max(right - item.dx_tab as i32);
            }
            at += 1;
        }
        width = width.max(max_tab + max_tab_width);
        for item in &mut items[start..at] {
            item.cx = width as u32;
            if is_string(item) && item.dx_tab != 0 {
                item.dx_tab = max_tab as u32;
            }
        }
        height = height.max(y);
        start = at;
    }
    (width, height)
}

/// Un item d'un menu déroulant, de quoi le dessiner (dans les coordonnées de
/// sa fenêtre).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopupItem {
    pub rect: Rect,
    pub text: Vec<u16>,
    pub f_type: u32,
    pub f_state: u32,
    /// Il ouvre un sous-menu (la flèche).
    pub submenu: bool,
    /// Où commence son raccourci (`dxTab`).
    pub dx_tab: i32,
}

/// Le texte `text` d'un item dans `rect`, aligné selon `align`, grisé en
/// relief s'il le faut ; faux sans la police.
#[expect(clippy::too_many_arguments, reason = "the text, its place and its colours")]
fn item_text(
    text: &[u16],
    bold: bool,
    rect: Rect,
    align: Align,
    color: ColorRef,
    (grayed, hilite): (bool, bool),
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let (shown, underline) = strip_prefix(text);
    let mut painted = true;
    let mut color = color;
    if grayed {
        if !hilite {
            let raised = Rect::new(rect.left + 1, rect.top + 1, rect.right + 1, rect.bottom + 1);
            painted &= text_ops(&shown, underline, bold, raised, align, c(color::BTNHIGHLIGHT), layout, ops);
        }
        color = c(color::BTNSHADOW);
    }
    painted && text_ops(&shown, underline, bold, rect, align, color, layout, ops)
}

/// MENU_DrawPopupMenu et MENU_DrawMenuItem : le fond de la zone cliente
/// `client` (COLOR_MENU), puis chaque item : surligné, son fond en
/// COLOR_HIGHLIGHT ; la coche (ou la puce) s'il est coché, la flèche s'il
/// ouvre un sous-menu, son texte et son raccourci ; un séparateur, un sillon.
/// Rend faux si la police manquait.
pub fn popup_ops(
    client: Rect,
    items: &[PopupItem],
    no_check: bool,
    c: &impl Fn(usize) -> ColorRef,
    m: &impl Fn(usize) -> i32,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let mut painted = true;
    ops.push(Op::Fill(client, c(color::MENU)));
    for item in items {
        if item.f_type & (mft::OWNERDRAW | mf::SYSMENU) != 0 {
            continue;
        }
        let rect = item.rect;
        let hilite = item.f_state & mf::HILITE != 0;
        let grayed = item.f_state & mf::GRAYED != 0;
        ops.push(Op::Fill(rect, c(if hilite { color::HIGHLIGHT } else { color::MENU })));
        if item.f_type & mft::MENUBARBREAK != 0 {
            let mut line = Rect::new(rect.left - 3, client.top + 3, rect.left - 1, client.bottom - 3);
            draw_edge(&mut line, EDGE_ETCHED, BF_LEFT, c, ops);
        }
        if item.f_type & mft::SEPARATOR != 0 {
            let top = (rect.top + rect.bottom) / 2 - 1;
            let mut line = Rect::new(rect.left + 1, top, rect.right - 1, rect.bottom);
            draw_edge(&mut line, EDGE_ETCHED, BF_TOP, c, ops);
            continue;
        }
        let color = c(match (hilite, grayed) {
            (_, true) => color::GRAYTEXT,
            (true, false) => color::HIGHLIGHTTEXT,
            (false, false) => color::MENUTEXT,
        });
        let check = m(sm::CXMENUCHECK);
        if !no_check && item.f_state & mf::CHECKED != 0 {
            let symbol = if item.f_type & mft::RADIOCHECK != 0 { 'h' } else { 'a' };
            let cell = square_in(Rect::new(rect.left, rect.top, rect.left + check, rect.bottom));
            painted &= marlett(cell, symbol, color, 0, rect, layout, ops);
        }
        if item.submenu {
            let cell = square_in(Rect::new(rect.right - check, rect.top, rect.right, rect.bottom));
            painted &= marlett(cell, '8', color, 0, rect, layout, ops);
        }
        if item.text.is_empty() {
            continue;
        }
        let mut text_rect = rect;
        text_rect.left += 4 + if no_check { 0 } else { check };
        text_rect.right -= ARROW_WIDTH;
        text_rect.bottom -= 1;
        let bold = item.f_state & mfs::DEFAULT != 0;
        let end =
            item.text.iter().position(|&unit| unit == u16::from(b'\t') || unit == 0x08).unwrap_or(item.text.len());
        let shape = (grayed, hilite);
        painted &= item_text(&item.text[..end], bold, text_rect, Align::Left, color, shape, c, layout, ops);
        if end < item.text.len() {
            let mut shortcut = text_rect;
            let align = if item.text[end] == u16::from(b'\t') {
                shortcut.left = item.dx_tab;
                Align::Left
            } else {
                shortcut.right = item.dx_tab;
                Align::Right
            };
            painted &= item_text(&item.text[end + 1..], bold, shortcut, align, color, shape, c, layout, ops);
        }
    }
    painted
}

/// Les fenêtres des menus déroulants montrés, et leur menu
/// (`POPUPMENU.spmenu`).
static POPUPS: KSpinLock<Vec<(u32, u32)>> = KSpinLock::new(Vec::new());

/// La fenêtre `hwnd` montre le menu `menu`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn register(hwnd: u32, menu: u32) {
    let mut popups = POPUPS.lock();
    popups.retain(|&(at, _)| at != hwnd);
    popups.push((hwnd, menu));
}

/// Le menu que montre la fenêtre `hwnd` (MN_GETHMENU).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn menu_of(hwnd: u32) -> Option<u32> {
    POPUPS.lock().iter().find(|&&(at, _)| at == hwnd).map(|&(_, menu)| menu)
}

/// Les items du menu de la fenêtre `window` (un menu déroulant) dans ses
/// coordonnées, et sa zone cliente.
fn items_of(window: &Window, menu: u32) -> Option<(Rect, Vec<PopupItem>, bool)> {
    let state = crate::menu::state(menu)?;
    let window_state = window.state();
    let (dx, dy) =
        (window_state.client.left - window_state.window.left, window_state.client.top - window_state.window.top);
    let client = Rect::new(
        dx,
        dy,
        dx + window_state.client.right - window_state.client.left,
        dy + window_state.client.bottom - window_state.client.top,
    );
    let items = state
        .items
        .iter()
        .map(|item| PopupItem {
            rect: Rect::new(item.x as i32 + dx, item.y as i32 + dy, item.cx as i32 + dx, item.cy as i32 + dy),
            text: item.text.clone(),
            f_type: item.f_type,
            f_state: item.f_state,
            submenu: item.submenu != 0,
            dx_tab: item.dx_tab as i32 + dx,
        })
        .collect();
    Some((client, items, state.flags & mns::NOCHECK != 0))
}

/// MENU_DrawPopupMenu : la zone cliente de la fenêtre `window` d'un menu
/// déroulant, peinte à l'écran là où elle se voit.
///
/// # IRQL
/// PASSIVE_LEVEL (les polices).
pub fn paint(window: &Window) {
    let Some(menu) = menu_of(window.handle) else { return };
    let Some((client, items, no_check)) = items_of(window, menu) else { return };
    let mut ops = Vec::new();
    let painted = popup_ops(
        client,
        &items,
        no_check,
        &crate::paint::system_color,
        &crate::metrics::get,
        &crate::font::text_run_named,
        &mut ops,
    );
    if !painted {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: a popup menu's text and symbols without their fonts");
        }
    }
    crate::paint::draw_frame_ops(window, &window.state(), &ops);
}

/// Le RECT au début de `bytes`.
fn rect_of(bytes: &[u8]) -> Option<Rect> {
    let word = |at: usize| Some(i32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    Some(Rect::new(word(0)?, word(4)?, word(8)?, word(12)?))
}

/// PopupMenuWndProc, la procédure du serveur de la classe #32768 :
/// WM_NCCREATE pose sa FNID ; sa zone cliente est celle de son style (son
/// cadre) ; WM_PAINT peint le menu, WM_ERASEBKGND n'efface rien ; elle ne
/// s'active pas à la souris ; MN_GETHMENU rend son menu ; WM_NCDESTROY
/// l'oublie.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn window_proc(window: &Window, message: u32, wparam: u32, lparam: &mut LParam<'_>) -> u32 {
    match message {
        WM_NCCREATE => {
            crate::window::set_fnid(window, abi::user::FNID_MENU);
            1
        }
        WM_CREATE => 0,
        WM_NCCALCSIZE => {
            let LParam::Buffer { bytes, .. } = lparam else { return 0 };
            let Some(rect) = rect_of(bytes) else { return 0 };
            let state = window.state();
            let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
            let calc = crate::defwnd::nc_calc_size(
                state.style,
                state.ex_style,
                class_style,
                wparam != 0,
                &|_| None,
                rect,
                &crate::metrics::get,
            );
            let client = calc.client;
            for (at, word) in [client.left, client.top, client.right, client.bottom].iter().enumerate() {
                bytes[4 * at..4 * at + 4].copy_from_slice(&word.to_le_bytes());
            }
            calc.result
        }
        WM_NCPAINT => {
            crate::paint::nc_paint(window, wparam);
            0
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            crate::window::change(window, |state| {
                state.begin_paint();
            });
            paint(window);
            crate::window::change(window, |state| state.painting = Rect::default());
            0
        }
        WM_MOUSEACTIVATE => MA_NOACTIVATE,
        WM_NCHITTEST => {
            let LParam::Value(value) = *lparam else { return 0 };
            let state = window.state();
            let point = (i32::from(value as u16 as i16), i32::from((value >> 16) as u16 as i16));
            crate::defwnd::nc_hit_test(
                state.style,
                state.ex_style,
                false,
                state.window,
                state.client,
                point,
                &crate::metrics::get,
            )
        }
        wm::MN_GETHMENU => menu_of(window.handle).unwrap_or(0),
        WM_NCDESTROY => {
            POPUPS.lock().retain(|&(at, _)| at != window.handle);
            0
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::font::{Named, Quality, TextRun};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn metric(index: usize) -> i32 {
        match index {
            sm::CYMENUSIZE => 18,
            sm::CXMENUCHECK => 13,
            _ => 0,
        }
    }

    /// Six pixels a character, 13 high.
    fn measure(text: &[u16], _bold: bool) -> (i32, i32) {
        (text.len() as i32 * 6, 13)
    }

    fn font() -> MenuFont<'static> {
        MenuFont { measure: &measure, char_width: 6, char_height: 13 }
    }

    fn item(text: &str, f_type: u32) -> Item {
        Item { text: wide(text), f_type, ..Item::default() }
    }

    fn places(items: &[Item]) -> Vec<(u32, u32, u32, u32, u32)> {
        items.iter().map(|item| (item.x, item.y, item.cx, item.cy, item.dx_tab)).collect()
    }

    #[test]
    fn items_go_down_one_column_as_wide_as_the_widest() {
        let mut items = [item("&Open", 0), item("", mft::SEPARATOR), item("E&xit", 0)];
        let size = layout(&mut items, false, &font(), &metric);
        // Open: 13 (check) + 4 + 6, its text from there (23); 6 (arrow), 2,
        // 24 of text: 55; 17 high (13 + 4); the separator 9.
        assert_eq!(places(&items), [(0, 0, 55, 17, 47), (0, 17, 55, 26, 0), (0, 26, 55, 43, 47)]);
        assert_eq!(size, (55, 43));
    }

    #[test]
    fn shortcuts_line_up_after_the_longest_text() {
        let mut items = [item("&Open\tCtrl+O", 0), item("Save &As...\tF12", 0)];
        let size = layout(&mut items, false, &font(), &metric);
        // Open: dxTab 23 + 24; Save As...: 23 + 60 = 83; widths 23 + 6 + 2 +
        // (24 + 6 + 36) = 97 and 23 + 6 + 2 + (60 + 6 + 18) = 115; the column
        // as wide as the longest tab and widest shortcut: 83 + (97 - 47).
        assert_eq!(items.iter().map(|item| item.dx_tab).collect::<Vec<_>>(), [83, 83]);
        assert_eq!(size, (133, 34));
    }

    #[test]
    fn a_menu_break_starts_a_column() {
        let mut items = [item("One", 0), item("Two", mft::MENUBREAK), item("Three", 0)];
        let size = layout(&mut items, true, &font(), &metric);
        // MNS_NOCHECK: 4 + 6, the text, 6, 2: One 36 wide; the second column
        // from 40 (4 between), Three 48 wide, the shortcuts of the column
        // after its longest text (80).
        assert_eq!(places(&items)[..2], [(0, 0, 36, 17, 28), (40, 0, 88, 17, 80)]);
        assert_eq!(items[2].y, 17);
        assert_eq!(size, (88, 34));
        assert_eq!(layout(&mut [], false, &font(), &metric), (0, 0));
    }

    fn no_fonts(_: Named, _: i32, _: &[u16], _: Option<i32>, _: Quality) -> Option<TextRun> {
        None
    }

    #[test]
    fn a_hilited_item_a_separator_and_a_checked_item() {
        let palette = |index: usize| ColorRef(index as u32);
        let items = [
            PopupItem {
                rect: Rect::new(3, 3, 58, 20),
                text: wide("&Open"),
                f_type: 0,
                f_state: mf::HILITE,
                submenu: false,
                dx_tab: 50,
            },
            PopupItem {
                rect: Rect::new(3, 20, 58, 29),
                text: Vec::new(),
                f_type: mft::SEPARATOR,
                f_state: 0,
                submenu: false,
                dx_tab: 0,
            },
        ];
        let mut ops = Vec::new();
        assert!(!popup_ops(Rect::new(3, 3, 58, 46), &items, false, &palette, &metric, &no_fonts, &mut ops));
        assert_eq!(ops[0], Op::Fill(Rect::new(3, 3, 58, 46), ColorRef(color::MENU as u32)));
        assert_eq!(ops[1], Op::Fill(Rect::new(3, 3, 58, 20), ColorRef(color::HIGHLIGHT as u32)), "hilited");
        assert_eq!(ops[2], Op::Fill(Rect::new(3, 20, 58, 29), ColorRef(color::MENU as u32)));
        let shadow = ColorRef(color::BTNSHADOW as u32);
        assert!(
            ops[3..].iter().any(|op| matches!(op, Op::Fill(r, c) if *c == shadow && r.top == 23 && r.left == 4)),
            "the separator's groove, from its middle less one"
        );
    }
}
