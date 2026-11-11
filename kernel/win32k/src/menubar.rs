//! La barre de menus d'une fenêtre (`menu.c` de win32k, ReactOS épinglé,
//! comme spécification) : la place de ses items ([`layout`] :
//! MENU_MenuBarCalcSize, MENU_CalcItemSize), que WM_NCCALCSIZE calcule
//! ([`calc`]) et garde dans les items (`xItem`, `yItem`, `cxItem`,
//! `cyItem` : la droite et le bas, comme ReactOS, dans les coordonnées de la
//! fenêtre) ; son dessin dans le cadre ([`bar_ops`] : IntDrawMenuBarTemp,
//! MENU_DrawMenuItem), le texte centré dans l'item, son préfixe `&` souligné
//! ([`strip_prefix`], comme DrawText) ; l'item surligné (HiliteMenuItem :
//! fond enfoncé, texte décalé d'un pixel), grisé (en relief).
//!
//! Le texte se mesure dans la police des menus (Tahoma, `lfMenuFont` des
//! métriques), en gras pour l'item par défaut ; la largeur moyenne d'un
//! caractère (MenuCharSize) borde chaque texte des deux côtés.
//!
//! Écarts voulus avec ReactOS : HiliteMenuItem surligne l'item ou l'éteint,
//! comme la documentation de l'API le dit (ReactOS sélectionne l'item comme
//! le suivi d'un menu, et le surligne même pour MF_UNHILITE) ;
//! MenuItemFromPoint rend -1 hors des items (ReactOS rend le nombre
//! d'items) ; un menu vide n'a pas de barre (comme le calcul de ReactOS, dont
//! le dessin la donnerait de SM_CYMENU).
//!
//! Pas encore : les items à bitmap (MDI : leur taille, leur dessin), les
//! items dessinés par l'application (WM_MEASUREITEM, WM_DRAWITEM), le menu
//! système (MF_SYSMENU), les menus plats (SPI_GETFLATMENU).

use alloc::vec::Vec;

use abi::menu::{mf, mfs, mft};
use abi::user::{color, sm, WS_CHILD, WS_POPUP};

use crate::font::{Quality, TAHOMA, TAHOMA_BOLD};
use crate::gdi::dib::{ColorRef, Rect};
use crate::gdi::draw::{draw_edge, Op, BDR_SUNKENOUTER, BF_RECT};
use crate::menu::Item;
use crate::nonclient::Layout;
use crate::window::Window;

/// La hauteur de LOGFONT de la police des menus (Tahoma 8 points).
pub const MENU_FONT_HEIGHT: i32 = -11;

/// L'alphabet dont la largeur moyenne fait MenuCharSize (IntGetCharDimensions).
const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// DrawText sans DT_NOPREFIX : `&` devant un caractère le souligne et
/// disparaît, `&&` donne un `&`, un `&` final reste. Rend le texte montré et
/// la position du premier caractère souligné.
pub fn strip_prefix(text: &[u16]) -> (Vec<u16>, Option<usize>) {
    const PREFIX: u16 = b'&' as u16;
    let mut shown = Vec::with_capacity(text.len());
    let mut underline = None;
    let mut at = 0;
    while at < text.len() {
        if text[at] == PREFIX && at + 1 < text.len() {
            at += 1;
            if text[at] != PREFIX && underline.is_none() {
                underline = Some(shown.len());
            }
        }
        shown.push(text[at]);
        at += 1;
    }
    (shown, underline)
}

/// Le texte d'un item dans la barre : jusqu'à sa première tabulation ou
/// son premier `\b` (MENU_DrawMenuItem).
fn bar_text(text: &[u16]) -> &[u16] {
    let end = text.iter().position(|&unit| unit == u16::from(b'\t') || unit == 0x08).unwrap_or(text.len());
    &text[..end]
}

/// La largeur et la hauteur (tmHeight) d'un texte montré dans la police des
/// menus, en gras pour un item par défaut (DrawText DT_CALCRECT |
/// DT_SINGLELINE).
pub type Measure<'a> = &'a dyn Fn(&[u16], bool) -> (i32, i32);

/// Ce que la mise en page tire de la police des menus.
pub struct MenuFont<'a> {
    pub measure: Measure<'a>,
    /// MenuCharSize.cx : la largeur moyenne d'un caractère.
    pub char_width: i32,
}

/// MENU_CalcItemSize pour la barre : l'item `item` commence en
/// (`x`, `y`) ; sa droite et son bas.
fn calc_item(item: &mut Item, (x, y): (i32, i32), font: &MenuFont, m: &impl Fn(usize) -> i32) -> (i32, i32) {
    let (mut right, mut bottom) = (x, y);
    if item.f_type & mft::SEPARATOR != 0 {
        bottom += m(sm::CYMENUSIZE) / 2;
    } else {
        let text = bar_text(&item.text);
        let mut height = m(sm::CYMENU) - 1;
        if !text.is_empty() {
            let (shown, _) = strip_prefix(text);
            let (width, text_height) = (font.measure)(&shown, item.f_state & mfs::DEFAULT != 0);
            right += width + 2 * font.char_width;
            height = height.max(text_height);
        }
        bottom += height;
    }
    item.x = x as u32;
    item.y = y as u32;
    (right, bottom)
}

/// MENU_MenuBarCalcSize : les items d'une barre dans `rect` (les
/// coordonnées de la fenêtre), de gauche à droite, une ligne de plus quand
/// un item ne tient pas ou porte MF_MENUBREAK ; ceux qui suivent le premier
/// MF_RIGHTJUSTIFY (MF_HELP) vont à droite de la dernière ligne. Rend la
/// hauteur de la barre (`cyMenu`, un pixel sous les items) ; 0 sans items.
pub fn layout(items: &mut [Item], rect: Rect, font: &MenuFont, m: &impl Fn(usize) -> i32) -> i32 {
    if items.is_empty() {
        return 0;
    }
    let mut bottom = rect.top;
    let mut start = 0;
    let mut help = None;
    while start < items.len() {
        let mut x = rect.left;
        let y = bottom;
        let mut at = start;
        while at < items.len() {
            let item = &mut items[at];
            if help.is_none() && item.f_type & mft::RIGHTJUSTIFY != 0 {
                help = Some(at);
            }
            if at != start && item.f_type & (mft::MENUBREAK | mft::MENUBARBREAK) != 0 {
                break;
            }
            let (mut right, item_bottom) = calc_item(item, (x, y), font, m);
            if right > rect.right {
                if at != start {
                    break;
                }
                right = rect.right;
            }
            item.cx = right as u32;
            item.cy = item_bottom as u32;
            bottom = bottom.max(item_bottom);
            x = right;
            at += 1;
        }
        start = at;
    }
    let height = bottom + 1 - rect.top;
    if let Some(help) = help {
        let line = items[items.len() - 1].y;
        let mut right = rect.right as u32;
        for item in items[help..].iter_mut().rev() {
            if item.y != line || item.cx >= right {
                break;
            }
            item.x += right - item.cx;
            item.cx = right;
            right = item.x;
        }
    }
    height
}

/// La largeur moyenne d'un caractère de la police (IntGetCharDimensions).
pub fn char_width(measure: Measure) -> i32 {
    let alphabet: Vec<u16> = ALPHABET.encode_utf16().collect();
    (measure(&alphabet, false).0 / 26 + 1) / 2
}

/// Un item de la barre, de quoi le dessiner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BarItem {
    /// Sa place dans la fenêtre.
    pub rect: Rect,
    pub text: Vec<u16>,
    pub f_type: u32,
    pub f_state: u32,
}

/// Une barre à dessiner : son rectangle dans la fenêtre (de sa hauteur
/// `cyMenu`), ses items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bar {
    pub rect: Rect,
    pub items: Vec<BarItem>,
    pub char_width: i32,
}

/// Le texte `text` centré dans `rect` (DT_CENTER | DT_VCENTER |
/// DT_SINGLELINE), coupé à `rect`, son caractère `underline` souligné
/// (TEXT_DrawUnderscore : sous la ligne de base) ; faux sans la police.
fn text_ops(
    text: &[u16],
    underline: Option<usize>,
    bold: bool,
    rect: Rect,
    color: ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let face = if bold { TAHOMA_BOLD } else { TAHOMA };
    let Some(run) = layout(face, MENU_FONT_HEIGHT, text, None, Quality::Antialiased) else { return false };
    let x = rect.left + (rect.right - rect.left - run.width) / 2;
    let top = rect.top + (rect.bottom - rect.top - run.metrics.height()) / 2;
    let baseline = top + run.metrics.ascent;
    for glyph in &run.glyphs {
        let at = (x + glyph.x + glyph.bitmap.left, baseline - glyph.bitmap.top);
        ops.push(Op::Glyph { at, bitmap: glyph.bitmap.clone(), color, clip: rect });
    }
    if let Some(at) = underline {
        let width_to = |end: usize| layout(face, MENU_FONT_HEIGHT, &text[..end], None, Quality::Antialiased);
        if let (Some(before), Some(through)) = (width_to(at), width_to(at + 1)) {
            let line = Rect::new(x + before.width, baseline + 1, x + through.width - 1, baseline + 2);
            let line = line.intersect(&rect);
            if !line.is_empty() {
                ops.push(Op::Fill(line, color));
            }
        }
    }
    true
}

/// IntDrawMenuBarTemp et MENU_DrawMenuItem : le fond de la barre (couleur
/// des menus), sa dernière ligne (COLOR_3DFACE), puis chaque item : surligné,
/// un fond enfoncé et son texte décalé d'un pixel ; grisé (MF_GRAYED), son
/// texte en relief. Rend faux si la police manquait pour un texte.
pub fn bar_ops(bar: &Bar, c: &impl Fn(usize) -> ColorRef, layout: Layout, ops: &mut Vec<Op>) -> bool {
    let mut painted = true;
    ops.push(Op::Fill(bar.rect, c(color::MENU)));
    let line = Rect::new(bar.rect.left, bar.rect.bottom - 1, bar.rect.right, bar.rect.bottom);
    ops.push(Op::Fill(line, c(color::BTNFACE)));
    for item in &bar.items {
        if item.f_type & (mft::SEPARATOR | mft::OWNERDRAW | mf::SYSMENU) != 0 {
            continue;
        }
        let mut rect = item.rect;
        let hilite = item.f_state & mf::HILITE != 0;
        let grayed = item.f_state & mf::GRAYED != 0;
        ops.push(Op::Fill(rect, c(color::MENU)));
        if hilite {
            draw_edge(&mut rect.clone(), BDR_SUNKENOUTER, BF_RECT, c, ops);
        }
        let text = bar_text(&item.text);
        if text.is_empty() {
            continue;
        }
        let (shown, underline) = strip_prefix(text);
        rect.left += bar.char_width;
        rect.right -= bar.char_width;
        if hilite && !grayed {
            rect = Rect::new(rect.left + 1, rect.top + 1, rect.right + 1, rect.bottom + 1);
        }
        let bold = item.f_state & mfs::DEFAULT != 0;
        let mut text_color = c(color::MENUTEXT);
        if grayed {
            if !hilite {
                let raised = Rect::new(rect.left + 1, rect.top + 1, rect.right + 1, rect.bottom + 1);
                painted &= text_ops(&shown, underline, bold, raised, c(color::BTNHIGHLIGHT), layout, ops);
            }
            text_color = c(color::BTNSHADOW);
        }
        painted &= text_ops(&shown, underline, bold, rect, text_color, layout, ops);
    }
    painted
}

/// La police des menus du système : Tahoma, ou rien sans elle (une barre
/// de SM_CYMENU, des textes sans largeur).
///
/// # IRQL
/// PASSIVE_LEVEL (les polices).
fn system_measure(text: &[u16], bold: bool) -> (i32, i32) {
    let face = if bold { TAHOMA_BOLD } else { TAHOMA };
    crate::font::text_run_named(face, MENU_FONT_HEIGHT, text, None, Quality::Antialiased)
        .map_or((0, 0), |run| (run.width, run.metrics.height()))
}

/// La barre de menus de `window` : sa barre (`IDMenu`) si elle n'est pas
/// fille et que le menu existe (HAS_MENU).
fn bar_menu(window: &Window) -> Option<u32> {
    let state = window.state();
    (state.style & (WS_CHILD | WS_POPUP) != WS_CHILD && state.menu != 0 && crate::menu::exists(state.menu))
        .then_some(state.menu)
}

/// MENU_DrawMenuBar(…, TRUE) de NC_HandleNCCalcSize : la barre de `window`
/// mise en page dans `rect` (dans les coordonnées de la fenêtre, sous le
/// titre), sa place gardée dans les items ; rend sa hauteur, `None` sans
/// barre.
///
/// # IRQL
/// PASSIVE_LEVEL (les polices).
pub fn calc(window: &Window, rect: Rect) -> Option<i32> {
    let menu = bar_menu(window)?;
    let mut items = crate::menu::items(menu);
    let font = MenuFont { measure: &system_measure, char_width: char_width(&system_measure) };
    let height = layout(&mut items, rect, &font, &crate::metrics::get);
    let width = (rect.right - rect.left).max(0) as u32;
    crate::menu::set_places(menu, &items, width, height.max(0) as u32);
    Some(height)
}

/// La barre de `window` à dessiner en haut de `rect` (NC_DoNCPaint) : ses
/// items à leur place, mis en page d'abord s'ils ne l'ont pas été depuis un
/// changement (`cyMenu` nul, IntDrawMenuBarTemp) ; `None` sans barre ou sans
/// items (sa hauteur est nulle).
///
/// # IRQL
/// PASSIVE_LEVEL (les polices).
pub fn paint(window: &Window, rect: Rect) -> Option<Bar> {
    let menu = bar_menu(window)?;
    let mut state = crate::menu::state(menu)?;
    if state.items.is_empty() {
        return None;
    }
    if state.height == 0 {
        calc(window, rect)?;
        state = crate::menu::state(menu)?;
    }
    let height = state.height as i32;
    let items = state
        .items
        .iter()
        .map(|item| BarItem {
            rect: Rect::new(item.x as i32, item.y as i32, item.cx as i32, item.cy as i32),
            text: item.text.clone(),
            f_type: item.f_type,
            f_state: item.f_state,
        })
        .collect();
    Some(Bar {
        rect: Rect::new(rect.left, rect.top, rect.right, rect.top + height),
        items,
        char_width: char_width(&system_measure),
    })
}

/// IntGetMenuItemRect : la place de l'item `position` du menu `menu` à
/// l'écran : dans la fenêtre dont il est la barre, ou dans la zone cliente
/// d'un menu déroulant ; `None` sans l'item ou sans fenêtre.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn item_rect(window: Option<&Window>, menu: u32, position: u32) -> Option<Rect> {
    let state = crate::menu::state(menu)?;
    let item = state.items.get(position as usize)?;
    let owner;
    let window = match window {
        Some(window) => window,
        None => {
            owner = crate::window::get(state.hwnd)?;
            &owner
        }
    };
    let window_state = window.state();
    let origin = if state.flags & abi::menu::mnf::POPUP != 0 { window_state.client } else { window_state.window };
    let (dx, dy) = (origin.left, origin.top);
    Some(Rect::new(item.x as i32 + dx, item.y as i32 + dy, item.cx as i32 + dx, item.cy as i32 + dy))
}

/// NtUserMenuItemFromPoint : la position de l'item du menu `menu` sous le
/// point `point` de l'écran, dans la fenêtre dont il est la barre ; `None`
/// ailleurs.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn item_from_point(menu: u32, (x, y): (i32, i32)) -> Option<u32> {
    let state = crate::menu::state(menu)?;
    let window = crate::window::get(state.hwnd)?;
    let origin = window.state().window;
    let (x, y) = (x - origin.left, y - origin.top);
    state
        .items
        .iter()
        .position(|item| x >= item.x as i32 && x < item.cx as i32 && y >= item.y as i32 && y < item.cy as i32)
        .map(|position| position as u32)
}

/// HiliteMenuItem : l'item `at` (MF_BYPOSITION, sinon par identifiant) de la
/// barre `menu` de `window` est surligné (MF_HILITE dans `flags`) ou ne l'est
/// plus ; le cadre se repeint s'il a changé.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn hilite(window: &Window, menu: u32, at: u32, flags: u32) {
    if crate::menu::hilite(menu, at, flags) && bar_menu(window) == Some(menu) {
        crate::paint::nc_paint(window, abi::user::HRGN_WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn metric(index: usize) -> i32 {
        match index {
            sm::CYMENU => 19,
            sm::CYMENUSIZE => 18,
            _ => 0,
        }
    }

    /// Six pixels par caractère, un de plus en gras ; 13 de haut.
    fn measure(text: &[u16], bold: bool) -> (i32, i32) {
        (text.len() as i32 * if bold { 7 } else { 6 }, 13)
    }

    fn font() -> MenuFont<'static> {
        MenuFont { measure: &measure, char_width: char_width(&measure) }
    }

    fn item(text: &str, f_type: u32) -> Item {
        Item { text: wide(text), f_type, ..Item::default() }
    }

    fn places(items: &[Item]) -> Vec<(u32, u32, u32, u32)> {
        items.iter().map(|item| (item.x, item.y, item.cx, item.cy)).collect()
    }

    #[test]
    fn prefixes_go_and_underline_the_first_character() {
        assert_eq!(strip_prefix(&wide("&File")), (wide("File"), Some(0)));
        assert_eq!(strip_prefix(&wide("E&xit")), (wide("Exit"), Some(1)));
        assert_eq!(strip_prefix(&wide("Save && &Quit")), (wide("Save & Quit"), Some(7)));
        assert_eq!(strip_prefix(&wide("&a&b")), (wide("ab"), Some(0)), "the first one only");
        assert_eq!(strip_prefix(&wide("End&")), (wide("End&"), None), "a final & stays");
        assert_eq!(strip_prefix(&wide("Plain")), (wide("Plain"), None));
    }

    #[test]
    fn the_average_character_of_the_menu_font() {
        assert_eq!(char_width(&measure), 6, "(312 / 26 + 1) / 2");
    }

    #[test]
    fn items_go_left_to_right_with_a_character_each_side() {
        let mut items = [item("&File", 0), item("&Edit", 0), item("", mft::SEPARATOR)];
        let height = layout(&mut items, Rect::new(4, 23, 396, 300), &font(), &metric);
        // File: 4 shown characters (24) + 2 * 6.
        assert_eq!(places(&items), [(4, 23, 40, 41), (40, 23, 76, 41), (76, 23, 76, 32)]);
        assert_eq!(height, 19, "SM_CYMENU - 1 high items, a pixel under them");
    }

    #[test]
    fn help_goes_to_the_right_and_a_long_bar_wraps() {
        let mut items = [item("File", 0), item("Help", mft::RIGHTJUSTIFY)];
        layout(&mut items, Rect::new(0, 0, 200, 100), &font(), &metric);
        assert_eq!(places(&items), [(0, 0, 36, 18), (164, 0, 200, 18)]);
        let mut long = [item("Aaaaaaaaaa", 0), item("Bbbbbbbbbb", 0), item("Cc", mft::MENUBREAK)];
        let height = layout(&mut long, Rect::new(0, 0, 100, 100), &font(), &metric);
        assert_eq!(places(&long), [(0, 0, 72, 18), (0, 18, 72, 36), (0, 36, 24, 54)], "a line each");
        assert_eq!(height, 55);
        let mut wide_item = [item("Wwwwwwwwwwwwwwwwwwwwwww", 0)];
        layout(&mut wide_item, Rect::new(0, 0, 50, 100), &font(), &metric);
        assert_eq!(wide_item[0].cx, 50, "alone on its line: cut at the right");
        assert_eq!(layout(&mut [], Rect::new(0, 0, 50, 100), &font(), &metric), 0, "no items, no bar");
    }

    #[test]
    fn a_default_item_is_measured_bold() {
        let mut items = [Item { f_state: mfs::DEFAULT, ..item("Open", 0) }];
        layout(&mut items, Rect::new(0, 0, 200, 100), &font(), &metric);
        assert_eq!(items[0].cx, 4 * 7 + 12);
    }

    /// A font of 6 pixels a character, 11 up and 2 down, without glyphs.
    fn flat_font(
        _: crate::font::Named,
        _: i32,
        text: &[u16],
        _: Option<i32>,
        _: Quality,
    ) -> Option<crate::font::TextRun> {
        let metrics = glyph::Metrics { ascent: 11, descent: 2, external_leading: 0, average_width: 6 };
        Some(crate::font::TextRun { glyphs: Vec::new(), width: 6 * text.len() as i32, metrics, truncated: false })
    }

    #[test]
    fn the_prefixed_character_is_underlined_under_the_baseline() {
        let mut ops = Vec::new();
        // "Exit", x underlined: centered in 40..80 (24 wide: from 48), 3..18
        // (13 high: from 4, baseline 15).
        let red = ColorRef(0xFF);
        assert!(text_ops(&wide("Exit"), Some(1), false, Rect::new(40, 3, 80, 18), red, &flat_font, &mut ops));
        assert_eq!(ops, [Op::Fill(Rect::new(54, 16, 59, 17), red)], "from 48 + 6 to 48 + 12 - 1");
    }

    #[test]
    fn the_bar_s_background_line_and_hilited_item() {
        let palette = |index: usize| ColorRef(index as u32);
        let no_fonts = |_: crate::font::Named, _: i32, _: &[u16], _: Option<i32>, _: Quality| None;
        let bar = Bar {
            rect: Rect::new(4, 23, 396, 42),
            items: alloc::vec![
                BarItem { rect: Rect::new(4, 23, 40, 41), text: wide("&File"), f_type: 0, f_state: mf::HILITE },
                BarItem { rect: Rect::new(40, 23, 40, 32), text: Vec::new(), f_type: mft::SEPARATOR, f_state: 0 },
            ],
            char_width: 6,
        };
        let mut ops = Vec::new();
        assert!(!bar_ops(&bar, &palette, &no_fonts, &mut ops), "no font: the text is not painted");
        assert_eq!(ops[0], Op::Fill(Rect::new(4, 23, 396, 42), ColorRef(color::MENU as u32)));
        assert_eq!(ops[1], Op::Fill(Rect::new(4, 41, 396, 42), ColorRef(color::BTNFACE as u32)), "the last line");
        assert_eq!(ops[2], Op::Fill(Rect::new(4, 23, 40, 41), ColorRef(color::MENU as u32)));
        let shadow = ColorRef(color::BTNSHADOW as u32);
        assert!(
            ops[3..].iter().any(|op| matches!(op, Op::Fill(r, c) if *c == shadow && r.left == 4 && r.top == 23)),
            "sunken"
        );
        let mut plain = Vec::new();
        let unlit = Bar { items: alloc::vec![BarItem { f_state: 0, ..bar.items[0].clone() }], ..bar };
        bar_ops(&unlit, &palette, &no_fonts, &mut plain);
        assert_eq!(plain.len(), 3, "the background, its line, the item's background");
    }
}
