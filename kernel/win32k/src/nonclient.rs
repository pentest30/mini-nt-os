//! Le cadre d'une fenêtre, sa zone non cliente : ce que dessine
//! DefWindowProc à WM_NCPAINT (NC_DoNCPaint de ReactOS, `nonclient.c`,
//! `painting.c`, `draw.c`, comme spécification), en opérations de dessin
//! dans les coordonnées de la fenêtre ([`frame_ops`]).
//!
//! De l'extérieur vers l'intérieur : le bord en relief d'une fenêtre qui en a
//! un (DrawEdge `EDGE_RAISED`), ou son bord statique ; le cadre épais
//! (`COLOR_ACTIVEBORDER` ou `COLOR_INACTIVEBORDER`) et le cadre fin ; la
//! barre de titre, en dégradé (SPI_GETGRADIENTCAPTIONS, vrai par défaut)
//! des couleurs actives ou inactives, ses boutons (fermer, réduire,
//! agrandir : DrawFrameControl, des boutons en relief doux) et le trait
//! dessous ; le bord client creux (`WS_EX_CLIENTEDGE`).
//!
//! Le texte du titre (UserDrawCaptionText) est en Tahoma gras (lfCaptionFont
//! par défaut : hauteur -11, gras ; Tahoma normal pour une fenêtre d'outils),
//! centré en hauteur, fini par « ... » s'il ne tient pas avant les boutons ;
//! le symbole de chaque bouton (UITOOLS95_DrawFrameCaption) est un caractère
//! de Marlett, monochrome, dans son carré : grisé (`DFCS_INACTIVE`, une
//! ombre claire puis `COLOR_BTNSHADOW`) pour réduire ou agrandir sans le
//! style qui le permet. Les glyphes viennent de `crate::font`, par la
//! fonction [`Layout`] que reçoit [`frame_ops`].
//!
//! Pas encore (ce que rend [`Unpainted`]) : l'icône de la fenêtre (icônes),
//! les barres de défilement, la barre de menus ; le texte et les symboles
//! sans leurs polices.

use alloc::vec::Vec;

use abi::user::WS_BORDER;
use abi::user::{
    color, sm, WS_CAPTION, WS_DLGFRAME, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME, WS_EX_STATICEDGE, WS_EX_TOOLWINDOW,
    WS_HSCROLL, WS_MAXIMIZE, WS_MAXIMIZEBOX, WS_MINIMIZE, WS_MINIMIZEBOX, WS_SYSMENU, WS_THICKFRAME, WS_VSCROLL,
};

use crate::defwnd::has_window_edge;
use crate::font::{Face, Quality, TextRun};
use crate::gdi::dib::{ColorRef, Rect};
use crate::gdi::draw::{draw_edge, Op, BF_ADJUST, BF_MIDDLE, BF_RECT, BF_SOFT, EDGE_RAISED, EDGE_SUNKEN};

/// La mise en glyphes d'un texte (`crate::font::text_run`) : police,
/// hauteur de LOGFONT, texte, largeur au plus, rendu.
pub type Layout<'a> = &'a dyn Fn(Face, i32, &[u16], Option<i32>, Quality) -> Option<TextRun>;

/// La hauteur de lfCaptionFont et de lfSmCaptionFont par défaut : un em de
/// 11 pixels.
pub const CAPTION_FONT_HEIGHT: i32 = -11;

/// Ce que le cadre aurait et qui n'est pas dessiné.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unpainted {
    /// Le texte du titre ou les symboles des boutons, sans leurs polices.
    pub text: bool,
    /// L'icône du titre.
    pub icon: bool,
    /// Les barres de défilement.
    pub scroll_bars: bool,
}

/// NC_DrawFrame : le cadre épais d'une fenêtre qui en a un (de la couleur
/// du bord actif ou inactif), puis le cadre fin d'une fenêtre à bordure ou
/// à cadre de dialogue ; `rect` devient ce qui reste dedans.
fn frame(
    rect: &mut Rect,
    active: bool,
    style: u32,
    ex_style: u32,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
    ops: &mut Vec<Op>,
) {
    let mut bands = |rect: &mut Rect, width: i32, height: i32, color: ColorRef| {
        let r = *rect;
        ops.push(Op::Fill(Rect::new(r.left, r.top, r.right, r.top + height), color));
        ops.push(Op::Fill(Rect::new(r.left, r.top, r.left + width, r.bottom), color));
        ops.push(Op::Fill(Rect::new(r.left, r.bottom - height, r.right, r.bottom), color));
        ops.push(Op::Fill(Rect::new(r.right - width, r.top, r.right, r.bottom), color));
        *rect = Rect::new(r.left + width, r.top + height, r.right - width, r.bottom - height);
    };
    if style & WS_THICKFRAME != 0 && style & WS_MINIMIZE == 0 {
        let width = (m(sm::CXFRAME) - m(sm::CXDLGFRAME)) * m(sm::CXBORDER);
        let height = (m(sm::CYFRAME) - m(sm::CYDLGFRAME)) * m(sm::CYBORDER);
        bands(rect, width, height, c(if active { color::ACTIVEBORDER } else { color::INACTIVEBORDER }));
    }
    if style & (WS_DLGFRAME | WS_BORDER) != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
        let index = if ex_style & (WS_EX_DLGMODALFRAME | WS_EX_CLIENTEDGE) != 0 {
            color::BTNFACE
        } else if ex_style & WS_EX_STATICEDGE != 0 {
            color::WINDOWFRAME
        } else if style & (WS_DLGFRAME | WS_THICKFRAME) != 0 {
            color::BTNFACE
        } else {
            color::WINDOWFRAME
        };
        bands(rect, m(sm::CXBORDER), m(sm::CYBORDER), c(index));
    }
}

/// Le symbole Marlett `symbol` d'un bouton `button` (UITOOLS95_DrawFrameCaption) :
/// dans son carré moins un pixel de chaque côté, une police dont la cellule
/// a sa hauteur, monochrome ; grisé (`inactive`) : une ombre en
/// `COLOR_BTNHIGHLIGHT` décalée d'un pixel, puis le symbole en
/// `COLOR_BTNSHADOW`, sinon en `COLOR_BTNTEXT`. Faux sans la police.
fn button_symbol(
    button: Rect,
    symbol: char,
    inactive: bool,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let (width, height) = (button.right - button.left, button.bottom - button.top);
    let side = width.min(height);
    let (left, top) = (button.left + (width - side) / 2, button.top + (height - side) / 2);
    let square = Rect::new(left + 1, top + 1, left + side - 1, top + side - 1);
    let Some(run) = layout(Face::Marlett, square.bottom - square.top, &[symbol as u16], None, Quality::Monochrome)
    else {
        return false;
    };
    let baseline = square.top + run.metrics.ascent;
    let mut draw = |offset: i32, color: ColorRef| {
        for glyph in &run.glyphs {
            let at = (square.left + glyph.x + glyph.bitmap.left + offset, baseline - glyph.bitmap.top + offset);
            ops.push(Op::Glyph { at, bitmap: glyph.bitmap.clone(), color, clip: button });
        }
    };
    if inactive {
        draw(1, c(color::BTNHIGHLIGHT));
    }
    draw(0, c(if inactive { color::BTNSHADOW } else { color::BTNTEXT }));
    true
}

/// Les boutons du titre `caption` (UserDrawCaptionButton) : fermer, puis
/// réduire et agrandir, des boutons en relief doux (DrawFrameControl
/// `DFC_CAPTION`) avec leur symbole ; faux si les symboles manquent.
fn caption_buttons(
    caption: Rect,
    style: u32,
    ex_style: u32,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    let button = |rect: Rect, symbol: char, inactive: bool, ops: &mut Vec<Op>| {
        draw_edge(&mut rect.clone(), EDGE_RAISED, BF_RECT | BF_MIDDLE | BF_SOFT, c, ops);
        button_symbol(rect, symbol, inactive, c, layout, ops)
    };
    let (cx, cy) = if ex_style & WS_EX_TOOLWINDOW != 0 {
        (m(sm::CXSMSIZE), m(sm::CYSMSIZE))
    } else {
        (m(sm::CXSIZE), m(sm::CYSIZE))
    };
    let close = Rect::new(caption.right - cx, caption.top + 2, caption.right - 2, caption.top + cy - 2);
    let mut drawn = button(close, 'r', false, ops);
    if style & (WS_MAXIMIZEBOX | WS_MINIMIZEBOX) == 0 || ex_style & WS_EX_TOOLWINDOW != 0 {
        return drawn;
    }
    let (cx, cy) = (m(sm::CXSIZE), m(sm::CYSIZE));
    let height = (caption.top + 2, caption.top + cy - 2);
    // Minimize: past the close button and the maximize one.
    let right = caption.right - (cx + 1) - (cx - 2);
    let minimize = if style & WS_MINIMIZE != 0 { '2' } else { '0' };
    let rect = Rect::new(right - cx + 1, height.0, right - 1, height.1);
    drawn &= button(rect, minimize, style & WS_MINIMIZEBOX == 0, ops);
    // Maximize: past the close button.
    let right = caption.right - (cx + 1);
    let maximize = if style & WS_MAXIMIZE != 0 { '2' } else { '1' };
    let rect = Rect::new(right - cx + 1, height.0, right - 1, height.1);
    drawn &= button(rect, maximize, style & WS_MAXIMIZEBOX == 0, ops);
    drawn
}

/// UserDrawCaptionText : `text` dans le titre `caption`, en Tahoma gras (ou
/// normal pour une fenêtre d'outils), de la couleur du texte du titre actif
/// ou inactif ; de deux pixels après le bord gauche (pas encore d'icône)
/// jusqu'aux boutons, centré en hauteur, fini par « ... » s'il ne tient pas.
/// Faux sans la police.
#[expect(clippy::too_many_arguments, reason = "the caption, its window's text and styles, and the system")]
fn caption_text(
    caption: Rect,
    text: &[u16],
    active: bool,
    style: u32,
    ex_style: u32,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
    ops: &mut Vec<Op>,
) -> bool {
    if text.is_empty() {
        return true;
    }
    let small = ex_style & WS_EX_TOOLWINDOW != 0;
    let mut room = Rect::new(caption.left + 2, caption.top, caption.right, caption.bottom);
    if style & WS_SYSMENU != 0 {
        room.right -= m(sm::CYCAPTION) - 1;
        if style & (WS_MAXIMIZEBOX | WS_MINIMIZEBOX) != 0 && !small {
            room.right -= 2 * (m(sm::CXSIZE) + 1);
        }
    }
    let face = if small { Face::Tahoma } else { Face::TahomaBold };
    let width = (room.right - room.left).max(0);
    let Some(run) = layout(face, CAPTION_FONT_HEIGHT, text, Some(width), Quality::Antialiased) else {
        return false;
    };
    let top = caption.top + (caption.bottom - caption.top - run.metrics.height()) / 2;
    let baseline = top + run.metrics.ascent;
    let color = c(if active { color::CAPTIONTEXT } else { color::INACTIVECAPTIONTEXT });
    for glyph in run.glyphs {
        let at = (room.left + glyph.x + glyph.bitmap.left, baseline - glyph.bitmap.top);
        ops.push(Op::Glyph { at, bitmap: glyph.bitmap, color, clip: room });
    }
    true
}

/// NC_DoNCPaint : le cadre d'une fenêtre de style `style` et `ex_style`,
/// de `width` × `height`, de titre `text`, active ou non, en dégradé ou non
/// (`gradient`), d'après les métriques `m`, les couleurs système `c` et la
/// mise en glyphes `layout` ; et ce qu'il n'a pas pu dessiner.
#[expect(clippy::too_many_arguments, reason = "what NC_DoNCPaint reads of the window and the system")]
pub fn frame_ops(
    style: u32,
    ex_style: u32,
    (width, height): (i32, i32),
    text: &[u16],
    active: bool,
    gradient: bool,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
    layout: Layout,
) -> (Vec<Op>, Unpainted) {
    let mut ops = Vec::new();
    let mut unpainted = Unpainted::default();
    let mut current = Rect::new(0, 0, width, height);
    if has_window_edge(style, ex_style) {
        draw_edge(&mut current, EDGE_RAISED, BF_RECT | BF_ADJUST, c, &mut ops);
    } else if ex_style & WS_EX_STATICEDGE != 0 {
        let r = current;
        ops.push(Op::Fill(Rect::new(r.left, r.top, r.right, r.top + 1), c(color::BTNSHADOW)));
        ops.push(Op::Fill(Rect::new(r.left, r.top, r.left + 1, r.bottom), c(color::BTNSHADOW)));
        ops.push(Op::Fill(Rect::new(r.left, r.bottom - 1, r.right, r.bottom), c(color::BTNHIGHLIGHT)));
        ops.push(Op::Fill(Rect::new(r.right - 1, r.top, r.right, r.bottom), c(color::BTNHIGHLIGHT)));
        current = Rect::new(r.left + 1, r.top + 1, r.right - 1, r.bottom - 1);
    }
    frame(&mut current, active, style, ex_style, m, c, &mut ops);

    if style & WS_CAPTION == WS_CAPTION {
        let caption_height = if ex_style & WS_EX_TOOLWINDOW != 0 { m(sm::CYSMCAPTION) } else { m(sm::CYCAPTION) };
        let caption = Rect::new(current.left, current.top, current.right, current.top + caption_height - 1);
        current.top += caption_height;
        let (from, to) = if active {
            (color::ACTIVECAPTION, color::GRADIENTACTIVECAPTION)
        } else {
            (color::INACTIVECAPTION, color::GRADIENTINACTIVECAPTION)
        };
        if gradient {
            ops.push(Op::GradientH(caption, c(from), c(to)));
        } else {
            ops.push(Op::Fill(caption, c(from)));
        }
        unpainted.text = !caption_text(caption, text, active, style, ex_style, m, c, layout, &mut ops);
        unpainted.icon = style & WS_SYSMENU != 0 && ex_style & WS_EX_TOOLWINDOW == 0;
        if style & WS_SYSMENU != 0 && !caption_buttons(caption, style, ex_style, m, c, layout, &mut ops) {
            unpainted.text = true;
        }
        if style & WS_MINIMIZE == 0 {
            // The line under the caption.
            let index = if ex_style & (WS_EX_STATICEDGE | WS_EX_CLIENTEDGE | WS_EX_DLGMODALFRAME) == WS_EX_STATICEDGE {
                color::WINDOWFRAME
            } else {
                color::BTNFACE
            };
            ops.push(Op::Fill(Rect::new(caption.left, caption.bottom, caption.right, caption.bottom + 1), c(index)));
        }
    }
    if style & WS_MINIMIZE == 0 {
        if ex_style & WS_EX_CLIENTEDGE != 0 {
            draw_edge(&mut current, EDGE_SUNKEN, BF_RECT | BF_ADJUST, c, &mut ops);
        }
        unpainted.scroll_bars = style & (WS_VSCROLL | WS_HSCROLL) != 0;
    }
    (ops, unpainted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::{Bitmap, PixelLayout};
    use crate::gdi::draw::paint;
    use crate::gdi::region::Region;
    use abi::user::{WS_EX_WINDOWEDGE, WS_OVERLAPPEDWINDOW, WS_POPUP};

    fn metric(index: usize) -> i32 {
        crate::metrics::system_metrics(1280, 800, &crate::metrics::Parameters::DEFAULT)[index]
    }

    fn system(index: usize) -> ColorRef {
        ColorRef(crate::metrics::SYSTEM_COLORS[index])
    }

    /// A palette where each system colour is its index: what part was drawn
    /// with which colour, even where the default colours are equal.
    fn coded(index: usize) -> ColorRef {
        ColorRef(0x0001_0000 + index as u32)
    }

    /// The frame of a `width` × `height` window drawn on a surface of its
    /// size: the colour of each pixel.
    fn render(style: u32, ex_style: u32, size: (i32, i32), active: bool) -> (impl Fn(i32, i32) -> u32, Unpainted) {
        render_with(style, ex_style, size, active, &system)
    }

    /// No fonts: the frame without its text and symbols.
    fn no_fonts(_: Face, _: i32, _: &[u16], _: Option<i32>, _: Quality) -> Option<TextRun> {
        None
    }

    fn render_with(
        style: u32,
        ex_style: u32,
        (width, height): (i32, i32),
        active: bool,
        palette: &impl Fn(usize) -> ColorRef,
    ) -> (impl Fn(i32, i32) -> u32, Unpainted) {
        render_text(style, ex_style, (width, height), &[], active, true, palette, &no_fonts)
    }

    #[expect(clippy::too_many_arguments, reason = "what frame_ops takes")]
    fn render_text(
        style: u32,
        ex_style: u32,
        (width, height): (i32, i32),
        text: &[u16],
        active: bool,
        gradient: bool,
        palette: &impl Fn(usize) -> ColorRef,
        layout: Layout,
    ) -> (impl Fn(i32, i32) -> u32, Unpainted) {
        let (ops, unpainted) =
            frame_ops(style, ex_style, (width, height), text, active, gradient, &metric, palette, layout);
        let mut pixels = alloc::vec![0u32; (width * height) as usize];
        let mut surface =
            Bitmap::new(&mut pixels, width as u32, height as u32, width as u32, PixelLayout::Rgbx).unwrap();
        paint(&mut surface, &ops, (0, 0), &Region::from_rect(Rect::new(0, 0, width, height)));
        (move |x: i32, y: i32| pixels[(y * width + x) as usize], unpainted)
    }

    #[test]
    fn an_overlapped_window_has_an_edge_a_frame_and_a_caption() {
        let (at, unpainted) = render(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (200, 100), false);
        assert_eq!((at(0, 0), at(1, 1)), (system(color::LIGHT_3D).0, system(color::BTNHIGHLIGHT).0), "the edge");
        assert_eq!((at(199, 99), at(198, 98)), (system(color::DKSHADOW_3D).0, system(color::BTNSHADOW).0));
        assert_eq!((at(2, 50), at(3, 50)), (system(color::INACTIVEBORDER).0, system(color::BTNFACE).0), "frames");
        assert_eq!(at(4, 4), system(color::INACTIVECAPTION).0, "the caption, from its first colour");
        assert_eq!(at(4, 22), system(color::INACTIVECAPTION).0, "19 rows");
        assert_eq!(at(10, 23), system(color::BTNFACE).0, "the line under the caption");
        assert_eq!(at(10, 24), 0, "the client area is not the frame's");
        assert_eq!((at(196, 50), at(197, 50)), (system(color::BTNFACE).0, system(color::INACTIVEBORDER).0), "right");
        assert_eq!(unpainted, Unpainted { text: true, icon: true, scroll_bars: false });
    }

    #[test]
    fn the_caption_goes_toward_its_gradient_colour() {
        let (at, _) = render(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (200, 100), true);
        assert_eq!(at(4, 10), system(color::ACTIVECAPTION).0, "active");
        let last = crate::gdi::draw::gradient_color(
            system(color::ACTIVECAPTION),
            system(color::GRADIENTACTIVECAPTION),
            4,
            196,
            120,
        );
        assert_eq!(at(120, 4), last.0, "the left of the buttons");
    }

    #[test]
    fn the_buttons_are_raised_with_a_face() {
        let (at, _) = render(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (200, 100), false);
        // Close: 177 to 194, 6 to 21; maximize: 158 to 175; minimize: 141 to 158.
        assert_eq!(at(177, 6), system(color::BTNHIGHLIGHT).0, "close, soft outer edge");
        assert_eq!(at(185, 13), system(color::BTNFACE).0, "its face (no symbol without Marlett)");
        assert_eq!(at(193, 20), system(color::DKSHADOW_3D).0, "its bottom-right");
        assert_eq!((at(158, 6), at(166, 13)), (system(color::BTNHIGHLIGHT).0, system(color::BTNFACE).0), "maximize");
        assert_eq!(
            (at(141, 6), at(157, 20)),
            (system(color::BTNHIGHLIGHT).0, system(color::DKSHADOW_3D).0),
            "minimize"
        );
        assert_ne!(at(176, 13), system(color::BTNFACE).0, "a gap between maximize and close: the caption");
    }

    #[test]
    fn frames_without_a_caption_or_with_a_client_edge() {
        let (ops, unpainted) = frame_ops(WS_POPUP, 0, (50, 50), &[], false, true, &metric, &system, &no_fonts);
        assert!(ops.is_empty() && unpainted == Unpainted::default(), "a popup has no frame");
        let (at, _) = render(WS_POPUP | WS_BORDER, 0, (20, 20), false);
        assert_eq!((at(0, 0), at(1, 1)), (system(color::WINDOWFRAME).0, 0), "a thin border");
        let (at, _) = render(WS_POPUP, WS_EX_CLIENTEDGE, (20, 20), false);
        assert_eq!((at(0, 0), at(1, 1)), (system(color::BTNSHADOW).0, system(color::DKSHADOW_3D).0), "sunken");
        let (at, _) = render(WS_POPUP, WS_EX_STATICEDGE, (20, 20), false);
        assert_eq!((at(0, 5), at(19, 5)), (system(color::BTNSHADOW).0, system(color::BTNHIGHLIGHT).0), "static");
        let (_, scrolled) = render(WS_POPUP | WS_VSCROLL, 0, (20, 20), false);
        assert!(scrolled.scroll_bars);
    }

    #[test]
    fn a_tool_window_has_a_small_caption_and_one_button() {
        let style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let (at, unpainted) = render(style, WS_EX_TOOLWINDOW | WS_EX_WINDOWEDGE, (100, 60), false);
        // Edge 2, thin frame 1: the caption from 3, 15 high (16 - 1), the line at 18.
        assert_eq!((at(3, 17), at(10, 18)), (system(color::INACTIVECAPTION).0, system(color::BTNFACE).0));
        assert!(!unpainted.icon, "no icon in a tool window");
        // The close button only, a small one.
        let left = 97 - metric(sm::CXSMSIZE);
        assert_eq!(at(left, 5), system(color::BTNHIGHLIGHT).0);
        assert_ne!(at(left - 1, 8), system(color::BTNFACE).0, "nothing left of it");
        assert_ne!(at(66, 10), system(color::BTNFACE).0, "no minimize or maximize button");
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The pixels of `area` with the colour of the system colour `index`.
    fn count(at: &impl Fn(i32, i32) -> u32, area: Rect, index: usize) -> usize {
        (area.top..area.bottom)
            .flat_map(|y| (area.left..area.right).map(move |x| (x, y)))
            .filter(|&(x, y)| at(x, y) == coded(index).0)
            .count()
    }

    /// The buttons of a window whose caption ends at x = 196 (an overlapped
    /// window 200 pixels wide): close, maximize, minimize.
    fn buttons() -> [Rect; 3] {
        let (cx, cy) = (metric(sm::CXSIZE), metric(sm::CYSIZE));
        let (top, bottom) = (6, 4 + cy - 2);
        let close = Rect::new(196 - cx, top, 196 - 2, bottom);
        let right = 196 - (cx + 1);
        let maximize = Rect::new(right - cx + 1, top, right - 1, bottom);
        let right = right - (cx - 2);
        [close, maximize, Rect::new(right - cx + 1, top, right - 1, bottom)]
    }

    /// The caption of `text`, without the gradient: each pixel's colour code
    /// is that of one system colour.
    fn render_caption(style: u32, text: &str, active: bool) -> (impl Fn(i32, i32) -> u32, Unpainted) {
        let layout: Layout = &crate::font::text_run;
        render_text(style, WS_EX_WINDOWEDGE, (200, 100), &units(text), active, false, &coded, layout)
    }

    #[test]
    fn the_caption_shows_its_text_and_the_buttons_their_symbols() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let (at, unpainted) = render_caption(WS_OVERLAPPEDWINDOW, "Mino", true);
        assert!(!unpainted.text, "text and symbols drawn");
        // The caption from (4, 4) to (196, 23), 19 rows: the text from x = 6,
        // its cell of 13 pixels from y = 4 + (19 - 13) / 2 = 7, its baseline
        // at 18; capitals of 8 pixels from 10.
        let text = Rect::new(6, 4, 60, 23);
        assert!(count(&at, text, color::CAPTIONTEXT) > 20, "the text, in the active caption's text colour");
        assert_eq!(count(&at, Rect::new(4, 4, 6, 23), color::CAPTIONTEXT), 0, "two pixels left of the text");
        assert_eq!(count(&at, Rect::new(6, 4, 196, 9), color::CAPTIONTEXT), 0, "nothing above its capitals");
        assert_eq!(count(&at, Rect::new(6, 18, 60, 23), color::CAPTIONTEXT), 0, "nothing below its baseline");
        assert!(count(&at, Rect::new(6, 17, 60, 18), color::CAPTIONTEXT) > 4, "its last row on the baseline");
        assert_eq!(count(&at, Rect::new(60, 4, 140, 23), color::CAPTIONTEXT), 0, "nothing past the text");
        for (name, button) in ["close", "maximize", "minimize"].into_iter().zip(buttons()) {
            assert!(count(&at, button, color::BTNTEXT) > 4, "the {name} symbol");
        }
        let (inactive, _) = render_caption(WS_OVERLAPPEDWINDOW, "Mino", false);
        // Fully covered pixels only: antialiased ones mix two codes.
        assert!(count(&inactive, text, color::INACTIVECAPTIONTEXT) > 20, "the inactive caption's text colour");
    }

    #[test]
    fn a_long_caption_stops_before_the_buttons() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let (at, _) =
            render_caption(WS_OVERLAPPEDWINDOW, "A caption far too long for a window of two hundred pixels", true);
        // Room to x = 196 - (19 - 1) - 2 × (18 + 1) = 140.
        let room_right = 196 - (metric(sm::CYCAPTION) - 1) - 2 * (metric(sm::CXSIZE) + 1);
        assert_eq!(count(&at, Rect::new(room_right, 4, 196, 23), color::CAPTIONTEXT), 0, "nothing past the room");
        // It ends with dots: on the baseline only, where a letter cut at the
        // edge would reach up to the capitals.
        let last = (6..room_right).rev().find(|&x| (4..23).any(|y| at(x, y) == coded(color::CAPTIONTEXT).0)).unwrap();
        assert!(last > room_right - 12, "the text goes up to the buttons");
        assert_eq!(count(&at, Rect::new(last - 8, 4, last + 1, 15), color::CAPTIONTEXT), 0, "dots, not letters");
        assert!(count(&at, Rect::new(last - 8, 15, last + 1, 18), color::CAPTIONTEXT) > 0, "dots");
    }

    #[test]
    fn a_button_without_its_style_is_greyed() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        // A minimize box only: maximize is drawn, greyed.
        let (at, _) = render_caption(WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, "", true);
        let [close, maximize, minimize] = buttons();
        let face = Rect::new(maximize.left + 2, maximize.top + 2, maximize.right - 2, maximize.bottom - 2);
        assert_eq!(count(&at, maximize, color::BTNTEXT), 0, "no active maximize symbol");
        assert!(count(&at, face, color::BTNSHADOW) > 4, "a grey one");
        assert!(count(&at, face, color::BTNHIGHLIGHT) > 4, "with its light shadow");
        assert!(count(&at, minimize, color::BTNTEXT) > 4 && count(&at, close, color::BTNTEXT) > 4, "the others");
    }

    #[test]
    fn each_part_has_its_colour() {
        let (inactive, _) = render_with(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (200, 100), false, &coded);
        let (active, _) = render_with(WS_OVERLAPPEDWINDOW, WS_EX_WINDOWEDGE, (200, 100), true, &coded);
        assert_eq!((inactive(2, 50), active(2, 50)), (coded(color::INACTIVEBORDER).0, coded(color::ACTIVEBORDER).0));
        assert_eq!(inactive(3, 50), coded(color::BTNFACE).0, "the thin frame");
        assert_eq!(inactive(4, 4), coded(color::INACTIVECAPTION).0);
        assert_eq!(active(4, 4), coded(color::ACTIVECAPTION).0);
        assert_eq!(inactive(185, 13), coded(color::BTNFACE).0, "a button face");
    }
}
