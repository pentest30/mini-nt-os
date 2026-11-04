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
//! Pas encore (ce que rend [`Unpainted`]) : le texte du titre et les
//! symboles des boutons (polices, ADR-013), l'icône de la fenêtre (icônes),
//! les barres de défilement, la barre de menus.

use alloc::vec::Vec;

use abi::user::WS_BORDER;
use abi::user::{
    color, sm, WS_CAPTION, WS_DLGFRAME, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME, WS_EX_STATICEDGE, WS_EX_TOOLWINDOW,
    WS_HSCROLL, WS_MAXIMIZEBOX, WS_MINIMIZE, WS_MINIMIZEBOX, WS_SYSMENU, WS_THICKFRAME, WS_VSCROLL,
};

use crate::defwnd::has_window_edge;
use crate::gdi::dib::{ColorRef, Rect};
use crate::gdi::draw::{draw_edge, Op, BF_ADJUST, BF_MIDDLE, BF_RECT, BF_SOFT, EDGE_RAISED, EDGE_SUNKEN};

/// Ce que le cadre aurait et qui n'est pas dessiné.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unpainted {
    /// Le texte du titre, les symboles des boutons (polices).
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

/// Les boutons du titre `caption` (UserDrawCaptionButton) : fermer, puis
/// réduire et agrandir, des boutons en relief doux (DrawFrameControl
/// `DFC_CAPTION`).
fn caption_buttons(
    caption: Rect,
    style: u32,
    ex_style: u32,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
    ops: &mut Vec<Op>,
) {
    let mut button = |rect: Rect| {
        draw_edge(&mut rect.clone(), EDGE_RAISED, BF_RECT | BF_MIDDLE | BF_SOFT, c, ops);
    };
    let (cx, cy) = if ex_style & WS_EX_TOOLWINDOW != 0 {
        (m(sm::CXSMSIZE), m(sm::CYSMSIZE))
    } else {
        (m(sm::CXSIZE), m(sm::CYSIZE))
    };
    button(Rect::new(caption.right - cx, caption.top + 2, caption.right - 2, caption.top + cy - 2));
    if style & (WS_MAXIMIZEBOX | WS_MINIMIZEBOX) == 0 || ex_style & WS_EX_TOOLWINDOW != 0 {
        return;
    }
    let (cx, cy) = (m(sm::CXSIZE), m(sm::CYSIZE));
    let height = (caption.top + 2, caption.top + cy - 2);
    // Minimize: past the close button and the maximize one.
    let right = caption.right - (cx + 1) - (cx - 2);
    button(Rect::new(right - cx + 1, height.0, right - 1, height.1));
    // Maximize: past the close button.
    let right = caption.right - (cx + 1);
    button(Rect::new(right - cx + 1, height.0, right - 1, height.1));
}

/// NC_DoNCPaint : le cadre d'une fenêtre de style `style` et `ex_style`,
/// de `width` × `height`, active ou non, en dégradé ou non (`gradient`),
/// d'après les métriques `m` et les couleurs système `c` ; et ce qu'il n'a
/// pas pu dessiner.
pub fn frame_ops(
    style: u32,
    ex_style: u32,
    (width, height): (i32, i32),
    active: bool,
    gradient: bool,
    m: &impl Fn(usize) -> i32,
    c: &impl Fn(usize) -> ColorRef,
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
        unpainted.text = true;
        unpainted.icon = style & WS_SYSMENU != 0 && ex_style & WS_EX_TOOLWINDOW == 0;
        if style & WS_SYSMENU != 0 {
            caption_buttons(caption, style, ex_style, m, c, &mut ops);
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

    fn render_with(
        style: u32,
        ex_style: u32,
        (width, height): (i32, i32),
        active: bool,
        palette: &impl Fn(usize) -> ColorRef,
    ) -> (impl Fn(i32, i32) -> u32, Unpainted) {
        let (ops, unpainted) = frame_ops(style, ex_style, (width, height), active, true, &metric, palette);
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
        assert_eq!(at(185, 13), system(color::BTNFACE).0, "its face (no symbol yet)");
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
        let (ops, unpainted) = frame_ops(WS_POPUP, 0, (50, 50), false, true, &metric, &system);
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
