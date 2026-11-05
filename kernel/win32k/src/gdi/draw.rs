//! Les dessins de USER dans le noyau (draw.c de ReactOS, comme
//! spécification) : une suite d'opérations ([`Op`]) sur des rectangles, que
//! [`paint`] fait sur une surface, coupées à une région ; les bords en
//! relief ([`draw_edge`], DrawEdge).
//!
//! Une opération est en coordonnées de son contexte (une fenêtre) : [`paint`]
//! la décale de son origine avant de la couper.
//!
//! Le texte y est une suite de glyphes rendus ([`Op::Glyph`], `crate::font`).
//!
//! Pas encore : les bords plats et monochromes (`BF_FLAT`, `BF_MONO`) et
//! diagonaux (`BF_DIAGONAL`), les lignes quelconques, les icônes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::dib::{Bitmap, ColorRef, Rect};
use super::region::Region;
use abi::user::color;

/// Une opération de dessin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// PatBlt d'un pinceau plein (PATCOPY).
    Fill(Rect, ColorRef),
    /// GradientFill horizontal (GRADIENT_FILL_RECT_H) : de la première
    /// couleur, à gauche, vers la seconde, à droite.
    GradientH(Rect, ColorRef, ColorRef),
    /// Un glyphe rendu en `color` (ExtTextOut, fond transparent), son coin en
    /// `at`, coupé à `clip` (ETO_CLIPPED).
    Glyph { at: (i32, i32), bitmap: Arc<glyph::Bitmap>, color: ColorRef, clip: Rect },
}

/// La couleur de la colonne `x` d'un dégradé de `from` à `to` entre `left`
/// (inclus) et `right` (exclus) : chaque composante interpolée en ligne.
pub fn gradient_color(from: ColorRef, to: ColorRef, left: i32, right: i32, x: i32) -> ColorRef {
    let width = i64::from((right - left).max(1));
    let position = i64::from(x - left);
    let mix = |a: u8, b: u8| (i64::from(a) + (i64::from(b) - i64::from(a)) * position / width) as u8;
    let (fr, fg, fb) = from.components();
    let (tr, tg, tb) = to.components();
    ColorRef::rgb(mix(fr, tr), mix(fg, tg), mix(fb, tb))
}

/// Fait `ops`, en coordonnées d'un contexte d'origine `origin` (à l'écran),
/// sur `surface`, dans la région `clip` (à l'écran).
pub fn paint(surface: &mut Bitmap<'_>, ops: &[Op], origin: (i32, i32), clip: &Region) {
    let moved = |r: Rect| Rect::new(r.left + origin.0, r.top + origin.1, r.right + origin.0, r.bottom + origin.1);
    for op in ops {
        for &visible in clip.rects() {
            match op {
                &Op::Fill(rect, color) => surface.fill_rect(moved(rect).intersect(&visible), color),
                Op::Glyph { at, bitmap, color, clip } => {
                    let at = (at.0 + origin.0, at.1 + origin.1);
                    let clip = moved(*clip).intersect(&visible);
                    surface.blend_coverage(at, bitmap.width, &bitmap.coverage, *color, clip);
                }
                &Op::GradientH(rect, from, to) => {
                    let rect = moved(rect);
                    let part = rect.intersect(&visible);
                    for x in part.left..part.right {
                        let column = Rect::new(x, part.top, x + 1, part.bottom);
                        surface.fill_rect(column, gradient_color(from, to, rect.left, rect.right, x));
                    }
                }
            }
        }
    }
}

/// BDR_*, BF_* et EDGE_* de DrawEdge.
pub const BDR_RAISEDOUTER: u32 = 0x0001;
pub const BDR_SUNKENOUTER: u32 = 0x0002;
pub const BDR_RAISEDINNER: u32 = 0x0004;
pub const BDR_SUNKENINNER: u32 = 0x0008;
pub const EDGE_RAISED: u32 = BDR_RAISEDOUTER | BDR_RAISEDINNER;
pub const EDGE_SUNKEN: u32 = BDR_SUNKENOUTER | BDR_SUNKENINNER;
pub const BF_LEFT: u32 = 0x0001;
pub const BF_TOP: u32 = 0x0002;
pub const BF_RIGHT: u32 = 0x0004;
pub const BF_BOTTOM: u32 = 0x0008;
pub const BF_RECT: u32 = BF_LEFT | BF_TOP | BF_RIGHT | BF_BOTTOM;
pub const BF_MIDDLE: u32 = 0x0800;
pub const BF_SOFT: u32 = 0x1000;
pub const BF_ADJUST: u32 = 0x2000;

/// Les couleurs système des quatre traits d'un bord : en haut et à gauche
/// (extérieur, intérieur), en bas et à droite (extérieur, intérieur) ;
/// `None` pour un trait absent. Un bord extérieur en relief est clair en
/// haut à gauche (`COLOR_3DLIGHT`, ou `COLOR_BTNHIGHLIGHT` en relief doux)
/// et très sombre en bas à droite (`COLOR_3DDKSHADOW`), un bord intérieur en
/// relief blanc (`COLOR_3DLIGHT` doux) puis ombré (`COLOR_BTNSHADOW`) ; un
/// bord creux l'inverse. Un bord intérieur seul se trace à la place de
/// l'extérieur.
fn edge_colors(edge: u32, soft: bool) -> [Option<usize>; 4] {
    let outer = match edge & (BDR_RAISEDOUTER | BDR_SUNKENOUTER) {
        BDR_RAISEDOUTER => Some((if soft { color::BTNHIGHLIGHT } else { color::LIGHT_3D }, color::DKSHADOW_3D)),
        BDR_SUNKENOUTER => Some((if soft { color::DKSHADOW_3D } else { color::BTNSHADOW }, color::BTNHIGHLIGHT)),
        _ => None,
    };
    let inner = match edge & (BDR_RAISEDINNER | BDR_SUNKENINNER) {
        BDR_RAISEDINNER => Some((if soft { color::LIGHT_3D } else { color::BTNHIGHLIGHT }, color::BTNSHADOW)),
        BDR_SUNKENINNER => Some((if soft { color::BTNSHADOW } else { color::DKSHADOW_3D }, color::LIGHT_3D)),
        _ => None,
    };
    match (outer, inner) {
        (Some(outer), inner) => [Some(outer.0), inner.map(|i| i.0), Some(outer.1), inner.map(|i| i.1)],
        (None, Some(inner)) if edge & (BDR_RAISEDOUTER | BDR_SUNKENOUTER) == 0 => {
            [Some(inner.0), None, Some(inner.1), None]
        }
        _ => [None; 4],
    }
}

/// IntDrawRectEdge : le bord `edge` (`BDR_*`) des côtés `flags` (`BF_*`) de
/// `rect`, ajouté à `ops` dans les couleurs `colors` ; avec `BF_MIDDLE`, le
/// milieu d'abord de `COLOR_BTNFACE` ; avec `BF_ADJUST`, `rect` devient ce
/// qui reste dedans. Rend FALSE pour un bord à la fois en relief et creux.
pub fn draw_edge(
    rect: &mut Rect,
    edge: u32,
    flags: u32,
    colors: &impl Fn(usize) -> ColorRef,
    ops: &mut Vec<Op>,
) -> bool {
    let valid = edge & (BDR_RAISEDINNER | BDR_SUNKENINNER) != (BDR_RAISEDINNER | BDR_SUNKENINNER)
        && edge & (BDR_RAISEDOUTER | BDR_SUNKENOUTER) != (BDR_RAISEDOUTER | BDR_SUNKENOUTER);
    let [lt_outer, lt_inner, rb_outer, rb_inner] = edge_colors(edge, flags & BF_SOFT != 0);
    let r = *rect;
    if flags & BF_MIDDLE != 0 && valid {
        ops.push(Op::Fill(r, colors(color::BTNFACE)));
    }
    let both = |side: u32| u32::from(flags & side == side);
    let (lb, rt, rb, lt) =
        (both(BF_BOTTOM | BF_LEFT), both(BF_TOP | BF_RIGHT), both(BF_BOTTOM | BF_RIGHT), both(BF_TOP | BF_LEFT));
    let (lb, rt, rb, lt) = (lb as i32, rt as i32, rb as i32, lt as i32);
    let mut line = |color: Option<usize>, rect: Rect| {
        if let Some(color) = color {
            ops.push(Op::Fill(rect, colors(color)));
        }
    };
    // The outer lines, then the inner ones.
    if flags & BF_TOP != 0 {
        line(lt_outer, Rect::new(r.left, r.top, r.right, r.top + 1));
    }
    if flags & BF_LEFT != 0 {
        line(lt_outer, Rect::new(r.left, r.top, r.left + 1, r.bottom));
    }
    if flags & BF_BOTTOM != 0 {
        line(rb_outer, Rect::new(r.left, r.bottom - 1, r.right, r.bottom));
    }
    if flags & BF_RIGHT != 0 {
        line(rb_outer, Rect::new(r.right - 1, r.top, r.right, r.bottom));
    }
    if flags & BF_TOP != 0 {
        line(lt_inner, Rect::new(r.left + lt, r.top + 1, r.right - rt, r.top + 2));
    }
    if flags & BF_LEFT != 0 {
        line(lt_inner, Rect::new(r.left + 1, r.top + lt, r.left + 2, r.bottom - lb));
    }
    if flags & BF_BOTTOM != 0 {
        line(rb_inner, Rect::new(r.left + lb, r.bottom - 2, r.right - rb, r.bottom - 1));
    }
    if flags & BF_RIGHT != 0 {
        line(rb_inner, Rect::new(r.right - 2, r.top + rt, r.right - 1, r.bottom - rb));
    }
    if (flags & BF_MIDDLE != 0 && valid) || flags & BF_ADJUST != 0 {
        // As many lines as the edge has, outer and inner.
        let lines = i32::from(edge & 0xF != 0) + i32::from(edge & 0x3 != 0 && edge & 0xC != 0);
        let mut inside = r;
        if flags & BF_LEFT != 0 {
            inside.left += lines;
        }
        if flags & BF_RIGHT != 0 {
            inside.right -= lines;
        }
        if flags & BF_TOP != 0 {
            inside.top += lines;
        }
        if flags & BF_BOTTOM != 0 {
            inside.bottom -= lines;
        }
        if flags & BF_ADJUST != 0 {
            *rect = inside;
        }
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::PixelLayout;

    fn system(index: usize) -> ColorRef {
        ColorRef(crate::metrics::SYSTEM_COLORS[index])
    }

    /// The colour at (x, y) of `ops` drawn on a 16 × 16 surface.
    fn render(ops: &[Op]) -> impl Fn(i32, i32) -> u32 {
        let mut pixels = alloc::vec![0u32; 16 * 16];
        let mut surface = Bitmap::new(&mut pixels, 16, 16, 16, PixelLayout::Rgbx).unwrap();
        paint(&mut surface, ops, (0, 0), &Region::from_rect(Rect::new(0, 0, 16, 16)));
        move |x, y| pixels[(y * 16 + x) as usize]
    }

    #[test]
    fn a_raised_edge_is_light_then_dark() {
        let mut rect = Rect::new(0, 0, 10, 8);
        let mut ops = Vec::new();
        assert!(draw_edge(&mut rect, EDGE_RAISED, BF_RECT | BF_ADJUST, &system, &mut ops));
        assert_eq!(rect, Rect::new(2, 2, 8, 6), "two lines on each side");
        let at = render(&ops);
        assert_eq!(at(0, 0), system(color::LIGHT_3D).0, "outer top-left");
        assert_eq!(at(1, 1), system(color::BTNHIGHLIGHT).0, "inner top-left");
        assert_eq!(at(9, 7), system(color::DKSHADOW_3D).0, "outer bottom-right");
        assert_eq!(at(8, 6), system(color::BTNSHADOW).0, "inner bottom-right");
        assert_eq!(at(7, 1), system(color::BTNHIGHLIGHT).0, "the inner top line");
        assert_eq!(at(8, 1), system(color::BTNSHADOW).0, "the inner right line, drawn after, takes the corner");
        assert_eq!(at(1, 6), system(color::BTNSHADOW).0, "and the inner bottom one");
        assert_eq!(
            (at(8, 0), at(8, 7)),
            (system(color::LIGHT_3D).0, system(color::DKSHADOW_3D).0),
            "inner lines stop at the outer ones"
        );
        assert_eq!(at(4, 4), 0, "the middle left alone");
    }

    #[test]
    fn sunken_soft_and_middle() {
        let mut ops = Vec::new();
        let mut rect = Rect::new(0, 0, 6, 6);
        draw_edge(&mut rect, EDGE_SUNKEN, BF_RECT, &system, &mut ops);
        assert_eq!(rect, Rect::new(0, 0, 6, 6), "no BF_ADJUST");
        let at = render(&ops);
        assert_eq!((at(0, 0), at(1, 1)), (system(color::BTNSHADOW).0, system(color::DKSHADOW_3D).0));
        assert_eq!((at(5, 5), at(4, 4)), (system(color::BTNHIGHLIGHT).0, system(color::LIGHT_3D).0));
        let mut button = Vec::new();
        draw_edge(&mut Rect::new(0, 0, 6, 6), EDGE_RAISED, BF_RECT | BF_MIDDLE | BF_SOFT, &system, &mut button);
        let at = render(&button);
        assert_eq!((at(0, 0), at(1, 1)), (system(color::BTNHIGHLIGHT).0, system(color::LIGHT_3D).0), "soft");
        assert_eq!(at(3, 3), system(color::BTNFACE).0, "the middle");
        let mut nothing = Vec::new();
        assert!(!draw_edge(&mut Rect::new(0, 0, 6, 6), EDGE_RAISED | BDR_SUNKENOUTER, BF_RECT, &system, &mut nothing));
        assert!(nothing.iter().all(|op| !matches!(op, Op::Fill(r, _) if r.left == 0 && r.top == 0 && r.bottom == 1)));
    }

    #[test]
    fn an_inner_edge_alone_takes_the_outer_line() {
        assert_eq!(edge_colors(BDR_RAISEDOUTER | BDR_SUNKENOUTER | BDR_RAISEDINNER, false), [None; 4], "no outer edge");
        assert_eq!(
            edge_colors(BDR_RAISEDOUTER | BDR_RAISEDINNER | BDR_SUNKENINNER, false),
            [Some(color::LIGHT_3D), None, Some(color::DKSHADOW_3D), None],
            "no inner edge"
        );
        assert_eq!(edge_colors(BDR_SUNKENINNER, false), [Some(color::DKSHADOW_3D), None, Some(color::LIGHT_3D), None]);
        let mut rect = Rect::new(0, 0, 6, 6);
        draw_edge(&mut rect, BDR_SUNKENINNER, BF_RECT | BF_ADJUST, &system, &mut Vec::new());
        assert_eq!(rect, Rect::new(1, 1, 5, 5), "one line");
    }

    #[test]
    fn gradients_go_from_left_to_right() {
        let (from, to) = (ColorRef::rgb(0, 100, 200), ColorRef::rgb(100, 100, 0));
        assert_eq!(gradient_color(from, to, 10, 20, 10), from);
        assert_eq!(gradient_color(from, to, 10, 20, 15), ColorRef::rgb(50, 100, 100));
        assert_eq!(gradient_color(from, to, 10, 20, 19), ColorRef::rgb(90, 100, 20));
        let at = render(&[Op::GradientH(Rect::new(0, 0, 10, 2), from, to)]);
        assert_eq!((at(0, 0), at(5, 1)), (from.0, ColorRef::rgb(50, 100, 100).0));
    }

    #[test]
    fn drawing_follows_the_origin_and_the_clip() {
        let mut pixels = alloc::vec![0u32; 16 * 16];
        let mut surface = Bitmap::new(&mut pixels, 16, 16, 16, PixelLayout::Rgbx).unwrap();
        let mut clip = Region::from_rect(Rect::new(0, 0, 16, 16));
        clip.subtract_rect(Rect::new(6, 6, 8, 8));
        paint(&mut surface, &[Op::Fill(Rect::new(0, 0, 4, 4), ColorRef(1))], (5, 5), &clip);
        let at = |x: usize, y: usize| pixels[y * 16 + x];
        assert_eq!((at(5, 5), at(8, 8), at(4, 5), at(9, 5)), (1, 1, 0, 0), "moved to 5, 5");
        assert_eq!(at(6, 6), 0, "clipped");
    }
}
