//! La géométrie des polygones (`polyfill.c` et `line.c` de ReactOS, comme
//! spécification) : les pixels qu'un polygone couvre, en lignes de balayage
//! ([`spans`]), pour Polygon, PolyPolygon et CreatePolyPolygonRgn ; les
//! courbes de Bézier réduites à des segments ([`flatten_beziers`],
//! GDI_Bezier), pour PolyBezier.
//!
//! Un pixel est dans un polygone quand son centre y est : c'est la règle des
//! régions de GDI (un polygone aux sommets entiers couvre ses bords gauche
//! et haut, pas ses bords droit et bas). ReactOS suit chaque arête par
//! Bresenham, ce qui diffère d'un pixel à leurs bouts ; avec les centres,
//! Polygon et la région du même polygone couvrent les mêmes pixels, et des
//! polygones qui se touchent (les bandes d'un dégradé de VCL) se pavent sans
//! trou ni recouvrement.
//!
//! Les polygones d'un PolyPolygon se remplissent ensemble, selon le mode
//! (SetPolyFillMode) : ALTERNATE, un pixel est dedans quand une demi-droite
//! qui en part coupe un nombre impair d'arêtes ; WINDING, quand les arêtes
//! tournent autour de lui un nombre non nul de fois. Un trou reste vide,
//! comme sous XP ; ReactOS remplit chaque polygone à part.
//!
//! Les coordonnées sont bornées à ±2^27 ([`COORDINATE_LIMIT`]), comme celles
//! des périphériques de NT : les calculs tiennent sur 64 bits, et un
//! polygone démesuré ne se parcourt que sur les lignes de la zone demandée.

use alloc::vec::Vec;

use abi::gdi::WINDING;

use super::dib::Rect;

/// La borne des coordonnées (2^27 − 1).
pub const COORDINATE_LIMIT: i32 = (1 << 27) - 1;

/// Le mode de remplissage d'un polygone (SetPolyFillMode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillMode {
    /// ALTERNATE : un nombre impair d'arêtes.
    Alternate,
    /// WINDING : un tour non nul.
    Winding,
}

impl FillMode {
    /// Le mode `mode` d'un DC (`lFillMode`) : WINDING, ou ALTERNATE pour
    /// toute autre valeur (celui d'un DC neuf).
    pub const fn from_mode(mode: i32) -> Self {
        if mode == WINDING {
            Self::Winding
        } else {
            Self::Alternate
        }
    }
}

/// `point` borné à ±[`COORDINATE_LIMIT`].
pub fn clamp_point((x, y): (i32, i32)) -> (i32, i32) {
    (x.clamp(-COORDINATE_LIMIT, COORDINATE_LIMIT), y.clamp(-COORDINATE_LIMIT, COORDINATE_LIMIT))
}

/// Une arête qui n'est pas horizontale, de haut en bas : de (`x0`, `y0`) à
/// (`x1`, `y1`), `y0 < y1`, et son sens (+1 : elle descendait, −1 : elle
/// montait).
#[derive(Clone, Copy, Debug)]
struct Edge {
    x0: i64,
    y0: i64,
    x1: i64,
    y1: i64,
    winding: i32,
}

impl Edge {
    /// L'arête de `from` à `to` (bornés) ; `None` si elle est horizontale :
    /// elle ne coupe aucune ligne de centres.
    fn new(from: (i32, i32), to: (i32, i32)) -> Option<Self> {
        let (from, to) = (clamp_point(from), clamp_point(to));
        let (top, bottom, winding) = match from.1.cmp(&to.1) {
            core::cmp::Ordering::Equal => return None,
            core::cmp::Ordering::Less => (from, to, 1),
            core::cmp::Ordering::Greater => (to, from, -1),
        };
        Some(Self {
            x0: i64::from(top.0),
            y0: i64::from(top.1),
            x1: i64::from(bottom.0),
            y1: i64::from(bottom.1),
            winding,
        })
    }

    /// Sur la ligne `y` (son centre en `y` + ½, entre `y0` inclus et `y1`
    /// exclus), le premier pixel dont le centre est sur l'arête ou à sa
    /// droite : ⌈x − ½⌉, x l'abscisse de l'arête à cette hauteur. En
    /// demi-unités, sur 64 bits (les coordonnées bornées à 2^27).
    fn crossing(&self, y: i64) -> i64 {
        let height = 2 * (self.y1 - self.y0);
        let numerator = 2 * self.x0 * height + 2 * (self.x1 - self.x0) * (2 * y + 1 - 2 * self.y0) - height;
        let denominator = 2 * height;
        numerator.div_euclid(denominator) + i64::from(numerator.rem_euclid(denominator) != 0)
    }
}

/// Les pixels des polygones `polygons` (chacun fermé, de son dernier point
/// au premier ; ceux de moins de deux points ne comptent pas), remplis
/// ensemble selon `mode`, dans `within` : des rectangles disjoints, ligne
/// après ligne, ceux de lignes voisines aux mêmes colonnes réunis.
pub fn spans(polygons: &[&[(i32, i32)]], mode: FillMode, within: Rect) -> Vec<Rect> {
    let mut edges: Vec<Edge> = Vec::new();
    for polygon in polygons.iter().filter(|polygon| polygon.len() >= 2) {
        for (index, &from) in polygon.iter().enumerate() {
            edges.extend(Edge::new(from, polygon[(index + 1) % polygon.len()]));
        }
    }
    let mut out = Vec::new();
    if edges.is_empty() || within.is_empty() {
        return out;
    }
    let top = edges.iter().map(|edge| edge.y0).min().unwrap_or(0).max(i64::from(within.top));
    let bottom = edges.iter().map(|edge| edge.y1).max().unwrap_or(0).min(i64::from(within.bottom));
    edges.sort_unstable_by_key(|edge| edge.y0);
    let (left, right) = (i64::from(within.left), i64::from(within.right));
    let mut next = 0;
    let mut active: Vec<Edge> = Vec::new();
    let mut crossings: Vec<(i64, i32)> = Vec::new();
    // Les morceaux de la ligne d'avant, et où leurs rectangles commencent
    // dans `out` : une ligne qui a les mêmes les prolonge.
    let mut previous: Vec<(i32, i32)> = Vec::new();
    let mut previous_at = 0;
    let mut row: Vec<(i32, i32)> = Vec::new();
    for y in top..bottom {
        while next < edges.len() && edges[next].y0 <= y {
            active.push(edges[next]);
            next += 1;
        }
        active.retain(|edge| edge.y1 > y);
        crossings.clear();
        crossings.extend(active.iter().map(|edge| (edge.crossing(y), edge.winding)));
        crossings.sort_unstable_by_key(|&(x, _)| x);
        row.clear();
        let mut push = |start: i64, end: i64| {
            let (start, end) = (start.max(left), end.min(right));
            if start >= end {
                return;
            }
            // Bounded by `within`: back to 32 bits.
            let (start, end) = (start as i32, end as i32);
            match row.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => row.push((start, end)),
            }
        };
        match mode {
            FillMode::Alternate => {
                for pair in crossings.chunks_exact(2) {
                    push(pair[0].0, pair[1].0);
                }
            }
            FillMode::Winding => {
                let (mut turns, mut start) = (0, 0);
                for &(x, winding) in &crossings {
                    let before = turns;
                    turns += winding;
                    if before == 0 && turns != 0 {
                        start = x;
                    } else if before != 0 && turns == 0 {
                        push(start, x);
                    }
                }
            }
        }
        let line = y as i32;
        if row.is_empty() {
            previous.clear();
        } else if row == previous {
            for rect in &mut out[previous_at..] {
                rect.bottom = line + 1;
            }
        } else {
            previous_at = out.len();
            out.extend(row.iter().map(|&(start, end)| Rect::new(start, line, end, line + 1)));
            core::mem::swap(&mut previous, &mut row);
        }
    }
    out
}

/// Le nombre de segments d'une courbe de points de contrôle `curve` : un
/// tous les quatre pixels de son polygone de contrôle (qui la borne), entre
/// 1 et 256.
fn segments(curve: &[(i64, i64); 4]) -> i64 {
    let length: i64 = curve.windows(2).map(|pair| (pair[1].0 - pair[0].0).abs() + (pair[1].1 - pair[0].1).abs()).sum();
    (length / 4).clamp(1, 256)
}

/// Le point `step` / `steps` de la courbe de Bézier cubique `curve`
/// (Bernstein, en entiers sur 64 bits, arrondi au plus près).
fn bezier_point(curve: &[(i64, i64); 4], step: i64, steps: i64) -> (i32, i32) {
    let (a, b) = (steps - step, step);
    let weights = [a * a * a, 3 * a * a * b, 3 * a * b * b, b * b * b];
    let cube = steps * steps * steps;
    let coordinate = |of: fn(&(i64, i64)) -> i64| {
        let sum: i64 = weights.iter().zip(curve).map(|(weight, point)| weight * of(point)).sum();
        // Within the control points: back to 32 bits.
        (2 * sum + cube).div_euclid(2 * cube) as i32
    };
    (coordinate(|point| point.0), coordinate(|point| point.1))
}

/// GDI_Bezier : les points d'une suite de courbes de Bézier cubiques
/// (PolyBezier : un premier point, puis trois par courbe, deux de contrôle
/// et sa fin, qui commence la suivante), réduite à des segments ; `None` si
/// le compte n'est pas 1 + 3n.
pub fn flatten_beziers(points: &[(i32, i32)]) -> Option<Vec<(i32, i32)>> {
    if points.is_empty() || !(points.len() - 1).is_multiple_of(3) {
        return None;
    }
    let point = |index: usize| {
        let (x, y) = clamp_point(points[index]);
        (i64::from(x), i64::from(y))
    };
    let mut out = alloc::vec![clamp_point(points[0])];
    for start in (0..points.len() - 1).step_by(3) {
        let curve = [point(start), point(start + 1), point(start + 2), point(start + 3)];
        let steps = segments(&curve);
        out.extend((1..=steps).map(|step| bezier_point(&curve, step, steps)));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: Rect = Rect::new(-1000, -1000, 1000, 1000);

    /// The pixels of `rects`, as a set.
    fn pixels(rects: &[Rect]) -> alloc::collections::BTreeSet<(i32, i32)> {
        let mut set = alloc::collections::BTreeSet::new();
        for rect in rects {
            for y in rect.top..rect.bottom {
                for x in rect.left..rect.right {
                    assert!(set.insert((x, y)), "({x}, {y}) twice: the rectangles overlap");
                }
            }
        }
        set
    }

    #[test]
    fn a_rectangle_covers_its_left_and_top_edges_not_its_right_and_bottom() {
        let square = [(2, 3), (12, 3), (12, 8), (2, 8)];
        let spans = spans(&[&square], FillMode::Alternate, ALL);
        assert_eq!(spans, [Rect::new(2, 3, 12, 8)], "one rectangle: the rows coalesce");
        // The same, clockwise or not, in either mode.
        let reversed = [(2, 8), (12, 8), (12, 3), (2, 3)];
        assert_eq!(super::spans(&[&reversed], FillMode::Winding, ALL), [Rect::new(2, 3, 12, 8)]);
    }

    #[test]
    fn a_triangle_takes_the_pixels_whose_centre_is_inside() {
        // (0, 0), (8, 0), (0, 8): the centre (x + ½, y + ½) is inside when
        // x + y + 1 < 8 — on the hypotenuse (x + y + 1 = 8) it is out, as a
        // right edge.
        let triangle = [(0, 0), (8, 0), (0, 8)];
        let covered = pixels(&spans(&[&triangle], FillMode::Alternate, ALL));
        let expected: alloc::collections::BTreeSet<(i32, i32)> =
            (0..8).flat_map(|y| (0..8).map(move |x| (x, y))).filter(|&(x, y)| x + y + 1 < 8).collect();
        assert_eq!(covered, expected);
    }

    #[test]
    fn neighbouring_polygons_tile_without_gaps_or_overlap() {
        // Bands of a gradient, slanted: each pixel of the whole is in one band.
        let bands: alloc::vec::Vec<[(i32, i32); 4]> =
            (0..5).map(|band| [(band * 7, 0), (band * 7 + 7, 0), (band * 7 + 12, 20), (band * 7 + 5, 20)]).collect();
        let mut all = alloc::collections::BTreeSet::new();
        for band in &bands {
            for pixel in pixels(&spans(&[band], FillMode::Alternate, ALL)) {
                assert!(all.insert(pixel), "{pixel:?} in two bands");
            }
        }
        let whole = [(0, 0), (35, 0), (40, 20), (5, 20)];
        assert_eq!(all, pixels(&spans(&[&whole], FillMode::Alternate, ALL)));
    }

    #[test]
    fn a_hole_stays_empty_in_alternate_and_fills_in_winding_when_it_turns_the_same_way() {
        let outer = [(0, 0), (10, 0), (10, 10), (0, 10)];
        let inner_same = [(3, 3), (7, 3), (7, 7), (3, 7)];
        let inner_reversed = [(3, 3), (3, 7), (7, 7), (7, 3)];
        let alternate = pixels(&spans(&[&outer, &inner_same], FillMode::Alternate, ALL));
        assert!(!alternate.contains(&(5, 5)) && alternate.contains(&(1, 1)), "a hole");
        assert_eq!(alternate.len(), 100 - 16);
        let winding = pixels(&spans(&[&outer, &inner_same], FillMode::Winding, ALL));
        assert_eq!(winding.len(), 100, "turning the same way: twice around, filled");
        let winding = pixels(&spans(&[&outer, &inner_reversed], FillMode::Winding, ALL));
        assert_eq!(winding.len(), 100 - 16, "turning back: zero, a hole");
    }

    #[test]
    fn a_star_differs_between_the_modes() {
        // A five-pointed star drawn in one stroke: its centre is crossed twice
        // in ALTERNATE (empty) and turned around twice in WINDING (filled).
        let star = [(50, 0), (79, 90), (2, 35), (98, 35), (21, 90)];
        let alternate = pixels(&spans(&[&star], FillMode::Alternate, ALL));
        let winding = pixels(&spans(&[&star], FillMode::Winding, ALL));
        assert!(!alternate.contains(&(50, 50)) && winding.contains(&(50, 50)));
        assert!(alternate.contains(&(50, 10)) && winding.contains(&(50, 10)), "a point");
        assert!(alternate.is_subset(&winding));
    }

    #[test]
    fn spans_stay_within_the_area_however_far_the_polygon_goes() {
        // A huge triangle: only the rows and columns asked for are walked.
        let huge = [(-2_000_000_000, -2_000_000_000), (2_000_000_000, -2_000_000_000), (0, 2_000_000_000)];
        let area = Rect::new(0, 0, 16, 16);
        let spans = spans(&[&huge], FillMode::Alternate, area);
        assert_eq!(spans, [area], "inside it all");
        // Nothing at all outside.
        assert!(super::spans(&[&[(0, 0), (4, 0), (4, 4)]], FillMode::Alternate, Rect::new(10, 10, 20, 20)).is_empty());
        // Degenerate polygons: a line, a point.
        assert!(super::spans(&[&[(0, 0), (9, 9)]], FillMode::Alternate, ALL).is_empty());
        assert!(super::spans(&[&[(3, 3)]], FillMode::Alternate, ALL).is_empty());
    }

    #[test]
    fn beziers_flatten_through_their_ends() {
        // A straight curve: its points stay on the line, from start to end.
        let straight = flatten_beziers(&[(0, 0), (10, 0), (20, 0), (30, 0)]).unwrap();
        assert_eq!((straight.first(), straight.last()), (Some(&(0, 0)), Some(&(30, 0))));
        assert!(straight.iter().all(|&(_, y)| y == 0));
        assert!(straight.windows(2).all(|pair| pair[0].0 <= pair[1].0), "in order");
        // Two curves: the second starts where the first ends.
        let two = flatten_beziers(&[(0, 0), (0, 20), (20, 20), (20, 0), (20, -20), (40, -20), (40, 0)]).unwrap();
        assert!(two.contains(&(20, 0)) && two.last() == Some(&(40, 0)));
        // The middle of a symmetric arch: halfway, at three quarters of the height.
        let arch = flatten_beziers(&[(0, 0), (0, 40), (40, 40), (40, 0)]).unwrap();
        assert!(arch.contains(&(20, 30)), "{arch:?}");
        // Counts that are not 1 + 3n.
        assert_eq!(flatten_beziers(&[]), None);
        assert_eq!(flatten_beziers(&[(0, 0), (1, 1), (2, 2)]), None);
        assert_eq!(flatten_beziers(&[(5, 5)]), Some(alloc::vec![(5, 5)]), "a point alone");
        // Far away: bounded, no overflow.
        let far =
            flatten_beziers(&[(i32::MIN, i32::MIN), (i32::MAX, i32::MIN), (i32::MIN, i32::MAX), (i32::MAX, i32::MAX)]);
        assert_eq!(far.unwrap().last(), Some(&(COORDINATE_LIMIT, COORDINATE_LIMIT)));
    }
}
