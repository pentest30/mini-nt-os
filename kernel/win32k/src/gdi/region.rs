//! Les régions : une union de rectangles disjoints, pour couper un dessin
//! à la partie visible d'une fenêtre (VIS_ComputeVisibleRegion) ou à ce
//! qu'un changement découvre.
//!
//! Une région se coupe à un rectangle ([`Region::intersect_rect`]) et s'en
//! retire ([`Region::subtract_rect`]) : chacun de ses rectangles perd la
//! partie commune, et ce qui en reste tient en quatre bandes au plus.
//!
//! Elle s'étend à un rectangle ([`Region::union_rect`]) : ce qu'elle en a
//! déjà s'ôte du rectangle avant qu'il s'ajoute.
//!
//! Pas encore : les objets région de GDI (handles, CombineRgn, les régions
//! d'une fenêtre, SetWindowRgn), une forme normalisée en bandes comme celle
//! de ReactOS (deux régions égales peuvent avoir des rectangles
//! différents).

use alloc::vec::Vec;

use super::dib::Rect;

/// Une région : des rectangles disjoints, non vides.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Region {
    rects: Vec<Rect>,
}

impl Region {
    /// La région de `rect` (vide s'il l'est).
    pub fn from_rect(rect: Rect) -> Self {
        let mut rects = Vec::new();
        if !rect.is_empty() {
            rects.push(rect);
        }
        Self { rects }
    }

    /// Ses rectangles.
    pub fn rects(&self) -> &[Rect] {
        &self.rects
    }

    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    /// Son aire, en pixels.
    pub fn area(&self) -> i64 {
        self.rects.iter().map(|r| i64::from(r.right - r.left) * i64::from(r.bottom - r.top)).sum()
    }

    /// Elle contient le pixel (`x`, `y`).
    pub fn contains(&self, x: i32, y: i32) -> bool {
        self.rects.iter().any(|r| x >= r.left && x < r.right && y >= r.top && y < r.bottom)
    }

    /// Elle se réduit à sa partie dans `rect` (RGN_AND).
    pub fn intersect_rect(&mut self, rect: Rect) {
        self.rects = self.rects.iter().map(|r| r.intersect(&rect)).filter(|r| !r.is_empty()).collect();
    }

    /// Elle perd sa partie dans `rect` (RGN_DIFF).
    pub fn subtract_rect(&mut self, rect: Rect) {
        let mut rects = Vec::new();
        for &r in &self.rects {
            subtract(r, rect, &mut rects);
        }
        self.rects = rects;
    }

    /// Elle perd sa partie dans `other`.
    pub fn subtract(&mut self, other: &Region) {
        for &rect in &other.rects {
            self.subtract_rect(rect);
        }
    }

    /// Sa partie commune avec `other` (RGN_AND).
    pub fn intersect(&self, other: &Region) -> Region {
        let mut rects = Vec::new();
        for &a in &self.rects {
            for &b in &other.rects {
                let common = a.intersect(&b);
                if !common.is_empty() {
                    rects.push(common);
                }
            }
        }
        Region { rects }
    }

    /// Elle s'étend à `rect` (RGN_OR) : ses rectangles restent disjoints.
    pub fn union_rect(&mut self, rect: Rect) {
        if rect.is_empty() {
            return;
        }
        self.subtract_rect(rect);
        self.rects.push(rect);
    }

    /// Le plus petit rectangle qui la tient (vide pour une région vide).
    pub fn bounds(&self) -> Rect {
        let Some(first) = self.rects.first() else { return Rect::default() };
        self.rects.iter().fold(*first, |bounds, rect| bounds.union(rect))
    }

    /// Elle se déplace de `dx`, `dy`.
    pub fn offset(&mut self, dx: i32, dy: i32) {
        for r in &mut self.rects {
            *r = Rect::new(r.left + dx, r.top + dy, r.right + dx, r.bottom + dy);
        }
    }
}

/// Ce qui reste de `a` hors de `b`, ajouté à `out` : au plus une bande au-dessus,
/// une au-dessous, une à gauche et une à droite de la partie commune.
fn subtract(a: Rect, b: Rect, out: &mut Vec<Rect>) {
    let common = a.intersect(&b);
    if common.is_empty() {
        out.push(a);
        return;
    }
    let pieces = [
        Rect::new(a.left, a.top, a.right, common.top),
        Rect::new(a.left, common.bottom, a.right, a.bottom),
        Rect::new(a.left, common.top, common.left, common.bottom),
        Rect::new(common.right, common.top, a.right, common.bottom),
    ];
    out.extend(pieces.into_iter().filter(|r| !r.is_empty()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hole_leaves_four_bands() {
        let mut region = Region::from_rect(Rect::new(0, 0, 10, 10));
        region.subtract_rect(Rect::new(3, 4, 6, 7));
        assert_eq!(region.area(), 100 - 9);
        assert_eq!(region.rects().len(), 4);
        assert!(!region.contains(3, 4) && !region.contains(5, 6), "the hole");
        assert!(region.contains(2, 4) && region.contains(6, 6) && region.contains(4, 3) && region.contains(4, 7));
        for (i, a) in region.rects().iter().enumerate() {
            for b in &region.rects()[i + 1..] {
                assert!(a.intersect(b).is_empty(), "disjoint: {a:?} {b:?}");
            }
        }
    }

    #[test]
    fn subtracting_and_intersecting() {
        let mut region = Region::from_rect(Rect::new(0, 0, 10, 10));
        region.subtract_rect(Rect::new(20, 20, 30, 30));
        assert_eq!(region.rects(), [Rect::new(0, 0, 10, 10)], "nothing in common");
        region.subtract_rect(Rect::new(-5, -5, 15, 5));
        assert_eq!(region.rects(), [Rect::new(0, 5, 10, 10)], "the top half gone");
        region.intersect_rect(Rect::new(2, 0, 4, 8));
        assert_eq!(region.rects(), [Rect::new(2, 5, 4, 8)]);
        region.subtract_rect(Rect::new(0, 0, 100, 100));
        assert!(region.is_empty());
        assert!(Region::from_rect(Rect::new(5, 5, 5, 9)).is_empty(), "an empty rectangle");
    }

    #[test]
    fn regions_intersect() {
        let mut a = Region::from_rect(Rect::new(0, 0, 10, 10));
        a.subtract_rect(Rect::new(0, 0, 10, 5));
        let b = Region::from_rect(Rect::new(5, 0, 20, 8));
        assert_eq!(a.intersect(&b).rects(), [Rect::new(5, 5, 10, 8)]);
        assert!(a.intersect(&Region::default()).is_empty());
    }

    #[test]
    fn a_union_stays_disjoint_and_bounded() {
        let mut region = Region::default();
        assert_eq!(region.bounds(), Rect::default());
        region.union_rect(Rect::new(0, 0, 10, 10));
        region.union_rect(Rect::new(5, 5, 15, 15));
        assert_eq!(region.area(), 100 + 100 - 25, "the common part counted once");
        assert_eq!(region.bounds(), Rect::new(0, 0, 15, 15));
        region.union_rect(Rect::new(20, 0, 20, 30));
        assert_eq!(region.bounds(), Rect::new(0, 0, 15, 15), "an empty rectangle adds nothing");
        region.union_rect(Rect::new(30, 30, 40, 40));
        assert_eq!(region.bounds(), Rect::new(0, 0, 40, 40));
        for (i, a) in region.rects().iter().enumerate() {
            for b in &region.rects()[i + 1..] {
                assert!(a.intersect(b).is_empty(), "disjoint: {a:?} {b:?}");
            }
        }
        region.subtract_rect(Rect::new(0, 0, 15, 15));
        region.subtract_rect(Rect::new(30, 30, 40, 40));
        assert!(region.is_empty(), "two pieces, taken away one after the other");
    }

    #[test]
    fn regions_subtract_and_move() {
        let mut region = Region::from_rect(Rect::new(0, 0, 4, 4));
        let mut other = Region::from_rect(Rect::new(0, 0, 2, 4));
        other.offset(2, 0);
        region.subtract(&other);
        assert_eq!(region.rects(), [Rect::new(0, 0, 2, 4)]);
    }
}
