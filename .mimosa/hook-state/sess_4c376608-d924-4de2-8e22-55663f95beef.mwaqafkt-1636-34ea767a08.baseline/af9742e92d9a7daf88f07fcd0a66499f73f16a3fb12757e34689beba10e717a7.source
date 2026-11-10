//! A scanline rasterizer of outlines into coverage, in fixed point.
//!
//! Each line segment of an outline adds, to the cells it crosses, the signed
//! area it covers to their right; a running sum over each row then gives the
//! coverage of every pixel, as a fraction of its area. This is the classic
//! signed-area accumulation, written from its public description, with
//! coordinates and areas in 16.16 fixed point: the kernel target computes
//! floats in software (ADR-013). Overlapping contours of the same direction
//! saturate to full coverage, opposite ones cancel (the holes of glyphs).
//!
//! Curves are flattened into line segments, more of them the further their
//! control points stand from the chord.

use alloc::vec;
use alloc::vec::Vec;

/// 1.0 in 16.16 fixed point.
pub const ONE: i64 = 1 << 16;

/// A point in pixels, 16.16 fixed point, y downwards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i64,
    pub y: i64,
}

impl Point {
    pub const fn new(x: i64, y: i64) -> Self {
        Self { x, y }
    }

    /// A point from whole pixels.
    pub const fn px(x: i64, y: i64) -> Self {
        Self { x: x * ONE, y: y * ONE }
    }
}

/// Coverage of a `width` × `height` bitmap, accumulated from outlines.
pub struct Rasterizer {
    width: usize,
    height: usize,
    /// The signed area each cell gets, then summed along the rows; two more
    /// cells than pixels, for what a segment leaves at the end of the last
    /// row.
    area: Vec<i64>,
    /// The pen of the outline being drawn, and its contour's start.
    pen: Point,
    start: Point,
}

impl Rasterizer {
    /// A rasterizer for a `width` × `height` bitmap, all of it uncovered.
    pub fn new(width: usize, height: usize) -> Self {
        Self { width, height, area: vec![0; width * height + 2], pen: Point::default(), start: Point::default() }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    /// Starts a contour at `to` (closing the previous one).
    pub fn move_to(&mut self, to: Point) {
        self.close();
        self.pen = to;
        self.start = to;
    }

    /// A line from the pen to `to`.
    pub fn line_to(&mut self, to: Point) {
        self.line(self.pen, to);
        self.pen = to;
    }

    /// A quadratic Bézier curve from the pen to `to`, through the control
    /// point `control`.
    pub fn quad_to(&mut self, control: Point, to: Point) {
        let from = self.pen;
        // How far the control point bends the curve from its chord.
        let deviation = distance(Point::new(from.x - 2 * control.x + to.x, from.y - 2 * control.y + to.y));
        let segments = segments_for(deviation, QUAD_FACTOR);
        for i in 1..=segments {
            let t = i * ONE / segments;
            let u = ONE - t;
            let point = Point::new(
                (u * u / ONE * from.x + 2 * u * t / ONE * control.x + t * t / ONE * to.x) / ONE,
                (u * u / ONE * from.y + 2 * u * t / ONE * control.y + t * t / ONE * to.y) / ONE,
            );
            self.line_to(if i == segments { to } else { point });
        }
    }

    /// A cubic Bézier curve from the pen to `to`, through `control1` and
    /// `control2`.
    pub fn cubic_to(&mut self, control1: Point, control2: Point, to: Point) {
        let from = self.pen;
        let bend = |a: Point, b: Point, c: Point| distance(Point::new(a.x - 2 * b.x + c.x, a.y - 2 * b.y + c.y));
        let deviation = bend(from, control1, control2).max(bend(control1, control2, to));
        let segments = segments_for(deviation, CUBIC_FACTOR);
        for i in 1..=segments {
            let t = i * ONE / segments;
            let u = ONE - t;
            let (uu, tt) = (u * u / ONE, t * t / ONE);
            let (uuu, uut, utt, ttt) = (uu * u / ONE, 3 * uu * t / ONE, 3 * u * tt / ONE, tt * t / ONE);
            let point = Point::new(
                (uuu * from.x + uut * control1.x + utt * control2.x + ttt * to.x) / ONE,
                (uuu * from.y + uut * control1.y + utt * control2.y + ttt * to.y) / ONE,
            );
            self.line_to(if i == segments { to } else { point });
        }
    }

    /// Closes the contour being drawn, with a line back to its start.
    pub fn close(&mut self) {
        if self.pen != self.start {
            self.line(self.pen, self.start);
            self.pen = self.start;
        }
    }

    /// Adds the line from `p0` to `p1`, whose x is kept within the bitmap.
    fn line(&mut self, p0: Point, p1: Point) {
        let right = self.width as i64 * ONE;
        let (p0, p1) = (Point::new(p0.x.clamp(0, right), p0.y), Point::new(p1.x.clamp(0, right), p1.y));
        if p0.y == p1.y {
            return;
        }
        // Downwards, the direction kept in the sign.
        let (direction, p0, p1) = if p0.y < p1.y { (1, p0, p1) } else { (-1, p1, p0) };
        let dxdy = (p1.x - p0.x) * ONE / (p1.y - p0.y);
        let first = (p0.y >> 16).max(0);
        let last = ((p1.y + ONE - 1) >> 16).min(self.height as i64);
        let mut x = p0.x + if p0.y < 0 { dxdy * -p0.y / ONE } else { 0 };
        for row in first..last {
            let top = (row * ONE).max(p0.y);
            let bottom = ((row + 1) * ONE).min(p1.y);
            let dy = bottom - top;
            let next = x + dxdy * dy / ONE;
            let d = dy * direction;
            let line = row as usize * self.width;
            let (x0, x1) = if x < next { (x, next) } else { (next, x) };
            let x0_floor = x0 & !(ONE - 1);
            let x0i = (x0 >> 16) as usize;
            let x1_ceil = (x1 + ONE - 1) & !(ONE - 1);
            let x1i = (x1_ceil >> 16) as usize;
            if x1i <= x0i + 1 {
                // Within one cell: what lies right of its middle goes to the
                // next.
                let middle = (x + next) / 2 - x0_floor;
                self.area[line + x0i] += d - d * middle / ONE;
                self.area[line + x0i + 1] += d * middle / ONE;
            } else {
                // Across cells: a triangle in the first and the last, a
                // trapezium in each between.
                let s = ONE * ONE / (x1 - x0);
                let x0f = x0 - x0_floor;
                let a0 = s * ((ONE - x0f) * (ONE - x0f) / ONE) / ONE / 2;
                let x1f = x1 - x1_ceil + ONE;
                let am = s * (x1f * x1f / ONE) / ONE / 2;
                self.area[line + x0i] += d * a0 / ONE;
                if x1i == x0i + 2 {
                    self.area[line + x0i + 1] += d * (ONE - a0 - am) / ONE;
                } else {
                    let a1 = s * (ONE + ONE / 2 - x0f) / ONE;
                    self.area[line + x0i + 1] += d * (a1 - a0) / ONE;
                    for cell in x0i + 2..x1i - 1 {
                        self.area[line + cell] += d * s / ONE;
                    }
                    let a2 = a1 + (x1i - x0i - 3) as i64 * s;
                    self.area[line + x1i - 1] += d * (ONE - a2 - am) / ONE;
                }
                self.area[line + x1i] += d * am / ONE;
            }
            x = next;
        }
    }

    /// The coverage of each pixel, row by row, from 0 (outside) to 255
    /// (inside), contours closed first.
    pub fn coverage(mut self) -> Vec<u8> {
        self.close();
        let mut sum = 0i64;
        self.area[..self.width * self.height]
            .iter()
            .map(|&area| {
                sum += area;
                (sum.abs().min(ONE) * 255 / ONE) as u8
            })
            .collect()
    }
}

/// The length of a vector, 16.16 fixed point.
fn distance(v: Point) -> i64 {
    isqrt(v.x * v.x + v.y * v.y)
}

/// How many segments flatten a curve whose control points stand
/// `deviation` from its chord (16.16): one under 1/√3 of a pixel, else
/// 1 + ⌊√(`factor` × deviation)⌋, at most 64; `factor` is in 16.16.
/// [`QUAD_FACTOR`] and [`CUBIC_FACTOR`] keep the chords within about a tenth
/// of a pixel of the curve.
fn segments_for(deviation: i64, factor: i64) -> i64 {
    if 3 * deviation * deviation < ONE * ONE {
        return 1;
    }
    // isqrt(deviation × factor × 2^16) is √(factor × deviation) in 16.16.
    (1 + (isqrt(deviation * factor) >> 16)).min(64)
}

/// √3 in 16.16: a quadratic curve's chords stay within dev / 4n² of it.
const QUAD_FACTOR: i64 = 113_512;
/// 7.5 in 16.16: a cubic curve's chords stay within 3 dev / 4n² of it, a
/// tenth of a pixel for n = √(7.5 dev).
const CUBIC_FACTOR: i64 = 491_520;

/// ⌊√n⌋ for n ≥ 0.
fn isqrt(n: i64) -> i64 {
    if n < 2 {
        return n.max(0);
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn square(raster: &mut Rasterizer, x0: i64, y0: i64, x1: i64, y1: i64) {
        raster.move_to(Point::new(x0, y0));
        raster.line_to(Point::new(x1, y0));
        raster.line_to(Point::new(x1, y1));
        raster.line_to(Point::new(x0, y1));
        raster.close();
    }

    fn total(coverage: &[u8]) -> i64 {
        coverage.iter().map(|&c| i64::from(c)).sum()
    }

    #[test]
    fn a_whole_pixel_square_covers_exactly_its_pixels() {
        let mut raster = Rasterizer::new(4, 4);
        square(&mut raster, ONE, ONE, 3 * ONE, 3 * ONE);
        let coverage = raster.coverage();
        for (i, &c) in coverage.iter().enumerate() {
            let (x, y) = (i % 4, i / 4);
            let inside = (1..3).contains(&x) && (1..3).contains(&y);
            assert_eq!(c, if inside { 255 } else { 0 }, "pixel ({x}, {y})");
        }
    }

    #[test]
    fn a_square_off_by_half_a_pixel_covers_four_quarters() {
        let mut raster = Rasterizer::new(3, 3);
        square(&mut raster, ONE / 2, ONE / 2, ONE + ONE / 2, ONE + ONE / 2);
        let coverage = raster.coverage();
        assert_eq!(&coverage[..], &[63, 63, 0, 63, 63, 0, 0, 0, 0]);
    }

    #[test]
    fn either_winding_covers_the_same() {
        let (mut clockwise, mut counter) = (Rasterizer::new(4, 4), Rasterizer::new(4, 4));
        square(&mut clockwise, ONE, ONE, 3 * ONE, 3 * ONE);
        square(&mut counter, ONE, 3 * ONE, 3 * ONE, ONE);
        assert_eq!(clockwise.coverage(), counter.coverage());
    }

    #[test]
    fn an_opposite_inner_contour_is_a_hole() {
        let mut raster = Rasterizer::new(6, 6);
        square(&mut raster, 0, 0, 6 * ONE, 6 * ONE);
        square(&mut raster, 2 * ONE, 4 * ONE, 4 * ONE, 2 * ONE);
        let coverage = raster.coverage();
        assert_eq!(coverage[2 * 6 + 2], 0, "the hole");
        assert_eq!(coverage[0], 255, "the ring");
        assert_eq!(total(&coverage), 255 * (36 - 4));
    }

    #[test]
    fn overlapping_contours_of_the_same_direction_saturate() {
        let mut raster = Rasterizer::new(4, 4);
        square(&mut raster, 0, 0, 3 * ONE, 3 * ONE);
        square(&mut raster, ONE, ONE, 4 * ONE, 4 * ONE);
        let coverage = raster.coverage();
        assert_eq!(coverage[4 + 1], 255, "covered twice is covered");
        assert_eq!(total(&coverage), 255 * (9 + 9 - 4));
    }

    #[test]
    fn a_slanted_triangle_covers_its_area() {
        // Area 8 × 6 / 2 = 24 pixels.
        let mut raster = Rasterizer::new(10, 8);
        raster.move_to(Point::px(1, 7));
        raster.line_to(Point::px(9, 7));
        raster.line_to(Point::px(1, 1));
        raster.close();
        let covered = total(&raster.coverage());
        assert!((covered - 24 * 255).abs() <= 24, "{covered} for 24 pixels");
    }

    #[test]
    fn a_circle_of_quadratic_curves_covers_about_pi_r_squared() {
        // Eight quadratic arcs of a circle of radius 20 around (24, 24).
        let (cx, cy, r) = (24 * ONE, 24 * ONE, 20 * ONE);
        let mut raster = Rasterizer::new(48, 48);
        // cos and sin of k × 45°, and the control point at 1 / cos(22.5°).
        const C: [i64; 8] = [65536, 46341, 0, -46341, -65536, -46341, 0, 46341];
        const S: [i64; 8] = [0, 46341, 65536, 46341, 0, -46341, -65536, -46341];
        const CONTROL: i64 = 70936;
        let at = |k: usize, scale: i64| {
            let (c, s) = (C[k % 8], S[k % 8]);
            Point::new(cx + r * scale / ONE * c / ONE, cy + r * scale / ONE * s / ONE)
        };
        let mid = |k: usize| {
            // The direction of k × 45° + 22.5°: the normalised sum of both ends.
            let (c, s) = (C[k % 8] + C[(k + 1) % 8], S[k % 8] + S[(k + 1) % 8]);
            let length = distance(Point::new(c, s));
            Point::new(cx + r * CONTROL / ONE * c / length, cy + r * CONTROL / ONE * s / length)
        };
        raster.move_to(at(0, ONE));
        for k in 0..8 {
            raster.quad_to(mid(k), at(k + 1, ONE));
        }
        let covered = total(&raster.coverage());
        let expected = 1257 * 255; // π × 20²
        assert!((covered - expected).abs() * 100 < expected, "{covered} for {expected}");
    }

    #[test]
    fn a_cubic_curve_covers_the_area_under_it() {
        // Over a base of 10 pixels, h(t) = 30t(1 - t) and dx = 60t(1 - t)dt:
        // the area is 1800 ∫ t²(1 - t)² dt = 60 pixels.
        let mut raster = Rasterizer::new(12, 12);
        raster.move_to(Point::px(1, 11));
        raster.cubic_to(Point::px(1, 1), Point::px(11, 1), Point::px(11, 11));
        raster.close();
        let covered = total(&raster.coverage());
        assert!((covered - 60 * 255).abs() * 50 < 60 * 255, "{covered} for 60 pixels");
    }

    #[test]
    fn points_outside_the_bitmap_are_kept_inside() {
        let mut raster = Rasterizer::new(4, 4);
        square(&mut raster, -2 * ONE, -2 * ONE, 6 * ONE, 6 * ONE);
        assert!(raster.coverage().iter().all(|&c| c == 255));
    }

    #[test]
    fn flattening_grows_with_the_bend() {
        assert_eq!(segments_for(ONE / 4, QUAD_FACTOR), 1);
        assert!(segments_for(4 * ONE, QUAD_FACTOR) > segments_for(ONE, QUAD_FACTOR));
        assert!(segments_for(4 * ONE, CUBIC_FACTOR) > segments_for(4 * ONE, QUAD_FACTOR), "more for a cubic");
        assert_eq!(segments_for(10_000 * ONE, CUBIC_FACTOR), 64);
        assert_eq!((isqrt(0), isqrt(15), isqrt(16), isqrt(1 << 40)), (0, 3, 4, 1 << 20));
    }
}
