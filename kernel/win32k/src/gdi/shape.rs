//! Les polygones, polylignes et courbes de GDI (`fillshap.c` et `line.c` de
//! ReactOS, comme spécification) : ce que NtGdiPolyPolyDraw dessine
//! ([`poly_poly_draw`]) — Polygon et PolyPolygon (remplis du pinceau du DC
//! selon son mode, `super::polyfill`, puis leur contour fermé du stylo),
//! Polyline et PolyPolyline, PolylineTo, PolyBezier et PolyBezierTo (des
//! traits du stylo) — et la région qu'il crée ([`create_poly_polygon_rgn`],
//! CreatePolyPolygonRgn).
//!
//! Le pinceau et le stylo sont ceux des attributs du DC
//! (DC_vUpdateFillBrush, DC_vUpdateLineBrush : `gdi32` les y choisit sans
//! appeler le noyau). Le remplissage et les traits suivent son mode de
//! mélange (`jROP2`, SetROP2 : R2_NOT inverse, comme VCL le fait pour ses
//! cadres). Un trait s'arrête avant son dernier point (IntEngLineTo) : le
//! contour fermé d'un polygone ne repasse pas sur ses sommets.
//!
//! Pas encore : les chemins (BeginPath… : une figure s'y ajouterait au lieu
//! de se dessiner), les stylos larges en chemins (un stylo large épaissit
//! chaque trait, `super::dib::Bitmap::draw_segment`), les transformations
//! autres que la translation MM_TEXT.

use alloc::vec::Vec;

use abi::gdi::poly_func::{POLY_BEZIER, POLY_BEZIER_TO, POLY_LINE_TO, POLY_POLYGON, POLY_POLYLINE};
use abi::ntstatus::NtStatus;

use super::dc::{self, Fill};
use super::dib::{rop3_of_rop2, Rect};
use super::polyfill::{self, FillMode};
use super::region::Region;

/// La borne d'une région de polygones : ±32767, les coordonnées de 16 bits
/// qu'avaient les régions de Windows 9x. Une région se parcourt ligne à
/// ligne et en garde un rectangle par ligne au plus : ce qu'elle tient reste
/// borné, quel que soit le polygone.
pub const REGION_LIMIT: i32 = 0x7FFF;

/// Les figures de `points` : `counts[i]` points pour la i-ème (leur somme est
/// le nombre de points).
fn figures<'a>(points: &'a [(i32, i32)], counts: &'a [usize]) -> impl Iterator<Item = &'a [(i32, i32)]> + 'a {
    counts.iter().scan(0, move |start, &count| {
        let figure = points.get(*start..*start + count)?;
        *start += count;
        Some(figure)
    })
}

/// NtGdiPolyPolyDraw, sauf la région : `function` ([`abi::gdi::poly_func`])
/// sur le DC `hdc`, de `points` (coordonnées logiques, translatées par
/// l'origine du DC) répartis en figures de `counts` points (au moins deux
/// chacune). PolyPolygon remplit ses figures ensemble puis trace leur
/// contour fermé ; PolyPolyline trace chacune ; PolyBezier (1 + 3n points),
/// PolylineTo et PolyBezierTo (3n points, depuis la position courante) ne
/// prennent que la première, et les deux derniers mettent la position
/// courante à son dernier point. `Ok(false)` pour des courbes au mauvais
/// compte, ou un DC sans attributs. `Err` : l'erreur de Win32
/// (`ERROR_INVALID_HANDLE` pour un DC qui n'est pas au processus,
/// `ERROR_INVALID_PARAMETER` pour une autre fonction).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn poly_poly_draw(hdc: u32, points: &[(i32, i32)], counts: &[usize], function: u32) -> Result<bool, u32> {
    use abi::winerror::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};
    if !matches!(function, POLY_POLYGON | POLY_POLYLINE | POLY_BEZIER | POLY_LINE_TO | POLY_BEZIER_TO) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let dc = dc::lock(hdc).ok_or(ERROR_INVALID_HANDLE)?;
    let Some((_, attr)) = dc.state().owner else { return Ok(false) };
    let brush = dc::fill_brush(&dc, attr, None, false).ok().flatten();
    let pen = dc::line_pen(&dc);
    let state = dc.state();
    let (dx, dy) = dc::logical_origin(&state, None);
    let device = |(x, y): (i32, i32)| polyfill::clamp_point((x.saturating_add(dx), y.saturating_add(dy)));
    let first = figures(points, counts).next().unwrap_or(&[]);
    // From the current position: it comes first.
    let from_current = |curve: &[(i32, i32)]| {
        let mut all = Vec::with_capacity(curve.len() + 1);
        all.push(dc::current_position(&state));
        all.extend_from_slice(curve);
        all
    };
    let figures: Vec<Vec<(i32, i32)>> = match function {
        POLY_POLYGON | POLY_POLYLINE => figures(points, counts).map(|figure| figure.to_vec()).collect(),
        POLY_LINE_TO => alloc::vec![from_current(first)],
        POLY_BEZIER => match polyfill::flatten_beziers(first) {
            Some(lines) => alloc::vec![lines],
            None => return Ok(false),
        },
        _ => match polyfill::flatten_beziers(&from_current(first)) {
            Some(lines) => alloc::vec![lines],
            None => return Ok(false),
        },
    };
    let figures: Vec<Vec<(i32, i32)>> =
        figures.into_iter().map(|figure| figure.into_iter().map(device).collect()).collect();
    let closed = function == POLY_POLYGON;
    let (rop2, mode) = dc::draw_modes(&state);
    let rao = state.rao();
    let parts: Vec<Rect> = rao.rects().to_vec();
    let fill =
        brush.filter(|_| closed).map(|brush| dc::fill_of(&state, &brush, None)).filter(|fill| *fill != Fill::Nothing);
    let spans = match fill {
        Some(_) => {
            let outlines: Vec<&[(i32, i32)]> = figures.iter().map(Vec::as_slice).collect();
            polyfill::spans(&outlines, mode, rao.bounds())
        }
        None => Vec::new(),
    };
    let rop3 = rop3_of_rop2(rop2);
    state.draw(|surface| {
        for span in &spans {
            for part in &parts {
                let area = part.intersect(span);
                match &fill {
                    Some(Fill::Solid(color)) => surface.pat_blt(area, *color, rop3),
                    Some(Fill::Mono(pattern)) => surface.pat_blt_mono(area, pattern, rop3),
                    Some(Fill::Nothing) | None => {}
                }
            }
        }
        if pen.is_null() {
            return;
        }
        for figure in &figures {
            for pair in figure.windows(2) {
                surface.draw_segment(pair[0], pair[1], &pen, rop2, &parts);
            }
            if let (true, [start, .., end]) = (closed, figure.as_slice()) {
                surface.draw_segment(*end, *start, &pen, rop2, &parts);
            }
        }
    });
    if matches!(function, POLY_LINE_TO | POLY_BEZIER_TO) {
        if let Some(&last) = first.last() {
            dc::set_current_position(&dc, last);
        }
    }
    Ok(true)
}

/// GreCreatePolyPolygonRgn : la région des polygones de `points` répartis
/// en figures de `counts` points, remplis ensemble selon `mode` (WINDING, ou
/// ALTERNATE : ce que CreatePolyPolygonRgn passe à la place du DC), coupée
/// à ±[`REGION_LIMIT`], au processus courant ; rend son handle.
///
/// # Errors
/// Celles de `super::rgnobj::create`.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn create_poly_polygon_rgn(points: &[(i32, i32)], counts: &[usize], mode: i32) -> Result<u32, NtStatus> {
    let outlines: Vec<&[(i32, i32)]> = figures(points, counts).collect();
    let within = Rect::new(-REGION_LIMIT, -REGION_LIMIT, REGION_LIMIT, REGION_LIMIT);
    let region = Region::from_disjoint(polyfill::spans(&outlines, FillMode::from_mode(mode), within));
    super::rgnobj::create(region)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_split_into_their_figures() {
        let points = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)];
        let split: Vec<&[(i32, i32)]> = figures(&points, &[2, 3]).collect();
        assert_eq!(split, [&points[..2], &points[2..]]);
        // Counts beyond the points: the figures that fit.
        assert_eq!(figures(&points, &[4, 4]).count(), 1);
    }
}
