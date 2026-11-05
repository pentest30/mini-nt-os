//! Les polices de win32k (ADR-013) : les fichiers TrueType que le noyau lit
//! au démarrage dans `\SystemRoot\Fonts` et installe ici ([`install`]), un
//! texte mis en glyphes à une taille ([`text_run`]), et le cache des glyphes
//! rendus (par `glyph`).
//!
//! Les polices connues sont celles dont USER a besoin pour dessiner le cadre
//! des fenêtres : Tahoma pour les titres (les LOGFONT par défaut de
//! NONCLIENTMETRICS, hauteur -11, gras pour lfCaptionFont), Marlett pour les
//! symboles des boutons. Une taille est une hauteur de LOGFONT : négative,
//! celle de l'em ; positive, celle de la cellule (ascent plus descent).
//!
//! Pas encore : la correspondance d'un LOGFONT quelconque (noms, graisses,
//! `FontSubstitutes`), les objets police de GDI (NtGdiHfontCreate,
//! SelectObject), ExtTextOut, GetTextExtentPoint32, GetTextMetrics ; le
//! crénage.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use glyph::{Bitmap, Font, Metrics, ONE};
use hal::sync::KSpinLock;

/// Une police que win32k connaît.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Face {
    /// Tahoma : les titres des petites fenêtres (lfSmCaptionFont), les menus,
    /// les messages.
    Tahoma = 0,
    /// Tahoma gras : les titres (lfCaptionFont).
    TahomaBold = 1,
    /// Marlett : les symboles des boutons du titre.
    Marlett = 2,
}

impl Face {
    /// Toutes, dans l'ordre de leur index.
    pub const ALL: [Face; 3] = [Face::Tahoma, Face::TahomaBold, Face::Marlett];

    /// Le nom de son fichier, dans `\SystemRoot\Fonts`.
    pub const fn file_name(self) -> &'static str {
        match self {
            Face::Tahoma => "tahoma.ttf",
            Face::TahomaBold => "tahomabd.ttf",
            Face::Marlett => "Marlett.ttf",
        }
    }
}

/// Le rendu d'un glyphe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quality {
    /// En niveaux de gris (ADR-013).
    Antialiased,
    /// Couvert ou non (`NONANTIALIASED_QUALITY`) : à moitié couvert, un
    /// pixel l'est.
    Monochrome,
}

/// Les fichiers installés, par [`Face`].
static FILES: KSpinLock<[Option<Arc<[u8]>>; 3]> = KSpinLock::new([None, None, None]);

/// Les glyphes rendus : police, em (16.16), glyphe, rendu.
type Key = (Face, i64, u16, Quality);
static CACHE: KSpinLock<BTreeMap<Key, Arc<Bitmap>>> = KSpinLock::new(BTreeMap::new());
/// Les glyphes gardés au plus ; au-delà, le cache se vide.
const CACHE_LIMIT: usize = 1024;

/// Installe la police `face`, lue dans `data`.
///
/// # Errors
/// Celle de `glyph` pour un fichier qu'il ne lit pas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn install(face: Face, data: Arc<[u8]>) -> Result<(), glyph::Error> {
    Font::parse(&data)?;
    FILES.lock()[face as usize] = Some(data);
    CACHE.lock().retain(|key, _| key.0 != face);
    Ok(())
}

/// Le fichier de `face`, s'il est installé.
fn file(face: Face) -> Option<Arc<[u8]>> {
    FILES.lock()[face as usize].clone()
}

/// La police `face` est installée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn installed(face: Face) -> bool {
    FILES.lock()[face as usize].is_some()
}

/// Un glyphe placé dans un texte : `x` pixels à droite de son début, sur sa
/// ligne de base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacedGlyph {
    pub x: i32,
    /// L'index de son caractère dans le texte.
    pub index: usize,
    pub bitmap: Arc<Bitmap>,
}

/// Un texte mis en glyphes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextRun {
    pub glyphs: Vec<PlacedGlyph>,
    /// Sa largeur : la somme des avances, arrondies chacune au pixel.
    pub width: i32,
    /// Les métriques de la police à cette taille (tmAscent, tmDescent…).
    pub metrics: Metrics,
    /// Le texte a été coupé et fini par « ... » pour tenir.
    pub truncated: bool,
}

/// L'em, en 16.16, d'une hauteur de LOGFONT `height` : négative, celle de
/// l'em ; positive, celle de la cellule ; nulle, 12 pixels de cellule (la
/// hauteur par défaut de GDI).
fn em_of(font: &Font, height: i32) -> i64 {
    match height {
        h if h < 0 => i64::from(h.unsigned_abs()) * ONE,
        0 => font.em_for_cell(12),
        h => font.em_for_cell(h as u32),
    }
}

/// Les métriques de TEXTMETRIC (FillTM) de la police `face` à la hauteur de
/// LOGFONT `height` ; `None` si elle n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_metrics(face: Face, height: i32) -> Option<glyph::TextMetrics> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    Some(font.text_metrics(em_of(&font, height)))
}

/// Les avances, arrondies au pixel, de chaque unité UTF-16 de `text` dans la
/// police `face` à la hauteur de LOGFONT `height` (une paire de substitution
/// a son avance sur sa première unité, rien sur la seconde), et les
/// métriques de la police ; `None` si elle n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn advances(face: Face, height: i32, text: &[u16]) -> Option<(Vec<i32>, Metrics)> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    let em = em_of(&font, height);
    let mut advances = Vec::with_capacity(text.len());
    for c in char::decode_utf16(text.iter().copied()) {
        let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
        let glyph = font.glyph_index(c).unwrap_or(0);
        advances.push(((font.advance(glyph, em) + ONE / 2) >> 16) as i32);
        if c.len_utf16() == 2 {
            advances.push(0);
        }
    }
    Some((advances, font.metrics(em)))
}

/// Le glyphe `glyph` de `font` (la police `face`) à l'em `em`, du cache ou
/// rendu ; `None` sans contour.
fn rendered(face: Face, font: &Font, em: i64, glyph: u16, quality: Quality) -> Option<Arc<Bitmap>> {
    let key = (face, em, glyph, quality);
    if let Some(bitmap) = CACHE.lock().get(&key) {
        return Some(bitmap.clone());
    }
    // Rendered without the lock: the cache only saves work.
    let mut bitmap = font.render(glyph, em)?;
    if quality == Quality::Monochrome {
        for coverage in &mut bitmap.coverage {
            *coverage = if *coverage >= 128 { 255 } else { 0 };
        }
    }
    let bitmap = Arc::new(bitmap);
    let mut cache = CACHE.lock();
    if cache.len() >= CACHE_LIMIT {
        cache.clear();
    }
    cache.insert(key, bitmap.clone());
    Some(bitmap)
}

/// `text` (UTF-16) en glyphes de la police `face` à la hauteur de LOGFONT
/// `height`. Avec `max_width`, un texte plus large est coupé et fini par
/// « ... » (DT_END_ELLIPSIS), autant de caractères qu'il en tient. `None`
/// si la police n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL (rend et alloue).
pub fn text_run(face: Face, height: i32, text: &[u16], max_width: Option<i32>, quality: Quality) -> Option<TextRun> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    let em = em_of(&font, height);
    let glyph_of = |c: char| font.glyph_index(c).unwrap_or(0);
    let advance = |glyph: u16| ((font.advance(glyph, em) + ONE / 2) >> 16) as i32;
    let glyphs: Vec<u16> =
        char::decode_utf16(text.iter().copied()).map(|c| glyph_of(c.unwrap_or(char::REPLACEMENT_CHARACTER))).collect();
    let mut kept = glyphs.len();
    let mut truncated = false;
    if let Some(max) = max_width {
        let total: i32 = glyphs.iter().map(|&g| advance(g)).sum();
        if total > max {
            truncated = true;
            let dots = 3 * advance(glyph_of('.'));
            let mut width = 0;
            kept = glyphs
                .iter()
                .take_while(|&&g| {
                    width += advance(g);
                    width + dots <= max
                })
                .count();
        }
    }
    let dot = glyph_of('.');
    let shown = glyphs[..kept].iter().copied().chain(core::iter::repeat_n(dot, if truncated { 3 } else { 0 }));
    let mut x = 0;
    let mut placed = Vec::new();
    for (index, glyph) in shown.enumerate() {
        if let Some(bitmap) = rendered(face, &font, em, glyph, quality) {
            placed.push(PlacedGlyph { x, index, bitmap });
        }
        x += advance(glyph);
    }
    Some(TextRun { glyphs: placed, width: x, metrics: font.metrics(em), truncated })
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;

    /// Installe les polices du ReactOS épinglé si elles ont été récupérées
    /// (`cargo xtask fetch-userland`) ; faux sinon.
    pub(crate) fn install_reactos_fonts() -> bool {
        const FONTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/reactos/0.4.16/reactos/Fonts/");
        Face::ALL.iter().all(|&face| {
            let Ok(data) = std::fs::read(alloc::format!("{FONTS}{}", face.file_name())) else {
                std::eprintln!("skipped: no {FONTS}{} (cargo xtask fetch-userland)", face.file_name());
                return false;
            };
            install(face, Arc::from(data)).is_ok()
        })
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn a_caption_in_tahoma_bold_has_its_glyphs_and_xp_s_metrics() {
        if !install_reactos_fonts() {
            return;
        }
        let run = text_run(Face::TahomaBold, -11, &units("Mino"), None, Quality::Antialiased).unwrap();
        assert_eq!((run.metrics.ascent, run.metrics.descent), (11, 2));
        assert_eq!(run.glyphs.len(), 4);
        assert!(run.glyphs.windows(2).all(|pair| pair[0].x < pair[1].x), "left to right");
        assert!((20..40).contains(&run.width), "Mino is {} pixels wide", run.width);
        assert!(!run.truncated);
        let spaced = text_run(Face::TahomaBold, -11, &units("M o"), None, Quality::Antialiased).unwrap();
        assert_eq!(spaced.glyphs.len(), 2, "a space has no glyph, only an advance");
    }

    #[test]
    fn a_text_too_wide_ends_with_an_ellipsis() {
        if !install_reactos_fonts() {
            return;
        }
        let text = units("A rather long caption for a narrow window");
        let full = text_run(Face::TahomaBold, -11, &text, None, Quality::Antialiased).unwrap();
        let cut = text_run(Face::TahomaBold, -11, &text, Some(60), Quality::Antialiased).unwrap();
        assert!(cut.truncated && cut.width <= 60 && cut.width < full.width, "{} of {}", cut.width, full.width);
        let fits = text_run(Face::TahomaBold, -11, &text, Some(full.width), Quality::Antialiased).unwrap();
        assert!(!fits.truncated, "exactly as wide fits");
    }

    #[test]
    fn marlett_symbols_are_monochrome_when_asked() {
        if !install_reactos_fonts() {
            return;
        }
        let run = text_run(Face::Marlett, 12, &units("r"), None, Quality::Monochrome).unwrap();
        let coverage = &run.glyphs[0].bitmap.coverage;
        assert!(coverage.iter().all(|&c| c == 0 || c == 255), "covered or not");
        assert!(coverage.contains(&255));
        assert_eq!(run.metrics.height(), 12, "a cell of 12 pixels");
    }

    #[test]
    fn a_file_that_is_no_font_is_refused() {
        assert_eq!(install(Face::Marlett, Arc::from(&b"no font"[..])), Err(glyph::Error::Malformed));
    }
}
