//! Les polices de win32k (ADR-013) : les fichiers TrueType que le noyau lit
//! au démarrage dans `\SystemRoot\Fonts` et installe ici ([`install`]), avec
//! leurs noms, leur graisse, leur italique et leur jeu de caractères ; les
//! substituts du registre (`FontSubstitutes`, [`set_substitutes`]) ; une
//! police trouvée par sa famille ([`find`]) ; un texte mis en glyphes à une
//! taille ([`text_run`]), et le cache des glyphes rendus (par `glyph`).
//!
//! Le cadre des fenêtres demande les siennes par leur nom ([`Named`]) :
//! Tahoma pour les titres (les LOGFONT par défaut de NONCLIENTMETRICS,
//! hauteur -11, gras pour lfCaptionFont), Marlett pour les symboles des
//! boutons. Une taille est une hauteur de LOGFONT : négative, celle de l'em ;
//! positive, celle de la cellule (ascent plus descent).
//!
//! Pas encore : le crénage, les polices bitmap (`.fon`), les collections
//! (seule la première police d'un fichier est lue), les polices privées d'un
//! processus (AddFontResource).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::gdi::{
    ANSI_CHARSET, ARABIC_CHARSET, BALTIC_CHARSET, CHINESEBIG5_CHARSET, DEFAULT_CHARSET, EASTEUROPE_CHARSET,
    GB2312_CHARSET, GREEK_CHARSET, HANGEUL_CHARSET, HEBREW_CHARSET, JOHAB_CHARSET, RUSSIAN_CHARSET, SHIFTJIS_CHARSET,
    SYMBOL_CHARSET, THAI_CHARSET, TURKISH_CHARSET, VIETNAMESE_CHARSET,
};
use glyph::{Bitmap, Font, Metrics, Names, ONE};
use hal::sync::KSpinLock;

/// Une police installée : son rang dans la table, dans l'ordre des
/// installations (une police réinstallée garde le sien).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Face(u16);

/// Ce que win32k sait d'une police installée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceInfo {
    /// Le nom de son fichier, dans `\SystemRoot\Fonts`.
    pub file_name: String,
    /// Sa famille (lfFaceName), son style, son nom complet.
    pub names: Names,
    /// usWeightClass.
    pub weight: u16,
    pub italic: bool,
    /// Le pas et la famille de son TEXTMETRIC (`TMPF_*`, `FF_*`).
    pub pitch_and_family: u8,
    /// Son jeu de caractères (le premier de ses pages de code, comme ReactOS :
    /// ANSI sans elles).
    pub char_set: u8,
}

impl FaceInfo {
    /// Elle est à pas fixe (TMPF_FIXED_PITCH, dont le nom dit le contraire,
    /// est clair).
    pub fn fixed_pitch(&self) -> bool {
        self.pitch_and_family & glyph::font::TMPF_VARIABLE_PITCH == 0
    }
}

/// Une police que le cadre des fenêtres demande par sa famille et sa
/// graisse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Named {
    pub family: &'static str,
    pub weight: u16,
}

/// Tahoma : les titres des petites fenêtres (lfSmCaptionFont), les menus, les
/// messages.
pub const TAHOMA: Named = Named { family: "Tahoma", weight: 400 };
/// Tahoma gras : les titres (lfCaptionFont).
pub const TAHOMA_BOLD: Named = Named { family: "Tahoma", weight: 700 };
/// Marlett : les symboles des boutons du titre.
pub const MARLETT: Named = Named { family: "Marlett", weight: 400 };

/// Le rendu d'un glyphe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quality {
    /// En niveaux de gris (ADR-013).
    Antialiased,
    /// Couvert ou non (`NONANTIALIASED_QUALITY`) : à moitié couvert, un
    /// pixel l'est.
    Monochrome,
}

/// Une police installée : ce qu'on en sait, et son fichier.
struct Installed {
    info: FaceInfo,
    data: Arc<[u8]>,
}

/// Les polices installées ; le rang d'une [`Face`] est sa place ici.
static FACES: KSpinLock<Vec<Installed>> = KSpinLock::new(Vec::new());

/// Les substituts de `FontSubstitutes` : un nom, le nom qu'il désigne.
static SUBSTITUTES: KSpinLock<Vec<(String, String)>> = KSpinLock::new(Vec::new());

/// Les glyphes rendus : police, em (16.16), glyphe, rendu.
type Key = (Face, i64, u16, Quality);
static CACHE: KSpinLock<BTreeMap<Key, Arc<Bitmap>>> = KSpinLock::new(BTreeMap::new());
/// Les glyphes gardés au plus ; au-delà, le cache se vide.
const CACHE_LIMIT: usize = 1024;

/// Le jeu de caractères de chaque bit de ulCodePageRange1 (`g_FontTci` de
/// ReactOS comme spécification) ; DEFAULT_CHARSET pour les bits réservés.
const CODE_PAGE_CHARSETS: [u8; 32] = {
    let mut charsets = [DEFAULT_CHARSET; 32];
    charsets[0] = ANSI_CHARSET;
    charsets[1] = EASTEUROPE_CHARSET;
    charsets[2] = RUSSIAN_CHARSET;
    charsets[3] = GREEK_CHARSET;
    charsets[4] = TURKISH_CHARSET;
    charsets[5] = HEBREW_CHARSET;
    charsets[6] = ARABIC_CHARSET;
    charsets[7] = BALTIC_CHARSET;
    charsets[8] = VIETNAMESE_CHARSET;
    charsets[16] = THAI_CHARSET;
    charsets[17] = SHIFTJIS_CHARSET;
    charsets[18] = GB2312_CHARSET;
    charsets[19] = HANGEUL_CHARSET;
    charsets[20] = CHINESEBIG5_CHARSET;
    charsets[21] = JOHAB_CHARSET;
    charsets[31] = SYMBOL_CHARSET;
    charsets
};

/// Le jeu de caractères d'une police dont les pages de code (`OS/2`
/// ulCodePageRange1) sont `range` : celui du premier bit qui en désigne un ;
/// ANSI sans `OS/2` de version 1 ou plus (IntGdiLoadFontsFromMemory).
pub fn char_set_of(range: Option<u32>) -> u8 {
    let Some(range) = range else { return ANSI_CHARSET };
    (0..32)
        .filter(|&bit| range & (1 << bit) != 0)
        .map(|bit| CODE_PAGE_CHARSETS[bit])
        .find(|&charset| charset != DEFAULT_CHARSET)
        .unwrap_or(ANSI_CHARSET)
}

/// Installe la police du fichier `file_name`, lue dans `data` : ses noms, sa
/// graisse, son italique, son pas et son jeu de caractères. Une police déjà
/// installée sous ce nom de fichier est remplacée, et garde son rang.
///
/// # Errors
/// Celle de `glyph` pour un fichier qu'il ne lit pas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn install(file_name: &str, data: Arc<[u8]>) -> Result<Face, glyph::Error> {
    let font = Font::parse(&data)?;
    let metrics = font.text_metrics(12 * ONE);
    let info = FaceInfo {
        file_name: String::from(file_name),
        names: font.names(),
        weight: metrics.weight,
        italic: font.is_italic(),
        pitch_and_family: metrics.pitch_and_family,
        char_set: char_set_of(font.code_page_ranges().map(|(first, _)| first)),
    };
    let mut faces = FACES.lock();
    let face = match faces.iter().position(|installed| installed.info.file_name.eq_ignore_ascii_case(file_name)) {
        Some(at) => {
            faces[at] = Installed { info, data };
            Face(at as u16)
        }
        None => {
            faces.push(Installed { info, data });
            Face((faces.len() - 1) as u16)
        }
    };
    drop(faces);
    CACHE.lock().retain(|key, _| key.0 != face);
    Ok(face)
}

/// Le fichier de `face`, s'il est installé.
fn file(face: Face) -> Option<Arc<[u8]>> {
    FACES.lock().get(usize::from(face.0)).map(|installed| installed.data.clone())
}

/// Ce qu'on sait de `face`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn info(face: Face) -> Option<FaceInfo> {
    FACES.lock().get(usize::from(face.0)).map(|installed| installed.info.clone())
}

/// Les polices installées, dans leur ordre.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn faces() -> Vec<(Face, FaceInfo)> {
    FACES.lock().iter().enumerate().map(|(at, installed)| (Face(at as u16), installed.info.clone())).collect()
}

/// La police de la famille `family` (sans casse) la plus proche de la
/// graisse `weight` et de l'italique `italic` : l'italique d'abord, puis
/// l'écart de graisse (à égalité, la plus grasse). `None` sans police de
/// cette famille.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn find(family: &str, weight: u16, italic: bool) -> Option<Face> {
    let faces = FACES.lock();
    faces
        .iter()
        .enumerate()
        .filter(|(_, installed)| installed.info.names.family.eq_ignore_ascii_case(family))
        .min_by_key(|(_, installed)| {
            let info = &installed.info;
            (info.italic != italic, info.weight.abs_diff(weight), core::cmp::Reverse(info.weight))
        })
        .map(|(at, _)| Face(at as u16))
}

/// La police `named`, si elle est installée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn named(named: Named) -> Option<Face> {
    find(named.family, named.weight, false)
}

/// Les substituts de `FontSubstitutes` deviennent `substitutes` (un nom, et le
/// nom qu'il désigne ; sans le jeu de caractères qui peut les suivre).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_substitutes(substitutes: Vec<(String, String)>) {
    let previous = core::mem::replace(&mut *SUBSTITUTES.lock(), substitutes);
    drop(previous);
}

/// SubstituteFontRecurse : le nom que désigne `name` à travers les
/// substituts, suivis 10 fois au plus (une boucle s'arrête là) ; `name` sans
/// substitut.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn substitute(name: &str) -> String {
    follow(&SUBSTITUTES.lock(), name)
}

/// Le nom que désigne `name` à travers `substitutes`, suivis 10 fois au plus.
fn follow(substitutes: &[(String, String)], name: &str) -> String {
    let mut current = String::from(name);
    for _ in 0..10 {
        match substitutes.iter().find(|(from, _)| from.eq_ignore_ascii_case(&current)) {
            Some((_, to)) if !to.eq_ignore_ascii_case(&current) => current = to.clone(),
            _ => break,
        }
    }
    current
}

/// Les substituts `(nom, nom désigné)` dont le nom est `name` (sans casse),
/// ou tous si `name` est vide.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn substitutes_of(name: &str) -> Vec<(String, String)> {
    SUBSTITUTES.lock().iter().filter(|(from, _)| name.is_empty() || from.eq_ignore_ascii_case(name)).cloned().collect()
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

/// Ce que l'énumération des polices dit d'une police (FontFamilyFillInfo).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumerationMetrics {
    /// Son TEXTMETRIC à la hauteur par défaut (une cellule de 12 pixels).
    pub text_metrics: glyph::TextMetrics,
    /// ntmSizeEM : son em, en unités de la police.
    pub size_em: u16,
    /// ntmCellHeight : sa cellule, en unités de la police.
    pub cell_height: u32,
    /// FONTSIGNATURE : ses plages Unicode et ses pages de code.
    pub unicode_ranges: [u32; 4],
    pub code_pages: [u32; 2],
}

/// Ce que l'énumération des polices dit de `face` ; `None` si elle n'est pas
/// installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn enumeration_metrics(face: Face) -> Option<EnumerationMetrics> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    let (ascent, descent) = font.windows_ascent_descent();
    let (unicode_ranges, code_pages) = font.signature();
    Some(EnumerationMetrics {
        text_metrics: font.text_metrics(em_of(&font, 0)),
        size_em: font.units_per_em(),
        cell_height: u32::try_from(ascent + descent).unwrap_or(0),
        unicode_ranges,
        code_pages,
    })
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
    let (placed, width) = place(face, &font, em, shown, quality);
    Some(TextRun { glyphs: placed, width, metrics: font.metrics(em), truncated })
}

/// Les glyphes `shown` de `font` (la police `face`) à l'em `em`, placés l'un
/// après l'autre de leur avance arrondie ; et la largeur du tout.
fn place(
    face: Face,
    font: &Font,
    em: i64,
    shown: impl Iterator<Item = u16>,
    quality: Quality,
) -> (Vec<PlacedGlyph>, i32) {
    let mut x = 0;
    let mut placed = Vec::new();
    for (index, glyph) in shown.enumerate() {
        if let Some(bitmap) = rendered(face, font, em, glyph, quality) {
            placed.push(PlacedGlyph { x, index, bitmap });
        }
        x += ((font.advance(glyph, em) + ONE / 2) >> 16) as i32;
    }
    (placed, x)
}

/// Les glyphes `glyphs` (des indices de glyphes, ETO_GLYPH_INDEX) de la
/// police `face` à la hauteur de LOGFONT `height` ; `None` si elle n'est
/// pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL (rend et alloue).
pub fn glyph_run(face: Face, height: i32, glyphs: &[u16], quality: Quality) -> Option<TextRun> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    let em = em_of(&font, height);
    let (placed, width) = place(face, &font, em, glyphs.iter().copied(), quality);
    Some(TextRun { glyphs: placed, width, metrics: font.metrics(em), truncated: false })
}

/// GetGlyphIndicesW (GreGetGlyphIndicesW) : le glyphe de chaque unité
/// UTF-16 de `text` dans `face` (une paire de substitution n'est pas lue :
/// ses moitiés sont des caractères absents, comme Windows). Un caractère
/// absent a `missing` (0xFFFF, GGI_MARK_NONEXISTING_GLYPHS) ou, sans lui,
/// le glyphe du caractère par défaut de la police (`OS/2` usDefaultChar).
/// `None` si elle n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn glyph_indices(face: Face, text: &[u16], missing: Option<u16>) -> Option<Vec<u16>> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    let glyph =
        |unit: u16| char::from_u32(u32::from(unit)).and_then(|c| font.glyph_index(c)).filter(|&glyph| glyph != 0);
    let default = missing.unwrap_or_else(|| glyph(font.default_char()).unwrap_or(0));
    Some(text.iter().map(|&unit| glyph(unit).unwrap_or(default)).collect())
}

/// Le nombre de glyphes de `face` ; `None` si elle n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn glyph_count(face: Face) -> Option<u16> {
    let data = file(face)?;
    Some(Font::parse(&data).ok()?.glyph_count())
}

/// GetCharABCWidths (GreGetCharABCWidthsW) : les largeurs A, B et C de
/// chaque code de `codes` dans `face` à la hauteur de LOGFONT `height` ;
/// des indices de glyphes avec `indices` (GCABCW_INDICES), sinon des
/// caractères (le glyphe 0 pour un caractère absent). `None` si la police
/// n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn abc_widths(face: Face, height: i32, codes: &[u32], indices: bool) -> Option<Vec<(i32, i32, i32)>> {
    let data = file(face)?;
    let font = Font::parse(&data).ok()?;
    let em = em_of(&font, height);
    let glyph = |code: u32| {
        if indices {
            code as u16
        } else {
            char::from_u32(code).and_then(|c| font.glyph_index(c)).unwrap_or(0)
        }
    };
    Some(codes.iter().map(|&code| font.abc(glyph(code), em)).collect())
}

/// GetFontData (ftGdiGetFontData) : le fichier de `face` et la place, dans
/// lui, de sa table `tag` (MS_MAKE_TAG : son premier caractère dans l'octet
/// bas), ou du fichier entier pour 0 ; `None` sans la police ou sans la
/// table.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn font_data(face: Face, tag: u32) -> Option<(Arc<[u8]>, core::ops::Range<usize>)> {
    let data = file(face)?;
    if tag == 0 {
        let whole = 0..data.len();
        return Some((data, whole));
    }
    let range = {
        let font = Font::parse(&data).ok()?;
        let table = font.table(tag.to_le_bytes())?;
        let start = table.as_ptr() as usize - data.as_ptr() as usize;
        start..start + table.len()
    };
    Some((data, range))
}

/// [`text_run`] dans la police `named` ; `None` si elle n'est pas installée.
///
/// # IRQL
/// PASSIVE_LEVEL (rend et alloue).
pub fn text_run_named(
    named: Named,
    height: i32,
    text: &[u16],
    max_width: Option<i32>,
    quality: Quality,
) -> Option<TextRun> {
    text_run(self::named(named)?, height, text, max_width, quality)
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;

    /// Les polices du ReactOS épinglé que les tests installent, s'il a été
    /// récupéré : celles du cadre des fenêtres, puis celles de la console, et
    /// Courier New italique pour l'italique.
    const TEST_FONTS: [&str; 7] =
        ["tahoma.ttf", "tahomabd.ttf", "Marlett.ttf", "UniVGA16.ttf", "lucon.ttf", "cour.ttf", "couri.ttf"];

    /// Installe les polices du ReactOS épinglé si elles ont été récupérées
    /// (`cargo xtask fetch-userland`), et les substituts que les tests
    /// demandent, ceux de la ruche SOFTWARE épinglée ; faux sinon.
    pub(crate) fn install_reactos_fonts() -> bool {
        const FONTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/reactos/0.4.16/reactos/Fonts/");
        let installed = TEST_FONTS.iter().all(|file_name| {
            let Ok(data) = std::fs::read(alloc::format!("{FONTS}{file_name}")) else {
                std::eprintln!("skipped: no {FONTS}{file_name} (cargo xtask fetch-userland)");
                return false;
            };
            install(file_name, Arc::from(data)).is_ok()
        });
        let pair = |from: &str, to: &str| (String::from(from), String::from(to));
        set_substitutes(alloc::vec![
            pair("MS Shell Dlg", "Tahoma"),
            pair("Terminal", "Lucida Console"),
            pair("Courier", "Courier New"),
        ]);
        installed
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn a_caption_in_tahoma_bold_has_its_glyphs_and_xp_s_metrics() {
        if !install_reactos_fonts() {
            return;
        }
        let run = text_run_named(TAHOMA_BOLD, -11, &units("Mino"), None, Quality::Antialiased).unwrap();
        assert_eq!((run.metrics.ascent, run.metrics.descent), (11, 2));
        assert_eq!(run.glyphs.len(), 4);
        assert!(run.glyphs.windows(2).all(|pair| pair[0].x < pair[1].x), "left to right");
        assert!((20..40).contains(&run.width), "Mino is {} pixels wide", run.width);
        assert!(!run.truncated);
        let spaced = text_run_named(TAHOMA_BOLD, -11, &units("M o"), None, Quality::Antialiased).unwrap();
        assert_eq!(spaced.glyphs.len(), 2, "a space has no glyph, only an advance");
    }

    #[test]
    fn a_text_too_wide_ends_with_an_ellipsis() {
        if !install_reactos_fonts() {
            return;
        }
        let text = units("A rather long caption for a narrow window");
        let full = text_run_named(TAHOMA_BOLD, -11, &text, None, Quality::Antialiased).unwrap();
        let cut = text_run_named(TAHOMA_BOLD, -11, &text, Some(60), Quality::Antialiased).unwrap();
        assert!(cut.truncated && cut.width <= 60 && cut.width < full.width, "{} of {}", cut.width, full.width);
        let fits = text_run_named(TAHOMA_BOLD, -11, &text, Some(full.width), Quality::Antialiased).unwrap();
        assert!(!fits.truncated, "exactly as wide fits");
    }

    #[test]
    fn marlett_symbols_are_monochrome_when_asked() {
        if !install_reactos_fonts() {
            return;
        }
        let run = text_run_named(MARLETT, 12, &units("r"), None, Quality::Monochrome).unwrap();
        let coverage = &run.glyphs[0].bitmap.coverage;
        assert!(coverage.iter().all(|&c| c == 0 || c == 255), "covered or not");
        assert!(coverage.contains(&255));
        assert_eq!(run.metrics.height(), 12, "a cell of 12 pixels");
    }

    #[test]
    fn a_file_that_is_no_font_is_refused() {
        assert_eq!(install("nofont.ttf", Arc::from(&b"no font"[..])), Err(glyph::Error::Malformed));
        assert!(faces().iter().all(|(_, info)| info.file_name != "nofont.ttf"), "nothing installed");
    }

    #[test]
    fn fonts_are_found_by_family_weight_and_italic() {
        if !install_reactos_fonts() {
            return;
        }
        // Without case: the reinstall below changes the case of Tahoma's name
        // in the table that the other tests, running at the same time, read.
        let file = |face: Option<Face>| face.and_then(info).map(|info| info.file_name.to_ascii_lowercase());
        assert_eq!(file(find("tahoma", 400, false)).as_deref(), Some("tahoma.ttf"), "without case");
        assert_eq!(file(find("Tahoma", 700, false)).as_deref(), Some("tahomabd.ttf"), "bold");
        assert_eq!(file(find("Tahoma", 550, false)).as_deref(), Some("tahomabd.ttf"), "nearer to 700 than to 400");
        assert_eq!(file(find("Tahoma", 500, true)).as_deref(), Some("tahoma.ttf"), "no italic Tahoma: the nearest");
        assert_eq!(file(find("Courier New", 400, true)).as_deref(), Some("couri.ttf"), "the italic face");
        assert_eq!(file(find("Courier New", 400, false)).as_deref(), Some("cour.ttf"), "the upright one");
        assert_eq!(file(find("VGA", 400, false)).as_deref(), Some("univga16.ttf"), "its family, not its file");
        assert_eq!(find("Arial", 400, false), None, "not installed");
        assert_eq!(file(named(MARLETT)).as_deref(), Some("marlett.ttf"));
        let reinstalled = install(
            "Tahoma.TTF",
            Arc::from(
                std::fs::read(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../third_party/reactos/0.4.16/reactos/Fonts/tahoma.ttf"
                ))
                .unwrap(),
            ),
        );
        assert_eq!(reinstalled.ok(), find("Tahoma", 400, false), "a font installed again keeps its place");
    }

    #[test]
    fn fonts_say_their_pitch_and_character_set() {
        if !install_reactos_fonts() {
            return;
        }
        let info = |family: &str| info(find(family, 400, false).unwrap()).unwrap();
        assert!(info("VGA").fixed_pitch() && info("Lucida Console").fixed_pitch() && info("Courier New").fixed_pitch());
        assert!(!info("Tahoma").fixed_pitch());
        assert_eq!(info("Tahoma").char_set, ANSI_CHARSET);
        assert_eq!((info("Tahoma").names.style.as_str(), info("Tahoma").weight), ("Regular", 400));
        assert_eq!(char_set_of(None), ANSI_CHARSET, "no OS/2 code pages");
        assert_eq!(char_set_of(Some(1 << 31)), SYMBOL_CHARSET);
        assert_eq!(char_set_of(Some(1 << 9 | 1 << 2)), RUSSIAN_CHARSET, "reserved bits are passed over");
    }

    #[test]
    fn glyph_indices_mark_or_default_what_is_missing() {
        if !install_reactos_fonts() {
            return;
        }
        let tahoma = find("Tahoma", 400, false).unwrap();
        let glyphs = glyph_indices(tahoma, &units("Ab"), Some(0xFFFF)).unwrap();
        assert!(glyphs.iter().all(|&glyph| glyph != 0 && glyph != 0xFFFF), "{glyphs:?}");
        assert_ne!(glyphs[0], glyphs[1]);
        let missing = [0xE000u16, 0xD800];
        assert_eq!(
            glyph_indices(tahoma, &missing, Some(0xFFFF)).unwrap(),
            [0xFFFF, 0xFFFF],
            "marked; a lone surrogate"
        );
        let default = glyph_indices(tahoma, &missing, None).unwrap();
        assert_eq!(default[0], default[1], "the default character's glyph");
        assert!(glyph_count(tahoma).unwrap() > 200);
    }

    #[test]
    fn abc_widths_add_up_to_the_advance() {
        if !install_reactos_fonts() {
            return;
        }
        let tahoma = find("Tahoma", 400, false).unwrap();
        let text = units("Wi j");
        let (advances, _) = advances(tahoma, -11, &text).unwrap();
        let codes: Vec<u32> = text.iter().map(|&unit| u32::from(unit)).collect();
        let by_char = abc_widths(tahoma, -11, &codes, false).unwrap();
        for (&(a, b, c), &advance) in by_char.iter().zip(&advances) {
            assert_eq!(a + b + c, advance);
        }
        assert_eq!(by_char[2], (0, 0, advances[2]), "a space is all advance");
        assert!(by_char.iter().enumerate().all(|(at, abc)| at == 2 || abc.1 > 0), "letters have ink: {by_char:?}");
        let glyphs: Vec<u32> = glyph_indices(tahoma, &text, None).unwrap().into_iter().map(u32::from).collect();
        assert_eq!(abc_widths(tahoma, -11, &glyphs, true).unwrap(), by_char, "by glyph index");
    }

    #[test]
    fn font_data_gives_a_table_or_the_file() {
        if !install_reactos_fonts() {
            return;
        }
        let tahoma = find("Tahoma", 400, false).unwrap();
        let tag = |name: &[u8; 4]| u32::from_le_bytes(*name);
        let (data, head) = font_data(tahoma, tag(b"head")).unwrap();
        assert_eq!(head.len(), 54, "the head table");
        assert_eq!(&data[head.start + 12..head.start + 16], &[0x5F, 0x0F, 0x3C, 0xF5], "its magic number");
        let (_, whole) = font_data(tahoma, 0).unwrap();
        assert_eq!(whole, 0..data.len(), "0: the whole file");
        assert!(font_data(tahoma, tag(b"zzzz")).is_none(), "no such table");
    }

    #[test]
    fn substitutes_are_followed_and_stop_on_a_loop() {
        let pair = |from: &str, to: &str| (String::from(from), String::from(to));
        let list = [pair("Old", "Middle"), pair("middle", "New"), pair("Ping", "Pong"), pair("Pong", "Ping")];
        assert_eq!(follow(&list, "OLD"), "New", "through two, without case");
        assert_eq!(follow(&list, "Other"), "Other", "no substitute");
        let looped = follow(&list, "Ping");
        assert!(looped == "Ping" || looped == "Pong", "a loop stops");
        if install_reactos_fonts() {
            assert_eq!(substitute("ms shell dlg"), "Tahoma");
            assert_eq!(substitutes_of("terminal"), [pair("Terminal", "Lucida Console")]);
        }
    }
}
