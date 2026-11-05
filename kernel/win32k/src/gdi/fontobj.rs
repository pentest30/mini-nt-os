//! Les polices de GDI (`font.c`, `freetype.c`, `stockobj.c` de ReactOS,
//! comme spécification) : l'objet police d'un client (LFONT, NtGdiHfontCreate),
//! les polices de stock, la correspondance d'un LOGFONT avec une police
//! installée (`crate::font`), ses métriques (TEXTMETRIC) et l'étendue d'un
//! texte.
//!
//! La police d'un DC est celle de ses attributs (`hlfntNew`, que `gdi32`
//! change lui-même : GdiSelectFont), le noyau la lisant quand il en a besoin ;
//! un DC neuf a la police du système (SYSTEM_FONT).
//!
//! Correspondance (TextIntRealizeFont) : le nom du LOGFONT à travers les
//! substituts (`FontSubstitutes`, SubstituteFontRecurse), puis la police de
//! cette famille la plus proche de sa graisse et de son italique
//! (`crate::font::find`) ; sans police de cette famille, une police à pas fixe
//! (Courier New d'abord) si le LOGFONT en demande une (FIXED_PITCH ou
//! FF_MODERN), sinon Tahoma, sinon la première installée. ReactOS donne une
//! pénalité à chaque écart (GetFontPenalty) ; ici, le nom décide. La hauteur
//! est celle du LOGFONT (négative : l'em ; positive : la cellule ; nulle : 12
//! pixels de cellule).
//!
//! L'énumération (EnumFontFamiliesEx, NtGdiGetFontFamilyInfo) :
//! [`family_info`].
//!
//! Pas encore : la largeur, l'italique, le soulignement et le barré au dessin
//! (les métriques les disent), l'orientation, GetObject d'une police,
//! GetCharWidth, les index de glyphes (GetTextExtentExPointI),
//! OUTLINETEXTMETRIC.

use alloc::string::String;
use alloc::sync::Arc;

use abi::gdi::{objt, stock, LogFontW32, TextMetricW32, TmDiff32, TmwInternal32, ANSI_CHARSET, DEFAULT_CHARSET};
use abi::gdi::{
    EnumLogFontExW32, FontFamilyInfo32, FontSignature32, NewTextMetricExW32, NewTextMetricW32, CLIP_DEFAULT_PRECIS,
    FF_MODERN, FIXED_PITCH, LO_FONT_TYPE, NTM_BOLD, NTM_ITALIC, NTM_REGULAR, OUT_OUTLINE_PRECIS, PROOF_QUALITY,
    SYMBOL_CHARSET, TRUETYPE_FONTTYPE,
};
use abi::ntstatus::NtStatus;

use super::handles::{self, Object, OWNER_PUBLIC};
use crate::font::{self, Face, Quality, TextRun};

/// Un objet police (LFONT) : le LOGFONT que le client a donné.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FontObject {
    pub logfont: LogFontW32,
}

const FW_NORMAL: i32 = 400;
const FW_BOLD: i32 = 700;

/// Un LOGFONT : hauteur, graisse et nom (les autres champs restent nuls).
fn logfont(height: i32, weight: i32, char_set: u8, face: &str) -> LogFontW32 {
    let mut logfont = LogFontW32 { height, weight, char_set, ..LogFontW32::default() };
    for (slot, unit) in logfont.face_name.iter_mut().zip(face.encode_utf16()) {
        *slot = unit;
    }
    logfont
}

/// Les polices de stock (CreateStockFonts, pour une page de code occidentale) :
/// leur index d'objet de stock et leur LOGFONT.
pub fn stock_fonts() -> [(usize, LogFontW32); 7] {
    [
        (stock::OEM_FIXED_FONT, logfont(12, FW_NORMAL, 255, "Terminal")),
        (stock::ANSI_FIXED_FONT, logfont(12, FW_NORMAL, ANSI_CHARSET, "Courier")),
        (stock::ANSI_VAR_FONT, logfont(12, FW_NORMAL, ANSI_CHARSET, "MS Sans Serif")),
        (stock::SYSTEM_FONT, logfont(16, FW_BOLD, DEFAULT_CHARSET, "System")),
        (stock::DEVICE_DEFAULT_FONT, logfont(16, FW_BOLD, ANSI_CHARSET, "System")),
        (stock::SYSTEM_FIXED_FONT, logfont(15, FW_NORMAL, DEFAULT_CHARSET, "Fixedsys")),
        (stock::DEFAULT_GUI_FONT, logfont(-11, FW_NORMAL, DEFAULT_CHARSET, "MS Shell Dlg")),
    ]
}

/// Un objet police de stock, public ; rend son handle.
pub fn create_stock(logfont: LogFontW32) -> Result<u32, NtStatus> {
    let handle =
        handles::insert(Object::Font(Arc::new(FontObject { logfont })), LO_FONT_TYPE, objt::LFONT, OWNER_PUBLIC)?;
    handles::make_stock(handle)
}

/// NtGdiHfontCreate : un objet police de `logfont`, au processus `pid` ;
/// rend son handle.
///
/// # Errors
/// Ceux de la table des handles.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn create(logfont: LogFontW32, pid: u32) -> Result<u32, NtStatus> {
    handles::insert(Object::Font(Arc::new(FontObject { logfont })), LO_FONT_TYPE, objt::LFONT, pid)
}

/// La police de `handle`, au processus `pid` ou publique.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(handle: u32, pid: u32) -> Option<LogFontW32> {
    match handles::get(handle, pid)? {
        Object::Font(font) => Some(font.logfont),
        _ => None,
    }
}

/// La police de `handle`, ou celle du système si `handle` n'en est pas une.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get_or_system(handle: u32, pid: u32) -> LogFontW32 {
    get(handle, pid).unwrap_or_else(|| stock_fonts()[3].1)
}

/// La police installée et la hauteur de LOGFONT que donne `logfont` (voir le
/// module) ; `None` sans police installée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn realize(logfont: &LogFontW32) -> Option<(Face, i32)> {
    let name = String::from_utf16_lossy(logfont.face());
    let family = font::substitute(name.trim());
    let weight = if logfont.weight <= 0 { FW_NORMAL } else { logfont.weight.min(1000) } as u16;
    let italic = logfont.italic != 0;
    let face = font::find(&family, weight, italic).or_else(|| {
        let fixed = logfont.pitch_and_family & 0x03 == FIXED_PITCH || logfont.pitch_and_family & 0xF0 == FF_MODERN;
        let fixed_face = || {
            font::find("Courier New", weight, italic)
                .or_else(|| font::faces().into_iter().find(|(_, info)| info.fixed_pitch()).map(|(face, _)| face))
        };
        let default = || font::find("Tahoma", weight, italic).or_else(|| font::faces().first().map(|(face, _)| *face));
        if fixed {
            fixed_face().or_else(default)
        } else {
            default()
        }
    })?;
    Some((face, logfont.height))
}

/// `text` mis en glyphes dans la police `logfont` ; `None` sans la police
/// installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_run(logfont: &LogFontW32, text: &[u16]) -> Option<TextRun> {
    let (face, height) = realize(logfont)?;
    font::text_run(face, height, text, None, Quality::Antialiased)
}

/// GetTextExtentPoint32 : la largeur de `text` (la somme des avances) et la
/// hauteur de la police (tmHeight) ; `None` sans la police installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_extent(logfont: &LogFontW32, text: &[u16]) -> Option<(i32, i32)> {
    let run = text_run(logfont, text)?;
    Some((run.width, run.metrics.height()))
}

/// TextIntGetTextExtentPoint : les étendues cumulées de `text` (la largeur
/// de chaque préfixe, une par unité UTF-16) et la hauteur de la police ;
/// `None` sans la police installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_extents(logfont: &LogFontW32, text: &[u16]) -> Option<(alloc::vec::Vec<i32>, i32)> {
    let (face, height) = realize(logfont)?;
    let (advances, metrics) = font::advances(face, height, text)?;
    let mut sum = 0;
    let cumulative = advances
        .iter()
        .map(|advance| {
            sum += advance;
            sum
        })
        .collect();
    Some((cumulative, metrics.height()))
}

/// FS_LATIN1 et FS_SYMBOL : les bits de FONTSIGNATURE.fsCsb[0] de la page
/// de code 1252 et des symboles.
const FS_LATIN1: u32 = 0x0000_0001;
const FS_SYMBOL: u32 = 0x8000_0000;

/// Le nom de l'écriture de chaque bit de fsCsb[0] (elfScript ; `g_ElfScripts`
/// de ReactOS comme spécification) ; vide pour les bits réservés.
const SCRIPTS: [&str; 32] = [
    "Western",
    "Central European",
    "Cyrillic",
    "Greek",
    "Turkish",
    "Hebrew",
    "Arabic",
    "Baltic",
    "Vietnamese",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "Thai",
    "Japanese",
    "CHINESE_GB2312",
    "Hangul",
    "CHINESE_BIG5",
    "Hangul(Johab)",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "Symbol",
];

/// `text` dans un tableau de caractères terminé par NUL (tronqué s'il le
/// faut).
fn copy_units<const N: usize>(text: &str, into: &mut [u16; N]) {
    for (slot, unit) in into.iter_mut().take(N - 1).zip(text.encode_utf16()) {
        *slot = unit;
    }
}

/// FontFamilyFillInfo : l'entrée d'énumération de `face`, sous le nom
/// `nominal` s'il est donné (celui d'un substitut), sinon sous sa famille.
/// Son LOGFONT et son TEXTMETRIC sont ceux de la hauteur par défaut.
fn fill_info(face: font::Face, info: &font::FaceInfo, nominal: Option<&str>) -> Option<FontFamilyInfo32> {
    let metrics = font::enumeration_metrics(face)?;
    let (tm, size_em, cell_height) = (metrics.text_metrics, metrics.size_em, metrics.cell_height);
    let (usb, mut csb) = (metrics.unicode_ranges, metrics.code_pages);
    let italic = if info.italic { 0xFF } else { 0 };
    let log_font = LogFontW32 {
        height: tm.metrics.height(),
        width: tm.metrics.average_width,
        weight: i32::from(tm.weight),
        italic,
        char_set: info.char_set,
        out_precision: OUT_OUTLINE_PRECIS,
        clip_precision: CLIP_DEFAULT_PRECIS,
        quality: PROOF_QUALITY,
        pitch_and_family: (tm.pitch_and_family & 0xF1) + 1,
        ..LogFontW32::default()
    };
    let mut enum_log_font = EnumLogFontExW32 { log_font, ..EnumLogFontExW32::default() };
    copy_units(nominal.unwrap_or(&info.names.family), &mut enum_log_font.log_font.face_name);
    copy_units(&info.names.full_name, &mut enum_log_font.full_name);
    copy_units(&info.names.style, &mut enum_log_font.style);
    if csb[0] == 0 {
        csb[0] = if tm.symbol { FS_SYMBOL } else { FS_LATIN1 };
    }
    // The script of the last code page that has a character set, as ReactOS.
    if let Some(script) =
        (0..32).rev().filter(|&bit| csb[0] & (1 << bit) != 0).map(|bit| SCRIPTS[bit]).find(|s| !s.is_empty())
    {
        copy_units(script, &mut enum_log_font.script);
    }
    let text_metric = TextMetricW32 {
        height: tm.metrics.height(),
        ascent: tm.metrics.ascent,
        descent: tm.metrics.descent,
        internal_leading: tm.internal_leading,
        external_leading: tm.metrics.external_leading,
        ave_char_width: tm.metrics.average_width.max(1),
        max_char_width: tm.max_width,
        weight: i32::from(tm.weight),
        overhang: 0,
        digitized_aspect_x: 96,
        digitized_aspect_y: 96,
        first_char: tm.first_char,
        last_char: tm.last_char,
        default_char: tm.default_char,
        break_char: tm.break_char,
        italic,
        underlined: 0,
        struck_out: 0,
        pitch_and_family: tm.pitch_and_family,
        char_set: info.char_set,
        reserved: [0; 3],
    };
    let mut flags = if info.italic { NTM_ITALIC } else { 0 };
    if tm.weight > 550 {
        flags |= NTM_BOLD;
    }
    if flags == 0 {
        flags = NTM_REGULAR;
    }
    let ntm = NewTextMetricW32 { text_metric, flags, size_em: u32::from(size_em), cell_height, avg_width: 0 };
    Some(FontFamilyInfo32 {
        enum_log_font,
        new_text_metric: NewTextMetricExW32 { ntm, signature: FontSignature32 { usb, csb } },
        font_type: TRUETYPE_FONTTYPE,
    })
}

/// Le nom `name` désigne la police `info` : sa famille ou son nom complet,
/// sans casse.
fn names_face(name: &str, info: &font::FaceInfo) -> bool {
    name.eq_ignore_ascii_case(&info.names.family) || name.eq_ignore_ascii_case(&info.names.full_name)
}

/// IntGetFontFamilyInfo : les polices qu'énumère EnumFontFamiliesEx pour
/// `logfont` (son nom, s'il en a un, et son jeu de caractères, sauf
/// DEFAULT_CHARSET) : les polices installées de ce nom (GetFontFamilyInfoForList),
/// puis celles que désignent les substituts de ce nom, sous le nom du
/// substitut (GetFontFamilyInfoForSubstitutes ; le premier seulement quand
/// un nom est donné).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn family_info(logfont: &LogFontW32) -> alloc::vec::Vec<FontFamilyInfo32> {
    let name = String::from_utf16_lossy(logfont.face());
    let char_set = logfont.char_set;
    let matches = |info: &font::FaceInfo, name: &str| {
        (char_set == DEFAULT_CHARSET || char_set == info.char_set) && (name.is_empty() || names_face(name, info))
    };
    let faces = font::faces();
    let mut entries: alloc::vec::Vec<FontFamilyInfo32> = faces
        .iter()
        .filter(|(_, info)| matches(info, &name))
        .filter_map(|(face, info)| fill_info(*face, info, None))
        .collect();
    for (from, to) in font::substitutes_of(&name) {
        if from.eq_ignore_ascii_case(&to) {
            continue;
        }
        let real = font::substitute(&from);
        entries.extend(
            faces
                .iter()
                .filter(|(_, info)| matches(info, &real))
                .filter_map(|(face, info)| fill_info(*face, info, Some(&from))),
        );
        if !name.is_empty() {
            break;
        }
    }
    entries
}

/// ftGdiGetTextMetricsW : le TMW_INTERNAL de `logfont` (FillTM) ; l'italique,
/// le soulignement et le barré sont ceux demandés. `None` sans la police
/// installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_metrics(logfont: &LogFontW32) -> Option<TmwInternal32> {
    let (face, height) = realize(logfont)?;
    let tm = font::text_metrics(face, height)?;
    let flag = |on: u8| if on != 0 { 0xFF } else { 0 };
    let narrow = |unit: u16| unit.min(0xFF) as u8;
    let text_metric = TextMetricW32 {
        height: tm.metrics.height(),
        ascent: tm.metrics.ascent,
        descent: tm.metrics.descent,
        internal_leading: tm.internal_leading,
        external_leading: tm.metrics.external_leading,
        ave_char_width: tm.metrics.average_width.max(1),
        max_char_width: tm.max_width,
        weight: i32::from(tm.weight),
        overhang: 0,
        digitized_aspect_x: 96,
        digitized_aspect_y: 96,
        first_char: tm.first_char,
        last_char: tm.last_char,
        default_char: tm.default_char,
        break_char: tm.break_char,
        italic: flag(logfont.italic),
        underlined: flag(logfont.underline),
        struck_out: flag(logfont.strike_out),
        pitch_and_family: tm.pitch_and_family,
        char_set: if tm.symbol { SYMBOL_CHARSET } else { ANSI_CHARSET },
        reserved: [0; 3],
    };
    let diff = TmDiff32 {
        cjotma: 0,
        ch_first: narrow(tm.first_char),
        ch_last: narrow(tm.last_char),
        ch_default: narrow(tm.default_char),
        ch_break: narrow(tm.break_char),
    };
    Some(TmwInternal32 { text_metric, diff })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(face: &str, weight: i32) -> LogFontW32 {
        logfont(-11, weight, DEFAULT_CHARSET, face)
    }

    #[test]
    fn a_logfont_gives_one_of_the_installed_fonts() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let file = |logfont: &LogFontW32| realize(logfont).and_then(|(face, _)| font::info(face)).unwrap().file_name;
        assert_eq!(file(&named("MS Shell Dlg", FW_NORMAL)), "tahoma.ttf", "a substitute");
        assert_eq!(realize(&named("MS Shell Dlg", FW_NORMAL)).map(|(_, height)| height), Some(-11));
        assert_eq!(file(&named("Tahoma", FW_BOLD)), "tahomabd.ttf", "bold");
        assert_eq!(file(&named("Tahoma", 600)), "tahomabd.ttf", "semibold (600) is nearer to bold");
        assert_eq!(file(&named("Tahoma", 549)), "tahoma.ttf", "549 is nearer to regular");
        assert_eq!(file(&named("MARLETT", FW_NORMAL)), "Marlett.ttf", "without case");
        assert_eq!(file(&named("vga", FW_NORMAL)), "UniVGA16.ttf", "the console's font, by its family");
        assert_eq!(file(&named("Terminal", FW_NORMAL)), "lucon.ttf", "Terminal is Lucida Console");
        assert_eq!(file(&named("", 0)), "tahoma.ttf", "the default");
        assert_eq!(file(&named("No Such Font", FW_NORMAL)), "tahoma.ttf", "an unknown name");
        let fixed = LogFontW32 { pitch_and_family: FIXED_PITCH, ..named("No Such Font", FW_NORMAL) };
        assert_eq!(file(&fixed), "cour.ttf", "an unknown fixed-pitch font: Courier New");
        let modern = LogFontW32 { pitch_and_family: FF_MODERN, ..named("", FW_NORMAL) };
        assert_eq!(file(&modern), "cour.ttf", "FF_MODERN");
        let system = stock_fonts()[3];
        assert_eq!(system.0, stock::SYSTEM_FONT);
        assert_eq!((file(&system.1), realize(&system.1).unwrap().1), (String::from("tahomabd.ttf"), 16));
    }

    #[test]
    fn enumeration_gives_fonts_by_name_and_substitutes_by_theirs() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let text = |units: &[u16]| String::from_utf16_lossy(&units[..units.iter().position(|&u| u == 0).unwrap()]);
        let vga = family_info(&named("vga", 0));
        assert_eq!(vga.len(), 1, "one face of that family");
        let entry = &vga[0];
        let log_font = &entry.enum_log_font.log_font;
        assert_eq!(text(&log_font.face_name), "VGA");
        assert_eq!(
            (text(&entry.enum_log_font.full_name), text(&entry.enum_log_font.style)),
            (String::from("VGA Medium"), String::from("Medium"))
        );
        // What consrv's IsValidConsoleFont2 asks of a console font.
        assert_eq!(log_font.pitch_and_family & 0x03, FIXED_PITCH, "fixed pitch");
        assert_eq!(log_font.pitch_and_family & 0xF0, FF_MODERN);
        assert_eq!(entry.font_type, TRUETYPE_FONTTYPE);
        assert_eq!(entry.new_text_metric.ntm.text_metric.height, log_font.height, "the default height");
        assert!(entry.new_text_metric.ntm.size_em > 0 && entry.new_text_metric.ntm.cell_height > 0);

        let terminal = family_info(&named("Terminal", 0));
        assert_eq!(terminal.len(), 1, "through its substitute");
        assert_eq!(text(&terminal[0].enum_log_font.log_font.face_name), "Terminal", "under the substitute's name");
        assert_eq!(text(&terminal[0].enum_log_font.full_name), "Lucida Console");

        let tahoma = family_info(&named("Tahoma", 0));
        let flags: alloc::vec::Vec<u32> = tahoma.iter().map(|entry| entry.new_text_metric.ntm.flags).collect();
        assert_eq!(flags, [NTM_REGULAR, NTM_BOLD], "regular and bold");
        // Its code pages: bits 0 to 4, 6 and 29 (reserved, without a script).
        assert_eq!(text(&tahoma[0].enum_log_font.script), "Arabic", "the script of its last code page");
        assert!(family_info(&named("No Such Font", 0)).is_empty());
        let japanese = LogFontW32 { char_set: abi::gdi::SHIFTJIS_CHARSET, ..named("Tahoma", 0) };
        assert!(family_info(&japanese).is_empty(), "another character set");
        let all = family_info(&LogFontW32 { char_set: DEFAULT_CHARSET, ..LogFontW32::default() });
        assert!(all.len() >= font::faces().len(), "every installed font, then the substitutes");
    }

    #[test]
    fn the_default_gui_font_has_xp_s_metrics() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let gui = stock_fonts()[6].1;
        let tm = text_metrics(&gui).unwrap().text_metric;
        assert_eq!((tm.height, tm.ascent, tm.descent, tm.internal_leading, tm.external_leading), (13, 11, 2, 2, 0));
        assert_eq!((tm.ave_char_width, tm.weight, tm.pitch_and_family, tm.char_set), (5, 400, 0x27, ANSI_CHARSET));
        assert_eq!((tm.digitized_aspect_x, tm.digitized_aspect_y, tm.first_char, tm.break_char), (96, 96, 0x20, 0x20));
        let underlined = LogFontW32 { underline: 1, italic: 1, ..gui };
        let tm = text_metrics(&underlined).unwrap().text_metric;
        assert_eq!((tm.underlined, tm.italic, tm.struck_out), (0xFF, 0xFF, 0), "as asked");
        let (width, height) = text_extent(&gui, &"Mino".encode_utf16().collect::<alloc::vec::Vec<_>>()).unwrap();
        assert_eq!(height, 13);
        assert!((18..30).contains(&width), "Mino is {width} pixels wide");
        let (bold, _) =
            text_extent(&named("Tahoma", FW_BOLD), &"Mino".encode_utf16().collect::<alloc::vec::Vec<_>>()).unwrap();
        assert!(bold > width, "bold is wider");
        let (extents, height) = text_extents(&gui, &"Mino".encode_utf16().collect::<alloc::vec::Vec<_>>()).unwrap();
        assert_eq!((extents.len(), extents[3], height), (4, width, 13), "the last extent is the width");
        assert!(extents.windows(2).all(|pair| pair[0] < pair[1]), "growing: {extents:?}");
    }
}
