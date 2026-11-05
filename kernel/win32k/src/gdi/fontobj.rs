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
//! Correspondance : une graisse de 600 ou plus donne Tahoma gras, sinon Tahoma
//! (les polices du cadre, ADR-013) ; « Marlett » donne Marlett. Les autres noms
//! (MS Shell Dlg, MS Sans Serif, System, Arial…) donnent aussi Tahoma, faute de
//! `FontSubstitutes` et des autres polices sur le disque. La hauteur est celle
//! du LOGFONT (négative : l'em ; positive : la cellule ; nulle : 12 pixels de
//! cellule).
//!
//! Pas encore : la largeur, l'italique, le soulignement et le barré au dessin
//! (les métriques les disent), l'orientation, les autres polices du disque et
//! leur énumération (EnumFontFamilies), GetObject d'une police,
//! GetCharWidth, GetTextExtentExPoint, OUTLINETEXTMETRIC.

use alloc::sync::Arc;

use abi::gdi::{objt, stock, LogFontW32, TextMetricW32, TmDiff32, TmwInternal32, ANSI_CHARSET, DEFAULT_CHARSET};
use abi::gdi::{LO_FONT_TYPE, SYMBOL_CHARSET};
use abi::ntstatus::NtStatus;

use super::handles::{self, Object, OWNER_PUBLIC};
use crate::font::{self, Face, Quality, TextRun};

/// Un objet police (LFONT) : le LOGFONT que le client a donné.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FontObject {
    pub logfont: LogFontW32,
}

/// FW_SEMIBOLD : la graisse à partir de laquelle la police est grasse.
const FW_SEMIBOLD: i32 = 600;
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

/// La police installée et la hauteur de LOGFONT que donne `logfont`.
pub fn realize(logfont: &LogFontW32) -> (Face, i32) {
    let marlett: alloc::vec::Vec<u16> = "marlett".encode_utf16().collect();
    let lower = |unit: u16| if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) { unit + 32 } else { unit };
    let face = if logfont.face().iter().map(|&u| lower(u)).eq(marlett.iter().copied()) {
        Face::Marlett
    } else if logfont.weight >= FW_SEMIBOLD {
        Face::TahomaBold
    } else {
        Face::Tahoma
    };
    (face, logfont.height)
}

/// `text` mis en glyphes dans la police `logfont` ; `None` sans la police
/// installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_run(logfont: &LogFontW32, text: &[u16]) -> Option<TextRun> {
    let (face, height) = realize(logfont);
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

/// ftGdiGetTextMetricsW : le TMW_INTERNAL de `logfont` (FillTM) ; l'italique,
/// le soulignement et le barré sont ceux demandés. `None` sans la police
/// installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_metrics(logfont: &LogFontW32) -> Option<TmwInternal32> {
    let (face, height) = realize(logfont);
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
        assert_eq!(realize(&named("MS Shell Dlg", FW_NORMAL)), (Face::Tahoma, -11));
        assert_eq!(realize(&named("Tahoma", FW_BOLD)), (Face::TahomaBold, -11), "bold");
        assert_eq!(realize(&named("Tahoma", 600)), (Face::TahomaBold, -11), "semibold (600) is bold");
        assert_eq!(realize(&named("Tahoma", 599)), (Face::Tahoma, -11), "below it, not");
        assert_eq!(realize(&named("MARLETT", FW_NORMAL)), (Face::Marlett, -11), "without case");
        assert_eq!(realize(&named("", 0)), (Face::Tahoma, -11), "the default");
        let system = stock_fonts()[3];
        assert_eq!((system.0, realize(&system.1)), (stock::SYSTEM_FONT, (Face::TahomaBold, 16)));
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
    }
}
