//! The fonts of the pinned ReactOS (`cargo xtask fetch-userland`), as win32k
//! uses them: Tahoma for the captions and the dialogs, Marlett for the caption
//! buttons (ADR-013). Skipped when the userland is not fetched.

use glyph::{Font, Metrics, ONE};

const FONTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/reactos/0.4.16/reactos/Fonts/");

fn read(name: &str) -> Option<Vec<u8>> {
    let path = format!("{FONTS}{name}");
    let file = std::fs::read(&path).ok();
    if file.is_none() {
        eprintln!("skipped: no {path} (cargo xtask fetch-userland)");
    }
    file
}

/// The coverage at (x, y) of a bitmap.
fn at(bitmap: &glyph::Bitmap, x: usize, y: usize) -> u8 {
    bitmap.coverage[y * bitmap.width + x]
}

#[test]
fn tahoma_at_8_points_has_xp_s_text_metrics() {
    let Some(file) = read("tahoma.ttf") else { return };
    let font = Font::parse(&file).expect("Tahoma");
    assert_eq!(font.units_per_em(), 2048);
    // LOGFONT height -11 at 96 DPI: an em of 11 pixels.
    let metrics = font.metrics(11 * ONE);
    assert_eq!(metrics, Metrics { ascent: 11, descent: 2, external_leading: 0, average_width: 5 });
    assert_eq!(metrics.height(), 13);
    // A positive height asks for the cell: 13 pixels give the same font.
    let em = font.em_for_cell(13);
    assert!((em - 11 * ONE).abs() < ONE / 4, "an em of {} for a cell of 13", em as f64 / ONE as f64);
    assert_eq!(font.metrics(em).height(), 13);
}

#[test]
fn tahoma_glyphs_have_stems_holes_and_advances() {
    let Some(file) = read("tahoma.ttf") else { return };
    let font = Font::parse(&file).expect("Tahoma");
    let em = 11 * ONE;
    let h = font.glyph_index('H').expect("H");
    let bitmap = font.render(h, em).expect("an outline");
    // Cap height of Tahoma is about 0.73 em: 8 pixels, on the baseline.
    assert!((7..=9).contains(&bitmap.height), "H is {} pixels high", bitmap.height);
    assert_eq!(bitmap.top as usize, bitmap.height, "H stands on the baseline");
    // Two stems: columns covered from top to bottom, and a bar between them.
    let column = |x: usize| (0..bitmap.height).map(|y| u32::from(at(&bitmap, x, y))).sum::<u32>();
    let full = 255 * bitmap.height as u32;
    let stems = (0..bitmap.width).filter(|&x| column(x) * 2 > full).count();
    assert!(stems >= 2, "the stems of H: {:?}", (0..bitmap.width).map(column).collect::<Vec<_>>());
    let advance = font.advance(h, em);
    assert!((6 * ONE..=9 * ONE).contains(&advance), "H advances {} pixels", advance as f64 / ONE as f64);

    let o = font.render(font.glyph_index('o').expect("o"), em).expect("an outline");
    let (cx, cy) = (o.width / 2, o.height / 2);
    assert!(at(&o, cx, cy) < 64, "the hole of o");
    assert!(at(&o, cx, 0) > 128 || at(&o, cx, 1) > 128, "the top of its ring");

    let space = font.glyph_index(' ').expect("space");
    assert!(font.render(space, em).is_none(), "a space has no outline");
    assert!(font.advance(space, em) > ONE, "but it advances");
    assert!(font.glyph_index('\u{E000}').is_none(), "no glyph in the private use area");
}

#[test]
fn tahoma_bold_is_wider_than_tahoma() {
    let (Some(regular), Some(bold)) = (read("tahoma.ttf"), read("tahomabd.ttf")) else { return };
    let (regular, bold) = (Font::parse(&regular).unwrap(), Font::parse(&bold).unwrap());
    let em = 11 * ONE;
    let width =
        |font: &Font, text: &str| -> i64 { text.chars().map(|c| font.advance(font.glyph_index(c).unwrap(), em)).sum() };
    assert!(width(&bold, "Mino") > width(&regular, "Mino"));
    assert_eq!(bold.metrics(em).height(), 13, "the same cell");
}

#[test]
fn marlett_maps_its_symbols_and_draws_the_close_button() {
    let Some(file) = read("Marlett.ttf") else { return };
    let font = Font::parse(&file).expect("Marlett");
    // The caption buttons: minimize '0', maximize '1', restore '2', close 'r'.
    let glyphs: Vec<_> = ['0', '1', '2', 'r'].iter().map(|&c| font.glyph_index(c)).collect();
    assert!(glyphs.iter().all(Option::is_some), "Marlett's symbols: {glyphs:?}");
    let close = font.render(glyphs[3].unwrap(), 9 * ONE).expect("the close cross");
    assert!(close.width >= 5 && close.height >= 5, "{}×{}", close.width, close.height);
    // A cross: its centre is covered, its edges' middles are not.
    let (cx, cy) = (close.width / 2, close.height / 2);
    assert!(at(&close, cx, cy) > 128, "the centre of the cross");
    assert!(at(&close, cx, 0) < 128, "the middle of its top edge");
    // Its diagonals mirror each other.
    let mirrored = (0..close.height)
        .all(|y| (0..close.width).all(|x| at(&close, x, y).abs_diff(at(&close, close.width - 1 - x, y)) < 96));
    assert!(mirrored, "a symmetric cross");
}

#[test]
fn malformed_data_is_refused() {
    assert_eq!(Font::parse(b"not a font").err(), Some(glyph::Error::Malformed));
}

#[test]
fn tahoma_and_marlett_have_the_text_metrics_gdi_gives_them() {
    let (Some(tahoma), Some(bold), Some(marlett)) = (read("tahoma.ttf"), read("tahomabd.ttf"), read("Marlett.ttf"))
    else {
        return;
    };
    let tahoma = Font::parse(&tahoma).unwrap();
    let metrics = tahoma.text_metrics(11 * ONE);
    assert_eq!((metrics.metrics.height(), metrics.internal_leading), (13, 2), "13 pixels, an em of 11");
    assert_eq!(metrics.weight, 400);
    assert_eq!((metrics.first_char, metrics.break_char, metrics.default_char), (0x20, 0x20, 0x1F));
    assert!(metrics.last_char > 0xFF, "a Unicode font: {:#x}", metrics.last_char);
    assert_eq!(metrics.pitch_and_family, 0x27, "variable pitch, vector, TrueType, Swiss");
    assert!(metrics.max_width > metrics.metrics.average_width);
    assert!(!metrics.symbol);
    assert_eq!(Font::parse(&bold).unwrap().text_metrics(11 * ONE).weight, 700);
    // This Marlett (Wine's) maps its symbols by Unicode, from 0 to y: not a
    // symbol font for GDI.
    let symbols = Font::parse(&marlett).unwrap().text_metrics(12 * ONE);
    assert!(!symbols.symbol);
    assert_eq!((symbols.first_char, symbols.last_char), (0x30, 0x79));
    assert_eq!((symbols.break_char, symbols.default_char), (0x30, 0x2F), "its first character, and the one before");
}

#[test]
fn names_italics_and_code_pages_are_those_gdi_reads() {
    let fonts = [
        ("tahoma.ttf", "Tahoma", "Regular", "Tahoma", false),
        ("tahomabd.ttf", "Tahoma", "Bold", "Tahoma Bold", false),
        ("UniVGA16.ttf", "VGA", "Medium", "VGA Medium", false),
        ("lucon.ttf", "Lucida Console", "Book", "Lucida Console", false),
        ("couri.ttf", "Courier New", "Italic", "Courier New Italic", true),
    ];
    for (file_name, family, style, full_name, italic) in fonts {
        let Some(file) = read(file_name) else { return };
        let font = Font::parse(&file).expect(file_name);
        let names = font.names();
        assert_eq!((names.family.as_str(), names.style.as_str()), (family, style), "{file_name}");
        assert_eq!(names.full_name, full_name, "{file_name}");
        assert_eq!(font.is_italic(), italic, "{file_name}");
    }
    let Some(file) = read("tahoma.ttf") else { return };
    let (latin, _) = Font::parse(&file).unwrap().code_page_ranges().expect("OS/2 of version 1 or later");
    assert_ne!(latin & 1, 0, "Latin 1 (code page 1252)");
}

#[test]
fn vga_is_a_fixed_pitch_modern_font() {
    let Some(file) = read("UniVGA16.ttf") else { return };
    let tm = Font::parse(&file).expect("VGA").text_metrics(16 * ONE);
    // Its `post` says proportional, its PANOSE monospaced: GDI takes it as
    // fixed (TMPF_FIXED_PITCH clear), FF_MODERN.
    assert_eq!(tm.pitch_and_family & 0x01, 0, "fixed pitch");
    assert_eq!(tm.pitch_and_family & 0xF0, glyph::font::FF_MODERN);
}
