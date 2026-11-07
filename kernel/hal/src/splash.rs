//! Le rideau de démarrage : un écran d'attente à la marque Mino — fond noir,
//! la marque au centre, une barre de progression à trois blocs, les mentions
//! du bas — pendant que le journal ne parle plus qu'à COM1.
//!
//! Le rideau s'affiche dès que le framebuffer est prêt
//! ([`show`], appelé par le démarrage du noyau), s'anime à chaque battement
//! d'horloge ([`tick`], depuis l'interruption du temporisateur) et se lève
//! quand quelqu'un d'autre prend l'écran : le premier dessin de win32k
//! ([`hide`]), le mode exclusif du lanceur ([`fb::set_exclusive`]) ou un
//! écran fatal ([`fb::write_str_fatal`], qui efface le rideau avant d'écrire).
//!
//! Rien de Microsoft ici : les formes et les couleurs sont celles du thème
//! de Mino ; l'agencement (fond noir, marque centrée, barre, mentions du
//! bas) est un motif d'écran d'attente générique.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::fb;

/// Le rideau est affiché : le miroir écran du journal est silencié.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Les battements d'horloge depuis l'affichage ; l'animation y lit sa phase.
static BEATS: AtomicU32 = AtomicU32::new(0);

/// Un pas d'animation tous les trois battements (~30 ms à 100 Hz).
const BEATS_PER_STEP: u32 = 3;
/// Chaque pas avance de deux pixels.
const STEP_PX: u32 = 2;

// Les couleurs (convention de fb : 0x00_RR_GG_BB) : le fond, le blanc du
// texte, le bleu de la marque, l'orange des blocs (l'accent du thème du
// bureau) et le gris pâle du cadre et des mentions.
const BG: u32 = 0x00_00_00_00;
const WHITE: u32 = 0x00_FF_FF_FF;
const MARK_COLOR: u32 = 0x00_20_9C_E0;
const BLOCK_COLOR: u32 = 0x00_D4_8C_53;
const PALE: u32 = 0x00_C8_C0_B8;

/// La marque : un carré de 88 px aux coins arrondis.
const MARK: u32 = 88;
/// La barre : 240 × 20, cadre de 2 px.
const BAR: (u32, u32) = (240, 20);

/// Affiche le rideau : fond noir, la marque et son « M », le mot « Mino », la
/// barre vide et les mentions du bas. Sans framebuffer, rien.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn show() {
    let (width, height) = fb::dimensions();
    if width == 0 || height == 0 {
        return;
    }
    fb::draw_rect(0, 0, width, height, BG);
    let cx = width / 2;
    let cy = height / 2;
    // La marque, 120 px au-dessus du centre, et son « M » blanc.
    let mark_x = cx - MARK / 2;
    let mark_y = cy - 120;
    rounded_square(mark_x, mark_y, MARK, MARK, 18, MARK_COLOR);
    fb::draw_text_at(mark_x + (MARK - 64) / 2, mark_y + 12, "M", WHITE, BG, 8);
    // Le mot « MINO OS », à l'échelle 4 (32 px par lettre), sous la marque.
    let word = "MINO OS";
    fb::draw_text_at(cx - word.len() as u32 * 16, mark_y + MARK + 20, word, WHITE, BG, 4);
    // La barre de progression, son cadre, et l'intérieur noir.
    let (bar_x, bar_y) = (cx - BAR.0 / 2, mark_y + MARK + 72);
    rounded_square(bar_x, bar_y, BAR.0, BAR.1, 8, PALE);
    rounded_square(bar_x + 2, bar_y + 2, BAR.0 - 4, BAR.1 - 4, 6, BG);
    // Les mentions du bas, comme il se doit.
    fb::draw_text_at(24, height - 40, "Copyright (c) MINO OS", PALE, BG, 1);
    fb::draw_text_at(width - 24 - 7 * 8, height - 40, "MINO OS", PALE, BG, 1);
    BEATS.store(0, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Release);
}

/// Un battement d'horloge : un pas d'animation tous les
/// [`BEATS_PER_STEP`], tant que le rideau est affiché. Les trois blocs
/// avancent de [`STEP_PX`] et rebondissent aux extrémités de la barre.
///
/// # IRQL
/// CLOCK_LEVEL (l'interruption d'horloge). Les écritures écran passent par
/// le verrou de la console, qui désactive les interruptions : pas de
/// blocage, et quelques microsecondes de plus au plus fort de l'attente.
#[inline]
pub fn tick() {
    if !ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let beats = BEATS.fetch_add(1, Ordering::Relaxed);
    if beats % BEATS_PER_STEP != 0 {
        return;
    }
    let (width, height) = fb::dimensions();
    if width == 0 || height == 0 {
        return;
    }
    let (bar_x, bar_y) = bar_place(width, height);
    // L'intérieur de la barre (le cadre de 2 px reste).
    let (inner_x, inner_y) = (bar_x + 4, bar_y + 4);
    let (inner_w, inner_h) = (BAR.0 - 8, BAR.1 - 8);
    // Le train : trois blocs de 14 px, espacés de 6.
    let (block, gap) = (14u32, 6u32);
    let train = 3 * block + 2 * gap;
    let range = inner_w - train;
    let phase = (beats / BEATS_PER_STEP) * STEP_PX % (2 * range);
    let pos = if phase >= range { 2 * range - phase } else { phase };
    fb::draw_rect(inner_x, inner_y, inner_w, inner_h, BG);
    for index in 0..3 {
        let x = inner_x + pos + index * (block + gap);
        fb::draw_rect(x, inner_y + (inner_h - 10) / 2, block, 10, BLOCK_COLOR);
    }
}

/// Le rideau se lève : `true` s'il était affiché (celui qui prend l'écran
/// doit donc l'effacer d'abord).
///
/// # IRQL
/// Tout niveau.
pub fn hide() -> bool {
    ACTIVE.swap(false, Ordering::AcqRel)
}

/// Le rideau est-il affiché ?
///
/// # IRQL
/// Tout niveau.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// La place de la barre, recalculée à l'identique pour l'animation.
fn bar_place(width: u32, height: u32) -> (u32, u32) {
    (width / 2 - BAR.0 / 2, height / 2 - 120 + MARK + 72)
}

/// Un carré plein aux coins arrondis : trois rectangles, puis les quatre
/// quarts de disque, un pixel à la fois.
fn rounded_square(x: u32, y: u32, w: u32, h: u32, radius: u32, color: u32) {
    let radius = radius.min(w / 2).min(h / 2);
    fb::draw_rect(x, y + radius, w, h - 2 * radius, color);
    fb::draw_rect(x + radius, y, w - 2 * radius, radius, color);
    fb::draw_rect(x + radius, y + h - radius, w - 2 * radius, radius, color);
    let corners = [(x, y), (x + w - radius, y), (x, y + h - radius), (x + w - radius, y + h - radius)];
    for py in 0..radius {
        for px in 0..radius {
            let dx = radius - 1 - px;
            let dy = radius - 1 - py;
            if dx * dx + dy * dy <= radius * radius {
                for (corner_x, corner_y) in corners {
                    fb::draw_rect(corner_x + px, corner_y + py, 1, 1, color);
                }
            }
        }
    }
}
