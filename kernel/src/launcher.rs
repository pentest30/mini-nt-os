//! Mino Launcher — interactive game selector drawn to the GOP framebuffer.
//!
//! Font scale: 2× (16×16 glyphs) for clear readability on 1280×800.
//! Keys: W/S = navigate, ENTER = launch (stub), D = debug shell.
//!
//! # IRQL: PASSIVE_LEVEL

// ── Scale ─────────────────────────────────────────────────────────────────────
const SC: u32 = 2;          // font pixel scale factor → 16×16 glyphs
const GW: u32 = 8 * SC;    // glyph width  in screen pixels
const GH: u32 = 8 * SC;    // glyph height in screen pixels

// ── Colours (0x00_RR_GG_BB) ──────────────────────────────────────────────────
const HEADER_BG: u32 = 0x00_0D_2A_4A; // dark navy
const HEADER_FG: u32 = 0x00_FF_FF_FF; // white
const BODY_BG:   u32 = 0x00_08_08_10; // near-black body
const SELECT_BG: u32 = 0x00_00_5C_9E; // blue highlight
const SELECT_FG: u32 = 0x00_FF_FF_FF; // white
const NORMAL_FG: u32 = 0x00_99_AA_BB; // light gray
const STATUS_BG: u32 = 0x00_0A_0A_14; // dark bar
const STATUS_FG: u32 = 0x00_55_66_77; // dim gray
const ACCENT_FG: u32 = 0x00_00_CC_88; // green accent
const DIM_FG:    u32 = 0x00_44_55_66; // dimmed metadata

// ── Layout (all values in screen pixels) ─────────────────────────────────────
const PAD:       u32 = 16;
const HEADER_H:  u32 = GH + PAD * 2; // header bar height
const DIVIDER_Y: u32 = HEADER_H;
const SUBTITLE_Y:u32 = DIVIDER_Y + PAD;
const LIST_Y:    u32 = SUBTITLE_Y + GH + PAD * 2;
const ROW_H:     u32 = GH + PAD;     // game row height
const STATUS_H:  u32 = GH + PAD;     // status bar height

// ── Game registry ─────────────────────────────────────────────────────────────
struct Game {
    name:   &'static str,
    status: &'static str,
    path:   &'static str,
}

static GAMES: &[Game] = &[
    Game { name: "Ghost Recon 2001 (GOG)",  status: "Phase 3 target", path: "/GAMES/GR/GR.EXE"     },
    Game { name: "Quake 3 Arena",           status: "Phase 3+",       path: "/GAMES/Q3/Q3.EXE"     },
    Game { name: "Half-Life 2",             status: "Phase 4 target", path: "/GAMES/HL2/HL2.EXE"   },
    Game { name: "Halo: Combat Evolved",    status: "Phase 4+",       path: "/GAMES/HALO/HALO.EXE" },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn txt(x: u32, y: u32, s: &str, fg: u32, bg: u32) {
    hal::fb::draw_text_at(x, y, s, fg, bg, SC);
}

#[inline]
fn rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    hal::fb::draw_rect(x, y, w, h, color);
}

// ── Repaint ───────────────────────────────────────────────────────────────────

fn repaint(selected: usize) {
    let (w, h) = hal::fb::screen_dims();
    if w == 0 || h == 0 { return; }

    // ── Background ──────────────────────────────────────────────────────────
    rect(0, 0, w, h, BODY_BG);

    // ── Header bar ──────────────────────────────────────────────────────────
    rect(0, 0, w, HEADER_H, HEADER_BG);
    txt(PAD, PAD, "micro-nt-os  --  Mino Launcher  v0.3", HEADER_FG, HEADER_BG);

    // Accent line under header
    rect(0, DIVIDER_Y, w, 2, ACCENT_FG);

    // Subtitle
    txt(PAD, SUBTITLE_Y, "W / S to navigate    ENTER to launch    D for debug shell", DIM_FG, BODY_BG);

    // ── Game list ────────────────────────────────────────────────────────────
    for (i, game) in GAMES.iter().enumerate() {
        let row_y  = LIST_Y + i as u32 * ROW_H;
        let is_sel = i == selected;
        let row_bg = if is_sel { SELECT_BG } else { BODY_BG };
        let row_fg = if is_sel { SELECT_FG } else { NORMAL_FG };

        rect(0, row_y, w, ROW_H, row_bg);

        // Selection arrow
        let arrow = if is_sel { ">" } else { " " };
        txt(PAD, row_y + PAD / 2, arrow, ACCENT_FG, row_bg);

        // Game name
        txt(PAD + GW + PAD / 2, row_y + PAD / 2, game.name, row_fg, row_bg);

        // Status tag — right-aligned
        let status_w = game.status.len() as u32 * GW;
        let sx = w.saturating_sub(PAD + status_w);
        txt(sx, row_y + PAD / 2, game.status, DIM_FG, row_bg);
    }

    // ── Status bar ───────────────────────────────────────────────────────────
    let bar_y = h.saturating_sub(STATUS_H);
    rect(0, bar_y, w, 2, ACCENT_FG);
    rect(0, bar_y + 2, w, STATUS_H, STATUS_BG);
    txt(PAD, bar_y + PAD / 2 + 1, "W/S Navigate    ENTER Launch    D Debug shell", STATUS_FG, STATUS_BG);
}

// ── Input ─────────────────────────────────────────────────────────────────────

fn read_key() -> u8 {
    loop {
        if let Some(b) = hal::ps2::try_read_byte()    { return b; }
        if let Some(b) = hal::serial::try_read_byte() { return b; }
        x86_64::instructions::hlt();
    }
}

/// Drain the PS/2 and serial FIFOs after a navigation action.
///
/// `repaint()` takes ~50 ms (filling 1280×800 pixels). During that window
/// PS/2 typematic repeats accumulate in the controller FIFO and would all
/// fire on the very next `read_key()` call, causing multi-step jumps.
/// Calling this immediately after repaint discards those stale bytes so each
/// physical keypress moves the selection by exactly one row.
#[inline]
fn drain_input() {
    for _ in 0..32 {
        let ps2_empty   = hal::ps2::try_read_byte().is_none();
        let serial_empty = hal::serial::try_read_byte().is_none();
        if ps2_empty && serial_empty { break; }
    }
}

// ── Public entry ──────────────────────────────────────────────────────────────

/// Run the Mino launcher. Returns when the user presses `D` (debug shell).
///
/// # IRQL: PASSIVE_LEVEL
pub fn run() {
    hal::fb::set_exclusive(true);
    let mut selected: usize = 0;
    repaint(selected);

    loop {
        match read_key() {
            b'w' | b'W' => {
                if selected > 0 { selected -= 1; repaint(selected); }
                drain_input();
            }
            b's' | b'S' => {
                if selected + 1 < GAMES.len() { selected += 1; repaint(selected); }
                drain_input();
            }
            b'\r' | b'\n' => {
                // TODO Phase 3: load + exec GAMES[selected].path via FAT + PE loader
                let (w, h) = hal::fb::screen_dims();
                let note_y = h / 2;
                rect(0, note_y - 4, w, GH + 8, BODY_BG);
                txt(PAD, note_y, "Not installed -- place game EXE in ESP:/GAMES/ first", ACCENT_FG, BODY_BG);
                hal::serial::write_str("[launcher] launch: ");
                hal::serial::write_str(GAMES[selected].path);
                hal::serial::write_str(" (not installed)\r\n");
            }
            b'd' | b'D' => {
                hal::fb::set_exclusive(false);
                hal::serial::write_str("[launcher] -> debug shell\r\n");
                return;
            }
            _ => {}
        }
    }
}
