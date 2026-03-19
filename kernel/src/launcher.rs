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
    Game { name: "D3D8 Test (DXVK chain)",  status: "Ready",         path: "/D3D8TEST.EXE"        },
    Game { name: "Ghost Recon 2001 (GOG)",  status: "Need GOG EXE",  path: "/GHOSTREC.EXE"        },
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
        // Read from the IRQ1 ring buffer (scancodes pushed by the ISR).
        if let Some(sc) = hal::ps2::pop_scancode() {
            if let Some(ascii) = hal::ps2::scancode_to_ascii_pub(sc) {
                return ascii;
            }
            // Key release or unmapped — try again.
            continue;
        }
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
        let ps2_empty    = hal::ps2::pop_scancode().is_none();
        let serial_empty = hal::serial::try_read_byte().is_none();
        if ps2_empty && serial_empty { break; }
    }
}

// ── Game launch ──────────────────────────────────────────────────────────────

/// Load a game EXE from the FAT ramdisk, set up PEB/TEB/stack, and spawn
/// as a ring-3 user-mode thread. Returns the thread ID (for wait) or None.
fn launch_game(fat_path: &str) -> Option<usize> {
    let file_name = fat_path.rsplit('/').next().unwrap_or(fat_path);

    // Use the buddy-backed DLL loader to read + parse + relocate the PE.
    // This handles files up to 16 MB without touching the 4 MB heap.
    let base = crate::syscall::load_dll_from_fat_pub(file_name);
    if base == 0 {
        hal::serial::write_str("[launch_game] load_dll_from_fat failed\r\n");
        return None;
    }

    // Debug: check if BSS is properly zeroed at the crash address
    let bss_val = unsafe { core::ptr::read_volatile(0x947BC4u64 as *const u32) };
    hal::serial::write_str("[BSS] 0x947BC4=");
    serial_write_hex(bss_val);
    hal::serial::write_str("\r\n");

    // Read entry point RVA from the loaded PE header (now mapped at base).
    // SAFETY: base is a valid mapped user VA; load_dll copies PE headers there.
    let entry_rva = unsafe {
        let e_lfanew = core::ptr::read_unaligned((base as u64 + 0x3C) as *const u32);
        if e_lfanew == 0 || e_lfanew > 0x1000 {
            hal::serial::write_str("[launch_game] bad e_lfanew\r\n");
            return None;
        }
        let opt_off = base as u64 + e_lfanew as u64 + 4 + 20;
        core::ptr::read_unaligned((opt_off + 16) as *const u32)
    };
    let entry_point = base.wrapping_add(entry_rva);

    hal::serial::write_str("[launch_game] entry=0x");
    serial_write_hex(entry_point);
    hal::serial::write_str("\r\n");

    // Set up PEB/TEB/stack for the game process
    let hhdm_offset = {
        let guard = crate::syscall::SYSCALL_CTX_PUB();
        match guard { Some(h) => h, None => return None }
    };

    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let mut mapper = crate::KernelPageMapper { pt };

    // Read image size from the mapped PE header
    let image_size = unsafe {
        let e_lfanew = core::ptr::read_unaligned((base as u64 + 0x3C) as *const u32);
        let opt_off = base as u64 + e_lfanew as u64 + 4 + 20;
        core::ptr::read_unaligned((opt_off + 56) as *const u32)
    };
    let img = ps::loader::LoadedImage {
        image_base: base as u64,
        entry_point: entry_point as u64,
        image_size,
    };

    // Allocate a fresh VAD for the game process
    let mut vad = mm::vad::VadTree::new();
    // Register the game image region in the VAD so setup_process doesn't conflict
    use mm::vad::{VadNode, PageProtect};
    let _ = vad.insert(VadNode::private(
        base as u64,
        base as u64 + image_size as u64,
        PageProtect::EXECUTE_READWRITE,
    ));

    static GAME_PID: spin::Mutex<u32> = spin::Mutex::new(100);
    let pid = {
        let mut p = GAME_PID.lock();
        let out = *p;
        *p = p.wrapping_add(4);
        out
    };

    let ctx = match ps::loader::setup_process(&img, &mut vad, &mut mapper, pid, 2) {
        Ok(c) => c,
        Err(e) => {
            hal::serial::write_str("[launch_game] setup_process failed: ");
            hal::serial::write_str(e);
            hal::serial::write_str("\r\n");
            return None;
        }
    };

    // Build a user-mode trampoline page BEFORE installing the VAD.
    let tramp_va = 0x00F0_0000u32;
    {
        use mm::vad::{VadNode, PageProtect};
        let _ = vad.insert(VadNode::private(
            tramp_va as u64, tramp_va as u64 + 0x1000,
            PageProtect::EXECUTE_READWRITE,
        ));
        use mm::virtual_alloc::PageMapper;
        let _ = mapper.commit_page(tramp_va as u64, true, true, true);
    }

    // Install the game's VAD as the active syscall context
    crate::syscall::install(vad, hhdm_offset);
    hal::timer::set_shared_user_data_addr(Some(ps::loader::SHARED_USER_DATA32_VA as u64));

    // Skip DllMain — MinGW CRT crashes at 0x11017e during constructor init.
    // The d3d8/d3d9 stubs handle Direct3DCreate8 via COM vtable without DllMain.
    // TODO Phase 4: proper MinGW CRT init (TLS, .CRT$XCA constructors).
    let dll_entries: alloc::vec::Vec<(u32,u32)> = alloc::vec::Vec::new();
    let code = tramp_va as *mut u8;
    let mut off = 0usize;

    for &(dll_base, dll_entry) in &dll_entries {
        hal::serial::write_str("[launch_game] DllMain trampoline: 0x");
        serial_write_hex(dll_entry);
        hal::serial::write_str("\r\n");
        // PUSH 0        (lpReserved)
        // PUSH 1        (DLL_PROCESS_ATTACH)
        // PUSH dll_base (hInstDLL)
        // MOV EAX, dll_entry
        // CALL EAX
        // (stdcall: callee cleans 12 bytes)
        unsafe {
            // push 0
            *code.add(off) = 0x6A; off += 1;
            *code.add(off) = 0x00; off += 1;
            // push 1
            *code.add(off) = 0x6A; off += 1;
            *code.add(off) = 0x01; off += 1;
            // push imm32 (dll_base)
            *code.add(off) = 0x68; off += 1;
            (code.add(off) as *mut u32).write_unaligned(dll_base); off += 4;
            // mov eax, imm32 (dll_entry)
            *code.add(off) = 0xB8; off += 1;
            (code.add(off) as *mut u32).write_unaligned(dll_entry); off += 4;
            // call eax
            *code.add(off) = 0xFF; off += 1;
            *code.add(off) = 0xD0; off += 1;
        }
    }

    // JMP game_entry (absolute)
    unsafe {
        *code.add(off) = 0xB8; off += 1;  // MOV EAX, entry_point
        (code.add(off) as *mut u32).write_unaligned(entry_point); off += 4;
        *code.add(off) = 0xFF; off += 1;  // JMP EAX
        *code.add(off) = 0xE0; off += 1;
    }

    hal::serial::write_str("[launch_game] trampoline built (");
    serial_write_u32(dll_entries.len() as u32);
    hal::serial::write_str(" DllMain calls + game entry)\r\n");

    // Spawn ring-3 thread — starts at the trampoline, which calls DllMains then jumps to game
    ke::scheduler::spawn_user_thread(
        tramp_va,
        ctx.stack_top,
        hal::gdt::user_code32_selector(),
        hal::gdt::user_data32_selector(),
        hal::gdt::user_teb_fs_selector(),
    )
}

fn serial_write_u32(mut n: u32) {
    if n == 0 { hal::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    hal::serial::write_str(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
}

fn serial_write_hex(n: u32) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 8];
    let mut v = n;
    let mut i = buf.len();
    loop { i -= 1; buf[i] = hex[(v & 0xF) as usize]; v >>= 4; if v == 0 || i == 0 { break; } }
    hal::serial::write_str(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
}

// ── Public entry ──────────────────────────────────────────────────────────────

/// Redraw only a single game row (fast — avoids full-screen repaint).
fn repaint_row(i: usize, selected: usize) {
    let (w, _) = hal::fb::screen_dims();
    if w == 0 { return; }
    let game = &GAMES[i];
    let row_y  = LIST_Y + i as u32 * ROW_H;
    let is_sel = i == selected;
    let row_bg = if is_sel { SELECT_BG } else { BODY_BG };
    let row_fg = if is_sel { SELECT_FG } else { NORMAL_FG };
    rect(0, row_y, w, ROW_H, row_bg);
    let arrow = if is_sel { ">" } else { " " };
    txt(PAD, row_y + PAD / 2, arrow, ACCENT_FG, row_bg);
    txt(PAD + GW + PAD / 2, row_y + PAD / 2, game.name, row_fg, row_bg);
    let status_w = game.status.len() as u32 * GW;
    let sx = w.saturating_sub(PAD + status_w);
    txt(sx, row_y + PAD / 2, game.status, DIM_FG, row_bg);
}

/// Run the Mino launcher. Returns when the user presses `D` (debug shell).
///
/// # IRQL: PASSIVE_LEVEL
pub fn run() {
    hal::fb::set_exclusive(true);
    hal::serial::write_str("[launcher] repaint start\r\n");
    let mut selected: usize = 0;
    repaint(selected);
    hal::serial::write_str("[launcher] repaint done — waiting for input\r\n");

    loop {
        match read_key() {
            b'w' | b'W' => {
                if selected > 0 {
                    let old = selected;
                    selected -= 1;
                    repaint_row(old, selected);
                    repaint_row(selected, selected);
                }
                drain_input();
            }
            b's' | b'S' => {
                if selected + 1 < GAMES.len() {
                    let old = selected;
                    selected += 1;
                    repaint_row(old, selected);
                    repaint_row(selected, selected);
                }
                drain_input();
            }
            b'\r' | b'\n' => {
                let path = GAMES[selected].path;
                let (w, h) = hal::fb::screen_dims();
                let note_y = h / 2;

                // Check if the game EXE exists on the FAT ramdisk
                if io_manager::open_fat_file(path).is_err() {
                    rect(0, note_y - 4, w, GH + 8, BODY_BG);
                    txt(PAD, note_y, "Not installed -- place game EXE on ramdisk", ACCENT_FG, BODY_BG);
                    hal::serial::write_str("[launcher] ");
                    hal::serial::write_str(path);
                    hal::serial::write_str(" not found\r\n");
                } else {
                    rect(0, note_y - 4, w, GH + 16, BODY_BG);
                    txt(PAD, note_y, "Loading...", ACCENT_FG, BODY_BG);
                    hal::serial::write_str("[launcher] launching ");
                    hal::serial::write_str(path);
                    hal::serial::write_str("\r\n");

                    // Release exclusive mode — game owns the framebuffer
                    hal::fb::set_exclusive(false);

                    match launch_game(path) {
                        Some(tid) => {
                            hal::serial::write_str("[launcher] game running (TID=");
                            serial_write_u32(tid as u32);
                            hal::serial::write_str(")\r\n");

                            // Wait for the game process to exit
                            while ke::scheduler::is_thread_running(tid) {
                                x86_64::instructions::hlt();
                            }
                            hal::serial::write_str("[launcher] game exited\r\n");
                        }
                        None => {
                            hal::serial::write_str("[launcher] launch FAILED\r\n");
                            rect(0, note_y - 4, w, GH + 16, BODY_BG);
                            txt(PAD, note_y, "Launch failed -- check serial log", 0x00FF4444, BODY_BG);
                        }
                    }
                    // Reclaim screen
                    hal::fb::set_exclusive(true);
                    repaint(selected);
                }
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
