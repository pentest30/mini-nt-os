//! GOP linear framebuffer console.
//!
//! Provides a simple 8×8-pixel text console drawn directly into the UEFI GOP
//! framebuffer.  All `log::*` records are mirrored here alongside COM1 serial.
//!
//! # Colour convention
//! Internal colours are `0x00_RR_GG_BB` (CSS-style).
//! - `Bgr` display: write the u32 value directly (little-endian gives B G R _).
//! - `Rgb` display: swap R and B before writing.
//!
//! # IRQL
//! `write_log_record` is called from `SerialLogger::log` at PASSIVE_LEVEL.
//! The CONSOLE spin-lock is held only briefly per character; never call from ISR.

use spin::Mutex;
use boot_info::{FramebufferInfo, PixelFormat};
use core::sync::atomic::{AtomicBool, Ordering};

/// When true, `write_log_record` is silenced — the launcher owns the screen.
static EXCLUSIVE: AtomicBool = AtomicBool::new(false);

/// Switch the display between log-mirror mode and exclusive launcher mode.
///
/// Set `on=true` before drawing the launcher UI; `on=false` when returning to
/// the serial debug shell so kernel log messages appear on screen again.
///
/// # IRQL: PASSIVE_LEVEL
pub fn set_exclusive(on: bool) {
    EXCLUSIVE.store(on, Ordering::Relaxed);
}

/// Returns true if the launcher owns the screen (and PS/2 input).
pub fn is_exclusive() -> bool {
    EXCLUSIVE.load(Ordering::Relaxed)
}

// ── Colours ───────────────────────────────────────────────────────────────────

const FG: u32 = 0x00_FF_FF_FF; // white
const BG: u32 = 0x00_00_00_00; // black

// ── 8×8 bitmap font — ASCII 0x20 … 0x7F ─────────────────────────────────────
//
// Each entry is 8 bytes (one per row). Bit 0 of a byte is the leftmost pixel.
// Source: classic VGA BIOS 8×8 character set (public domain).

static FONT: [[u8; 8]; 96] = [
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00], // 0x20  ' '
    [0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00], // 0x21  '!'
    [0x36,0x36,0x00,0x00,0x00,0x00,0x00,0x00], // 0x22  '"'
    [0x36,0x36,0x7F,0x36,0x7F,0x36,0x36,0x00], // 0x23  '#'
    [0x0C,0x3E,0x03,0x1E,0x30,0x1F,0x0C,0x00], // 0x24  '$'
    [0x00,0x63,0x33,0x18,0x0C,0x66,0x63,0x00], // 0x25  '%'
    [0x1C,0x36,0x1C,0x6E,0x3B,0x33,0x6E,0x00], // 0x26  '&'
    [0x06,0x06,0x03,0x00,0x00,0x00,0x00,0x00], // 0x27  '\''
    [0x18,0x0C,0x06,0x06,0x06,0x0C,0x18,0x00], // 0x28  '('
    [0x06,0x0C,0x18,0x18,0x18,0x0C,0x06,0x00], // 0x29  ')'
    [0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00], // 0x2A  '*'
    [0x00,0x0C,0x0C,0x3F,0x0C,0x0C,0x00,0x00], // 0x2B  '+'
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x06], // 0x2C  ','
    [0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00], // 0x2D  '-'
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x00], // 0x2E  '.'
    [0x60,0x30,0x18,0x0C,0x06,0x03,0x01,0x00], // 0x2F  '/'
    [0x3E,0x63,0x73,0x7B,0x6F,0x67,0x3E,0x00], // 0x30  '0'
    [0x0C,0x0E,0x0C,0x0C,0x0C,0x0C,0x3F,0x00], // 0x31  '1'
    [0x1E,0x33,0x30,0x1C,0x06,0x33,0x3F,0x00], // 0x32  '2'
    [0x1E,0x33,0x30,0x1C,0x30,0x33,0x1E,0x00], // 0x33  '3'
    [0x38,0x3C,0x36,0x33,0x7F,0x30,0x78,0x00], // 0x34  '4'
    [0x3F,0x03,0x1F,0x30,0x30,0x33,0x1E,0x00], // 0x35  '5'
    [0x1C,0x06,0x03,0x1F,0x33,0x33,0x1E,0x00], // 0x36  '6'
    [0x3F,0x33,0x30,0x18,0x0C,0x0C,0x0C,0x00], // 0x37  '7'
    [0x1E,0x33,0x33,0x1E,0x33,0x33,0x1E,0x00], // 0x38  '8'
    [0x1E,0x33,0x33,0x3E,0x30,0x18,0x0E,0x00], // 0x39  '9'
    [0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x00], // 0x3A  ':'
    [0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x06], // 0x3B  ';'
    [0x18,0x0C,0x06,0x03,0x06,0x0C,0x18,0x00], // 0x3C  '<'
    [0x00,0x00,0x3F,0x00,0x00,0x3F,0x00,0x00], // 0x3D  '='
    [0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00], // 0x3E  '>'
    [0x1E,0x33,0x30,0x18,0x0C,0x00,0x0C,0x00], // 0x3F  '?'
    [0x3E,0x63,0x7B,0x7B,0x7B,0x03,0x1E,0x00], // 0x40  '@'
    [0x0C,0x1E,0x33,0x33,0x3F,0x33,0x33,0x00], // 0x41  'A'
    [0x3F,0x66,0x66,0x3E,0x66,0x66,0x3F,0x00], // 0x42  'B'
    [0x3C,0x66,0x03,0x03,0x03,0x66,0x3C,0x00], // 0x43  'C'
    [0x1F,0x36,0x66,0x66,0x66,0x36,0x1F,0x00], // 0x44  'D'
    [0x7F,0x46,0x16,0x1E,0x16,0x46,0x7F,0x00], // 0x45  'E'
    [0x7F,0x46,0x16,0x1E,0x16,0x06,0x0F,0x00], // 0x46  'F'
    [0x3C,0x66,0x03,0x03,0x73,0x66,0x7C,0x00], // 0x47  'G'
    [0x33,0x33,0x33,0x3F,0x33,0x33,0x33,0x00], // 0x48  'H'
    [0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 0x49  'I'
    [0x78,0x30,0x30,0x30,0x33,0x33,0x1E,0x00], // 0x4A  'J'
    [0x67,0x66,0x36,0x1E,0x36,0x66,0x67,0x00], // 0x4B  'K'
    [0x0F,0x06,0x06,0x06,0x46,0x66,0x7F,0x00], // 0x4C  'L'
    [0x63,0x77,0x7F,0x7F,0x6B,0x63,0x63,0x00], // 0x4D  'M'
    [0x63,0x67,0x6F,0x7B,0x73,0x63,0x63,0x00], // 0x4E  'N'
    [0x1C,0x36,0x63,0x63,0x63,0x36,0x1C,0x00], // 0x4F  'O'
    [0x3F,0x66,0x66,0x3E,0x06,0x06,0x0F,0x00], // 0x50  'P'
    [0x1E,0x33,0x33,0x33,0x3B,0x1E,0x38,0x00], // 0x51  'Q'
    [0x3F,0x66,0x66,0x3E,0x36,0x66,0x67,0x00], // 0x52  'R'
    [0x1E,0x33,0x07,0x0E,0x38,0x33,0x1E,0x00], // 0x53  'S'
    [0x3F,0x2D,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 0x54  'T'
    [0x33,0x33,0x33,0x33,0x33,0x33,0x3F,0x00], // 0x55  'U'
    [0x33,0x33,0x33,0x33,0x33,0x1E,0x0C,0x00], // 0x56  'V'
    [0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00], // 0x57  'W'
    [0x63,0x63,0x36,0x1C,0x1C,0x36,0x63,0x00], // 0x58  'X'
    [0x33,0x33,0x33,0x1E,0x0C,0x0C,0x1E,0x00], // 0x59  'Y'
    [0x7F,0x63,0x31,0x18,0x4C,0x66,0x7F,0x00], // 0x5A  'Z'
    [0x1E,0x06,0x06,0x06,0x06,0x06,0x1E,0x00], // 0x5B  '['
    [0x03,0x06,0x0C,0x18,0x30,0x60,0x40,0x00], // 0x5C  '\'
    [0x1E,0x18,0x18,0x18,0x18,0x18,0x1E,0x00], // 0x5D  ']'
    [0x08,0x1C,0x36,0x63,0x00,0x00,0x00,0x00], // 0x5E  '^'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF], // 0x5F  '_'
    [0x0C,0x0C,0x18,0x00,0x00,0x00,0x00,0x00], // 0x60  '`'
    [0x00,0x00,0x1E,0x30,0x3E,0x33,0x6E,0x00], // 0x61  'a'
    [0x07,0x06,0x06,0x3E,0x66,0x66,0x3B,0x00], // 0x62  'b'
    [0x00,0x00,0x1E,0x33,0x03,0x33,0x1E,0x00], // 0x63  'c'
    [0x38,0x30,0x30,0x3E,0x33,0x33,0x6E,0x00], // 0x64  'd'
    [0x00,0x00,0x1E,0x33,0x3F,0x03,0x1E,0x00], // 0x65  'e'
    [0x1C,0x36,0x06,0x0F,0x06,0x06,0x0F,0x00], // 0x66  'f'
    [0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x1F], // 0x67  'g'
    [0x07,0x06,0x36,0x6E,0x66,0x66,0x67,0x00], // 0x68  'h'
    [0x0C,0x00,0x0E,0x0C,0x0C,0x0C,0x1E,0x00], // 0x69  'i'
    [0x30,0x00,0x30,0x30,0x30,0x33,0x33,0x1E], // 0x6A  'j'
    [0x07,0x06,0x66,0x36,0x1E,0x36,0x67,0x00], // 0x6B  'k'
    [0x0E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 0x6C  'l'
    [0x00,0x00,0x33,0x7F,0x7F,0x6B,0x63,0x00], // 0x6D  'm'
    [0x00,0x00,0x1F,0x33,0x33,0x33,0x33,0x00], // 0x6E  'n'
    [0x00,0x00,0x1E,0x33,0x33,0x33,0x1E,0x00], // 0x6F  'o'
    [0x00,0x00,0x3B,0x66,0x66,0x3E,0x06,0x0F], // 0x70  'p'
    [0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x78], // 0x71  'q'
    [0x00,0x00,0x3B,0x6E,0x66,0x06,0x0F,0x00], // 0x72  'r'
    [0x00,0x00,0x3E,0x03,0x1E,0x30,0x1F,0x00], // 0x73  's'
    [0x08,0x0C,0x3E,0x0C,0x0C,0x2C,0x18,0x00], // 0x74  't'
    [0x00,0x00,0x33,0x33,0x33,0x33,0x6E,0x00], // 0x75  'u'
    [0x00,0x00,0x33,0x33,0x33,0x1E,0x0C,0x00], // 0x76  'v'
    [0x00,0x00,0x63,0x6B,0x7F,0x7F,0x36,0x00], // 0x77  'w'
    [0x00,0x00,0x63,0x36,0x1C,0x36,0x63,0x00], // 0x78  'x'
    [0x00,0x00,0x33,0x33,0x33,0x3E,0x30,0x1F], // 0x79  'y'
    [0x00,0x00,0x3F,0x19,0x0C,0x26,0x3F,0x00], // 0x7A  'z'
    [0x38,0x0C,0x0C,0x07,0x0C,0x0C,0x38,0x00], // 0x7B  '{'
    [0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00], // 0x7C  '|'
    [0x07,0x0C,0x0C,0x38,0x0C,0x0C,0x07,0x00], // 0x7D  '}'
    [0x6E,0x3B,0x00,0x00,0x00,0x00,0x00,0x00], // 0x7E  '~'
    [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF], // 0x7F  DEL → full block
];

// ── Console state ─────────────────────────────────────────────────────────────

const GW: u32 = 8; // glyph width  (pixels)
const GH: u32 = 8; // glyph height (pixels)

struct Console {
    fb:     *mut u32,   // HHDM-mapped virtual base of the framebuffer
    width:  u32,        // horizontal resolution (pixels)
    height: u32,        // vertical   resolution (pixels)
    stride: u32,        // pixels per scan line
    format: PixelFormat,
    col:    u32,        // current column  (character cells)
    row:    u32,        // current row     (character cells)
    cols:   u32,        // total columns
    rows:   u32,        // total rows
}

// SAFETY: Console is accessed exclusively through the CONSOLE spin-lock.
//         The raw pointer is a stable HHDM-mapped physical range.
unsafe impl Send for Console {}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

// ── Private helpers ───────────────────────────────────────────────────────────

impl Console {
    /// Convert an internal `0x00RRGGBB` colour to the native framebuffer format.
    #[inline]
    fn to_native(&self, color: u32) -> u32 {
        match self.format {
            // BGR: memory is [B, G, R, _].  Little-endian u32 of 0x00RRGGBB
            //      is already [BB, GG, RR, 00] = [B, G, R, _]. ✓
            PixelFormat::Bgr | PixelFormat::Unknown => color,
            // RGB: memory is [R, G, B, _].  Swap R and B.
            PixelFormat::Rgb => {
                let r = (color >> 16) & 0xFF;
                let g = (color >>  8) & 0xFF;
                let b =  color        & 0xFF;
                (b << 16) | (g << 8) | r
            }
        }
    }

    #[inline]
    fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height { return; }
        let native = self.to_native(color);
        // SAFETY: x, y are bounds-checked; fb points to a valid mapped framebuffer.
        unsafe { self.fb.add((y * self.stride + x) as usize).write_volatile(native); }
    }

    fn draw_glyph(&mut self, col: u32, row: u32, ch: u8) {
        self.draw_glyph_px(col * GW, row * GH, ch, FG, BG, 1);
    }

    fn clear_row(&mut self, row: u32) {
        let bg = self.to_native(BG);
        let py = row * GH;
        for y in py..py + GH {
            for x in 0..self.width {
                // SAFETY: x,y within framebuffer dimensions.
                unsafe { self.fb.add((y * self.stride + x) as usize).write_volatile(bg); }
            }
        }
    }

    fn clear(&mut self) {
        let bg    = self.to_native(BG);
        let total = (self.height * self.stride) as usize;
        // SAFETY: total covers exactly the mapped framebuffer.
        for i in 0..total {
            unsafe { self.fb.add(i).write_volatile(bg); }
        }
        self.col = 0;
        self.row = 0;
    }

    fn scroll(&mut self) {
        // Copy all rows up by one glyph height using memmove-style ptr::copy.
        let row_pixels = (GH * self.stride) as usize;
        let copy_pixels = ((self.rows - 1) * GH * self.stride) as usize;
        // SAFETY: src and dst are within the framebuffer; dst < src so no overlap issue.
        unsafe {
            let dst = self.fb as *mut u8;
            let src = (self.fb as *mut u8).add(row_pixels * 4);
            core::ptr::copy(src, dst, copy_pixels * 4);
        }
        self.clear_row(self.rows - 1);
        self.row = self.rows - 1;
    }

    fn write_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.col = 0;
                self.row += 1;
                if self.row >= self.rows { self.scroll(); }
            }
            '\r' => {
                self.col = 0;
            }
            '\x08' => {
                // Backspace: move cursor left and blank the vacated cell.
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = self.cols - 1;
                }
                self.draw_glyph(self.col, self.row, b' ');
            }
            c if (c as u32) >= 0x20 && (c as u32) < 0x80 => {
                self.draw_glyph(self.col, self.row, c as u8);
                self.col += 1;
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows { self.scroll(); }
                }
            }
            _ => {} // skip other control chars and non-ASCII
        }
    }

    fn write_str_inner(&mut self, s: &str) {
        for ch in s.chars() { self.write_char(ch); }
    }
}

// ── Pixel-level drawing primitives ────────────────────────────────────────────

impl Console {
    /// Fill a rectangle. `color` is 0x00_RR_GG_BB.
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let native = self.to_native(color);
        let x1 = x.min(self.width);
        let y1 = y.min(self.height);
        let x2 = (x + w).min(self.width);
        let y2 = (y + h).min(self.height);
        for row in y1..y2 {
            for col in x1..x2 {
                // SAFETY: col, row are bounds-checked against framebuffer dims.
                unsafe { self.fb.add((row * self.stride + col) as usize).write_volatile(native); }
            }
        }
    }

    /// Draw a character at pixel position (px, py) with explicit fg/bg.
    /// Each source pixel is rendered as a `scale × scale` block.
    fn draw_glyph_px(&mut self, px: u32, py: u32, ch: u8, fg: u32, bg: u32, scale: u32) {
        let idx = ch.wrapping_sub(0x20) as usize;
        let glyph = if idx < 96 { &FONT[idx] } else { &FONT[0] };
        let fg_n = self.to_native(fg);
        let bg_n = self.to_native(bg);
        for gy in 0..GH {
            let bits = glyph[gy as usize];
            for gx in 0..GW {
                let native = if bits & (0x01 << gx) != 0 { fg_n } else { bg_n };
                for sy in 0..scale {
                    for sx in 0..scale {
                        let x = px + gx * scale + sx;
                        let y = py + gy * scale + sy;
                        if x < self.width && y < self.height {
                            // SAFETY: x, y are bounds-checked against framebuffer dims.
                            unsafe { self.fb.add((y * self.stride + x) as usize).write_volatile(native); }
                        }
                    }
                }
            }
        }
    }

    /// Draw a string at pixel position (px, py). Clips at screen right edge.
    fn draw_str_px(&mut self, mut px: u32, py: u32, s: &str, fg: u32, bg: u32, scale: u32) {
        let gw = GW * scale;
        for ch in s.bytes() {
            if px + gw > self.width { break; }
            if ch >= 0x20 && ch < 0x80 {
                self.draw_glyph_px(px, py, ch, fg, bg, scale);
            }
            px += gw;
        }
    }
}

// ── Bochs Graphics Adapter (BGA / VBE DISPI) reinit ──────────────────────────
//
// OVMF calls ExitBootServices callbacks that reset VGA to text mode.  After
// that, writes to the GOP linear framebuffer physical address reach guest RAM
// but the QEMU SDL display renders VGA text mode from the VGA VRAM region —
// so nothing we write appears on screen.
//
// Fix: reprogram the BGA I/O ports (0x01CE / 0x01CF) to re-enable the linear
// framebuffer at the same resolution OVMF configured.  NOCLEARMEM avoids
// wiping any content; we clear in software afterward.

#[cfg(target_os = "none")]
fn bga_init_lfb(width: u32, height: u32) {
    use x86_64::instructions::port::Port;

    const BGA_IDX: u16 = 0x01CE;
    const BGA_DAT: u16 = 0x01CF;

    // BGA register indices
    const R_ID:     u16 = 0x00;
    const R_XRES:   u16 = 0x01;
    const R_YRES:   u16 = 0x02;
    const R_BPP:    u16 = 0x03;
    const R_ENABLE: u16 = 0x04;
    const R_VIRT_W: u16 = 0x06;

    // ENABLE field flags
    const F_ENABLED:    u16 = 0x01;
    const F_LFB:        u16 = 0x40;
    const F_NOCLEARMEM: u16 = 0x80;

    // SAFETY: I/O port access on bare-metal x86; ports 0x01CE/0x01CF are the
    // standard Bochs VBE DISPI index/data ports used by QEMU's standard VGA.
    let mut idx: Port<u16> = unsafe { Port::new(BGA_IDX) };
    let mut dat: Port<u16> = unsafe { Port::new(BGA_DAT) };

    // Verify BGA is present: ID register must be 0xB0C0–0xB0C6.
    let id = unsafe { idx.write(R_ID); dat.read() };
    if !(0xB0C0..=0xB0C6).contains(&id) {
        super::serial::write_str("[fb] BGA not detected — skipping LFB reinit\r\n");
        return;
    }

    let w = width  as u16;
    let h = height as u16;

    unsafe {
        idx.write(R_ENABLE); dat.write(0);                           // disable first
        idx.write(R_XRES);   dat.write(w);
        idx.write(R_YRES);   dat.write(h);
        idx.write(R_BPP);    dat.write(32);
        idx.write(R_VIRT_W); dat.write(w);
        idx.write(R_ENABLE); dat.write(F_ENABLED | F_LFB | F_NOCLEARMEM);
    }

    super::serial::write_str("[fb] BGA LFB reinit OK\r\n");
}

#[cfg(not(target_os = "none"))]
fn bga_init_lfb(_width: u32, _height: u32) {}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the framebuffer console.
///
/// Must be called after the HHDM page tables are active.
/// No-op if `info.is_valid()` returns false (headless / VGA-only machine).
///
/// # Safety
/// `hhdm_offset + info.base` must be a valid, writable mapping of the
/// physical framebuffer.
pub fn init(info: &FramebufferInfo, hhdm_offset: u64) {
    if !info.is_valid() { return; }

    // Re-enable BGA linear framebuffer mode.  OVMF's ExitBootServices hooks
    // can reset the VGA device to text mode; this restores LFB so subsequent
    // pixel writes are visible in the QEMU SDL window.
    bga_init_lfb(info.width, info.height);

    // SAFETY: bootloader identity-maps [0, 4 GiB); framebuffer is below 4 GiB
    //         on all supported platforms.  After HHDM activation, access via
    //         hhdm_offset + phys is always valid.
    let virt = (hhdm_offset + info.base) as *mut u32;
    let cols = info.width  / GW;
    let rows = info.height / GH;

    let mut c = Console {
        fb:     virt,
        width:  info.width,
        height: info.height,
        stride: info.stride,
        format: info.format,
        col:    0,
        row:    0,
        cols,
        rows,
    };

    c.clear();
    c.write_str_inner("micro-nt-os  [fb ok]\n");
    *CONSOLE.lock() = Some(c);
}

/// Blit a BGRA8888 source buffer to the framebuffer.
///
/// `src` is a row-major BGRA pixel buffer (4 bytes/pixel).
/// `src_w` / `src_h` are the source dimensions in pixels.
/// The image is placed at (dst_x, dst_y) and clipped to framebuffer bounds.
///
/// Used by the Vulkan present path to display swapchain images.
///
/// # IRQL: PASSIVE_LEVEL
pub fn blit_bgra(src: *const u32, src_w: u32, src_h: u32, dst_x: u32, dst_y: u32) {
    let guard = CONSOLE.lock();
    let c = match guard.as_ref() { Some(c) => c, None => return };
    let fb = c.fb;
    let fb_w = c.stride;
    let fb_h = c.height;
    for row in 0..src_h {
        let dy = dst_y + row;
        if dy >= fb_h { break; }
        for col in 0..src_w {
            let dx = dst_x + col;
            if dx >= fb_w { continue; }
            // SAFETY: src is caller-validated; fb is the HHDM-mapped framebuffer.
            let pixel = unsafe { *src.add((row * src_w + col) as usize) };
            let native = c.to_native(pixel);
            unsafe { *fb.add((dy * fb_w + dx) as usize) = native; }
        }
    }
}

/// Return the current framebuffer dimensions (width, height) or (0, 0) if uninitialised.
pub fn dimensions() -> (u32, u32) {
    let guard = CONSOLE.lock();
    match guard.as_ref() {
        Some(c) => (c.width, c.height),
        None => (0, 0),
    }
}

/// Write a string directly to the framebuffer console.
///
/// No-op if the console is not yet initialised or exclusive mode is active.
pub fn write_str(s: &str) {
    if EXCLUSIVE.load(Ordering::Relaxed) { return; }
    if let Some(ref mut c) = *CONSOLE.lock() {
        c.write_str_inner(s);
    }
}

/// Write a single byte to the framebuffer console (ASCII only).
///
/// Handles `\n`, `\r`, backspace (`0x08`), and printable 0x20–0x7E.
/// No-op if the console is not yet initialised or exclusive mode is active.
pub fn write_byte(b: u8) {
    if EXCLUSIVE.load(Ordering::Relaxed) { return; }
    if let Some(ref mut c) = *CONSOLE.lock() {
        c.write_char(b as char);
    }
}

/// Return the virtual address of the framebuffer pointer stored in CONSOLE,
/// or 0 if not initialised. Debug only.
pub fn fb_ptr_addr() -> u64 {
    match CONSOLE.lock().as_ref() {
        Some(c) => c.fb as u64,
        None    => 0,
    }
}

/// Framebuffer dimensions `(width, height)`. Returns `(0, 0)` if not yet init.
pub fn screen_dims() -> (u32, u32) {
    match CONSOLE.lock().as_ref() {
        Some(c) => (c.width, c.height),
        None    => (0, 0),
    }
}

/// Fill a rectangle with `color` (0x00_RR_GG_BB).
///
/// # IRQL: PASSIVE_LEVEL
pub fn draw_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    if let Some(ref mut c) = *CONSOLE.lock() {
        c.fill_rect(x, y, w, h, color);
    }
}

/// Draw a string at pixel coordinates with explicit foreground/background.
///
/// Only ASCII 0x20-0x7F is rendered; other bytes are skipped.
/// `scale` — pixel multiplier: 1 = 8×8 glyphs, 2 = 16×16, 3 = 24×24.
///
/// # IRQL: PASSIVE_LEVEL
pub fn draw_text_at(x: u32, y: u32, text: &str, fg: u32, bg: u32, scale: u32) {
    if let Some(ref mut c) = *CONSOLE.lock() {
        c.draw_str_px(x, y, text, fg, bg, scale);
    }
}

/// Write a formatted log record to the framebuffer.
///
/// Called by `SerialLogger::log` so every `log::*` macro appears on screen.
/// The format mirrors serial: `[LEVEL] message\n`.
/// No-op when exclusive (launcher) mode is active.
pub fn write_log_record(level: &str, args: &core::fmt::Arguments<'_>) {
    if EXCLUSIVE.load(Ordering::Relaxed) { return; }
    let mut guard = CONSOLE.lock();
    let c = match guard.as_mut() {
        Some(c) => c,
        None    => return,
    };

    c.write_str_inner("[");
    c.write_str_inner(level);
    c.write_str_inner("] ");

    struct FbWriter<'a>(&'a mut Console);
    impl core::fmt::Write for FbWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            self.0.write_str_inner(s);
            Ok(())
        }
    }
    let _ = core::fmt::write(&mut FbWriter(c), *args);
    c.write_str_inner("\n");
}
