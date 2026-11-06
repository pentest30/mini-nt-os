//! Screen checks of a boot scenario (`screen = X Y RRGGBB`): once its
//! markers are all in the serial log, QEMU's monitor (HMP, on a Unix socket
//! in the run directory) dumps the screen (`screendump`, a binary PPM), and
//! each listed pixel must have its colour. The monitor also types the keys
//! of a scenario (`keys = MARKER => KEY…`, [`send_keys`]).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::Result;

/// A pixel a scenario expects on the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pixel {
    pub x: u32,
    pub y: u32,
    pub rgb: [u8; 3],
}

impl Pixel {
    /// `X Y RRGGBB`, in decimal for the position and hexadecimal for the
    /// colour.
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        let [x, y, colour] = fields[..] else {
            return Err(format!("expected `X Y RRGGBB`, found `{value}`"));
        };
        let x = x.parse().map_err(|_| format!("`{x}` is not a column"))?;
        let y = y.parse().map_err(|_| format!("`{y}` is not a row"))?;
        let rgb = u32::from_str_radix(colour, 16)
            .ok()
            .filter(|_| colour.len() == 6)
            .ok_or_else(|| format!("`{colour}` is not a colour RRGGBB"))?;
        let [_, r, g, b] = rgb.to_be_bytes();
        Ok(Self { x, y, rgb: [r, g, b] })
    }
}

/// A screen dump: its size and its pixels, three bytes each, row by row.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

impl Image {
    /// A binary PPM (`P6`, maximum 255), as QEMU's `screendump` writes it.
    pub fn parse_ppm(bytes: &[u8]) -> std::result::Result<Self, String> {
        // The header: four fields separated by whitespace (comments are
        // allowed), then one whitespace byte before the pixels.
        let mut fields = Vec::new();
        let mut at = 0;
        while fields.len() < 4 {
            while at < bytes.len() && (bytes[at].is_ascii_whitespace() || bytes[at] == b'#') {
                if bytes[at] == b'#' {
                    while at < bytes.len() && bytes[at] != b'\n' {
                        at += 1;
                    }
                } else {
                    at += 1;
                }
            }
            let start = at;
            while at < bytes.len() && !bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if start == at {
                return Err("a PPM header cut short".into());
            }
            fields.push(String::from_utf8_lossy(&bytes[start..at]).into_owned());
        }
        if fields[0] != "P6" || fields[3] != "255" {
            return Err(format!("not a binary PPM of 8-bit samples: {} … {}", fields[0], fields[3]));
        }
        let number = |field: &str| field.parse::<u32>().map_err(|_| format!("`{field}` is not a size"));
        let (width, height) = (number(&fields[1])?, number(&fields[2])?);
        let pixels = bytes.get(at + 1..).unwrap_or_default();
        let size = width as usize * height as usize * 3;
        if pixels.len() < size {
            return Err(format!("{} bytes of pixels for {width}x{height}", pixels.len()));
        }
        Ok(Self { width, height, rgb: pixels[..size].to_vec() })
    }

    /// The colour at (`x`, `y`), if it is on the image.
    pub fn at(&self, x: u32, y: u32) -> Option<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let i = (y as usize * self.width as usize + x as usize) * 3;
        Some([self.rgb[i], self.rgb[i + 1], self.rgb[i + 2]])
    }

    /// Each pixel of `expected` has its colour; otherwise, what differs.
    pub fn check(&self, expected: &[Pixel]) -> std::result::Result<(), String> {
        let wrong: Vec<String> = expected
            .iter()
            .filter_map(|pixel| {
                let found = self.at(pixel.x, pixel.y);
                (found != Some(pixel.rgb)).then(|| {
                    let colour = |rgb: [u8; 3]| format!("{:02X}{:02X}{:02X}", rgb[0], rgb[1], rgb[2]);
                    let found = found.map_or_else(|| "off the screen".to_string(), colour);
                    format!("({}, {}) is {found}, not {}", pixel.x, pixel.y, colour(pixel.rgb))
                })
            })
            .collect();
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(format!("screen of {}x{}: {}", self.width, self.height, wrong.join("; ")))
        }
    }
}

/// Dumps the screen of the QEMU whose monitor listens on `socket` into
/// `file`, and reads it back.
pub fn capture(socket: &Path, file: &Path) -> Result<Image> {
    let stream = UnixStream::connect(socket).map_err(|e| format!("QEMU monitor {}: {e}", socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| format!("QEMU monitor: {e}"))?;
    let mut writer = stream.try_clone().map_err(|e| format!("QEMU monitor: {e}"))?;
    let _ = std::fs::remove_file(file);
    writeln!(writer, "screendump {}", file.display()).map_err(|e| format!("QEMU monitor: {e}"))?;
    // A prompt after the banner, then another once the command has run.
    let mut reader = stream;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 256];
    let start = Instant::now();
    while count(&seen, b"(qemu) ") < 2 && start.elapsed() < Duration::from_secs(10) {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("QEMU monitor: {e}")),
        }
    }
    let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    Image::parse_ppm(&bytes)
}

/// How long each key of a `sendkey` stays down (ms).
const KEY_HOLD_MS: u32 = 30;
/// The margin after the last release of a `sendkey` (ms).
const KEY_SETTLE_MS: u32 = 30;

/// How long QEMU takes to type `key` (`sendkey`, `shift-a` is two keys):
/// it presses the keys one hold apart, then releases them one hold apart,
/// from a queue of delayed events. The next `sendkey` must wait for the
/// last release: with QEMU 8.2, one that comes while releases are still
/// queued loses some of them (the step 8 of the console, `docs/compat/
/// m5-console.md`: 670 keys pressed, 568 released, a Shift left down).
fn key_duration(key: &str) -> Duration {
    let keys = key.split('-').count() as u32;
    Duration::from_millis(u64::from(2 * keys * KEY_HOLD_MS + KEY_SETTLE_MS))
}

/// Types `keys` on the QEMU whose monitor listens on `socket`, one after
/// the other (`sendkey`), each answered by the monitor and released
/// ([`key_duration`]) before the next.
pub fn send_keys(socket: &Path, keys: &[String]) -> Result<()> {
    let stream = UnixStream::connect(socket).map_err(|e| format!("QEMU monitor {}: {e}", socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| format!("QEMU monitor: {e}"))?;
    let mut writer = stream.try_clone().map_err(|e| format!("QEMU monitor: {e}"))?;
    let mut reader = stream;
    let mut seen = Vec::new();
    let mut prompts = 1;
    for key in keys {
        writeln!(writer, "sendkey {key} {KEY_HOLD_MS}").map_err(|e| format!("QEMU monitor: {e}"))?;
        prompts += 1;
        let mut chunk = [0u8; 256];
        let start = Instant::now();
        while count(&seen, b"(qemu) ") < prompts && start.elapsed() < Duration::from_secs(10) {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    break
                }
                Err(e) => return Err(format!("QEMU monitor: {e}")),
            }
        }
        std::thread::sleep(key_duration(key));
    }
    Ok(())
}

/// How many times `needle` is in `haystack`.
fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|window| *window == needle).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_waits_for_its_releases() {
        // Pressed then released, one hold apart each, and the margin.
        assert_eq!(key_duration("a"), Duration::from_millis(2 * 30 + 30));
        assert_eq!(key_duration("shift-semicolon"), Duration::from_millis(4 * 30 + 30));
        assert_eq!(key_duration("ctrl-alt-delete"), Duration::from_millis(6 * 30 + 30));
    }

    #[test]
    fn a_pixel_is_a_position_and_a_colour() {
        assert_eq!(Pixel::parse("640 400 3A6EA5"), Ok(Pixel { x: 640, y: 400, rgb: [0x3A, 0x6E, 0xA5] }));
        assert!(Pixel::parse("640 400").is_err());
        assert!(Pixel::parse("640 x 3A6EA5").is_err());
        assert!(Pixel::parse("1 2 3A6EA").is_err(), "five digits");
        assert!(Pixel::parse("1 2 GGGGGG").is_err());
    }

    #[test]
    fn a_ppm_is_read_and_checked() {
        let mut ppm = b"P6\n# QEMU\n2 1\n255\n".to_vec();
        ppm.extend_from_slice(&[0x3A, 0x6E, 0xA5, 0, 0, 0]);
        let image = Image::parse_ppm(&ppm).unwrap();
        assert_eq!((image.width, image.height), (2, 1));
        assert_eq!((image.at(0, 0), image.at(1, 0), image.at(2, 0)), (Some([0x3A, 0x6E, 0xA5]), Some([0; 3]), None));
        let blue = Pixel { x: 0, y: 0, rgb: [0x3A, 0x6E, 0xA5] };
        assert_eq!(image.check(&[blue]), Ok(()));
        let wrong = image.check(&[Pixel { x: 1, ..blue }, Pixel { x: 5, ..blue }]).unwrap_err();
        assert!(
            wrong.contains("(1, 0) is 000000, not 3A6EA5") && wrong.contains("(5, 0) is off the screen"),
            "{wrong}"
        );
        assert!(Image::parse_ppm(b"P6\n2 1\n255\n\x01").is_err(), "too few pixels");
        assert!(Image::parse_ppm(b"P5\n2 1\n255\n\0\0").is_err(), "grey");
        assert!(Image::parse_ppm(b"P6\n2").is_err(), "cut short");
    }
}
