//! Glyphs of TrueType and OpenType fonts, for win32k's text (ADR-013).
//! `no_std`, with `alloc`; tested on the host.
//!
//! - [`font`]: a font parsed by `ttf-parser` (the only dependency, allowed by
//!   ADR-016): its metrics at a size, as GDI reads them, its glyphs, their
//!   advances, and each glyph rendered to coverage.
//! - [`raster`]: the rasterizer, in fixed point, with grayscale
//!   antialiasing; no hinting.
//!
//! The glyph cache belongs to win32k, which knows its fonts and sizes.

#![no_std]
extern crate alloc;

pub mod font;
pub mod raster;

pub use font::{Bitmap, Error, Font, Metrics, Names, TextMetrics, MAX_GLYPH_PIXELS};
pub use raster::{Point, Rasterizer, ONE};
