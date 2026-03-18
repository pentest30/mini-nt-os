//! PE loader — host-side analysis tool.
//!
//! Run this on a game .exe to inspect what APIs it needs before
//! implementing them in the Win32 layer.
//!
//! Usage: pe-loader <path-to-game.exe>
//!
//! Output:
//!   - Image base, entry point, section layout
//!   - All imported DLLs and functions
//!   - TLS callbacks (common in DRM)
//!   - Load config (SafeSEH, etc.)

use pelite::pe32::{Pe, PeFile};
use pelite::FileMap;
use std::path::PathBuf;

fn main() {
    let path = std::env::args().nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("Usage: pe-loader <game.exe>");
            std::process::exit(1);
        });

    let map  = FileMap::open(&path).expect("Cannot open file");
    let pe   = PeFile::from_bytes(&map).expect("Not a valid PE32 file");
    let opt  = pe.optional_header();

    println!("=== PE Analysis: {} ===\n", path.display());

    // ── Image layout ──────────────────────────────────────────────────────────
    println!("Image base:    0x{:08X}", opt.ImageBase);
    println!("Entry point:   0x{:08X}", opt.AddressOfEntryPoint);
    println!("Size of image: {} KiB", opt.SizeOfImage / 1024);
    println!("Subsystem:     {}", match opt.Subsystem {
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        _ => "other",
    });

    // ── Sections ──────────────────────────────────────────────────────────────
    println!("\n--- Sections ---");
    for section in pe.section_headers() {
        let name = section.name().unwrap_or("?");
        println!("  {:<8} VA=0x{:08X}  size=0x{:08X}  chars=0x{:08X}",
            name,
            section.VirtualAddress,
            section.VirtualSize,
            section.Characteristics);
    }

    // ── Imports ───────────────────────────────────────────────────────────────
    println!("\n--- Imports ---");
    if let Ok(imports) = pe.imports() {
        for desc in imports {
            let dll = desc.dll_name().unwrap_or(pelite::util::CStr::from_bytes(b"<unknown>\0").unwrap());
            println!("\n  [{}]", dll);
            if let Ok(names) = desc.int() {
                for import in names {
                    match import {
                        Ok(pelite::pe32::imports::Import::ByName { name, .. }) => {
                            println!("    {}", name);
                        }
                        Ok(pelite::pe32::imports::Import::ByOrdinal { ord }) => {
                            println!("    #{}  (by ordinal)", ord);
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    } else {
        println!("  (no imports or import table parse error)");
    }

    // ── TLS (DRM / self-modifying code indicator) ──────────────────────────
    println!("\n--- TLS ---");
    match pe.tls() {
        Ok(tls) => {
            println!("  TLS callbacks present — check for DRM/anti-debug");
            // callback count requires iterating; skip for brevity
        }
        Err(_) => println!("  None"),
    }

    // ── Load config (SafeSEH) ────────────────────────────────────────────────
    println!("\n--- Load config ---");
    match pe.load_config() {
        Ok(_) => println!("  Present (SafeSEH / security cookie)"),
        Err(_) => println!("  None"),
    }

    println!("\nDone.");
}
