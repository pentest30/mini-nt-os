//! Les appels de GDI en lot (`gdibatch.c` de ReactOS, comme
//! spécification) : `gdi32` met certains appels (PatBlt…) dans le TEB du
//! thread (`GdiTebBatch`, `GdiBatchCount`) au lieu d'appeler le noyau ;
//! [`flush`] les exécute, pour le DC du lot, avant le service suivant du
//! thread chez win32k (KiSystemService) et au retour d'un rappel du mode
//! utilisateur (KeUserModeCallback, par l'appel que Ps en a reçu :
//! `ps::callback::set_gdi_batch_flush`), puis vide le lot.
//!
//! Les appels exécutés : PatBlt, SelectClipRgn (`RGN_COPY`, d'un rectangle
//! ou d'aucune région : [`dc::select_clip_rect`]), DeleteObject (d'une
//! région, d'un pinceau ou d'une police : [`super::delete_object`]),
//! TextOut et ExtTextOut (GdiBCTextOut, avec les attributs de texte pris
//! par `gdi32` ; GdiBCExtTextOut, un rectangle rempli : [`text`]) et
//! SelectObject d'une police (GdiBCSelObj : `gdi32` a déjà changé `hlfntNew`
//! des attributs, que le noyau lit quand il dessine ; rien à faire).
//!
//! Un appel plus court que son enregistrement finit le lot (ReactOS lirait
//! les octets qui le suivent).
//!
//! Pas encore, journalisé une fois : les autres appels en lot (PolyPatBlt,
//! SetBrushOrg), sautés.

use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec::Vec;

use abi::gdi::{
    batch, eto, GdiBatchHeader32, GdiBsExtSelClipRgn32, GdiBsExtTextOut32, GdiBsObject32, GdiBsPatBlt32,
    GdiBsTextOut32, GdiTebBatch32, GDIBS_NORECT, GDI_BATCH_BUFFER_SIZE, GDI_HANDLE_TYPE_MASK, LO_DC_TYPE,
};
use abi::teb32::Teb32;
use ke::usermem::{copy_from_user, copy_to_user, UserPtr};

use super::dc::{self, Dc};
use super::dib::{ColorRef, Rect};
use super::text::{self, TextAttrs};

/// Un appel du lot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    PatBlt(GdiBsPatBlt32),
    /// SelectClipRgn : le mode, le rectangle de la région (aucun :
    /// `GDIBS_NORECT`).
    SelectClip(i32, Option<Rect>),
    /// DeleteObject (GdiBCDelRgn, GdiBCDelObj) : le handle.
    Delete(u32),
    /// TextOut, ExtTextOut (GdiBCTextOut) : l'appel, ses caractères, ses
    /// avances (`lpDx`) s'il en a.
    TextOut(GdiBsTextOut32, Vec<u16>, Option<Vec<i32>>),
    /// ExtTextOut sans caractères (GdiBCExtTextOut) : un rectangle rempli.
    ExtTextOut(GdiBsExtTextOut32),
    /// SelectObject (GdiBCSelObj) : le handle.
    Select(u32),
    /// Un appel pas encore exécuté : sa commande (GDIBATCHCMD).
    Other(u16),
}

/// Les `count` appels du lot `buffer` (GdiFlushUserBatch), jusqu'au premier
/// de taille nulle ou qui dépasse.
pub fn calls(buffer: &[u8], count: u32) -> alloc::vec::Vec<Call> {
    let mut calls = alloc::vec::Vec::new();
    let mut at = 0usize;
    for _ in 0..count {
        let Some(head) = buffer.get(at..at + size_of::<GdiBatchHeader32>()) else { break };
        let size = usize::from(u16::from_le_bytes([head[0], head[1]]));
        let cmd = u16::from_le_bytes([head[2], head[3]]);
        let Some(bytes) = buffer.get(at..at + size).filter(|_| size != 0) else { break };
        let call = match cmd {
            batch::PAT_BLT => GdiBsPatBlt32::from_bytes(bytes).map(Call::PatBlt),
            batch::EXT_SEL_CLIP_RGN => GdiBsExtSelClipRgn32::from_bytes(bytes).map(|call| {
                let rect = call.rect;
                let rect = Rect::new(rect.left, rect.top, rect.right, rect.bottom);
                let mode = (call.mode & !GDIBS_NORECT) as i32;
                Call::SelectClip(mode, (call.mode & GDIBS_NORECT == 0).then_some(rect))
            }),
            batch::DEL_RGN | batch::DEL_OBJ => GdiBsObject32::from_bytes(bytes).map(|call| Call::Delete(call.handle)),
            batch::SEL_OBJ => GdiBsObject32::from_bytes(bytes).map(|call| Call::Select(call.handle)),
            batch::TEXT_OUT => text_out(bytes),
            batch::EXT_TEXT_OUT => GdiBsExtTextOut32::from_bytes(bytes).map(Call::ExtTextOut),
            other => Some(Call::Other(other)),
        };
        let Some(call) = call else { break };
        calls.push(call);
        at += size;
    }
    calls
}

/// Un TextOut en lot : l'appel, puis, depuis l'octet 0x50, ses avances
/// (`size` octets, des entiers) et ses caractères ; `None` s'ils dépassent
/// l'appel.
fn text_out(bytes: &[u8]) -> Option<Call> {
    let call = GdiBsTextOut32::from_bytes(bytes)?;
    let start = 0x50usize;
    let dx_end = start.checked_add(call.size as usize)?;
    let text_end = dx_end.checked_add((call.count as usize).checked_mul(2)?)?;
    let dx_bytes = bytes.get(start..dx_end)?;
    let text_bytes = bytes.get(dx_end..text_end)?;
    let text = text_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let dx = (call.size != 0)
        .then(|| dx_bytes.chunks_exact(4).map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect());
    Some(Call::TextOut(call, text, dx))
}

/// Les commandes en lot pas encore exécutées, déjà journalisées.
static REPORTED: AtomicU32 = AtomicU32::new(0);

/// Exécute `call` sur `dc` (sans DC, un appel qui dessine ou découpe ne
/// fait rien).
fn run(call: &Call, dc: Option<&Dc>) {
    match call {
        Call::PatBlt(call) => {
            if let Some(dc) = dc {
                dc::batched_pat_blt(dc, call.x, call.y, call.width, call.height, call.rop, call.hbrush);
            }
        }
        Call::SelectClip(mode, rect) => {
            if let Some(dc) = dc {
                dc.change(|state| dc::select_clip_rect(state, *rect, *mode));
            }
        }
        Call::Delete(handle) => {
            super::delete_object(*handle);
        }
        Call::Select(_) => {}
        Call::TextOut(call, string, dx) => {
            if let Some(dc) = dc {
                let rect = call.rect;
                let rect =
                    (call.options & GDIBS_NORECT == 0).then(|| Rect::new(rect.left, rect.top, rect.right, rect.bottom));
                let attrs = TextAttrs {
                    font: call.hlfnt_new,
                    color: ColorRef(call.cr_foreground_clr),
                    background: ColorRef(call.cr_background_clr),
                    bk_mode: call.bk_mode,
                    align: call.fl_text_align,
                };
                // ETO_PDY gives pairs: the horizontal advances are every other one.
                let dx: Option<Vec<i32>> = dx.as_ref().map(|dx| {
                    if call.options & eto::PDY != 0 {
                        dx.iter().step_by(2).copied().collect()
                    } else {
                        dx.clone()
                    }
                });
                let options = call.options & !GDIBS_NORECT;
                text::ext_text_out(
                    &dc.state(),
                    dc::current_pid(),
                    (call.x, call.y),
                    options,
                    rect,
                    string,
                    dx.as_deref(),
                    &attrs,
                );
            }
        }
        Call::ExtTextOut(call) => {
            if let (Some(dc), true) = (dc, call.options & eto::OPAQUE != 0) {
                let rect = call.rect;
                let rect = Rect::new(rect.left, rect.top, rect.right, rect.bottom);
                let background = ColorRef(call.ul_background_clr);
                let attrs = TextAttrs { font: 0, color: background, background, bk_mode: 0, align: 0 };
                text::ext_text_out(&dc.state(), dc::current_pid(), (0, 0), call.options, Some(rect), &[], None, &attrs);
            }
        }
        Call::Other(cmd) => {
            let bit = 1u32 << (u32::from(*cmd) % 32);
            if REPORTED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
                log::warn!("win32k: batched GDI call {cmd}: not yet (skipped)");
            }
        }
    }
}

/// NtGdiFlushUserBatch : exécute les appels en lot du thread courant, puis
/// vide son lot. Rien s'il n'en a pas, ou s'il en compte plus que son
/// tampon n'en tient (comme ReactOS : le lot reste).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un thread de Ps, sans rien tenir.
pub fn flush() {
    let Some(thread) = ps::ethread::current_thread() else { return };
    let teb = thread.teb();
    drop(thread);
    let count_at = teb + offset_of!(Teb32, gdi_batch_count) as u32;
    let Ok(count) = UserPtr::<u32>::new(count_at).read() else { return };
    if count == 0 || count > (GDI_BATCH_BUFFER_SIZE / 4) as u32 {
        return;
    }
    let batch_at = u64::from(teb) + offset_of!(Teb32, gdi_teb_batch) as u64;
    let mut hdc = [0u8; 4];
    let mut buffer = alloc::vec![0u8; GDI_BATCH_BUFFER_SIZE];
    let read = copy_from_user(&mut hdc, batch_at + offset_of!(GdiTebBatch32, hdc) as u64)
        .and_then(|()| copy_from_user(&mut buffer, batch_at + offset_of!(GdiTebBatch32, buffer) as u64));
    if read.is_err() {
        return;
    }
    let hdc = u32::from_le_bytes(hdc);
    let dc = (hdc & GDI_HANDLE_TYPE_MASK == LO_DC_TYPE).then(|| dc::lock(hdc)).flatten();
    for call in calls(&buffer, count) {
        run(&call, dc.as_deref());
    }
    // Empty for the next round: Offset, HDC, then the count.
    let _ = copy_to_user(batch_at, &[0u8; 8]);
    let _ = UserPtr::<u32>::new(count_at).write(&0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::gdi::rop;

    fn pat_blt(x: i32) -> GdiBsPatBlt32 {
        GdiBsPatBlt32 {
            header: GdiBatchHeader32 { size: 0x40, cmd: batch::PAT_BLT },
            x,
            width: 10,
            height: 10,
            rop: rop::PATCOPY,
            hbrush: 0x0090_0010,
            ..GdiBsPatBlt32::default()
        }
    }

    #[test]
    fn calls_follow_each_other_by_their_size() {
        let mut buffer = alloc::vec::Vec::new();
        buffer.extend_from_slice(pat_blt(1).as_bytes());
        // A SetBrushOrg: 4 + 8 bytes.
        buffer.extend_from_slice(&[12, 0, batch::SET_BRUSH_ORG as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        buffer.extend_from_slice(pat_blt(2).as_bytes());
        assert_eq!(
            calls(&buffer, 3),
            [Call::PatBlt(pat_blt(1)), Call::Other(batch::SET_BRUSH_ORG), Call::PatBlt(pat_blt(2))]
        );
        assert_eq!(calls(&buffer, 1), [Call::PatBlt(pat_blt(1))], "only the counted calls");
    }

    #[test]
    fn clips_and_deletions_are_read() {
        let clip = |mode: u32| GdiBsExtSelClipRgn32 {
            header: GdiBatchHeader32 { size: 24, cmd: batch::EXT_SEL_CLIP_RGN },
            mode,
            rect: abi::user::Rect32 { left: 1, top: 2, right: 3, bottom: 4 },
        };
        let delete = |cmd| GdiBsObject32 { header: GdiBatchHeader32 { size: 8, cmd }, handle: 0x0104_0100 };
        let mut buffer = alloc::vec::Vec::new();
        buffer.extend_from_slice(clip(5).as_bytes());
        buffer.extend_from_slice(clip(5 | GDIBS_NORECT).as_bytes());
        buffer.extend_from_slice(delete(batch::DEL_RGN).as_bytes());
        buffer.extend_from_slice(delete(batch::DEL_OBJ).as_bytes());
        assert_eq!(
            calls(&buffer, 4),
            [
                Call::SelectClip(5, Some(Rect::new(1, 2, 3, 4))),
                Call::SelectClip(5, None),
                Call::Delete(0x0104_0100),
                Call::Delete(0x0104_0100)
            ]
        );
        let mut short = clip(5);
        short.header.size = 20;
        assert_eq!(calls(&short.as_bytes()[..20], 1), [], "a clip smaller than its record");
        let mut short = delete(batch::DEL_RGN);
        short.header.size = 4;
        assert_eq!(calls(&short.as_bytes()[..4], 1), [], "a deletion without its handle");
    }

    #[test]
    fn text_outs_bring_their_characters_and_advances() {
        let call = |count: u32, size: u32| GdiBsTextOut32 {
            header: GdiBatchHeader32 { size: (0x50 + size + 2 * count) as u16, cmd: batch::TEXT_OUT },
            x: 10,
            y: 20,
            options: GDIBS_NORECT,
            count,
            size,
            hlfnt_new: 0x010A_0040,
            ..GdiBsTextOut32::default()
        };
        let mut buffer = alloc::vec::Vec::new();
        buffer.extend_from_slice(&call(2, 0).as_bytes()[..0x50]);
        buffer.extend_from_slice(&[b'O', 0, b'K', 0]);
        buffer.extend_from_slice(&call(1, 4).as_bytes()[..0x50]);
        buffer.extend_from_slice(&7i32.to_le_bytes());
        buffer.extend_from_slice(&[b'x', 0]);
        let select = GdiBsObject32 { header: GdiBatchHeader32 { size: 8, cmd: batch::SEL_OBJ }, handle: 0x010A_0040 };
        buffer.extend_from_slice(select.as_bytes());
        assert_eq!(
            calls(&buffer, 3),
            [
                Call::TextOut(call(2, 0), alloc::vec![u16::from(b'O'), u16::from(b'K')], None),
                Call::TextOut(call(1, 4), alloc::vec![u16::from(b'x')], Some(alloc::vec![7])),
                Call::Select(0x010A_0040),
            ]
        );
        // Characters past the call: it ends the batch.
        let mut long = call(9, 0);
        long.header.size = 0x54;
        let mut bytes = long.as_bytes()[..0x50].to_vec();
        bytes.extend_from_slice(&[b'a', 0, b'b', 0]);
        assert_eq!(calls(&bytes, 1), []);
        let fill = GdiBsExtTextOut32 {
            header: GdiBatchHeader32 { size: 0x28, cmd: batch::EXT_TEXT_OUT },
            options: 2,
            ..Default::default()
        };
        assert_eq!(calls(fill.as_bytes(), 1), [Call::ExtTextOut(fill)]);
    }

    #[test]
    fn a_call_of_no_size_or_past_the_buffer_ends_the_batch() {
        let mut buffer = alloc::vec::Vec::new();
        buffer.extend_from_slice(pat_blt(1).as_bytes());
        buffer.extend_from_slice(&[0, 0, batch::POLY_PAT_BLT as u8, 0]);
        buffer.extend_from_slice(pat_blt(2).as_bytes());
        assert_eq!(calls(&buffer, 3), [Call::PatBlt(pat_blt(1))]);
        assert_eq!(calls(&pat_blt(1).as_bytes()[..0x30], 1), [], "a call cut short");
        let mut short = pat_blt(1);
        short.header.size = 8;
        assert_eq!(calls(short.as_bytes(), 1), [], "a PatBlt smaller than its record");
    }
}
