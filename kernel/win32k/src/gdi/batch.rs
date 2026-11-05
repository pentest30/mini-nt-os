//! Les appels de GDI en lot (`gdibatch.c` de ReactOS, comme
//! spécification) : `gdi32` met certains appels (PatBlt…) dans le TEB du
//! thread (`GdiTebBatch`, `GdiBatchCount`) au lieu d'appeler le noyau ;
//! [`flush`] les exécute, pour le DC du lot, avant le service suivant du
//! thread chez win32k (KiSystemService) et au retour d'un rappel du mode
//! utilisateur (KeUserModeCallback, par l'appel que Ps en a reçu :
//! `ps::callback::set_gdi_batch_flush`), puis vide le lot.
//!
//! Les appels exécutés : PatBlt, SelectClipRgn (`RGN_COPY`, d'un rectangle
//! ou d'aucune région : [`dc::select_clip_rect`]) et DeleteObject (d'une
//! région ou d'un pinceau : [`rgnobj::delete_object`]).
//!
//! Un appel plus court que son enregistrement finit le lot (ReactOS lirait
//! les octets qui le suivent).
//!
//! Pas encore, journalisé une fois : les autres appels en lot (PolyPatBlt,
//! TextOut, ExtTextOut, SetBrushOrg, SelectObject d'une police), sautés.

use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use abi::gdi::{
    batch, GdiBatchHeader32, GdiBsExtSelClipRgn32, GdiBsObject32, GdiBsPatBlt32, GdiTebBatch32, GDIBS_NORECT,
    GDI_BATCH_BUFFER_SIZE, GDI_HANDLE_TYPE_MASK, LO_DC_TYPE,
};
use abi::teb32::Teb32;
use ke::usermem::{copy_from_user, copy_to_user, UserPtr};

use super::dc::{self, Dc};
use super::dib::Rect;
use super::rgnobj;

/// Un appel du lot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    PatBlt(GdiBsPatBlt32),
    /// SelectClipRgn : le mode, le rectangle de la région (aucun :
    /// `GDIBS_NORECT`).
    SelectClip(i32, Option<Rect>),
    /// DeleteObject (GdiBCDelRgn, GdiBCDelObj) : le handle.
    Delete(u32),
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
            other => Some(Call::Other(other)),
        };
        let Some(call) = call else { break };
        calls.push(call);
        at += size;
    }
    calls
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
            rgnobj::delete_object(*handle);
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
    fn a_call_of_no_size_or_past_the_buffer_ends_the_batch() {
        let mut buffer = alloc::vec::Vec::new();
        buffer.extend_from_slice(pat_blt(1).as_bytes());
        buffer.extend_from_slice(&[0, 0, batch::SEL_OBJ as u8, 0]);
        buffer.extend_from_slice(pat_blt(2).as_bytes());
        assert_eq!(calls(&buffer, 3), [Call::PatBlt(pat_blt(1))]);
        assert_eq!(calls(&pat_blt(1).as_bytes()[..0x30], 1), [], "a call cut short");
        let mut short = pat_blt(1);
        short.header.size = 8;
        assert_eq!(calls(short.as_bytes(), 1), [], "a PatBlt smaller than its record");
    }
}
