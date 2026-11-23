//! Les services des crochets (`win32k::hook`) : NtUserSetWindowsHookEx,
//! NtUserSetWindowsHookAW, NtUserUnhookWindowsHookEx, NtUserCallNextHookEx,
//! NtUserCallMsgFilter.
//!
//! Ils rendent une valeur : un échec rend 0, avec l'erreur Win32 comme
//! dernière erreur.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use abi::ntstatus::NtStatus;
use abi::user::{hcbt, wh, CbtCreateWnd32, CbtCreateWndExtra32, CreateStructW32, Msg32};
use abi::winerror::dos_error;
use win32k::gui::ThreadInfo;
use win32k::hook::HookParam;
use win32k::hook::Request;

/// 0 avec `error` comme dernière erreur.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// Le `THREADINFO` du thread courant (déjà un thread GUI : `super::dispatch`).
fn current() -> Arc<ThreadInfo> {
    win32k::convert_current_thread().expect("a GUI thread at a win32k service")
}

/// Le MSG entier en `address`, chez le processus courant.
fn read_message(address: u32) -> Result<Msg32, NtStatus> {
    let mut bytes = [0u8; size_of::<Msg32>()];
    ke::usermem::copy_from_user(&mut bytes, u64::from(address))?;
    let word = |i: usize| u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    Ok(Msg32 {
        hwnd: word(0),
        message: word(1),
        w_param: word(2),
        l_param: word(3),
        time: word(4),
        pt_x: word(5) as i32,
        pt_y: word(6) as i32,
    })
}

/// Écrit `message` en `address`.
fn write_message(address: u32, message: &Msg32) -> Result<(), NtStatus> {
    ke::usermem::copy_to_user(u64::from(address), message.as_bytes())
}

/// Le CBT_CREATEWNDW en `address` et le CREATESTRUCTW qu'il désigne.
fn read_cbt_create(address: u32) -> Result<CbtCreateWndExtra32, NtStatus> {
    let mut head = [0u8; size_of::<CbtCreateWnd32>()];
    ke::usermem::copy_from_user(&mut head, u64::from(address))?;
    let word = |bytes: &[u8], i: usize| {
        u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]])
    };
    let mut bytes = [0u8; size_of::<CreateStructW32>()];
    ke::usermem::copy_from_user(&mut bytes, u64::from(word(&head, 0)))?;
    Ok(CbtCreateWndExtra32 {
        create_struct: CreateStructW32 {
            create_params: word(&bytes, 0),
            instance: word(&bytes, 1),
            menu: word(&bytes, 2),
            parent: word(&bytes, 3),
            cy: word(&bytes, 4) as i32,
            cx: word(&bytes, 5) as i32,
            y: word(&bytes, 6) as i32,
            x: word(&bytes, 7) as i32,
            style: word(&bytes, 8),
            name: word(&bytes, 9),
            class: word(&bytes, 10),
            ex_style: word(&bytes, 11),
        },
        insert_after: word(&head, 1),
    })
}

/// UserCallNextHookEx : ce qu'un crochet a pu changer revient au
/// CBT_CREATEWNDW de l'appelant (`hwndInsertAfter`) et à son CREATESTRUCTW
/// (`x`, `y`, `cx`, `cy`).
fn write_cbt_create(address: u32, create: &CbtCreateWndExtra32) -> Result<(), NtStatus> {
    let mut head = [0u8; size_of::<CbtCreateWnd32>()];
    ke::usermem::copy_from_user(&mut head, u64::from(address))?;
    let lpcs = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    ke::usermem::copy_to_user(u64::from(address) + 4, &create.insert_after.to_le_bytes())?;
    let placed = create.create_struct;
    let mut place = [0u8; 16];
    for (i, value) in [placed.cy, placed.cx, placed.y, placed.x].into_iter().enumerate() {
        place[4 * i..4 * i + 4].copy_from_slice(&value.to_le_bytes());
    }
    ke::usermem::copy_to_user(u64::from(lpcs) + 16, &place)
}

/// Pose le crochet `request` (`win32k::hook::set_windows_hook`).
fn set_hook(request: Request) -> NtStatus {
    match win32k::hook::set_windows_hook(&current(), request) {
        Ok(handle) => NtStatus(handle),
        Err(error) => fail(error),
    }
}

/// NtUserSetWindowsHookEx(Mod, UnsafeModuleName, ThreadId, HookId,
/// HookProc, Ansi) : HHOOK, le crochet posé ; le nom du module n'est lu
/// qu'avec un module. 0 et l'erreur de `win32k::hook::set_windows_hook`, ou
/// celle d'un nom illisible.
pub(super) fn nt_user_set_windows_hook_ex(arguments: &[u32]) -> NtStatus {
    let [module, module_name, thread_id, id, proc_, ansi] = arguments[..6] else { unreachable!("6 arguments") };
    let module_name = if module != 0 {
        match super::object::capture_unicode_string(module_name) {
            Ok(name) => name,
            Err(status) => return fail(dos_error(status)),
        }
    } else {
        Vec::new()
    };
    set_hook(Request { module, module_name, thread_id, id: id as i32, proc_, ansi: ansi != 0 })
}

/// NtUserSetWindowsHookAW(idHook, lpfn, Ansi) : SetWindowsHook, l'ancienne
/// forme : un crochet du thread courant, sans module.
pub(super) fn nt_user_set_windows_hook_aw(arguments: &[u32]) -> NtStatus {
    let [id, proc_, ansi] = arguments[..3] else { unreachable!("3 arguments") };
    let thread_id = ps::ethread::current_thread().map_or(0, |thread| thread.tid());
    set_hook(Request { module: 0, module_name: Vec::new(), thread_id, id: id as i32, proc_, ansi: ansi != 0 })
}

/// NtUserUnhookWindowsHookEx(Hook) : TRUE, le crochet retiré ; FALSE et
/// `ERROR_INVALID_HOOK_HANDLE` pour un handle qui n'en est pas un.
pub(super) fn nt_user_unhook_windows_hook_ex(arguments: &[u32]) -> NtStatus {
    match win32k::hook::unhook(arguments[0]) {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}

/// NtUserCallNextHookEx(Code, wParam, lParam, Ansi) : LRESULT, ce que rend
/// le crochet suivant du crochet courant du thread (`win32k::hook::call_next`)
/// ; 0 sans crochet courant ou sans suivant. `lParam` est le MSG des
/// crochets de messages, relu ici et réécrit pour WH_GETMESSAGE ; un MSG
/// illisible rend 0 sans appel.
pub(super) fn nt_user_call_next_hook_ex(arguments: &[u32]) -> NtStatus {
    let [code, w_param, l_param, _ansi] = arguments[..4] else { unreachable!("4 arguments") };
    let thread = current();
    let Some(id) = win32k::hook::current_id(&thread) else { return NtStatus(0) };
    if id == wh::CBT {
        // Only HCBT_CREATEWND is called: its CBT_CREATEWNDW, read and
        // written back where the caller has it.
        if code as i32 != hcbt::CREATEWND || l_param == 0 {
            return NtStatus(0);
        }
        let Ok(mut create) = read_cbt_create(l_param) else { return NtStatus(0) };
        let result = win32k::hook::call_next(&thread, code as i32, w_param, &mut HookParam::CreateWindow(&mut create));
        let _ = write_cbt_create(l_param, &create);
        return NtStatus(result);
    }
    let mut message = Msg32::default();
    if l_param != 0 {
        match read_message(l_param) {
            Ok(read) => message = read,
            Err(_) => return NtStatus(0),
        }
    }
    let result = win32k::hook::call_next(&thread, code as i32, w_param, &mut HookParam::Message(&mut message));
    if id == wh::GETMESSAGE && l_param != 0 {
        let _ = write_message(l_param, &message);
    }
    NtStatus(result)
}

/// NtUserCallMsgFilter(lpmsg, code) : BOOL, ce que rendent les crochets
/// WH_SYSMSGFILTER puis WH_MSGFILTER du thread pour le MSG en `lpmsg`, dans
/// une boucle de type `code` (`win32k::hook::call_msg_filter`) ; le MSG est
/// réécrit. FALSE pour un MSG illisible.
pub(super) fn nt_user_call_msg_filter(arguments: &[u32]) -> NtStatus {
    let [address, code] = arguments[..2] else { unreachable!("2 arguments") };
    let Ok(mut message) = read_message(address) else { return NtStatus(0) };
    let result = win32k::hook::call_msg_filter(&current(), &mut message, code as i32);
    if write_message(address, &message).is_err() {
        return NtStatus(0);
    }
    NtStatus(result)
}
