//! msvcrt.dll — Microsoft C Runtime.
//!
//! Games link msvcrt for malloc/free, string functions, and CRT init.
//! We provide the minimum surface to get past CRT startup.

#![no_std]
extern crate alloc;

use alloc::alloc::{alloc, dealloc, realloc, Layout};

/// malloc — allocate memory from the kernel heap.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    if size == 0 { return core::ptr::null_mut(); }
    let layout = Layout::from_size_align(size, 8).unwrap();
    unsafe { alloc(layout) }
}

/// calloc — allocate zero-initialised memory.
#[no_mangle]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    let total = count.saturating_mul(size);
    let ptr = unsafe { malloc(total) };
    if !ptr.is_null() {
        unsafe { core::ptr::write_bytes(ptr, 0, total); }
    }
    ptr
}

/// realloc.
#[no_mangle]
pub unsafe extern "C" fn realloc_fn(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null()  { return unsafe { malloc(new_size) }; }
    if new_size == 0  { unsafe { free(ptr) }; return core::ptr::null_mut(); }
    let layout = Layout::from_size_align(new_size, 8).unwrap();
    unsafe { realloc(ptr, layout, new_size) }
}

/// free.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() { return; }
    // NOTE: We don't know the original size here. In a real implementation
    // we'd store the layout in a header before the allocation.
    // Phase 2: implement a proper allocator with size tracking.
}

/// memcpy.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { core::ptr::copy_nonoverlapping(src, dst, n); }
    dst
}

/// memset.
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe { core::ptr::write_bytes(dst, c as u8, n); }
    dst
}

/// memcmp.
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let diff = unsafe { *a.add(i) as i32 - *b.add(i) as i32 };
        if diff != 0 { return diff; }
    }
    0
}

/// strlen.
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    while unsafe { *s.add(n) } != 0 { n += 1; }
    n
}

/// _exit — CRT exit hook.
#[no_mangle]
pub extern "C" fn _exit(code: i32) -> ! {
    log::info!("msvcrt _exit({})", code);
    loop { x86_64::instructions::hlt(); }
}
