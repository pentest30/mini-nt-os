//! Thread scheduler — Phase 2 bootstrap.
//!
//! Design principles (no heap allocation anywhere in this module):
//!   - Thread records live in a fixed-size static table (MAX_THREADS slots).
//!   - The idle thread's kernel stack lives in a `static mut` byte array.
//!   - The ready queue is a ring buffer of thread-table indices.
//!   - `init()` can be called with interrupts disabled → no allocator contact.
//!
//! IRQL discipline:
//!   - `init()`  → call with IRQs disabled (called from kernel_main).
//!   - `tick()`  → called from timer ISR (DIRQL); must not block or alloc.
//!   - `schedule()` → called at DISPATCH_LEVEL from tick(); no alloc.
//!
//! WI7e Ch.4 "Scheduling", ReactOS ntoskrnl/ke/thrdschd.c

use spin::Mutex;
use crate::thread::{KContext, ThreadState};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of concurrently tracked threads (Phase 2 bootstrap).
pub const MAX_THREADS: usize = 8;

/// Maximum depth of the ready queue.
const MAX_READY: usize = MAX_THREADS;

/// Priority used for the boot thread (kernel_main).
const BOOT_PRIORITY: u8 = 8;

/// Idle thread always runs at priority 0.
const IDLE_PRIORITY: u8 = 0;

/// Size of the idle thread's kernel stack. Static allocation, no heap.
const IDLE_STACK_SIZE: usize = 4096;

// ── Static idle-thread storage ────────────────────────────────────────────────
//
// By using static buffers for the idle thread we avoid any heap allocation
// inside `init()`. This sidesteps the LockedHeap / timer-ISR deadlock that
// plagued earlier attempts with `Box<KThread>`.

/// Idle thread kernel stack — never heap-allocated.
static mut IDLE_STACK: [u8; IDLE_STACK_SIZE] = [0u8; IDLE_STACK_SIZE];

// ── Ready queue ───────────────────────────────────────────────────────────────

/// Fixed-capacity FIFO queue of thread-table indices.
///
/// # Why not `VecDeque`?
/// `VecDeque` allocates on the heap. Heap allocation is forbidden at
/// DISPATCH_LEVEL (IRQL discipline). A ring buffer with a compile-time
/// capacity is the correct NT-kernel pattern.
#[derive(Clone, Copy)]
pub struct ReadyQueue {
    buf:  [usize; MAX_READY],
    head: usize,
    len:  usize,
}

impl ReadyQueue {
    pub const fn new() -> Self {
        Self { buf: [0; MAX_READY], head: 0, len: 0 }
    }

    /// Returns `true` if the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Returns `true` if the queue is full.
    #[inline]
    pub fn is_full(&self) -> bool { self.len == MAX_READY }

    /// Enqueue a thread index. Returns `false` if the queue is full.
    pub fn push(&mut self, tid: usize) -> bool {
        if self.is_full() { return false; }
        let tail = (self.head + self.len) % MAX_READY;
        self.buf[tail] = tid;
        self.len += 1;
        true
    }

    /// Dequeue the next ready thread index. Returns `None` if empty.
    pub fn pop(&mut self) -> Option<usize> {
        if self.is_empty() { return None; }
        let tid = self.buf[self.head];
        self.head = (self.head + 1) % MAX_READY;
        self.len -= 1;
        Some(tid)
    }

    /// Number of items in the queue.
    #[inline]
    pub fn len(&self) -> usize { self.len }
}

// ── Thread record ─────────────────────────────────────────────────────────────

/// One entry in the static thread table.
///
/// `ctx` is an *owned* context stored inline — no pointer indirection needed
/// for the boot and idle threads. User threads (Phase 2.5+) set `user_mode`
/// and carry their kernel-stack top in `kernel_stack_top` so the scheduler
/// can update TSS.RSP0 before switching to them in ring-3.
#[derive(Clone, Copy)]
pub struct ThreadRecord {
    pub ctx:              KContext,
    pub state:            ThreadState,
    pub priority:         u8,
    pub used:             bool,
    /// `true` for threads that run in ring-3. The scheduler updates TSS.RSP0
    /// to `kernel_stack_top` before switching to these threads.
    pub user_mode:        bool,
    /// Top of this thread's dedicated kernel stack (initial RSP0 value).
    /// Zero for kernel-mode threads (boot, idle).
    pub kernel_stack_top: u64,
}

impl ThreadRecord {
    pub const fn empty() -> Self {
        Self {
            ctx: KContext { rsp: 0, rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0, rip: 0 },
            state: ThreadState::Initialized,
            priority: 0,
            used: false,
            user_mode: false,
            kernel_stack_top: 0,
        }
    }
}

// ── Scheduler inner state ─────────────────────────────────────────────────────

/// Scheduler state — no heap, all static.
pub struct SchedulerInner {
    pub threads:     [ThreadRecord; MAX_THREADS],
    pub current:     usize,     // index of the currently running thread
    pub idle_tid:    usize,     // index of the idle thread (never terminates)
    pub ready:       ReadyQueue,
    pub tick_count:  u64,
}

impl SchedulerInner {
    pub const fn new() -> Self {
        Self {
            threads: [ThreadRecord::empty(); MAX_THREADS],
            current: 0,
            idle_tid: 1,
            ready: ReadyQueue::new(),
            tick_count: 0,
        }
    }

    /// Allocate the next free thread slot. Returns the TID or `None` if full.
    pub fn alloc_tid(&mut self) -> Option<usize> {
        self.threads.iter().position(|t| !t.used)
    }

    /// Schedule: pick the next thread to run and return (current_tid, next_tid).
    ///
    /// Returns `None` if no switch is needed (only one runnable thread).
    /// The caller is responsible for calling `ke::thread::switch_to` with the
    /// actual `KContext` pointers.
    pub fn pick_next(&mut self) -> Option<(usize, usize)> {
        let cur = self.current;

        // Determine the next thread: try ready queue first, then idle fallback.
        // Skip any Terminated entries — terminate_user_threads() marks threads
        // Terminated while they may still be sitting in the queue. Without this
        // check, pick_next() would pop a Terminated thread and immediately set
        // its state back to Running, undoing the termination.
        let next_from_queue = loop {
            match self.ready.pop() {
                Some(tid) if self.threads[tid].state == ThreadState::Terminated => {
                    // Discard — thread was terminated after being enqueued.
                }
                other => break other,
            }
        };

        let next = match next_from_queue {
            Some(tid) => tid,
            None => {
                // Queue empty: fall back to idle unless we ARE idle.
                if cur == self.idle_tid {
                    // Already on idle with nothing to do — no switch.
                    return None;
                }
                self.idle_tid
            }
        };

        // Now re-enqueue current (if it's still runnable and not idle).
        if self.threads[cur].state == ThreadState::Running && cur != self.idle_tid {
            self.threads[cur].state = ThreadState::Ready;
            self.ready.push(cur);
        }

        self.threads[next].state = ThreadState::Running;
        self.current = next;
        Some((cur, next))
    }
}

// ── Global scheduler ─────────────────────────────────────────────────────────

static SCHED: Mutex<Option<SchedulerInner>> = Mutex::new(None);

pub struct Scheduler;

/// Initialise the scheduler.
///
/// Creates two threads:
///   - TID 0: boot thread (current execution = `kernel_main`).
///   - TID 1: idle thread (static stack, `idle_thread_main`).
///
/// # IRQL: must be called with interrupts DISABLED to avoid a timer ISR
/// re-entering SCHED.lock() while we are holding it here.
pub fn init() {
    let mut guard = SCHED.lock();
    if guard.is_some() { return; }

    let mut s = SchedulerInner::new();

    // TID 0 — boot thread (kernel_main). Captures the live RSP/RIP on first
    // context switch; KContext fields are filled in by ke_context_switch.
    let boot_tid = s.alloc_tid().expect("scheduler: no slot for boot thread");
    s.threads[boot_tid].used     = true;
    s.threads[boot_tid].state    = ThreadState::Running;
    s.threads[boot_tid].priority = BOOT_PRIORITY;
    s.current = boot_tid;

    // TID 1 — idle thread. Stack lives in a static buffer — zero heap.
    let idle_tid = s.alloc_tid().expect("scheduler: no slot for idle thread");
    // SAFETY: IDLE_STACK is static; we set up the stack frame here (single-
    //         threaded init; no concurrent access before interrupts re-enable).
    let idle_rsp = unsafe {
        let top = (core::ptr::addr_of_mut!(IDLE_STACK) as *mut u8).add(IDLE_STACK_SIZE);
        // 16-byte align then push one return-address slot.
        let rsp = ((top as usize) - 8) & !0xF;
        *(rsp as *mut u64) = idle_thread_main as *const () as u64;
        rsp as u64
    };
    s.threads[idle_tid].used          = true;
    s.threads[idle_tid].state         = ThreadState::Ready;
    s.threads[idle_tid].priority      = IDLE_PRIORITY;
    s.threads[idle_tid].ctx.rsp       = idle_rsp;
    s.threads[idle_tid].ctx.rip       = idle_thread_main as *const () as u64;
    s.idle_tid = idle_tid;

    *guard = Some(s);
    log::info!("Ke scheduler: initialised (boot TID={}, idle TID={})", boot_tid, idle_tid);
}

/// Called from the APIC timer ISR at every clock tick.
///
/// Increments the monotonic tick counter.  The actual context switch is
/// triggered by `schedule()`, which is called separately after EOI
/// (so the APIC can accept the next interrupt before we switch stacks).
///
/// # IRQL: DIRQL (hardware interrupt) — no alloc, no page faults.
pub fn tick() {
    let mut guard = SCHED.lock();
    let Some(s) = guard.as_mut() else { return };
    s.tick_count += 1;
}

/// Preemptive round-robin context switch.
///
/// Called from the APIC timer ISR hook **after** EOI so the APIC can
/// accept the next periodic tick before we switch stacks.
///
/// Acquires the scheduler lock, calls `pick_next()` to select the next
/// thread, releases the lock, then calls the raw context-switch stub.
/// Releasing the lock before switching avoids a lock-across-context-switch
/// scenario on SMP (Phase 3+); on Phase 2 single-CPU it makes no difference
/// since interrupts are already disabled inside the ISR.
///
/// # IRQL: DIRQL — no alloc, no page faults, interrupts disabled.
pub fn schedule() {
    // ── Select next thread while holding the lock ─────────────────────────
    let switch = {
        let mut guard = SCHED.lock();
        let Some(s) = guard.as_mut() else { return };
        s.pick_next().map(|(cur, next)| {
            // Update TSS.RSP0 when switching to a user-mode thread so that the
            // next ring-3→ring-0 transition pushes the interrupt frame onto that
            // thread's dedicated kernel stack rather than the shared boot stack.
            //
            // SAFETY: called at DISPATCH_LEVEL (timer ISR, IF=0, single-CPU).
            //         TSS RSP0 write is atomic w.r.t. any concurrent ISR.
            if s.threads[next].user_mode && s.threads[next].kernel_stack_top != 0 {
                unsafe { hal::gdt::set_kernel_stack_top(s.threads[next].kernel_stack_top) };
            }
            // SAFETY: pointers into the static SCHED table — 'static lifetime.
            let old_ctx = &mut s.threads[cur].ctx  as *mut  crate::thread::KContext;
            let new_ctx = &    s.threads[next].ctx as *const crate::thread::KContext;
            (old_ctx, new_ctx)
        })
        // lock released here — guard drops at end of block
    };

    // ── Perform the switch outside the lock ───────────────────────────────
    if let Some((old_ctx, new_ctx)) = switch {
        // SAFETY:
        //   - Both pointers are into the static `SCHED` table (always valid).
        //   - Called inside the timer ISR with IF=0 (single-CPU; no concurrent
        //     access to these slots while we are switching).
        //   - `pick_next()` guarantees old_ctx ≠ new_ctx.
        unsafe { crate::thread::context_switch_raw(old_ctx, new_ctx) };
    }
}

/// Returns `true` if the thread at `tid` is still alive (not Terminated).
///
/// Used by the kernel shell to spin-wait for a child process to exit:
/// ```ignore
/// while ke::scheduler::is_thread_running(child_tid) { hlt(); }
/// ```
///
/// # IRQL: PASSIVE_LEVEL
pub fn is_thread_running(tid: usize) -> bool {
    let guard = SCHED.lock();
    let Some(s) = guard.as_ref() else { return false };
    if tid >= MAX_THREADS || !s.threads[tid].used {
        return false;
    }
    s.threads[tid].state != ThreadState::Terminated
}

/// Enqueue a thread in the ready queue.
///
/// Called when a thread becomes runnable (e.g., after a wait completes).
pub fn make_ready(tid: usize) {
    let mut guard = SCHED.lock();
    let Some(s) = guard.as_mut() else { return };
    if tid < MAX_THREADS && s.threads[tid].used {
        s.threads[tid].state = ThreadState::Ready;
        s.ready.push(tid);
    }
}

/// Register a new ring-3 (user-mode) thread with the scheduler.
///
/// Allocates an 8 KiB kernel stack, builds the `ring3_iretq_trampoline` frame
/// on it, and adds the thread to the ready queue so the next `schedule()` call
/// can switch to it.
///
/// Stack frame layout (highest address = `kernel_stack_top`):
///
/// ```text
///   [top-56]  placeholder (overwritten with trampoline addr by ke_context_switch)
///   [top-48]  FS selector (u64)   ← popped into RAX by trampoline
///   [top-40]  EIP / entry32 (u64) ┐
///   [top-32]  CS | RPL=3  (u64)   │
///   [top-24]  RFLAGS (u64)        ├─ IRETQ frame consumed by trampoline's iretq
///   [top-16]  user RSP32  (u64)   │
///   [top- 8]  SS | RPL=3  (u64)   ┘
/// ```
///
/// `ctx.rsp` = `top-56` (where ke_context_switch loads RSP and writes ctx.rip).
/// `ctx.rip` = address of `ring3_iretq_trampoline`.
///
/// # IRQL: PASSIVE_LEVEL — heap allocation happens here.
/// Returns the scheduler TID, or `None` if the thread table is full.
pub fn spawn_user_thread(
    entry32: u32,
    stack32: u32,
    cs:      u16,
    ss:      u16,
    fs:      u16,
) -> Option<usize> {
    // ── Allocate dedicated kernel stack ───────────────────────────────────
    // 8 KiB matches the kernel stack used for syscall / interrupt handling.
    // Bump allocator never returns this memory, which is fine — Phase 2.5.
    const KSTACK_SIZE: usize = 8 * 1024;
    const RFLAGS: u64 = (1u64 << 9)   // IF = 1
                      | (3u64 << 12)  // IOPL = 3
                      | (1u64 << 1);  // reserved always-1 bit

    let kstack = alloc::vec![0u8; KSTACK_SIZE];
    let kstack_top = kstack.as_ptr() as u64 + KSTACK_SIZE as u64;
    // Leak: the stack must outlive this thread; bump allocator never frees.
    core::mem::forget(kstack);

    // ── Build kernel stack frame (7 × u64 = 56 bytes) ────────────────────
    // Frame is placed at the TOP of the kernel stack.
    // ke_context_switch writes ctx.rip into frame[0] before executing `ret`,
    // so frame[0] just needs to be writeable — its initial value is ignored.
    let frame_base = (kstack_top - 7 * 8) as *mut u64;
    // SAFETY: frame_base is inside our freshly-allocated kstack buffer.
    unsafe {
        frame_base.add(0).write(0);                // placeholder for trampoline addr
        frame_base.add(1).write(fs as u64);        // FS selector → popped by trampoline
        frame_base.add(2).write(entry32 as u64);   // RIP  ┐
        frame_base.add(3).write((cs as u64) | 3);  // CS   │
        frame_base.add(4).write(RFLAGS);            // RFLAGS│ IRETQ frame
        frame_base.add(5).write(stack32 as u64);   // RSP  │
        frame_base.add(6).write((ss as u64) | 3);  // SS   ┘
    }

    // ── Register with the scheduler ───────────────────────────────────────
    let mut guard = SCHED.lock();
    let s = guard.as_mut()?;
    let tid = s.alloc_tid()?;

    s.threads[tid].used             = true;
    s.threads[tid].state            = ThreadState::Ready;
    s.threads[tid].priority         = BOOT_PRIORITY; // same as boot thread
    s.threads[tid].user_mode        = true;
    s.threads[tid].kernel_stack_top = kstack_top;
    s.threads[tid].ctx.rsp          = frame_base as u64;
    s.threads[tid].ctx.rip          = hal::ring3::ring3_iretq_trampoline_fn();
    // Non-volatile GP registers can be zero — ring-3 ABI doesn't use callee-saved regs
    // across the kernel→user transition; the trampoline doesn't inspect them.
    s.threads[tid].ctx.rbx = 0;
    s.threads[tid].ctx.rbp = 0;
    s.threads[tid].ctx.r12 = 0;
    s.threads[tid].ctx.r13 = 0;
    s.threads[tid].ctx.r14 = 0;
    s.threads[tid].ctx.r15 = 0;

    s.ready.push(tid);

    log::info!(
        "Ke scheduler: spawned user-mode thread TID={} entry={:#010x} usp={:#010x} kstack_top={:#x}",
        tid, entry32, stack32, kstack_top,
    );
    Some(tid)
}

/// Terminate all user-mode threads except the current one.
///
/// Call this when the kernel shell takes exclusive console ownership so that
/// no user-mode thread (e.g. CMD.EXE) can steal serial/PS2 input or flood
/// the framebuffer with log messages.
///
/// Threads already Terminated are left alone. The boot thread (TID 0) is
/// never touched regardless of user_mode flag.
///
/// # IRQL: PASSIVE_LEVEL
pub fn terminate_user_threads() {
    let mut guard = SCHED.lock();
    let Some(s) = guard.as_mut() else { return };
    let cur = s.current;
    for (tid, thread) in s.threads.iter_mut().enumerate() {
        if !thread.used { continue; }
        if tid == cur  { continue; } // don't terminate ourselves
        if tid == 0    { continue; } // never kill boot thread
        if thread.user_mode && thread.state != ThreadState::Terminated {
            thread.state = ThreadState::Terminated;
        }
    }
}

/// Mark the currently running thread as Terminated and context-switch away.
///
/// Used by `NtTerminateProcess`/`NtTerminateThread` to exit the current
/// user-mode thread cooperatively.  After this call the thread's slot is
/// kept in the table (for handle-table lookup) but will never be scheduled
/// again.
///
/// # IRQL: PASSIVE_LEVEL (called from syscall handler with IF=0 via INT 0x2E,
///         effectively DISPATCH_LEVEL — no alloc inside this function).
pub fn terminate_current_thread() {
    let switch = {
        let mut guard = SCHED.lock();
        let Some(s) = guard.as_mut() else { return };
        let cur = s.current;
        // Mark as terminated so pick_next won't re-enqueue it.
        s.threads[cur].state = ThreadState::Terminated;
        // pick_next will skip re-enqueue because state != Running.
        s.pick_next().map(|(old, next)| {
            if s.threads[next].user_mode && s.threads[next].kernel_stack_top != 0 {
                // SAFETY: same as schedule() — IF=0, single-CPU.
                unsafe { hal::gdt::set_kernel_stack_top(s.threads[next].kernel_stack_top) };
            }
            let old_ctx = &mut s.threads[old].ctx  as *mut  crate::thread::KContext;
            let new_ctx = &    s.threads[next].ctx as *const crate::thread::KContext;
            (old_ctx, new_ctx)
        })
    };

    if let Some((old_ctx, new_ctx)) = switch {
        // SAFETY: pointers into static SCHED table; IF=0 (no concurrent ISR).
        unsafe { crate::thread::context_switch_raw(old_ctx, new_ctx) };
        // If context_switch_raw returns (shouldn't for a terminated thread)
        // fall through to the halt loop below.
    }

    // No runnable thread — spin until the next timer tick selects someone else.
    loop {
        x86_64::instructions::hlt();
    }
}

fn idle_thread_main() -> ! {
    // The first time this function runs, we arrive here via `ret` from
    // `ke_context_switch` which was called inside the APIC timer ISR.
    // At that point IF=0 (ISR has interrupts disabled).  We must re-enable
    // interrupts so future timer ticks can preempt the idle `hlt` loop and
    // switch us back to a runnable thread.
    //
    // On subsequent visits, `ke_context_switch` returns inside the timer ISR
    // handler body, which eventually executes `iretq` to restore the saved
    // RFLAGS (IF=1) and land back at the `hlt` below.  The `sti` here only
    // matters for the very first invocation.
    //
    // SAFETY: we are at PASSIVE_LEVEL equivalent — the switch stub has already
    // dropped back to the idle stack; no kernel locks are held.
    x86_64::instructions::interrupts::enable();
    loop {
        x86_64::instructions::hlt();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p ke
//
// Tests cover:
//   T1-2a: ReadyQueue FIFO semantics and wrap-around.
//   T1-2b: SchedulerInner state transitions (no actual context switch needed).
//   T1-2c: Round-robin: two threads alternate on successive pick_next calls.
//   T1-2d: Idle thread always runs when queue is empty.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::ThreadState;

    // ── Helper: build a minimal SchedulerInner for testing ───────────────────

    fn make_scheduler_with_n_ready(n: usize) -> SchedulerInner {
        let mut s = SchedulerInner::new();

        // TID 0: boot/current (Running)
        s.threads[0].used     = true;
        s.threads[0].state    = ThreadState::Running;
        s.threads[0].priority = 8;
        s.current = 0;

        // TID 1: idle (always available)
        s.threads[1].used     = true;
        s.threads[1].state    = ThreadState::Ready;
        s.threads[1].priority = 0;
        s.idle_tid = 1;

        // TIDs 2..2+n: additional ready threads
        for i in 0..n {
            let tid = 2 + i;
            s.threads[tid].used     = true;
            s.threads[tid].state    = ThreadState::Ready;
            s.threads[tid].priority = 4;
            s.ready.push(tid);
        }
        s
    }

    // ── T1-2a: ReadyQueue ────────────────────────────────────────────────────

    #[test]
    fn ready_queue_new_is_empty() {
        let q = ReadyQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn ready_queue_push_pop_fifo_order() {
        let mut q = ReadyQueue::new();
        q.push(10);
        q.push(20);
        q.push(30);
        assert_eq!(q.pop(), Some(10));
        assert_eq!(q.pop(), Some(20));
        assert_eq!(q.pop(), Some(30));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn ready_queue_len_tracks_items() {
        let mut q = ReadyQueue::new();
        q.push(1);
        q.push(2);
        assert_eq!(q.len(), 2);
        q.pop();
        assert_eq!(q.len(), 1);
        q.pop();
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn ready_queue_wraps_around_correctly() {
        let mut q = ReadyQueue::new();
        // Fill to capacity
        for i in 0..MAX_READY { assert!(q.push(i)); }
        assert!(q.is_full());
        assert!(!q.push(99), "push to full queue must return false");
        // Drain half and refill — tests wrap-around
        for _ in 0..(MAX_READY / 2) { q.pop(); }
        for i in 0..(MAX_READY / 2) { assert!(q.push(100 + i)); }
        assert_eq!(q.len(), MAX_READY);
    }

    #[test]
    fn ready_queue_push_returns_false_when_full() {
        let mut q = ReadyQueue::new();
        for i in 0..MAX_READY { q.push(i); }
        assert!(!q.push(999));
    }

    // ── T1-2b: SchedulerInner state transitions ───────────────────────────────

    #[test]
    fn alloc_tid_returns_sequential_slots() {
        let mut s = SchedulerInner::new();
        // First free slot is 0
        let t0 = s.alloc_tid().expect("slot 0");
        s.threads[t0].used = true;
        let t1 = s.alloc_tid().expect("slot 1");
        s.threads[t1].used = true;
        assert_eq!(t0, 0);
        assert_eq!(t1, 1);
    }

    #[test]
    fn alloc_tid_returns_none_when_table_full() {
        let mut s = SchedulerInner::new();
        for i in 0..MAX_THREADS { s.threads[i].used = true; }
        assert!(s.alloc_tid().is_none());
    }

    #[test]
    fn pick_next_moves_current_to_ready_if_running() {
        let mut s = make_scheduler_with_n_ready(1); // TID 2 in queue
        // Current = TID 0 (Running), ready has TID 2
        let result = s.pick_next();
        assert!(result.is_some());
        let (prev, next) = result.unwrap();
        assert_eq!(prev, 0);
        assert_eq!(next, 2);
        // TID 0 should be back in ready (it was Running → Ready → enqueued)
        assert_eq!(s.threads[0].state, ThreadState::Ready);
        // TID 2 is now Running
        assert_eq!(s.threads[2].state, ThreadState::Running);
        assert_eq!(s.current, 2);
    }

    // ── T1-2c: Round-robin ────────────────────────────────────────────────────

    #[test]
    fn round_robin_two_threads_alternate() {
        let mut s = make_scheduler_with_n_ready(2); // TIDs 2 and 3 in queue
        // Tick 1: switch 0 → 2
        let (_, next1) = s.pick_next().expect("first switch");
        assert_eq!(next1, 2);
        // Tick 2: switch 2 → 3 (TID 0 re-enqueued from tick 1)
        let (_, next2) = s.pick_next().expect("second switch");
        assert_eq!(next2, 3);
        // Tick 3: switch 3 → 0 (TIDs 0, 2 are in queue)
        let (_, next3) = s.pick_next().expect("third switch");
        assert_eq!(next3, 0);
    }

    #[test]
    fn round_robin_preserves_fifo_order() {
        let mut s = make_scheduler_with_n_ready(3); // TIDs 2, 3, 4
        let mut seq = alloc::vec::Vec::new();
        for _ in 0..4 {
            if let Some((_, next)) = s.pick_next() {
                seq.push(next);
            }
        }
        // Must visit 2, 3, 4 in insertion order before cycling back
        assert_eq!(seq[0], 2);
        assert_eq!(seq[1], 3);
        assert_eq!(seq[2], 4);
    }

    // ── T1-2d: Idle thread fallback ──────────────────────────────────────────

    #[test]
    fn idle_thread_runs_when_queue_is_empty() {
        let mut s = make_scheduler_with_n_ready(0); // no user threads, only idle
        let result = s.pick_next();
        assert!(result.is_some());
        let (_, next) = result.unwrap();
        assert_eq!(next, s.idle_tid, "must fall back to idle when queue empty");
    }

    #[test]
    fn idle_thread_not_re_enqueued_into_ready_queue() {
        let mut s = make_scheduler_with_n_ready(0);
        s.current = s.idle_tid; // simulate idle is currently running
        s.threads[s.idle_tid].state = ThreadState::Running;
        // pick_next: idle is running, queue empty → no switch needed
        let result = s.pick_next();
        assert!(result.is_none(), "no switch needed when only idle is runnable");
        // Idle must NOT appear in the ready queue
        assert_eq!(s.ready.len(), 0);
    }

    #[test]
    fn idle_thread_yields_to_newly_ready_thread() {
        let mut s = make_scheduler_with_n_ready(0);
        // Put idle as current
        s.current = s.idle_tid;
        s.threads[s.idle_tid].state = ThreadState::Running;
        // A new thread becomes ready
        s.threads[2].used  = true;
        s.threads[2].state = ThreadState::Ready;
        s.ready.push(2);
        // pick_next should switch idle → TID 2
        let result = s.pick_next();
        assert!(result.is_some());
        let (_, next) = result.unwrap();
        assert_eq!(next, 2);
    }
}
