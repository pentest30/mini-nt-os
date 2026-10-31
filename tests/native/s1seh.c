/*
 * Spike S1 (docs/05-feuille-de-route.md, M3): the SEH test. A write to
 * address 0, inside a function of its own with a __finally block, inside a
 * __try whose filter lets the exception go on, inside a __try whose filter
 * takes it. The kernel sends the page fault to ntdll's
 * KiUserExceptionDispatcher, whose RtlDispatchException walks the FS:[0]
 * chain: the inner filter runs and declines, the outer one accepts; then
 * RtlUnwind runs the __finally block on its way, and the outer __except block
 * runs. The program prints what it saw and ends with 0x5153 if all of it
 * happened as it should (ntoskrnl::userland::run_boot_programs).
 *
 * Built by `cargo xtask` (xtask/src/native.rs) with clang for
 * i686-pc-windows-msvc, which compiles __try/__except (GCC does not on i386),
 * with -fasync-exceptions so that a faulting instruction counts; linked by
 * lld-link with seh3.c, the frame handler that clang's code calls.
 */

typedef long NTSTATUS;
typedef void *HANDLE;

#define NtCurrentProcess() ((HANDLE)-1)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define STATUS_ACCESS_VIOLATION 0xC0000005UL

/* What the kernel expects if every check holds, and otherwise. */
#define EXIT_STATUS ((NTSTATUS)0x5153)
#define EXIT_FAILURE ((NTSTATUS)0x0BAD)

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall NtTerminateProcess(HANDLE process, NTSTATUS status);

/* Null, but read at run time: the compiler cannot see the fault coming. */
static int *volatile null_pointer;
static volatile int inner_filter_ran;
/* 1 after a normal end of its __try, 2 after an abnormal one. */
static volatile int finally_ran;

/* A frame of its own: RtlUnwind calls its handler, which runs the block. */
__attribute__((noinline)) static void write_to_zero(void)
{
    __try {
        *null_pointer = 1;
    } __finally {
        finally_ran = _abnormal_termination() ? 2 : 1;
    }
}

void __stdcall NtProcessStartup(void *peb)
{
    (void)peb;
    unsigned long code = 0;
    int caught = 0;
    __try {
        __try {
            write_to_zero();
        } __except (inner_filter_ran = 1, EXCEPTION_CONTINUE_SEARCH) {
            caught = -1;
        }
    } __except (code = _exception_code(), EXCEPTION_EXECUTE_HANDLER) {
        caught = 1;
    }
    DbgPrint("[s1] SEH: write to 0 %s, code %08lX, inner filter %s, __finally %s\n",
             caught == 1 ? "caught" : "not caught", code, inner_filter_ran ? "declined" : "not run",
             finally_ran == 2 ? "ran on unwind" : "did not run on unwind");
    int ok = caught == 1 && code == STATUS_ACCESS_VIOLATION && inner_filter_ran && finally_ran == 2;
    NtTerminateProcess(NtCurrentProcess(), ok ? EXIT_STATUS : EXIT_FAILURE);
}
