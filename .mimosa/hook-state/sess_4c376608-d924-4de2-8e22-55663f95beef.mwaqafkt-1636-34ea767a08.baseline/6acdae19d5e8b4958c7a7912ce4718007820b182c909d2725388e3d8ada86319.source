/*
 * M5, console: a program of the CONSOLE subsystem, compiled with MinGW and
 * linked to ReactOS's kernel32, which CONSOLE1.EXE (console1.c) starts
 * (scenario `console`). Before it runs, kernel32 connects it to consrv,
 * which gives it a console. It is the program of the M5's exit criterion:
 * 8 threads synchronised by a critical section, each adding to a counter
 * under the lock and letting the others run while it holds it (Sleep(0)),
 * so that they wait for it; then it writes to its console (WriteConsoleW).
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; it ends with EXIT_STATUS if the counter is right and no two
 * threads were in the critical section at once.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point ConsoleStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
typedef void *HANDLE;
typedef DWORD(__stdcall *THREAD_START)(void *);

/* RTL_CRITICAL_SECTION, 32 bits. */
typedef struct {
    void *DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    DWORD SpinCount;
} CRITICAL_SECTION;

#define THREADS 8
#define ROUNDS 2000
#define YIELD_EVERY 64
#define INFINITE 0xFFFFFFFF
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack_size, THREAD_START start,
                                                    void *parameter, DWORD flags, DWORD *thread_id);
__declspec(dllimport) void __stdcall DeleteCriticalSection(CRITICAL_SECTION *section);
__declspec(dllimport) void __stdcall EnterCriticalSection(CRITICAL_SECTION *section);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD which);
__declspec(dllimport) void __stdcall InitializeCriticalSection(CRITICAL_SECTION *section);
__declspec(dllimport) void __stdcall LeaveCriticalSection(CRITICAL_SECTION *section);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL all,
                                                             DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall WriteConsoleW(HANDLE console, const void *buffer, DWORD count, DWORD *written,
                                                   void *reserved);

static CRITICAL_SECTION lock;
static volatile LONG counter;
static volatile LONG inside;
static volatile LONG overlaps;

/* ROUNDS additions to the counter, each under the lock; every YIELD_EVERY
   rounds, the others run while this thread holds it. */
static DWORD __stdcall add(void *parameter)
{
    int round;

    (void)parameter;
    for (round = 0; round < ROUNDS; round++) {
        LONG value;

        EnterCriticalSection(&lock);
        if (++inside != 1)
            overlaps++;
        value = counter;
        if (round % YIELD_EVERY == 0)
            Sleep(0);
        counter = value + 1;
        inside--;
        LeaveCriticalSection(&lock);
    }
    return ROUNDS;
}

/* The 8 threads; whether the counter is right. */
static BOOL count_with_threads(void)
{
    HANDLE threads[THREADS];
    DWORD id;
    DWORD ended;
    int i;

    InitializeCriticalSection(&lock);
    EnterCriticalSection(&lock);
    EnterCriticalSection(&lock);
    DbgPrint("[threads] EnterCriticalSection twice: recursion %ld\n", lock.RecursionCount);
    LeaveCriticalSection(&lock);
    LeaveCriticalSection(&lock);
    for (i = 0; i < THREADS; i++) {
        threads[i] = CreateThread(0, 0, add, 0, 0, &id);
        if (!threads[i]) {
            DbgPrint("[threads] CreateThread: error %lu\n", GetLastError());
            return 0;
        }
    }
    ended = WaitForMultipleObjects(THREADS, threads, 1, INFINITE);
    DbgPrint("[threads] %d threads: wait %lu, counter %ld of %d, overlaps %ld, contended: %s\n", THREADS, ended, counter,
             THREADS * ROUNDS, overlaps, lock.LockSemaphore ? "yes" : "no");
    for (i = 0; i < THREADS; i++)
        CloseHandle(threads[i]);
    DeleteCriticalSection(&lock);
    return counter == THREADS * ROUNDS && overlaps == 0;
}

DWORD __stdcall ConsoleStartup(void)
{
    static const WCHAR text[] = L"Mino: 8 threads\r\n";
    DWORD written = 0;
    BOOL counted;
    BOOL wrote;

    DbgPrint("[threads] started\n");
    counted = count_with_threads();
    wrote = WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), text, sizeof text / sizeof text[0] - 1, &written, 0);
    DbgPrint("[threads] WriteConsoleW: %d (%lu), %lu characters\n", wrote, wrote ? 0 : GetLastError(), written);
    DbgPrint("[threads] done\n");
    ExitProcess(counted ? EXIT_STATUS : 3);
    return 0;
}
