/*
 * Many threads alive at once: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32, which the scenario
 * `many-threads` puts on the boot disk in the place of winlogon.exe. The
 * installer of Apache OpenOffice 4.1.17 stopped on "Insufficient system
 * resources exist to complete the requested service": the Visual C++ runtime
 * installer's rpcrt4 could not queue a work item (QueueUserWorkItem, error
 * 1450), RtlCreateUserThread failing with STATUS_INSUFFICIENT_RESOURCES. Ke
 * had a table of 64 threads for the whole system, kernel threads included,
 * and ready queues of 64; XP runs hundreds at rest.
 * 1. THREADS threads are created, each waiting on a manual-reset event;
 * 2. the program waits until each one has run up to its wait;
 * 3. the event is set: each one ends, and the program waits for each.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;

#define THREADS 200
#define INFINITE 0xFFFFFFFF
#define WAIT_OBJECT_0 0

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const void *name);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, DWORD(__stdcall *start)(void *),
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

static HANDLE go;
static HANDLE threads[THREADS];
static volatile long waiting, released;

static DWORD __stdcall waiter(void *parameter)
{
    (void)parameter;
    __sync_fetch_and_add(&waiting, 1);
    if (WaitForSingleObject(go, INFINITE) == WAIT_OBJECT_0)
        __sync_fetch_and_add(&released, 1);
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    int created = 0, ended = 0, i;
    DWORD error = 0;

    go = CreateEventW(0, 1, 0, 0);
    if (!go)
        ExitProcess(1);
    DbgPrint("[threads] ready: %d threads to create\n", THREADS);

    /* 1. Every thread, all alive at once. */
    for (i = 0; i < THREADS; i++) {
        threads[i] = CreateThread(0, 0, waiter, 0, 0, 0);
        if (!threads[i]) {
            error = GetLastError();
            break;
        }
        created++;
    }
    if (created < THREADS)
        DbgPrint("[threads] thread %d not created (error %lu)\n", created, error);
    DbgPrint("[threads] step 1: %d of %d threads created\n", created, THREADS);

    /* 2. Each one runs up to its wait (10 s at most). */
    for (i = 0; i < 1000 && waiting < created; i++)
        Sleep(10);
    DbgPrint("[threads] step 2: %ld of %d threads waiting\n", waiting, created);

    /* 3. All released; each one ends. */
    SetEvent(go);
    for (i = 0; i < created; i++) {
        ended += WaitForSingleObject(threads[i], INFINITE) == WAIT_OBJECT_0;
        CloseHandle(threads[i]);
    }
    DbgPrint("[threads] step 3: %ld released, %d of %d ended\n", released, ended, created);
    CloseHandle(go);
    DbgPrint("[threads] done\n");
    ExitProcess(0);
    return 0;
}
