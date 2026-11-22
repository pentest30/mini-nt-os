/*
 * SetThreadPriority and GetThreadPriority: a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32, which the
 * scenario `thread-priority` puts on the boot disk in the place of
 * winlogon.exe. GIMP 2.6 stopped on GLib's fatal "g_thread_set_priority:
 * error Incorrect function during SetThreadPriority": kernel32 makes it
 * NtSetInformationThread(ThreadBasePriority), which had no handler. As
 * ReactOS (ps/query.c, KeSetBasePriorityThread, KeQueryBasePriorityThread):
 * 1. each priority of a normal process, from THREAD_PRIORITY_IDLE to
 *    THREAD_PRIORITY_TIME_CRITICAL, set and read back (the saturated ones
 *    too: kernel32 passes them as -16 and 16);
 * 2. a priority out of range (3): refused, ERROR_INVALID_PARAMETER, the
 *    previous one kept;
 * 3. another thread's, by its handle.
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

#define THREAD_PRIORITY_IDLE (-15)
#define THREAD_PRIORITY_TIME_CRITICAL 15
#define ERROR_INVALID_PARAMETER 87
#define INFINITE 0xFFFFFFFF

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const void *name);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, DWORD(__stdcall *start)(void *),
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) HANDLE __stdcall GetCurrentThread(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) int __stdcall GetThreadPriority(HANDLE thread);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
__declspec(dllimport) BOOL __stdcall SetThreadPriority(HANDLE thread, int priority);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

static HANDLE go;

static DWORD __stdcall waiting(void *parameter)
{
    (void)parameter;
    WaitForSingleObject(go, INFINITE);
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    static const int priorities[] = {THREAD_PRIORITY_IDLE, -2, -1, 0, 1, 2, THREAD_PRIORITY_TIME_CRITICAL};
    HANDLE self = GetCurrentThread(), other;
    int i, kept = 0, refused, read_back, before, after;
    BOOL set;
    DWORD error;

    DbgPrint("[prio] ready: the thread's priority %d\n", GetThreadPriority(self));

    /* 1. Each priority of a normal process. */
    for (i = 0; i < 7; i++) {
        set = SetThreadPriority(self, priorities[i]);
        int got = GetThreadPriority(self);
        kept += set && got == priorities[i];
        if (!set || got != priorities[i])
            DbgPrint("[prio] %d: set %d, read back %d (error %lu)\n", priorities[i], set, got, GetLastError());
    }
    DbgPrint("[prio] step 1: %d of 7 priorities set and read back\n", kept);

    /* 2. Out of range. */
    SetThreadPriority(self, 1);
    SetLastError(0);
    refused = !SetThreadPriority(self, 3);
    error = GetLastError();
    read_back = GetThreadPriority(self);
    DbgPrint("[prio] step 2: 3 refused %d, error %lu, still %d\n", refused, error, read_back);
    SetThreadPriority(self, 0);

    /* 3. Another thread's. */
    go = CreateEventW(0, 1, 0, 0);
    other = CreateThread(0, 0, waiting, 0, 0, 0);
    if (!go || !other)
        ExitProcess(1);
    /* One call after the other: the arguments of a call have no order. */
    before = GetThreadPriority(other);
    set = SetThreadPriority(other, -2);
    after = GetThreadPriority(other);
    DbgPrint("[prio] step 3: another thread at %d, set to -2 %d, read back %d\n", before, set, after);
    SetEvent(go);
    WaitForSingleObject(other, INFINITE);
    CloseHandle(other);
    CloseHandle(go);
    DbgPrint("[prio] done\n");
    ExitProcess(0);
    return 0;
}
