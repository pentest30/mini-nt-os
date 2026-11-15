/*
 * MsgWaitForMultipleObjects: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `msg-wait` puts on the boot disk in the place of winlogon.exe (like
 * send1.c). user32 adds the event of the thread's queue to the caller's
 * objects; it asks the kernel for it with NtUserCallOneParam
 * (ONEPARAM_ROUTINE_GETINPUTEVENT), and clears the wake mask after the wait
 * (NOPARAM_ROUTINE_MSQCLEARWAKEMASK). Without that event, every call fails
 * at once (WAIT_FAILED): explorer's desktop thread was given up for dead
 * that way (desktop.cpp:193). The main thread takes a desktop like
 * winlogon, empties its queue, then:
 * 1. waits 100 ms for any input on an empty queue: WAIT_TIMEOUT;
 * 2. waits for a message that a worker thread posts 200 ms later: the
 *    queue's turn (WAIT_OBJECT_0 + 1 for one object), in time, and the
 *    message is in the queue;
 * 3. waits, as explorer's CDesktopThread::Initialize does, for a worker
 *    thread or an event that the worker sets 200 ms later: the event's
 *    turn (WAIT_OBJECT_0 + 1), in time;
 * 4. waits for nothing but the queue, with WaitMessage between: it still
 *    works after the wake mask was cleared.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef DWORD(__stdcall *THREAD_START)(void *);

typedef struct {
    LONG x;
    LONG y;
} POINT;

typedef struct {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG;

#define WM_USER 0x0400
#define PM_REMOVE 0x0001
#define QS_POSTMESSAGE 0x0008
#define QS_ALLEVENTS 0x04BF
#define QS_ALLINPUT 0x04FF
#define MAXIMUM_ALLOWED 0x02000000
#define INFINITE 0xFFFFFFFF
#define WAIT_TIMEOUT 258
#define EXIT_STATUS 0x7004

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const WCHAR *name);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) DWORD __stdcall MsgWaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL all,
                                                                DWORD milliseconds, DWORD wake_mask);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall WaitMessage(void);

static DWORD main_thread;
static HANDLE event;

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1))
        return 0;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return 0;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop))
        return 0;
    return 1;
}

/* Removes every message, and the queue's signal of them. */
static void empty_queue(void)
{
    MSG message;

    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        ;
    MsgWaitForMultipleObjects(0, 0, 0, 0, QS_ALLINPUT);
}

/* Posts WM_USER + 1 to the main thread 200 ms after its start. */
static DWORD __stdcall poster(void *parameter)
{
    (void)parameter;
    Sleep(200);
    PostThreadMessageW(main_thread, WM_USER + 1, 7, 0);
    return 0;
}

/* Sets the event 200 ms after its start, then lives 2 s more. */
static DWORD __stdcall setter(void *parameter)
{
    (void)parameter;
    Sleep(200);
    SetEvent(event);
    Sleep(2000);
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    HANDLE handles[2];
    HANDLE thread;
    MSG message;
    DWORD id, start, elapsed, result;
    BOOL got;

    if (!take_a_desktop())
        ExitProcess(1);
    main_thread = GetCurrentThreadId();
    event = CreateEventW(0, 0, 0, 0);
    if (!event)
        ExitProcess(2);
    empty_queue();
    DbgPrint("[msgwait] ready\n");

    result = MsgWaitForMultipleObjects(0, 0, 0, 100, QS_ALLINPUT);
    DbgPrint("[msgwait] step 1: an empty queue: %lu\n", result);

    thread = CreateThread(0, 0, poster, 0, 0, &id);
    if (!thread)
        ExitProcess(3);
    handles[0] = event;
    start = GetTickCount();
    result = MsgWaitForMultipleObjects(1, handles, 0, 5000, QS_POSTMESSAGE);
    elapsed = GetTickCount() - start;
    got = PeekMessageW(&message, 0, 0, 0, PM_REMOVE) && message.message == WM_USER + 1 && message.wParam == 7;
    DbgPrint("[msgwait] step 2: a message posted by another thread: %lu, in time %d, the message there %d\n", result,
             elapsed >= 100 && elapsed < 2000, got);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    empty_queue();

    thread = CreateThread(0, 0, setter, 0, 0, &id);
    if (!thread)
        ExitProcess(4);
    handles[0] = thread;
    handles[1] = event;
    start = GetTickCount();
    result = MsgWaitForMultipleObjects(2, handles, 0, INFINITE, QS_ALLEVENTS);
    elapsed = GetTickCount() - start;
    DbgPrint("[msgwait] step 3: a thread or the event it sets: %lu, in time %d\n", result,
             elapsed >= 100 && elapsed < 2000);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    empty_queue();
    PostThreadMessageW(main_thread, WM_USER + 2, 0, 0);
    WaitMessage();
    got = PeekMessageW(&message, 0, 0, 0, PM_REMOVE) && message.message == WM_USER + 2;
    thread = CreateThread(0, 0, poster, 0, 0, &id);
    if (!thread)
        ExitProcess(5);
    result = MsgWaitForMultipleObjects(0, 0, 0, 5000, QS_POSTMESSAGE);
    DbgPrint("[msgwait] step 4: WaitMessage got its message %d; the queue again: %lu\n", got, result);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    DbgPrint("[msgwait] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
