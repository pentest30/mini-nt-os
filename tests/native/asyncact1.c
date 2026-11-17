/*
 * Activating a window of another thread (WM_ASYNC_SETACTIVEWINDOW and the
 * deactivation of the thread that loses the foreground: win32k::input::
 * activate, win32k::queue's events; co_IntSetForegroundMessageQueue,
 * IntActivateWindow and IntDeactivateWindow of ReactOS as the
 * specification): a Win32 program (subsystem WINDOWS), compiled with MinGW
 * and linked to ReactOS's kernel32 and user32, which the scenario
 * `async-activate` puts on the boot disk in the place of winlogon.exe (like
 * activate1.c). It takes a desktop like winlogon; its main thread A shows
 * A1, then starts a thread B, which shows B1 (with a child BC) and B2
 * without activating them, then:
 * 1. A calls SetForegroundWindow(B1): A, which loses the foreground, gets at
 *    once (in the call) WM_NCACTIVATE, WM_ACTIVATE (WA_INACTIVE),
 *    WM_ACTIVATEAPP (FALSE, thread B) and WM_KILLFOCUS for A1, and has no
 *    active window nor focus after it; B, in its own thread, gets
 *    WM_ACTIVATEAPP (TRUE, thread A) for B1 and B2, then WM_NCACTIVATE,
 *    WM_ACTIVATE and WM_SETFOCUS for B1;
 * 2. B gives the focus to BC; A calls SetForegroundWindow(B2): B, still in
 *    the foreground, moves its activation from B1 to B2 in its thread
 *    (WM_ACTIVATE of both, WM_KILLFOCUS of BC, WM_SETFOCUS of B2), and
 *    nobody gets WM_ACTIVATEAPP;
 * 3. While B sleeps in a message handler, A calls SetForegroundWindow(A1),
 *    then SetForegroundWindow(B2): B gains the foreground back before it saw
 *    that it lost it, and that deactivation goes; once awake, B gets
 *    WM_ACTIVATEAPP (TRUE, thread A) for B1 and B2 and WM_NCACTIVATE for
 *    B2, already active (no WM_ACTIVATE, no WM_KILLFOCUS);
 * 4. While B sleeps again, A calls SetForegroundWindow(B1); B, awake, calls
 *    SetForegroundWindow(B2) itself: the activation of B1 that waited is
 *    stale and goes, B2 stays active;
 * 5. A calls SetForegroundWindow(A1): B, which loses the foreground, gets
 *    in its thread WM_NCACTIVATE and WM_ACTIVATE (WA_INACTIVE) for B2,
 *    WM_ACTIVATEAPP (FALSE, thread A) for B1 and B2, and WM_KILLFOCUS for
 *    B2, after which it has no active window nor focus; A gets
 *    WM_ACTIVATEAPP (TRUE, thread B), WM_ACTIVATE and WM_SETFOCUS for A1.
 * Each message goes to the debug port (DbgPrint) with the step, the window,
 * its parameters and the thread that handled it, where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef DWORD(__stdcall *THREAD_START)(void *);

typedef struct {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HICON hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HICON hIconSm;
} WNDCLASSEXW;

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

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WM_ACTIVATE 0x0006
#define WM_SETFOCUS 0x0007
#define WM_KILLFOCUS 0x0008
#define WM_ACTIVATEAPP 0x001C
#define WM_NCACTIVATE 0x0086
#define WM_APP 0x8000
#define WM_QUIT 0x0012
#define SW_SHOWNORMAL 1
#define SW_SHOWNOACTIVATE 4
#define PM_REMOVE 1
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define INFINITE 0xFFFFFFFF
#define EXIT_STATUS 0x7009

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HWND __stdcall GetActiveWindow(void);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) HWND __stdcall GetForegroundWindow(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HWND __stdcall SetFocus(HWND window);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static HDESK desktop;
static HWND a1, b1, bc, b2;
static DWORD thread_a;
static volatile DWORD thread_b;
/* The step under way; what B has done (its windows ready, then the last
   message of each step), counted; B asleep in a handler. */
static volatile int step;
static volatile LONG b_progress;
static volatile LONG b_sleeping;

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;

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

static const char *window_name(HWND hwnd)
{
    if (hwnd == 0)
        return "none";
    if (hwnd == a1)
        return "A1";
    if (hwnd == b1)
        return "B1";
    if (hwnd == bc)
        return "BC";
    if (hwnd == b2)
        return "B2";
    return "another window";
}

static const char *thread_name(DWORD tid)
{
    if (tid == 0)
        return "none";
    if (tid == thread_a)
        return "A";
    if (tid == thread_b)
        return "B";
    return "another";
}

static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    const char *in = thread_name(GetCurrentThreadId());
    const char *name = window_name(hwnd);

    switch (message) {
    case WM_NCACTIVATE:
        DbgPrint("[async] step %d: %s WM_NCACTIVATE %u, in thread %s\n", step, name, w, in);
        if (step == 3 && hwnd == b2 && w)
            __sync_fetch_and_add(&b_progress, 1);
        break;
    case WM_ACTIVATE:
        DbgPrint("[async] step %d: %s WM_ACTIVATE %x, other %s, in thread %s\n", step, name, w,
                 window_name((HWND)l), in);
        break;
    case WM_ACTIVATEAPP:
        DbgPrint("[async] step %d: %s WM_ACTIVATEAPP %u, other thread %s, in thread %s\n", step, name, w,
                 thread_name((DWORD)l), in);
        return 0;
    case WM_SETFOCUS:
        DbgPrint("[async] step %d: %s WM_SETFOCUS, from %s, in thread %s; active %s\n", step, name,
                 window_name((HWND)w), in, window_name(GetActiveWindow()));
        if ((step == 1 && hwnd == b1) || (step == 2 && hwnd == b2))
            __sync_fetch_and_add(&b_progress, 1);
        break;
    case WM_KILLFOCUS:
        DbgPrint("[async] step %d: %s WM_KILLFOCUS, to %s, in thread %s; active %s, focus %s\n", step, name,
                 window_name((HWND)w), in, window_name(GetActiveWindow()), window_name(GetFocus()));
        if (step == 5 && hwnd == b2)
            __sync_fetch_and_add(&b_progress, 1);
        break;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

/* Handles A's messages for `ms` milliseconds. */
static void pump_for(int ms)
{
    MSG message;
    int i;

    for (i = 0; i < ms / 10; i++) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
        Sleep(10);
    }
}

/* B sleeps in a handler (`then_b2`: then makes B2 active itself); returns
   once it does. */
static BOOL put_b_to_sleep(WPARAM then_b2)
{
    int i;

    b_sleeping = 0;
    PostThreadMessageW(thread_b, WM_APP + 1, then_b2, 0);
    for (i = 0; i < 300 && !b_sleeping; i++)
        Sleep(10);
    if (!b_sleeping)
        DbgPrint("[async] step %d: B made no sleep\n", step);
    return b_sleeping != 0;
}

/* Handles A's messages until B has made `count` steps of progress, for 3 s
   at most. */
static BOOL wait_for_b(LONG count)
{
    MSG message;
    int i;

    for (i = 0; i < 300; i++) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
        if (b_progress >= count)
            return 1;
        Sleep(10);
    }
    DbgPrint("[async] step %d: B made %ld of %ld steps\n", step, b_progress, count);
    return 0;
}

static DWORD __stdcall thread_b_main(void *parameter)
{
    HINSTANCE instance = GetModuleHandleW(0);
    MSG message;

    (void)parameter;
    thread_b = GetCurrentThreadId();
    if (!SetThreadDesktop(desktop))
        DbgPrint("[async] B has no desktop\n");
    b1 = CreateWindowExW(0, L"MinoAsync", L"B1", WS_OVERLAPPEDWINDOW, 450, 100, 300, 200, 0, 0, instance, 0);
    bc = CreateWindowExW(0, L"MinoAsync", L"BC", WS_CHILD | WS_VISIBLE, 10, 10, 100, 30, b1, 0, instance, 0);
    b2 = CreateWindowExW(0, L"MinoAsync", L"B2", WS_OVERLAPPEDWINDOW, 450, 350, 300, 200, 0, 0, instance, 0);
    if (!b1 || !bc || !b2)
        DbgPrint("[async] B's windows missing\n");
    ShowWindow(b1, SW_SHOWNOACTIVATE);
    ShowWindow(b2, SW_SHOWNOACTIVATE);
    DbgPrint("[async] B ready: active %s, focus %s\n", window_name(GetActiveWindow()), window_name(GetFocus()));
    __sync_fetch_and_add(&b_progress, 1);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        if (message.hwnd == 0 && message.message == WM_APP) {
            SetFocus(bc);
            DbgPrint("[async] step 2: B gave the focus to %s\n", window_name(GetFocus()));
            __sync_fetch_and_add(&b_progress, 1);
            continue;
        }
        if (message.hwnd == 0 && message.message == WM_APP + 1) {
            b_sleeping = 1;
            Sleep(1000);
            if (message.wParam) {
                SetForegroundWindow(b2);
                DbgPrint("[async] step %d: B chose B2 itself: active %s\n", step, window_name(GetActiveWindow()));
                __sync_fetch_and_add(&b_progress, 1);
            }
            continue;
        }
        DispatchMessageW(&message);
    }
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HANDLE thread;
    DWORD id;
    BOOL result, second;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoAsync";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    thread_a = GetCurrentThreadId();
    a1 = CreateWindowExW(0, L"MinoAsync", L"A1", WS_OVERLAPPEDWINDOW, 100, 100, 300, 200, 0, 0, instance, 0);
    if (!a1)
        ExitProcess(3);
    ShowWindow(a1, SW_SHOWNORMAL);
    thread = CreateThread(0, 0, thread_b_main, 0, 0, &id);
    if (!thread || !wait_for_b(1))
        ExitProcess(4);

    step = 1;
    result = SetForegroundWindow(b1);
    DbgPrint("[async] step 1: SetForegroundWindow(B1) %d; A after it: active %s, focus %s\n", result,
             window_name(GetActiveWindow()), window_name(GetFocus()));
    wait_for_b(2);
    DbgPrint("[async] step 1: foreground %s\n", window_name(GetForegroundWindow()));

    step = 2;
    PostThreadMessageW(thread_b, WM_APP, 0, 0);
    wait_for_b(3);
    result = SetForegroundWindow(b2);
    DbgPrint("[async] step 2: SetForegroundWindow(B2) %d\n", result);
    wait_for_b(4);
    DbgPrint("[async] step 2: foreground %s\n", window_name(GetForegroundWindow()));

    step = 3;
    if (put_b_to_sleep(0)) {
        result = SetForegroundWindow(a1);
        second = SetForegroundWindow(b2);
        DbgPrint("[async] step 3: while B sleeps, SetForegroundWindow(A1) %d, then (B2) %d\n", result, second);
    }
    wait_for_b(5);
    DbgPrint("[async] step 3: foreground %s\n", window_name(GetForegroundWindow()));

    step = 4;
    if (put_b_to_sleep(1)) {
        result = SetForegroundWindow(b1);
        DbgPrint("[async] step 4: while B sleeps, SetForegroundWindow(B1) %d\n", result);
    }
    wait_for_b(6);
    pump_for(300);
    DbgPrint("[async] step 4: foreground %s\n", window_name(GetForegroundWindow()));

    step = 5;
    result = SetForegroundWindow(a1);
    DbgPrint("[async] step 5: SetForegroundWindow(A1) %d; A after it: active %s, focus %s\n", result,
             window_name(GetActiveWindow()), window_name(GetFocus()));
    wait_for_b(7);
    DbgPrint("[async] step 5: foreground %s\n", window_name(GetForegroundWindow()));

    PostThreadMessageW(thread_b, WM_QUIT, 0, 0);
    WaitForSingleObject(thread, INFINITE);
    DbgPrint("[async] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
