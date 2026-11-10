/*
 * USER's timers: a Win32 program (subsystem WINDOWS), compiled with MinGW
 * and linked to ReactOS's kernel32 and user32, which the scenario `timers`
 * puts on the boot disk in the place of winlogon.exe (like gui1.c). It
 * takes a desktop like winlogon, opens a window, and checks, one after the
 * other:
 * - a window timer (SetTimer(window, 1, 100 ms)): three WM_TIMER for the
 *   window, wParam 1, lParam 0, at least 90 ms apart; KillTimer stops it
 *   (TRUE, then FALSE), and no WM_TIMER comes after;
 * - a thread timer (SetTimer(NULL, 0, ...)): win32k gives it a free id,
 *   WM_TIMER comes without a window with that id in wParam; SetTimer with
 *   that id replaces it; a window timer of id 0 gives 1;
 * - a timer procedure (SetTimer(window, 2, 30 ms, procedure)): WM_TIMER
 *   carries the procedure in lParam, and DispatchMessage calls it once
 *   win32k says it is the process's (NtUserValidateTimerCallback);
 * - the place of WM_TIMER: a timer due while the thread sleeps shows in
 *   GetQueueStatus(QS_TIMER), and a message posted after comes out first;
 * - a system timer (SetSystemTimer): WM_SYSTIMER, which KillSystemTimer
 *   stops;
 * then it ends with EXIT_STATUS. Each result goes to the debug port
 * (DbgPrint), where the scenario looks for it.
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
typedef unsigned int UINT_PTR;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef void(__stdcall *TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);

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
#define WS_VISIBLE 0x10000000
#define WM_USER 0x0400
#define WM_TIMER 0x0113
#define WM_SYSTIMER 0x0118
#define QS_TIMER 0x0010
#define PM_REMOVE 0x0001
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x7001

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) DWORD __stdcall GetQueueStatus(UINT flags);
__declspec(dllimport) BOOL __stdcall KillSystemTimer(HWND window, UINT_PTR id);
__declspec(dllimport) BOOL __stdcall KillTimer(HWND window, UINT_PTR id);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) UINT_PTR __stdcall SetSystemTimer(HWND window, UINT_PTR id, UINT elapse, TIMERPROC procedure);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) UINT_PTR __stdcall SetTimer(HWND window, UINT_PTR id, UINT elapse, TIMERPROC procedure);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

static HWND window;
/* The calls of the timer procedure, and of WM_SYSTIMER. */
static int procedure_calls;
static int system_ticks;

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

static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_SYSTIMER && w == 7) {
        system_ticks++;
        DbgPrint("[timer] WM_SYSTIMER 7, window %s; KillSystemTimer: %d\n", hwnd == window ? "ours" : "other",
                 KillSystemTimer(hwnd, 7));
        return 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

static void __stdcall timer_procedure(HWND hwnd, UINT message, UINT_PTR id, DWORD time)
{
    procedure_calls++;
    DbgPrint("[timer] procedure: window %s, message %x, id %u, time %s; KillTimer: %d\n",
             hwnd == window ? "ours" : "other", message, id, time ? "set" : "0", KillTimer(hwnd, id));
}

/* The next message, dispatched; FALSE at WM_QUIT. */
static BOOL pump(MSG *message)
{
    if (GetMessageW(message, 0, 0, 0) <= 0)
        return 0;
    DispatchMessageW(message);
    return 1;
}

/* Waits for the WM_TIMER of `hwnd` and `id`, dispatching the rest. */
static BOOL wait_timer(HWND hwnd, UINT_PTR id, MSG *message)
{
    while (pump(message))
        if (message->message == WM_TIMER && message->hwnd == hwnd && message->wParam == id)
            return 1;
    return 0;
}

static void window_timer(void)
{
    MSG message;
    DWORD times[3];
    int spaced = 1, plain = 1, i;
    BOOL killed, again;

    DbgPrint("[timer] SetTimer(window, 1, 100): %u\n", SetTimer(window, 1, 100, 0));
    for (i = 0; i < 3; i++) {
        if (!wait_timer(window, 1, &message))
            ExitProcess(4);
        times[i] = GetTickCount();
        plain = plain && message.lParam == 0 && message.time != 0;
    }
    for (i = 1; i < 3; i++)
        spaced = spaced && times[i] - times[i - 1] >= 90;
    DbgPrint("[timer] window timer: 3 ticks, plain %d, at least 90 ms apart %d\n", plain, spaced);
    /* One call after the other: the order of a call's arguments is not. */
    killed = KillTimer(window, 1);
    again = KillTimer(window, 1);
    DbgPrint("[timer] KillTimer(window, 1): %d, again: %d\n", killed, again);
    Sleep(250);
    DbgPrint("[timer] WM_TIMER after KillTimer: %d\n", PeekMessageW(&message, 0, WM_TIMER, WM_TIMER, PM_REMOVE));
}

static void thread_timer(void)
{
    MSG message;
    UINT_PTR id = SetTimer(0, 0, 50, 0), zero;

    DbgPrint("[timer] SetTimer(NULL, 0, 50): %u\n", id);
    if (!wait_timer(0, id, &message))
        ExitProcess(5);
    DbgPrint("[timer] thread timer: WM_TIMER without a window, id %u\n", message.wParam);
    DbgPrint("[timer] SetTimer(NULL, %u, 80) again: %u\n", id, SetTimer(0, id, 80, 0));
    DbgPrint("[timer] KillTimer(NULL, %u): %d\n", id, KillTimer(0, id));
    zero = SetTimer(window, 0, 1000, 0);
    DbgPrint("[timer] SetTimer(window, 0, 1000): %u; KillTimer: %d\n", zero, KillTimer(window, 0));
}

static void timer_procedure_call(void)
{
    MSG message;

    DbgPrint("[timer] SetTimer(window, 2, 30, procedure): %u\n", SetTimer(window, 2, 30, timer_procedure));
    while (!procedure_calls)
        if (!pump(&message))
            ExitProcess(6);
    DbgPrint("[timer] procedure in lParam: %d\n", message.lParam == (LPARAM)timer_procedure);
}

static void timer_last(void)
{
    MSG message;
    DWORD status;
    int first = 0;

    SetTimer(window, 3, 20, 0);
    Sleep(100);
    status = GetQueueStatus(QS_TIMER);
    DbgPrint("[timer] GetQueueStatus(QS_TIMER) after a sleep: %08lx\n", status);
    PostMessageW(window, WM_USER + 1, 0, 0);
    while (!first && pump(&message)) {
        if (message.message == WM_USER + 1)
            first = 1;
        else if (message.message == WM_TIMER && message.wParam == 3)
            first = 2;
    }
    DbgPrint("[timer] first out: %s\n", first == 1 ? "the posted message" : "WM_TIMER");
    KillTimer(window, 3);
}

static void system_timer(void)
{
    MSG message;

    DbgPrint("[timer] SetSystemTimer(window, 7, 30): %u\n", SetSystemTimer(window, 7, 30, 0));
    while (!system_ticks)
        if (!pump(&message))
            ExitProcess(7);
    Sleep(100);
    DbgPrint("[timer] WM_SYSTIMER after KillSystemTimer: %d\n",
             PeekMessageW(&message, 0, WM_SYSTIMER, WM_SYSTIMER, PM_REMOVE));
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoTimer";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    window = CreateWindowExW(0, L"MinoTimer", L"Timers", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 300, 200, 0, 0,
                             class_info.hInstance, 0);
    if (!window)
        ExitProcess(3);
    UpdateWindow(window);
    DbgPrint("[timer] ready\n");
    window_timer();
    thread_timer();
    timer_procedure_call();
    timer_last();
    system_timer();
    DbgPrint("[timer] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
