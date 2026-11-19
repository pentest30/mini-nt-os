/*
 * EnableWindow and SetActiveWindow, as a modal dialog box does them to its
 * owner (IntEnableWindow and NtUserSetActiveWindow of ReactOS as the
 * specification; win32k::window::enable_window, win32k::input::set_active): a
 * Win32 program (subsystem WINDOWS), compiled with MinGW and linked to
 * ReactOS's kernel32 and user32, which the scenario `enable-window` puts on
 * the boot disk in the place of winlogon.exe (like closebtn1.c). It takes a
 * desktop like winlogon and shows B at (100, 100, 300 x 200), then O at
 * (450, 100), with its child C, which gets the keyboard:
 * 1. O active, C with the keyboard;
 * 2. EnableWindow(O, FALSE) returns FALSE, O gets WM_CANCELMODE then
 *    WM_ENABLE (FALSE); again, TRUE and WM_CANCELMODE alone; O disabled, C
 *    keeps the keyboard; SetFocus(O) fails;
 * 3. D, a popup owned by O, shown; EnableWindow(O, TRUE) returns TRUE and
 *    O gets WM_ENABLE (TRUE); SetActiveWindow(O) returns D: O active, in the
 *    foreground, with the keyboard; D gets WM_ACTIVATE (WA_INACTIVE);
 * 4. D destroyed; SetActiveWindow(C) returns O and changes nothing;
 * 5. O with the keyboard disabled: WM_KILLFOCUS, nobody has the keyboard;
 * 6. SetActiveWindow(NULL) returns O: B active, in the foreground;
 * 7. an unknown window: FALSE and ERROR_INVALID_WINDOW_HANDLE for both;
 * 8. SetActiveWindow(X), the window of another thread: NULL, and B stays
 *    active and in the foreground.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
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
#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WS_CAPTION 0x00C00000
#define WM_ACTIVATE 0x0006
#define WM_SETFOCUS 0x0007
#define WM_KILLFOCUS 0x0008
#define WM_ENABLE 0x000A
#define WM_CANCELMODE 0x001F
#define WM_QUIT 0x0012
#define INFINITE 0xFFFFFFFF
#define PM_REMOVE 0x0001
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x7009

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const WCHAR *name);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, DWORD(__stdcall *start)(void *),
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EnableWindow(HWND window, BOOL enable);
__declspec(dllimport) HWND __stdcall GetActiveWindow(void);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) HWND __stdcall GetForegroundWindow(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall IsWindowEnabled(HWND window);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HWND __stdcall SetActiveWindow(HWND window);
__declspec(dllimport) HWND __stdcall SetFocus(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static HWND b, o, c, d, x;
/* Set once X, the window of the other thread, exists. */
static HANDLE x_ready;
/* What O received, in order (C: WM_CANCELMODE, E0 and E1: WM_ENABLE, A0
   and A1: WM_ACTIVATE, S: WM_SETFOCUS, K: WM_KILLFOCUS), and D's
   WM_ACTIVATE (WA_INACTIVE). */
static char trace[64];
static int trace_length, d_deactivated;

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

static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        DispatchMessageW(&message);
}

/* `text`, then a space, at the end of the trace. */
static void note(const char *text)
{
    while (*text && trace_length < (int)sizeof trace - 2)
        trace[trace_length++] = *text++;
    trace[trace_length++] = ' ';
    trace[trace_length] = 0;
}

/* The trace without its last space, and a new one started. */
static const char *take_trace(void)
{
    static char taken[64];
    int i;
    for (i = 0; i < trace_length; i++)
        taken[i] = trace[i];
    taken[trace_length > 0 ? trace_length - 1 : 0] = 0;
    trace_length = 0;
    trace[0] = 0;
    return taken;
}

static LRESULT __stdcall window_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (window == o) {
        if (message == WM_CANCELMODE)
            note("C");
        else if (message == WM_ENABLE)
            note(wp ? "E1" : "E0");
        else if (message == WM_ACTIVATE)
            note((wp & 0xFFFF) ? "A1" : "A0");
        else if (message == WM_SETFOCUS)
            note("S");
        else if (message == WM_KILLFOCUS)
            note("K");
    }
    if (window == d && message == WM_ACTIVATE && (wp & 0xFFFF) == 0)
        d_deactivated++;
    return DefWindowProcW(window, message, wp, lp);
}

static HWND create(const WCHAR *name, DWORD style, int x, int y, int width, int height, HWND parent)
{
    return CreateWindowExW(0, L"Enable1", name, style, x, y, width, height, parent, 0, GetModuleHandleW(0), 0);
}

/* The other thread: X, hidden, then its messages until WM_QUIT. */
static DWORD __stdcall other_thread(void *parameter)
{
    MSG message;
    (void)parameter;
    x = create(L"X", WS_OVERLAPPEDWINDOW, 300, 350, 300, 200, 0);
    SetEvent(x_ready);
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    DestroyWindow(x);
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW window_class;
    BOOL first, second;
    HWND previous;
    DWORD error, other_tid;
    HANDLE other;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&window_class, 0, sizeof window_class);
    window_class.cbSize = sizeof window_class;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = GetModuleHandleW(0);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    window_class.lpszClassName = L"Enable1";
    if (!RegisterClassExW(&window_class))
        ExitProcess(2);
    b = create(L"B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 300, 200, 0);
    o = create(L"O", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 450, 100, 300, 200, 0);
    c = create(L"C", WS_CHILD | WS_VISIBLE, 10, 10, 100, 50, o);
    if (!b || !o || !c)
        ExitProcess(3);
    pump();
    SetFocus(c);
    take_trace();
    DbgPrint("[enable] step 1: active O %d, focus C %d\n", GetActiveWindow() == o, GetFocus() == c);

    first = EnableWindow(o, 0);
    second = EnableWindow(o, 0);
    DbgPrint("[enable] step 2: EnableWindow(O, FALSE) %d then %d; O got \"%s\"\n", first != 0, second != 0,
             take_trace());
    previous = SetFocus(o);
    DbgPrint("[enable] step 2: enabled %d, focus C %d; SetFocus(O) %p, focus C %d\n", IsWindowEnabled(o) != 0,
             GetFocus() == c, previous, GetFocus() == c);
    take_trace();

    d = create(L"D", WS_POPUP | WS_CAPTION | WS_VISIBLE, 500, 150, 200, 100, o);
    pump();
    DbgPrint("[enable] step 3: D active %d, focus D %d\n", GetActiveWindow() == d, GetFocus() == d);
    take_trace();
    first = EnableWindow(o, 1);
    previous = SetActiveWindow(o);
    pump();
    DbgPrint("[enable] step 3: EnableWindow(O, TRUE) %d, SetActiveWindow(O) D %d; O got \"%s\"\n", first != 0,
             previous == d, take_trace());
    DbgPrint("[enable] step 3: active O %d, foreground O %d, focus O %d, enabled %d; D WM_ACTIVATE 0 %d\n",
             GetActiveWindow() == o, GetForegroundWindow() == o, GetFocus() == o, IsWindowEnabled(o) != 0,
             d_deactivated);

    DestroyWindow(d);
    pump();
    take_trace();
    previous = SetActiveWindow(c);
    DbgPrint("[enable] step 4: SetActiveWindow(C) O %d; active O %d, focus O %d; O got \"%s\"\n", previous == o,
             GetActiveWindow() == o, GetFocus() == o, take_trace());

    first = EnableWindow(o, 0);
    DbgPrint("[enable] step 5: EnableWindow(O, FALSE) %d; O got \"%s\"; focus nobody %d\n", first != 0, take_trace(),
             GetFocus() == 0);
    first = EnableWindow(o, 1);
    DbgPrint("[enable] step 5: EnableWindow(O, TRUE) %d; O got \"%s\"\n", first != 0, take_trace());

    previous = SetActiveWindow(0);
    pump();
    DbgPrint("[enable] step 6: SetActiveWindow(NULL) O %d; active B %d, foreground B %d, focus B %d; O got \"%s\"\n",
             previous == o, GetActiveWindow() == b, GetForegroundWindow() == b, GetFocus() == b, take_trace());

    SetLastError(0);
    first = EnableWindow((HWND)0x1234, 1);
    error = GetLastError();
    SetLastError(0);
    previous = SetActiveWindow((HWND)0x1234);
    DbgPrint("[enable] step 7: EnableWindow %d, error %lu; SetActiveWindow %p, error %lu\n", first != 0, error,
             previous, GetLastError());

    x_ready = CreateEventW(0, 1, 0, 0);
    other = CreateThread(0, 0, other_thread, 0, 0, &other_tid);
    if (!x_ready || !other || WaitForSingleObject(x_ready, INFINITE) != 0 || !x)
        ExitProcess(4);
    previous = SetActiveWindow(x);
    pump();
    DbgPrint("[enable] step 8: SetActiveWindow(X) %p; active B %d, foreground B %d\n", previous,
             GetActiveWindow() == b, GetForegroundWindow() == b);
    PostThreadMessageW(other_tid, WM_QUIT, 0, 0);
    WaitForSingleObject(other, INFINITE);
    CloseHandle(other);

    DestroyWindow(o);
    DestroyWindow(b);
    DbgPrint("[enable] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
