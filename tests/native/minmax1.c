/*
 * Minimizing, maximizing and restoring top-level windows: a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's kernel32
 * and user32, which the scenario `minmax` puts on the boot disk in the place
 * of winlogon.exe (like `scroll`, see scroll1.c). On WinSta0\Default:
 * - E, created maximized (WS_MAXIMIZE: co_WinPosMinMaximize at its
 *   creation), then destroyed;
 * - B (topmost), T (a tool window), F (created minimized, WS_MINIMIZE: the
 *   first place at the bottom left) and W, overlapped, W active at 100, 100
 *   (400 x 300), over T;
 * - ShowWindow of W: SW_MINIMIZE (the icon at the next free place, beside
 *   F's, WM_SIZE SIZE_MINIMIZED, B activated rather than the tool window T
 *   under W: ActivateOtherWindowMin), F destroyed, SW_RESTORE (WM_QUERYOPEN, its
 *   rectangle back, active again), SW_SHOWMAXIMIZED (WM_GETMINMAXINFO's place:
 *   its thick frame off the screen, SIZE_MAXIMIZED), minimized from
 *   maximized then restored maximized (WPF_RESTORETOMAXIMIZED), restored; a
 *   WM_QUERYOPEN that answers FALSE keeps it minimized;
 * - GetWindowPlacement of each state, SetWindowPlacement of a new normal
 *   rectangle while maximized, and of a place for the icon
 *   (WPF_SETMINPOSITION) of D, which it keeps;
 * - then the mouse, typed by the scenario through QEMU's monitor at each
 *   "[minmax] mouse:" line: the maximize button, the restore button of the
 *   maximized window, the minimize button, the restore button of the icon,
 *   a double-click on the caption (maximized) and on the maximized caption
 *   (restored), a press on the maximize button released elsewhere (nothing);
 * - at last B minimized, W maximized, and the restore button of W pressed
 *   and held: the scenario captures the screen.
 * Each step goes to the debug port (DbgPrint, a line each, its values taken
 * before: MinGW evaluates arguments from the last).
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
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef void(__stdcall *TIMERPROC)(HWND, UINT, unsigned int, DWORD);

typedef struct {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HICON hIconSm;
} WNDCLASSEXW;

typedef struct {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

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

typedef struct {
    UINT length;
    UINT flags;
    UINT showCmd;
    POINT ptMinPosition;
    POINT ptMaxPosition;
    RECT rcNormalPosition;
} WINDOWPLACEMENT;

typedef struct {
    POINT ptReserved;
    POINT ptMaxSize;
    POINT ptMaxPosition;
    POINT ptMinTrackSize;
    POINT ptMaxTrackSize;
} MINMAXINFO;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define WS_MINIMIZE 0x20000000
#define WS_MAXIMIZE 0x01000000
#define WS_EX_TOPMOST 0x00000008
#define WS_EX_TOOLWINDOW 0x00000080
#define WS_POPUP 0x80000000
#define WS_CAPTION 0x00C00000
#define WS_SYSMENU 0x00080000
#define WM_SIZE 0x0005
#define WM_ACTIVATE 0x0006
#define WM_QUERYOPEN 0x0013
#define WM_GETMINMAXINFO 0x0024
#define WM_TIMER 0x0113
#define WM_NCLBUTTONDOWN 0x00A1
#define WM_NCLBUTTONDBLCLK 0x00A3
#define WM_APP 0x8000
#define SW_SHOWNORMAL 1
#define SW_SHOWMINIMIZED 2
#define SW_SHOWMAXIMIZED 3
#define SW_MINIMIZE 6
#define SW_HIDE 0
#define SW_RESTORE 9
#define GW_HWNDPREV 3
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define HWND_TOP ((HWND)0)
#define WPF_SETMINPOSITION 0x0001
#define HTCAPTION 2
#define HTMINBUTTON 8
#define HTMAXBUTTON 9
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x6012
#define HOLD_TIMER 7

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);

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
__declspec(dllimport) HWND __stdcall GetActiveWindow(void);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT command);
__declspec(dllimport) BOOL __stdcall GetWindowPlacement(HWND window, WINDOWPLACEMENT *placement);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall IsIconic(HWND window);
__declspec(dllimport) BOOL __stdcall IsZoomed(HWND window);
__declspec(dllimport) BOOL __stdcall KillTimer(HWND window, unsigned int id);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) unsigned int __stdcall SetTimer(HWND window, unsigned int id, UINT elapse, TIMERPROC proc);
__declspec(dllimport) BOOL __stdcall SetWindowPlacement(HWND window, const WINDOWPLACEMENT *placement);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND after, int x, int y, int cx, int cy, UINT flags);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static const WCHAR CLASS_NAME[] = L"MinoMinMax";
static HWND w, b;

/* What W's procedure saw. */
static UINT received[32];
static unsigned int received_count;
static int size_type = -1;
static LPARAM size_value;
static int query_open, refuse_open;
/* A maximum size and place of its own for WM_GETMINMAXINFO (0: none). */
static int own_max;

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
    DbgPrint("[minmax] on WinSta0\\Default\n");
    return 1;
}

/* Prints the messages W received since the last time. */
static void print_messages(const char *what)
{
    char text[32 * 5 + 1];
    char *at = text;
    unsigned int i;
    static const char digits[] = "0123456789abcdef";

    for (i = 0; i < received_count; i++) {
        int shift;
        for (shift = 12; shift >= 0; shift -= 4)
            *at++ = digits[(received[i] >> shift) & 15];
        *at++ = ' ';
    }
    *at = 0;
    DbgPrint("[minmax] %s received %u: %s\n", what, received_count, text);
    received_count = 0;
}

/* The state of `window`: iconic, zoomed, its rectangle. */
static void print_state(const char *what, HWND window)
{
    RECT rect;
    int iconic = IsIconic(window), zoomed = IsZoomed(window);
    GetWindowRect(window, &rect);
    DbgPrint("[minmax] %s: iconic %d, zoomed %d, %ld %ld %ld %ld\n", what, iconic, zoomed, rect.left, rect.top,
             rect.right, rect.bottom);
}

static void print_placement(const char *what, HWND window)
{
    WINDOWPLACEMENT placement;
    BOOL ok;
    memset(&placement, 0, sizeof placement);
    placement.length = sizeof placement;
    ok = GetWindowPlacement(window, &placement);
    DbgPrint("[minmax] %s: GetWindowPlacement %d: show %u, flags %u, min %ld %ld, max %ld %ld, normal %ld %ld %ld %ld\n",
             what, ok, placement.showCmd, placement.flags, placement.ptMinPosition.x, placement.ptMinPosition.y,
             placement.ptMaxPosition.x, placement.ptMaxPosition.y, placement.rcNormalPosition.left,
             placement.rcNormalPosition.top, placement.rcNormalPosition.right, placement.rcNormalPosition.bottom);
}

/* The mouse steps, in order: what W's procedure waits for, and the line
 * that asks the scenario for it. */
static const struct {
    UINT message;
    WPARAM hit;
    const char *what;
} steps[] = {
    {WM_NCLBUTTONDOWN, HTMAXBUTTON, "the maximize button"},
    {WM_NCLBUTTONDOWN, HTMAXBUTTON, "the restore button of the maximized window"},
    {WM_NCLBUTTONDOWN, HTMINBUTTON, "the minimize button"},
    {WM_NCLBUTTONDOWN, HTMINBUTTON, "the restore button of the icon"},
    {WM_NCLBUTTONDBLCLK, HTCAPTION, "a double-click on the caption"},
    {WM_NCLBUTTONDBLCLK, HTCAPTION, "a double-click on the maximized caption"},
    {WM_NCLBUTTONDOWN, HTMAXBUTTON, "the maximize button released elsewhere"},
    {WM_NCLBUTTONDOWN, HTMAXBUTTON, "the restore button held"},
};
static unsigned int step;

static void ask_for_step(void)
{
    DbgPrint("[minmax] mouse: %s\n", steps[step].what);
}

/* A step of the mouse: DefWindowProc follows it, then the state. */
static LRESULT mouse_step(HWND window, UINT message, WPARAM hit, LPARAM l)
{
    LRESULT result;
    unsigned int done = step;
    RECT rect;
    int iconic, zoomed;

    if (done == sizeof steps / sizeof steps[0] - 1) {
        /* Held: the timer comes while DefWindowProc follows the button. */
        SetTimer(window, HOLD_TIMER, 300, 0);
        return DefWindowProcW(window, message, hit, l);
    }
    size_type = -1;
    result = DefWindowProcW(window, message, hit, l);
    iconic = IsIconic(window);
    zoomed = IsZoomed(window);
    GetWindowRect(window, &rect);
    DbgPrint("[minmax] step %u: iconic %d, zoomed %d, %ld %ld %ld %ld\n", done + 1, iconic, zoomed, rect.left,
             rect.top, rect.right, rect.bottom);
    DbgPrint("[minmax] step %u: WM_SIZE %d %ld %ld, active W %d\n", done + 1, size_type, size_value & 0xFFFF,
             size_value >> 16, GetActiveWindow() == window);
    step++;
    if (step == sizeof steps / sizeof steps[0] - 1)
        PostMessageW(window, WM_APP, 0, 0);
    else
        ask_for_step();
    return result;
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (window == w && received_count < 32)
        received[received_count++] = message;
    switch (message) {
    case WM_SIZE:
        if (window == w) {
            size_type = wp;
            size_value = lp;
        }
        break;
    case WM_QUERYOPEN:
        if (window == w) {
            query_open++;
            if (refuse_open)
                return 0;
        }
        break;
    case WM_GETMINMAXINFO:
        if (own_max) {
            MINMAXINFO *info = (MINMAXINFO *)lp;
            info->ptMaxPosition.x = 600;
            info->ptMaxPosition.y = 50;
            info->ptMaxSize.x = 500;
            info->ptMaxSize.y = 300;
            return 0;
        }
        break;
    case WM_NCLBUTTONDOWN:
    case WM_NCLBUTTONDBLCLK:
        if (window == w && step < sizeof steps / sizeof steps[0] && message == steps[step].message &&
            wp == steps[step].hit)
            return mouse_step(window, message, wp, lp);
        break;
    case WM_TIMER:
        if (window == w && wp == HOLD_TIMER) {
            KillTimer(window, HOLD_TIMER);
            DbgPrint("[minmax] the restore button is held\n");
            return 0;
        }
        break;
    case WM_APP:
        if (window == w) {
            /* The end: B minimized under the screen's bottom left, W
             * maximized over the rest. */
            ShowWindow(b, SW_MINIMIZE);
            ShowWindow(w, SW_SHOWMAXIMIZED);
            print_state("at last, B", b);
            print_state("at last, W", w);
            DbgPrint("[minmax] at last: B above W %d, W active %d\n", GetWindow(w, GW_HWNDPREV) == b,
                     GetActiveWindow() == w);
            ask_for_step();
            return 0;
        }
        break;
    }
    return DefWindowProcW(window, message, wp, lp);
}

static HWND create(DWORD ex_style, const WCHAR *name, DWORD style, int x, int y, int width, int height)
{
    return CreateWindowExW(ex_style, CLASS_NAME, name, style, x, y, width, height, 0, 0, GetModuleHandleW(0), 0);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HWND e, f, d, t;
    MSG message;
    RECT client;
    WINDOWPLACEMENT placement;
    BOOL was, ok;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);

    /* Created maximized. */
    e = create(0, L"E", WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_MAXIMIZE, 10, 10, 300, 200);
    print_state("E, created maximized", e);
    print_placement("E", e);
    DestroyWindow(e);

    /* B, topmost; T, a tool window; F, created minimized (the first place);
     * W, active, above T. */
    b = create(WS_EX_TOPMOST, L"B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 700, 450, 400, 250);
    t = create(WS_EX_TOOLWINDOW, L"T", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 850, 100, 200, 100);
    f = create(0, L"F", WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_MINIMIZE, 10, 10, 300, 200);
    print_state("F, created minimized", f);
    w = create(0, L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300);
    if (!b || !t || !f || !w)
        ExitProcess(3);
    print_state("W", w);
    DbgPrint("[minmax] W active %d\n", GetActiveWindow() == w);

    /* Minimized: the next free place at the bottom left (F has the first);
     * B active, not T (a tool window, the window under W). */
    received_count = 0;
    size_type = -1;
    was = ShowWindow(w, SW_MINIMIZE);
    print_messages("SW_MINIMIZE");
    DbgPrint("[minmax] SW_MINIMIZE: was %d, WM_SIZE %d %ld, active B %d, focus B %d\n", was, size_type, size_value,
             GetActiveWindow() == b, GetFocus() == b);
    print_state("minimized", w);
    GetClientRect(w, &client);
    DbgPrint("[minmax] minimized: client %ld %ld\n", client.right, client.bottom);
    print_placement("minimized", w);
    was = ShowWindow(w, SW_MINIMIZE);
    DbgPrint("[minmax] SW_MINIMIZE again: was %d, iconic %d\n", was, IsIconic(w));
    DestroyWindow(f);

    /* WM_QUERYOPEN refuses, then accepts. */
    refuse_open = 1;
    query_open = 0;
    was = ShowWindow(w, SW_RESTORE);
    DbgPrint("[minmax] SW_RESTORE refused: was %d, WM_QUERYOPEN %d, iconic %d\n", was, query_open, IsIconic(w));
    refuse_open = 0;
    received_count = 0;
    size_type = -1;
    was = ShowWindow(w, SW_RESTORE);
    print_messages("SW_RESTORE");
    DbgPrint("[minmax] SW_RESTORE: was %d, WM_QUERYOPEN %d, WM_SIZE %d %ld %ld, active W %d, focus W %d\n", was,
             query_open, size_type, size_value & 0xFFFF, size_value >> 16, GetActiveWindow() == w, GetFocus() == w);
    print_state("restored", w);

    /* Maximized: WM_GETMINMAXINFO's place, its frame off the screen. */
    received_count = 0;
    size_type = -1;
    was = ShowWindow(w, SW_SHOWMAXIMIZED);
    print_messages("SW_SHOWMAXIMIZED");
    GetClientRect(w, &client);
    DbgPrint("[minmax] SW_SHOWMAXIMIZED: was %d, WM_SIZE %d %ld %ld, client %ld %ld\n", was, size_type,
             size_value & 0xFFFF, size_value >> 16, client.right, client.bottom);
    print_state("maximized", w);
    print_placement("maximized", w);
    was = ShowWindow(w, SW_SHOWMAXIMIZED);
    DbgPrint("[minmax] SW_SHOWMAXIMIZED again: was %d\n", was);

    /* Minimized from maximized: it comes back maximized. */
    ShowWindow(w, SW_MINIMIZE);
    print_placement("minimized from maximized", w);
    ShowWindow(w, SW_RESTORE);
    print_state("restored to maximized", w);
    size_type = -1;
    ShowWindow(w, SW_RESTORE);
    DbgPrint("[minmax] restored from maximized: WM_SIZE %d\n", size_type);
    print_state("restored again", w);

    /* A maximum of its own (WM_GETMINMAXINFO). */
    own_max = 1;
    ShowWindow(w, SW_SHOWMAXIMIZED);
    print_state("maximized to its own place", w);
    ShowWindow(w, SW_RESTORE);
    own_max = 0;

    /* Its maximized place is kept (InternalPos): WM_GETMINMAXINFO's place
     * by default, its size the default one. Then SetWindowPlacement while
     * maximized: covering the monitor, its placement has no maximized place,
     * which it forgets; the new normal rectangle. */
    ShowWindow(w, SW_SHOWMAXIMIZED);
    print_state("maximized at its place kept", w);
    memset(&placement, 0, sizeof placement);
    placement.length = sizeof placement;
    GetWindowPlacement(w, &placement);
    placement.rcNormalPosition.left = 150;
    placement.rcNormalPosition.top = 120;
    placement.rcNormalPosition.right = 550;
    placement.rcNormalPosition.bottom = 420;
    ok = SetWindowPlacement(w, &placement);
    DbgPrint("[minmax] SetWindowPlacement while maximized: %d, zoomed %d\n", ok, IsZoomed(w));
    ShowWindow(w, SW_RESTORE);
    print_state("restored to the new rectangle", w);
    placement.showCmd = SW_SHOWNORMAL;
    placement.rcNormalPosition.left = 100;
    placement.rcNormalPosition.top = 100;
    placement.rcNormalPosition.right = 500;
    placement.rcNormalPosition.bottom = 400;
    SetWindowPlacement(w, &placement);
    print_state("placed back", w);

    /* D: a place of its own for its icon (WPF_SETMINPOSITION), kept. */
    d = create(0, L"D", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 300, 200, 300, 200);
    memset(&placement, 0, sizeof placement);
    placement.length = sizeof placement;
    GetWindowPlacement(d, &placement);
    placement.flags = WPF_SETMINPOSITION;
    placement.showCmd = SW_SHOWMINIMIZED;
    placement.ptMinPosition.x = 400;
    placement.ptMinPosition.y = 600;
    ok = SetWindowPlacement(d, &placement);
    print_state("D, SetWindowPlacement(WPF_SETMINPOSITION)", d);
    print_placement("D", d);
    ShowWindow(d, SW_RESTORE);
    ShowWindow(d, SW_MINIMIZE);
    print_state("D, minimized again", d);
    /* Kept, hidden: a window that is not topmost under B and W (when all
     * the others are topmost, HWND_TOP puts a window above the last of
     * them, like IntLinkHwnd of ReactOS). */
    ShowWindow(d, SW_HIDE);

    /* W in front, active, for the mouse. */
    SetWindowPos(w, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    DbgPrint("[minmax] before the mouse: W active %d, iconic %d, zoomed %d\n", GetActiveWindow() == w, IsIconic(w),
             IsZoomed(w));
    ask_for_step();

    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(EXIT_STATUS);
    return 0;
}
