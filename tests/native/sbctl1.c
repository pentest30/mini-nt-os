/*
 * Scroll bar controls (SB_CTL, the ScrollBar class of user32): a Win32
 * program (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's
 * kernel32 and user32, which the scenario `scroll-control` puts on the boot
 * disk in the place of winlogon.exe (like defer1.c). explorer's folder window
 * died on them: the address bar's autocompletion (browseui's CAutoComplete)
 * makes ScrollBar controls for its drop-down list, its size box subclassed by
 * ATL (SubclassWindow: SetWindowLongPtr of GWLP_WNDPROC), and win32k refused
 * both SB_CTL and the procedure of a server-side window. The program takes a
 * desktop like winlogon, shows a white popup with a vertical ScrollBar
 * control in it, then:
 * 1. SetScrollInfo(SB_CTL) and GetScrollInfo: the range, page and position
 *    kept by win32k (NtUserSetScrollInfo, NtUserSBGetParms);
 * 2. what user32 reads itself in the control's extra bytes (SBWND.SBCalc):
 *    GetScrollPos and SBM_GETRANGE;
 * 3. SetScrollPos past the end: the previous position, the new one clamped;
 * 4. GetScrollBarInfo(OBJID_CLIENT): the bar in the control's client area,
 *    its arrows and thumb;
 * 5. EnableScrollBar(SB_CTL, ESB_DISABLE_UP): the top arrow unavailable;
 * 6. ShowScrollBar(SB_CTL): the control hidden, then shown again;
 * 7. subclassed like ATL does it: SetWindowLongW(GWLP_WNDPROC) gives the old
 *    procedure, the class's (user32's ScrollBar procedure); the control's
 *    messages go through the new one, which passes them on (CallWindowProcW);
 *    given back its procedure, the control has it again;
 * 8. the same in ANSI: the old procedure is the class's ANSI one, and given
 *    back it makes the procedure the server's again (the Unicode one seen);
 * 9. the control painted by user32 (its WM_PAINT): the scenario reads the
 *    screen, the face of its top arrow.
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
    UINT cbSize;
    UINT fMask;
    int nMin;
    int nMax;
    UINT nPage;
    int nPos;
    int nTrackPos;
} SCROLLINFO;

typedef struct {
    DWORD cbSize;
    RECT rcScrollBar;
    int dxyLineButton;
    int xyThumbTop;
    int xyThumbBottom;
    int reserved;
    DWORD rgstate[6];
} SCROLLBARINFO;

#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define SBS_VERT 0x0001
#define SB_CTL 2
#define SIF_RANGE 0x0001
#define SIF_PAGE 0x0002
#define SIF_POS 0x0004
#define SIF_ALL 0x0017
#define SBM_GETRANGE 0x00E3
#define ESB_DISABLE_UP 0x0001
#define OBJID_CLIENT ((LONG)0xFFFFFFFC)
#define STATE_SYSTEM_UNAVAILABLE 0x00000001
#define SM_CYVSCROLL 20
#define GWLP_WNDPROC (-4)
#define GCL_WNDPROC (-24)
#define PM_REMOVE 0x0001
#define MAXIMUM_ALLOWED 0x02000000
#define COLOR_WINDOW 5
#define EXIT_STATUS 0x7007

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall CallWindowProcA(WNDPROC procedure, HWND window, UINT message, WPARAM w,
                                                       LPARAM l);
__declspec(dllimport) LRESULT __stdcall CallWindowProcW(WNDPROC procedure, HWND window, UINT message, WPARAM w,
                                                       LPARAM l);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EnableScrollBar(HWND window, UINT bar, UINT arrows);
__declspec(dllimport) BOOL __stdcall GetScrollBarInfo(HWND window, LONG object, SCROLLBARINFO *info);
__declspec(dllimport) DWORD __stdcall GetClassLongA(HWND window, int index);
__declspec(dllimport) DWORD __stdcall GetClassLongW(HWND window, int index);
__declspec(dllimport) BOOL __stdcall GetScrollInfo(HWND window, int bar, SCROLLINFO *info);
__declspec(dllimport) int __stdcall GetScrollPos(HWND window, int bar);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) BOOL __stdcall IsWindowVisible(HWND window);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) int __stdcall SetScrollInfo(HWND window, int bar, const SCROLLINFO *info, BOOL redraw);
__declspec(dllimport) int __stdcall SetScrollPos(HWND window, int bar, int position, BOOL redraw);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) LONG __stdcall SetWindowLongA(HWND window, int index, LONG value);
__declspec(dllimport) LONG __stdcall SetWindowLongW(HWND window, int index, LONG value);
__declspec(dllimport) BOOL __stdcall ShowScrollBar(HWND window, int bar, BOOL show);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

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
    return DefWindowProcW(hwnd, message, w, l);
}

/* The control's procedures before the subclassing, and the messages its
   subclass procedures saw. */
static WNDPROC old_unicode, old_ansi;
static int seen;

static LRESULT __stdcall subclass_unicode(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    seen++;
    return CallWindowProcW(old_unicode, hwnd, message, w, l);
}

static LRESULT __stdcall subclass_ansi(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    seen++;
    return CallWindowProcA(old_ansi, hwnd, message, w, l);
}

/* Handles every message there is, WM_PAINT included. */
static void pump(void)
{
    MSG message;
    int i;

    for (i = 0; i < 20; i++) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
        Sleep(10);
    }
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSEXW class_info;
    SCROLLINFO info;
    SCROLLBARINFO bar;
    HWND parent, control;
    int set, before, after, low = -1, high = -1;
    BOOL got, hidden, shown, enabled, now, back, again;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoScrollParent";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    parent = CreateWindowExW(0, L"MinoScrollParent", L"P", WS_POPUP | WS_VISIBLE, 100, 100, 300, 260, 0, 0, instance,
                             0);
    control = CreateWindowExW(0, L"ScrollBar", 0, WS_CHILD | WS_VISIBLE | SBS_VERT, 10, 10, 20, 200, parent, 0,
                              instance, 0);
    DbgPrint("[sbctl] ready: the control %d\n", control != 0);
    if (!parent || !control)
        ExitProcess(3);

    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.fMask = SIF_ALL;
    info.nMin = 0;
    info.nMax = 99;
    info.nPage = 10;
    info.nPos = 30;
    set = SetScrollInfo(control, SB_CTL, &info, 1);
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.fMask = SIF_ALL;
    got = GetScrollInfo(control, SB_CTL, &info);
    DbgPrint("[sbctl] step 1: SetScrollInfo %d; GetScrollInfo %d: %d..%d, page %u, position %d\n", set, got, info.nMin,
             info.nMax, info.nPage, info.nPos);

    SendMessageW(control, SBM_GETRANGE, (WPARAM)&low, (LPARAM)&high);
    DbgPrint("[sbctl] step 2: GetScrollPos %d, SBM_GETRANGE %d..%d\n", GetScrollPos(control, SB_CTL), low, high);

    before = SetScrollPos(control, SB_CTL, 200, 1);
    after = GetScrollPos(control, SB_CTL);
    DbgPrint("[sbctl] step 3: SetScrollPos(200) %d, then %d\n", before, after);

    memset(&bar, 0, sizeof bar);
    bar.cbSize = sizeof bar;
    got = GetScrollBarInfo(control, OBJID_CLIENT, &bar);
    DbgPrint("[sbctl] step 4: GetScrollBarInfo %d: %ldx%ld, arrows %d (the metric %d), thumb at the end %d\n", got,
             bar.rcScrollBar.right - bar.rcScrollBar.left, bar.rcScrollBar.bottom - bar.rcScrollBar.top,
             bar.dxyLineButton, GetSystemMetrics(SM_CYVSCROLL),
             bar.xyThumbBottom == 200 - bar.dxyLineButton && bar.xyThumbTop > bar.dxyLineButton);

    enabled = EnableScrollBar(control, SB_CTL, ESB_DISABLE_UP);
    memset(&bar, 0, sizeof bar);
    bar.cbSize = sizeof bar;
    GetScrollBarInfo(control, OBJID_CLIENT, &bar);
    DbgPrint("[sbctl] step 5: EnableScrollBar %d, the top arrow unavailable %d, the bottom one %d\n", enabled,
             (bar.rgstate[1] & STATE_SYSTEM_UNAVAILABLE) != 0, (bar.rgstate[5] & STATE_SYSTEM_UNAVAILABLE) != 0);
    EnableScrollBar(control, SB_CTL, 0);

    ShowScrollBar(control, SB_CTL, 0);
    hidden = !IsWindowVisible(control);
    ShowScrollBar(control, SB_CTL, 1);
    shown = IsWindowVisible(control);
    DbgPrint("[sbctl] step 6: ShowScrollBar hides %d, shows %d\n", hidden, shown);

    old_unicode = (WNDPROC)SetWindowLongW(control, GWLP_WNDPROC, (LONG)subclass_unicode);
    now = GetWindowLongW(control, GWLP_WNDPROC) == (LONG)subclass_unicode;
    low = high = -1;
    SendMessageW(control, SBM_GETRANGE, (WPARAM)&low, (LPARAM)&high);
    back = SetWindowLongW(control, GWLP_WNDPROC, (LONG)old_unicode) == (LONG)subclass_unicode;
    again = GetWindowLongW(control, GWLP_WNDPROC) == (LONG)old_unicode;
    DbgPrint("[sbctl] step 7: subclassed %d (the old procedure the class's %d), messages seen %d, SBM_GETRANGE %d..%d; "
             "given back %d, its procedure again %d\n",
             old_unicode != 0 && now, (DWORD)old_unicode == GetClassLongW(control, GCL_WNDPROC), seen > 0, low, high,
             back, again);

    seen = 0;
    old_ansi = (WNDPROC)SetWindowLongA(control, GWLP_WNDPROC, (LONG)subclass_ansi);
    SendMessageW(control, SBM_GETRANGE, (WPARAM)&low, (LPARAM)&high);
    back = SetWindowLongA(control, GWLP_WNDPROC, (LONG)old_ansi) == (LONG)subclass_ansi;
    DbgPrint("[sbctl] step 8: subclassed in ANSI %d (the class's ANSI procedure %d), messages seen %d; given back %d, "
             "the Unicode procedure again %d\n",
             old_ansi != 0 && old_ansi != old_unicode, (DWORD)old_ansi == GetClassLongA(control, GCL_WNDPROC), seen > 0,
             back, GetWindowLongW(control, GWLP_WNDPROC) == (LONG)old_unicode);

    UpdateWindow(parent);
    pump();
    DbgPrint("[sbctl] step 9: painted; look now\n");
    /* The scenario reads the screen and ends the run meanwhile. */
    Sleep(60000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
