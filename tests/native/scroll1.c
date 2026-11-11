/*
 * The scroll bars of windows: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `scroll` puts on the boot disk in the place of winlogon.exe (like `cursor`,
 * see cursor1.c). On WinSta0\Default:
 * - C, hidden, without a scroll bar style: no scroll bars before anyone
 *   speaks of them (GetScrollInfo, GetScrollPos: ERROR_NO_SCROLLBARS);
 * - A, at 100, 100 (400 x 300), with both bars, which user32's
 *   DefWindowProc gives it at WM_NCCREATE (0 to 100): SetScrollInfo of the
 *   vertical one (0 to 99, a page of 10, at 30), which user32 reads back
 *   itself (GetScrollPos, GetScrollRange: the SBINFO in the desktop's heap)
 *   or from the kernel (GetScrollInfo); SetScrollPos past the end stops at
 *   the range less the page, and returns the position before;
 *   GetScrollBarInfo: the bar on the screen, its arrows, its thumb; the
 *   horizontal bar from 0 to 199, a page of 50;
 * - B, at 600, 100 (300 x 200), with a horizontal bar: hidden when it has
 *   nothing to scroll (its client area taller), shown again when it has,
 *   disabled instead with SIF_DISABLENOSCROLL (both arrows unavailable),
 *   EnableScrollBar, ShowScrollBar.
 * Once A is painted, it says it waits, and the scenario clicks the down
 * arrow of its vertical bar through QEMU's monitor: user32 follows the
 * mouse (WM_SYSCOMMAND SC_VSCROLL, DefWndTrackScrollBar) and sends
 * WM_VSCROLL SB_LINEDOWN, then SB_ENDSCROLL at the release. Each step goes
 * to the debug port (DbgPrint, a line each, its values taken before: MinGW
 * evaluates arguments from the last); the program ends with EXIT_STATUS.
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
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

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

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define WS_VSCROLL 0x00200000
#define WS_HSCROLL 0x00100000
#define WM_PAINT 0x000F
#define WM_VSCROLL 0x0115
#define WM_HSCROLL 0x0114
#define GWL_STYLE (-16)
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define SB_HORZ 0
#define SB_VERT 1
#define SB_LINEDOWN 1
#define SB_ENDSCROLL 8
#define SIF_RANGE 0x0001
#define SIF_PAGE 0x0002
#define SIF_POS 0x0004
#define SIF_DISABLENOSCROLL 0x0008
#define SIF_ALL 0x0017
#define ESB_ENABLE_BOTH 0
#define ESB_DISABLE_LTUP 1
#define OBJID_HSCROLL ((LONG)0xFFFFFFFA)
#define OBJID_VSCROLL ((LONG)0xFFFFFFFB)
#define EXIT_STATUS 0x6011

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EnableScrollBar(HWND window, UINT bar, UINT arrows);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall GetScrollBarInfo(HWND window, LONG object, SCROLLBARINFO *info);
__declspec(dllimport) BOOL __stdcall GetScrollInfo(HWND window, int bar, SCROLLINFO *info);
__declspec(dllimport) int __stdcall GetScrollPos(HWND window, int bar);
__declspec(dllimport) BOOL __stdcall GetScrollRange(HWND window, int bar, int *min, int *max);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) int __stdcall SetScrollInfo(HWND window, int bar, const SCROLLINFO *info, BOOL redraw);
__declspec(dllimport) int __stdcall SetScrollPos(HWND window, int bar, int pos, BOOL redraw);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall ShowScrollBar(HWND window, int bar, BOOL show);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static const WCHAR CLASS_NAME[] = L"MinoScroll";
static HWND a;
static int painted, line_downs;

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
    DbgPrint("[scroll] on WinSta0\\Default\n");
    return 1;
}

static LRESULT __stdcall scroll_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;
    int request = w & 0xFFFF;

    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        EndPaint(window, &paint);
        if (window == a && !painted) {
            painted = 1;
            DbgPrint("[scroll] waiting\n");
        }
        return 0;
    case WM_VSCROLL:
        if (window != a)
            break;
        if (request == SB_LINEDOWN) {
            /* The first only: the button may be held past the first delay
             * of user32's timer, which repeats it. */
            int before = SetScrollPos(window, SB_VERT, GetScrollPos(window, SB_VERT) + 1, 1);
            if (!line_downs++)
                DbgPrint("[scroll] WM_VSCROLL SB_LINEDOWN: no control %d, the position before %d\n", l == 0, before);
        } else if (request == SB_ENDSCROLL) {
            DbgPrint("[scroll] WM_VSCROLL SB_ENDSCROLL: moved %d\n", GetScrollPos(window, SB_VERT) > 30);
            PostQuitMessage(0);
        }
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static void set_info(SCROLLINFO *info, UINT mask, int min, int max, UINT page, int pos)
{
    memset(info, 0, sizeof *info);
    info->cbSize = sizeof *info;
    info->fMask = mask;
    info->nMin = min;
    info->nMax = max;
    info->nPage = page;
    info->nPos = pos;
}

static int client_height(HWND window)
{
    RECT rect;
    GetClientRect(window, &rect);
    return rect.bottom;
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND b, c;
    MSG message;
    SCROLLINFO info;
    SCROLLBARINFO bar;
    int min = -1, max = -1, ok, got, pos, height, hidden, style;
    DWORD error, disabled[3], enabled[2];

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = scroll_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);

    c = CreateWindowExW(0, CLASS_NAME, L"C", WS_OVERLAPPEDWINDOW, 0, 500, 200, 100, 0, 0, instance, 0);
    set_info(&info, SIF_ALL, 0, 0, 0, 0);
    SetLastError(0);
    ok = GetScrollInfo(c, SB_VERT, &info);
    error = GetLastError();
    SetLastError(0);
    pos = GetScrollPos(c, SB_VERT);
    DbgPrint("[scroll] C, without scroll bars: GetScrollInfo %d (%lu), GetScrollPos %d (%lu)\n", ok, error, pos,
             GetLastError());

    a = CreateWindowExW(0, CLASS_NAME, L"A", WS_OVERLAPPEDWINDOW | WS_VSCROLL | WS_HSCROLL | WS_VISIBLE, 100, 100, 400,
                        300, 0, 0, instance, 0);
    b = CreateWindowExW(0, CLASS_NAME, L"B", WS_OVERLAPPEDWINDOW | WS_HSCROLL | WS_VISIBLE, 600, 100, 300, 200, 0, 0,
                        instance, 0);
    if (!a || !b || !c)
        ExitProcess(3);
    GetScrollRange(a, SB_VERT, &min, &max);
    DbgPrint("[scroll] A, from WM_NCCREATE: GetScrollRange %d %d, GetScrollPos %d\n", min, max, GetScrollPos(a, SB_VERT));

    set_info(&info, SIF_ALL, 0, 99, 10, 30);
    ok = SetScrollInfo(a, SB_VERT, &info, 1);
    pos = GetScrollPos(a, SB_VERT);
    GetScrollRange(a, SB_VERT, &min, &max);
    set_info(&info, SIF_ALL, -1, -1, 0, -1);
    got = GetScrollInfo(a, SB_VERT, &info);
    DbgPrint("[scroll] A: SetScrollInfo %d, GetScrollPos %d, GetScrollRange %d %d, GetScrollInfo %d: %d %d %u %d\n", ok,
             pos, min, max, got, info.nMin, info.nMax, info.nPage, info.nPos);
    ok = SetScrollPos(a, SB_VERT, 200, 1);
    DbgPrint("[scroll] A: SetScrollPos(200) %d, then %d\n", ok, GetScrollPos(a, SB_VERT));
    memset(&bar, 0, sizeof bar);
    bar.cbSize = sizeof bar;
    ok = GetScrollBarInfo(a, OBJID_VSCROLL, &bar);
    DbgPrint("[scroll] A: GetScrollBarInfo %d: %ld %ld %ld %ld, arrows %d, thumb %d %d, state %lx\n", ok,
             bar.rcScrollBar.left, bar.rcScrollBar.top, bar.rcScrollBar.right, bar.rcScrollBar.bottom,
             bar.dxyLineButton, bar.xyThumbTop, bar.xyThumbBottom, bar.rgstate[0]);
    SetScrollPos(a, SB_VERT, 30, 1);
    set_info(&info, SIF_ALL, 0, 199, 50, 0);
    SetScrollInfo(a, SB_HORZ, &info, 1);

    height = client_height(b);
    set_info(&info, SIF_RANGE | SIF_PAGE, 0, 9, 10, 0);
    SetScrollInfo(b, SB_HORZ, &info, 1);
    style = (GetWindowLongW(b, GWL_STYLE) & WS_HSCROLL) != 0;
    hidden = client_height(b);
    set_info(&info, SIF_RANGE, 0, 99, 0, 0);
    SetScrollInfo(b, SB_HORZ, &info, 1);
    DbgPrint("[scroll] B: client height %d; nothing to scroll: WS_HSCROLL %d, client height %d; again: WS_HSCROLL %d, "
             "client height %d\n",
             height, style, hidden, (GetWindowLongW(b, GWL_STYLE) & WS_HSCROLL) != 0, client_height(b));
    set_info(&info, SIF_RANGE | SIF_PAGE | SIF_DISABLENOSCROLL, 0, 9, 10, 0);
    SetScrollInfo(b, SB_HORZ, &info, 1);
    memset(&bar, 0, sizeof bar);
    bar.cbSize = sizeof bar;
    GetScrollBarInfo(b, OBJID_HSCROLL, &bar);
    style = (GetWindowLongW(b, GWL_STYLE) & WS_HSCROLL) != 0;
    disabled[0] = bar.rgstate[0];
    disabled[1] = bar.rgstate[1];
    disabled[2] = bar.rgstate[5];
    ok = EnableScrollBar(b, SB_HORZ, ESB_ENABLE_BOTH);
    GetScrollBarInfo(b, OBJID_HSCROLL, &bar);
    enabled[0] = bar.rgstate[1];
    enabled[1] = bar.rgstate[5];
    got = EnableScrollBar(b, SB_HORZ, ESB_DISABLE_LTUP);
    GetScrollBarInfo(b, OBJID_HSCROLL, &bar);
    DbgPrint("[scroll] B, SIF_DISABLENOSCROLL: WS_HSCROLL %d, states %lx %lx %lx; EnableScrollBar(ESB_ENABLE_BOTH) %d: "
             "%lx %lx; ESB_DISABLE_LTUP %d: %lx %lx\n",
             style, disabled[0], disabled[1], disabled[2], ok, enabled[0], enabled[1], got, bar.rgstate[1],
             bar.rgstate[5]);
    ok = ShowScrollBar(b, SB_HORZ, 0);
    hidden = client_height(b);
    got = ShowScrollBar(b, SB_HORZ, 1);
    height = client_height(b);
    DbgPrint("[scroll] B: ShowScrollBar(FALSE) %d, client height %d, ShowScrollBar(TRUE) %d, client height %d, again %d\n",
             ok, hidden, got, height, ShowScrollBar(b, SB_HORZ, 1));

    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    memset(&bar, 0, sizeof bar);
    bar.cbSize = sizeof bar;
    GetScrollBarInfo(a, OBJID_VSCROLL, &bar);
    DbgPrint("[scroll] A after the click: arrow states %lx %lx, thumb lower %d\n", bar.rgstate[1], bar.rgstate[5],
             bar.xyThumbTop > 84);
    DbgPrint("[scroll] done\n");
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
