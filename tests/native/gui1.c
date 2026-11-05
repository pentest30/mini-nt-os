/*
 * M6, windows: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32, user32 and gdi32. The scenario `gui` puts it on the
 * boot disk in the place of winlogon.exe, which smss starts as its initial
 * command (csrss makes it a CSR process): it gets a real user32, connected
 * to csrss and win32k, without winlogon's RPC server, services and GINA.
 *
 * Like winlogon, it registers as the logon process, creates the interactive
 * window station WinSta0 and a desktop, and goes on it. Then it registers a
 * class and creates a window of it: win32k sends the window procedure
 * WM_NCCREATE, WM_CREATE... through KeUserModeCallback. An overlapped
 * window gets WM_GETMINMAXINFO and its frame from the system metrics, by
 * DefWindowProc in win32k (NtUserMessageCall), and its default place from
 * the monitor. SetWindowPos moves, sizes, orders, shows and hides windows;
 * ShowWindow shows and hides them. A window shown paints its frame in the
 * kernel and erases its client area with a DC the kernel lends it
 * (WM_ERASEBKGND: user32's DefWindowProc fills it with the class brush,
 * through gdi32 and the GDI handle table it shares with win32k).
 * Each step and each
 * message goes to the debug port (DbgPrint), where the scenario looks for
 * them; the program ends with EXIT_STATUS.
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
typedef void *HDC;
typedef void *HGDIOBJ;
typedef void *HRGN;
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
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

typedef struct {
    POINT ptReserved;
    POINT ptMaxSize;
    POINT ptMaxPosition;
    POINT ptMinTrackSize;
    POINT ptMaxTrackSize;
} MINMAXINFO;

typedef struct {
    HWND hwnd;
    HWND hwndInsertAfter;
    int x;
    int y;
    int cx;
    int cy;
    UINT flags;
} WINDOWPOS;

typedef struct {
    DWORD cbSize;
    RECT rcMonitor;
    RECT rcWork;
    DWORD dwFlags;
    WCHAR szDevice[32];
} MONITORINFOEXW;

typedef void *HMONITOR;

typedef struct {
    void *lpCreateParams;
    HINSTANCE hInstance;
    HMENU hMenu;
    HWND hwndParent;
    int cy;
    int cx;
    int y;
    int x;
    LONG style;
    const WCHAR *lpszName;
    const WCHAR *lpszClass;
    DWORD dwExStyle;
} CREATESTRUCTW;

#define MAXIMUM_ALLOWED 0x02000000
#define CS_GLOBALCLASS 0x4000
#define ERROR_CLASS_ALREADY_EXISTS 1410
#define ERROR_CLASS_DOES_NOT_EXIST 1411
#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_CLIPSIBLINGS 0x04000000
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_CAPTION 0x00C00000
#define WS_THICKFRAME 0x00040000
#define CW_USEDEFAULT ((int)0x80000000)
#define GWL_STYLE (-16)
#define GWL_EXSTYLE (-20)
#define WS_EX_TOPMOST 0x00000008
#define GW_HWNDFIRST 0
#define GW_HWNDNEXT 2
#define HWND_TOP ((HWND)0)
#define HWND_BOTTOM ((HWND)1)
#define HWND_TOPMOST ((HWND)-1)
#define HWND_NOTOPMOST ((HWND)-2)
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define SWP_NOZORDER 0x0004
#define SWP_NOACTIVATE 0x0010
#define SWP_SHOWWINDOW 0x0040
#define SWP_HIDEWINDOW 0x0080
#define SWP_FRAMECHANGED 0x0020
#define MONITOR_DEFAULTTONULL 0
#define MONITOR_DEFAULTTONEAREST 2
#define WM_MOVE 0x0003
#define WM_SIZE 0x0005
#define WM_WINDOWPOSCHANGED 0x0047
#define WM_SHOWWINDOW 0x0018
#define WS_VISIBLE 0x10000000
#define WS_CLIPCHILDREN 0x02000000
#define WS_BORDER 0x00800000
#define SW_HIDE 0
#define SW_SHOWNORMAL 1
#define SW_SHOWNOACTIVATE 4
#define SW_SHOW 5
#define ERROR_INVALID_PARAMETER 87
#define GW_CHILD 5
#define WM_PARENTNOTIFY 0x0210
#define ERROR_TLW_WITH_WSCHILD 1406
#define ERROR_CANNOT_FIND_WND_CLASS 1407
#define COLOR_WINDOW 5
#define WM_ERASEBKGND 0x0014
#define OBJ_BRUSH 2
#define PATCOPY 0x00F00021
#define BLACKNESS 0x00000042
#define WM_PAINT 0x000F
#define PM_REMOVE 0x0001
#define PM_NOREMOVE 0x0000
#define QS_PAINT 0x0020
#define FALSE 0
#define TRUE 1
#define RDW_INVALIDATE 0x0001
#define RDW_INTERNALPAINT 0x0002
#define RDW_ERASE 0x0004
#define RDW_ALLCHILDREN 0x0080
#define RDW_UPDATENOW 0x0100
#define RDW_ERASENOW 0x0200
#define RDW_FRAME 0x0400
#define COLOR_HIGHLIGHT 13
#define WM_CREATE 0x0001
#define WM_GETMINMAXINFO 0x0024
#define WM_NCCALCSIZE 0x0083
#define WM_NCCREATE 0x0081
#define RGN_AND 1
#define RGN_OR 2
#define RGN_DIFF 4
#define NULLREGION 1
#define SIMPLEREGION 2
#define COMPLEXREGION 3
#define DCX_EXCLUDERGN 0x00000040
#define DCX_INTERSECTRGN 0x00000080
#define DCX_KEEPCLIPRGN 0x00040000
#define OBJ_REGION 8

/* What the scenario expects when the program runs to its end. */
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

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
__declspec(dllimport) BOOL __stdcall GetClassInfoExW(HINSTANCE instance, const WCHAR *name, WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) HWND __stdcall GetParent(HWND window);
__declspec(dllimport) DWORD __stdcall GetSysColor(int index);
__declspec(dllimport) HBRUSH __stdcall GetSysColorBrush(int index);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) DWORD __stdcall GetQueueStatus(UINT flags);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HWND window, const RECT *rect, BOOL erase);
__declspec(dllimport) BOOL __stdcall ValidateRect(HWND window, const RECT *rect);
__declspec(dllimport) BOOL __stdcall GetUpdateRect(HWND window, RECT *rect, BOOL erase);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);
__declspec(dllimport) BOOL __stdcall RedrawWindow(HWND window, const RECT *rect, void *region, UINT flags);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) HDC __stdcall GetDCEx(HWND window, HRGN clip, DWORD flags);
__declspec(dllimport) HDC __stdcall GetWindowDC(HWND window);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC dc);
__declspec(dllimport) BOOL __stdcall InvalidateRgn(HWND window, HRGN region, BOOL erase);
__declspec(dllimport) BOOL __stdcall ValidateRgn(HWND window, HRGN region);
__declspec(dllimport) int __stdcall GetUpdateRgn(HWND window, HRGN region, BOOL erase);
__declspec(dllimport) int __stdcall GetClipBox(HDC dc, RECT *rect);
__declspec(dllimport) int __stdcall CombineRgn(HRGN destination, HRGN first, HRGN second, int mode);
__declspec(dllimport) HRGN __stdcall CreateRectRgn(int left, int top, int right, int bottom);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ object);
__declspec(dllimport) int __stdcall ExtSelectClipRgn(HDC dc, HRGN region, int mode);
__declspec(dllimport) BOOL __stdcall GdiFlush(void);
__declspec(dllimport) int __stdcall GetRgnBox(HRGN region, RECT *rect);
__declspec(dllimport) int __stdcall SelectClipRgn(HDC dc, HRGN region);
__declspec(dllimport) BOOL __stdcall SetRectRgn(HRGN region, int left, int top, int right, int bottom);
__declspec(dllimport) DWORD __stdcall GetObjectType(HGDIOBJ object);
__declspec(dllimport) BOOL __stdcall PatBlt(HDC dc, int x, int y, int width, int height, DWORD rop);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT command);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) BOOL __stdcall GetMonitorInfoW(HMONITOR monitor, MONITORINFOEXW *info);
__declspec(dllimport) BOOL __stdcall IsWindowVisible(HWND window);
__declspec(dllimport) HMONITOR __stdcall MonitorFromPoint(POINT point, DWORD flags);
__declspec(dllimport) HMONITOR __stdcall MonitorFromWindow(HWND window, DWORD flags);
__declspec(dllimport) BOOL __stdcall MoveWindow(HWND window, int x, int y, int width, int height, BOOL repaint);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND after, int x, int y, int cx, int cy, UINT flags);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) int __stdcall GetWindowTextW(HWND window, WCHAR *text, int size);
__declspec(dllimport) BOOL __stdcall IsWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetWindowTextW(HWND window, const WCHAR *text);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

/* No C runtime: what GCC may call to clear or copy a structure. */
void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned int count)
{
    unsigned char *to = destination;
    const unsigned char *from = source;
    while (count--)
        *to++ = *from++;
    return destination;
}

static const WCHAR CLASS_NAME[] = L"MinoTestWindow";
/* A class whose windows draw stripes on their background. */
static const WCHAR STRIPED_CLASS[] = L"MinoStriped";
static const WCHAR WINDOW_NAME[] = L"Mino";
#define CREATE_PARAMETER ((void *)0x1234)

/* Whether two strings are equal. */
static BOOL same(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/* The messages the window procedure received, in order, until printed. */
static UINT received[32];
static unsigned int received_count;
/* What WM_PARENTNOTIFY gave. */
static WPARAM notified_w;
static LPARAM notified_l;
/* What WM_GETMINMAXINFO gave, and the minimum size to answer (0: none). */
static MINMAXINFO limits;
static LONG minimum_width;
static LONG minimum_height;
/* What the last WM_MOVE, WM_SIZE and WM_WINDOWPOSCHANGED gave. */
static LPARAM moved_l;
static LPARAM sized_l;
static WINDOWPOS changed;
/* What the last WM_SHOWWINDOW gave. */
static WPARAM shown_w;
/* The window that paints itself in WM_PAINT, and what BeginPaint gave it. */
static HWND painter;
static PAINTSTRUCT painted;
static unsigned int painter_paints;
/* The overlapped window "Visible". */
static HWND visible_window;
/* A window whose procedure does not call BeginPaint for WM_PAINT. */
static HWND lazy_window;
/* A window with WS_CLIPCHILDREN and a child. */
static HWND clipper_window;
/* The DC of the last WM_ERASEBKGND, and GetClipBox of it then. */
static HDC erased_dc;
static int erased_region;
static RECT erased_box;

/* Prints the messages received since the last time. */
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
    DbgPrint("[gui] %s received %u: %s\n", what, received_count, text);
    received_count = 0;
}

static void check_callback_window(HWND window);
static void check_caption_state(void);

static LRESULT __stdcall window_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (received_count < 32)
        received[received_count++] = message;
    if (message == WM_PARENTNOTIFY) {
        notified_w = w;
        notified_l = l;
    }
    if (message == WM_MOVE)
        moved_l = l;
    if (message == WM_SIZE)
        sized_l = l;
    if (message == WM_WINDOWPOSCHANGED)
        changed = *(const WINDOWPOS *)l;
    if (message == WM_SHOWWINDOW)
        shown_w = w;
    if (message == WM_ERASEBKGND) {
        erased_dc = (HDC)w;
        erased_region = GetClipBox(erased_dc, &erased_box);
    }
    if (message == WM_GETMINMAXINFO) {
        MINMAXINFO *info = (MINMAXINFO *)l;
        limits = *info;
        if (minimum_width) {
            info->ptMinTrackSize.x = minimum_width;
            info->ptMinTrackSize.y = minimum_height;
            return 0;
        }
    }
    if (message == WM_PAINT && window == lazy_window)
        return 0;
    if (message == WM_PAINT && window == painter) {
        /* A black square at the top of its client area, between BeginPaint
           and EndPaint, further right each time. */
        HDC dc = BeginPaint(window, &painted);
        PatBlt(dc, 12 * painter_paints++, 0, 10, 10, BLACKNESS);
        EndPaint(window, &painted);
        return 0;
    }
    if ((message == WM_NCCREATE || message == WM_CREATE) && ((const CREATESTRUCTW *)l)->style == (LONG)WS_POPUP
        && ((const CREATESTRUCTW *)l)->lpCreateParams == CREATE_PARAMETER) {
        const CREATESTRUCTW *create = (const CREATESTRUCTW *)l;
        BOOL expected = create->lpCreateParams == CREATE_PARAMETER && same(create->lpszName, WINDOW_NAME)
                        && same(create->lpszClass, CLASS_NAME) && create->x == 100 && create->y == 50
                        && create->cx == 400 && create->cy == 300;
        DbgPrint("[gui] %s: CREATESTRUCT %s\n", message == WM_NCCREATE ? "WM_NCCREATE" : "WM_CREATE",
                 expected ? "as given" : "WRONG");
        if (message == WM_CREATE)
            check_callback_window(window);
    }
    if (message == WM_CREATE && ((const CREATESTRUCTW *)l)->style == (LONG)WS_OVERLAPPEDWINDOW)
        check_caption_state();
    return DefWindowProcW(window, message, w, l);
}

/* A window of the striped class erases its client area like the others,
   with its class brush, then draws 24 black lines at its top, one PatBlt
   each: more than a batch holds (GDI_BATCH_LIMIT, 20), so that gdi32 asks
   win32k to run the batch (NtGdiFlush) before queuing again; then a line
   under them with the DC's own brush (WHITE_BRUSH, FillRect having put it
   back). */
static LRESULT __stdcall striped_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    LRESULT result = window_procedure(window, message, w, l);
    int i;

    if (message == WM_ERASEBKGND) {
        for (i = 0; i < 24; i++)
            PatBlt((HDC)w, 2 * i, 0, 1, 5, BLACKNESS);
        PatBlt((HDC)w, 0, 6, 48, 1, PATCOPY);
    }
    return result;
}

/* The TEB of the current thread. */
static const unsigned char *current_teb(void)
{
    const unsigned char *teb;
    __asm__("movl %%fs:0x18, %0" : "=r"(teb));
    return teb;
}

/* TEB.Win32ClientInfo, CLIENTINFO.CallbackWnd: during a call from win32k,
   the window and its WND (in this process's view of the desktop's heap),
   whose first word is its handle. */
static void check_callback_window(HWND window)
{
    const DWORD *callback = (const DWORD *)(current_teb() + 0x6CC + 0x28);
    BOOL right = callback[0] == (DWORD)window && callback[1] && *(const DWORD *)callback[1] == (DWORD)window;
    DbgPrint("[gui] CallbackWnd: %s\n", right ? "the window and its WND" : "WRONG");
}

/* After WM_NCCALCSIZE (DefWindowProc in win32k), the WND of a window with a
   caption has WNDS_HASCAPTION in its state, after its THRDESKHEAD. */
static void check_caption_state(void)
{
    const DWORD *callback = (const DWORD *)(current_teb() + 0x6CC + 0x28);
    const DWORD *wnd = (const DWORD *)callback[1];
    DbgPrint("[gui] WM_CREATE: WNDS_HASCAPTION %s\n", wnd && (wnd[5] & 8) ? "set" : "WRONG");
    /* WM_GETMINMAXINFO: maximized, it covers its monitor. */
    DbgPrint("[gui] WM_CREATE: WNDS_MAXIMIZESTOMONITOR %s\n", wnd && (wnd[5] & 0x40000000) ? "set" : "WRONG");
}

/* A window procedure that refuses WM_NCCREATE. */
static LRESULT __stdcall refusing_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_NCCREATE)
        return 0;
    return DefWindowProcW(window, message, w, l);
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1)) {
        DbgPrint("[gui] RegisterLogonProcess failed (%lu)\n", GetLastError());
        return 0;
    }
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station)) {
        DbgPrint("[gui] no window station (%lu)\n", GetLastError());
        return 0;
    }
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop)) {
        DbgPrint("[gui] no desktop (%lu)\n", GetLastError());
        return 0;
    }
    DbgPrint("[gui] on WinSta0\\Default\n");
    return 1;
}

/* The class again, and user32's Button: GetClassInfoExW (NtUserGetClassInfo)
   and a second registration. */
static void check_classes(HINSTANCE instance, ATOM atom, const WNDCLASSEXW *registered)
{
    WNDCLASSEXW found;
    BOOL got;
    ATOM again;

    memset(&found, 0, sizeof found);
    found.cbSize = sizeof found;
    got = GetClassInfoExW(instance, CLASS_NAME, &found);
    DbgPrint("[gui] GetClassInfoExW: %s\n",
             (ATOM)got == atom && found.lpfnWndProc == registered->lpfnWndProc && found.hInstance == instance
                     && found.hbrBackground == registered->hbrBackground && found.style == registered->style
                 ? "the class as registered"
                 : "WRONG");
    memset(&found, 0, sizeof found);
    found.cbSize = sizeof found;
    got = GetClassInfoExW(0, L"Button", &found);
    DbgPrint("[gui] GetClassInfoExW(Button): %s\n",
             got && found.lpfnWndProc && !(found.style & CS_GLOBALCLASS) ? "user32's class" : "WRONG");
    SetLastError(0);
    got = GetClassInfoExW(instance, L"NoSuchClass", &found);
    DbgPrint("[gui] GetClassInfoExW(NoSuchClass): %d (%lu)\n", got, GetLastError());
    SetLastError(0);
    again = RegisterClassExW(registered);
    DbgPrint("[gui] RegisterClassExW again: %04x (%lu)\n", again, GetLastError());
}

/* What user32 reads of the window by itself (its WND, in the desktop's
   heap), a child window, and windows that cannot be created. */
static void check_window(HWND window, HINSTANCE instance)
{
    WCHAR text[16];
    RECT rect;
    HWND child;
    WNDCLASSEXW refusing;

    DbgPrint("[gui] IsWindow: %d\n", IsWindow(window));
    GetWindowTextW(window, text, 16);
    DbgPrint("[gui] GetWindowTextW: %s\n", same(text, WINDOW_NAME) ? "Mino" : "WRONG");
    print_messages("GetWindowTextW");
    SetWindowTextW(window, L"Mino, longer");
    GetWindowTextW(window, text, 16);
    DbgPrint("[gui] SetWindowTextW, longer: %s\n", same(text, L"Mino, longer") ? "as set" : "WRONG");
    SetWindowTextW(window, L"M");
    GetWindowTextW(window, text, 16);
    DbgPrint("[gui] SetWindowTextW, shorter: %s\n", same(text, L"M") ? "as set" : "WRONG");
    print_messages("SetWindowTextW and GetWindowTextW");
    DbgPrint("[gui] GetWindowLongW(GWL_STYLE): %08lx\n", (DWORD)GetWindowLongW(window, GWL_STYLE));
    GetWindowRect(window, &rect);
    DbgPrint("[gui] GetWindowRect: %ld %ld %ld %ld\n", rect.left, rect.top, rect.right, rect.bottom);

    SetLastError(0);
    child = CreateWindowExW(0, CLASS_NAME, L"Child", WS_CHILD, 10, 20, 100, 50, window, (HMENU)7, instance, 0);
    DbgPrint("[gui] child: %s (%lu)\n", child ? "a window" : "none", GetLastError());
    print_messages("the child and its parent");
    DbgPrint("[gui] WM_PARENTNOTIFY: %s\n", notified_w == (7 << 16 | WM_CREATE) && (HWND)notified_l == child ? "WM_CREATE, 7, the child" : "WRONG");
    DbgPrint("[gui] GetParent: %s\n", GetParent(child) == window ? "the window" : "WRONG");
    DbgPrint("[gui] GetWindow(GW_CHILD): %s\n", GetWindow(window, GW_CHILD) == child ? "the child" : "WRONG");
    GetWindowRect(child, &rect);
    DbgPrint("[gui] child GetWindowRect: %ld %ld %ld %ld\n", rect.left, rect.top, rect.right, rect.bottom);

    SetLastError(0);
    child = CreateWindowExW(0, CLASS_NAME, L"Orphan", WS_CHILD, 0, 0, 10, 10, 0, 0, instance, 0);
    DbgPrint("[gui] child without a parent: %p (%lu)\n", child, GetLastError());
    SetLastError(0);
    child = CreateWindowExW(0, L"NoSuchClass", L"None", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);
    DbgPrint("[gui] window of no class: %p (%lu)\n", child, GetLastError());
    memset(&refusing, 0, sizeof refusing);
    refusing.cbSize = sizeof refusing;
    refusing.lpfnWndProc = refusing_procedure;
    refusing.hInstance = instance;
    refusing.lpszClassName = L"MinoRefusing";
    RegisterClassExW(&refusing);
    child = CreateWindowExW(0, L"MinoRefusing", L"Refused", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);
    DbgPrint("[gui] window refusing WM_NCCREATE: %p\n", child);
}

/* Fills the stack below the caller with ones. user32 sets the length of a
   class name's LARGE_STRING but not its bAnsi bit, which keeps what was on
   its stack: then a one, which win32k must not read as ANSI. */
static void __attribute__((noinline)) dirty_stack(void)
{
    volatile unsigned char ones[3072]; /* under a page: no stack probe */
    unsigned int i;

    for (i = 0; i < sizeof ones; i++)
        ones[i] = 0xFF;
}

/* A sizing popup window with a caption, and its rectangle. */
static void print_sized(HINSTANCE instance, const char *what, int x, int y, int width, int height)
{
    RECT rect;
    HWND window;

    dirty_stack();
    window = CreateWindowExW(0, CLASS_NAME, L"Sized", WS_POPUP | WS_CAPTION | WS_THICKFRAME, x, y, width, height, 0,
                             0, instance, 0);
    if (!window) {
        DbgPrint("[gui] %s: none (%lu)\n", what, GetLastError());
        return;
    }
    GetWindowRect(window, &rect);
    DbgPrint("[gui] %s: %ld %ld %ld %ld\n", what, rect.left, rect.top, rect.right, rect.bottom);
    received_count = 0;
}

/* An overlapped window: WM_GETMINMAXINFO first, the place and size of
   ReactOS without a monitor, its client area without the frame and the
   caption (WM_NCCALCSIZE in DefWindowProc). Then sizing windows, kept
   within the limits WM_GETMINMAXINFO gives. Returns the overlapped window. */
static HWND check_overlapped(HINSTANCE instance)
{
    RECT rect;
    HWND window;

    window = CreateWindowExW(0, CLASS_NAME, L"Overlapped", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, 0,
                             0, instance, 0);
    DbgPrint("[gui] overlapped: %s (%lu)\n", window ? "a window" : "none", GetLastError());
    if (!window)
        return 0;
    print_messages("the overlapped window");
    DbgPrint("[gui] WM_GETMINMAXINFO: maximized %ldx%ld at %ld,%ld, tracking %ldx%ld to %ldx%ld\n",
             limits.ptMaxSize.x, limits.ptMaxSize.y, limits.ptMaxPosition.x, limits.ptMaxPosition.y,
             limits.ptMinTrackSize.x, limits.ptMinTrackSize.y, limits.ptMaxTrackSize.x, limits.ptMaxTrackSize.y);
    GetWindowRect(window, &rect);
    DbgPrint("[gui] overlapped GetWindowRect: %ld %ld %ld %ld\n", rect.left, rect.top, rect.right, rect.bottom);
    GetClientRect(window, &rect);
    DbgPrint("[gui] overlapped GetClientRect: %ld %ld %ld %ld\n", rect.left, rect.top, rect.right, rect.bottom);
    DbgPrint("[gui] DefWindowProcW(WM_USER + 1): %ld\n", DefWindowProcW(window, 0x401, 0, 0));
    /* NCCALCSIZE_PARAMS: valid rectangles; the class has no CS_*REDRAW. */
    {
        struct {
            RECT rgrc[3];
            void *lppos;
        } calc;
        LRESULT result;

        memset(&calc, 0, sizeof calc);
        calc.rgrc[0].left = 100;
        calc.rgrc[0].top = 100;
        calc.rgrc[0].right = 400;
        calc.rgrc[0].bottom = 300;
        result = DefWindowProcW(window, WM_NCCALCSIZE, 1, (LPARAM)&calc);
        DbgPrint("[gui] DefWindowProcW(WM_NCCALCSIZE, TRUE): %lx, %ld %ld %ld %ld\n", result, calc.rgrc[0].left,
                 calc.rgrc[0].top, calc.rgrc[0].right, calc.rgrc[0].bottom);
    }

    print_sized(instance, "sizing, too small", 10, 20, 50, 10);
    print_sized(instance, "sizing, too large", 0, 0, 5000, 5000);
    minimum_width = 300;
    minimum_height = 200;
    print_sized(instance, "sizing, larger minimum", 0, 0, 100, 100);
    minimum_width = 0;
    return window;
}

/* Prints the rectangle of a window. */
static void print_rect(const char *what, HWND window)
{
    RECT rect;

    GetWindowRect(window, &rect);
    DbgPrint("[gui] %s: %ld %ld %ld %ld\n", what, rect.left, rect.top, rect.right, rect.bottom);
}

/* The monitor: MonitorFromWindow, MonitorFromPoint, GetMonitorInfoW. */
static void check_monitor(HWND window)
{
    MONITORINFOEXW info;
    POINT far;
    BOOL got;
    HMONITOR monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONULL);

    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    if (!monitor || !GetMonitorInfoW(monitor, &info)) {
        DbgPrint("[gui] monitor: none (%lu)\n", GetLastError());
        return;
    }
    DbgPrint("[gui] monitor: %ld %ld %ld %ld, work %ld %ld %ld %ld, flags %lu, %s\n", info.rcMonitor.left,
             info.rcMonitor.top, info.rcMonitor.right, info.rcMonitor.bottom, info.rcWork.left, info.rcWork.top,
             info.rcWork.right, info.rcWork.bottom, info.dwFlags,
             same(info.szDevice, L"\\\\.\\DISPLAY1") ? "\\\\.\\DISPLAY1" : "WRONG");
    info.cbSize = 40; /* MONITORINFO */
    info.rcWork.right = 0;
    got = GetMonitorInfoW(monitor, &info);
    DbgPrint("[gui] GetMonitorInfoW, MONITORINFO: %d, work right %ld\n", got, info.rcWork.right);
    info.cbSize = 12;
    SetLastError(0);
    if (GetMonitorInfoW(monitor, &info))
        DbgPrint("[gui] GetMonitorInfoW of 12 bytes: WRONG\n");
    else
        DbgPrint("[gui] GetMonitorInfoW of 12 bytes: refused (%lu)\n", GetLastError());
    far.x = 5000;
    far.y = 5000;
    DbgPrint("[gui] MonitorFromPoint far away: %s, nearest %s\n", MonitorFromPoint(far, MONITOR_DEFAULTTONULL) ? "WRONG" : "none",
             MonitorFromPoint(far, MONITOR_DEFAULTTONEAREST) == monitor ? "the monitor" : "WRONG");
    SetLastError(0);
    monitor = MonitorFromWindow(window, 3);
    DbgPrint("[gui] MonitorFromWindow, bad flags: %p (%lu)\n", monitor, GetLastError());
}

/* SetWindowPos: moving and sizing a window (WM_WINDOWPOSCHANGING, its size
   within WM_GETMINMAXINFO's limits, WM_NCCALCSIZE, WM_WINDOWPOSCHANGED and
   its WM_MOVE and WM_SIZE), MoveWindow, a child moving with its parent. */
static void check_set_window_pos(HWND window, HWND popup)
{
    HWND child = GetWindow(popup, GW_CHILD);
    HWND next;
    BOOL done;

    received_count = 0;
    SetWindowPos(window, 0, 50, 60, 400, 300, SWP_NOZORDER | SWP_NOACTIVATE);
    print_messages("SetWindowPos");
    DbgPrint("[gui] WM_WINDOWPOSCHANGED: %d %d %d %d, flags %04x; WM_MOVE %d %d, WM_SIZE %d %d\n", changed.x,
             changed.y, changed.cx, changed.cy, changed.flags, (short)(moved_l & 0xFFFF), (short)(moved_l >> 16),
             (short)(sized_l & 0xFFFF), (short)(sized_l >> 16));
    print_rect("SetWindowPos", window);
    SetWindowPos(window, 0, 0, 0, 10, 10, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    print_rect("SetWindowPos, too small", window);
    received_count = 0;
    SetWindowPos(window, 0, 70, 80, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    print_messages("SetWindowPos, moved");
    print_rect("SetWindowPos, moved", window);
    next = GetWindow(window, GW_HWNDNEXT);
    MoveWindow(window, 100, 100, 300, 200, 1);
    print_rect("MoveWindow", window);
    DbgPrint("[gui] MoveWindow: same rank %s\n", GetWindow(window, GW_HWNDNEXT) == next ? "yes" : "WRONG");

    SetWindowPos(popup, 0, 200, 150, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    print_rect("the child of a moved window", child);
    received_count = 0;
    SetWindowPos(child, 0, 20, 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    print_messages("SetWindowPos of a child");
    DbgPrint("[gui] child WM_MOVE: %d %d, WINDOWPOS %d %d\n", (short)(moved_l & 0xFFFF), (short)(moved_l >> 16),
             changed.x, changed.y);
    print_rect("SetWindowPos of a child", child);

    SetLastError(0);
    done = SetWindowPos((HWND)0x1234, 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    DbgPrint("[gui] SetWindowPos of no window: %d (%lu)\n", done, GetLastError());
    SetLastError(0);
    done = SetWindowPos(window, (HWND)0x1234, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    DbgPrint("[gui] SetWindowPos after no window: %d (%lu)\n", done, GetLastError());
}

/* What GetClipBox gave of the DC of the last WM_ERASEBKGND, then of the
   same DC once given back, which PatBlt cannot use either (gdi32 finds no
   attributes and asks NtGdiPatBlt). */
static void print_erased(const char *what)
{
    RECT after;
    int region = GetClipBox(erased_dc, &after);
    BOOL painted;
    DWORD error;

    SetLastError(0);
    painted = PatBlt(erased_dc, 0, 0, 10, 10, PATCOPY);
    error = GetLastError();
    DbgPrint("[gui] %s: %s, GetClipBox %d: %ld %ld %ld %ld; after: %d, PatBlt %d (%lu)\n", what,
             ((DWORD)erased_dc & 0x7F0000) == 0x10000 ? "a DC" : "WRONG", erased_region, erased_box.left,
             erased_box.top, erased_box.right, erased_box.bottom, region, painted, error);
}

/* The Z order of two windows, and showing and hiding one. */
static void check_z_order(HINSTANCE instance)
{
    const UINT keep = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
    HWND a = CreateWindowExW(0, CLASS_NAME, L"A", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);
    HWND b = CreateWindowExW(0, CLASS_NAME, L"B", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);

    DbgPrint("[gui] created: B above A %s\n", GetWindow(b, GW_HWNDNEXT) == a ? "yes" : "WRONG");
    received_count = 0;
    SetWindowPos(a, HWND_TOP, 0, 0, 0, 0, keep);
    print_messages("HWND_TOP, hidden");
    DbgPrint("[gui] HWND_TOP: A above B %s\n", GetWindow(a, GW_HWNDNEXT) == b ? "yes" : "WRONG");
    SetWindowPos(a, HWND_BOTTOM, 0, 0, 0, 0, keep);
    DbgPrint("[gui] HWND_BOTTOM: A last %s\n", GetWindow(a, GW_HWNDNEXT) ? "WRONG" : "yes");
    SetWindowPos(a, HWND_TOP, 0, 0, 0, 0, keep);
    SetWindowPos(a, b, 0, 0, 0, 0, keep);
    DbgPrint("[gui] after B: A next to B %s\n", GetWindow(b, GW_HWNDNEXT) == a ? "yes" : "WRONG");
    SetWindowPos(a, HWND_TOPMOST, 0, 0, 0, 0, keep);
    DbgPrint("[gui] HWND_TOPMOST: A first %s, WS_EX_TOPMOST %s\n", GetWindow(b, GW_HWNDFIRST) == a ? "yes" : "WRONG",
             GetWindowLongW(a, GWL_EXSTYLE) & WS_EX_TOPMOST ? "set" : "WRONG");
    SetWindowPos(b, HWND_TOP, 0, 0, 0, 0, keep);
    DbgPrint("[gui] HWND_TOP under a topmost window: B after A %s\n", GetWindow(a, GW_HWNDNEXT) == b ? "yes" : "WRONG");
    SetWindowPos(a, HWND_NOTOPMOST, 0, 0, 0, 0, keep);
    DbgPrint("[gui] HWND_NOTOPMOST: WS_EX_TOPMOST %s, A above B %s\n",
             GetWindowLongW(a, GWL_EXSTYLE) & WS_EX_TOPMOST ? "WRONG" : "clear",
             GetWindow(a, GW_HWNDNEXT) == b ? "yes" : "WRONG");

    received_count = 0;
    SetWindowPos(a, 0, 0, 0, 0, 0, keep | SWP_NOZORDER | SWP_SHOWWINDOW);
    print_messages("SWP_SHOWWINDOW");
    DbgPrint("[gui] SWP_SHOWWINDOW: visible %d\n", IsWindowVisible(a));
    SetWindowPos(a, 0, 0, 0, 0, 0, keep | SWP_NOZORDER | SWP_HIDEWINDOW);
    DbgPrint("[gui] SWP_HIDEWINDOW: visible %d\n", IsWindowVisible(a));
}

/* Another overlapped window placed by default: the next of the cascade. */
static void check_default_place(HINSTANCE instance)
{
    HWND window = CreateWindowExW(0, CLASS_NAME, L"Cascade", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0,
                                  0, 0, instance, 0);
    print_rect("the next default place", window);
    received_count = 0;
}

/* ShowWindow: WM_SHOWWINDOW, SetWindowPos, then the WM_SIZE and WM_MOVE an
   overlapped window waited for; hiding; a child under a hidden parent; a
   command beyond SW_MAX; windows created visible. */
static void check_show_window(HINSTANCE instance, HWND popup)
{
    HWND child = GetWindow(popup, GW_CHILD);
    HWND pending;
    HWND clipper;
    HWND cover;
    HWND window = CreateWindowExW(0, CLASS_NAME, L"Shown", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, 0,
                                  0, instance, 0);
    BOOL was;
    BOOL visible;
    LONG style;

    received_count = 0;
    was = ShowWindow(window, SW_SHOWNORMAL);
    visible = IsWindowVisible(window);
    print_messages("ShowWindow(SW_SHOWNORMAL)");
    DbgPrint("[gui] ShowWindow(SW_SHOWNORMAL): was %d, visible %d, WM_SHOWWINDOW %u, WM_SIZE %d %d, WM_MOVE %d %d\n",
             was, visible, shown_w, (short)(sized_l & 0xFFFF), (short)(sized_l >> 16), (short)(moved_l & 0xFFFF),
             (short)(moved_l >> 16));
    was = ShowWindow(window, SW_SHOW);
    print_messages("ShowWindow(SW_SHOW), visible");
    DbgPrint("[gui] ShowWindow(SW_SHOW), visible: was %d\n", was);
    was = ShowWindow(window, SW_HIDE);
    visible = IsWindowVisible(window);
    print_messages("ShowWindow(SW_HIDE)");
    DbgPrint("[gui] ShowWindow(SW_HIDE): was %d, visible %d, WM_SHOWWINDOW %u\n", was, visible, shown_w);
    was = ShowWindow(window, SW_HIDE);
    print_messages("ShowWindow(SW_HIDE), hidden");
    DbgPrint("[gui] ShowWindow(SW_HIDE), hidden: was %d\n", was);

    was = ShowWindow(child, SW_SHOW);
    style = GetWindowLongW(child, GWL_STYLE);
    visible = IsWindowVisible(child);
    print_messages("ShowWindow of a child of a hidden window");
    DbgPrint("[gui] ShowWindow of a child of a hidden window: was %d, WS_VISIBLE %s, visible %d\n", was,
             style & WS_VISIBLE ? "set" : "clear", visible);

    /* Shown by SetWindowPos: its WM_SIZE and WM_MOVE still wait, through
       hiding, for ShowWindow to show it. */
    window = CreateWindowExW(0, CLASS_NAME, L"Pending", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, 0, 0, instance, 0);
    pending = window;
    SetWindowPos(window, 0, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    received_count = 0;
    ShowWindow(window, SW_HIDE);
    print_messages("ShowWindow(SW_HIDE) before WM_SIZE");
    ShowWindow(window, SW_SHOWNOACTIVATE);
    print_messages("ShowWindow(SW_SHOWNOACTIVATE) at last");

    SetLastError(0);
    was = ShowWindow(window, 12);
    DbgPrint("[gui] ShowWindow(12): %d (%lu)\n", was, GetLastError());
    SetLastError(0);
    was = ShowWindow((HWND)0x1234, SW_SHOW);
    DbgPrint("[gui] ShowWindow of no window: %d (%lu)\n", was, GetLastError());

    received_count = 0;
    window = CreateWindowExW(0, CLASS_NAME, L"Visible", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT,
                             SW_SHOWNOACTIVATE, CW_USEDEFAULT, 0, 0, 0, instance, 0);
    visible_window = window;
    visible = IsWindowVisible(window);
    print_messages("created visible, SW_SHOWNOACTIVATE");
    DbgPrint("[gui] created visible: visible %d, WINDOWPOS flags %04x\n", visible, changed.flags);
    print_rect("created visible", window);
    /* Its client area erased with a DC of the client area, a simple region,
       given back after. */
    print_erased("WM_ERASEBKGND of \"Visible\"");
    /* Its frame painted again under "Visible": clipped by the window above,
       its client area too (an L: a complex region). */
    received_count = 0;
    SetWindowPos(pending, 0, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    print_messages("SWP_FRAMECHANGED under another window");
    print_erased("WM_ERASEBKGND under another window");
    /* A framed child sticking out of its parent's client area: clipped to it.
       The parent clips its children, so the child paints at once. */
    clipper = CreateWindowExW(0, CLASS_NAME, L"Clipper", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VISIBLE, 1050, 100,
                              200, 150, 0, 0, instance, 0);
    clipper_window = clipper;
    CreateWindowExW(0, CLASS_NAME, L"Framed", WS_CHILD | WS_VISIBLE | WS_BORDER, -10, -10, 50, 50, clipper, 0,
                    instance, 0);
    /* Its frame changed, the parent erases its client area again around its
       child, which keeps its border. */
    SetWindowPos(clipper, 0, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    /* Shown over "Visible", then hidden: the desktop does not paint over
       "Visible" (which is not painted again yet). */
    cover = CreateWindowExW(0, CLASS_NAME, L"Cover", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 400, 300, 200, 100, 0, 0,
                            instance, 0);
    ShowWindow(cover, SW_HIDE);
    CreateWindowExW(0, STRIPED_CLASS, L"Striped", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 1050, 300, 200, 100, 0, 0,
                    instance, 0);
    received_count = 0;
    window = CreateWindowExW(0, CLASS_NAME, L"Popup", WS_POPUP | WS_VISIBLE, 10, 10, 50, 50, 0, 0, instance, 0);
    visible = IsWindowVisible(window);
    print_messages("popup created visible");
    DbgPrint("[gui] popup created visible: visible %d, WINDOWPOS flags %04x\n", visible, changed.flags);
    painter = window;
}

/* The windows left to paint get WM_PAINT from the message loop, one after
   the other, until all are validated (DefWindowProc: BeginPaint and
   EndPaint); "Visible", in which "Cover" left its remains, has its frame
   painted again and its background erased. The popup paints itself. */
static void check_paint_messages(void)
{
    MSG message;
    unsigned int paints = 0;
    DWORD before = GetQueueStatus(QS_PAINT);
    DWORD after;
    HWND painted_windows[16];
    char names[160];
    char *at = names;
    unsigned int i;

    /* WM_PAINT goes to the first window to paint (the popup, on top), for a
       filter that asks for it, its window or a parent of it. */
    BOOL popup = PeekMessageW(&message, painter, 0, 0, PM_NOREMOVE) && message.hwnd == painter;
    BOOL other = PeekMessageW(&message, clipper_window, 0, 0, PM_NOREMOVE);
    BOOL thread = PeekMessageW(&message, (HWND)-1, 0, 0, PM_NOREMOVE);
    BOOL above = PeekMessageW(&message, 0, WM_PAINT + 1, 0x400, PM_NOREMOVE);
    BOOL range = PeekMessageW(&message, 0, WM_PAINT, WM_PAINT, PM_NOREMOVE) && message.message == WM_PAINT;

    DbgPrint("[gui] PeekMessage of WM_PAINT: the popup %d, another window %d, the thread %d, above %d, WM_PAINT %d\n",
             popup, other, thread, above, range);
    received_count = 0;
    while (paints < 16 && PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
        if (message.message == WM_PAINT)
            painted_windows[paints++] = message.hwnd;
        DispatchMessageW(&message);
    }
    after = GetQueueStatus(QS_PAINT);
    print_messages("the message loop");
    /* Their names, in ASCII, once the messages are printed. */
    for (i = 0; i < paints; i++) {
        WCHAR name[16];
        int j, length = GetWindowTextW(painted_windows[i], name, 16);
        for (j = 0; j < length && at < names + sizeof names - 2; j++)
            *at++ = (char)name[j];
        *at++ = ' ';
    }
    *at = 0;
    DbgPrint("[gui] WM_PAINT %u times: %s; GetQueueStatus(QS_PAINT) %08lx, then %08lx\n", paints, names, before,
             after);
    SetLastError(0);
    i = PatBlt(painted.hdc, 0, 0, 1, 1, BLACKNESS);
    DbgPrint("[gui] BeginPaint of the popup: %s, fErase %d, rcPaint %ld %ld %ld %ld; after EndPaint, PatBlt %u (%lu)\n",
             ((DWORD)painted.hdc & 0x7F0000) == 0x10000 ? "a DC" : "WRONG", painted.fErase, painted.rcPaint.left,
             painted.rcPaint.top, painted.rcPaint.right, painted.rcPaint.bottom, i, GetLastError());
}

static void set_rect(RECT *rect, LONG left, LONG top, LONG right, LONG bottom)
{
    rect->left = left;
    rect->top = top;
    rect->right = right;
    rect->bottom = bottom;
}

/* QS_PAINT among the kinds of messages in the queue. */
static int paint_pending(void)
{
    return (GetQueueStatus(QS_PAINT) >> 16 & QS_PAINT) != 0;
}

/* InvalidateRect, ValidateRect and GetUpdateRect on an update region of
   two pieces; UpdateWindow; RedrawWindow and its flags. */
static void check_redraw(void)
{
    RECT r, update;
    BOOL got, other;
    int pending;
    HWND framed = GetWindow(clipper_window, GW_CHILD);
    HWND hidden;
    HWND plain;
    MSG message;

    set_rect(&r, 10, 10, 20, 20);
    InvalidateRect(visible_window, &r, FALSE);
    set_rect(&r, 100, 50, 120, 60);
    InvalidateRect(visible_window, &r, FALSE);
    got = GetUpdateRect(visible_window, &update, FALSE);
    DbgPrint("[gui] InvalidateRect twice: %d %ld %ld %ld %ld\n", got, update.left, update.top, update.right,
             update.bottom);
    set_rect(&r, 10, 10, 20, 20);
    ValidateRect(visible_window, &r);
    got = GetUpdateRect(visible_window, &update, FALSE);
    DbgPrint("[gui] ValidateRect of one piece: %d %ld %ld %ld %ld\n", got, update.left, update.top, update.right,
             update.bottom);
    set_rect(&r, 100, 50, 120, 60);
    ValidateRect(visible_window, &r);
    got = GetUpdateRect(visible_window, &update, FALSE);
    pending = paint_pending();
    DbgPrint("[gui] ValidateRect of the other: %d %ld %ld %ld %ld, QS_PAINT %d\n", got, update.left, update.top,
             update.right, update.bottom, pending);

    /* WM_PAINT at once: the popup erased, its square further right. */
    InvalidateRect(painter, 0, TRUE);
    received_count = 0;
    UpdateWindow(painter);
    print_messages("UpdateWindow");
    got = GetUpdateRect(painter, &update, FALSE);
    DbgPrint("[gui] UpdateWindow, then: %d\n", got);

    /* The background of a part of the popup erased at once; still to paint
       until validated. */
    set_rect(&r, 12, 0, 17, 5);
    received_count = 0;
    RedrawWindow(painter, &r, 0, RDW_INVALIDATE | RDW_ERASE | RDW_ERASENOW);
    print_messages("RDW_ERASENOW");
    got = GetUpdateRect(painter, &update, FALSE);
    pending = paint_pending();
    DbgPrint("[gui] RDW_ERASENOW: %d %ld %ld %ld %ld, QS_PAINT %d\n", got, update.left, update.top, update.right,
             update.bottom, pending);
    /* GetUpdateRect erasing first: the corner again. */
    InvalidateRect(painter, &r, TRUE);
    received_count = 0;
    got = GetUpdateRect(painter, &update, TRUE);
    print_messages("GetUpdateRect(TRUE)");
    ValidateRect(painter, 0);
    other = GetUpdateRect(painter, &update, FALSE);
    DbgPrint("[gui] GetUpdateRect(TRUE): %d; ValidateRect of the popup: %d\n", got, other);

    /* Nothing for a window never shown. */
    hidden = CreateWindowExW(0, CLASS_NAME, L"Hidden", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, 0, 0,
                             GetModuleHandleW(0), 0);
    got = RedrawWindow(hidden, 0, 0, RDW_INVALIDATE | RDW_ERASE);
    other = GetUpdateRect(hidden, &update, FALSE);
    DbgPrint("[gui] RedrawWindow of a hidden window: %d, update %d\n", got, other);

    /* WM_PAINT at once, in which BeginPaint paints the frame and erases. */
    received_count = 0;
    RedrawWindow(visible_window, 0, 0, RDW_INVALIDATE | RDW_FRAME | RDW_ERASE | RDW_UPDATENOW);
    print_messages("RDW_UPDATENOW");
    got = GetUpdateRect(visible_window, &update, FALSE);
    DbgPrint("[gui] RDW_UPDATENOW, then: %d\n", got);

    /* WM_PAINT with nothing to update. */
    RedrawWindow(visible_window, 0, 0, RDW_INTERNALPAINT);
    got = GetUpdateRect(visible_window, &update, FALSE);
    pending = paint_pending();
    other = PeekMessageW(&message, visible_window, WM_PAINT, WM_PAINT, PM_REMOVE);
    if (other)
        DispatchMessageW(&message);
    DbgPrint("[gui] RDW_INTERNALPAINT: update %d, QS_PAINT %d, WM_PAINT %d, then QS_PAINT %d\n", got, pending, other,
             paint_pending());

    /* A parent clipping its children invalidates them with RDW_ALLCHILDREN
       only; UpdateWindow paints it, then its child. */
    RedrawWindow(clipper_window, 0, 0, RDW_INVALIDATE | RDW_ERASE);
    got = GetUpdateRect(framed, &update, FALSE);
    RedrawWindow(clipper_window, 0, 0, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
    other = GetUpdateRect(framed, &update, FALSE);
    received_count = 0;
    UpdateWindow(clipper_window);
    print_messages("UpdateWindow of a parent");
    pending = GetUpdateRect(clipper_window, &update, FALSE) || GetUpdateRect(framed, &update, FALSE);
    DbgPrint("[gui] RDW_ALLCHILDREN: the child %d, then %d; after UpdateWindow %d\n", got, other, pending);

    SetLastError(0);
    got = RedrawWindow(visible_window, 0, 0, 0x10000);
    DbgPrint("[gui] RedrawWindow, unknown flag: %d (%lu)\n", got, GetLastError());

    /* InvalidateRect without erasing: WM_PAINT does not erase; validated,
       a background to erase is not erased either. */
    set_rect(&r, 10, 10, 20, 20);
    InvalidateRect(visible_window, &r, FALSE);
    received_count = 0;
    UpdateWindow(visible_window);
    print_messages("UpdateWindow without erasing");
    InvalidateRect(visible_window, &r, TRUE);
    ValidateRect(visible_window, 0);
    received_count = 0;
    RedrawWindow(visible_window, 0, 0, RDW_INTERNALPAINT | RDW_UPDATENOW);
    print_messages("RDW_INTERNALPAINT after ValidateRect");

    /* A parent that does not clip its children invalidates them; its child
       painted at once leaves the rest of the parent to paint (here, below
       it). A procedure that does not call BeginPaint gets its frame and
       background painted all the same, and stays to paint. */
    plain = CreateWindowExW(0, CLASS_NAME, L"Plain", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 1050, 450, 200, 100, 0, 0,
                            GetModuleHandleW(0), 0);
    lazy_window = CreateWindowExW(0, CLASS_NAME, L"Lazy", WS_CHILD | WS_VISIBLE, 0, 0, 192, 20, plain, 0,
                                  GetModuleHandleW(0), 0);
    RedrawWindow(plain, 0, 0, RDW_INVALIDATE | RDW_ERASE);
    received_count = 0;
    UpdateWindow(lazy_window);
    print_messages("UpdateWindow of a child that does not paint");
    got = GetUpdateRect(lazy_window, &update, FALSE);
    other = GetUpdateRect(plain, &update, FALSE);
    DbgPrint("[gui] the child still to paint %d; its parent %d %ld %ld %ld %ld\n", got, other, update.left, update.top,
             update.right, update.bottom);
}

/* GetRgnBox of a region, printed after `what`. */
static void print_region(const char *what, int result, HRGN region)
{
    RECT box;
    int complexity = GetRgnBox(region, &box);
    DbgPrint("[gui] %s: %d, box %d: %ld %ld %ld %ld\n", what, result, complexity, box.left, box.top, box.right,
             box.bottom);
}

/* GetClipBox of a DC, in `box`; its complexity. */
static int clip_box(HDC dc, RECT *box)
{
    set_rect(box, -1, -1, -1, -1);
    return GetClipBox(dc, box);
}

/* Regions of GDI, which gdi32 changes itself when they stay rectangles;
   the DCs of GetDC, GetWindowDC and GetDCEx, cut by a region, and by a
   clip region; InvalidateRgn, ValidateRgn and GetUpdateRgn. */
static void check_dc_and_regions(void)
{
    HWND window = CreateWindowExW(0, CLASS_NAME, L"Regions", WS_POPUP | WS_VISIBLE, 1050, 600, 200, 150, 0, 0,
                                  GetModuleHandleW(0), 0);
    HWND plain = GetParent(lazy_window);
    HRGN first = CreateRectRgn(100, 100, 0, 0);
    HRGN second = CreateRectRgn(50, 50, 150, 150);
    HRGN result = CreateRectRgn(0, 0, 0, 0);
    HRGN clip, other, gone;
    HDC dc;
    RECT box;
    int complexity, again, released, twice;
    DWORD type;

    ValidateRect(window, 0);
    print_region("CreateRectRgn, corners swapped", 0, first);
    print_region("CombineRgn(RGN_OR)", CombineRgn(result, first, second, RGN_OR), result);
    print_region("CombineRgn(RGN_AND), in gdi32", CombineRgn(result, first, second, RGN_AND), result);
    print_region("CombineRgn(RGN_DIFF)", CombineRgn(result, first, second, RGN_DIFF), result);
    /* Changed by gdi32 alone, then taken back by the kernel. */
    SetRectRgn(first, 10, 10, 20, 20);
    print_region("SetRectRgn, then RGN_OR", CombineRgn(result, first, second, RGN_OR), result);
    SetLastError(0);
    complexity = CombineRgn(result, first, 0, RGN_OR);
    DbgPrint("[gui] CombineRgn without a second region: %d (%lu)\n", complexity, GetLastError());

    /* DeleteObject, queued in the TEB: the entry goes back, then serves
       again with one more reuse. */
    DeleteObject(result);
    GdiFlush();
    type = GetObjectType(result);
    complexity = GetRgnBox(result, &box);
    gone = result;
    result = CreateRectRgn(0, 0, 0, 0);
    DbgPrint("[gui] DeleteObject: GetObjectType %lu, GetRgnBox %d; a new region in its entry %s, GetObjectType %lu\n",
             type, complexity,
             ((DWORD)result & 0xFFFF) == ((DWORD)gone & 0xFFFF) && result != gone ? "reused" : "WRONG",
             GetObjectType(result));

    /* A DC of the client area: black in its top left corner. */
    dc = GetDC(window);
    complexity = clip_box(dc, &box);
    PatBlt(dc, 0, 0, 20, 20, BLACKNESS);
    released = ReleaseDC(window, dc);
    twice = ReleaseDC(window, dc);
    SetLastError(0);
    again = PatBlt(dc, 0, 0, 20, 20, BLACKNESS);
    DbgPrint("[gui] GetDC: clip %d: %ld %ld %ld %ld; ReleaseDC %d, again %d; PatBlt after %d (%lu)\n", complexity,
             box.left, box.top, box.right, box.bottom, released, twice, again, GetLastError());
    /* DeleteDC gives a window DC back, once. */
    dc = GetDC(window);
    released = DeleteDC(dc);
    twice = ReleaseDC(window, dc);
    SetLastError(0);
    again = DeleteDC(dc);
    DbgPrint("[gui] DeleteDC of a window DC: %d, then ReleaseDC %d, DeleteDC %d (%lu)\n", released, twice, again,
             GetLastError());

    /* The whole window, its frame included: its top left corner black. */
    dc = GetWindowDC(plain);
    complexity = clip_box(dc, &box);
    PatBlt(dc, 0, 0, 4, 4, BLACKNESS);
    ReleaseDC(plain, dc);
    DbgPrint("[gui] GetWindowDC: clip %d: %ld %ld %ld %ld\n", complexity, box.left, box.top, box.right, box.bottom);

    /* The whole screen, over every window. */
    dc = GetDC(0);
    complexity = clip_box(dc, &box);
    PatBlt(dc, 1260, 780, 5, 5, BLACKNESS);
    ReleaseDC(0, dc);
    DbgPrint("[gui] GetDC(NULL): clip %d: %ld %ld %ld %ld\n", complexity, box.left, box.top, box.right, box.bottom);

    /* Cut by a region on the screen, which the DC deletes when given back;
       or keeps, without it. */
    clip = CreateRectRgn(1100, 650, 1120, 670);
    dc = GetDCEx(window, clip, DCX_INTERSECTRGN);
    complexity = clip_box(dc, &box);
    PatBlt(dc, 0, 0, 200, 150, BLACKNESS);
    ReleaseDC(window, dc);
    DbgPrint("[gui] GetDCEx(DCX_INTERSECTRGN): clip %d: %ld %ld %ld %ld; the region after ReleaseDC %lu\n",
             complexity, box.left, box.top, box.right, box.bottom, GetObjectType(clip));
    clip = CreateRectRgn(1060, 610, 1250, 750);
    dc = GetDCEx(window, clip, DCX_EXCLUDERGN | DCX_KEEPCLIPRGN);
    complexity = clip_box(dc, &box);
    ReleaseDC(window, dc);
    DbgPrint("[gui] GetDCEx(DCX_EXCLUDERGN, DCX_KEEPCLIPRGN): clip %d: %ld %ld %ld %ld; the region after "
             "ReleaseDC %lu\n",
             complexity, box.left, box.top, box.right, box.bottom, GetObjectType(clip));
    DeleteObject(clip);

    /* A clip region from the DC's origin, selected in the TEB's batch: only
       its square gets black; combined in the kernel; outside the window;
       none. */
    dc = GetDC(window);
    clip = CreateRectRgn(120, 0, 140, 20);
    other = CreateRectRgn(150, 0, 160, 10);
    complexity = SelectClipRgn(dc, clip);
    again = clip_box(dc, &box);
    DbgPrint("[gui] SelectClipRgn: %d, GetClipBox %d: %ld %ld %ld %ld\n", complexity, again, box.left, box.top,
             box.right, box.bottom);
    PatBlt(dc, 0, 0, 200, 150, BLACKNESS);
    complexity = ExtSelectClipRgn(dc, other, RGN_OR);
    SetRectRgn(other, 300, 300, 400, 400);
    again = SelectClipRgn(dc, other);
    released = SelectClipRgn(dc, 0);
    twice = clip_box(dc, &box);
    DbgPrint("[gui] ExtSelectClipRgn(RGN_OR): %d; outside: %d; none: %d, GetClipBox %d: %ld %ld %ld %ld\n",
             complexity, again, released, twice, box.left, box.top, box.right, box.bottom);
    ReleaseDC(window, dc);

    /* The update region: two pieces, one validated, then none. */
    SetRectRgn(first, 10, 10, 30, 30);
    SetRectRgn(second, 50, 50, 60, 60);
    InvalidateRgn(window, first, FALSE);
    InvalidateRgn(window, second, FALSE);
    print_region("InvalidateRgn twice, GetUpdateRgn", GetUpdateRgn(window, result, FALSE), result);
    ValidateRgn(window, first);
    print_region("ValidateRgn of one, GetUpdateRgn", GetUpdateRgn(window, result, FALSE), result);
    ValidateRgn(window, 0);
    print_region("ValidateRgn(NULL), GetUpdateRgn", GetUpdateRgn(window, result, FALSE), result);
    SetLastError(0);
    complexity = InvalidateRgn(0, first, FALSE);
    DbgPrint("[gui] InvalidateRgn(NULL): %d (%lu)\n", complexity, GetLastError());
    /* Without erasing: WM_PAINT alone. */
    InvalidateRgn(window, second, FALSE);
    received_count = 0;
    UpdateWindow(window);
    print_messages("UpdateWindow after InvalidateRgn(FALSE)");
    /* Its background erased at once in a region: the black corner cut. */
    received_count = 0;
    RedrawWindow(window, 0, first, RDW_INVALIDATE | RDW_ERASE | RDW_ERASENOW);
    print_messages("RedrawWindow of a region");
    print_region("then GetUpdateRgn", GetUpdateRgn(window, result, FALSE), result);
    ValidateRgn(window, 0);
    /* Only the caption to paint: user32 asks the kernel (WNDS_SENDNCPAINT),
       which empties the region. */
    ValidateRect(plain, 0);
    set_rect(&box, -4, -20, 10, -10);
    RedrawWindow(plain, &box, 0, RDW_INVALIDATE | RDW_FRAME);
    print_region("only the frame to paint, GetUpdateRgn", GetUpdateRgn(plain, result, FALSE), result);
    DeleteObject(first);
    DeleteObject(second);
    DeleteObject(result);
    DeleteObject(clip);
    DeleteObject(other);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    ATOM atom;
    HWND window;
    HWND overlapped;

    if (!take_a_desktop())
        ExitProcess(1);
    /* SM_CXSCREEN, SM_CYSCREEN, SM_CYCAPTION, SM_CXFRAME, SM_CXMINTRACK;
       COLOR_BACKGROUND, COLOR_WINDOW, COLOR_BTNFACE. */
    DbgPrint("[gui] GetSystemMetrics: screen %dx%d, caption %d, frame %d, minimum width %d\n", GetSystemMetrics(0),
             GetSystemMetrics(1), GetSystemMetrics(4), GetSystemMetrics(32), GetSystemMetrics(34));
    DbgPrint("[gui] GetSysColor: %06lx %06lx %06lx\n", GetSysColor(1), GetSysColor(5), GetSysColor(15));
    /* A stock brush, public in the GDI handle table that gdi32 reads; an
       entry never given out, nothing. */
    DbgPrint("[gui] GetSysColorBrush(COLOR_WINDOW): %s, GetObjectType %lu; of no brush %lu\n",
             ((DWORD)GetSysColorBrush(COLOR_WINDOW) >> 16) == 0x90 ? "a stock brush" : "WRONG",
             GetObjectType(GetSysColorBrush(COLOR_WINDOW)), GetObjectType((HGDIOBJ)0x00100FFF));

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = window_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    atom = RegisterClassExW(&class_info);
    DbgPrint("[gui] RegisterClassExW: atom %04x (%lu)\n", atom, atom ? 0 : GetLastError());
    if (!atom)
        ExitProcess(2);
    check_classes(instance, atom, &class_info);
    class_info.lpfnWndProc = striped_procedure;
    class_info.hbrBackground = (HBRUSH)(COLOR_HIGHLIGHT + 1);
    class_info.lpszClassName = STRIPED_CLASS;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);

    SetLastError(0);
    window = CreateWindowExW(0, CLASS_NAME, WINDOW_NAME, WS_POPUP, 100, 50, 400, 300, 0, 0, instance,
                             CREATE_PARAMETER);
    DbgPrint("[gui] CreateWindowExW: %s (%lu)\n", window ? "a window" : "none", GetLastError());
    if (!window)
        ExitProcess(3);
    print_messages("the window");
    check_window(window, instance);
    overlapped = check_overlapped(instance);
    if (overlapped) {
        check_monitor(overlapped);
        check_default_place(instance);
        check_set_window_pos(overlapped, window);
    }
    check_z_order(instance);
    check_show_window(instance, window);
    check_paint_messages();
    check_redraw();
    check_dc_and_regions();

    DbgPrint("[gui] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
