/*
 * M6, windows: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32. The scenario `gui` puts it on the
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
 * ShowWindow shows and hides them.
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
#define MONITOR_DEFAULTTONULL 0
#define MONITOR_DEFAULTTONEAREST 2
#define WM_MOVE 0x0003
#define WM_SIZE 0x0005
#define WM_WINDOWPOSCHANGED 0x0047
#define WM_SHOWWINDOW 0x0018
#define WS_VISIBLE 0x10000000
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
#define WM_CREATE 0x0001
#define WM_GETMINMAXINFO 0x0024
#define WM_NCCALCSIZE 0x0083
#define WM_NCCREATE 0x0081

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
    if (message == WM_GETMINMAXINFO) {
        MINMAXINFO *info = (MINMAXINFO *)l;
        limits = *info;
        if (minimum_width) {
            info->ptMinTrackSize.x = minimum_width;
            info->ptMinTrackSize.y = minimum_height;
            return 0;
        }
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
    visible = IsWindowVisible(window);
    print_messages("created visible, SW_SHOWNOACTIVATE");
    DbgPrint("[gui] created visible: visible %d, WINDOWPOS flags %04x\n", visible, changed.flags);
    print_rect("created visible", window);
    received_count = 0;
    window = CreateWindowExW(0, CLASS_NAME, L"Popup", WS_POPUP | WS_VISIBLE, 10, 10, 50, 50, 0, 0, instance, 0);
    visible = IsWindowVisible(window);
    print_messages("popup created visible");
    DbgPrint("[gui] popup created visible: visible %d, WINDOWPOS flags %04x\n", visible, changed.flags);
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

    DbgPrint("[gui] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
