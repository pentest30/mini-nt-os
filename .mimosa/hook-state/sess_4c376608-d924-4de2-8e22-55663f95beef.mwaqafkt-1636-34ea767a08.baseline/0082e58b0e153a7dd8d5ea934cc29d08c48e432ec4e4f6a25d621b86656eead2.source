/*
 * Windows and the mouse: a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `mouse-windows` puts on the boot disk in the place of winlogon.exe (like
 * mouse1.c). It opens two framed windows (WS_OVERLAPPEDWINDOW) that overlap,
 * A then B, of two classes with two backgrounds (COLOR_WINDOW for A,
 * COLOR_BTNFACE for B), and logs what the mouse does to them:
 * - a press in A's client area, A not active: WM_MOUSEACTIVATE, A activated
 *   and brought to the front (WM_ACTIVATE, GetActiveWindow, GetFocus), then
 *   WM_LBUTTONDOWN; A takes the capture (SetCapture, GetCapture);
 * - with the capture, a move far outside A still comes to A, in A's client
 *   coordinates; the release too (WM_LBUTTONUP), where A gives the capture
 *   back (ReleaseCapture: WM_CAPTURECHANGED) and reads the cursor
 *   (GetCursorPos);
 * - a drag of B's caption: WM_NCHITTEST says HTCAPTION, WM_NCLBUTTONDOWN
 *   (DefWindowProc activates B, brings it in front of A and moves it with
 *   the mouse until the release: WM_EXITSIZEMOVE, where B logs its place);
 * - a drag of A's bottom right corner (HTBOTTOMRIGHT) sizes A;
 * - a second thread opens window C and a click activates it: that thread
 *   takes the foreground; a click in A, still the main thread's active
 *   window, brings the main thread back (WM_MOUSEACTIVATE again);
 * - a click queued while the main thread sleeps is no double-click:
 *   PeekMessage for WM_LBUTTONDBLCLK leaves it, PeekMessage for
 *   WM_LBUTTONDOWN takes it;
 * - a click on B's close button (HTCLOSE): WM_SYSCOMMAND SC_CLOSE, then
 *   WM_CLOSE, which ends the program with EXIT_STATUS.
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
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

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
#define WM_ACTIVATE 0x0006
#define WM_CLOSE 0x0010
#define WM_EXITSIZEMOVE 0x0232
#define WM_MOUSEMOVE 0x0200
#define WM_LBUTTONDOWN 0x0201
#define WM_LBUTTONUP 0x0202
#define WM_LBUTTONDBLCLK 0x0203
#define WM_MOUSEACTIVATE 0x0021
#define PM_REMOVE 0x0001
#define WM_MOUSEWHEEL 0x020A
#define WM_CAPTURECHANGED 0x0215
#define WM_NCLBUTTONDOWN 0x00A1
#define WM_NCLBUTTONUP 0x00A2
#define COLOR_WINDOW 5
#define COLOR_BTNFACE 15
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x600F

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

typedef DWORD(__stdcall *THREAD_START)(void *);
typedef void *HANDLE;
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);

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
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HWND __stdcall GetActiveWindow(void);
__declspec(dllimport) HWND __stdcall GetCapture(void);
__declspec(dllimport) BOOL __stdcall GetCursorPos(POINT *point);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall ReleaseCapture(void);
__declspec(dllimport) HWND __stdcall SetCapture(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

static HWND window_a;
static HWND window_b;
static HWND window_c;
static HDESK desktop;
static volatile int c_ready;
/* WM_MOUSEACTIVATE received by A, B and C. */
static int mouse_activations[3];
/* The filtered PeekMessage test: armed by A's third activation, run after
 * the following release. */
static int filter_test;

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

/* A, B, none or other: which of the two windows `window` is. */
static const char *name_of(HWND window)
{
    if (!window)
        return "none";
    if (window == window_a)
        return "A";
    if (window == window_b)
        return "B";
    if (window == window_c)
        return "C";
    return "other";
}

/* The point of a mouse message: signed 16-bit halves of lParam. */
static int x_of(LPARAM l)
{
    return (short)(l & 0xFFFF);
}

static int y_of(LPARAM l)
{
    return (short)((l >> 16) & 0xFFFF);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    const char *name = name_of(window);
    POINT cursor;
    RECT rect;

    switch (message) {
    case WM_ACTIVATE: {
        /* DefWindowProc gives the activated window the keyboard (SetFocus):
         * GetFocus says so after it. */
        LRESULT result = DefWindowProcW(window, message, w, l);
        if (w & 0xFFFF)
            DbgPrint("[mouse2] %s activated: active %s, focus %s\n", name, name_of(GetActiveWindow()),
                     name_of(GetFocus()));
        return result;
    }
    case WM_LBUTTONDOWN:
        DbgPrint("[mouse2] %s ldown %d,%d\n", name, x_of(l), y_of(l));
        if (window == window_a) {
            SetCapture(window);
            DbgPrint("[mouse2] capture %s\n", name_of(GetCapture()));
        }
        return 0;
    case WM_MOUSEMOVE:
        if (GetCapture() == window)
            DbgPrint("[mouse2] %s captured move %d,%d\n", name, x_of(l), y_of(l));
        return 0;
    case WM_LBUTTONUP:
        if (GetCapture() == window)
            ReleaseCapture();
        if (!GetCursorPos(&cursor))
            cursor.x = cursor.y = -1;
        DbgPrint("[mouse2] %s lup %d,%d; cursor %ld,%ld; capture %s\n", name, x_of(l), y_of(l), cursor.x, cursor.y,
                 name_of(GetCapture()));
        return 0;
    case WM_CAPTURECHANGED:
        DbgPrint("[mouse2] %s capture changed to %s\n", name, name_of((HWND)l));
        return 0;
    case WM_NCLBUTTONDOWN:
        DbgPrint("[mouse2] %s ncldown hit %d\n", name, (int)w);
        break;
    case WM_NCLBUTTONUP:
        DbgPrint("[mouse2] %s nclup hit %d\n", name, (int)w);
        break;
    case WM_MOUSEACTIVATE: {
        int index = window == window_a ? 0 : window == window_b ? 1 : 2;
        DbgPrint("[mouse2] %s mouse-activate #%d\n", name, ++mouse_activations[index]);
        if (window == window_a && mouse_activations[0] == 3)
            filter_test = 1;
        break;
    }
    case WM_EXITSIZEMOVE:
        GetWindowRect(window, &rect);
        DbgPrint("[mouse2] %s moved or sized: %ld,%ld %ldx%ld\n", name, rect.left, rect.top, rect.right - rect.left,
                 rect.bottom - rect.top);
        break;
    case WM_CLOSE:
        DbgPrint("[mouse2] %s close\n", name);
        PostQuitMessage(0);
        return 0;
    case WM_MOUSEWHEEL:
        DbgPrint("[mouse2] wheel at %s\n", name);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

/* The second thread: window C, on the same desktop, and its messages. */
static DWORD __stdcall thread_c(void *parameter)
{
    MSG message;

    (void)parameter;
    if (!SetThreadDesktop(desktop))
        DbgPrint("[mouse2] C has no desktop\n");
    window_c = CreateWindowExW(0, L"MinoMouseC", L"C", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 850, 100, 300, 200, 0, 0,
                               GetModuleHandleW(0), 0);
    UpdateWindow(window_c);
    c_ready = 1;
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return 0;
}

/* A click queued while the thread sleeps: a plain WM_LBUTTONDOWN, so a
 * filter for WM_LBUTTONDBLCLK must leave it in the queue. */
static void filtered_peek(void)
{
    MSG message;
    BOOL dblclk, down;

    DbgPrint("[mouse2] waiting for a click\n");
    Sleep(1500);
    dblclk = PeekMessageW(&message, 0, WM_LBUTTONDBLCLK, WM_LBUTTONDBLCLK, PM_REMOVE);
    down = PeekMessageW(&message, 0, WM_LBUTTONDOWN, WM_LBUTTONDOWN, PM_REMOVE);
    DbgPrint("[mouse2] filtered peek: dblclk %d, down %d at %s\n", dblclk, down,
             down ? name_of(message.hwnd) : "none");
}

static BOOL register_class(const WCHAR *name, int background)
{
    WNDCLASSEXW class_info;

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = (HBRUSH)(background + 1);
    class_info.lpszClassName = name;
    return RegisterClassExW(&class_info) != 0;
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    if (!register_class(L"MinoMouseA", COLOR_WINDOW) || !register_class(L"MinoMouseB", COLOR_BTNFACE) ||
        !register_class(L"MinoMouseC", COLOR_WINDOW))
        ExitProcess(2);
    window_a = CreateWindowExW(0, L"MinoMouseA", L"A", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0,
                               instance, 0);
    window_b = CreateWindowExW(0, L"MinoMouseB", L"B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 300, 250, 400, 300, 0, 0,
                               instance, 0);
    if (!window_a || !window_b)
        ExitProcess(3);
    UpdateWindow(window_a);
    UpdateWindow(window_b);
    {
        DWORD id;
        if (!CreateThread(0, 0, thread_c, 0, 0, &id))
            ExitProcess(4);
        while (!c_ready)
            Sleep(10);
    }
    DbgPrint("[mouse2] ready: active %s\n", name_of(GetActiveWindow()));
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
        if (filter_test == 1 && message.message == WM_LBUTTONUP) {
            filter_test = 2;
            filtered_peek();
        }
    }
    DbgPrint("[mouse2] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
