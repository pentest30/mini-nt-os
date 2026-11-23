/*
 * EnumDisplayMonitors: a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `enum-monitors` puts on the boot disk in the place of winlogon.exe. GIMP
 * 2.6 (GTK2's gdk) ended on a read of 0xC right after
 * NtUserEnumDisplayMonitors, which had no handler: user32 counted no monitor
 * and called back nothing. The program takes a desktop like winlogon, shows a
 * popup, then:
 * 1. EnumDisplayMonitors(NULL, NULL): one call back, with the primary monitor
 *    (MonitorFromPoint), the whole screen (SM_CXSCREEN, SM_CYSCREEN), no DC,
 *    and the program's data; SM_CMONITORS is 1;
 * 2. with a clipping rectangle on the screen: the rectangle itself;
 * 3. with one off the screen: no call back, and TRUE;
 * 4. with the popup's DC and no rectangle: the DC given back, the part of
 *    the screen it paints, from its corner (0, 0 to the client's size);
 * 5. a call back that answers FALSE: EnumDisplayMonitors answers FALSE.
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
typedef void *HWND;
typedef void *HDC;
typedef void *HMONITOR;
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
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

typedef struct {
    LONG x;
    LONG y;
} POINT;

typedef BOOL(__stdcall *MONITORENUMPROC)(HMONITOR, HDC, RECT *, LPARAM);

typedef struct {
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
} WNDCLASSW;

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define MAXIMUM_ALLOWED 0x02000000
#define COLOR_WINDOW 5
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define SM_CMONITORS 80
#define MONITOR_DEFAULTTOPRIMARY 1

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
__declspec(dllimport) BOOL __stdcall EnumDisplayMonitors(HDC hdc, const RECT *clip, MONITORENUMPROC procedure,
                                                         LPARAM data);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) HMONITOR __stdcall MonitorFromPoint(POINT point, DWORD flags);
__declspec(dllimport) ATOM __stdcall RegisterClassW(const WNDCLASSW *info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC hdc);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

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

/* What the call backs saw. */
static int calls;
static HMONITOR seen_monitor;
static HDC seen_dc;
static RECT seen_rect;
static LPARAM seen_data;
static BOOL answer = 1;

static BOOL __stdcall seen(HMONITOR monitor, HDC hdc, RECT *rect, LPARAM data)
{
    calls++;
    seen_monitor = monitor;
    seen_dc = hdc;
    seen_rect = *rect;
    seen_data = data;
    return answer;
}

static int same_rect(const RECT *a, LONG left, LONG top, LONG right, LONG bottom)
{
    return a->left == left && a->top == top && a->right == right && a->bottom == bottom;
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSW class_info;
    HWND popup;
    HDC hdc;
    RECT clip, client;
    POINT origin = {0, 0};
    HMONITOR primary;
    BOOL done;
    int width = GetSystemMetrics(SM_CXSCREEN), height = GetSystemMetrics(SM_CYSCREEN);

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoMonitors";
    if (!RegisterClassW(&class_info))
        ExitProcess(2);
    popup = CreateWindowExW(0, L"MinoMonitors", L"M", WS_POPUP | WS_VISIBLE, 100, 50, 300, 200, 0, 0, instance, 0);
    primary = MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY);
    DbgPrint("[enummon] ready: the popup %d, the primary monitor %d, SM_CMONITORS %d\n", popup != 0, primary != 0,
             GetSystemMetrics(SM_CMONITORS));
    if (!popup || !primary)
        ExitProcess(3);

    /* 1. Everything. */
    calls = 0;
    done = EnumDisplayMonitors(0, 0, seen, 7);
    DbgPrint("[enummon] step 1: %d, %d call back(s): the primary monitor %d, the whole screen %d, no DC %d, the "
             "data %d\n",
             done, calls, seen_monitor == primary, same_rect(&seen_rect, 0, 0, width, height), seen_dc == 0,
             (int)seen_data);

    /* 2. A rectangle on the screen. */
    calls = 0;
    clip.left = 10;
    clip.top = 20;
    clip.right = 110;
    clip.bottom = 220;
    done = EnumDisplayMonitors(0, &clip, seen, 0);
    DbgPrint("[enummon] step 2: %d, %d call back(s), the rectangle %d\n", done, calls,
             same_rect(&seen_rect, 10, 20, 110, 220));

    /* 3. A rectangle off the screen. */
    calls = 0;
    clip.left = -500;
    clip.top = -500;
    clip.right = -400;
    clip.bottom = -400;
    done = EnumDisplayMonitors(0, &clip, seen, 0);
    DbgPrint("[enummon] step 3: off the screen: %d, %d call back(s)\n", done, calls);

    /* 4. The popup's DC. */
    calls = 0;
    hdc = GetDC(popup);
    GetClientRect(popup, &client);
    done = EnumDisplayMonitors(hdc, 0, seen, 0);
    DbgPrint("[enummon] step 4: a DC: %d, %d call back(s), the DC %d, its part from its corner %d (%ld,%ld)-(%ld,%ld)\n",
             done, calls, seen_dc == hdc, same_rect(&seen_rect, 0, 0, client.right, client.bottom), seen_rect.left,
             seen_rect.top, seen_rect.right, seen_rect.bottom);
    ReleaseDC(popup, hdc);

    /* 5. A call back that stops. */
    calls = 0;
    answer = 0;
    done = EnumDisplayMonitors(0, 0, seen, 0);
    DbgPrint("[enummon] step 5: a call back that answers FALSE: %d, %d call back(s)\n", done, calls);
    DbgPrint("[enummon] done\n");
    ExitProcess(0);
    return 0;
}
