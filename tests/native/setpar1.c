/*
 * SetParent (co_IntSetParent of ReactOS as the specification;
 * win32k::winpos::set_parent): a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `set-parent` puts on the boot disk in the place of winlogon.exe. It takes
 * a desktop like winlogon and shows P, a popup with a child C:
 * 1. V, a popup, put under P: SetParent returns the desktop window, V's
 *    parent is P, and P has two children (EnumChildWindows), V first;
 * 2. W, a popup that destroys itself on its WM_SHOWWINDOW (FALSE), the hide
 *    SetParent starts with: SetParent fails, W is gone, and P's children
 *    are still V and C. The window used to be linked under P all the same,
 *    its dead handle first among P's children, and the list stopped there:
 *    P had no child any more (the review of PR 158).
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
typedef BOOL(__stdcall *WNDENUMPROC)(HWND, LPARAM);

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

#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WS_CAPTION 0x00C00000
#define WM_SHOWWINDOW 0x0018
#define GW_CHILD 5
#define GA_PARENT 1
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000

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
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) BOOL __stdcall EnumChildWindows(HWND parent, WNDENUMPROC callback, LPARAM l);
__declspec(dllimport) HWND __stdcall GetAncestor(HWND window, UINT flags);
__declspec(dllimport) HWND __stdcall GetDesktopWindow(void);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT command);
__declspec(dllimport) BOOL __stdcall IsWindow(HWND window);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HWND __stdcall SetParent(HWND child, HWND parent);
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

/* W destroys itself when hidden. */
static int doomed;

static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_SHOWWINDOW && !w && doomed) {
        doomed = 0;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

/* P's children, in order. */
static HWND children[8];
static int child_count;

static BOOL __stdcall count_child(HWND window, LPARAM l)
{
    (void)l;
    if (child_count < 8)
        children[child_count] = window;
    child_count++;
    return 1;
}

static int count_children(HWND parent)
{
    child_count = 0;
    memset(children, 0, sizeof children);
    EnumChildWindows(parent, count_child, 0);
    return child_count;
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSEXW info;
    HWND p, c, v, w, old;
    DWORD error;
    int count, gone, in_order, first;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.lpfnWndProc = procedure;
    info.hInstance = instance;
    info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    info.lpszClassName = L"MinoSetParent";
    if (!RegisterClassExW(&info))
        ExitProcess(2);
    p = CreateWindowExW(0, L"MinoSetParent", L"P", WS_POPUP | WS_CAPTION | WS_VISIBLE, 100, 100, 400, 300, 0, 0,
                        instance, 0);
    c = p ? CreateWindowExW(0, L"MinoSetParent", L"C", WS_CHILD | WS_VISIBLE, 10, 10, 100, 50, p, 0, instance, 0) : 0;
    if (!c)
        ExitProcess(3);
    count = count_children(p);
    DbgPrint("[setparent] ready: P with C, %d child\n", count);

    /* 1. A popup put under P. */
    v = CreateWindowExW(0, L"MinoSetParent", L"V", WS_POPUP | WS_VISIBLE, 600, 100, 100, 80, 0, 0, instance, 0);
    /* One call after the other: the arguments of a call have no order. */
    old = v ? SetParent(v, p) : 0;
    count = count_children(p);
    first = children[0] == v;
    DbgPrint("[setparent] step 1: SetParent(V, P) gave the desktop %d; V's parent P %d; P's children %d, V first %d\n",
             old == GetDesktopWindow(), GetAncestor(v, GA_PARENT) == p, count, first);

    /* 2. A popup destroyed by the hide SetParent starts with. */
    w = CreateWindowExW(0, L"MinoSetParent", L"W", WS_POPUP | WS_VISIBLE, 600, 300, 100, 80, 0, 0, instance, 0);
    if (!w)
        ExitProcess(4);
    doomed = 1;
    SetLastError(0);
    old = SetParent(w, p);
    error = GetLastError();
    gone = !IsWindow(w);
    count = count_children(p);
    in_order = children[0] == v && children[1] == c;
    first = GetWindow(p, GW_CHILD) == v;
    DbgPrint("[setparent] step 2: SetParent(W, P) of a window destroyed on its hide %p (error %lu), W gone %d; P's "
             "children %d, V and C %d, P's first child V %d\n",
             old, error, gone, count, in_order, first);
    DbgPrint("[setparent] done\n");
    ExitProcess(0);
    return 0;
}
