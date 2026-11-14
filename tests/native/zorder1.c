/*
 * What a window uncovers when only its place in the Z order changes: a
 * Win32 program (subsystem WINDOWS), compiled with MinGW and linked to
 * ReactOS's kernel32, user32 and gdi32, which the scenario `zorder` puts on
 * the boot disk in the place of winlogon.exe (like activate1.c). It takes a
 * desktop like winlogon and shows two popups that overlap: A, red, at
 * (100, 100)-(400, 300), then B, green, above it at (200, 200)-(500, 400).
 * Then SetWindowPos sends B to the bottom without moving it (as
 * NtUserSetShellWindowEx sends explorer's desktop under its taskbar): the
 * overlap, which was B's, is now A's, and A must paint it again. The
 * scenario reads the screen once the program says so: red in the overlap,
 * green where only B is.
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

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define HWND_BOTTOM ((HWND)1)
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define SWP_NOACTIVATE 0x0010
#define PM_REMOVE 0x0001
#define MAXIMUM_ALLOWED 0x02000000

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(DWORD color);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND insert_after, int x, int y, int cx, int cy,
                                                  UINT flags);
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

/* A class whose background is `color` (COLORREF, 0x00BBGGRR). */
static BOOL register_class(const WCHAR *name, DWORD color)
{
    WNDCLASSEXW class_info;

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = CreateSolidBrush(color);
    class_info.lpszClassName = name;
    return class_info.hbrBackground && RegisterClassExW(&class_info) != 0;
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
    HWND a, b;
    BOOL moved;

    if (!take_a_desktop())
        ExitProcess(1);
    if (!register_class(L"MinoRed", 0x000000FF) || !register_class(L"MinoGreen", 0x0000FF00))
        ExitProcess(2);
    a = CreateWindowExW(0, L"MinoRed", L"A", WS_POPUP | WS_VISIBLE, 100, 100, 300, 200, 0, 0, instance, 0);
    b = CreateWindowExW(0, L"MinoGreen", L"B", WS_POPUP | WS_VISIBLE, 200, 200, 300, 200, 0, 0, instance, 0);
    if (!a || !b)
        ExitProcess(3);
    UpdateWindow(a);
    UpdateWindow(b);
    pump();
    DbgPrint("[zorder] A and B painted, B above\n");
    moved = SetWindowPos(b, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    pump();
    DbgPrint("[zorder] B sent to the bottom: %d; look now\n", moved);
    /* The scenario reads the screen and ends the run meanwhile. */
    Sleep(60000);
    ExitProcess(0);
    return 0;
}
