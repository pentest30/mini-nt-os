/*
 * A DC taken while its window moves (DceResetActiveDCEs): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's kernel32,
 * user32 and gdi32, which the scenario `dc-reset` puts on the boot disk in
 * the place of winlogon.exe (like zorder1.c). explorer takes a DC of its
 * desktop while the desktop is above everything and keeps it; it paints
 * the background by it once the desktop is under the taskbar. The program
 * takes a desktop like winlogon and shows two popups: B, green, at
 * (100, 100)-(400, 300), then A, red, above it at (200, 200)-(500, 400).
 * It takes a DC of A (GetDC) and keeps it, then:
 * 1. sends A to the bottom without moving it, and fills A's DC blue: the
 *    overlap stays B's (green), the rest of A turns blue;
 * 2. moves A to (600, 200), and fills A's DC yellow: A turns yellow at its
 *    new place, not at the old one.
 * It reads the screen itself (GetPixel on the screen's DC) and says what
 * it found. A DC that kept the region of its taking painted over B and at
 * A's old place.
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

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define HWND_BOTTOM ((HWND)1)
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define SWP_NOZORDER 0x0004
#define SWP_NOACTIVATE 0x0010
#define PM_REMOVE 0x0001
#define MAXIMUM_ALLOWED 0x02000000

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(DWORD color);
__declspec(dllimport) DWORD __stdcall GetPixel(void *dc, int x, int y);

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
__declspec(dllimport) int __stdcall FillRect(void *dc, const RECT *rect, HBRUSH brush);
__declspec(dllimport) void *__stdcall GetDC(HWND window);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, void *dc);

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

#define GREEN 0x0000FF00
#define BLUE 0x00FF0000
#define YELLOW 0x0000FFFF

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    RECT all = {0, 0, 300, 200};
    void *taken, *screen;
    HWND a, b;

    if (!take_a_desktop())
        ExitProcess(1);
    if (!register_class(L"MinoRed", 0x000000FF) || !register_class(L"MinoGreen", GREEN))
        ExitProcess(2);
    b = CreateWindowExW(0, L"MinoGreen", L"B", WS_POPUP | WS_VISIBLE, 100, 100, 300, 200, 0, 0, instance, 0);
    a = CreateWindowExW(0, L"MinoRed", L"A", WS_POPUP | WS_VISIBLE, 200, 200, 300, 200, 0, 0, instance, 0);
    if (!a || !b)
        ExitProcess(3);
    pump();
    taken = GetDC(a);
    screen = GetDC(0);
    if (!taken || !screen)
        ExitProcess(4);
    DbgPrint("[dcreset] ready, A above B, a DC of A taken\n");

    SetWindowPos(a, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    pump();
    FillRect(taken, &all, CreateSolidBrush(BLUE));
    DbgPrint("[dcreset] step 1: A sent to the bottom; the overlap stays B's %d, the rest of A painted %d\n",
             GetPixel(screen, 300, 250) == GREEN, GetPixel(screen, 450, 350) == BLUE);

    SetWindowPos(a, 0, 600, 200, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    pump();
    FillRect(taken, &all, CreateSolidBrush(YELLOW));
    DbgPrint("[dcreset] step 2: A moved; painted at its new place %d, not at the old one %d\n",
             GetPixel(screen, 750, 300) == YELLOW, GetPixel(screen, 450, 350) != YELLOW);

    ReleaseDC(a, taken);
    ReleaseDC(0, screen);
    DbgPrint("[dcreset] done\n");
    ExitProcess(0x7005);
    return 0;
}
