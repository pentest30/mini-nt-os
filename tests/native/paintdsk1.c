/*
 * PaintDesktop: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32, user32 and gdi32, which the scenario
 * `paint-desktop` puts on the boot disk in the place of winlogon.exe (like
 * zorder1.c). explorer's desktop paints its background by PaintDesktop
 * (NtUserPaintDesktop: IntPaintDesktop fills the DC's clip box with the
 * brush of the desktop window's class, COLOR_BACKGROUND, while no wallpaper
 * is set). The program takes a desktop like winlogon, then:
 * 1. in a memory DC of 16 x 16 pixels painted white, PaintDesktop, then
 *    GetPixel: the desktop's colour; the DC keeps its own brush;
 * 2. a white popup at (100, 100)-(400, 300) whose WM_ERASEBKGND fills its
 *    DC white, then calls PaintDesktop: the scenario reads the screen
 *    inside it, the desktop's colour.
 * Without NtUserPaintDesktop, PaintDesktop fails and white stays.
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
typedef void *HBITMAP;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef DWORD COLORREF;
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

#define WM_ERASEBKGND 0x0014
#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define PM_REMOVE 0x0001
#define MAXIMUM_ALLOWED 0x02000000
#define COLOR_BACKGROUND 1
#define COLOR_WINDOW 5
#define WHITE 0x00FFFFFF

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HBITMAP __stdcall CreateCompatibleBitmap(HDC dc, int width, int height);
__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF color);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) HGDIOBJ __stdcall GetCurrentObject(HDC dc, UINT type);
__declspec(dllimport) COLORREF __stdcall GetPixel(HDC dc, int x, int y);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) int __stdcall FillRect(HDC dc, const RECT *rect, HBRUSH brush);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) DWORD __stdcall GetSysColor(int index);
__declspec(dllimport) HBRUSH __stdcall GetSysColorBrush(int index);
__declspec(dllimport) BOOL __stdcall PaintDesktop(HDC dc);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC dc);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

#define OBJ_BRUSH 2

static int painted;
static BOOL painted_ok;

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
    if (message == WM_ERASEBKGND) {
        RECT rect = {0, 0, 300, 200};
        FillRect((HDC)w, &rect, GetSysColorBrush(COLOR_WINDOW));
        painted_ok = PaintDesktop((HDC)w);
        painted++;
        return 1;
    }
    return DefWindowProcW(hwnd, message, w, l);
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
    HDC screen, memory;
    HBITMAP bitmap;
    HBRUSH own;
    RECT all = {0, 0, 16, 16};
    COLORREF desktop_color, pixel;
    BOOL done, kept;
    HWND window;

    if (!take_a_desktop())
        ExitProcess(1);
    desktop_color = GetSysColor(COLOR_BACKGROUND);
    DbgPrint("[paintdsk] ready; the desktop's colour %06lx\n", desktop_color);

    screen = GetDC(0);
    memory = CreateCompatibleDC(screen);
    bitmap = CreateCompatibleBitmap(screen, 16, 16);
    ReleaseDC(0, screen);
    if (!memory || !bitmap)
        ExitProcess(2);
    SelectObject(memory, bitmap);
    FillRect(memory, &all, GetSysColorBrush(COLOR_WINDOW));
    own = CreateSolidBrush(0x00123456);
    SelectObject(memory, own);
    done = PaintDesktop(memory);
    pixel = GetPixel(memory, 8, 8);
    kept = GetCurrentObject(memory, OBJ_BRUSH) == own;
    DbgPrint("[paintdsk] step 1: a memory DC: %d, the desktop's colour %d, its brush kept %d\n", done,
             pixel == desktop_color, kept);
    DeleteDC(memory);

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoPaintDesktop";
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    window = CreateWindowExW(0, L"MinoPaintDesktop", L"P", WS_POPUP | WS_VISIBLE, 100, 100, 300, 200, 0, 0, instance,
                             0);
    if (!window)
        ExitProcess(4);
    UpdateWindow(window);
    pump();
    DbgPrint("[paintdsk] step 2: a window erased by PaintDesktop: %d, erased %d; look now\n", painted_ok,
             painted > 0);
    /* The scenario reads the screen and ends the run meanwhile. */
    Sleep(60000);
    ExitProcess(0);
    return 0;
}
