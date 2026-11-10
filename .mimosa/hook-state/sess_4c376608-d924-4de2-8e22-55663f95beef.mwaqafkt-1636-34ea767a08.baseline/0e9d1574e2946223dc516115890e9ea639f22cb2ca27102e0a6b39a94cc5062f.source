/*
 * The mouse: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which the scenario `mouse` puts
 * on the boot disk in the place of winlogon.exe (like `keyboard`, see
 * keys1.c). It takes a desktop like winlogon and opens a window over the
 * whole screen (WS_POPUP: its client area is the screen, so a point in it
 * is a point on the screen), of a class that wants double clicks
 * (CS_DBLCLKS). Once it is painted, it says it waits; the scenario then
 * moves the mouse and presses its buttons through QEMU's monitor (`keys =
 * … move:…, press:…, release, wheel:…`), which the PS/2 mouse driver
 * (IRQ12, i8042) and the raw input thread turn into WM_MOUSEMOVE,
 * WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONDOWN,
 * WM_RBUTTONUP and WM_MOUSEWHEEL for the window. Each one goes to the debug
 * port (DbgPrint) with its point and MK_* keys; the wheel ends the program
 * with EXIT_STATUS.
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
typedef short SHORT;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
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

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define CS_DBLCLKS 0x0008
#define WM_PAINT 0x000F
#define WM_MOUSEMOVE 0x0200
#define WM_LBUTTONDOWN 0x0201
#define WM_LBUTTONUP 0x0202
#define WM_LBUTTONDBLCLK 0x0203
#define WM_RBUTTONDOWN 0x0204
#define WM_RBUTTONUP 0x0205
#define WM_MOUSEWHEEL 0x020A
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define VK_LBUTTON 0x01
#define EXIT_STATUS 0x600E

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

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
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) SHORT __stdcall GetAsyncKeyState(int key);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static const WCHAR CLASS_NAME[] = L"MinoMouse";
static int painted;

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
    DbgPrint("[mouse] on WinSta0\\Default\n");
    return 1;
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

static LRESULT __stdcall mouse_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        EndPaint(window, &paint);
        if (!painted)
            DbgPrint("[mouse] waiting\n");
        painted = 1;
        return 0;
    case WM_MOUSEMOVE:
        DbgPrint("[mouse] move %d,%d keys %04x\n", x_of(l), y_of(l), w);
        return 0;
    case WM_LBUTTONDOWN:
        DbgPrint("[mouse] ldown %d,%d keys %04x; async %s\n", x_of(l), y_of(l), w,
                 GetAsyncKeyState(VK_LBUTTON) & 0x8000 ? "down" : "up");
        return 0;
    case WM_LBUTTONUP:
        DbgPrint("[mouse] lup %d,%d keys %04x\n", x_of(l), y_of(l), w);
        return 0;
    case WM_LBUTTONDBLCLK:
        DbgPrint("[mouse] ldblclk %d,%d keys %04x\n", x_of(l), y_of(l), w);
        return 0;
    case WM_RBUTTONDOWN:
        DbgPrint("[mouse] rdown %d,%d keys %04x\n", x_of(l), y_of(l), w);
        return 0;
    case WM_RBUTTONUP:
        DbgPrint("[mouse] rup %d,%d keys %04x\n", x_of(l), y_of(l), w);
        return 0;
    case WM_MOUSEWHEEL:
        DbgPrint("[mouse] wheel %d at %d,%d keys %04x\n", (short)(w >> 16), x_of(l), y_of(l), w & 0xFFFF);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.style = CS_DBLCLKS;
    class_info.lpfnWndProc = mouse_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    window = CreateWindowExW(0, CLASS_NAME, L"Mouse", WS_POPUP | WS_VISIBLE, 0, 0, GetSystemMetrics(SM_CXSCREEN),
                             GetSystemMetrics(SM_CYSCREEN), 0, 0, instance, 0);
    if (!window)
        ExitProcess(3);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[mouse] done\n");
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
