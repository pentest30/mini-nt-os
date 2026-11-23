/*
 * SaveDC and RestoreDC (DC_vRestoreDC of ReactOS as the specification;
 * win32k::gdi::dc::Dc::save_state, restore_state): a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32, user32 and
 * gdi32, which the scenario `save-restore-dc` puts on the boot disk in the
 * place of winlogon.exe. It takes a desktop like winlogon, shows a popup, and
 * on its DC (GetDC, a DC with its attributes in the process):
 * 1. SaveDC twice around a move (MoveToEx) and a background colour
 *    (SetBkColor); RestoreDC(-1) brings back the first ones, RestoreDC(1)
 *    the ones from before, a level past the stack fails;
 * 2. the same on a memory DC (CreateCompatibleDC).
 * Notepad++ (Scintilla) saves and restores its DCs as it paints: the first
 * RestoreDC of a DC with attributes took the lock of the DC's state twice
 * (an `if let` kept the first guard through its body), and the processor
 * spun at DISPATCH_LEVEL for ever: the whole system froze.
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
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
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
    LONG x;
    LONG y;
} POINT;

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define WS_CAPTION 0x00C00000
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define RGB(r, g, b) ((COLORREF)((r) | ((g) << 8) | ((b) << 16)))

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
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC dc);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) COLORREF __stdcall GetBkColor(HDC dc);
__declspec(dllimport) BOOL __stdcall GetCurrentPositionEx(HDC dc, POINT *point);
__declspec(dllimport) BOOL __stdcall MoveToEx(HDC dc, int x, int y, POINT *old);
__declspec(dllimport) BOOL __stdcall RestoreDC(HDC dc, int level);
__declspec(dllimport) int __stdcall SaveDC(HDC dc);
__declspec(dllimport) COLORREF __stdcall SetBkColor(HDC dc, COLORREF color);

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

/* The current position and the background colour of `dc` match. */
static int state_is(HDC dc, LONG x, LONG y, COLORREF background)
{
    POINT at;
    memset(&at, 0, sizeof at);
    return GetCurrentPositionEx(dc, &at) && at.x == x && at.y == y && GetBkColor(dc) == background;
}

/* Two saves around a move and a background colour, then the restores; the
   results, one per step, in `steps`. One call after the other: the
   arguments of a call have no order. */
static void save_and_restore(HDC dc, const char *name)
{
    int first, second, back_one, back_one_state, back_all, back_all_state, past;
    COLORREF original = GetBkColor(dc);

    MoveToEx(dc, 0, 0, 0);
    first = SaveDC(dc);
    MoveToEx(dc, 10, 20, 0);
    SetBkColor(dc, RGB(1, 2, 3));
    second = SaveDC(dc);
    MoveToEx(dc, 30, 40, 0);
    SetBkColor(dc, RGB(4, 5, 6));
    back_one = RestoreDC(dc, -1);
    back_one_state = state_is(dc, 10, 20, RGB(1, 2, 3));
    back_all = RestoreDC(dc, first);
    back_all_state = state_is(dc, 0, 0, original);
    past = RestoreDC(dc, 5);
    DbgPrint("[savedc] %s: SaveDC %d then %d; RestoreDC(-1) %d, the first state %d; RestoreDC(%d) %d, the state "
             "before %d; RestoreDC(5) %d\n",
             name, first, second, back_one, back_one_state, first, back_all, back_all_state, past);
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSEXW info;
    HWND window;
    HDC dc, memory;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.lpfnWndProc = procedure;
    info.hInstance = instance;
    info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    info.lpszClassName = L"MinoSaveDC";
    if (!RegisterClassExW(&info))
        ExitProcess(2);
    window = CreateWindowExW(0, L"MinoSaveDC", L"S", WS_POPUP | WS_CAPTION | WS_VISIBLE, 100, 100, 300, 200, 0, 0,
                             instance, 0);
    dc = window ? GetDC(window) : 0;
    DbgPrint("[savedc] ready: a window DC %d\n", dc != 0);
    if (!dc)
        ExitProcess(3);

    /* 1. The window's DC. */
    save_and_restore(dc, "window DC");

    /* 2. A memory DC. */
    memory = CreateCompatibleDC(dc);
    if (memory) {
        save_and_restore(memory, "memory DC");
        DeleteDC(memory);
    }
    ReleaseDC(window, dc);
    DbgPrint("[savedc] done\n");
    ExitProcess(0);
    return 0;
}
