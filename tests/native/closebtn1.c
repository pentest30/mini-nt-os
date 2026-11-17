/*
 * The close button follows Close in the window menu (UserDrawCaptionButton,
 * NC_DoButton and IntEnableMenuItem of ReactOS as the specification;
 * win32k::sysmenu::close_enabled, win32k::menu::enable): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's kernel32,
 * user32 and gdi32, which the scenario `close-button` puts on the boot disk
 * in the place of winlogon.exe (like sysmenu1.c). It takes a desktop like
 * winlogon and shows three windows: W1 at (100, 100, 300 x 200), W2 at (450,
 * 100), of a CS_NOCLOSE class, W3 at (100, 350). It reads the close button's
 * symbol on the screen (GetPixel: its black pixels, and those of
 * COLOR_BTNSHADOW, the grayed symbol's), then:
 * 1. EnableMenuItem(GetSystemMenu(W1), SC_CLOSE, MF_GRAYED) returns
 *    MF_ENABLED, and W1's close button is grayed at once (the frame
 *    repainted by EnableMenuItem itself);
 * 2. W2's close button is grayed (CS_NOCLOSE);
 * 3. Close grayed, then enabled again, in W3: its button is black again;
 * 4. the mouse of QEMU clicks W1's close button, double-clicks W1's icon,
 *    clicks W2's close button: nothing (no SC_CLOSE, no WM_CLOSE); then it
 *    clicks W3's close button: WM_CLOSE.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; a "[closebtn] mouse:" line asks the scenario for its mouse.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef DWORD COLORREF;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HKL;
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
#define CS_NOCLOSE 0x0200
#define WM_CLOSE 0x0010
#define WM_SYSCOMMAND 0x0112
#define WM_INITMENUPOPUP 0x0117
#define SC_CLOSE 0xF060
#define MF_BYCOMMAND 0x0000
#define MF_ENABLED 0x0000
#define MF_GRAYED 0x0001
#define PM_REMOVE 0x0001
#define SM_CXFRAME 32
#define SM_CYFRAME 33
#define SM_CXSIZE 30
#define SM_CYSIZE 31
#define COLOR_BTNSHADOW 16
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x7009

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
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) UINT __stdcall EnableMenuItem(HMENU menu, UINT id, UINT enable);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) DWORD __stdcall GetSysColor(int index);
__declspec(dllimport) HMENU __stdcall GetSystemMenu(HWND window, BOOL revert);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC hdc);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

__declspec(dllimport) COLORREF __stdcall GetPixel(HDC hdc, int x, int y);

static HWND w1, w2, w3;
/* What W1 and W2 received: SC_CLOSE, WM_CLOSE; and the window menus W1
   opened. */
static int sc_close[2], wm_close[2], w1_popups;

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

static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        DispatchMessageW(&message);
}

/* The close button's symbol of `window` on the screen: inside its edges,
   the black pixels (an enabled symbol) and those of COLOR_BTNSHADOW (a
   grayed one). */
static void close_symbol(HWND window, int *black, int *shadow)
{
    RECT rect;
    int x, y, left, top, right, bottom;
    COLORREF gray = GetSysColor(COLOR_BTNSHADOW), color;
    HDC hdc = GetDC(0);

    GetWindowRect(window, &rect);
    right = rect.right - GetSystemMetrics(SM_CXFRAME) - 2;
    left = rect.right - GetSystemMetrics(SM_CXFRAME) - GetSystemMetrics(SM_CXSIZE);
    top = rect.top + GetSystemMetrics(SM_CYFRAME) + 2;
    bottom = rect.top + GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CYSIZE) - 2;
    *black = *shadow = 0;
    for (y = top + 2; y < bottom - 2; y++)
        for (x = left + 2; x < right - 2; x++) {
            color = GetPixel(hdc, x, y);
            if (color == 0)
                (*black)++;
            else if (color == gray)
                (*shadow)++;
        }
    ReleaseDC(0, hdc);
}

/* Is the symbol grayed (shadow pixels, no black ones) or enabled (black
   ones, no shadow)? */
static const char *symbol_of(HWND window)
{
    int black, shadow;

    close_symbol(window, &black, &shadow);
    if (black == 0 && shadow > 0)
        return "grayed";
    if (black > 0 && shadow == 0)
        return "enabled";
    return "neither";
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    int which = window == w1 ? 0 : window == w2 ? 1 : -1;

    if (message == WM_SYSCOMMAND && (wp & 0xFFF0) == SC_CLOSE && which >= 0)
        sc_close[which]++;
    if (message == WM_INITMENUPOPUP && window == w1)
        w1_popups++;
    if (message == WM_CLOSE) {
        if (which >= 0) {
            wm_close[which]++;
            return 0;
        }
        if (window == w3) {
            DbgPrint("[closebtn] step 4: W3 WM_CLOSE; W1 SC_CLOSE %d, WM_CLOSE %d, its window menus %d; W2 SC_CLOSE "
                     "%d, WM_CLOSE %d\n",
                     sc_close[0], wm_close[0], w1_popups, sc_close[1], wm_close[1]);
            DbgPrint("[closebtn] done\n");
            ExitProcess(EXIT_STATUS);
        }
    }
    return DefWindowProcW(window, message, wp, lp);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HMENU sys1, sys3;
    UINT before, grayed, enabled;
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoCloseButton";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    class_info.style = CS_NOCLOSE;
    class_info.lpszClassName = L"MinoNoClose";
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    w1 = CreateWindowExW(0, L"MinoCloseButton", L"W1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 300, 200, 0, 0,
                         instance, 0);
    w2 = CreateWindowExW(0, L"MinoNoClose", L"W2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 450, 100, 300, 200, 0, 0,
                         instance, 0);
    w3 = CreateWindowExW(0, L"MinoCloseButton", L"W3", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 350, 300, 200, 0, 0,
                         instance, 0);
    if (!w1 || !w2 || !w3)
        ExitProcess(4);
    pump();

    DbgPrint("[closebtn] step 1: before, W1's close button %s\n", symbol_of(w1));
    sys1 = GetSystemMenu(w1, 0);
    before = EnableMenuItem(sys1, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
    /* No message pumped: EnableMenuItem repainted the button itself. */
    DbgPrint("[closebtn] step 1: EnableMenuItem %u; W1's close button %s\n", before, symbol_of(w1));
    DbgPrint("[closebtn] step 2: W2's close button %s\n", symbol_of(w2));
    sys3 = GetSystemMenu(w3, 0);
    grayed = EnableMenuItem(sys3, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
    DbgPrint("[closebtn] step 3: grayed %u, W3's close button %s\n", grayed, symbol_of(w3));
    enabled = EnableMenuItem(sys3, SC_CLOSE, MF_BYCOMMAND | MF_ENABLED);
    DbgPrint("[closebtn] step 3: enabled again %u, W3's close button %s\n", enabled, symbol_of(w3));

    DbgPrint("[closebtn] mouse: the close buttons\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(5);
    return 0;
}
