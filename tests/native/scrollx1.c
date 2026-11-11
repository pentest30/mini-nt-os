/*
 * The scrolling of a window and of a DC: a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32, user32
 * and gdi32, which the scenario `scrollex` puts on the boot disk in the place
 * of winlogon.exe (like `scroll`, see scroll1.c). On WinSta0\Default, W at
 * 100, 100 (400 x 300, its client area 392 x 272 from 104, 124, clipping its
 * children) shows bands of 20 pixels, red, green and blue in turn, from a
 * position `top` (band k at row y when (y + top) / 20 is k); its WM_PAINT
 * paints only what it is asked to (rcPaint). Once painted:
 * - ScrollWindowEx up 30 (SW_INVALIDATE | SW_ERASE): the copy moves the
 *   bands, what it uncovers (the last 30 rows) comes back in hrgnUpdate,
 *   prcUpdate and GetUpdateRect, and only it is painted (UpdateWindow);
 * - ScrollDC down 20 on GetDC(W): the first 20 rows to repaint;
 * - a child C (black, 50 x 30 at 300, 100) and ScrollWindowEx left 10 with
 *   SW_SCROLLCHILDREN: C moves with the content and receives WM_MOVE.
 * Each step goes to the debug port (DbgPrint, a line each, its values taken
 * before); the program ends with EXIT_STATUS.
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
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HRGN;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HGDIOBJ;
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
    HCURSOR hCursor;
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

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define WS_CHILD 0x40000000
#define WS_CLIPCHILDREN 0x02000000
#define WM_PAINT 0x000F
#define WM_MOVE 0x0003
#define WM_APP 0x8000
#define BLACK_BRUSH 4
#define MAXIMUM_ALLOWED 0x02000000
#define SW_SCROLLCHILDREN 0x0001
#define SW_INVALIDATE 0x0002
#define SW_ERASE 0x0004
#define EXIT_STATUS 0x6012
#define BAND 20

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);

__declspec(dllimport) HRGN __stdcall CreateRectRgn(int left, int top, int right, int bottom);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF color);
__declspec(dllimport) int __stdcall GetRgnBox(HRGN region, RECT *rect);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);

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
__declspec(dllimport) int __stdcall FillRect(HDC hdc, const RECT *rect, HBRUSH brush);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall GetUpdateRect(HWND window, RECT *rect, BOOL erase);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HWND window, const RECT *rect, BOOL erase);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC hdc);
__declspec(dllimport) BOOL __stdcall ScrollDC(HDC hdc, int dx, int dy, const RECT *scroll, const RECT *clip,
                                              HRGN update, RECT *update_rect);
__declspec(dllimport) int __stdcall ScrollWindowEx(HWND window, int dx, int dy, const RECT *scroll, const RECT *clip,
                                                   HRGN update, RECT *update_rect, UINT flags);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

static const WCHAR W_CLASS[] = L"MinoScrollW";
static const WCHAR C_CLASS[] = L"MinoScrollC";
static HWND w, c;
static HBRUSH bands[3];
/* Where the content starts: band k at row y when (y + top) / BAND is k. */
static int top;
static int painted, log_paint, moves;
static LONG moved_x = -1, moved_y = -1;

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
    DbgPrint("[scrollx] on WinSta0\\Default\n");
    return 1;
}

/* The bands that meet `rect`, each cut to it. */
static void paint_bands(HDC hdc, const RECT *rect)
{
    int y = rect->top - ((rect->top + top) % BAND + BAND) % BAND;
    for (; y < rect->bottom; y += BAND) {
        RECT band = {rect->left, y, rect->right, y + BAND};
        if (band.top < rect->top)
            band.top = rect->top;
        if (band.bottom > rect->bottom)
            band.bottom = rect->bottom;
        FillRect(hdc, &band, bands[(((y + top) / BAND) % 3 + 3) % 3]);
    }
}

static void steps(void)
{
    HRGN region = CreateRectRgn(0, 0, 0, 0);
    RECT update = {-1, -1, -1, -1}, box = {-1, -1, -1, -1}, pending = {-1, -1, -1, -1}, before, after;
    HDC hdc;
    int result;
    BOOL ok;

    result = ScrollWindowEx(w, 0, -30, 0, 0, region, &update, SW_INVALIDATE | SW_ERASE);
    top += 30;
    GetRgnBox(region, &box);
    GetUpdateRect(w, &pending, 0);
    DbgPrint("[scrollx] ScrollWindowEx up 30: %d, prcUpdate %ld %ld %ld %ld, hrgnUpdate %ld %ld %ld %ld, GetUpdateRect "
             "%ld %ld %ld %ld\n",
             result, update.left, update.top, update.right, update.bottom, box.left, box.top, box.right, box.bottom,
             pending.left, pending.top, pending.right, pending.bottom);
    log_paint = 1;
    UpdateWindow(w);

    hdc = GetDC(w);
    ok = ScrollDC(hdc, 0, 20, 0, 0, 0, &update);
    ReleaseDC(w, hdc);
    top -= 20;
    DbgPrint("[scrollx] ScrollDC down 20: %d, prcUpdate %ld %ld %ld %ld\n", ok, update.left, update.top, update.right,
             update.bottom);
    InvalidateRect(w, &update, 1);
    UpdateWindow(w);
    log_paint = 0;

    c = CreateWindowExW(0, C_CLASS, L"C", WS_CHILD | WS_VISIBLE, 300, 100, 50, 30, w, 0, GetModuleHandleW(0), 0);
    UpdateWindow(c);
    GetWindowRect(c, &before);
    moves = 1;
    result = ScrollWindowEx(w, -10, 0, 0, 0, 0, 0, SW_SCROLLCHILDREN | SW_INVALIDATE | SW_ERASE);
    moves = 0;
    GetWindowRect(c, &after);
    DbgPrint("[scrollx] SW_SCROLLCHILDREN left 10: %d, C from %ld to %ld, WM_MOVE %ld %ld\n", result, before.left,
             after.left, moved_x, moved_y);
    UpdateWindow(w);
    UpdateWindow(c);
    DbgPrint("[scrollx] done\n");
    PostQuitMessage(0);
}

static LRESULT __stdcall w_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    PAINTSTRUCT paint;

    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        paint_bands(paint.hdc, &paint.rcPaint);
        EndPaint(window, &paint);
        if (log_paint)
            DbgPrint("[scrollx] WM_PAINT %ld %ld %ld %ld\n", paint.rcPaint.left, paint.rcPaint.top,
                     paint.rcPaint.right, paint.rcPaint.bottom);
        if (!painted) {
            painted = 1;
            DbgPrint("[scrollx] painted\n");
            PostMessageW(window, WM_APP, 0, 0);
        }
        return 0;
    case WM_APP:
        steps();
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

static LRESULT __stdcall c_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_MOVE && moves) {
        moved_x = (short)(lparam & 0xFFFF);
        moved_y = (short)((lparam >> 16) & 0xFFFF);
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    bands[0] = CreateSolidBrush(0x0000FF);
    bands[1] = CreateSolidBrush(0x00A000);
    bands[2] = CreateSolidBrush(0xFF0000);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = w_procedure;
    class_info.hInstance = instance;
    class_info.lpszClassName = W_CLASS;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    class_info.lpfnWndProc = c_procedure;
    class_info.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    class_info.lpszClassName = C_CLASS;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    w = CreateWindowExW(0, W_CLASS, L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CLIPCHILDREN, 100, 100, 400, 300, 0, 0,
                        instance, 0);
    if (!w)
        ExitProcess(3);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
